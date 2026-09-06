const std = @import("std");
const test_support = @import("../test_support.zig");
const engine = @import("engine.zig");
const diagnostics_mod = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_types = @import("../yaml/types.zig");
const util = @import("../util.zig");
const fix_builder = @import("../fix/builder.zig");
const workspace = @import("../workspace.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const Step = engine.Step;
const DiagnosticList = engine.DiagnosticList;
const spans = @import("spans.zig");
const Span = yaml_types.Span;
const ActionRef = workflow_types.ActionRef;
const Fix = diagnostics_mod.Fix;

/// - `.with_cache_input`: the action exposes a `cache:` input taking a
///   package manager name.
/// - `.bun_independent`: setup-bun has no `cache:` input, so only a sibling
///   `actions/cache` step counts and no autofix is possible.
/// - `.uv_independent`: setup-uv caches by default (`enable-cache: auto`), so
///   only an explicit `enable-cache: "false"` is a finding.
const SetupKind = enum { with_cache_input, bun_independent, uv_independent };

const CacheableSetup = struct {
    setup_action: []const u8,
    cache_key: []const u8,
    message: []const u8,
    fix_hint_base: []const u8,
    kind: SetupKind = .with_cache_input,
};

const cacheable_setups = [_]CacheableSetup{
    .{
        .setup_action = "actions/setup-node",
        .cache_key = "cache",
        .message = "Job uses actions/setup-node without caching. Add actions/cache or set 'cache' input.",
        .fix_hint_base = "Set 'cache' to the package manager ('npm', 'yarn', or 'pnpm') in the action's 'with' inputs, or add a separate actions/cache step.",
    },
    .{
        .setup_action = "actions/setup-python",
        .cache_key = "cache",
        .message = "Job uses actions/setup-python without caching. Add actions/cache or set 'cache' input.",
        .fix_hint_base = "Set 'cache' to the package manager ('pip', 'pipenv', or 'poetry') in the action's 'with' inputs, or add a separate actions/cache step.",
    },
    .{
        .setup_action = "actions/setup-go",
        .cache_key = "cache",
        .message = "Job uses actions/setup-go without caching. Add actions/cache or set 'cache' input.",
        .fix_hint_base = "Add 'cache: true' to the setup action's 'with' inputs (requires go.sum), or add a separate actions/cache step.",
    },
    .{
        .setup_action = "oven-sh/setup-bun",
        .cache_key = "",
        .message = "Job uses oven-sh/setup-bun without caching. Add an actions/cache step keyed by your bun lockfile.",
        .fix_hint_base = "Add an actions/cache step after setup-bun with path '~/.bun/install/cache' keyed by your bun lockfile (bun.lock or bun.lockb).",
        .kind = .bun_independent,
    },
    .{
        .setup_action = "astral-sh/setup-uv",
        .cache_key = "enable-cache",
        .message = "Job uses astral-sh/setup-uv with 'enable-cache: false' and no actions/cache step. Remove the input, set it to 'true', or add an actions/cache step.",
        .fix_hint_base = "Remove the 'enable-cache: false' input or set it to 'true' to restore astral-sh/setup-uv's built-in caching.",
        .kind = .uv_independent,
    },
};

fn buildCacheFix(
    diag_list: *DiagnosticList,
    job: *const Job,
    setup_action: []const u8,
    cache_value: []const u8,
    description: []const u8,
) ?Fix {
    const alloc = diag_list.fixAllocator();

    var edits = std.ArrayList(diagnostics_mod.Edit){};

    for (job.steps) |step| {
        const action_ref = step.uses orelse continue;
        const action_name = util.actionBaseName(action_ref.raw);
        if (!std.mem.eql(u8, action_name, setup_action)) continue;

        if (step.with) |with| {
            if (with.get("cache")) |_| continue;
        }

        const col = step.uses_key_col orelse continue;
        if (col == 0) continue;

        if (step.with != null) {
            const anchor = step.with_last_entry_end_byte orelse continue;
            const appended = fix_builder.appendMappingEntry(
                alloc,
                anchor,
                col + 1,
                "cache",
                cache_value,
            ) orelse continue;
            edits.appendSlice(alloc, appended) catch continue;
        } else {
            // `with: {}` / `with:` parses to a null `with` while the key is still
            // in source; inserting another `with:` block would duplicate it (#171).
            if (util.hasEmptySection(step.empty_sections, "with")) continue;
            const anchor = step.uses_value_end_byte orelse continue;
            const inserted = fix_builder.insertWithEntry(alloc, anchor, col, "cache", cache_value) orelse continue;
            edits.appendSlice(alloc, inserted) catch continue;
        }
    }

    if (edits.items.len == 0) return null;

    const owned = edits.toOwnedSlice(alloc) catch return null;
    return .{
        .description = description,
        .safety = .unsafe,
        .edits = owned,
    };
}

const DispatchResult = struct {
    fix: ?Fix,
    hint_extra: ?[]const u8,
};

/// `manager` / `ambiguous` name the `workspace.Context` fields to read.
const InferredCacheSetup = struct {
    action: []const u8,
    manager: []const u8,
    ambiguous: []const u8,
    override_key: []const u8,
};

const inferred_cache_setups = [_]InferredCacheSetup{
    .{
        .action = "actions/setup-node",
        .manager = "node_cache",
        .ambiguous = "ambiguous_node_lockfiles",
        .override_key = "node_cache_manager",
    },
    .{
        .action = "actions/setup-python",
        .manager = "python_cache",
        .ambiguous = "ambiguous_python_lockfiles",
        .override_key = "python_cache_manager",
    },
};

fn dispatchCacheFix(
    diag_list: *DiagnosticList,
    job: *const Job,
    setup_action: []const u8,
) DispatchResult {
    const none = DispatchResult{ .fix = null, .hint_extra = null };
    const alloc = diag_list.fixAllocator();
    const ctx = workspace.current;

    inline for (inferred_cache_setups) |setup| {
        if (std.mem.eql(u8, setup_action, setup.action)) {
            if (@field(ctx, setup.manager)) |mgr| {
                const mgr_str = mgr.toString();
                const description = std.fmt.allocPrint(
                    alloc,
                    "add \"cache: {s}\" to {s} step(s)",
                    .{ mgr_str, setup.action },
                ) catch return none;
                return .{
                    .fix = buildCacheFix(diag_list, job, setup_action, mgr_str, description),
                    .hint_extra = null,
                };
            }
            const ambiguous = @field(ctx, setup.ambiguous);
            if (ambiguous.len > 0) {
                return .{
                    .fix = null,
                    .hint_extra = formatAmbiguity(alloc, ambiguous, setup.override_key),
                };
            }
            return none;
        }
    }

    if (std.mem.eql(u8, setup_action, "actions/setup-go")) {
        if (!ctx.go_sum_present) return none;
        return .{
            .fix = buildCacheFix(
                diag_list,
                job,
                setup_action,
                "true",
                "add \"cache: true\" to actions/setup-go step(s) (go.sum detected)",
            ),
            .hint_extra = null,
        };
    }

    return none;
}

fn formatAmbiguity(
    alloc: std.mem.Allocator,
    lockfiles: []const []const u8,
    override_key: []const u8,
) ?[]const u8 {
    const list = std.mem.join(alloc, ", ", lockfiles) catch return null;
    return std.fmt.allocPrint(
        alloc,
        " Detected lockfiles: {s} — specify via .zghalint.yml rules.PERF001.{s}.",
        .{ list, override_key },
    ) catch null;
}

fn checkCacheNotUsed(job: *const Job, diag_list: *DiagnosticList) void {
    inline for (cacheable_setups) |ca| {
        checkCacheableSetup(ca, job, diag_list);
    }
}

fn checkCacheableSetup(
    comptime ca: CacheableSetup,
    job: *const Job,
    diag_list: *DiagnosticList,
) void {
    // Span of the first setup step that warrants a warning, so the diagnostic
    // points at the action rather than at the job.
    var setup_span: ?Span = null;
    var has_cache = false;

    for (job.steps) |*step| {
        const action_ref = step.uses orelse continue;
        const action_name = util.actionBaseName(action_ref.raw);

        if (std.mem.eql(u8, action_name, "actions/cache")) {
            has_cache = true;
            continue;
        }
        if (!std.mem.eql(u8, action_name, ca.setup_action)) continue;

        switch (comptime ca.kind) {
            .with_cache_input => {
                if (setup_span == null) setup_span = spans.usesSpan(step);
                const with = step.with orelse continue;
                const val = with.get(ca.cache_key) orelse continue;
                if (val.len > 0) has_cache = true;
            },
            .bun_independent => {
                if (setup_span == null) setup_span = spans.usesSpan(step);
            },
            .uv_independent => {
                const with = step.with orelse continue;
                const val = with.get(ca.cache_key) orelse continue;
                if (std.mem.eql(u8, val, "false") and setup_span == null) {
                    setup_span = spans.usesSpan(step);
                }
            },
        }
    }

    const span = setup_span orelse return;
    if (has_cache) return;

    const dispatched: DispatchResult = switch (comptime ca.kind) {
        .with_cache_input => dispatchCacheFix(diag_list, job, ca.setup_action),
        .bun_independent => .{
            .fix = null,
            .hint_extra = if (workspace.current.bun_lockfile_present)
                null
            else
                " Note: no bun.lock or bun.lockb detected at the workspace root.",
        },
        .uv_independent => .{ .fix = null, .hint_extra = null },
    };

    const hint: []const u8 = if (dispatched.hint_extra) |extra| blk: {
        const combined = std.fmt.allocPrint(
            diag_list.fixAllocator(),
            "{s}{s}",
            .{ ca.fix_hint_base, extra },
        ) catch break :blk ca.fix_hint_base;
        break :blk combined;
    } else ca.fix_hint_base;

    diag_list.append(.{
        .rule_id = "PERF001",
        .severity = .warning,
        .message = ca.message,
        .span = span,
        .fix_hint = hint,
        .fix = dispatched.fix,
    }) catch return;
}

fn checkRedundantCheckout(job: *const Job, diag_list: *DiagnosticList) void {
    var checkout_without_path_count: u32 = 0;
    // Report on the first redundant checkout — the second one, since a single
    // path-less checkout is fine.
    var redundant_span: ?Span = null;

    for (job.steps) |*step| {
        if (step.uses) |action_ref| {
            const action_name = util.actionBaseName(action_ref.raw);
            if (std.mem.eql(u8, action_name, "actions/checkout")) {
                const has_path = if (step.with) |with| with.get("path") != null else false;
                if (!has_path) {
                    checkout_without_path_count += 1;
                    if (checkout_without_path_count == 2) redundant_span = spans.usesSpan(step);
                }
            }
        }
    }

    if (redundant_span) |span| {
        diag_list.append(.{
            .rule_id = "PERF002",
            .severity = .warning,
            .message = "Multiple actions/checkout steps without 'path' in the same job. This checks out to the same directory repeatedly.",
            .span = span,
            .fix_hint = "Remove redundant checkout steps or specify different 'path' values.",
        }) catch return;
    }
}

fn buildFailFastDisabledFix(diag_list: *DiagnosticList, entry_span: Span) ?Fix {
    const edits = fix_builder.deleteMappingEntry(
        diag_list.fixAllocator(),
        entry_span,
    ) orelse return null;

    return .{
        .description = "remove fail-fast: false from strategy",
        .safety = .unsafe,
        .edits = edits,
    };
}

fn checkFailFastDisabled(job: *const Job, diag_list: *DiagnosticList) void {
    const strategy = job.strategy orelse return;

    // fail_fast defaults to true; only flag when explicitly false
    if (strategy.fail_fast) return;

    var diag = diagnostics_mod.Diagnostic{
        .rule_id = "PERF003",
        .severity = .warning,
        .message = "Strategy has fail-fast: false. Failed matrix jobs will continue running, wasting CI resources.",
        .span = strategy.fail_fast_value_span orelse strategy.fail_fast_entry_span orelse job.span,
        .fix_hint = "Consider removing 'fail-fast: false' to cancel remaining jobs on first failure.",
    };
    if (strategy.fail_fast_entry_span) |entry_span| {
        diag.fix = buildFailFastDisabledFix(diag_list, entry_span);
    }

    diag_list.append(diag) catch return;
}

pub const rules = [_]Rule{
    .{
        .id = "PERF001",
        .name = "cache-not-used",
        .description = "Job uses a language setup action without caching enabled",
        .severity = .warning,
        .category = .performance,
        .check_job = checkCacheNotUsed,
    },
    .{
        .id = "PERF002",
        .name = "redundant-checkout",
        .description = "Multiple actions/checkout without path in the same job",
        .severity = .warning,
        .category = .performance,
        .check_job = checkRedundantCheckout,
    },
    .{
        .id = "PERF003",
        .name = "fail-fast-disabled",
        .description = "Strategy has fail-fast disabled, wasting CI resources on failures",
        .severity = .warning,
        .category = .performance,
        .check_job = checkFailFastDisabled,
    },
};

test "PERF001: detect missing cache for setup-node" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("actions/setup-node@v4") },
            Step{ .run = "npm test" },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("PERF001", diags.get(0).rule_id);
}

test "PERF001: no warning when cache input is set" {
    var with = workflow_types.StringMap.init(std.testing.allocator);
    defer with.deinit();
    try with.put("cache", "npm");

    const steps = [_]Step{
        Step{ .uses = ActionRef.parse("actions/setup-node@v4"), .with = with },
    };
    const job = Job{
        .id = "build",
        .steps = &steps,
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF001: no warning when actions/cache is present" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("actions/setup-node@v4") },
            Step{ .uses = ActionRef.parse("actions/cache@v3") },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF001: detect missing cache for setup-python" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("actions/setup-python@v5") },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
}

test "PERF001: detect missing cache for setup-go" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("actions/setup-go@v5") },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
}

test "PERF001: setup-go without with: attaches unsafe fix that adds a with block" {
    workspace.set(.{ .go_sum_present = true });
    defer workspace.clear();

    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/setup-go@v5"),
            .uses_key_col = 9,
            .uses_value_end_byte = 100,
        },
    };
    const job = Job{ .id = "build", .steps = &steps };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestExpectedNonNull;
    try std.testing.expectEqual(diagnostics_mod.FixSafety.unsafe, fix.safety);
    try std.testing.expectEqual(@as(usize, 1), fix.edits.len);
    try std.testing.expectEqual(@as(usize, 100), fix.edits[0].start_byte);
    try std.testing.expectEqual(@as(usize, 100), fix.edits[0].end_byte);
    try std.testing.expectEqualStrings("\n        with:\n          cache: true", fix.edits[0].replacement);
}

test "PERF001: setup-go without go.sum suppresses fix" {
    defer workspace.clear();
    workspace.clear(); // explicit: no go.sum in workspace

    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/setup-go@v5"),
            .uses_key_col = 9,
            .uses_value_end_byte = 100,
        },
    };
    const job = Job{ .id = "build", .steps = &steps };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "PERF001: setup-go with existing with: appends cache entry" {
    workspace.set(.{ .go_sum_present = true });
    defer workspace.clear();

    var with = workflow_types.StringMap.init(std.testing.allocator);
    defer with.deinit();
    try with.put("go-version", "1.21");

    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/setup-go@v5"),
            .with = with,
            .uses_key_col = 9,
            .uses_value_end_byte = 100,
            .with_last_entry_end_byte = 140,
        },
    };
    const job = Job{ .id = "build", .steps = &steps };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestExpectedNonNull;
    try std.testing.expectEqual(diagnostics_mod.FixSafety.unsafe, fix.safety);
    try std.testing.expectEqual(@as(usize, 1), fix.edits.len);
    try std.testing.expectEqual(@as(usize, 140), fix.edits[0].start_byte);
    try std.testing.expectEqual(@as(usize, 140), fix.edits[0].end_byte);
    try std.testing.expectEqualStrings("\n          cache: true", fix.edits[0].replacement);
}

test "PERF001: setup-go with empty cache: value skips fix to avoid duplicate key" {
    workspace.set(.{ .go_sum_present = true });
    defer workspace.clear();

    var with = workflow_types.StringMap.init(std.testing.allocator);
    defer with.deinit();
    try with.put("cache", "");

    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/setup-go@v5"),
            .with = with,
            .uses_key_col = 9,
            .uses_value_end_byte = 100,
            .with_last_entry_end_byte = 140,
        },
    };
    const job = Job{ .id = "build", .steps = &steps };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "PERF001: setup-node/setup-python do not receive autofix without lockfile" {
    defer workspace.clear();
    workspace.clear();

    const node_job = Job{
        .id = "build",
        .steps = &.{Step{
            .uses = ActionRef.parse("actions/setup-node@v4"),
            .uses_key_col = 9,
            .uses_value_end_byte = 100,
        }},
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&node_job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);

    diags.deinit();
    diags = DiagnosticList.init(std.testing.allocator);
    const python_job = Job{
        .id = "build",
        .steps = &.{Step{
            .uses = ActionRef.parse("actions/setup-python@v5"),
            .uses_key_col = 9,
            .uses_value_end_byte = 100,
        }},
    };
    checkCacheNotUsed(&python_job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "PERF001: setup-node fix populated when node_cache=npm" {
    workspace.set(.{ .node_cache = .npm });
    defer workspace.clear();

    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/setup-node@v4"),
            .uses_key_col = 9,
            .uses_value_end_byte = 100,
        },
    };
    const job = Job{ .id = "build", .steps = &steps };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings(
        \\add "cache: npm" to actions/setup-node step(s)
    , fix.description);
    try std.testing.expectEqual(@as(usize, 1), fix.edits.len);
    try std.testing.expectEqualStrings("\n        with:\n          cache: npm", fix.edits[0].replacement);
}

test "PERF001: setup-node fix uses pnpm when node_cache=pnpm" {
    workspace.set(.{ .node_cache = .pnpm });
    defer workspace.clear();

    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/setup-node@v4"),
            .uses_key_col = 9,
            .uses_value_end_byte = 100,
        },
    };
    const job = Job{ .id = "build", .steps = &steps };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("\n        with:\n          cache: pnpm", fix.edits[0].replacement);
}

test "PERF001: setup-node fix uses yarn when node_cache=yarn" {
    workspace.set(.{ .node_cache = .yarn });
    defer workspace.clear();

    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/setup-node@v4"),
            .uses_key_col = 9,
            .uses_value_end_byte = 100,
        },
    };
    const job = Job{ .id = "build", .steps = &steps };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    const fix = diags.get(0).fix orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("\n        with:\n          cache: yarn", fix.edits[0].replacement);
}

test "PERF001: setup-node ambiguous lockfiles surface fix_hint listing them" {
    const lockfiles = [_][]const u8{ "package-lock.json", "yarn.lock" };
    workspace.set(.{ .ambiguous_node_lockfiles = &lockfiles });
    defer workspace.clear();

    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/setup-node@v4"),
            .uses_key_col = 9,
            .uses_value_end_byte = 100,
        },
    };
    const job = Job{ .id = "build", .steps = &steps };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
    const hint = diags.get(0).fix_hint orelse return error.TestExpectedNonNull;
    try std.testing.expect(std.mem.indexOf(u8, hint, "package-lock.json") != null);
    try std.testing.expect(std.mem.indexOf(u8, hint, "yarn.lock") != null);
    try std.testing.expect(std.mem.indexOf(u8, hint, "node_cache_manager") != null);
}

test "PERF001: setup-python fix with python_cache=poetry" {
    workspace.set(.{ .python_cache = .poetry });
    defer workspace.clear();

    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/setup-python@v5"),
            .uses_key_col = 9,
            .uses_value_end_byte = 100,
        },
    };
    const job = Job{ .id = "build", .steps = &steps };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    const fix = diags.get(0).fix orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings(
        \\add "cache: poetry" to actions/setup-python step(s)
    , fix.description);
    try std.testing.expectEqualStrings("\n        with:\n          cache: poetry", fix.edits[0].replacement);
}

test "PERF001: setup-python fix with python_cache=pipenv" {
    workspace.set(.{ .python_cache = .pipenv });
    defer workspace.clear();

    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/setup-python@v5"),
            .uses_key_col = 9,
            .uses_value_end_byte = 100,
        },
    };
    const job = Job{ .id = "build", .steps = &steps };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    const fix = diags.get(0).fix orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("\n        with:\n          cache: pipenv", fix.edits[0].replacement);
}

test "PERF001: setup-python ambiguous lockfiles produce hint" {
    const lockfiles = [_][]const u8{ "poetry.lock", "Pipfile.lock" };
    workspace.set(.{ .ambiguous_python_lockfiles = &lockfiles });
    defer workspace.clear();

    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/setup-python@v5"),
            .uses_key_col = 9,
            .uses_value_end_byte = 100,
        },
    };
    const job = Job{ .id = "build", .steps = &steps };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    try std.testing.expect(diags.get(0).fix == null);
    const hint = diags.get(0).fix_hint orelse return error.TestExpectedNonNull;
    try std.testing.expect(std.mem.indexOf(u8, hint, "python_cache_manager") != null);
}

test "PERF001: setup-go with missing span skips fix" {
    workspace.set(.{ .go_sum_present = true });
    defer workspace.clear();

    const job = Job{
        .id = "build",
        .steps = &.{Step{ .uses = ActionRef.parse("actions/setup-go@v5") }},
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "PERF001: multiple setup-go steps in one job produce a single multi-edit fix" {
    workspace.set(.{ .go_sum_present = true });
    defer workspace.clear();

    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/setup-go@v5"),
            .uses_key_col = 9,
            .uses_value_end_byte = 50,
        },
        .{
            .uses = ActionRef.parse("actions/setup-go@v5"),
            .uses_key_col = 9,
            .uses_value_end_byte = 120,
        },
    };
    const job = Job{ .id = "build", .steps = &steps };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestExpectedNonNull;
    try std.testing.expectEqual(@as(usize, 2), fix.edits.len);
    try std.testing.expectEqual(@as(usize, 50), fix.edits[0].start_byte);
    try std.testing.expectEqual(@as(usize, 120), fix.edits[1].start_byte);
}

test "PERF001: autofix applied to YAML source adds cache: true to setup-go" {
    workspace.set(.{ .go_sum_present = true });
    defer workspace.clear();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/setup-go@v5
        \\        with:
        \\          go-version: '1.21'
        \\      - uses: actions/setup-go@v5
        \\
    ;

    const result = try test_support.lintAndFix(std.testing.allocator, source, .{ .job = &checkCacheNotUsed }, true);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.diagnostic_count);
    try std.testing.expectEqual(diagnostics_mod.FixSafety.unsafe, result.first_safety.?);
    try std.testing.expectEqual(@as(usize, 2), result.edits_applied);

    const cache_count = std.mem.count(u8, result.content, "cache: true");
    try std.testing.expectEqual(@as(usize, 2), cache_count);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "go-version: '1.21'") != null);
}

test "PERF001: setup-node autofix applied to YAML source with node_cache=npm" {
    workspace.set(.{ .node_cache = .npm });
    defer workspace.clear();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/setup-node@v4
        \\
    ;

    const result = try test_support.lintAndFix(std.testing.allocator, source, .{ .job = &checkCacheNotUsed }, true);
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(std.mem.indexOf(u8, result.content, "cache: npm") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "with:") != null);
}

test "PERF001: no warning for unrelated actions" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("actions/checkout@v4") },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF001: detect missing cache for setup-bun" {
    workspace.set(.{ .bun_lockfile_present = true });
    defer workspace.clear();

    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("oven-sh/setup-bun@v1") },
            Step{ .run = "bun install" },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("PERF001", diags.get(0).rule_id);
    try std.testing.expect(diags.get(0).fix == null);
    const msg = diags.get(0).message;
    try std.testing.expect(std.mem.indexOf(u8, msg, "oven-sh/setup-bun") != null);
}

test "PERF001: no warning for setup-bun when actions/cache is present" {
    workspace.set(.{ .bun_lockfile_present = true });
    defer workspace.clear();

    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("oven-sh/setup-bun@v1") },
            Step{ .uses = ActionRef.parse("actions/cache@v4") },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF001: setup-bun without bun lockfile extends hint" {
    defer workspace.clear();
    workspace.clear();

    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("oven-sh/setup-bun@v1") },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const hint = diags.get(0).fix_hint orelse return error.TestExpectedNonNull;
    try std.testing.expect(std.mem.indexOf(u8, hint, "no bun.lock or bun.lockb detected") != null);
}

test "PERF001: setup-uv without enable-cache input does not warn" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("astral-sh/setup-uv@v3") },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF001: setup-uv with enable-cache=true does not warn" {
    var with = workflow_types.StringMap.init(std.testing.allocator);
    defer with.deinit();
    try with.put("enable-cache", "true");

    const steps = [_]Step{
        Step{ .uses = ActionRef.parse("astral-sh/setup-uv@v3"), .with = with },
    };
    const job = Job{ .id = "build", .steps = &steps };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF001: setup-uv with enable-cache=false warns" {
    var with = workflow_types.StringMap.init(std.testing.allocator);
    defer with.deinit();
    try with.put("enable-cache", "false");

    const steps = [_]Step{
        Step{ .uses = ActionRef.parse("astral-sh/setup-uv@v3"), .with = with },
    };
    const job = Job{ .id = "build", .steps = &steps };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("PERF001", diags.get(0).rule_id);
    try std.testing.expect(diags.get(0).fix == null);
    const msg = diags.get(0).message;
    try std.testing.expect(std.mem.indexOf(u8, msg, "enable-cache") != null);
}

test "PERF001: setup-uv with enable-cache=false but actions/cache present does not warn" {
    var with = workflow_types.StringMap.init(std.testing.allocator);
    defer with.deinit();
    try with.put("enable-cache", "false");

    const steps = [_]Step{
        Step{ .uses = ActionRef.parse("astral-sh/setup-uv@v3"), .with = with },
        Step{ .uses = ActionRef.parse("actions/cache@v4") },
    };
    const job = Job{ .id = "build", .steps = &steps };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF002: detect redundant checkout" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("actions/checkout@v4") },
            Step{ .run = "echo hello" },
            Step{ .uses = ActionRef.parse("actions/checkout@v4") },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkRedundantCheckout(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("PERF002", diags.get(0).rule_id);
}

test "PERF002: no warning when path is specified" {
    var with = workflow_types.StringMap.init(std.testing.allocator);
    defer with.deinit();
    try with.put("path", "sub-repo");

    const steps = [_]Step{
        Step{ .uses = ActionRef.parse("actions/checkout@v4") },
        Step{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
    };
    const job = Job{
        .id = "build",
        .steps = &steps,
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkRedundantCheckout(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF002: no warning with single checkout" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("actions/checkout@v4") },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkRedundantCheckout(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF003: detect fail-fast false" {
    const job = Job{
        .id = "test",
        .strategy = .{ .fail_fast = false },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkFailFastDisabled(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("PERF003", diags.get(0).rule_id);
}

test "PERF003: attach unsafe autofix when removable span exists" {
    const job = Job{
        .id = "test",
        .strategy = .{
            .fail_fast = false,
            .fail_fast_value_span = Span{
                .start_line = 1,
                .start_col = 18,
                .end_line = 1,
                .end_col = 25,
                .start_byte = 17,
                .end_byte = 24,
            },
            .fail_fast_entry_span = Span{
                .start_line = 1,
                .start_col = 1,
                .end_line = 2,
                .end_col = 1,
                .start_byte = 0,
                .end_byte = 25,
            },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkFailFastDisabled(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(diagnostics_mod.FixSafety.unsafe, fix.safety);
    try std.testing.expectEqualStrings("remove fail-fast: false from strategy", fix.description);
    try std.testing.expectEqual(@as(usize, 1), fix.edits.len);
    try std.testing.expectEqual(@as(usize, 0), fix.edits[0].start_byte);
    try std.testing.expectEqual(@as(usize, 25), fix.edits[0].end_byte);
    try std.testing.expectEqualStrings("", fix.edits[0].replacement);
}

test "PERF003: no autofix without removable span" {
    const job = Job{
        .id = "test",
        .strategy = .{
            .fail_fast = false,
            .fail_fast_value_span = Span.point(1, 1, 0),
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkFailFastDisabled(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "PERF003: autofix removes fail-fast line from workflow source" {
    const fix_engine = @import("../fix/engine.zig");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      fail-fast: "false" # keep running
        \\      max-parallel: 2
        \\      matrix:
        \\        node: [18, 20]
        \\    steps:
        \\      - run: npm test
        \\
    ;

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var diags = DiagnosticList.init(alloc);
    defer diags.deinit();
    checkFailFastDisabled(&wf.jobs[0], &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix != null);

    const safe_fixes = try fix_engine.collectFixes(std.testing.allocator, diags.items.items, false);
    defer std.testing.allocator.free(safe_fixes);
    try std.testing.expectEqual(@as(usize, 0), safe_fixes.len);

    const all_fixes = try fix_engine.collectFixes(std.testing.allocator, diags.items.items, true);
    defer std.testing.allocator.free(all_fixes);
    try std.testing.expectEqual(@as(usize, 1), all_fixes.len);

    const result = try fix_engine.applyFixes(std.testing.allocator, source, all_fixes);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
    try std.testing.expectEqualStrings(
        \\name: CI
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      max-parallel: 2
        \\      matrix:
        \\        node: [18, 20]
        \\    steps:
        \\      - run: npm test
        \\
    ,
        result.content,
    );
}

test "PERF003: no warning when fail-fast is true (default)" {
    const job = Job{
        .id = "test",
        .strategy = .{},
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkFailFastDisabled(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF003: no warning without strategy" {
    const job = Job{ .id = "test" };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkFailFastDisabled(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF001: fixture harness applies expected fix" {
    const node_ambiguous_lockfiles = [_][]const u8{ "package-lock.json", "yarn.lock" };

    const Case = struct {
        name: []const u8,
        input_path: []const u8,
        expected_path: ?[]const u8,
        ctx: workspace.Context,
    };

    const cases = [_]Case{
        .{
            .name = "setup-node-npm",
            .input_path = "tests/fixtures/perf001-cache/setup-node-npm/input.yml",
            .expected_path = "tests/fixtures/perf001-cache/setup-node-npm/expected.yml",
            .ctx = .{ .node_cache = .npm },
        },
        .{
            .name = "setup-node-pnpm",
            .input_path = "tests/fixtures/perf001-cache/setup-node-pnpm/input.yml",
            .expected_path = "tests/fixtures/perf001-cache/setup-node-pnpm/expected.yml",
            .ctx = .{ .node_cache = .pnpm },
        },
        .{
            .name = "setup-python-poetry",
            .input_path = "tests/fixtures/perf001-cache/setup-python-poetry/input.yml",
            .expected_path = "tests/fixtures/perf001-cache/setup-python-poetry/expected.yml",
            .ctx = .{ .python_cache = .poetry },
        },
        .{
            .name = "setup-go-gosum",
            .input_path = "tests/fixtures/perf001-cache/setup-go-gosum/input.yml",
            .expected_path = "tests/fixtures/perf001-cache/setup-go-gosum/expected.yml",
            .ctx = .{ .go_sum_present = true },
        },
        .{
            .name = "setup-node-ambiguous",
            .input_path = "tests/fixtures/perf001-cache/setup-node-ambiguous/input.yml",
            .expected_path = null,
            .ctx = .{ .ambiguous_node_lockfiles = &node_ambiguous_lockfiles },
        },
        .{
            .name = "setup-bun-lock",
            .input_path = "tests/fixtures/perf001-cache/setup-bun-lock/input.yml",
            .expected_path = null,
            .ctx = .{ .bun_lockfile_present = true },
        },
        // #171: a flow `with:` has no safe append anchor, and an empty `with:`
        // would be duplicated by the insertion path.
        .{
            .name = "setup-node-flow-with",
            .input_path = "tests/fixtures/perf001-cache/setup-node-flow-with/input.yml",
            .expected_path = null,
            .ctx = .{ .node_cache = .npm },
        },
        .{
            .name = "setup-node-empty-with",
            .input_path = "tests/fixtures/perf001-cache/setup-node-empty-with/input.yml",
            .expected_path = null,
            .ctx = .{ .node_cache = .npm },
        },
        .{
            .name = "setup-uv-disabled",
            .input_path = "tests/fixtures/perf001-cache/setup-uv-disabled/input.yml",
            .expected_path = null,
            .ctx = .{},
        },
    };

    // Fixture paths are relative to the repo root. Tests run with cwd = repo
    // root under both `zig build test` and the local wrapper, so a runtime
    // read keeps this harness independent of the build-system embed-dir
    // wiring.
    const cwd = std.fs.cwd();

    for (cases) |case| {
        workspace.set(case.ctx);
        defer workspace.clear();

        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const input = cwd.readFileAlloc(alloc, case.input_path, 64 * 1024) catch |err| {
            std.debug.print("case '{s}': failed to read {s}: {s}\n", .{ case.name, case.input_path, @errorName(err) });
            return err;
        };

        const result = try test_support.lintAndFix(std.testing.allocator, input, .{ .job = &checkCacheNotUsed }, true);
        defer result.deinit(std.testing.allocator);

        try std.testing.expectEqual(@as(usize, 1), result.diagnostic_count);

        if (case.expected_path) |exp_path| {
            const expected = try cwd.readFileAlloc(alloc, exp_path, 64 * 1024);
            if (result.fix_count == 0) {
                std.debug.print("case '{s}': expected fix, got null\n", .{case.name});
                return error.TestExpectedFix;
            }
            std.testing.expectEqualStrings(expected, result.content) catch |err| {
                std.debug.print("case '{s}' output mismatch\n", .{case.name});
                return err;
            };
        } else {
            try std.testing.expectEqual(@as(usize, 0), result.fix_count);
        }
    }
}
