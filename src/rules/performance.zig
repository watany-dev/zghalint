const std = @import("std");
const engine = @import("engine.zig");
const diagnostics_mod = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_types = @import("../yaml/types.zig");
const util = @import("../util.zig");
const fix_builder = @import("../fix/builder.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const Step = engine.Step;
const Workflow = engine.Workflow;
const DiagnosticList = engine.DiagnosticList;
const Span = yaml_types.Span;
const ActionRef = workflow_types.ActionRef;
const Fix = diagnostics_mod.Fix;

/// Actions that set up language runtimes and support caching.
const CacheableSetup = struct {
    setup_action: []const u8,
    cache_key: []const u8,
};

const cacheable_setups = [_]CacheableSetup{
    .{ .setup_action = "actions/setup-node", .cache_key = "cache" },
    .{ .setup_action = "actions/setup-python", .cache_key = "cache" },
    .{ .setup_action = "actions/setup-go", .cache_key = "cache" },
};

// ── PERF001: Cache not used ──

fn checkCacheNotUsed(job: *const Job, diag_list: *DiagnosticList) void {
    inline for (cacheable_setups) |ca| {
        var uses_setup = false;
        var has_cache = false;

        for (job.steps) |step| {
            if (step.uses) |action_ref| {
                const action_name = util.actionBaseName(action_ref.raw);

                if (std.mem.eql(u8, action_name, ca.setup_action)) {
                    uses_setup = true;
                    // Check if the setup action itself has cache input set
                    if (step.with) |with| {
                        if (with.get(ca.cache_key)) |val| {
                            if (val.len > 0) {
                                has_cache = true;
                            }
                        }
                    }
                }

                if (std.mem.eql(u8, action_name, "actions/cache")) {
                    has_cache = true;
                }
            }
        }

        if (uses_setup and !has_cache) {
            diag_list.append(.{
                .rule_id = "PERF001",
                .severity = .warning,
                .message = "Job uses " ++ ca.setup_action ++ " without caching. Add actions/cache or set 'cache' input.",
                .span = Span.point(0, 0, 0),
                .fix_hint = "Add 'cache: true' to the setup action's 'with' inputs, or add a separate actions/cache step.",
            }) catch return;
        }
    }
}

// ── PERF002: Redundant checkout ──

fn checkRedundantCheckout(job: *const Job, diag_list: *DiagnosticList) void {
    var checkout_without_path_count: u32 = 0;

    for (job.steps) |step| {
        if (step.uses) |action_ref| {
            const action_name = util.actionBaseName(action_ref.raw);
            if (std.mem.eql(u8, action_name, "actions/checkout")) {
                const has_path = if (step.with) |with| with.get("path") != null else false;
                if (!has_path) {
                    checkout_without_path_count += 1;
                }
            }
        }
    }

    if (checkout_without_path_count > 1) {
        diag_list.append(.{
            .rule_id = "PERF002",
            .severity = .warning,
            .message = "Multiple actions/checkout steps without 'path' in the same job. This checks out to the same directory repeatedly.",
            .span = Span.point(0, 0, 0),
            .fix_hint = "Remove redundant checkout steps or specify different 'path' values.",
        }) catch return;
    }
}

// ── PERF003: fail-fast disabled ──

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
        .span = strategy.fail_fast_value_span orelse Span.point(0, 0, 0),
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

// ── Tests ──

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
    const yaml_parser_mod = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");
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

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

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
