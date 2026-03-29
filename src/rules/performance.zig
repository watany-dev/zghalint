const std = @import("std");
const engine = @import("engine.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_types = @import("../yaml/types.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const Step = engine.Step;
const Workflow = engine.Workflow;
const DiagnosticList = engine.DiagnosticList;
const Span = yaml_types.Span;
const ActionRef = workflow_types.ActionRef;

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
                const action_name = actionBaseName(action_ref.raw);

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
            const action_name = actionBaseName(action_ref.raw);
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

fn checkFailFastDisabled(job: *const Job, diag_list: *DiagnosticList) void {
    const strategy = job.strategy orelse return;

    // fail_fast defaults to true; only flag when explicitly false
    if (strategy.fail_fast) return;

    diag_list.append(.{
        .rule_id = "PERF003",
        .severity = .warning,
        .message = "Strategy has fail-fast: false. Failed matrix jobs will continue running, wasting CI resources.",
        .span = Span.point(0, 0, 0),
        .fix_hint = "Consider removing 'fail-fast: false' to cancel remaining jobs on first failure.",
    }) catch return;
}

/// Extract the base name (owner/repo) from an action reference string like "actions/checkout@v4".
fn actionBaseName(raw: []const u8) []const u8 {
    return if (std.mem.indexOf(u8, raw, "@")) |pos| raw[0..pos] else raw;
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
