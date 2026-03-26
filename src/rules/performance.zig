const std = @import("std");
const engine = @import("engine.zig");
const types = @import("../workflow/types.zig");
const Rule = engine.Rule;
const Job = engine.Job;
const Step = engine.Step;
const Workflow = engine.Workflow;
const DiagnosticList = engine.DiagnosticList;

/// Actions that set up language runtimes and support caching.
const CacheableAction = struct {
    setup_action: []const u8,
    cache_key: []const u8,
};

const cacheable_actions = [_]CacheableAction{
    .{ .setup_action = "actions/setup-node", .cache_key = "cache" },
    .{ .setup_action = "actions/setup-python", .cache_key = "cache" },
    .{ .setup_action = "actions/setup-go", .cache_key = "cache" },
};

// ── PERF001: Cache not used ──

fn checkCacheNotUsed(job: *const Job, diagnostics: *DiagnosticList) void {
    inline for (cacheable_actions) |ca| {
        var uses_setup = false;
        var has_cache = false;

        for (job.steps) |step| {
            if (step.uses) |action_ref| {
                const action_name = actionBaseName(action_ref.raw);

                if (std.mem.eql(u8, action_name, ca.setup_action)) {
                    uses_setup = true;
                    // Check if the setup action itself has cache: true in with
                    if (step.with) |with| {
                        if (with.get(ca.cache_key)) |val| {
                            if (std.mem.eql(u8, val, "true") or
                                std.mem.eql(u8, val, "npm") or
                                std.mem.eql(u8, val, "yarn") or
                                std.mem.eql(u8, val, "pnpm") or
                                std.mem.eql(u8, val, "pip") or
                                std.mem.eql(u8, val, "pipenv") or
                                std.mem.eql(u8, val, "poetry"))
                            {
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
            diagnostics.append(.{
                .rule_id = "PERF001",
                .severity = .warning,
                .message = "Job uses " ++ ca.setup_action ++ " without caching. Add actions/cache or set 'cache' input.",
                .fix_hint = "Add 'cache: true' to the setup action's 'with' inputs, or add a separate actions/cache step.",
            });
        }
    }
}

// ── PERF002: Redundant checkout ──

fn checkRedundantCheckout(job: *const Job, diagnostics: *DiagnosticList) void {
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
        diagnostics.append(.{
            .rule_id = "PERF002",
            .severity = .warning,
            .message = "Multiple actions/checkout steps without 'path' in the same job. This checks out to the same directory repeatedly.",
            .fix_hint = "Remove redundant checkout steps or specify different 'path' values.",
        });
    }
}

// ── PERF003: Large matrix without fail-fast ──

fn checkLargeMatrixFailFast(job: *const Job, diagnostics: *DiagnosticList) void {
    const strategy = job.strategy orelse return;
    const total = strategy.totalCombinations();
    if (total < 4) return;

    if (strategy.fail_fast) |ff| {
        if (ff == false) {
            diagnostics.append(.{
                .rule_id = "PERF003",
                .severity = .warning,
                .message = "Large matrix (4+ entries) with fail-fast: false. Failed jobs will waste CI resources.",
                .fix_hint = "Consider removing 'fail-fast: false' or reducing the matrix size.",
            });
        }
    }
}

/// Extract the base name (owner/repo) from an action reference string like "actions/checkout@v4".
fn actionBaseName(raw: []const u8) []const u8 {
    const before_at = if (std.mem.indexOf(u8, raw, "@")) |pos| raw[0..pos] else raw;
    return before_at;
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
        .name = "large-matrix-no-fail-fast",
        .description = "Large matrix with fail-fast disabled wastes CI resources",
        .severity = .warning,
        .category = .performance,
        .check_job = checkLargeMatrixFailFast,
    },
};

// ── Tests ──

test "PERF001: detect missing cache for setup-node" {
    const allocator = std.testing.allocator;
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = types.ActionRef.parse("actions/setup-node@v4") },
            Step{ .run = "npm test" },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("PERF001", diags.get(0).rule_id);
}

test "PERF001: no warning when cache input is set" {
    const allocator = std.testing.allocator;
    const keys = [_][]const u8{"cache"};
    const vals = [_][]const u8{"npm"};
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{
                .uses = types.ActionRef.parse("actions/setup-node@v4"),
                .with = .{ .keys = &keys, .values = &vals },
            },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF001: no warning when actions/cache is present" {
    const allocator = std.testing.allocator;
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = types.ActionRef.parse("actions/setup-node@v4") },
            Step{ .uses = types.ActionRef.parse("actions/cache@v3") },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF001: detect missing cache for setup-python" {
    const allocator = std.testing.allocator;
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = types.ActionRef.parse("actions/setup-python@v5") },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
}

test "PERF001: detect missing cache for setup-go" {
    const allocator = std.testing.allocator;
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = types.ActionRef.parse("actions/setup-go@v5") },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkCacheNotUsed(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
}

test "PERF002: detect redundant checkout" {
    const allocator = std.testing.allocator;
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = types.ActionRef.parse("actions/checkout@v4") },
            Step{ .run = "echo hello" },
            Step{ .uses = types.ActionRef.parse("actions/checkout@v4") },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkRedundantCheckout(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("PERF002", diags.get(0).rule_id);
}

test "PERF002: no warning when path is specified" {
    const allocator = std.testing.allocator;
    const keys = [_][]const u8{"path"};
    const vals = [_][]const u8{"sub-repo"};
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = types.ActionRef.parse("actions/checkout@v4") },
            Step{
                .uses = types.ActionRef.parse("actions/checkout@v4"),
                .with = .{ .keys = &keys, .values = &vals },
            },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkRedundantCheckout(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF002: no warning with single checkout" {
    const allocator = std.testing.allocator;
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = types.ActionRef.parse("actions/checkout@v4") },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkRedundantCheckout(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF003: detect large matrix with fail-fast false" {
    const allocator = std.testing.allocator;
    const matrix_entries = [_]types.MatrixEntry{
        .{
            .key = "os",
            .values = &.{ "ubuntu-latest", "windows-latest" },
        },
        .{
            .key = "node",
            .values = &.{ "18", "20" },
        },
    };
    const job = Job{
        .id = "test",
        .strategy = .{
            .matrix = &matrix_entries,
            .fail_fast = false,
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkLargeMatrixFailFast(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("PERF003", diags.get(0).rule_id);
}

test "PERF003: no warning for small matrix" {
    const allocator = std.testing.allocator;
    const matrix_entries = [_]types.MatrixEntry{
        .{
            .key = "os",
            .values = &.{ "ubuntu-latest", "windows-latest" },
        },
    };
    const job = Job{
        .id = "test",
        .strategy = .{
            .matrix = &matrix_entries,
            .fail_fast = false,
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkLargeMatrixFailFast(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF003: no warning when fail-fast is not false" {
    const allocator = std.testing.allocator;
    const matrix_entries = [_]types.MatrixEntry{
        .{
            .key = "os",
            .values = &.{ "ubuntu-latest", "windows-latest" },
        },
        .{
            .key = "node",
            .values = &.{ "18", "20" },
        },
    };
    const job = Job{
        .id = "test",
        .strategy = .{
            .matrix = &matrix_entries,
            .fail_fast = true,
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkLargeMatrixFailFast(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERF003: no warning when fail-fast is default (null)" {
    const allocator = std.testing.allocator;
    const matrix_entries = [_]types.MatrixEntry{
        .{
            .key = "os",
            .values = &.{ "ubuntu-latest", "windows-latest" },
        },
        .{
            .key = "node",
            .values = &.{ "18", "20" },
        },
    };
    const job = Job{
        .id = "test",
        .strategy = .{
            .matrix = &matrix_entries,
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkLargeMatrixFailFast(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}
