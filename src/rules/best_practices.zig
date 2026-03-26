const std = @import("std");
const engine = @import("engine.zig");
const types = @import("../workflow/types.zig");
const Rule = engine.Rule;
const Job = engine.Job;
const Step = engine.Step;
const Workflow = engine.Workflow;
const DiagnosticList = engine.DiagnosticList;

// ── BP001: Missing timeout-minutes ──

fn checkMissingTimeout(job: *const Job, diagnostics: *DiagnosticList) void {
    if (job.timeout_minutes == null) {
        diagnostics.append(.{
            .rule_id = "BP001",
            .severity = .warning,
            .message = "Job is missing 'timeout-minutes'. Default timeout is 6 hours, which is usually too long.",
            .fix_hint = "Add 'timeout-minutes' to the job (e.g., timeout-minutes: 30).",
        });
    }
}

// ── BP002: Missing step name ──

fn checkMissingStepName(step: *const Step, diagnostics: *DiagnosticList) void {
    if (step.name == null) {
        diagnostics.append(.{
            .rule_id = "BP002",
            .severity = .info,
            .message = "Step is missing a 'name' field. Named steps improve workflow readability.",
            .fix_hint = "Add a descriptive 'name' to this step.",
        });
    }
}

// ── BP003: Deprecated action version ──

const DeprecatedAction = struct {
    action: []const u8,
    version: []const u8,
    replacement: []const u8,
};

const deprecated_actions = [_]DeprecatedAction{
    .{ .action = "actions/checkout", .version = "v1", .replacement = "v4" },
    .{ .action = "actions/checkout", .version = "v2", .replacement = "v4" },
    .{ .action = "actions/checkout", .version = "v3", .replacement = "v4" },
    .{ .action = "actions/setup-node", .version = "v1", .replacement = "v4" },
    .{ .action = "actions/setup-node", .version = "v2", .replacement = "v4" },
    .{ .action = "actions/setup-node", .version = "v3", .replacement = "v4" },
    .{ .action = "actions/setup-python", .version = "v1", .replacement = "v5" },
    .{ .action = "actions/setup-python", .version = "v2", .replacement = "v5" },
    .{ .action = "actions/setup-python", .version = "v3", .replacement = "v5" },
    .{ .action = "actions/setup-python", .version = "v4", .replacement = "v5" },
    .{ .action = "actions/setup-go", .version = "v1", .replacement = "v5" },
    .{ .action = "actions/setup-go", .version = "v2", .replacement = "v5" },
    .{ .action = "actions/setup-go", .version = "v3", .replacement = "v5" },
    .{ .action = "actions/setup-java", .version = "v1", .replacement = "v4" },
    .{ .action = "actions/setup-java", .version = "v2", .replacement = "v4" },
    .{ .action = "actions/setup-java", .version = "v3", .replacement = "v4" },
    .{ .action = "actions/upload-artifact", .version = "v1", .replacement = "v4" },
    .{ .action = "actions/upload-artifact", .version = "v2", .replacement = "v4" },
    .{ .action = "actions/upload-artifact", .version = "v3", .replacement = "v4" },
    .{ .action = "actions/download-artifact", .version = "v1", .replacement = "v4" },
    .{ .action = "actions/download-artifact", .version = "v2", .replacement = "v4" },
    .{ .action = "actions/download-artifact", .version = "v3", .replacement = "v4" },
    .{ .action = "actions/cache", .version = "v1", .replacement = "v4" },
    .{ .action = "actions/cache", .version = "v2", .replacement = "v4" },
};

fn checkDeprecatedAction(step: *const Step, diagnostics: *DiagnosticList) void {
    const action_ref = step.uses orelse return;
    if (action_ref.is_local or action_ref.is_docker) return;

    const action_name = actionBaseName(action_ref.raw);
    const version = action_ref.ref orelse return;

    for (deprecated_actions) |dep| {
        if (std.mem.eql(u8, action_name, dep.action) and std.mem.eql(u8, version, dep.version)) {
            diagnostics.append(.{
                .rule_id = "BP003",
                .severity = .warning,
                .message = "Using deprecated action version. Consider upgrading.",
                .fix_hint = "Upgrade to a newer version.",
            });
            return;
        }
    }
}

// ── BP004: Cross-platform shell not specified ──

fn checkCrossPlatformShell(job: *const Job, diagnostics: *DiagnosticList) void {
    if (!hasWindowsInMatrix(job)) return;

    for (job.steps) |step| {
        if (step.run != null and step.shell == null) {
            diagnostics.append(.{
                .rule_id = "BP004",
                .severity = .warning,
                .message = "Step with 'run' does not specify 'shell' in a job targeting Windows. Default shells differ across platforms.",
                .fix_hint = "Add 'shell: bash' or 'shell: pwsh' to ensure consistent behavior.",
            });
        }
    }
}

fn hasWindowsInMatrix(job: *const Job) bool {
    // Check runs-on directly
    if (job.runs_on) |runs_on| {
        if (containsWindows(runs_on)) return true;
    }

    // Check matrix values
    const strategy = job.strategy orelse return false;
    const entries = strategy.matrix orelse return false;
    for (entries) |entry| {
        for (entry.values) |val| {
            if (containsWindows(val)) return true;
        }
    }
    return false;
}

fn containsWindows(s: []const u8) bool {
    // Case-insensitive check for "windows"
    if (s.len < 7) return false;
    var i: usize = 0;
    while (i + 7 <= s.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(s[i .. i + 7], "windows")) return true;
    }
    return false;
}

// ── BP005: Push trigger without concurrency ──

fn checkPushConcurrency(wf: *const Workflow, diagnostics: *DiagnosticList) void {
    var has_push = false;
    for (wf.on.events) |event| {
        if (event.event == .push) {
            has_push = true;
            break;
        }
    }

    if (has_push and wf.concurrency == null) {
        diagnostics.append(.{
            .rule_id = "BP005",
            .severity = .info,
            .message = "Workflow has 'push' trigger but no 'concurrency' setting. Rapid pushes may queue redundant runs.",
            .fix_hint = "Add a 'concurrency' group to cancel or queue redundant workflow runs.",
        });
    }
}

fn actionBaseName(raw: []const u8) []const u8 {
    const before_at = if (std.mem.indexOf(u8, raw, "@")) |pos| raw[0..pos] else raw;
    return before_at;
}

pub const rules = [_]Rule{
    .{
        .id = "BP001",
        .name = "missing-timeout",
        .description = "Job is missing timeout-minutes (default 6 hours is too long)",
        .severity = .warning,
        .category = .best_practice,
        .check_job = checkMissingTimeout,
    },
    .{
        .id = "BP002",
        .name = "missing-step-name",
        .description = "Step is missing a name field",
        .severity = .info,
        .category = .best_practice,
        .check_step = checkMissingStepName,
    },
    .{
        .id = "BP003",
        .name = "deprecated-action-version",
        .description = "Using a known deprecated action version",
        .severity = .warning,
        .category = .best_practice,
        .check_step = checkDeprecatedAction,
    },
    .{
        .id = "BP004",
        .name = "cross-platform-shell",
        .description = "Run step without shell in a Windows-targeting job",
        .severity = .warning,
        .category = .best_practice,
        .check_job = checkCrossPlatformShell,
    },
    .{
        .id = "BP005",
        .name = "push-without-concurrency",
        .description = "Push trigger without concurrency setting",
        .severity = .info,
        .category = .best_practice,
        .check_workflow = checkPushConcurrency,
    },
};

// ── Tests ──

test "BP001: detect missing timeout-minutes" {
    const allocator = std.testing.allocator;
    const job = Job{ .id = "build" };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkMissingTimeout(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("BP001", diags.get(0).rule_id);
}

test "BP001: no warning when timeout is set" {
    const allocator = std.testing.allocator;
    const job = Job{ .id = "build", .timeout_minutes = 30 };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkMissingTimeout(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP002: detect missing step name" {
    const allocator = std.testing.allocator;
    const step = Step{ .run = "echo hello" };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkMissingStepName(&step, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("BP002", diags.get(0).rule_id);
}

test "BP002: no warning when name is present" {
    const allocator = std.testing.allocator;
    const step = Step{ .name = "Run tests", .run = "npm test" };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkMissingStepName(&step, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP003: detect deprecated checkout v1" {
    const allocator = std.testing.allocator;
    const step = Step{ .uses = types.ActionRef.parse("actions/checkout@v1") };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkDeprecatedAction(&step, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("BP003", diags.get(0).rule_id);
}

test "BP003: detect deprecated checkout v2" {
    const allocator = std.testing.allocator;
    const step = Step{ .uses = types.ActionRef.parse("actions/checkout@v2") };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkDeprecatedAction(&step, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
}

test "BP003: no warning for current version" {
    const allocator = std.testing.allocator;
    const step = Step{ .uses = types.ActionRef.parse("actions/checkout@v4") };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkDeprecatedAction(&step, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP003: no warning for local actions" {
    const allocator = std.testing.allocator;
    const step = Step{ .uses = types.ActionRef.parse("./local-action") };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkDeprecatedAction(&step, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP004: detect missing shell with windows matrix" {
    const allocator = std.testing.allocator;
    const matrix_entries = [_]types.MatrixEntry{
        .{
            .key = "os",
            .values = &.{ "ubuntu-latest", "windows-latest" },
        },
    };
    const job = Job{
        .id = "test",
        .strategy = .{ .matrix = &matrix_entries },
        .steps = &.{
            Step{ .name = "Build", .run = "make build" },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkCrossPlatformShell(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("BP004", diags.get(0).rule_id);
}

test "BP004: no warning when shell is specified" {
    const allocator = std.testing.allocator;
    const matrix_entries = [_]types.MatrixEntry{
        .{
            .key = "os",
            .values = &.{ "ubuntu-latest", "windows-latest" },
        },
    };
    const job = Job{
        .id = "test",
        .strategy = .{ .matrix = &matrix_entries },
        .steps = &.{
            Step{ .name = "Build", .run = "make build", .shell = "bash" },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkCrossPlatformShell(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP004: no warning without windows" {
    const allocator = std.testing.allocator;
    const job = Job{
        .id = "test",
        .runs_on = "ubuntu-latest",
        .steps = &.{
            Step{ .name = "Build", .run = "make build" },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkCrossPlatformShell(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP004: detect windows in runs-on" {
    const allocator = std.testing.allocator;
    const job = Job{
        .id = "test",
        .runs_on = "windows-latest",
        .steps = &.{
            Step{ .name = "Build", .run = "make build" },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkCrossPlatformShell(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
}

test "BP005: detect push without concurrency" {
    const allocator = std.testing.allocator;
    const events = [_]types.EventConfig{
        .{ .event = .push, .name = "push" },
    };
    const wf = Workflow{
        .on = .{ .events = &events },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkPushConcurrency(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("BP005", diags.get(0).rule_id);
}

test "BP005: no warning when concurrency is set" {
    const allocator = std.testing.allocator;
    const events = [_]types.EventConfig{
        .{ .event = .push, .name = "push" },
    };
    const wf = Workflow{
        .on = .{ .events = &events },
        .concurrency = .{ .group = "ci-${{ github.ref }}", .cancel_in_progress = true },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkPushConcurrency(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP005: no warning without push trigger" {
    const allocator = std.testing.allocator;
    const events = [_]types.EventConfig{
        .{ .event = .pull_request, .name = "pull_request" },
    };
    const wf = Workflow{
        .on = .{ .events = &events },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkPushConcurrency(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}
