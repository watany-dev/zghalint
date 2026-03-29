const std = @import("std");
const engine = @import("engine.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_types = @import("../yaml/types.zig");
const diagnostics_mod = @import("../diagnostics.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const Step = engine.Step;
const Workflow = engine.Workflow;
const DiagnosticList = engine.DiagnosticList;
const Span = yaml_types.Span;
const ActionRef = workflow_types.ActionRef;
const Fix = diagnostics_mod.Fix;
const Edit = diagnostics_mod.Edit;
const FixSafety = diagnostics_mod.FixSafety;

// ── BP001: Missing timeout-minutes ──

fn checkMissingTimeout(job: *const Job, diag_list: *DiagnosticList) void {
    if (job.timeout_minutes != null) return;

    var fix: ?Fix = null;

    // Generate fix only when we have real position info (start_col >= 1, since yaml parser is 1-based)
    if (job.span.start_col >= 1) {
        const indent: usize = @intCast(job.span.start_col - 1);
        const prefix = "timeout-minutes: 30\n";
        const text_len = prefix.len + indent;

        const replacement = diag_list.allocator.alloc(u8, text_len) catch null;
        const edits = diag_list.allocator.alloc(Edit, 1) catch null;

        if (replacement != null and edits != null) {
            @memcpy(replacement.?[0..prefix.len], prefix);
            @memset(replacement.?[prefix.len..], ' ');

            edits.?[0] = .{
                .start_byte = job.span.start_byte,
                .end_byte = job.span.start_byte,
                .replacement = replacement.?,
            };
            fix = .{
                .description = "Add timeout-minutes: 30",
                .safety = .safe,
                .edits = edits.?,
            };
        }
    }

    diag_list.append(.{
        .rule_id = "BP001",
        .severity = .warning,
        .message = "Job is missing 'timeout-minutes'. Default timeout is 6 hours, which is usually too long.",
        .span = job.span,
        .fix_hint = "Add 'timeout-minutes' to the job (e.g., timeout-minutes: 30).",
        .fix = fix,
    }) catch return;
}

// ── BP002: Missing step name ──

fn checkMissingStepName(step: *const Step, diag_list: *DiagnosticList) void {
    if (step.name == null) {
        diag_list.append(.{
            .rule_id = "BP002",
            .severity = .info,
            .message = "Step is missing a 'name' field. Named steps improve workflow readability.",
            .span = Span.point(0, 0, 0),
            .fix_hint = "Add a descriptive 'name' to this step.",
        }) catch return;
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

fn checkDeprecatedAction(step: *const Step, diag_list: *DiagnosticList) void {
    const action_ref = step.uses orelse return;
    if (action_ref.is_local or action_ref.is_docker) return;

    const action_name = actionBaseName(action_ref.raw);
    const version = action_ref.ref orelse return;

    for (deprecated_actions) |dep| {
        if (std.mem.eql(u8, action_name, dep.action) and std.mem.eql(u8, version, dep.version)) {
            diag_list.append(.{
                .rule_id = "BP003",
                .severity = .warning,
                .message = "Using deprecated action version. Consider upgrading.",
                .span = Span.point(0, 0, 0),
                .fix_hint = "Upgrade to a newer version.",
            }) catch return;
            return;
        }
    }
}

// ── BP004: Cross-platform shell not specified ──

fn checkCrossPlatformShell(job: *const Job, diag_list: *DiagnosticList) void {
    if (!hasWindowsTarget(job)) return;

    for (job.steps) |step| {
        if (step.run != null and step.shell == null) {
            diag_list.append(.{
                .rule_id = "BP004",
                .severity = .warning,
                .message = "Step with 'run' does not specify 'shell' in a job targeting Windows. Default shells differ across platforms.",
                .span = Span.point(0, 0, 0),
                .fix_hint = "Add 'shell: bash' or 'shell: pwsh' to ensure consistent behavior.",
            }) catch return;
        }
    }
}

fn hasWindowsTarget(job: *const Job) bool {
    if (job.runs_on) |runs_on| {
        if (containsWindows(runs_on)) return true;
    }
    return false;
}

fn containsWindows(s: []const u8) bool {
    if (s.len < 7) return false;
    var i: usize = 0;
    while (i + 7 <= s.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(s[i .. i + 7], "windows")) return true;
    }
    return false;
}

// ── BP005: Push trigger without concurrency ──

fn checkPushConcurrency(wf: *const Workflow, diag_list: *DiagnosticList) void {
    var has_push = false;
    for (wf.on.events) |event| {
        if (event.event == .push) {
            has_push = true;
            break;
        }
    }

    if (has_push and wf.concurrency == null) {
        diag_list.append(.{
            .rule_id = "BP005",
            .severity = .info,
            .message = "Workflow has 'push' trigger but no 'concurrency' setting. Rapid pushes may queue redundant runs.",
            .span = Span.point(0, 0, 0),
            .fix_hint = "Add a 'concurrency' group to cancel or queue redundant workflow runs.",
        }) catch return;
    }
}

fn actionBaseName(raw: []const u8) []const u8 {
    return if (std.mem.indexOf(u8, raw, "@")) |pos| raw[0..pos] else raw;
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

fn makeEmptyTrigger() workflow_types.Trigger {
    return .{ .events = &.{} };
}

test "BP001: detect missing timeout-minutes" {
    const job = Job{ .id = "build" };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkMissingTimeout(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("BP001", diags.get(0).rule_id);
}

test "BP001: no fix when span has no position info" {
    const job = Job{ .id = "build" };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkMissingTimeout(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "BP001: no warning when timeout is set" {
    const job = Job{ .id = "build", .timeout_minutes = 30 };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkMissingTimeout(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP001: autofix generated with real span" {
    // Use arena to avoid leaks from fix allocations
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Simulate a job at column 5 (1-based), byte offset 20
    const job = Job{
        .id = "build",
        .span = .{
            .start_line = 4,
            .start_col = 5,
            .end_line = 6,
            .end_col = 10,
            .start_byte = 20,
            .end_byte = 80,
        },
    };
    var diags = DiagnosticList.init(alloc);
    checkMissingTimeout(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const d = diags.get(0);
    try std.testing.expect(d.fix != null);

    const fix = d.fix.?;
    try std.testing.expectEqualStrings("Add timeout-minutes: 30", fix.description);
    try std.testing.expect(fix.safety == .safe);
    try std.testing.expectEqual(@as(usize, 1), fix.edits.len);

    const edit = fix.edits[0];
    // Insertion at start_byte
    try std.testing.expectEqual(@as(usize, 20), edit.start_byte);
    try std.testing.expectEqual(@as(usize, 20), edit.end_byte);
    // Replacement: "timeout-minutes: 30\n" + 4 spaces (start_col 5 - 1)
    try std.testing.expectEqualStrings("timeout-minutes: 30\n    ", edit.replacement);
}

test "BP001: autofix applied to YAML source" {
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
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\
    ;

    // Parse YAML → Workflow
    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

    // Run rule
    var diags = DiagnosticList.init(alloc);
    checkMissingTimeout(&wf.jobs[0], &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestUnexpectedResult;

    // Apply fix
    const fixes = [_]Fix{fix};
    const result = try fix_engine.applyFixes(std.testing.allocator, source, &fixes);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
    // Verify the fixed source contains timeout-minutes
    try std.testing.expect(std.mem.indexOf(u8, result.content, "timeout-minutes: 30") != null);
    // Verify the original content is preserved
    try std.testing.expect(std.mem.indexOf(u8, result.content, "runs-on: ubuntu-latest") != null);
    // Verify timeout appears before runs-on
    const timeout_pos = std.mem.indexOf(u8, result.content, "timeout-minutes: 30").?;
    const runs_on_pos = std.mem.indexOf(u8, result.content, "runs-on: ubuntu-latest").?;
    try std.testing.expect(timeout_pos < runs_on_pos);
}

test "BP002: detect missing step name" {
    const step = Step{ .run = "echo hello" };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkMissingStepName(&step, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("BP002", diags.get(0).rule_id);
}

test "BP002: no warning when name is present" {
    const step = Step{ .name = "Run tests", .run = "npm test" };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkMissingStepName(&step, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP003: detect deprecated checkout v1" {
    const step = Step{ .uses = ActionRef.parse("actions/checkout@v1") };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkDeprecatedAction(&step, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("BP003", diags.get(0).rule_id);
}

test "BP003: detect deprecated checkout v2" {
    const step = Step{ .uses = ActionRef.parse("actions/checkout@v2") };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkDeprecatedAction(&step, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
}

test "BP003: no warning for current version" {
    const step = Step{ .uses = ActionRef.parse("actions/checkout@v4") };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkDeprecatedAction(&step, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP003: no warning for local actions" {
    const step = Step{ .uses = ActionRef.parse("./local-action") };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkDeprecatedAction(&step, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP004: detect missing shell with windows runs-on" {
    const job = Job{
        .id = "test",
        .runs_on = "windows-latest",
        .steps = &.{
            Step{ .name = "Build", .run = "make build" },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCrossPlatformShell(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("BP004", diags.get(0).rule_id);
}

test "BP004: no warning when shell is specified" {
    const job = Job{
        .id = "test",
        .runs_on = "windows-latest",
        .steps = &.{
            Step{ .name = "Build", .run = "make build", .shell = "bash" },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCrossPlatformShell(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP004: no warning without windows" {
    const job = Job{
        .id = "test",
        .runs_on = "ubuntu-latest",
        .steps = &.{
            Step{ .name = "Build", .run = "make build" },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCrossPlatformShell(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP005: detect push without concurrency" {
    const events = [_]workflow_types.EventConfig{
        .{ .event = .push, .name = "push" },
    };
    const wf = Workflow{
        .on = .{ .events = &events },
        .jobs = &.{},
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPushConcurrency(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("BP005", diags.get(0).rule_id);
}

test "BP005: no warning when concurrency is set" {
    const events = [_]workflow_types.EventConfig{
        .{ .event = .push, .name = "push" },
    };
    const wf = Workflow{
        .on = .{ .events = &events },
        .concurrency = .{ .group = "ci-${{ github.ref }}", .cancel_in_progress = true },
        .jobs = &.{},
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPushConcurrency(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP005: no warning without push trigger" {
    const events = [_]workflow_types.EventConfig{
        .{ .event = .pull_request, .name = "pull_request" },
    };
    const wf = Workflow{
        .on = .{ .events = &events },
        .jobs = &.{},
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPushConcurrency(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}
