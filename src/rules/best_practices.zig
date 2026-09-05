const std = @import("std");
const test_support = @import("../test_support.zig");
const engine = @import("engine.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_types = @import("../yaml/types.zig");
const diagnostics_mod = @import("../diagnostics.zig");
const fix_builder = @import("../fix/builder.zig");
const util = @import("../util.zig");
const spans = @import("spans.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const Step = engine.Step;
const Workflow = engine.Workflow;
const DiagnosticList = engine.DiagnosticList;
const Span = yaml_types.Span;
const ActionRef = workflow_types.ActionRef;
const Diagnostic = diagnostics_mod.Diagnostic;
const Fix = diagnostics_mod.Fix;
const FixSafety = diagnostics_mod.FixSafety;

// ── BP001: Missing timeout-minutes ──

fn checkMissingTimeout(job: *const Job, diag_list: *DiagnosticList) void {
    if (job.timeout_minutes != null or job.timeout_minutes_specified) return;

    var fix: ?Fix = null;
    if (job.span.start_col >= 1) {
        const indent: u32 = job.span.start_col - 1;
        if (fix_builder.insertMappingEntryBefore(
            diag_list.fixAllocator(),
            .{ .byte = job.span.start_byte, .indent = indent },
            "timeout-minutes",
            "30",
        )) |edits| {
            fix = .{
                .description = "Add timeout-minutes: 30",
                .safety = .safe,
                .edits = edits,
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

fn generateStepName(allocator: std.mem.Allocator, step: *const Step) ?[]const u8 {
    if (step.uses) |ref| {
        if (ref.is_local or ref.is_docker) return null;
        const repo = ref.repo orelse return null;
        return util.stepNameFromRepo(allocator, repo);
    }
    if (step.run) |run| {
        return util.stepNameFromRun(allocator, run);
    }
    return null;
}

fn buildStepNameFix(list: *DiagnosticList, step: *const Step) ?Fix {
    const insert_byte = step.uses_key_start_byte orelse return null;
    const key_col = step.uses_key_col orelse return null;
    if (key_col < 1) return null;

    const fix_alloc = list.fixAllocator();
    const generated = generateStepName(fix_alloc, step) orelse return null;
    const indent: u32 = key_col - 1;

    const edits = fix_builder.insertMappingEntryBefore(
        fix_alloc,
        .{ .byte = insert_byte, .indent = indent },
        "name",
        generated,
    ) orelse return null;

    return .{
        .description = "Add step name",
        .safety = .safe,
        .edits = edits,
    };
}

fn checkMissingStepName(step: *const Step, diag_list: *DiagnosticList) void {
    if (step.name != null) return;

    var diag = Diagnostic{
        .rule_id = "BP002",
        .severity = .info,
        .message = "Step is missing a 'name' field. Named steps improve workflow readability.",
        .span = step.span,
        .fix_hint = "Add a descriptive 'name' to this step.",
    };
    diag.fix = buildStepNameFix(diag_list, step);
    diag_list.append(diag) catch return;
}

// ── BP003: Deprecated action version ──

const DeprecatedAction = struct {
    action: []const u8,
    /// Major versions strictly below this are deprecated (`v1` .. `vN-1`).
    deprecated_below: u8,
    replacement: []const u8,
};

const deprecated_actions = [_]DeprecatedAction{
    .{ .action = "actions/checkout", .deprecated_below = 4, .replacement = "v4" },
    .{ .action = "actions/setup-node", .deprecated_below = 4, .replacement = "v4" },
    .{ .action = "actions/setup-python", .deprecated_below = 5, .replacement = "v5" },
    .{ .action = "actions/setup-go", .deprecated_below = 4, .replacement = "v5" },
    .{ .action = "actions/setup-java", .deprecated_below = 4, .replacement = "v4" },
    .{ .action = "actions/upload-artifact", .deprecated_below = 4, .replacement = "v4" },
    .{ .action = "actions/download-artifact", .deprecated_below = 4, .replacement = "v4" },
    .{ .action = "actions/cache", .deprecated_below = 3, .replacement = "v4" },
};

/// Major version of a bare `vN` tag (single digit, as every deprecated tag is).
fn majorTag(version: []const u8) ?u8 {
    if (version.len != 2 or version[0] != 'v') return null;
    if (!std.ascii.isDigit(version[1])) return null;
    return version[1] - '0';
}

fn buildDeprecatedActionFix(
    list: *DiagnosticList,
    step: *const Step,
    old_version: []const u8,
    new_version: []const u8,
) ?Fix {
    const end_byte = step.uses_value_end_byte orelse return null;
    const style = step.uses_value_style orelse return null;

    const quote_offset: usize = switch (style) {
        .plain => 0,
        .single_quoted, .double_quoted => 1,
        .literal, .folded => return null,
    };

    if (end_byte < quote_offset + old_version.len) return null;

    const version_end = end_byte - quote_offset;
    const version_start = version_end - old_version.len;

    const version_span = yaml_types.Span{
        .start_line = 0,
        .start_col = 0,
        .end_line = 0,
        .end_col = 0,
        .start_byte = version_start,
        .end_byte = version_end,
    };
    const edits = fix_builder.replaceScalar(
        list.fixAllocator(),
        version_span,
        .plain,
        new_version,
    ) orelse return null;

    return .{
        .description = "Upgrade deprecated action version",
        .safety = .safe,
        .edits = edits,
    };
}

fn checkDeprecatedAction(step: *const Step, diag_list: *DiagnosticList) void {
    const action_ref = step.uses orelse return;
    if (action_ref.is_local or action_ref.is_docker) return;

    const action_name = util.actionBaseName(action_ref.raw);
    const version = action_ref.ref orelse return;

    const major = majorTag(version);
    for (deprecated_actions) |dep| {
        if (std.mem.eql(u8, action_name, dep.action) and
            major != null and major.? >= 1 and major.? < dep.deprecated_below)
        {
            var diag = Diagnostic{
                .rule_id = "BP003",
                .severity = .warning,
                .message = "Using deprecated action version. Consider upgrading.",
                .span = step.span,
                .fix_hint = "Upgrade to a newer version.",
            };
            diag.fix = buildDeprecatedActionFix(diag_list, step, version, dep.replacement);
            diag_list.append(diag) catch return;
            return;
        }
    }
}

// ── BP004: Cross-platform shell not specified ──

fn buildCrossPlatformShellFix(list: *DiagnosticList, step: *const Step) ?Fix {
    const insert_byte = step.shell_insertion_byte orelse return null;
    if (step.span.start_col == 0) return null;
    const indent: u32 = step.span.start_col - 1;

    const edits = fix_builder.insertMappingEntry(
        list.fixAllocator(),
        .{ .byte = insert_byte, .indent = indent },
        "shell",
        "bash",
    ) orelse return null;

    return .{
        .description = "add shell: bash to cross-platform run step",
        .safety = .unsafe,
        .edits = edits,
    };
}

fn checkCrossPlatformShell(job: *const Job, diag_list: *DiagnosticList) void {
    if (!hasWindowsTarget(job)) return;

    for (job.steps) |*step| {
        if (step.run != null and step.shell == null) {
            diag_list.append(.{
                .rule_id = "BP004",
                .severity = .warning,
                .message = "Step with 'run' does not specify 'shell' in a job targeting Windows. Default shells differ across platforms.",
                .span = step.span,
                .fix_hint = "Add 'shell: bash' or 'shell: pwsh' to ensure consistent behavior.",
                .fix = buildCrossPlatformShellFix(diag_list, step),
            }) catch return;
        }
    }
}

fn hasWindowsTarget(job: *const Job) bool {
    const runs_on = job.runs_on orelse return false;
    return std.ascii.indexOfIgnoreCase(runs_on, "windows") != null;
}

// ── BP005: Push trigger without concurrency ──

fn buildPushConcurrencyFix(list: *DiagnosticList, wf: *const Workflow) ?Fix {
    const insert_byte = wf.concurrency_insertion_byte orelse return null;

    const subs = [_]fix_builder.SubEntry{
        .{ .key = "group", .value = "${{ github.workflow }}-${{ github.ref }}" },
        .{ .key = "cancel-in-progress", .value = "${{ github.event_name == 'pull_request' }}" },
    };

    const edits = fix_builder.insertMappingEntryBlock(
        list.fixAllocator(),
        .{ .byte = insert_byte, .indent = wf.top_level_indent },
        "concurrency",
        &subs,
        2,
    ) orelse return null;

    return .{
        .description = "insert top-level concurrency block",
        .safety = .unsafe,
        .edits = edits,
    };
}

pub fn checkPushConcurrency(wf: *const Workflow, diag_list: *DiagnosticList) void {
    if (wf.hasEvent(.push) and wf.concurrency == null) {
        diag_list.append(.{
            .rule_id = "BP005",
            .severity = .info,
            .message = "Workflow has 'push' trigger but no 'concurrency' setting. Rapid pushes may queue redundant runs.",
            // A missing top-level key has no token of its own; point at the
            // head of the workflow file.
            .span = Span.point(1, 1, 0),
            .fix_hint = "Add a 'concurrency' group to cancel or queue redundant workflow runs.",
            .fix = buildPushConcurrencyFix(diag_list, wf),
        }) catch return;
    }
}

// ── BP008: Deprecated workflow command in `run:` ──

/// A workflow command GitHub has disabled. The diagnostic message and fix hint
/// are assembled from these parts at comptime in `checkDeprecatedWorkflowCommand`.
const DeprecatedWorkflowCommand = struct {
    /// Command name as it appears in the script.
    marker: []const u8,
    /// Clause appended to "GitHub disabled it" — empty, or the CVE reason.
    reason: []const u8,
    /// Completes "so ...".
    effect: []const u8,
    /// Argument form following `marker` in the deprecated call.
    args: []const u8,
    /// The file-based form that replaced the command.
    replacement: []const u8,
};

const security_reason = " for security reasons (CVE-2020-15228)";
const named_value_args = " name=NAME::VALUE";

const deprecated_workflow_commands = [_]DeprecatedWorkflowCommand{
    .{ .marker = "::set-output", .reason = "", .effect = "the step output is never set", .args = named_value_args, .replacement = "echo \"NAME=VALUE\" >> \"$GITHUB_OUTPUT\"" },
    .{ .marker = "::save-state", .reason = "", .effect = "the state is never saved", .args = named_value_args, .replacement = "echo \"NAME=VALUE\" >> \"$GITHUB_STATE\"" },
    .{ .marker = "::set-env", .reason = security_reason, .effect = "the environment variable is never set", .args = named_value_args, .replacement = "echo \"NAME=VALUE\" >> \"$GITHUB_ENV\"" },
    .{ .marker = "::add-path", .reason = security_reason, .effect = "the path is never added", .args = "::VALUE", .replacement = "echo \"VALUE\" >> \"$GITHUB_PATH\"" },
};

/// True when `marker` occurs as a workflow command: starting a shell word (so
/// `Foo::set-env` does not match) and followed by an argument list or the value
/// separator (so `::set-outputs` does not match).
fn usesDeprecatedCommand(script: []const u8, marker: []const u8) bool {
    var offset: usize = 0;
    while (std.mem.indexOfPos(u8, script, offset, marker)) |idx| {
        const end = idx + marker.len;
        offset = end;
        const starts_word = idx == 0 or switch (script[idx - 1]) {
            ' ', '\t', '\n', '\r', '"', '\'', '`' => true,
            else => false,
        };
        const name_ends = end >= script.len or switch (script[end]) {
            ' ', '\t', '\n', '\r', ':' => true,
            else => false,
        };
        if (starts_word and name_ends) return true;
    }
    return false;
}

fn checkDeprecatedWorkflowCommand(step: *const Step, diag_list: *DiagnosticList) void {
    const script = step.run orelse return;

    // Report once per command kind: repeats within one script share a span.
    inline for (deprecated_workflow_commands) |cmd| {
        if (usesDeprecatedCommand(script, cmd.marker)) {
            diag_list.append(.{
                .rule_id = "BP008",
                .severity = .@"error",
                .message = "Deprecated workflow command '" ++ cmd.marker ++ "' in 'run:'. GitHub disabled it" ++ cmd.reason ++ ", so " ++ cmd.effect ++ ".",
                .span = spans.runAnchor(step).whole(),
                .fix_hint = "Replace '" ++ cmd.marker ++ cmd.args ++ "' with '" ++ cmd.replacement ++ "'.",
            }) catch return;
        }
    }
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
    .{
        .id = "BP008",
        .name = "deprecated-workflow-command",
        .description = "Deprecated workflow command (set-output, save-state, set-env, add-path) used in run:",
        .severity = .@"error",
        .category = .best_practice,
        .check_step = checkDeprecatedWorkflowCommand,
    },
};

// ── Tests ──

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

test "BP001: no warning when timeout-minutes key is present but invalid" {
    const job = Job{ .id = "build", .timeout_minutes_specified = true };
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
    const wf = try test_support.parseWorkflowSource(alloc, source);

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

test "BP002: no fix when position info is missing" {
    const step = Step{ .run = "echo hello" };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkMissingStepName(&step, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "BP002: autofix generated from uses" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const step = Step{
        .uses = ActionRef.parse("actions/checkout@v4"),
        .uses_key_col = 9,
        .uses_key_start_byte = 50,
    };
    var diags = DiagnosticList.init(alloc);
    checkMissingStepName(&step, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestUnexpectedResult;
    try std.testing.expect(fix.safety == .safe);
    const edit = fix.edits[0];
    try std.testing.expectEqual(@as(usize, 50), edit.start_byte);
    try std.testing.expectEqual(@as(usize, 50), edit.end_byte);
    try std.testing.expectEqualStrings("name: Checkout\n        ", edit.replacement);
}

test "BP002: no fix for local actions" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const step = Step{
        .uses = ActionRef.parse("./local-action"),
        .uses_key_col = 9,
        .uses_key_start_byte = 50,
    };
    var diags = DiagnosticList.init(alloc);
    checkMissingStepName(&step, &diags);
    try std.testing.expect(diags.get(0).fix == null);
}

test "BP002: no fix when `if:` precedes `uses:` in step" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // `if:` comes before `uses:`, so the parser must NOT set uses_key_start_byte
    // (BP002 autofix would otherwise insert `name:` between `if:` and `uses:`).
    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - if: always()
        \\        uses: actions/checkout@v4
        \\
    ;

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var diags = DiagnosticList.init(alloc);
    checkMissingStepName(&wf.jobs[0].steps[0], &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "BP002: autofix applied to YAML source" {
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

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var diags = DiagnosticList.init(alloc);
    checkMissingStepName(&wf.jobs[0].steps[0], &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestUnexpectedResult;

    const fixes = [_]Fix{fix};
    const result = try fix_engine.applyFixes(std.testing.allocator, source, &fixes);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "name: Checkout") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "uses: actions/checkout@v4") != null);
    // name: Checkout must appear before uses:
    const name_pos = std.mem.indexOf(u8, result.content, "name: Checkout").?;
    const uses_pos = std.mem.indexOf(u8, result.content, "uses: actions/checkout@v4").?;
    try std.testing.expect(name_pos < uses_pos);
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

test "BP003: no fix when position info is missing" {
    const step = Step{ .uses = ActionRef.parse("actions/checkout@v1") };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkDeprecatedAction(&step, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "BP003: autofix generated for plain scalar uses" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // "actions/checkout@v1" ends at byte 25, version "v1" occupies bytes 23..25
    const step = Step{
        .uses = ActionRef.parse("actions/checkout@v1"),
        .uses_value_end_byte = 25,
        .uses_value_style = .plain,
    };
    var diags = DiagnosticList.init(alloc);
    checkDeprecatedAction(&step, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const d = diags.get(0);
    try std.testing.expect(d.fix != null);
    const fix = d.fix.?;
    try std.testing.expect(fix.safety == .safe);
    try std.testing.expectEqual(@as(usize, 1), fix.edits.len);

    const edit = fix.edits[0];
    try std.testing.expectEqual(@as(usize, 23), edit.start_byte);
    try std.testing.expectEqual(@as(usize, 25), edit.end_byte);
    try std.testing.expectEqualStrings("v4", edit.replacement);
}

test "BP003: autofix with single-quoted scalar keeps quotes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // "'actions/checkout@v1'" — quote at 0 and 20, v1 at 18..20, end_byte=21
    const step = Step{
        .uses = ActionRef.parse("actions/checkout@v1"),
        .uses_value_end_byte = 21,
        .uses_value_style = .single_quoted,
    };
    var diags = DiagnosticList.init(alloc);
    checkDeprecatedAction(&step, &diags);

    const fix = diags.get(0).fix orelse return error.TestUnexpectedResult;
    const edit = fix.edits[0];
    try std.testing.expectEqual(@as(usize, 18), edit.start_byte);
    try std.testing.expectEqual(@as(usize, 20), edit.end_byte);
    try std.testing.expectEqualStrings("v4", edit.replacement);
}

test "BP003: autofix applied to YAML source" {
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
        \\      - uses: actions/checkout@v1
        \\
    ;

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var diags = DiagnosticList.init(alloc);
    checkDeprecatedAction(&wf.jobs[0].steps[0], &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestUnexpectedResult;

    const fixes = [_]Fix{fix};
    const result = try fix_engine.applyFixes(std.testing.allocator, source, &fixes);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "actions/checkout@v4") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "actions/checkout@v1") == null);
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

test "BP004: no fix when shell_insertion_byte is missing" {
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
    try std.testing.expect(diags.get(0).fix == null);
}

test "BP004: attaches unsafe fix when shell_insertion_byte and span are present" {
    const job = Job{
        .id = "test",
        .runs_on = "windows-latest",
        .steps = &.{
            Step{
                .run = "make build",
                .span = .{
                    .start_line = 7,
                    .start_col = 9,
                    .end_line = 7,
                    .end_col = 20,
                    .start_byte = 0,
                    .end_byte = 0,
                },
                .shell_insertion_byte = 42,
            },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkCrossPlatformShell(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestExpectedNonNull;
    try std.testing.expectEqual(FixSafety.unsafe, fix.safety);
    try std.testing.expectEqual(@as(usize, 1), fix.edits.len);
    try std.testing.expectEqual(@as(usize, 42), fix.edits[0].start_byte);
    try std.testing.expectEqual(@as(usize, 42), fix.edits[0].end_byte);
    try std.testing.expectEqualStrings("        shell: bash\n", fix.edits[0].replacement);
}

test "BP004: autofix applied to YAML source inserts shell: bash after run" {
    const fix_engine = @import("../fix/engine.zig");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: windows-latest
        \\    steps:
        \\      - run: make build
        \\
    ;

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var diags = DiagnosticList.init(alloc);
    checkCrossPlatformShell(&wf.jobs[0], &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestExpectedNonNull;
    try std.testing.expectEqual(FixSafety.unsafe, fix.safety);

    const fixes = [_]Fix{fix};
    const result = try fix_engine.applyFixes(std.testing.allocator, source, &fixes);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "shell: bash") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "run: make build") != null);

    const run_pos = std.mem.indexOf(u8, result.content, "run: make build").?;
    const shell_pos = std.mem.indexOf(u8, result.content, "shell: bash").?;
    try std.testing.expect(run_pos < shell_pos);
}

test "BP005: detect push without concurrency" {
    const events = [_]workflow_types.EventConfig{
        .{ .event = .push },
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
        .{ .event = .push },
    };
    const wf = Workflow{
        .on = .{ .events = &events },
        .concurrency = .{ .group = "ci-${{ github.ref }}" },
        .jobs = &.{},
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPushConcurrency(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP005: no warning without push trigger" {
    const events = [_]workflow_types.EventConfig{
        .{ .event = .pull_request },
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

test "BP005: fix metadata is attached with .unsafe" {
    const events = [_]workflow_types.EventConfig{
        .{ .event = .push },
    };
    const wf = Workflow{
        .on = .{ .events = &events },
        .jobs = &.{},
        .concurrency_insertion_byte = 10,
        .top_level_indent = 0,
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPushConcurrency(&wf, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestExpectedNonNull;
    try std.testing.expect(fix.safety == .unsafe);
    try std.testing.expectEqualStrings("insert top-level concurrency block", fix.description);
    try std.testing.expectEqual(@as(usize, 1), fix.edits.len);
}

test "BP005: fix is null when concurrency_insertion_byte is missing" {
    const events = [_]workflow_types.EventConfig{
        .{ .event = .push },
    };
    const wf = Workflow{
        .on = .{ .events = &events },
        .jobs = &.{},
        // concurrency_insertion_byte left null
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPushConcurrency(&wf, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "BP005: autofix inserts block-form concurrency after on: line" {
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

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var diags = DiagnosticList.init(alloc);
    checkPushConcurrency(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestExpectedNonNull;

    const fixes = [_]Fix{fix};
    const result = try fix_engine.applyFixes(std.testing.allocator, source, &fixes);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
    try std.testing.expectEqualStrings(
        \\name: CI
        \\on: push
        \\concurrency:
        \\  group: ${{ github.workflow }}-${{ github.ref }}
        \\  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\
    ,
        result.content,
    );
}

// ── BP008 tests ──

fn bp008Diags(script: []const u8, diags: *DiagnosticList) void {
    const step = Step{ .run = script };
    checkDeprecatedWorkflowCommand(&step, diags);
}

test "BP008: each deprecated command is detected with its replacement hint" {
    const cases = .{
        .{ "echo \"::set-output name=version::1.0.0\"", "GITHUB_OUTPUT" },
        .{ "echo \"::save-state name=cache-hit::true\"", "GITHUB_STATE" },
        .{ "echo \"::set-env name=FOO::bar\"", "GITHUB_ENV" },
        .{ "echo \"::add-path::/usr/local/bin\"", "GITHUB_PATH" },
    };

    inline for (cases) |case| {
        var diags = DiagnosticList.init(std.testing.allocator);
        defer diags.deinit();
        bp008Diags(case[0], &diags);

        try std.testing.expectEqual(@as(usize, 1), diags.len());
        try std.testing.expectEqualStrings("BP008", diags.get(0).rule_id);
        try std.testing.expect(diags.get(0).severity == .@"error");
        const hint = diags.get(0).fix_hint orelse return error.TestExpectedNonNull;
        try std.testing.expect(std.mem.indexOf(u8, hint, case[1]) != null);
    }
}

test "BP008: single-quoted and bare line-start forms are detected" {
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    bp008Diags("echo '::set-output name=a::b'\n::set-env name=C::d\n", &diags);

    try std.testing.expectEqual(@as(usize, 2), diags.len());
}

test "BP008: no diagnostic for the GITHUB_* file replacements" {
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    bp008Diags(
        \\echo "version=1.0.0" >> "$GITHUB_OUTPUT"
        \\echo "FOO=bar" >> "$GITHUB_ENV"
        \\echo "/usr/local/bin" >> "$GITHUB_PATH"
        \\echo "cache-hit=true" >> "$GITHUB_STATE"
    , &diags);

    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP008: current workflow commands are not flagged" {
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    bp008Diags(
        \\echo "::error::boom"
        \\echo "::warning file=a.txt::careful"
        \\echo "::notice::hello"
        \\echo "::debug::details"
        \\echo "::group::build"
        \\echo "::endgroup::"
        \\echo "::add-mask::$SECRET"
        \\echo "::stop-commands::token"
    , &diags);

    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP008: scope-resolution identifiers are not flagged" {
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    bp008Diags("./gen Foo::set-env Bar::add-path", &diags);

    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP008: longer command names sharing a prefix are not flagged" {
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    bp008Diags("echo \"::set-outputs name=a::b\"", &diags);

    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP008: repeated occurrences of one command report once" {
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    bp008Diags(
        \\echo "::set-output name=a::1"
        \\echo "::set-output name=b::2"
    , &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
}

test "BP008: diagnostic span follows the run: scalar span" {
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    const step = Step{
        .run = "echo \"::set-output name=a::1\"",
        .run_meta = .{ .value_span = Span.point(7, 15, 120), .style = .plain },
    };
    checkDeprecatedWorkflowCommand(&step, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqual(@as(u32, 7), diags.get(0).span.start_line);
    try std.testing.expectEqual(@as(usize, 120), diags.get(0).span.start_byte);
}
