const std = @import("std");
const engine = @import("engine.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_types = @import("../yaml/types.zig");
const diagnostics_mod = @import("../diagnostics.zig");
const fix_builder = @import("../fix/builder.zig");
const util = @import("../util.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const Step = engine.Step;
const Workflow = engine.Workflow;
const DiagnosticList = engine.DiagnosticList;
const Span = yaml_types.Span;
const ActionRef = workflow_types.ActionRef;
const Diagnostic = diagnostics_mod.Diagnostic;
const Fix = diagnostics_mod.Fix;
const Edit = diagnostics_mod.Edit;
const FixSafety = diagnostics_mod.FixSafety;

// ── BP001: Missing timeout-minutes ──

fn checkMissingTimeout(job: *const Job, diag_list: *DiagnosticList) void {
    if (job.timeout_minutes != null) return;

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

    for (deprecated_actions) |dep| {
        if (std.mem.eql(u8, action_name, dep.action) and std.mem.eql(u8, version, dep.version)) {
            var diag = Diagnostic{
                .rule_id = "BP003",
                .severity = .warning,
                .message = "Using deprecated action version. Consider upgrading.",
                .span = step.span,
                .fix_hint = "Upgrade to a newer version.",
            };
            diag.fix = buildDeprecatedActionFix(diag_list, step, dep.version, dep.replacement);
            diag_list.append(diag) catch return;
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

pub fn checkPushConcurrencyForTest(wf: *const Workflow, diag_list: *DiagnosticList) void {
    checkPushConcurrency(wf, diag_list);
}

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
            .fix = buildPushConcurrencyFix(diag_list, wf),
        }) catch return;
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
    const yaml_parser_mod = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");

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

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

    var diags = DiagnosticList.init(alloc);
    checkMissingStepName(&wf.jobs[0].steps[0], &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "BP002: autofix applied to YAML source" {
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

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

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
        \\      - uses: actions/checkout@v1
        \\
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

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

test "BP005: fix metadata is attached with .unsafe" {
    const events = [_]workflow_types.EventConfig{
        .{ .event = .push, .name = "push" },
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
        .{ .event = .push, .name = "push" },
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

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

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
