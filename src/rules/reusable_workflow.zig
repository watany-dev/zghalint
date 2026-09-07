const std = @import("std");
const engine = @import("engine.zig");
const called_workflow = @import("called_workflow.zig");
const workflow_types = @import("../workflow/types.zig");
const test_support = @import("../test_support.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const Job = engine.Job;
const DiagnosticList = engine.DiagnosticList;
const WorkflowCallInputProblem = workflow_types.WorkflowCallInputProblem;
const CallArgKey = workflow_types.CallArgKey;

fn workflowCallInputProblemMessage(
    alloc: std.mem.Allocator,
    problem: WorkflowCallInputProblem,
) ?[]const u8 {
    return switch (problem.kind) {
        .missing_type => std.fmt.allocPrint(
            alloc,
            "workflow_call input \"{s}\" is missing required property \"type\"",
            .{problem.input_name},
        ) catch null,
        .invalid_type => if (problem.detail.len == 0)
            std.fmt.allocPrint(
                alloc,
                "workflow_call input \"{s}\" has an invalid type",
                .{problem.input_name},
            ) catch null
        else
            std.fmt.allocPrint(
                alloc,
                "workflow_call input \"{s}\" has invalid type \"{s}\". expected \"string\", \"number\" or \"boolean\"",
                .{ problem.input_name, problem.detail },
            ) catch null,
        .default_type_mismatch => std.fmt.allocPrint(
            alloc,
            "workflow_call input \"{s}\" default value does not match type \"{s}\"",
            .{ problem.input_name, problem.detail },
        ) catch null,
        .required_with_default => std.fmt.allocPrint(
            alloc,
            "workflow_call input \"{s}\" cannot be required and have a default value",
            .{problem.input_name},
        ) catch null,
    };
}

fn checkWorkflowCallInputs(wf: *const Workflow, list: *DiagnosticList) void {
    const alloc = list.fixAllocator();
    for (wf.on.events) |event| {
        if (event.event != .workflow_call) continue;
        for (event.workflow_call_input_problems) |problem| {
            const message = workflowCallInputProblemMessage(alloc, problem) orelse continue;
            list.append(.{
                .rule_id = "RW001",
                .severity = .@"error",
                .message = message,
                .span = problem.span,
                .fix_hint = switch (problem.kind) {
                    .missing_type => "add a `type` field (`string`, `number`, or `boolean`).",
                    .invalid_type => "use `string`, `number`, or `boolean` for workflow_call inputs.",
                    .default_type_mismatch => "change the default value to match the declared type.",
                    .required_with_default => "remove either `required: true` or `default`.",
                },
            }) catch return;
        }
    }
}

/// Call arguments are matched case-insensitively, the way the runner resolves
/// them, so a case difference is never reported as a missing or unknown name.
fn hasCallArg(keys: []const CallArgKey, name: []const u8) bool {
    for (keys) |key| {
        if (std.ascii.eqlIgnoreCase(key.name, name)) return true;
    }
    return false;
}

/// RW002: a `required: true` input of the called workflow that the call never
/// passes. Only a local call is checked — `called_workflow.load` returns null
/// for everything else.
fn checkCallRequiredInputs(wf: *const Workflow, list: *DiagnosticList) void {
    for (wf.jobs) |*job| {
        const uses = job.uses orelse continue;

        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const called = called_workflow.load(arena.allocator(), uses) orelse continue;

        for (called.inputs) |input| {
            if (!(input.required orelse false)) continue;
            // A required input that also carries a default still gets a value
            // at dispatch time; RW001 reports that contradiction on the
            // definition side, so the call is not at fault here.
            if (input.default_value != null) continue;
            if (hasCallArg(job.with_keys, input.name)) continue;

            reportMissingInput(job, uses, input.name, list);
        }
    }
}

fn reportMissingInput(
    job: *const Job,
    uses: []const u8,
    input_name: []const u8,
    list: *DiagnosticList,
) void {
    const alloc = list.fixAllocator();
    const message = std.fmt.allocPrint(
        alloc,
        "required input \"{s}\" of \"{s}\" is not set by this call",
        .{ input_name, uses },
    ) catch return;
    const hint = std.fmt.allocPrint(
        alloc,
        "add `{s}:` under the job's `with:`",
        .{input_name},
    ) catch return;

    list.append(.{
        .rule_id = "RW002",
        .severity = .@"error",
        .message = message,
        .span = job.uses_value_span orelse job.span,
        .fix_hint = hint,
    }) catch return;
}

pub const rules = [_]Rule{
    .{
        .id = "RW001",
        .name = "workflow-call-inputs",
        .description = "Validates workflow_call input definitions",
        .severity = .@"error",
        .category = .reusable_workflow,
        .check_workflow = checkWorkflowCallInputs,
    },
    .{
        .id = "RW002",
        .name = "workflow-call-required-inputs",
        .description = "Every required input of a called local workflow must be passed",
        .severity = .@"error",
        .category = .reusable_workflow,
        .check_workflow = checkCallRequiredInputs,
    },
};

const testing = std.testing;

test "RW001: invalid workflow_call inputs from issue example" {
    const source =
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      env:
        \\        type: choice
        \\        options: [dev, prod]
        \\      version:
        \\        description: Version
        \\      verbose:
        \\        type: boolean
        \\        default: 'yes'
        \\jobs:
        \\  call:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo ok
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    checkWorkflowCallInputs(&wf, &diags);

    try testing.expectEqual(@as(usize, 3), diags.len());
    try testing.expect(test_support.hasDiagnostic(&diags, "RW001"));
}

test "RW001: valid workflow_call inputs produce no diagnostics" {
    const source =
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      version:
        \\        type: string
        \\        required: true
        \\      verbose:
        \\        type: boolean
        \\        default: false
        \\jobs:
        \\  call:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo ok
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    checkWorkflowCallInputs(&wf, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RW001: required with default is reported" {
    const source =
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      name:
        \\        type: string
        \\        required: true
        \\        default: main
        \\jobs:
        \\  call:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo ok
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    checkWorkflowCallInputs(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "required") != null);
}

/// The called workflow every RW002 test resolves `./.github/workflows/reusable.yml`
/// to. Set before installing `called_workflow.source_override`.
var called_source: []const u8 = "";

fn calledLookup(path: []const u8) ?[]const u8 {
    if (!std.mem.eql(u8, path, ".github/workflows/reusable.yml")) return null;
    return called_source;
}

const required_input_workflow =
    \\on:
    \\  workflow_call:
    \\    inputs:
    \\      version:
    \\        type: string
    \\        required: true
    \\      env:
    \\        type: string
    \\        default: dev
    \\jobs:
    \\  build:
    \\    runs-on: ubuntu-latest
    \\    steps:
    \\      - run: echo ok
    \\
;

fn runCallInputCheck(arena: std.mem.Allocator, source: []const u8, list: *DiagnosticList) !void {
    const wf = try test_support.parseWorkflowSource(arena, source);
    checkCallRequiredInputs(&wf, list);
}

test "RW002: a missing required input is reported" {
    called_source = required_input_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\    with:
        \\      env: prod
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallInputCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings("RW002", diags.get(0).rule_id);
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "version") != null);
}

test "RW002: a passed required input is accepted" {
    called_source = required_input_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\    with:
        \\      version: '1.0'
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallInputCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RW002: a remote call is not checked" {
    called_source = required_input_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    const source =
        \\on: push
        \\jobs:
        \\  remote:
        \\    uses: octo-org/repo/.github/workflows/ci.yml@main
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallInputCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RW002: a required input with a default is not demanded" {
    called_source =
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      target:
        \\        type: string
        \\        required: true
        \\        default: main
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo ok
        \\
    ;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallInputCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RW002: a non-scalar `with:` value still counts as passed" {
    called_source = required_input_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    // `version` holds a sequence, which the value map drops; only `with_keys`
    // still sees the key, and the call did pass it.
    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\    with:
        \\      version:
        \\        - '1.0'
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallInputCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}
