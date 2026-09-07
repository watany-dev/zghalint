const std = @import("std");
const engine = @import("engine.zig");
const called_workflow = @import("called_workflow.zig");
const workflow_types = @import("../workflow/types.zig");
const util = @import("../util.zig");
const test_support = @import("../test_support.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const Job = engine.Job;
const DiagnosticList = engine.DiagnosticList;
const WorkflowCallInputProblem = workflow_types.WorkflowCallInputProblem;
const CallArg = workflow_types.CallArg;

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

/// Whether any of `items` — call arguments or declarations, both of which carry
/// a `name` — is `name`. The comparison is case-insensitive, the way the runner
/// resolves these, so a case difference is never reported as a missing or
/// unknown name.
fn hasName(items: anytype, name: []const u8) bool {
    for (items) |item| {
        if (std.ascii.eqlIgnoreCase(item.name, name)) return true;
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
            if (hasName(job.with_args, input.name)) continue;

            reportMissingArg(.input, job, uses, input.name, list);
        }
    }
}

/// A `required` name of the called workflow the call never passes. The
/// diagnostic sits on the `uses:` because the call has no token for the name it
/// is missing.
fn reportMissingArg(
    kind: ArgKind,
    job: *const Job,
    uses: []const u8,
    name: []const u8,
    list: *DiagnosticList,
) void {
    const alloc = list.fixAllocator();
    const message = std.fmt.allocPrint(
        alloc,
        "required {s} \"{s}\" of \"{s}\" is not set by this call",
        .{ kind.noun(), name, uses },
    ) catch return;
    const hint = std.fmt.allocPrint(
        alloc,
        "add `{s}:` under the job's `{s}:`",
        .{ name, kind.callKey() },
    ) catch return;

    list.append(.{
        .rule_id = kind.missingRuleId(),
        .severity = .@"error",
        .message = message,
        .span = job.uses_value_span orelse job.span,
        .fix_hint = hint,
    }) catch return;
}

/// A `with:` / `secrets:` name the called workflow does not declare.
fn reportUnknownArg(
    kind: ArgKind,
    declared: []const []const u8,
    arg: CallArg,
    uses: []const u8,
    list: *DiagnosticList,
) void {
    const alloc = list.fixAllocator();
    const message = std.fmt.allocPrint(
        alloc,
        "unknown {s} \"{s}\" for \"{s}\"",
        .{ kind.noun(), arg.name, uses },
    ) catch return;
    const hint = if (util.didYouMean(arg.name, declared)) |near|
        std.fmt.allocPrint(alloc, "did you mean `{s}`?", .{near}) catch return
    else
        std.fmt.allocPrint(
            alloc,
            "remove it, or declare the {s} under the called workflow's `workflow_call`",
            .{kind.noun()},
        ) catch return;

    list.append(.{
        .rule_id = kind.unknownRuleId(),
        .severity = .@"error",
        .message = message,
        .span = arg.name_span,
        .fix_hint = hint,
    }) catch return;
}

/// The names a called workflow declares, for `didYouMean`. An allocation
/// failure costs the suggestion, not the diagnostic.
fn declaredNames(alloc: std.mem.Allocator, defs: anytype) []const []const u8 {
    const names = alloc.alloc([]const u8, defs.len) catch return &.{};
    for (defs, names) |def, *slot| slot.* = def.name;
    return names;
}

/// The two halves of a reusable workflow call that name declarations in the
/// called workflow. They differ only in the noun and the rule that owns them.
const ArgKind = enum {
    input,
    secret,

    fn noun(self: ArgKind) []const u8 {
        return @tagName(self);
    }

    fn callKey(self: ArgKind) []const u8 {
        return switch (self) {
            .input => "with",
            .secret => "secrets",
        };
    }

    /// A name the call fails to pass, and a name it passes that does not
    /// exist, are two rules on the input side and one on the secret side.
    fn missingRuleId(self: ArgKind) []const u8 {
        return switch (self) {
            .input => "RW002",
            .secret => "RW004",
        };
    }

    fn unknownRuleId(self: ArgKind) []const u8 {
        return switch (self) {
            .input => "RW003",
            .secret => "RW004",
        };
    }
};

fn findInput(inputs: []const workflow_types.InputDef, name: []const u8) ?workflow_types.InputDef {
    for (inputs) |input| {
        if (std.ascii.eqlIgnoreCase(input.name, name)) return input;
    }
    return null;
}

/// RW003: a `with:` entry the called workflow does not declare, or one whose
/// value cannot be a value of the declared type.
fn checkCallInputs(wf: *const Workflow, list: *DiagnosticList) void {
    for (wf.jobs) |*job| {
        const uses = job.uses orelse continue;
        if (job.with_args.len == 0) continue;

        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const called = called_workflow.load(arena.allocator(), uses) orelse continue;

        for (job.with_args) |arg| {
            const input = findInput(called.inputs, arg.name) orelse {
                const declared = declaredNames(arena.allocator(), called.inputs);
                reportUnknownArg(.input, declared, arg, uses, list);
                continue;
            };
            reportInputTypeMismatch(input, arg, list);
        }
    }
}

fn reportInputTypeMismatch(input: workflow_types.InputDef, arg: CallArg, list: *DiagnosticList) void {
    // A missing or invalid `type:` is RW001's finding on the definition side;
    // without one there is nothing here to check the value against.
    const input_type = input.input_type orelse return;
    // A non-scalar value, and one built by an expression, are both opaque:
    // neither can be compared against the declared type without evaluating it.
    const value = arg.value orelse return;
    if (std.mem.indexOf(u8, value, "${{") != null) return;
    if (input_type.matchesScalar(value)) return;

    const alloc = list.fixAllocator();
    const message = std.fmt.allocPrint(
        alloc,
        "input \"{s}\" value does not match type \"{s}\"",
        .{ input.name, input_type.name() },
    ) catch return;
    const hint = std.fmt.allocPrint(
        alloc,
        "pass a `{s}` value",
        .{input_type.name()},
    ) catch return;

    list.append(.{
        .rule_id = "RW003",
        .severity = .@"error",
        .message = message,
        .span = arg.value_span orelse arg.name_span,
        .fix_hint = hint,
    }) catch return;
}

/// RW004: a `required: true` secret of the called workflow the call never
/// passes, and a `secrets:` entry the called workflow does not declare.
fn checkCallSecrets(wf: *const Workflow, list: *DiagnosticList) void {
    for (wf.jobs) |*job| {
        const uses = job.uses orelse continue;
        // `secrets: inherit` hands over every secret of the caller, so there is
        // nothing left to match against a declaration.
        if (job.secrets) |config| {
            if (config == .inherit) continue;
        }

        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const called = called_workflow.load(arena.allocator(), uses) orelse continue;
        // A called workflow that declares no `workflow_call.secrets` has no
        // closed secret set to check a call against.
        if (called.secrets.len == 0) continue;

        for (called.secrets) |secret| {
            if (!(secret.required orelse false)) continue;
            if (hasName(job.secrets_args, secret.name)) continue;
            reportMissingArg(.secret, job, uses, secret.name, list);
        }

        for (job.secrets_args) |arg| {
            if (hasName(called.secrets, arg.name)) continue;
            const declared = declaredNames(arena.allocator(), called.secrets);
            reportUnknownArg(.secret, declared, arg, uses, list);
        }
    }
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
    .{
        .id = "RW003",
        .name = "workflow-call-input-values",
        .description = "A call must only pass inputs the called local workflow declares, with matching types",
        .severity = .@"error",
        .category = .reusable_workflow,
        .check_workflow = checkCallInputs,
    },
    .{
        .id = "RW004",
        .name = "workflow-call-secrets",
        .description = "A call must pass every required secret of the called local workflow and no undeclared one",
        .severity = .@"error",
        .category = .reusable_workflow,
        .check_workflow = checkCallSecrets,
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

const typed_input_workflow =
    \\on:
    \\  workflow_call:
    \\    inputs:
    \\      version:
    \\        type: string
    \\      retries:
    \\        type: number
    \\      verbose:
    \\        type: boolean
    \\jobs:
    \\  build:
    \\    runs-on: ubuntu-latest
    \\    steps:
    \\      - run: echo ok
    \\
;

fn runCallInputValueCheck(arena: std.mem.Allocator, source: []const u8, list: *DiagnosticList) !void {
    const wf = try test_support.parseWorkflowSource(arena, source);
    checkCallInputs(&wf, list);
}

test "RW003: an unknown input is reported with a suggestion" {
    called_source = typed_input_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\    with:
        \\      verison: '1.0'
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallInputValueCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings("RW003", diags.get(0).rule_id);
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "verison") != null);
    try testing.expect(std.mem.indexOf(u8, diags.get(0).fix_hint.?, "version") != null);
}

test "RW003: an unknown input without a near name falls back to a generic hint" {
    called_source = typed_input_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\    with:
        \\      completely_different: x
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallInputValueCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).fix_hint.?, "did you mean") == null);
}

test "RW003: a value that does not match the declared type is reported" {
    called_source = typed_input_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\    with:
        \\      retries: three
        \\      verbose: sometimes
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallInputValueCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "number") != null);
    try testing.expect(std.mem.indexOf(u8, diags.get(1).message, "boolean") != null);
}

test "RW003: matching values and expressions are accepted" {
    called_source = typed_input_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\    with:
        \\      version: '1.0'
        \\      retries: 3
        \\      verbose: true
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallInputValueCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RW003: an expression value is not type-checked" {
    called_source = typed_input_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\    with:
        \\      retries: ${{ github.event.inputs.retries }}
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallInputValueCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RW003: a remote call is not checked" {
    called_source = typed_input_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: octo-org/repo/.github/workflows/ci.yml@main
        \\    with:
        \\      anything: x
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallInputValueCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RW003: an input without a declared type is not type-checked" {
    called_source =
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      version:
        \\        description: no type here
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
        \\    with:
        \\      version: anything
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallInputValueCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

const secret_workflow =
    \\on:
    \\  workflow_call:
    \\    secrets:
    \\      npm_token:
    \\        required: true
    \\      slack_webhook:
    \\        required: false
    \\jobs:
    \\  build:
    \\    runs-on: ubuntu-latest
    \\    steps:
    \\      - run: echo ok
    \\
;

fn runCallSecretCheck(arena: std.mem.Allocator, source: []const u8, list: *DiagnosticList) !void {
    const wf = try test_support.parseWorkflowSource(arena, source);
    checkCallSecrets(&wf, list);
}

test "RW004: a missing required secret and an unknown secret are reported" {
    called_source = secret_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\    secrets:
        \\      slack_webhook: ${{ secrets.SLACK }}
        \\      aws_key: ${{ secrets.AWS }}
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallSecretCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expectEqualStrings("RW004", diags.get(0).rule_id);
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "npm_token") != null);
    try testing.expect(std.mem.indexOf(u8, diags.get(1).message, "aws_key") != null);
}

test "RW004: a call passing every required secret is accepted" {
    called_source = secret_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\    secrets:
        \\      npm_token: ${{ secrets.NPM_TOKEN }}
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallSecretCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RW004: secrets inherit skips every check" {
    called_source = secret_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\    secrets: inherit
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallSecretCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RW004: an absent secrets key still reports a missing required secret" {
    called_source = secret_workflow;
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
    try runCallSecretCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "npm_token") != null);
}

test "RW004: a called workflow declaring no secrets is not checked" {
    called_source =
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      version:
        \\        type: string
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
        \\    secrets:
        \\      anything: ${{ secrets.ANYTHING }}
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallSecretCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RW004: a remote call is not checked" {
    called_source = secret_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: octo-org/repo/.github/workflows/ci.yml@main
        \\    secrets:
        \\      aws_key: ${{ secrets.AWS }}
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallSecretCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RW004: a near-miss secret name carries a suggestion" {
    called_source = secret_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\    secrets:
        \\      npm_toke: ${{ secrets.NPM_TOKEN }}
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallSecretCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(1).fix_hint.?, "npm_token") != null);
}
