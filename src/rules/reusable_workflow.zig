const std = @import("std");
const engine = @import("engine.zig");
const called_workflow = @import("called_workflow.zig");
const expr_check = @import("expr_check.zig");
const expr_scan = @import("expr_scan.zig");
const spans = @import("spans.zig");
const workflow_types = @import("../workflow/types.zig");
const util = @import("../util.zig");
const rename = @import("rename.zig");
const fix_builder = @import("../fix/builder.zig");
const test_support = @import("../test_support.zig");
const diagnostics = @import("../diagnostics.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const Job = engine.Job;
const DiagnosticList = engine.DiagnosticList;
const Anchor = spans.Anchor;
const Span = spans.Span;
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

/// The `type:` a missing declaration's `default:` implies. Unsafe because the
/// inference only ever sees one literal: an author who meant `string` but wrote
/// `default: 1` gets `number`, which changes how the value reaches the called
/// workflow.
fn buildMissingTypeFix(
    list: *DiagnosticList,
    problem: WorkflowCallInputProblem,
) ?diagnostics.Fix {
    if (problem.kind != .missing_type) return null;
    const insertion = problem.type_insertion orelse return null;

    const alloc = list.fixAllocator();
    const edits = fix_builder.insertMappingEntryBefore(
        alloc,
        .{ .byte = insertion.anchor_byte, .indent = insertion.indent },
        "type",
        insertion.type_name,
    ) orelse return null;
    const description = std.fmt.allocPrint(
        alloc,
        "Add type: {s} inferred from the default value",
        .{insertion.type_name},
    ) catch return null;

    return .{ .description = description, .safety = .unsafe, .edits = edits };
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
                .fix = buildMissingTypeFix(list, problem),
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

        var arena = std.heap.ArenaAllocator.init(list.allocator);
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
    const suggestion = util.didYouMean(arg.name, declared);
    const hint = if (suggestion) |near|
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
        .fix = if (suggestion) |near| rename.tokenFix(list, arg.name_span, arg.name, near) else null,
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

        var arena = std.heap.ArenaAllocator.init(list.allocator);
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

        var arena = std.heap.ArenaAllocator.init(list.allocator);
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

/// Job IDs and context properties resolve case-insensitively on the runner, so
/// a case difference is never a finding.
fn eqlId(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// Only a plain identifier names something to resolve; a globbed or computed
/// segment (`jobs.*`, `needs[matrix.job]`) has no literal name.
fn identSegment(segment: ?expr_check.Segment) ?[]const u8 {
    const seg = segment orelse return null;
    return switch (seg) {
        .ident => |name| name,
        .index_string => |name| name,
        .star => null,
    };
}

fn findJob(wf: *const Workflow, job_id: []const u8) ?*const Job {
    for (wf.jobs) |*job| {
        if (eqlId(job.id, job_id)) return job;
    }
    return null;
}

fn suggestionSuffix(alloc: std.mem.Allocator, name: []const u8, candidates: []const []const u8) []const u8 {
    const suggestion = util.didYouMean(name, candidates) orelse return "";
    return std.fmt.allocPrint(alloc, ". did you mean \"{s}\"?", .{suggestion}) catch "";
}

/// RW005, definition side: `on.workflow_call.outputs.<name>.value` may only
/// read `jobs.<id>.outputs.<x>` of this workflow, and both names must exist.
const OutputValueResolver = struct {
    /// Backs the expression parse trees; messages go to the list's own arena.
    alloc: std.mem.Allocator,
    wf: *const Workflow,
    list: *DiagnosticList,

    pub fn checkPath(self: OutputValueResolver, path: []const u8, span: Span) void {
        var iter = expr_check.SegmentIter{ .path = path };
        const root = identSegment(iter.next()) orelse return;
        // `jobs` is the only context a `value:` can read; EXPR015 reports the
        // others.
        if (!eqlId(root, "jobs")) return;

        const job_id = identSegment(iter.next()) orelse return;
        const job = findJob(self.wf, job_id) orelse {
            self.reportUnknownJob(job_id, span);
            return;
        };
        if (!eqlId(identSegment(iter.next()) orelse return, "outputs")) return;
        const output = identSegment(iter.next()) orelse return;

        // A job that itself calls a workflow declares its outputs in that
        // file, which this workflow's parse tree does not carry.
        if (job.uses != null) return;
        if (hasName(job.outputs, output)) return;
        self.reportUnknownOutput(job, output, span);
    }

    fn reportUnknownJob(self: OutputValueResolver, job_id: []const u8, span: Span) void {
        const alloc = self.list.fixAllocator();
        const names = alloc.alloc([]const u8, self.wf.jobs.len) catch return;
        for (self.wf.jobs, names) |*job, *name| name.* = job.id;
        const message = std.fmt.allocPrint(
            alloc,
            "\"{s}\" is not a job in this workflow{s}",
            .{ job_id, suggestionSuffix(alloc, job_id, names) },
        ) catch return;

        self.list.append(.{
            .rule_id = "RW005",
            .severity = .@"error",
            .message = message,
            .span = span,
            .fix_hint = "reference a job defined in this workflow",
        }) catch return;
    }

    fn reportUnknownOutput(self: OutputValueResolver, job: *const Job, output: []const u8, span: Span) void {
        const alloc = self.list.fixAllocator();
        const message = std.fmt.allocPrint(
            alloc,
            "output \"{s}\" is not defined in job \"{s}\"{s}",
            .{ output, job.id, suggestionSuffix(alloc, output, declaredNames(alloc, job.outputs)) },
        ) catch return;

        self.list.append(.{
            .rule_id = "RW005",
            .severity = .@"error",
            .message = message,
            .span = span,
            .fix_hint = "declare the output under the referenced job's `outputs:`",
        }) catch return;
    }
};

/// RW005, call side: `needs.<job>.outputs.<name>` where `<job>` calls a local
/// reusable workflow. EXPR012 hands these over because the declaration lives
/// in the called file.
const NeedsOutputResolver = struct {
    alloc: std.mem.Allocator,
    wf: *const Workflow,
    job: *const Job,
    list: *DiagnosticList,

    pub fn checkPath(self: NeedsOutputResolver, path: []const u8, span: Span) void {
        var iter = expr_check.SegmentIter{ .path = path };
        const root = identSegment(iter.next()) orelse return;
        if (!eqlId(root, "needs")) return;

        const job_id = identSegment(iter.next()) orelse return;
        // A job the current one does not need is EXPR012's finding; reporting
        // its outputs too would double up on one mistake.
        if (!self.isNeeded(job_id)) return;
        const dep = findJob(self.wf, job_id) orelse return;
        const uses = dep.uses orelse return;

        if (!eqlId(identSegment(iter.next()) orelse return, "outputs")) return;
        const output = identSegment(iter.next()) orelse return;

        var arena = std.heap.ArenaAllocator.init(self.list.allocator);
        defer arena.deinit();
        const called = called_workflow.load(arena.allocator(), uses) orelse return;
        if (hasName(called.outputs, output)) return;

        self.reportUnknownOutput(dep, called.outputs, output, span);
    }

    fn isNeeded(self: NeedsOutputResolver, job_id: []const u8) bool {
        for (self.job.needs) |dep| {
            if (eqlId(dep, job_id)) return true;
        }
        return false;
    }

    fn reportUnknownOutput(
        self: NeedsOutputResolver,
        dep: *const Job,
        declared: []const workflow_types.CallOutputDef,
        output: []const u8,
        span: Span,
    ) void {
        const alloc = self.list.fixAllocator();
        const message = std.fmt.allocPrint(
            alloc,
            "output \"{s}\" is not defined in \"{s}\" called by job \"{s}\"{s}",
            .{ output, dep.uses.?, dep.id, suggestionSuffix(alloc, output, declaredNames(alloc, declared)) },
        ) catch return;

        self.list.append(.{
            .rule_id = "RW005",
            .severity = .@"error",
            .message = message,
            .span = span,
            .fix_hint = "declare the output under the called workflow's `workflow_call.outputs:`",
        }) catch return;
    }
};

fn callsLocalWorkflow(wf: *const Workflow) bool {
    for (wf.jobs) |*job| {
        const uses = job.uses orelse continue;
        if (called_workflow.localPath(uses) != null) return true;
    }
    return false;
}

fn checkCallOutputs(wf: *const Workflow, list: *DiagnosticList) void {
    // Scratch for the expression parser: no diagnostic points at it, and
    // the list's allocator keeps it under the run's leak detection (#159).
    var arena = std.heap.ArenaAllocator.init(list.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const resolver = OutputValueResolver{ .alloc = alloc, .wf = wf, .list = list };
    for (wf.on.events) |event| {
        if (event.event != .workflow_call) continue;
        for (event.workflow_call_outputs) |output| {
            const value = output.value orelse continue;
            expr_scan.scanText(resolver, value, Anchor.fromMeta(output.value_meta, output.name_span));
        }
    }

    // Without a local call there is no `needs.<job>.outputs` this rule owns,
    // and scanning every expression of the workflow would be pure overhead.
    if (!callsLocalWorkflow(wf)) return;
    for (wf.jobs) |*job| {
        expr_scan.scanJob(NeedsOutputResolver{
            .alloc = alloc,
            .wf = wf,
            .job = job,
            .list = list,
        }, job);
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
    .{
        .id = "RW005",
        .name = "workflow-call-outputs",
        .description = "Outputs of a reusable workflow must name jobs that exist, and callers must reference declared outputs",
        .severity = .@"error",
        .category = .reusable_workflow,
        .check_workflow = checkCallOutputs,
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

test "RW003: the suggestion is applied as a rename of the with: key" {
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

    const outcome = try test_support.lintAndFix(
        testing.allocator,
        source,
        .{ .workflow = checkCallInputs },
        false,
    );
    defer outcome.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), outcome.fix_count);
    try testing.expectEqual(diagnostics.FixSafety.safe, outcome.first_safety.?);
    try testing.expect(std.mem.indexOf(u8, outcome.content, "version: '1.0'") != null);
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

fn runCallOutputCheck(arena: std.mem.Allocator, source: []const u8, list: *DiagnosticList) !void {
    const wf = try test_support.parseWorkflowSource(arena, source);
    checkCallOutputs(&wf, list);
}

fn expectOutputDiagnostics(source: []const u8, expected: []const []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runCallOutputCheck(arena.allocator(), source, &diags);

    try testing.expectEqual(expected.len, diags.len());
    for (expected, 0..) |needle, i| {
        const diag = diags.get(i);
        try testing.expectEqualStrings("RW005", diag.rule_id);
        try testing.expectEqual(engine.Severity.@"error", diag.severity);
        if (std.mem.indexOf(u8, diag.message, needle) == null) {
            std.debug.print("message '{s}' does not contain '{s}'\n", .{ diag.message, needle });
            return error.UnexpectedMessage;
        }
    }
}

test "RW005: an output value naming a missing job is reported" {
    try expectOutputDiagnostics(
        \\on:
        \\  workflow_call:
        \\    outputs:
        \\      version:
        \\        value: ${{ jobs.build.outputs.version }}
        \\      bad:
        \\        value: ${{ jobs.nonexistent.outputs.x }}
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    outputs:
        \\      version: ${{ steps.v.outputs.version }}
        \\    steps:
        \\      - id: v
        \\        run: echo "version=1" >> "$GITHUB_OUTPUT"
        \\
    , &.{"\"nonexistent\" is not a job in this workflow"});
}

test "RW005: an output value naming an output the job never declares is reported" {
    try expectOutputDiagnostics(
        \\on:
        \\  workflow_call:
        \\    outputs:
        \\      version:
        \\        value: ${{ jobs.build.outputs.versio }}
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    outputs:
        \\      version: ${{ steps.v.outputs.version }}
        \\    steps:
        \\      - id: v
        \\        run: echo "version=1" >> "$GITHUB_OUTPUT"
        \\
    , &.{"output \"versio\" is not defined in job \"build\". did you mean \"version\"?"});
}

test "RW005: an output value of a job that itself calls a workflow is not checked" {
    try expectOutputDiagnostics(
        \\on:
        \\  workflow_call:
        \\    outputs:
        \\      version:
        \\        value: ${{ jobs.call.outputs.version }}
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/other.yml
        \\
    , &.{});
}

const output_workflow =
    \\on:
    \\  workflow_call:
    \\    outputs:
    \\      version:
    \\        value: ${{ jobs.build.outputs.version }}
    \\jobs:
    \\  build:
    \\    runs-on: ubuntu-latest
    \\    outputs:
    \\      version: ${{ steps.v.outputs.version }}
    \\    steps:
    \\      - id: v
    \\        run: echo "version=1" >> "$GITHUB_OUTPUT"
    \\
;

test "RW005: a caller referencing an undeclared output of a called workflow is reported" {
    called_source = output_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    try expectOutputDiagnostics(
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\  use:
        \\    needs: [call]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ needs.call.outputs.versio }}"
        \\
    , &.{"output \"versio\" is not defined in \"./.github/workflows/reusable.yml\" called by job \"call\". did you mean \"version\"?"});
}

test "RW005: a caller referencing a declared output is accepted" {
    called_source = output_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    try expectOutputDiagnostics(
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\  use:
        \\    needs: [call]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ needs.call.outputs.version }}"
        \\
    , &.{});
}

test "RW005: a caller of an unreadable or remote workflow is not checked" {
    called_source = output_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    try expectOutputDiagnostics(
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: octo-org/repo/.github/workflows/ci.yml@main
        \\  use:
        \\    needs: [call]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ needs.call.outputs.ver }}"
        \\
    , &.{});
}

test "RW005: outputs of a plain job are left to EXPR012" {
    try expectOutputDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo ok
        \\  use:
        \\    needs: [build]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ needs.build.outputs.ver }}"
        \\
    , &.{});
}

test "RW005: a job the caller does not need is left to EXPR012" {
    called_source = output_workflow;
    called_workflow.source_override = &calledLookup;
    defer called_workflow.source_override = null;

    try expectOutputDiagnostics(
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\  use:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ needs.call.outputs.ver }}"
        \\
    , &.{});
}

test "RW001: missing type: is fixed by inferring the type from the default" {
    const source =
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      verbose:
        \\        default: true
        \\      retries:
        \\        default: 3
        \\      branch:
        \\        default: main
        \\jobs:
        \\  call:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo ok
        \\
    ;

    const result = try test_support.lintAndFix(
        testing.allocator,
        source,
        .{ .workflow = &checkWorkflowCallInputs },
        true,
    );
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 3), result.fix_count);
    try testing.expectEqual(diagnostics.FixSafety.unsafe, result.first_safety.?);
    try testing.expectEqualStrings(
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      verbose:
        \\        type: boolean
        \\        default: true
        \\      retries:
        \\        type: number
        \\        default: 3
        \\      branch:
        \\        type: string
        \\        default: main
        \\jobs:
        \\  call:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo ok
        \\
    ,
        result.content,
    );
}

test "RW001: an input without a default gets no fix" {
    const source =
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      version:
        \\        description: Version
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
    try testing.expect(diags.get(0).fix == null);
}

test "RW001: a quoted default infers string, not the literal it looks like" {
    const source =
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      verbose:
        \\        default: 'true'
        \\jobs:
        \\  call:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo ok
        \\
    ;

    const result = try test_support.lintAndFix(
        testing.allocator,
        source,
        .{ .workflow = &checkWorkflowCallInputs },
        true,
    );
    defer result.deinit(testing.allocator);

    try testing.expect(std.mem.indexOf(u8, result.content, "type: string") != null);
}
