//! EXPR013 — contextual typing of the `inputs` context (issue #89).
//!
//! `inputs.<name>` is fed by `workflow_dispatch.inputs` and
//! `workflow_call.inputs`; a workflow declaring neither trigger has no
//! `inputs` context at all. Both facts live in `on:`, so this is a
//! `check_workflow` rule.
//!
//! The legacy `github.event.inputs.<name>` spelling is left alone here: it
//! only ever carries `workflow_dispatch` inputs, and the generic path walker
//! already accepts any name below `github.event`.

const std = @import("std");
const engine = @import("engine.zig");
const expr_check = @import("expr_check.zig");
const expr_scan = @import("expr_scan.zig");
const spans = @import("spans.zig");
const util = @import("../util.zig");
const rename = @import("rename.zig");
const test_support = @import("../test_support.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const DiagnosticList = engine.DiagnosticList;
const Span = spans.Span;

/// Context keys resolve case-insensitively on the runner, so `inputs.Version`
/// reaches an input declared as `version`.
fn nameEql(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

const Declared = struct {
    names: []const []const u8,
    /// False when the workflow has neither `workflow_dispatch` nor
    /// `workflow_call`: then `inputs` itself does not exist, which is a
    /// different finding from an undeclared name.
    available: bool,
};

/// The union of both triggers' inputs: a workflow declaring `workflow_call`
/// and `workflow_dispatch` can be reached either way, so a name declared by
/// one of them is valid.
fn collectInputs(wf: *const Workflow, alloc: std.mem.Allocator) Declared {
    var names: std.ArrayList([]const u8) = .empty;
    var available = false;

    for (wf.on.events) |event| {
        switch (event.event) {
            .workflow_call => {
                available = true;
                for (event.workflow_call_inputs) |input| appendUnique(&names, alloc, input.name);
            },
            .workflow_dispatch => {
                available = true;
                for (event.workflow_dispatch_inputs) |input| appendUnique(&names, alloc, input.name);
            },
            else => {},
        }
    }

    return .{
        .names = names.toOwnedSlice(alloc) catch &.{},
        .available = available,
    };
}

fn appendUnique(names: *std.ArrayList([]const u8), alloc: std.mem.Allocator, name: []const u8) void {
    for (names.items) |seen| {
        if (nameEql(seen, name)) return;
    }
    names.append(alloc, name) catch return;
}

const Resolver = struct {
    declared: Declared,
    /// Backs the expression parse trees; diagnostic messages are allocated
    /// from the list's own arena instead.
    alloc: std.mem.Allocator,
    list: *DiagnosticList,

    pub fn checkPath(self: Resolver, path: []const u8, span: Span) void {
        var iter = expr_check.SegmentIter{ .path = path };
        const root = identSegment(iter.next()) orelse return;
        if (!nameEql(root, "inputs")) return;

        if (!self.declared.available) {
            self.reportUnavailable(span);
            return;
        }

        // `inputs` alone (`toJSON(inputs)`) and computed keys
        // (`inputs[matrix.key]`) carry no name to resolve.
        const name = identSegment(iter.next()) orelse return;
        for (self.declared.names) |declared| {
            if (nameEql(declared, name)) return;
        }
        self.reportUnknownInput(path, name, span);
    }

    fn reportUnavailable(self: Resolver, span: Span) void {
        self.list.append(.{
            .rule_id = "EXPR013",
            .severity = .@"error",
            .message = "\"inputs\" is not available: this workflow has neither \"workflow_dispatch\" nor \"workflow_call\"",
            .span = span,
            .fix_hint = "add a `workflow_dispatch:` or `workflow_call:` trigger, or drop the reference",
        }) catch return;
    }

    fn reportUnknownInput(self: Resolver, path: []const u8, name: []const u8, span: Span) void {
        const alloc = self.list.fixAllocator();
        const suggestion = util.didYouMean(name, self.declared.names);
        const suffix = if (suggestion) |s|
            std.fmt.allocPrint(alloc, ". did you mean \"{s}\"?", .{s}) catch ""
        else
            "";
        const message = std.fmt.allocPrint(
            alloc,
            "input \"{s}\" is not defined in this workflow's triggers{s}",
            .{ name, suffix },
        ) catch return;

        self.list.append(.{
            .rule_id = "EXPR013",
            .severity = .@"error",
            .message = message,
            .span = span,
            .fix_hint = "declare the input under `workflow_dispatch.inputs:` or `workflow_call.inputs:`",
            .fix = if (suggestion) |s| rename.pathSegmentFix(self.list, span, path, 1, s) else null,
        }) catch return;
    }
};

/// Only plain identifiers are resolved: a globbed or computed segment
/// (`inputs.*`, `inputs[matrix.key]`) has no literal name.
fn identSegment(segment: ?expr_check.Segment) ?[]const u8 {
    const seg = segment orelse return null;
    return switch (seg) {
        .ident => |name| name,
        .index_string => |name| name,
        .star => null,
    };
}

pub fn checkWorkflow(wf: *const Workflow, list: *DiagnosticList) void {
    // Scratch for the expression parser: no diagnostic points at it, and
    // the list's allocator keeps it under the run's leak detection (#159).
    var arena = std.heap.ArenaAllocator.init(list.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const resolver = Resolver{
        .declared = collectInputs(wf, alloc),
        .alloc = alloc,
        .list = list,
    };

    expr_scan.scanScalarMap(resolver, wf.env, wf.env_meta, spans.workflow_head);
    for (wf.jobs) |*job| expr_scan.scanJob(resolver, job);
}

pub const rules = [_]Rule{
    .{
        .id = "EXPR013",
        .name = "inputs-context",
        .description = "`inputs.<name>` must name an input the workflow's triggers declare",
        .severity = .@"error",
        .category = .expression,
        .check_workflow = &checkWorkflow,
    },
};

const testing = std.testing;

fn diagnose(arena: std.mem.Allocator, source: []const u8, list: *DiagnosticList) !void {
    const wf = try test_support.parseWorkflowSource(arena, source);
    checkWorkflow(&wf, list);
}

fn expectNoDiagnostics(source: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    try diagnose(arena.allocator(), source, &list);
    if (list.len() != 0) {
        std.debug.print("unexpected diagnostic: {s}\n", .{list.get(0).message});
    }
    try testing.expectEqual(@as(usize, 0), list.len());
}

fn expectMessage(source: []const u8, needle: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    try diagnose(arena.allocator(), source, &list);
    for (list.items.items) |diag| {
        if (std.mem.indexOf(u8, diag.message, needle) != null) {
            try testing.expectEqualStrings("EXPR013", diag.rule_id);
            return;
        }
    }
    if (list.len() != 0) {
        std.debug.print("messages did not contain \"{s}\"; first: {s}\n", .{ needle, list.get(0).message });
    }
    return error.MessageNotFound;
}

test "EXPR013: a misspelled dispatch input is reported with a suggestion" {
    try expectMessage(
        \\on:
        \\  workflow_dispatch:
        \\    inputs:
        \\      environment:
        \\        type: string
        \\jobs:
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ inputs.enviroment }}"
    , "input \"enviroment\" is not defined in this workflow's triggers. did you mean \"environment\"?");
}

test "EXPR013: an input no trigger declares is reported" {
    try expectMessage(
        \\on:
        \\  workflow_dispatch:
        \\    inputs:
        \\      environment:
        \\        type: string
        \\jobs:
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ inputs.version }}"
    , "input \"version\" is not defined");
}

test "EXPR013: a workflow with neither trigger has no inputs context" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ inputs.foo }}"
    , "\"inputs\" is not available");
}

test "EXPR013: the union of both triggers' inputs is valid" {
    try expectNoDiagnostics(
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      version:
        \\        type: string
        \\  workflow_dispatch:
        \\    inputs:
        \\      environment:
        \\        type: string
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ inputs.version }} ${{ inputs.environment }}"
    );
}

test "EXPR013: input names resolve case-insensitively" {
    try expectNoDiagnostics(
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      version:
        \\        type: string
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ inputs.VERSION }}"
    );
}

test "EXPR013: a bare inputs reference carries no name to resolve" {
    try expectNoDiagnostics(
        \\on:
        \\  workflow_dispatch:
        \\    inputs:
        \\      version:
        \\        type: string
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ toJSON(inputs) }}"
    );
}

test "EXPR013: job-level if and with are scanned too" {
    try expectMessage(
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      version:
        \\        type: string
        \\jobs:
        \\  build:
        \\    if: inputs.verison == '1'
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    , "input \"verison\" is not defined");
}
