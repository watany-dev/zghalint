//! EXPR012 — contextual typing of the `needs` context (issue #88).
//!
//! `needs.<job>` is only usable for jobs listed in the current job's `needs:`,
//! its only properties are `outputs` and `result`, and `needs.<job>.outputs.<name>`
//! must name an output the referenced job declares. All three need the whole
//! workflow, so this is a `check_workflow` rule rather than part of the
//! per-step expression rule.

const std = @import("std");
const engine = @import("engine.zig");
const expressions = @import("expressions.zig");
const expr_check = @import("expr_check.zig");
const spans = @import("spans.zig");
const util = @import("../util.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml = @import("../yaml/types.zig");
const test_support = @import("../test_support.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const Job = engine.Job;
const DiagnosticList = engine.DiagnosticList;
const Span = yaml.Span;
const Anchor = spans.Anchor;

/// The two properties GitHub exposes under `needs.<job>`.
const needs_properties = [_][]const u8{ "outputs", "result" };

/// Job IDs and context properties are matched case-insensitively, the way the
/// runner resolves context keys, so a case difference is never reported.
fn eqlId(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

const NeedsVisitor = struct {
    wf: *const Workflow,
    job: *const Job,
    list: *DiagnosticList,

    /// Diagnostic messages are formatted into the list's own allocator, so
    /// nothing from the parse tree outlives this call and the arena is freed
    /// here rather than leaked the way `expressions.zig` has to.
    pub fn onExpression(self: *const NeedsVisitor, expr: []const u8, span: Span) void {
        // Most expressions never mention `needs`; parsing them would be pure
        // overhead on a large workflow.
        if (std.ascii.indexOfIgnoreCase(expr, "needs") == null) return;

        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        var parser = expressions.ExprParser.init(arena.allocator(), expr);
        // A malformed expression is EXPR001's to report.
        const node = parser.parse() catch return;
        self.walk(&node, span);
    }

    fn walk(self: *const NeedsVisitor, node: *const expressions.ExprNode, span: Span) void {
        if (node.kind == .context_access) {
            self.checkPath(node.value, span);
            return;
        }
        for (node.children) |*child| self.walk(child, span);
    }

    fn checkPath(self: *const NeedsVisitor, path: []const u8, span: Span) void {
        var iter = expr_check.SegmentIter{ .path = path };
        const root = identSegment(iter.next()) orelse return;
        if (!eqlId(root, "needs")) return;

        // `needs` alone (`toJSON(needs)`) and computed keys
        // (`needs[matrix.job]`) carry nothing to check.
        const job_id = identSegment(iter.next()) orelse return;

        const target = self.findJob(job_id);
        if (!self.isNeeded(job_id)) {
            self.reportNotNeeded(job_id, target != null, span);
            return;
        }
        // A `needs:` entry naming no job is a workflow-level problem, not an
        // expression one.
        const dep = target orelse return;

        const property = identSegment(iter.next()) orelse return;
        if (!isKnownProperty(property)) {
            self.reportUnknownProperty(job_id, property, span);
            return;
        }
        if (!eqlId(property, "outputs")) return;

        // Outputs of a reusable workflow live in the called file; RW005 owns them.
        if (dep.uses != null) return;

        const output = identSegment(iter.next()) orelse return;
        for (dep.outputs) |declared| {
            if (eqlId(declared.name, output)) return;
        }
        self.reportUnknownOutput(dep, output, span);
    }

    fn findJob(self: *const NeedsVisitor, job_id: []const u8) ?*const Job {
        for (self.wf.jobs) |*candidate| {
            if (eqlId(candidate.id, job_id)) return candidate;
        }
        return null;
    }

    fn isNeeded(self: *const NeedsVisitor, job_id: []const u8) bool {
        for (self.job.needs) |dep| {
            if (eqlId(dep, job_id)) return true;
        }
        return false;
    }

    fn reportNotNeeded(self: *const NeedsVisitor, job_id: []const u8, exists: bool, span: Span) void {
        const alloc = self.list.fixAllocator();
        const message = if (exists)
            std.fmt.allocPrint(
                alloc,
                "\"{s}\" is not in the \"needs\" of this job",
                .{job_id},
            ) catch return
        else
            std.fmt.allocPrint(
                alloc,
                "\"{s}\" is not a job in this workflow{s}",
                .{ job_id, self.jobIdSuggestion(job_id) },
            ) catch return;

        self.list.append(.{
            .rule_id = "EXPR012",
            .severity = .@"error",
            .message = message,
            .span = span,
            .fix_hint = if (exists)
                "add the job to this job's `needs:`, or drop the reference"
            else
                "reference a job defined in this workflow",
        }) catch return;
    }

    fn reportUnknownProperty(self: *const NeedsVisitor, job_id: []const u8, property: []const u8, span: Span) void {
        const alloc = self.list.fixAllocator();
        var suffix_buf: [64]u8 = undefined;
        const suffix = if (util.didYouMean(property, &needs_properties)) |s|
            std.fmt.bufPrint(&suffix_buf, ". did you mean \"{s}\"?", .{s}) catch ""
        else
            "";
        const message = std.fmt.allocPrint(
            alloc,
            "unknown property \"{s}\" on \"needs.{s}\"{s}",
            .{ property, job_id, suffix },
        ) catch return;

        self.list.append(.{
            .rule_id = "EXPR012",
            .severity = .@"error",
            .message = message,
            .span = span,
            .fix_hint = "`needs.<job>` only has \"outputs\" and \"result\"",
        }) catch return;
    }

    fn reportUnknownOutput(self: *const NeedsVisitor, dep: *const Job, output: []const u8, span: Span) void {
        const alloc = self.list.fixAllocator();
        const message = std.fmt.allocPrint(
            alloc,
            "output \"{s}\" is not defined in job \"{s}\"{s}",
            .{ output, dep.id, self.outputSuggestion(dep, output) },
        ) catch return;

        self.list.append(.{
            .rule_id = "EXPR012",
            .severity = .@"error",
            .message = message,
            .span = span,
            .fix_hint = "declare the output under the referenced job's `outputs:`",
        }) catch return;
    }

    /// Allocated from the diagnostic allocator so the suffix outlives this
    /// call; allocation failure degrades to no suggestion.
    fn jobIdSuggestion(self: *const NeedsVisitor, job_id: []const u8) []const u8 {
        const alloc = self.list.fixAllocator();
        const names = alloc.alloc([]const u8, self.wf.jobs.len) catch return "";
        for (self.wf.jobs, names) |*candidate, *name| name.* = candidate.id;
        return suggestionSuffix(alloc, job_id, names);
    }

    fn outputSuggestion(self: *const NeedsVisitor, dep: *const Job, output: []const u8) []const u8 {
        const alloc = self.list.fixAllocator();
        const names = alloc.alloc([]const u8, dep.outputs.len) catch return "";
        for (dep.outputs, names) |declared, *name| name.* = declared.name;
        return suggestionSuffix(alloc, output, names);
    }

    fn visitIf(
        self: *const NeedsVisitor,
        if_condition: ?[]const u8,
        meta: ?workflow_types.ScalarValueMeta,
        fallback: Span,
    ) void {
        const if_val = if_condition orelse return;
        const anchor = Anchor.fromMeta(meta, fallback);

        // `if:` may omit the `${{ }}` wrapper, in which case the whole value
        // is one expression.
        if (std.mem.indexOf(u8, if_val, "${{") == null) {
            const trimmed = std.mem.trim(u8, if_val, " \t\n\r");
            if (trimmed.len == 0) return;
            const leading = std.mem.indexOfNone(u8, if_val, " \t\n\r") orelse 0;
            self.onExpression(trimmed, anchor.at(if_val, leading, trimmed.len));
            return;
        }
        expressions.forEachExpression(if_val, anchor, self);
    }

    fn visitScalarMap(
        self: *const NeedsVisitor,
        map: ?workflow_types.StringMap,
        meta_map: ?workflow_types.ScalarValueMetaMap,
        fallback: Span,
    ) void {
        const values = map orelse return;
        for (values.keys(), values.values()) |key, value| {
            const entry_meta = if (meta_map) |m| m.get(key) else null;
            expressions.forEachExpression(value, Anchor.fromMeta(entry_meta, fallback), self);
        }
    }
};

fn suggestionSuffix(alloc: std.mem.Allocator, name: []const u8, candidates: []const []const u8) []const u8 {
    const suggestion = util.didYouMean(name, candidates) orelse return "";
    return std.fmt.allocPrint(alloc, ". did you mean \"{s}\"?", .{suggestion}) catch "";
}

fn isKnownProperty(name: []const u8) bool {
    for (needs_properties) |known| {
        if (eqlId(known, name)) return true;
    }
    return false;
}

/// Only plain identifiers are checked: a computed or globbed segment
/// (`needs['a']`, `needs.*`) has no literal name to compare.
fn identSegment(segment: ?expr_check.Segment) ?[]const u8 {
    const seg = segment orelse return null;
    return switch (seg) {
        .ident => |name| name,
        .star, .index_string => null,
    };
}

fn checkNeedsContext(wf: *const Workflow, list: *DiagnosticList) void {
    for (wf.jobs) |*job| {
        const visitor = NeedsVisitor{ .wf = wf, .job = job, .list = list };

        visitor.visitIf(job.if_condition, job.if_condition_meta, job.span);
        visitor.visitScalarMap(job.env, job.env_meta, job.span);
        // Job-level `with:` feeds a reusable workflow call; per-entry spans
        // are not captured, so the job span anchors them.
        visitor.visitScalarMap(job.with, null, job.span);

        for (job.steps) |*step| {
            if (step.run) |run_val| {
                expressions.forEachExpression(run_val, spans.runAnchor(step), &visitor);
            }
            visitor.visitIf(step.if_condition, step.if_condition_meta, step.span);
            visitor.visitScalarMap(step.with, step.with_meta, step.span);
            visitor.visitScalarMap(step.env, step.env_meta, step.span);
        }
    }
}

pub const rules = [_]Rule{
    .{
        .id = "EXPR012",
        .name = "needs-context",
        .description = "Validates needs.<job>.outputs.<name> references against the workflow",
        .severity = .@"error",
        .category = .expression,
        .check_workflow = checkNeedsContext,
    },
};

const testing = std.testing;

fn diagnose(arena: std.mem.Allocator, source: []const u8, list: *DiagnosticList) !void {
    const wf = try test_support.parseWorkflowSource(arena, source);
    checkNeedsContext(&wf, list);
}

fn expectNoDiagnostics(source: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    try diagnose(arena.allocator(), source, &list);
    if (list.len() != 0) {
        std.debug.print("unexpected diagnostic: {s}\n", .{list.get(0).message});
        return error.UnexpectedDiagnostic;
    }
}

fn expectMessage(source: []const u8, needle: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    try diagnose(arena.allocator(), source, &list);
    try testing.expectEqual(@as(usize, 1), list.len());
    const diag = list.get(0);
    try testing.expectEqualStrings("EXPR012", diag.rule_id);
    try testing.expectEqual(engine.Severity.@"error", diag.severity);
    if (std.mem.indexOf(u8, diag.message, needle) == null) {
        std.debug.print("message '{s}' does not contain '{s}'\n", .{ diag.message, needle });
        return error.UnexpectedMessage;
    }
}

const issue_88_source =
    \\on: push
    \\jobs:
    \\  setup:
    \\    runs-on: ubuntu-latest
    \\    outputs:
    \\      version: ${{ steps.v.outputs.version }}
    \\    steps:
    \\      - id: v
    \\        run: echo "version=1" >> "$GITHUB_OUTPUT"
    \\  lint:
    \\    runs-on: ubuntu-latest
    \\    steps:
    \\      - run: echo hi
    \\  build:
    \\    needs: [setup]
    \\    runs-on: ubuntu-latest
    \\    steps:
    \\      - run: echo "${{ needs.setup.outputs.ver }}"
    \\      - run: echo "${{ needs.lint.result }}"
    \\      - run: echo "${{ needs.setup.output.version }}"
    \\
;

test "EXPR012: the three detections from issue #88" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    try diagnose(arena.allocator(), issue_88_source, &list);

    try testing.expectEqual(@as(usize, 3), list.len());
    // "ver" is 4 edits from "version", past `util.didYouMean`'s threshold of 2,
    // so no suggestion is appended.
    try testing.expect(std.mem.indexOf(u8, list.get(0).message, "output \"ver\" is not defined in job \"setup\"") != null);
    try testing.expect(std.mem.indexOf(u8, list.get(1).message, "\"lint\" is not in the \"needs\" of this job") != null);
    try testing.expect(std.mem.indexOf(u8, list.get(2).message, "unknown property \"output\" on \"needs.setup\". did you mean \"outputs\"?") != null);
}

test "EXPR012: valid needs references produce no diagnostics" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  setup:
        \\    runs-on: ubuntu-latest
        \\    outputs:
        \\      version: ${{ steps.v.outputs.version }}
        \\    steps:
        \\      - id: v
        \\        run: echo "version=1" >> "$GITHUB_OUTPUT"
        \\  build:
        \\    needs: [setup]
        \\    if: needs.setup.result == 'success'
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ needs.setup.outputs.version }}"
        \\
    );
}

test "EXPR012: a job absent from the workflow is named as such" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  setup:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\  build:
        \\    needs: [setup]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ needs.setpu.result }}"
        \\
    , "\"setpu\" is not a job in this workflow. did you mean \"setup\"?");
}

test "EXPR012: a needs entry naming no job is left to workflow-level checks" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    needs: [ghost]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ needs.ghost.outputs.anything }}"
        \\
    );
}

test "EXPR012: outputs of a reusable workflow call are left to RW005" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  called:
        \\    uses: ./.github/workflows/reusable.yml
        \\  build:
        \\    needs: [called]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ needs.called.outputs.whatever }}"
        \\
    );
}

test "EXPR012: computed and bare needs accesses are skipped" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  setup:
        \\    runs-on: ubuntu-latest
        \\    outputs:
        \\      version: '1'
        \\    steps:
        \\      - run: echo hi
        \\  build:
        \\    needs: [setup]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ toJSON(needs) }}"
        \\      - run: echo "${{ needs['setup'].outputs.version }}"
        \\      - run: echo "${{ needs.setup.outputs['version'] }}"
        \\
    );
}

test "EXPR012: job IDs and output names match case-insensitively" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  Setup:
        \\    runs-on: ubuntu-latest
        \\    outputs:
        \\      Version: '1'
        \\    steps:
        \\      - run: echo hi
        \\  build:
        \\    needs: [Setup]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ needs.setup.outputs.version }}"
        \\
    );
}

test "EXPR012: context property names match case-insensitively" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  setup:
        \\    runs-on: ubuntu-latest
        \\    outputs:
        \\      version: '1'
        \\    steps:
        \\      - run: echo hi
        \\  build:
        \\    needs: [setup]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ NEEDS.setup.OUTPUTS.version }}"
        \\      - run: echo "${{ needs.setup.RESULT }}"
        \\
    );
}

test "EXPR012: needs references in job env, step env, with and if are checked" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    try diagnose(arena.allocator(),
        \\on: push
        \\jobs:
        \\  setup:
        \\    runs-on: ubuntu-latest
        \\    outputs:
        \\      version: '1'
        \\    steps:
        \\      - run: echo hi
        \\  build:
        \\    needs: [setup]
        \\    runs-on: ubuntu-latest
        \\    env:
        \\      A: ${{ needs.setup.outputs.a }}
        \\    steps:
        \\      - if: ${{ needs.setup.outputs.b }}
        \\        env:
        \\          C: ${{ needs.setup.outputs.c }}
        \\        uses: actions/checkout@v4
        \\        with:
        \\          ref: ${{ needs.setup.outputs.d }}
        \\
    , &list);

    try testing.expectEqual(@as(usize, 4), list.len());
    try testing.expectEqual(@as(usize, 4), test_support.countDiagnostics(&list, "EXPR012"));
}
