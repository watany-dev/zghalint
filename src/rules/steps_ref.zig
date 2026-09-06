//! EXPR010 — resolve `steps.<id>` references against the steps actually
//! declared in the surrounding job (#86).
//!
//! `steps` is a loose object in the builtin catalog (`expr_catalog.zig`), so
//! the generic path walker accepts any `<id>` and any property below it. The
//! per-job step list is workflow data, not catalog data, so the check lives
//! here and hangs off `check_job`: only a job knows its steps *and* their
//! order, and order is what makes `steps.<id>` valid or not at a given step.
//!
//! This is the first of the contextual-typing rules (EXPR010-EXPR014); the
//! reference-resolution shape here — walk every expression of a step, pick
//! out the accesses rooted at one context, resolve them against per-job
//! data — is meant to be shared by the rest.

const std = @import("std");
const engine = @import("engine.zig");
const expressions = @import("expressions.zig");
const expr_check = @import("expr_check.zig");
const spans = @import("spans.zig");
const util = @import("../util.zig");
const workflow_types = @import("../workflow/types.zig");
const test_support = @import("../test_support.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const Step = engine.Step;
const DiagnosticList = engine.DiagnosticList;
const Span = spans.Span;
const Anchor = spans.Anchor;
const ExprNode = expressions.ExprNode;

/// The only properties GitHub exposes directly under `steps.<id>`. Anything
/// below `outputs` is defined by the action itself, so it is not checked here
/// (DEP004 / DEP005 own that).
const step_properties = [_][]const u8{ "outputs", "conclusion", "outcome" };

const DefinedStep = struct {
    id: []const u8,
    /// Index of the *first* step carrying this id. Duplicate ids are SYN006's
    /// finding; resolving to the earliest one keeps this rule from piling a
    /// second, order-based complaint on top of it.
    index: usize,
};

/// Step IDs are matched case-insensitively because GitHub resolves
/// expression paths that way (`steps.Setup` reaches a step with `id: setup`).
fn idEql(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn collectStepIds(job: *const Job, buf: *std.ArrayList(DefinedStep), alloc: std.mem.Allocator) void {
    for (job.steps, 0..) |step, index| {
        const id = step.id orelse continue;
        if (id.len == 0) continue;
        for (buf.items) |seen| {
            if (idEql(seen.id, id)) break;
        } else {
            buf.append(alloc, .{ .id = id, .index = index }) catch return;
        }
    }
}

const Resolver = struct {
    defined: []const DefinedStep,
    /// Index of the step whose expressions are being scanned.
    current: usize,
    list: *DiagnosticList,

    fn find(self: Resolver, id: []const u8) ?DefinedStep {
        for (self.defined) |candidate| {
            if (idEql(candidate.id, id)) return candidate;
        }
        return null;
    }

    fn suggestId(self: Resolver, id: []const u8, alloc: std.mem.Allocator) ?[]const u8 {
        var names: std.ArrayList([]const u8) = .empty;
        defer names.deinit(alloc);
        for (self.defined) |candidate| {
            // A step declared later cannot be the intended target either, but
            // it is still the likeliest typo source, so it stays a candidate.
            names.append(alloc, candidate.id) catch return null;
        }
        return util.didYouMean(id, names.items);
    }
};

fn appendUnknownStep(res: Resolver, id: []const u8, span: Span) void {
    const alloc = res.list.fixAllocator();
    const message = if (res.suggestId(id, alloc)) |s|
        std.fmt.allocPrint(alloc, "step \"{s}\" is not defined in this job. did you mean \"{s}\"?", .{ id, s }) catch return
    else
        std.fmt.allocPrint(alloc, "step \"{s}\" is not defined in this job", .{id}) catch return;

    res.list.append(.{
        .rule_id = "EXPR010",
        .severity = .@"error",
        .message = message,
        .span = span,
        .fix_hint = "give the target step an `id:` and reference that id, or fix the typo",
    }) catch return;
}

fn appendForwardReference(res: Resolver, id: []const u8, span: Span) void {
    const alloc = res.list.fixAllocator();
    const message = std.fmt.allocPrint(
        alloc,
        "step \"{s}\" is defined after this step, so it has no value here",
        .{id},
    ) catch return;

    res.list.append(.{
        .rule_id = "EXPR010",
        .severity = .@"error",
        .message = message,
        .span = span,
        .fix_hint = "move the referenced step before this one, or reference a step that already ran",
    }) catch return;
}

fn appendSelfReference(res: Resolver, id: []const u8, span: Span) void {
    const alloc = res.list.fixAllocator();
    const message = std.fmt.allocPrint(
        alloc,
        "step \"{s}\" is this step itself, so its outputs are not available here",
        .{id},
    ) catch return;

    res.list.append(.{
        .rule_id = "EXPR010",
        .severity = .@"error",
        .message = message,
        .span = span,
        .fix_hint = "reference a step that already ran",
    }) catch return;
}

fn appendUnknownProperty(res: Resolver, id: []const u8, prop: []const u8, span: Span) void {
    const alloc = res.list.fixAllocator();
    const message = if (util.didYouMean(prop, &step_properties)) |s|
        std.fmt.allocPrint(alloc, "unknown property \"{s}\" on step \"{s}\". did you mean \"{s}\"?", .{ prop, id, s }) catch return
    else
        std.fmt.allocPrint(
            alloc,
            "unknown property \"{s}\" on step \"{s}\". valid properties are \"outputs\", \"conclusion\" and \"outcome\"",
            .{ prop, id },
        ) catch return;

    res.list.append(.{
        .rule_id = "EXPR010",
        .severity = .@"error",
        .message = message,
        .span = span,
        .fix_hint = "use `outputs`, `conclusion` or `outcome`",
    }) catch return;
}

/// `steps.*` and `steps[expr]` carry no resolvable id, so they are skipped
/// rather than guessed at.
fn segmentName(seg: expr_check.Segment) ?[]const u8 {
    return switch (seg) {
        .ident => |name| name,
        .index_string => |name| name,
        .star => null,
    };
}

fn checkPath(res: Resolver, path: []const u8, span: Span) void {
    var iter = expr_check.SegmentIter{ .path = path };
    const root = iter.next() orelse return;
    const root_name = segmentName(root) orelse return;
    if (!std.ascii.eqlIgnoreCase(root_name, "steps")) return;

    const id_seg = iter.next() orelse return;
    const id = segmentName(id_seg) orelse return;

    const target = res.find(id) orelse {
        appendUnknownStep(res, id, span);
        return;
    };
    if (target.index == res.current) {
        appendSelfReference(res, id, span);
        return;
    }
    if (target.index > res.current) {
        appendForwardReference(res, id, span);
        return;
    }

    const prop_seg = iter.next() orelse return;
    const prop = segmentName(prop_seg) orelse return;
    for (step_properties) |valid| {
        if (std.ascii.eqlIgnoreCase(prop, valid)) return;
    }
    appendUnknownProperty(res, id, prop, span);
}

const Scan = struct {
    res: Resolver,
    text: []const u8,
    anchor: Anchor,
    /// Offset of the expression source inside `text`, so a node's
    /// expression-relative byte range maps back to a file position.
    expr_offset: usize,

    fn spanOf(self: Scan, node: *const ExprNode) Span {
        const start = self.expr_offset + node.start_byte;
        const len = if (node.end_byte > node.start_byte) node.end_byte - node.start_byte else 0;
        return self.anchor.at(self.text, start, len);
    }

    fn walk(self: Scan, node: *const ExprNode) void {
        if (node.kind == .context_access) {
            checkPath(self.res, node.value, self.spanOf(node));
            return;
        }
        for (node.children) |*child| self.walk(child);
    }
};

/// A parse failure is EXPR001's finding; this rule stays silent on it.
fn scanExpression(res: Resolver, text: []const u8, anchor: Anchor, expr_offset: usize, expr: []const u8) void {
    var parser = expressions.ExprParser.init(arenaAllocator(), expr);
    const node = parser.parse() catch return;
    const scan = Scan{ .res = res, .text = text, .anchor = anchor, .expr_offset = expr_offset };
    scan.walk(&node);
}

/// Mirrors `expressions.getArenaAllocator`: the parse tree only has to
/// outlive the walk, and the engine hands rules no arena (#159).
fn arenaAllocator() std.mem.Allocator {
    return std.heap.page_allocator;
}

fn scanInterpolatedText(res: Resolver, text: []const u8, anchor: Anchor) void {
    var pos: usize = 0;
    while (pos + 2 < text.len) {
        if (!(text[pos] == '$' and text[pos + 1] == '{' and text[pos + 2] == '{')) {
            pos += 1;
            continue;
        }
        const expr_start = pos + 3;
        const end_offset = std.mem.indexOf(u8, text[expr_start..], "}}") orelse return;
        const content = text[expr_start .. expr_start + end_offset];
        pos = expr_start + end_offset + 2;

        const leading = std.mem.indexOfNone(u8, content, " \t\n\r") orelse continue;
        const trimmed = std.mem.trim(u8, content, " \t\n\r");
        scanExpression(res, text, anchor, expr_start + leading, trimmed);
    }
}

/// `if:` may omit the `${{ }}` wrapper, in which case the whole scalar is one
/// expression.
fn scanCondition(res: Resolver, condition: ?[]const u8, meta: ?workflow_types.ScalarValueMeta, fallback: Span) void {
    const value = condition orelse return;
    const anchor = Anchor.fromMeta(meta, fallback);
    if (std.mem.indexOf(u8, value, "${{") != null) {
        scanInterpolatedText(res, value, anchor);
        return;
    }
    const trimmed = std.mem.trim(u8, value, " \t\n\r");
    if (trimmed.len == 0) return;
    const leading: usize = @intFromPtr(trimmed.ptr) - @intFromPtr(value.ptr);
    scanExpression(res, value, anchor, leading, trimmed);
}

fn scanScalarMap(
    res: Resolver,
    map: ?workflow_types.StringMap,
    meta_map: ?workflow_types.ScalarValueMetaMap,
    fallback: Span,
) void {
    const values = map orelse return;
    for (values.keys(), values.values()) |key, value| {
        const entry_meta = if (meta_map) |m| m.get(key) else null;
        scanInterpolatedText(res, value, Anchor.fromMeta(entry_meta, fallback));
    }
}

fn scanStep(res: Resolver, step: *const Step) void {
    if (step.run) |run_val| {
        scanInterpolatedText(res, run_val, spans.runAnchor(step));
    }
    scanCondition(res, step.if_condition, step.if_condition_meta, step.span);
    scanScalarMap(res, step.with, step.with_meta, step.span);
    scanScalarMap(res, step.env, step.env_meta, step.span);
}

pub fn checkJob(job: *const Job, list: *DiagnosticList) void {
    if (job.steps.len == 0) return;

    const alloc = arenaAllocator();
    var defined: std.ArrayList(DefinedStep) = .empty;
    defer defined.deinit(alloc);
    collectStepIds(job, &defined, alloc);
    if (defined.items.len == 0) return;

    for (job.steps, 0..) |*step, index| {
        scanStep(.{ .defined = defined.items, .current = index, .list = list }, step);
    }
}

pub const step_reference_rule = Rule{
    .id = "EXPR010",
    .name = "undefined-step-reference",
    .description = "`steps.<id>` must name a step defined earlier in the same job",
    .severity = .@"error",
    .category = .expression,
    .check_job = &checkJob,
};

pub const rules = [_]Rule{step_reference_rule};

const testing = std.testing;

fn runOnSource(source: []const u8, list: *DiagnosticList) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);
    for (wf.jobs) |*job| checkJob(job, list);
}

fn expectMessage(source: []const u8, needle: []const u8) !void {
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    try runOnSource(source, &list);

    const diag = test_support.findDiagnostic(&list, "EXPR010") orelse {
        std.debug.print("no EXPR010 diagnostic for source:\n{s}\n", .{source});
        return error.MissingDiagnostic;
    };
    if (std.mem.indexOf(u8, diag.message, needle) == null) {
        std.debug.print("message \"{s}\" does not contain \"{s}\"\n", .{ diag.message, needle });
        return error.UnexpectedMessage;
    }
}

fn expectNoDiagnostics(source: []const u8) !void {
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    try runOnSource(source, &list);
    if (list.len() != 0) {
        std.debug.print("unexpected diagnostic: {s}\n", .{list.get(0).message});
        return error.UnexpectedDiagnostic;
    }
}

test "EXPR010: a misspelled step id is reported with a suggestion" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: setup
        \\        run: echo "v=1" >> "$GITHUB_OUTPUT"
        \\      - run: echo "${{ steps.stup.outputs.v }}"
    ,
        "step \"stup\" is not defined in this job. did you mean \"setup\"?",
    );
}

test "EXPR010: an unrelated step id is reported without a suggestion" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: setup
        \\        run: echo hi
        \\      - run: echo "${{ steps.deploy_release.outputs.v }}"
    ,
        "step \"deploy_release\" is not defined in this job",
    );
}

test "EXPR010: an unknown property under a step is reported" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: setup
        \\        run: echo hi
        \\      - run: echo "${{ steps.setup.output.v }}"
    ,
        "unknown property \"output\" on step \"setup\". did you mean \"outputs\"?",
    );
}

test "EXPR010: an unknown property with no near match lists the valid ones" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: setup
        \\        run: echo hi
        \\      - run: echo "${{ steps.setup.result }}"
    ,
        "valid properties are \"outputs\", \"conclusion\" and \"outcome\"",
    );
}

test "EXPR010: a step defined later in the job is a forward reference" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ steps.later.outputs.v }}"
        \\      - id: later
        \\        run: echo hi
    ,
        "step \"later\" is defined after this step",
    );
}

test "EXPR010: a step referencing its own id is reported" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: setup
        \\        run: echo hi
        \\      - id: build
        \\        run: echo "${{ steps.build.outputs.v }}"
    ,
        "step \"build\" is this step itself",
    );
}

test "EXPR010: references in if, with and env are checked" {
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    try runOnSource(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: setup
        \\        run: echo hi
        \\      - if: steps.stup.conclusion == 'success'
        \\        uses: actions/checkout@v4
        \\        with:
        \\          ref: ${{ steps.stup.outputs.v }}
        \\        env:
        \\          V: ${{ steps.stup.outputs.v }}
    , &list);

    try testing.expectEqual(@as(usize, 3), test_support.countDiagnostics(&list, "EXPR010"));
}

test "EXPR010: valid backward references and properties are accepted" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: setup
        \\        run: echo "v=1" >> "$GITHUB_OUTPUT"
        \\      - if: steps.setup.conclusion == 'success'
        \\        run: echo "${{ steps.setup.outputs.v }} ${{ steps.setup.outcome }}"
    );
}

test "EXPR010: step ids resolve case-insensitively" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: Setup
        \\        run: echo hi
        \\      - run: echo "${{ steps.setup.outputs.v }}"
    );
}

// The expression parser accepts `[...]` only at the end of a path, so this
// covers `steps['id']` on its own; `steps['id'].outputs` is EXPR001's finding.
test "EXPR010: bracket access resolves the step id" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: setup
        \\        run: echo hi
        \\      - run: echo "${{ steps['stup'] }}"
    ,
        "step \"stup\" is not defined in this job",
    );
}

test "EXPR010: an id-less job is left alone" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ steps.setup.outputs.v }}"
    );
}

test "EXPR010: steps.* and other contexts are not resolved" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: setup
        \\        run: echo hi
        \\      - run: echo "${{ toJSON(steps.*.outputs) }} ${{ needs.other.outputs.v }}"
    );
}

test "EXPR010: a duplicate id resolves to its first definition" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: setup
        \\        run: echo hi
        \\      - run: echo "${{ steps.setup.outputs.v }}"
        \\      - id: setup
        \\        run: echo hi
    );
}

test "EXPR010: an unparsable expression is left to EXPR001" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: setup
        \\        run: echo hi
        \\      - run: echo "${{ steps.stup. }}"
    );
}

test "EXPR010: the diagnostic points at the reference inside a run scalar" {
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    try runOnSource(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: setup
        \\        run: echo hi
        \\      - run: echo "${{ steps.stup.outputs.v }}"
    , &list);

    const diag = test_support.findDiagnostic(&list, "EXPR010").?;
    try testing.expectEqual(@as(u32, 8), diag.span.start_line);
}
