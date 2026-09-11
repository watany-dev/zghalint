//! EXPR010 — resolve `steps.<id>` references against the steps actually
//! declared in the surrounding job (#86).
//!
//! `steps` is a loose object in the builtin catalog (`expr_catalog.zig`), so
//! the generic path walker accepts any `<id>` and any property below it. The
//! per-job step list is workflow data, not catalog data, so the check lives
//! here and hangs off `check_job`: only a job knows its steps *and* their
//! order, and order is what makes `steps.<id>` valid or not at a given step.
//!
//! It is the first of the contextual-typing rules (EXPR010-EXPR014), so the
//! reference resolution here is written to be shared by the rest.

const std = @import("std");
const engine = @import("engine.zig");
const expr_check = @import("expr_check.zig");
const expr_scan = @import("expr_scan.zig");
const spans = @import("spans.zig");
const util = @import("../util.zig");
const rename = @import("rename.zig");
const test_support = @import("../test_support.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const Step = engine.Step;
const DiagnosticList = engine.DiagnosticList;
const Span = spans.Span;

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
        addDefinedStep(step.id, index, buf, alloc);
        addNestedDefinedSteps(step.nestedSteps(), index, buf, alloc);
    }
}

fn addDefinedStep(id: ?[]const u8, index: usize, buf: *std.ArrayList(DefinedStep), alloc: std.mem.Allocator) void {
    const step_id = id orelse return;
    if (step_id.len == 0) return;
    for (buf.items) |seen| {
        if (idEql(seen.id, step_id)) return;
    }
    buf.append(alloc, .{ .id = step_id, .index = index }) catch return;
}

fn addNestedDefinedSteps(steps: []const Step, index: usize, buf: *std.ArrayList(DefinedStep), alloc: std.mem.Allocator) void {
    for (steps) |step| {
        addDefinedStep(step.id, index, buf, alloc);
        addNestedDefinedSteps(step.nestedSteps(), index, buf, alloc);
    }
}

const Resolver = struct {
    defined: []const DefinedStep,
    /// Suggestion candidates. A step declared later cannot be the intended
    /// target either, but it is still the likeliest typo source, so it stays
    /// in the list.
    ids: []const []const u8,
    /// Index of the *top-level* step whose expressions are being scanned.
    /// Nested `parallel:` children share this index so they are not "earlier"
    /// than each other; `current_id` distinguishes a true self-reference
    /// from a sibling in the same group.
    current: usize,
    current_id: ?[]const u8 = null,
    /// Backs the expression parse trees, which never outlive a walk;
    /// diagnostic messages go to the list's own arena instead.
    alloc: std.mem.Allocator,
    list: *DiagnosticList,

    fn find(self: Resolver, id: []const u8) ?DefinedStep {
        for (self.defined) |candidate| {
            if (idEql(candidate.id, id)) return candidate;
        }
        return null;
    }

    /// The hook `expr_scan` calls for every context access it finds.
    pub fn checkPath(self: Resolver, path: []const u8, span: Span) void {
        checkStepPath(self, path, span);
    }
};

/// `path` is the whole `steps.<id>...` path the span covers; the rename lands
/// on the id segment alone.
fn appendUnknownStep(res: Resolver, path: []const u8, id: []const u8, span: Span) void {
    const alloc = res.list.fixAllocator();
    const suggestion = util.didYouMean(id, res.ids);
    const message = if (suggestion) |s|
        std.fmt.allocPrint(alloc, "step \"{s}\" is not defined in this job. did you mean \"{s}\"?", .{ id, s }) catch return
    else
        std.fmt.allocPrint(alloc, "step \"{s}\" is not defined in this job", .{id}) catch return;

    res.list.append(.{
        .rule_id = "EXPR010",
        .severity = .@"error",
        .message = message,
        .span = span,
        .fix_hint = "give the target step an `id:` and reference that id, or fix the typo",
        .fix = if (suggestion) |s| rename.pathSegmentFix(res.list, span, path, 1, s) else null,
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

fn appendUnknownProperty(res: Resolver, path: []const u8, id: []const u8, prop: []const u8, span: Span) void {
    const alloc = res.list.fixAllocator();
    const suggestion = util.didYouMean(prop, &step_properties);
    const message = if (suggestion) |s|
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
        .fix = if (suggestion) |s| rename.pathSegmentFix(res.list, span, path, 2, s) else null,
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

fn checkStepPath(res: Resolver, path: []const u8, span: Span) void {
    var iter = expr_check.SegmentIter{ .path = path };
    const root = iter.next() orelse return;
    const root_name = segmentName(root) orelse return;
    if (!std.ascii.eqlIgnoreCase(root_name, "steps")) return;

    const id_seg = iter.next() orelse return;
    const id = segmentName(id_seg) orelse return;

    const target = res.find(id) orelse {
        appendUnknownStep(res, path, id, span);
        return;
    };
    if (target.index == res.current) {
        if (res.current_id) |own| {
            if (idEql(own, id)) {
                appendSelfReference(res, id, span);
                return;
            }
        }
        appendForwardReference(res, id, span);
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
    appendUnknownProperty(res, path, id, prop, span);
}

pub fn checkJob(job: *const Job, list: *DiagnosticList) void {
    if (job.steps.len == 0) return;

    // Scratch for the expression parser: no diagnostic points at it, and
    // the list's allocator keeps it under the run's leak detection (#159).
    var arena = std.heap.ArenaAllocator.init(list.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var defined: std.ArrayList(DefinedStep) = .empty;
    collectStepIds(job, &defined, alloc);

    var ids: std.ArrayList([]const u8) = .empty;
    for (defined.items) |entry| ids.append(alloc, entry.id) catch return;

    // A job where no step carries an `id:` is not skipped: there every
    // `steps.<id>` reference is certainly undefined.
    for (job.steps, 0..) |*step, index| {
        scanStepTree(step, Resolver{
            .defined = defined.items,
            .ids = ids.items,
            .current = index,
            .alloc = alloc,
            .list = list,
        });
    }
}

fn scanStepTree(step: *const Step, resolver: Resolver) void {
    var current = resolver;
    current.current_id = step.id;
    expr_scan.scanStep(current, step);
    for (step.nestedSteps()) |*child| scanStepTree(child, resolver);
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
    if (std.mem.find(u8, diag.message, needle) == null) {
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

test "EXPR010: a job where no step has an id still resolves references" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ steps.setup.outputs.v }}"
    ,
        "step \"setup\" is not defined in this job",
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

test "EXPR010: a parallel sibling is not this step itself" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - parallel:
        \\          - id: frontend
        \\            run: echo v=1 >> "$GITHUB_OUTPUT"
        \\          - run: echo "${{ steps.frontend.outputs.v }}"
    ,
        "step \"frontend\" is defined after this step",
    );
}

test "EXPR010: a parallel child's outputs are available after the group" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - parallel:
        \\          - id: frontend
        \\            run: echo v=1 >> "$GITHUB_OUTPUT"
        \\          - run: echo backend
        \\      - run: echo "${{ steps.frontend.outputs.v }}"
    );
}

test "EXPR010: a self-reference inside parallel is still this step" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - parallel:
        \\          - id: frontend
        \\            run: echo "${{ steps.frontend.outputs.v }}"
        \\          - run: echo backend
    ,
        "step \"frontend\" is this step itself",
    );
}
