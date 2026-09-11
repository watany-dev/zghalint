//! EXPR019 — `steps.<id>.outputs` of a background step is only defined after
//! a matching `wait` / `wait-all`. GitHub still runs an implicit wait-all
//! before post-job cleanup, so a missing wait with no output reference is
//! not a finding, and `--fix` must not insert `wait` (a long-running
//! producer would hang the job). Closes #433.

const std = @import("std");
const engine = @import("engine.zig");
const expr_check = @import("expr_check.zig");
const expr_scan = @import("expr_scan.zig");
const diagnostics = @import("../diagnostics.zig");
const test_support = @import("../test_support.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const Step = engine.Step;
const DiagnosticList = engine.DiagnosticList;
const Span = diagnostics.Span;

fn idEql(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn containsId(ids: []const []const u8, id: []const u8) bool {
    for (ids) |candidate| {
        if (idEql(candidate, id)) return true;
    }
    return false;
}

fn addId(pending: *std.ArrayList([]const u8), alloc: std.mem.Allocator, id: []const u8) void {
    if (id.len == 0) return;
    if (std.mem.find(u8, id, "${{") != null) return;
    if (containsId(pending.items, id)) return;
    pending.append(alloc, id) catch return;
}

fn removeId(pending: *std.ArrayList([]const u8), id: []const u8) void {
    if (id.len == 0) return;
    if (std.mem.find(u8, id, "${{") != null) return;
    var n: usize = 0;
    for (pending.items) |item| {
        if (idEql(item, id)) continue;
        pending.items[n] = item;
        n += 1;
    }
    pending.shrinkRetainingCapacity(n);
}

fn collectIds(steps: []const Step, buf: *std.ArrayList([]const u8), alloc: std.mem.Allocator) void {
    for (steps) |*step| {
        if (step.id) |id| addId(buf, alloc, id);
        collectIds(step.nestedSteps(), buf, alloc);
    }
}

fn segmentName(seg: expr_check.Segment) ?[]const u8 {
    return switch (seg) {
        .ident => |name| name,
        .index_string => |name| name,
        .star => null,
    };
}

const Visitor = struct {
    pending: []const []const u8,
    extra: []const []const u8,
    skip_id: ?[]const u8,
    alloc: std.mem.Allocator,
    list: *DiagnosticList,

    fn isUnsynced(self: Visitor, id: []const u8) bool {
        if (self.skip_id) |skip| {
            if (idEql(skip, id)) return false;
        }
        return containsId(self.pending, id) or containsId(self.extra, id);
    }

    pub fn checkPath(self: Visitor, path: []const u8, span: Span) void {
        var iter = expr_check.SegmentIter{ .path = path };
        const root = segmentName(iter.next() orelse return) orelse return;
        if (!std.ascii.eqlIgnoreCase(root, "steps")) return;

        const id = segmentName(iter.next() orelse return) orelse return;
        const prop = segmentName(iter.next() orelse return) orelse return;
        if (!std.ascii.eqlIgnoreCase(prop, "outputs")) return;
        if (!self.isUnsynced(id)) return;

        const alloc = self.list.fixAllocator();
        const message = std.fmt.allocPrint(
            alloc,
            "outputs of background step \"{s}\" are used before that step has been waited on",
            .{id},
        ) catch return;

        self.list.append(.{
            .rule_id = "EXPR019",
            .severity = .warning,
            .message = message,
            .span = span,
            .fix_hint = "add a `wait:` or `wait-all:` step before reading those outputs",
        }) catch return;
    }
};

fn scanForPending(
    step: *const Step,
    pending: []const []const u8,
    extra: []const []const u8,
    skip_id: ?[]const u8,
    alloc: std.mem.Allocator,
    list: *DiagnosticList,
) void {
    expr_scan.scanStep(Visitor{
        .pending = pending,
        .extra = extra,
        .skip_id = skip_id,
        .alloc = alloc,
        .list = list,
    }, step);
}

fn applyControl(step: *const Step, pending: *std.ArrayList([]const u8), alloc: std.mem.Allocator) void {
    if (step.control) |control| switch (control) {
        .wait => |refs| {
            for (refs) |ref| removeId(pending, ref.id);
        },
        .wait_all => pending.clearRetainingCapacity(),
        .cancel => |ref| removeId(pending, ref.id),
        .parallel => {},
    } else if (step.background) {
        if (step.id) |id| addId(pending, alloc, id);
    }
}

/// `wait` / `wait-all` / `cancel` nested in a `parallel:` group finish as
/// part of that group, so they take effect for later top-level steps. They
/// do not synchronize siblings *during* the group (those children run
/// concurrently). Background children of the group are waited by the
/// group's implicit wait and must not stay pending afterwards.
fn applyParallelEffects(steps: []const Step, pending: *std.ArrayList([]const u8)) void {
    for (steps) |*step| {
        if (step.control) |control| switch (control) {
            .wait => |refs| {
                for (refs) |ref| removeId(pending, ref.id);
            },
            .wait_all => pending.clearRetainingCapacity(),
            .cancel => |ref| removeId(pending, ref.id),
            .parallel => |children| applyParallelEffects(children, pending),
        };
    }
}

fn walkParallel(
    steps: []const Step,
    outer: []const []const u8,
    group: []const []const u8,
    alloc: std.mem.Allocator,
    list: *DiagnosticList,
) void {
    for (steps) |*step| {
        scanForPending(step, outer, group, step.id, alloc, list);
        if (step.control) |control| switch (control) {
            .parallel => |children| walkParallel(children, outer, group, alloc, list),
            else => {},
        };
    }
}

fn walkSequence(
    steps: []const Step,
    pending: *std.ArrayList([]const u8),
    alloc: std.mem.Allocator,
    list: *DiagnosticList,
) void {
    for (steps) |*step| {
        if (step.control) |control| switch (control) {
            .parallel => |children| {
                var group_ids: std.ArrayList([]const u8) = .empty;
                collectIds(children, &group_ids, alloc);
                scanForPending(step, pending.items, group_ids.items, step.id, alloc, list);
                walkParallel(children, pending.items, group_ids.items, alloc, list);
                applyParallelEffects(children, pending);
                continue;
            },
            else => {},
        };
        scanForPending(step, pending.items, &.{}, null, alloc, list);
        applyControl(step, pending, alloc);
    }
}

pub fn checkJob(job: *const Job, list: *DiagnosticList) void {
    if (job.steps.len == 0) return;

    var arena = std.heap.ArenaAllocator.init(list.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var pending: std.ArrayList([]const u8) = .empty;
    walkSequence(job.steps, &pending, alloc, list);
}

pub const background_output_rule = Rule{
    .id = "EXPR019",
    .name = "background-output-before-wait",
    .description = "`steps.<id>.outputs` of a background step is only available after `wait` / `wait-all`",
    .severity = .warning,
    .category = .expression,
    .check_job = &checkJob,
};

pub const rules = [_]Rule{background_output_rule};

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

    const diag = test_support.findDiagnostic(&list, "EXPR019") orelse {
        std.debug.print("no EXPR019 diagnostic for source:\n{s}\n", .{source});
        return error.MissingDiagnostic;
    };
    try testing.expect(diag.severity == .warning);
    try testing.expect(diag.fix == null);
    if (std.mem.find(u8, diag.message, needle) == null) {
        std.debug.print("message \"{s}\" does not contain \"{s}\"\n", .{ diag.message, needle });
        return error.UnexpectedMessage;
    }
}

fn expectNoExpr019(source: []const u8) !void {
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    try runOnSource(source, &list);
    if (test_support.findDiagnostic(&list, "EXPR019")) |diag| {
        std.debug.print("unexpected EXPR019: {s}\n", .{diag.message});
        return error.UnexpectedDiagnostic;
    }
}

test "EXPR019: outputs of a background step before wait are reported" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: producer
        \\        background: true
        \\        run: echo value=ready >> "$GITHUB_OUTPUT"
        \\      - run: echo "${{ steps.producer.outputs.value }}"
    ,
        "outputs of background step \"producer\"",
    );
}

test "EXPR019: a reference after wait is clean" {
    try expectNoExpr019(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: producer
        \\        background: true
        \\        run: echo value=ready >> "$GITHUB_OUTPUT"
        \\      - wait: producer
        \\      - run: echo "${{ steps.producer.outputs.value }}"
    );
}

test "EXPR019: a reference after wait-all is clean" {
    try expectNoExpr019(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: producer
        \\        background: true
        \\        run: echo value=ready >> "$GITHUB_OUTPUT"
        \\      - wait-all:
        \\      - run: echo "${{ steps.producer.outputs.value }}"
    );
}

test "EXPR019: a background step with no output reference is clean" {
    try expectNoExpr019(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: producer
        \\        background: true
        \\        run: echo value=ready >> "$GITHUB_OUTPUT"
        \\      - run: echo independent
    );
}

test "EXPR019: conclusion and outcome of a pending step are not reported" {
    try expectNoExpr019(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: producer
        \\        background: true
        \\        run: echo hi
        \\      - run: echo "${{ steps.producer.conclusion }} ${{ steps.producer.outcome }}"
    );
}

test "EXPR019: job-level outputs are evaluated after the implicit wait-all" {
    try expectNoExpr019(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    outputs:
        \\      value: ${{ steps.producer.outputs.value }}
        \\    steps:
        \\      - id: producer
        \\        background: true
        \\        run: echo value=ready >> "$GITHUB_OUTPUT"
    );
}

test "EXPR019: wait of one id leaves another pending" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: a
        \\        background: true
        \\        run: echo a=1 >> "$GITHUB_OUTPUT"
        \\      - id: b
        \\        background: true
        \\        run: echo b=1 >> "$GITHUB_OUTPUT"
        \\      - wait: a
        \\      - run: echo "${{ steps.a.outputs.a }} ${{ steps.b.outputs.b }}"
    ,
        "\"b\"",
    );
}

test "EXPR019: cancel drops the id without warning later output refs" {
    try expectNoExpr019(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: producer
        \\        background: true
        \\        run: echo value=ready >> "$GITHUB_OUTPUT"
        \\      - cancel: producer
        \\      - run: echo "${{ steps.producer.outputs.value }}"
    );
}

test "EXPR019: parallel sibling output refs are reported" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - parallel:
        \\          - id: frontend
        \\            run: echo v=1 >> "$GITHUB_OUTPUT"
        \\          - run: echo "${{ steps.frontend.outputs.v }}"
    ,
        "\"frontend\"",
    );
}

test "EXPR019: outputs of a parallel child are available after the group" {
    try expectNoExpr019(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - parallel:
        \\          - id: frontend
        \\            run: echo v=1 >> "$GITHUB_OUTPUT"
        \\          - run: echo backend
        \\      - run: echo "${{ steps.frontend.outputs.v }}"
    );
}

test "EXPR019: a parallel child still sees an outer pending background step" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: producer
        \\        background: true
        \\        run: echo value=ready >> "$GITHUB_OUTPUT"
        \\      - parallel:
        \\          - run: echo "${{ steps.producer.outputs.value }}"
        \\          - run: echo other
    ,
        "\"producer\"",
    );
}

test "EXPR019: wait inside parallel synchronizes that id for later steps" {
    try expectNoExpr019(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: producer
        \\        background: true
        \\        run: echo value=ready >> "$GITHUB_OUTPUT"
        \\      - parallel:
        \\          - wait: producer
        \\          - run: echo other
        \\      - run: echo "${{ steps.producer.outputs.value }}"
    );
}

test "EXPR019: step ids are matched case-insensitively" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: Producer
        \\        background: true
        \\        run: echo value=ready >> "$GITHUB_OUTPUT"
        \\      - run: echo "${{ steps.producer.outputs.value }}"
    ,
        "\"producer\"",
    );
}

test "EXPR019: a non-background step's outputs are not reported" {
    try expectNoExpr019(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: producer
        \\        run: echo value=ready >> "$GITHUB_OUTPUT"
        \\      - run: echo "${{ steps.producer.outputs.value }}"
    );
}

test "EXPR019: a background step's own expressions are not pending yet" {
    try expectNoExpr019(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: producer
        \\        background: true
        \\        env:
        \\          PREV: ${{ steps.producer.outputs.value }}
        \\        run: echo value=ready >> "$GITHUB_OUTPUT"
    );
}

test "EXPR019: steps['id'] without .outputs is not reported" {
    // `steps['id'].outputs` is not a flattened path (EXPR001); a bare
    // `steps['id']` has no outputs segment, so it stays out of this rule.
    try expectNoExpr019(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: producer
        \\        background: true
        \\        run: echo value=ready >> "$GITHUB_OUTPUT"
        \\      - run: echo "${{ steps['producer'] }}"
    );
}

test "EXPR019: wait-all inside parallel clears outer pending afterwards" {
    try expectNoExpr019(
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: producer
        \\        background: true
        \\        run: echo value=ready >> "$GITHUB_OUTPUT"
        \\      - parallel:
        \\          - wait-all:
        \\          - run: echo other
        \\      - run: echo "${{ steps.producer.outputs.value }}"
    );
}
