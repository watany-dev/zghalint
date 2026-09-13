//! EXPR012 — contextual typing of the `needs` context (issue #88).
//!
//! `needs.<job>` is only usable for jobs listed in the current job's `needs:`,
//! its only properties are `outputs` and `result`, and `needs.<job>.outputs.<name>`
//! must name an output the referenced job declares. All three need the whole
//! workflow, so this is a `check_workflow` rule rather than part of the
//! per-step expression rule. Job IDs and context properties match
//! case-insensitively, as the runner resolves them.

const std = @import("std");
const engine = @import("engine.zig");
const expr_check = @import("expr_check.zig");
const expr_scan = @import("expr_scan.zig");
const util = @import("../util.zig");
const rename = @import("rename.zig");
const yaml = @import("../yaml/types.zig");
const test_support = @import("../test_support.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const Job = engine.Job;
const DiagnosticList = engine.DiagnosticList;
const Span = yaml.Span;

/// The two properties GitHub exposes under `needs.<job>`.
const needs_properties = [_][]const u8{ "outputs", "result" };

const NeedsVisitor = struct {
    wf: *const Workflow,
    job: *const Job,
    list: *DiagnosticList,
    /// Backs the expression parse trees, which never outlive the walk;
    /// diagnostic messages go to the list's own arena instead.
    alloc: std.mem.Allocator,

    /// The hook `expr_scan` calls for every context access it finds. The span
    /// covers the path alone, which is what lets a rename land on one of its
    /// segments.
    pub fn checkPath(self: NeedsVisitor, path: []const u8, loc: expr_scan.Loc) void {
        var iter = expr_check.SegmentIter{ .path = path };
        const root = (iter.next() orelse return).plainIdent() orelse return;
        if (!std.ascii.eqlIgnoreCase(root, "needs")) return;

        // `needs` alone (`toJSON(needs)`) and computed keys
        // (`needs[matrix.job]`) carry nothing to check.
        const job_id = (iter.next() orelse return).plainIdent() orelse return;

        const target = self.findJob(job_id);
        if (!self.isNeeded(job_id)) {
            self.reportNotNeeded(path, job_id, target != null, loc.resolve());
            return;
        }
        // A `needs:` entry naming no job is a workflow-level problem, not an
        // expression one.
        const dep = target orelse return;

        const property = (iter.next() orelse return).plainIdent() orelse return;
        if (!isKnownProperty(property)) {
            self.reportUnknownProperty(path, job_id, property, loc.resolve());
            return;
        }
        if (!std.ascii.eqlIgnoreCase(property, "outputs")) return;

        // Outputs of a reusable workflow live in the called file; RW005 owns them.
        if (dep.uses != null) return;

        const output = (iter.next() orelse return).plainIdent() orelse return;
        for (dep.outputs) |declared| {
            if (std.ascii.eqlIgnoreCase(declared.name, output)) return;
        }
        self.reportUnknownOutput(path, dep, output, loc.resolve());
    }

    fn findJob(self: NeedsVisitor, job_id: []const u8) ?*const Job {
        for (self.wf.jobs) |*candidate| {
            if (std.ascii.eqlIgnoreCase(candidate.id, job_id)) return candidate;
        }
        return null;
    }

    fn isNeeded(self: NeedsVisitor, job_id: []const u8) bool {
        for (self.job.needs) |dep| {
            if (std.ascii.eqlIgnoreCase(dep, job_id)) return true;
        }
        return false;
    }

    fn reportNotNeeded(
        self: NeedsVisitor,
        path: []const u8,
        job_id: []const u8,
        exists: bool,
        span: Span,
    ) void {
        const alloc = self.list.fixAllocator();
        const nearest = if (exists) null else self.nearestJobId(job_id);
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
                .{ job_id, util.suggestionSuffix(alloc, nearest) },
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
            .fix = if (nearest) |s| rename.pathSegmentFix(self.list, span, path, 1, s) else null,
        }) catch return;
    }

    fn reportUnknownProperty(
        self: NeedsVisitor,
        path: []const u8,
        job_id: []const u8,
        property: []const u8,
        span: Span,
    ) void {
        const alloc = self.list.fixAllocator();
        const suggestion = util.didYouMean(property, &needs_properties);
        const suffix = util.suggestionSuffix(alloc, suggestion);
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
            .fix = if (suggestion) |s| rename.pathSegmentFix(self.list, span, path, 2, s) else null,
        }) catch return;
    }

    fn reportUnknownOutput(
        self: NeedsVisitor,
        path: []const u8,
        dep: *const Job,
        output: []const u8,
        span: Span,
    ) void {
        const alloc = self.list.fixAllocator();
        const nearest = self.nearestOutput(dep, output);
        const message = std.fmt.allocPrint(
            alloc,
            "output \"{s}\" is not defined in job \"{s}\"{s}",
            .{ output, dep.id, util.suggestionSuffix(alloc, nearest) },
        ) catch return;

        self.list.append(.{
            .rule_id = "EXPR012",
            .severity = .@"error",
            .message = message,
            .span = span,
            .fix_hint = "declare the output under the referenced job's `outputs:`",
            .fix = if (nearest) |s| rename.pathSegmentFix(self.list, span, path, 3, s) else null,
        }) catch return;
    }

    /// The candidate list is allocated from the diagnostic allocator;
    /// allocation failure degrades to no suggestion.
    fn nearestJobId(self: NeedsVisitor, job_id: []const u8) ?[]const u8 {
        const alloc = self.list.fixAllocator();
        const names = alloc.alloc([]const u8, self.wf.jobs.len) catch return null;
        for (self.wf.jobs, names) |*candidate, *name| name.* = candidate.id;
        return util.didYouMean(job_id, names);
    }

    fn nearestOutput(self: NeedsVisitor, dep: *const Job, output: []const u8) ?[]const u8 {
        const alloc = self.list.fixAllocator();
        const names = alloc.alloc([]const u8, dep.outputs.len) catch return null;
        for (dep.outputs, names) |declared, *name| name.* = declared.name;
        return util.didYouMean(output, names);
    }
};

fn isKnownProperty(name: []const u8) bool {
    for (needs_properties) |known| {
        if (std.ascii.eqlIgnoreCase(known, name)) return true;
    }
    return false;
}

/// Only a dotted identifier is checked: a computed or globbed segment
/// (`needs['a']`, `needs.*`) has no literal name to compare.
fn checkNeedsContext(wf: *const Workflow, list: *DiagnosticList) void {
    var arena = std.heap.ArenaAllocator.init(list.allocator);
    defer arena.deinit();

    for (wf.jobs) |*job| {
        const visitor = NeedsVisitor{
            .wf = wf,
            .job = job,
            .list = list,
            .alloc = arena.allocator(),
        };
        expr_scan.scanJob(visitor, job);
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

const workflow_check: test_support.Check = .{ .workflow = &checkNeedsContext };

fn diagnose(arena: std.mem.Allocator, source: []const u8, list: *DiagnosticList) !void {
    try test_support.lintSourceAlloc(arena, source, workflow_check, list);
}

fn expectNoDiagnostics(source: []const u8) !void {
    try test_support.expectNoDiagnostics(source, workflow_check);
}

fn expectMessage(source: []const u8, needle: []const u8) !void {
    try test_support.expectMessage(source, workflow_check, "EXPR012", needle);
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
    try testing.expect(std.mem.find(u8, list.get(0).message, "output \"ver\" is not defined in job \"setup\"") != null);
    try testing.expect(std.mem.find(u8, list.get(1).message, "\"lint\" is not in the \"needs\" of this job") != null);
    try testing.expect(std.mem.find(u8, list.get(2).message, "unknown property \"output\" on \"needs.setup\". did you mean \"outputs\"?") != null);
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
