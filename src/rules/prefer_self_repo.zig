//! BP009 — prefer `$/` over `./` when the call is the workflow's own repo
//! (issue #440).
//!
//! Job-level `uses: ./.github/workflows/…` names a file in the repository
//! that contains the workflow. `$/` is the same repository at the workflow's
//! commit. Step-level `uses: ./` is GITHUB_WORKSPACE, which may be a different
//! checkout or generated files, so this rule does not look at steps. Replacing
//! `./` with `$/` would change that meaning, so there is no autofix.

const std = @import("std");
const engine = @import("engine.zig");
const runtime = @import("../runtime.zig");
const workspace = @import("../workspace.zig");
const called_workflow = @import("called_workflow.zig");
const test_support = @import("../test_support.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const DiagnosticList = engine.DiagnosticList;

fn definitionRoot() []const u8 {
    return workspace.repoRoot() orelse ".";
}

fn fileExists(alloc: std.mem.Allocator, rel: []const u8) bool {
    const full = std.Io.Dir.path.join(alloc, &.{ definitionRoot(), rel }) catch return false;
    const stat = std.Io.Dir.cwd().statFile(runtime.io(), full, .{}) catch return false;
    return stat.kind == .file;
}

fn checkJob(job: *const Job, list: *DiagnosticList) void {
    const uses = job.uses orelse return;
    const rel = called_workflow.localPath(uses) orelse return;
    if (!fileExists(list.fixAllocator(), rel)) return;

    const suggested = std.fmt.allocPrint(list.fixAllocator(), "$/{s}", .{rel}) catch return;
    list.append(.{
        .rule_id = "BP009",
        .severity = .info,
        .message = std.fmt.allocPrint(
            list.fixAllocator(),
            "prefer \"{s}\" over \"{s}\" to name the repository this workflow came from",
            .{ suggested, uses },
        ) catch "prefer $/ over ./ for this repository's workflow",
        .span = job.uses_value_span orelse job.span,
        .fix_hint = "write the call as $/{path}; ./ and $/ both name this repository, and $/ is the self-repository form",
    }) catch return;
}

pub const rules = [_]Rule{
    .{
        .id = "BP009",
        .name = "prefer-self-repository",
        .description = "job-level uses: ./path that exists in this repository can use $/",
        .severity = .info,
        .category = .best_practice,
        .check_job = &checkJob,
    },
};

const testing = std.testing;

fn runBp009(source: []const u8) !DiagnosticList {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);
    var list = DiagnosticList.init(testing.allocator);
    for (wf.jobs) |*job| checkJob(job, &list);
    return list;
}

test "BP009: an on-disk local reusable workflow is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/ci.yml
    ;

    var diags = try runBp009(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), test_support.countDiagnostics(&diags, "BP009"));
    try testing.expect(std.mem.find(u8, diags.get(0).message, "$/.github/workflows/ci.yml") != null);
    try testing.expect(diags.get(0).fix == null);
}

test "BP009: a missing local workflow is silent" {
    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
    ;

    var diags = try runBp009(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "BP009: $/ and step-level ./ are silent" {
    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: $/.github/workflows/ci.yml
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    timeout-minutes: 5
        \\    steps:
        \\      - uses: ./action.yml
        \\        name: workspace action
    ;

    var diags = try runBp009(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}
