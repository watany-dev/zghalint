//! DEP003: validate the format of `uses:` values.
//!
//! A step's `uses:` names an action; a job's `uses:` calls a reusable
//! workflow. The two accept different shapes, so they are classified by
//! separate functions that share the segment helpers below.

const std = @import("std");
const engine = @import("engine.zig");
const spans = @import("spans.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const Step = engine.Step;
const DiagnosticList = engine.DiagnosticList;

/// Why a `uses:` value is rejected. Message and hint travel together so both
/// checks stay one-liners, and so DEP004 (local action inputs) can reuse the
/// same verdict once it needs to know whether a reference is well-formed.
pub const Problem = struct {
    message: []const u8,
    hint: []const u8,
};

const action_formats =
    "use \"{owner}/{repo}@{ref}\", \"{owner}/{repo}/{path}@{ref}\", \"./{path}\" or \"docker://{image}\"";
const workflow_formats =
    "use \"{owner}/{repo}/.github/workflows/{file}@{ref}\" or \"./.github/workflows/{file}\"";
const drop_ref_hint = "remove the \"@ref\" suffix";
const add_ref_hint = "append a ref, e.g. \"@v4\" or a full commit SHA";

const docker_prefix = "docker://";
const workflows_prefix = ".github/workflows/";

/// Returns null when `raw` is a well-formed step `uses:` value.
pub fn actionProblem(raw: []const u8) ?Problem {
    // A `uses:` built from an expression is only known at run time.
    if (std.mem.indexOf(u8, raw, "${{") != null) return null;

    if (raw.len == 0) return .{
        .message = "`uses:` is empty",
        .hint = action_formats,
    };

    if (isLocalPath(raw)) {
        if (std.mem.indexOfScalar(u8, raw, '@') != null) return .{
            .message = "local action reference must not carry a `@ref`; it always runs from the current checkout",
            .hint = drop_ref_hint,
        };
        if (!std.mem.startsWith(u8, raw, "./")) return .{
            .message = "local action reference must be relative to the repository root",
            .hint = action_formats,
        };
        return null;
    }

    if (std.mem.startsWith(u8, raw, docker_prefix)) {
        if (raw.len == docker_prefix.len) return .{
            .message = "`docker://` action reference has no image name",
            .hint = action_formats,
        };
        return null;
    }

    if (refProblem(raw, action_formats)) |p| return p;

    var it = std.mem.splitScalar(u8, pathBeforeRef(raw), '/');
    const owner = it.first();
    const repo = it.next() orelse return .{
        .message = "action reference has no owner; an action lives in a repository",
        .hint = action_formats,
    };
    if (!isOwnerSegment(owner) or !isNameSegment(repo)) return .{
        .message = "action reference has an empty or invalid `{owner}/{repo}` part",
        .hint = action_formats,
    };
    while (it.next()) |segment| {
        if (segment.len == 0) return .{
            .message = "action reference has an empty path segment",
            .hint = action_formats,
        };
    }
    return null;
}

/// Returns null when `raw` is a well-formed job `uses:` value.
pub fn reusableWorkflowProblem(raw: []const u8) ?Problem {
    if (std.mem.indexOf(u8, raw, "${{") != null) return null;

    if (raw.len == 0) return .{
        .message = "`uses:` is empty",
        .hint = workflow_formats,
    };

    if (isLocalPath(raw)) {
        if (std.mem.indexOfScalar(u8, raw, '@') != null) return .{
            .message = "local reusable workflow call must not carry a `@ref`; it always runs from the current checkout",
            .hint = drop_ref_hint,
        };
        if (!std.mem.startsWith(u8, raw, "./")) return .{
            .message = "local reusable workflow call must be relative to the repository root",
            .hint = workflow_formats,
        };
        if (!isWorkflowFilePath(raw["./".len..])) return .{
            .message = "local reusable workflow call must point to a `.yml` or `.yaml` file under \".github/workflows/\"",
            .hint = workflow_formats,
        };
        return null;
    }

    if (std.mem.startsWith(u8, raw, docker_prefix)) return .{
        .message = "job-level `uses:` calls a reusable workflow, so a `docker://` image is not accepted",
        .hint = workflow_formats,
    };

    if (refProblem(raw, workflow_formats)) |p| return p;

    var it = std.mem.splitScalar(u8, pathBeforeRef(raw), '/');
    const owner = it.first();
    const repo = it.next() orelse return .{
        .message = "reusable workflow call has no owner; a called workflow lives in a repository",
        .hint = workflow_formats,
    };
    if (!isOwnerSegment(owner) or !isNameSegment(repo)) return .{
        .message = "reusable workflow call has an empty or invalid `{owner}/{repo}` part",
        .hint = workflow_formats,
    };
    if (!isWorkflowFilePath(it.rest())) return .{
        .message = "reusable workflow call must point to a `.yml` or `.yaml` file under \".github/workflows/\" of the called repository",
        .hint = workflow_formats,
    };
    return null;
}

/// The ref defects both forms share. Only the accepted formats differ, so the
/// caller passes its own format hint.
fn refProblem(raw: []const u8, formats: []const u8) ?Problem {
    const at = std.mem.indexOfScalar(u8, raw, '@') orelse return .{
        .message = "`uses:` has no `@ref`; the version is required",
        .hint = add_ref_hint,
    };
    const ref = raw[at + 1 ..];
    if (ref.len == 0) return .{
        .message = "`uses:` has an empty `@ref`",
        .hint = add_ref_hint,
    };
    if (std.mem.indexOfScalar(u8, ref, '@') != null) return .{
        .message = "`uses:` contains more than one `@`",
        .hint = formats,
    };
    return null;
}

/// The `{path}` half of `{path}@{ref}`. Only valid once `refProblem` passed,
/// which is what guarantees the `@`.
fn pathBeforeRef(raw: []const u8) []const u8 {
    return raw[0..std.mem.indexOfScalar(u8, raw, '@').?];
}

fn isLocalPath(raw: []const u8) bool {
    return std.mem.startsWith(u8, raw, "./") or std.mem.startsWith(u8, raw, "../");
}

/// A GitHub login never starts with a dot, so `.github/x@v1` is a path, not
/// an `{owner}/{repo}` pair.
fn isOwnerSegment(segment: []const u8) bool {
    return segment.len != 0 and segment[0] != '.';
}

/// A repository name may start with a dot — an organization's shared actions
/// and workflows live in its `.github` repository — but `.` and `..` are path
/// components rather than names.
fn isNameSegment(segment: []const u8) bool {
    if (segment.len == 0) return false;
    return !std.mem.eql(u8, segment, ".") and !std.mem.eql(u8, segment, "..");
}

/// `path` is relative to the repository root. GitHub keeps workflows directly
/// in `.github/workflows/`, so a nested directory is not a workflow file.
fn isWorkflowFilePath(path: []const u8) bool {
    if (!std.mem.startsWith(u8, path, workflows_prefix)) return false;
    const file = path[workflows_prefix.len..];
    if (std.mem.indexOfScalar(u8, file, '/') != null) return false;

    const ext = std.fs.path.extension(file);
    if (!std.mem.eql(u8, ext, ".yml") and !std.mem.eql(u8, ext, ".yaml")) return false;
    return file.len != ext.len;
}

fn checkStepUses(step: *const Step, list: *DiagnosticList) void {
    const action = step.uses orelse return;
    const problem = actionProblem(action.raw) orelse return;

    list.append(.{
        .rule_id = "DEP003",
        .severity = .@"error",
        .message = problem.message,
        .span = spans.usesSpan(step),
        .fix_hint = problem.hint,
    }) catch return;
}

fn checkJobUses(job: *const Job, list: *DiagnosticList) void {
    const uses = job.uses orelse return;
    const problem = reusableWorkflowProblem(uses) orelse return;

    list.append(.{
        .rule_id = "DEP003",
        .severity = .@"error",
        .message = problem.message,
        .span = job.uses_value_span orelse job.span,
        .fix_hint = problem.hint,
    }) catch return;
}

pub const rules = [_]Rule{
    .{
        .id = "DEP003",
        .name = "uses-format",
        .description = "`uses:` must name an action or a reusable workflow in a supported format",
        .severity = .@"error",
        .category = .dependency,
        .check_job = &checkJobUses,
        .check_step = &checkStepUses,
    },
};

const testing = std.testing;
const test_support = @import("../test_support.zig");
const workflow_types = @import("../workflow/types.zig");

const dummySpan = test_support.dummySpan;

fn expectActionOk(raw: []const u8) !void {
    if (actionProblem(raw)) |p| {
        std.debug.print("unexpected DEP003 for '{s}': {s}\n", .{ raw, p.message });
        return error.TestUnexpectedResult;
    }
}

fn expectActionProblem(raw: []const u8) !Problem {
    return actionProblem(raw) orelse {
        std.debug.print("expected DEP003 for '{s}'\n", .{raw});
        return error.TestUnexpectedResult;
    };
}

fn expectWorkflowOk(raw: []const u8) !void {
    if (reusableWorkflowProblem(raw)) |p| {
        std.debug.print("unexpected DEP003 for '{s}': {s}\n", .{ raw, p.message });
        return error.TestUnexpectedResult;
    }
}

fn expectWorkflowProblem(raw: []const u8) !Problem {
    return reusableWorkflowProblem(raw) orelse {
        std.debug.print("expected DEP003 for '{s}'\n", .{raw});
        return error.TestUnexpectedResult;
    };
}

test "DEP003: well-formed action references are accepted" {
    try expectActionOk("actions/checkout@v4");
    try expectActionOk("actions/cache/restore@v4");
    try expectActionOk("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683");
    try expectActionOk("./.github/actions/setup");
    try expectActionOk("docker://alpine:3.19");
    try expectActionOk("docker://ghcr.io/owner/image@sha256:abc");
}

test "DEP003: action reference without a ref is reported" {
    const problem = try expectActionProblem("actions/checkout");
    try testing.expect(std.mem.indexOf(u8, problem.message, "@ref") != null);
    try testing.expectEqualStrings(add_ref_hint, problem.hint);
}

test "DEP003: action reference with an empty ref is reported" {
    _ = try expectActionProblem("actions/checkout@");
}

test "DEP003: action reference with two @ is reported" {
    _ = try expectActionProblem("actions/checkout@v4@v5");
}

test "DEP003: local action with a ref is reported" {
    const problem = try expectActionProblem("./my-action@v1");
    try testing.expectEqualStrings(drop_ref_hint, problem.hint);
}

test "DEP003: local action must start with ./" {
    _ = try expectActionProblem("../shared/action");
}

test "DEP003: empty owner or repo segment is reported" {
    _ = try expectActionProblem("actions//checkout@v4");
    _ = try expectActionProblem("/checkout@v4");
    _ = try expectActionProblem("actions/checkout//sub@v4");
}

test "DEP003: missing owner is reported" {
    const problem = try expectActionProblem("checkout@v4");
    try testing.expect(std.mem.indexOf(u8, problem.message, "owner") != null);
}

test "DEP003: dot-prefixed owner is not a repository reference" {
    _ = try expectActionProblem(".github/checkout@v4");
    _ = try expectActionProblem("actions/../checkout@v4");
}

test "DEP003: an organization's .github repository is a valid reference" {
    try expectActionOk("myorg/.github/actions/setup@v1");
    try expectWorkflowOk("myorg/.github/.github/workflows/ci.yml@main");
}

test "DEP003: empty uses is reported" {
    _ = try expectActionProblem("");
    _ = try expectWorkflowProblem("");
}

test "DEP003: bare docker:// without an image is reported" {
    _ = try expectActionProblem("docker://");
}

test "DEP003: expressions are left to the expression rules" {
    try expectActionOk("actions/checkout@${{ env.REF }}");
    try expectWorkflowOk("${{ matrix.workflow }}");
}

test "DEP003: well-formed reusable workflow calls are accepted" {
    try expectWorkflowOk("octo-org/repo/.github/workflows/ci.yml@main");
    try expectWorkflowOk("octo-org/repo/.github/workflows/ci.yaml@v1");
    try expectWorkflowOk("./.github/workflows/reusable.yml");
}

test "DEP003: reusable workflow call outside .github/workflows is reported" {
    _ = try expectWorkflowProblem("octo-org/repo/ci.yml@main");
    _ = try expectWorkflowProblem("octo-org/repo/.github/workflows/nested/ci.yml@main");
    _ = try expectWorkflowProblem("./workflows/reusable.yml");
    _ = try expectWorkflowProblem("./.github/workflows/reusable.txt");
    _ = try expectWorkflowProblem("./.github/workflows/.yml");
}

test "DEP003: reusable workflow call without a ref is reported" {
    _ = try expectWorkflowProblem("octo-org/repo/.github/workflows/ci.yml");
}

test "DEP003: local reusable workflow call with a ref is reported" {
    const problem = try expectWorkflowProblem("./.github/workflows/ci.yml@main");
    try testing.expectEqualStrings(drop_ref_hint, problem.hint);
}

test "DEP003: local reusable workflow call must start with ./" {
    _ = try expectWorkflowProblem("../.github/workflows/ci.yml");
}

test "DEP003: docker image is not a reusable workflow" {
    _ = try expectWorkflowProblem("docker://alpine:3.19");
}

test "DEP003: reusable workflow call without an owner is reported" {
    _ = try expectWorkflowProblem("repo/.github/workflows/ci.yml@main");
}

test "DEP003: step check reports at the uses value span" {
    const step = workflow_types.Step{
        .uses = workflow_types.ActionRef.parse("actions/checkout"),
        .uses_value_span = dummySpan(40, 57),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkStepUses(&step, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("DEP003", diag.rule_id);
    try testing.expect(diag.severity == .@"error");
    try testing.expectEqual(@as(usize, 40), diag.span.start_byte);
}

test "DEP003: step without uses is ignored" {
    const step = workflow_types.Step{ .run = "echo hi" };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkStepUses(&step, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "DEP003: job check reports at the uses value span" {
    const job = workflow_types.Job{
        .id = "call",
        .uses = "octo-org/repo/ci.yml@main",
        .uses_value_span = dummySpan(70, 95),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkJobUses(&job, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqual(@as(usize, 70), diags.get(0).span.start_byte);
}

test "DEP003: job without uses is ignored" {
    const job = workflow_types.Job{ .id = "build", .runs_on = "ubuntu-latest" };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkJobUses(&job, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "DEP003: end-to-end over a real workflow file" {
    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout
        \\      - uses: actions/cache/restore@v4
        \\  call:
        \\    uses: octo-org/repo/ci.yml@main
        \\
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    for (wf.jobs) |*job| {
        checkJobUses(job, &diags);
        for (job.steps) |*step| checkStepUses(step, &diags);
    }

    try testing.expectEqual(@as(usize, 2), diags.len());
    // The step diagnostic points at the `uses:` value, not at the step mapping.
    try testing.expect(diags.get(0).span.start_line == 7 or diags.get(1).span.start_line == 7);
}

test "DEP003: rule metadata" {
    try testing.expectEqual(@as(usize, 1), rules.len);
    try testing.expectEqualStrings("DEP003", rules[0].id);
    try testing.expectEqualStrings("uses-format", rules[0].name);
    try testing.expect(rules[0].category == .dependency);
    try testing.expect(rules[0].severity == .@"error");
}
