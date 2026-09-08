const std = @import("std");
const test_support = @import("../test_support.zig");
const engine = @import("engine.zig");
const fix_builder = @import("../fix/builder.zig");
const rename = @import("rename.zig");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_types = @import("../yaml/types.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const Step = engine.Step;
const Workflow = engine.Workflow;
const DiagnosticList = engine.DiagnosticList;
const Permissions = workflow_types.Permissions;
const PermissionsMeta = workflow_types.PermissionsMeta;
const Span = yaml_types.Span;
const ActionRef = workflow_types.ActionRef;
const Fix = diagnostics.Fix;
const spans = @import("spans.zig");
const util = @import("../util.zig");

fn checkBroadPermissions(wf: *const Workflow, diag_list: *DiagnosticList) void {
    if (wf.permissions) |perms| {
        checkPermissionsScope(perms, wf.permissions_meta, spans.workflow_head, .workflow, diag_list);
    }

    for (wf.jobs) |job| {
        if (job.permissions) |perms| {
            checkPermissionsScope(perms, job.permissions_meta, job.span, .job, diag_list);
        }
    }
}

const write_all_replacement = "{contents: read}";

/// Shared with security.zig, which reports the same `write-all` grant as SEC004.
pub fn makeWriteAllFix(diag_list: *DiagnosticList, value_span: Span) ?Fix {
    const edits = fix_builder.replaceScalar(
        diag_list.fixAllocator(),
        value_span,
        .plain,
        write_all_replacement,
    ) orelse return null;
    return .{
        .description = "Replace 'write-all' with minimal permissions",
        .safety = .safe,
        .edits = edits,
    };
}

fn makeDowngradeToReadFix(diag_list: *DiagnosticList, yaml_key: []const u8, value_span: Span) ?Fix {
    const edits = fix_builder.replaceScalar(
        diag_list.fixAllocator(),
        value_span,
        .plain,
        "read",
    ) orelse return null;
    const description = std.fmt.allocPrint(
        diag_list.fixAllocator(),
        "Downgrade '{s}: write' to 'read'",
        .{yaml_key},
    ) catch return null;
    return .{
        .description = description,
        .safety = .unsafe,
        .edits = edits,
    };
}

/// Where a `permissions:` block was written. A workflow-level grant applies to
/// every job in the file, so it is judged more strictly than a job-level one.
const Placement = enum { workflow, job };

/// Scopes whose `write` grant lets a job change what the repository stores,
/// runs or ships: its code and workflow files (`contents`, `actions`), the
/// packages it publishes (`packages`) and its deployments (`deployments`).
/// Those are the paths by which a compromised step escalates beyond its own
/// run, so PERM001 reports them wherever they are declared.
///
/// Every other scope writes repository *metadata* — issues, pull requests,
/// checks, statuses, discussions, projects, code-scanning alerts, attestations,
/// artifact metadata, models, Pages deployments — or mints an OIDC token
/// (`id-token`). GitHub's own documented workflows require those at `write` and
/// cannot ask for less: CodeQL needs `security-events: write`, trusted
/// publishing needs `id-token: write`, `actions/deploy-pages` needs
/// `pages: write`, a labeler needs `issues: write`. Reporting such a grant on
/// the job that needs it is noise, not a finding (#285) — but at workflow level
/// it still hands the scope to every other job, which `Placement` catches.
const escalating_scopes = [_][]const u8{
    "actions",
    "contents",
    "deployments",
    "packages",
};

fn scopeEscalatesPrivilege(comptime key: []const u8) bool {
    comptime {
        for (escalating_scopes) |scope| {
            if (std.mem.eql(u8, key, scope)) return true;
        }
        return false;
    }
}

/// `fallback` is the span reported when the parser captured no span for the
/// offending permissions entry (e.g. a flow-style `permissions:` mapping).
fn checkPermissionsScope(
    perms: Permissions,
    meta: ?PermissionsMeta,
    fallback: Span,
    placement: Placement,
    diag_list: *DiagnosticList,
) void {
    if (perms.write_all) {
        const span = perms.value_span orelse fallback;
        diag_list.append(.{
            .rule_id = "PERM001",
            .severity = .warning,
            .message = "Overly broad 'write-all' permissions. Apply principle of least privilege.",
            .span = span,
            .fix_hint = "Replace 'write-all' with specific permissions needed.",
            .fix = if (perms.value_span) |vs| makeWriteAllFix(diag_list, vs) else null,
        }) catch return;
        return;
    }

    // `PermissionsMeta` declares exactly the scope keys, so it doubles as the
    // key list.
    inline for (workflow_types.permission_scopes) |field| {
        const key: []const u8 = comptime workflow_types.permissionScopeKey(field);
        const escalates = comptime scopeEscalatesPrivilege(key);
        if (escalates or placement == .workflow) {
            const level: ?workflow_types.PermissionLevel = @field(perms, field);
            const value_span: ?Span = if (meta) |m| @field(m, field) else null;
            if (level) |lvl| {
                if (lvl == .write) {
                    // The GitHub Actions spec has no `id-token: read`, so that
                    // entry has to be removed rather than lowered.
                    const is_id_token = comptime std.mem.eql(u8, key, "id-token");
                    diag_list.append(.{
                        .rule_id = "PERM001",
                        .severity = .info,
                        .message = if (escalates)
                            "Broad write permission detected. Ensure this is necessary."
                        else
                            "Workflow-level write permission is granted to every job, not just the one that needs it.",
                        .span = value_span orelse fallback,
                        .fix_hint = if (escalates)
                            "Consider if 'read' permission would suffice instead of 'write'."
                        else if (is_id_token)
                            "id-token: write enables OIDC. Declare it on the job that needs OIDC."
                        else
                            "Move this scope onto the job that needs it, or lower it to 'read' here.",
                        // Lowering a metadata scope would break the job that
                        // needs it, so only the escalating ones carry a fix.
                        .fix = if (escalates) blk: {
                            const vs = value_span orelse break :blk null;
                            break :blk makeDowngradeToReadFix(diag_list, key, vs);
                        } else null,
                    }) catch return;
                }
            }
        }
    }
}

fn permissionProblemMessage(
    alloc: std.mem.Allocator,
    problem: workflow_types.PermissionProblem,
) ?[]const u8 {
    return switch (problem.kind) {
        .unknown_scope => blk: {
            var suffix_buf: [64]u8 = undefined;
            const suffix = if (util.didYouMean(problem.text, workflow_types.permission_scope_keys)) |s|
                std.fmt.bufPrint(&suffix_buf, ". did you mean \"{s}\"?", .{s}) catch ""
            else
                "";
            break :blk std.fmt.allocPrint(
                alloc,
                "unknown permission scope \"{s}\"{s}",
                .{ problem.text, suffix },
            ) catch null;
        },
        // An empty `text` means the value was missing or not a scalar, so there
        // is no level to quote back.
        .invalid_level => if (problem.text.len == 0) std.fmt.allocPrint(
            alloc,
            "missing permission level for \"{s}\". expected \"read\", \"write\" or \"none\"",
            .{problem.scope},
        ) catch null else std.fmt.allocPrint(
            alloc,
            "invalid permission level \"{s}\" for \"{s}\". expected \"read\", \"write\" or \"none\"",
            .{ problem.text, problem.scope },
        ) catch null,
        .invalid_all => std.fmt.allocPrint(
            alloc,
            "invalid permission \"{s}\" for all scopes. expected \"read-all\" or \"write-all\"",
            .{problem.text},
        ) catch null,
    };
}

fn reportPermissionProblems(
    problems: []const workflow_types.PermissionProblem,
    diag_list: *DiagnosticList,
) void {
    const alloc = diag_list.fixAllocator();
    for (problems) |problem| {
        const message = permissionProblemMessage(alloc, problem) orelse continue;
        diag_list.append(.{
            .rule_id = "PERM003",
            .severity = .@"error",
            .message = message,
            .span = problem.span,
            .fix_hint = switch (problem.kind) {
                .unknown_scope => "use one of the permission scopes GitHub Actions defines.",
                .invalid_level => "use 'read', 'write' or 'none' as the permission level.",
                .invalid_all => "use 'read-all' or 'write-all', or list scopes individually.",
            },
            .fix = unknownScopeFix(diag_list, problem),
        }) catch return;
    }
}

/// Only `unknown_scope` renames: an invalid *level* is a value the workflow
/// author has to choose, and `didYouMean` is not consulted for it.
fn unknownScopeFix(
    list: *DiagnosticList,
    problem: workflow_types.PermissionProblem,
) ?Fix {
    if (problem.kind != .unknown_scope) return null;
    const suggestion = util.didYouMean(problem.text, workflow_types.permission_scope_keys) orelse return null;
    return rename.tokenFix(list, problem.span, problem.text, suggestion);
}

fn checkInvalidPermissions(wf: *const Workflow, diag_list: *DiagnosticList) void {
    reportPermissionProblems(wf.permission_problems, diag_list);
    for (wf.jobs) |job| {
        reportPermissionProblems(job.permission_problems, diag_list);
    }
}

fn buildJobPermissionsFix(list: *DiagnosticList, job: *const Job) ?Fix {
    const insert_byte = job.permissions_insertion_byte orelse return null;
    if (job.job_indent == 0) return null;
    const indent: u32 = job.job_indent - 1;

    const subs = [_]fix_builder.SubEntry{
        .{ .key = "contents", .value = "read" },
    };

    const edits = fix_builder.insertMappingEntryBlock(
        list.fixAllocator(),
        .{ .byte = insert_byte, .indent = indent },
        "permissions",
        &subs,
        2,
    ) orelse return null;

    return .{
        .description = "insert job-level permissions: contents: read",
        .safety = .unsafe,
        .edits = edits,
    };
}

fn checkJobPermissions(job: *const Job, diag_list: *DiagnosticList) void {
    if (job.permissions != null) return;

    for (job.steps) |*step| {
        if (step.uses) |action_ref| {
            if (action_ref.is_local or action_ref.is_docker) continue;

            const owner = action_ref.owner orelse continue;
            if (std.mem.eql(u8, owner, "actions") or std.mem.eql(u8, owner, "github")) continue;

            diag_list.append(.{
                .rule_id = "PERM002",
                .severity = .warning,
                .message = "Job uses third-party actions without job-level 'permissions'. Define explicit permissions to limit token scope.",
                .span = spans.usesSpan(step),
                .fix_hint = "Add a 'permissions' block to this job to restrict the GITHUB_TOKEN scope.",
                .fix = buildJobPermissionsFix(diag_list, job),
            }) catch return;
            return;
        }
    }
}

/// A workflow-level `permissions:` that grants no write already limits
/// `GITHUB_TOKEN` for every job, so asking each job to repeat the block is
/// noise (#334). `write-all` or any `: write` still needs a job-level
/// narrowing, and a missing workflow block is the default full token.
fn permissionsGrantWrite(perms: Permissions) bool {
    if (perms.write_all) return true;
    inline for (workflow_types.permission_scopes) |field| {
        const level: ?workflow_types.PermissionLevel = @field(perms, field);
        if (level) |lvl| {
            if (lvl == .write) return true;
        }
    }
    return false;
}

fn checkMissingJobPermissions(wf: *const Workflow, diag_list: *DiagnosticList) void {
    if (wf.permissions) |perms| {
        if (!permissionsGrantWrite(perms)) return;
    }
    for (wf.jobs) |*job| {
        checkJobPermissions(job, diag_list);
    }
}

pub const rules = [_]Rule{
    .{
        .id = "PERM001",
        .name = "broad-permissions",
        .description = "Overly broad permission scope detected",
        .severity = .warning,
        .category = .permissions,
        .check_workflow = checkBroadPermissions,
    },
    .{
        .id = "PERM002",
        .name = "missing-job-permissions",
        .description = "Job with third-party actions lacks explicit permissions",
        .severity = .warning,
        .category = .permissions,
        .check_workflow = checkMissingJobPermissions,
    },
    .{
        .id = "PERM003",
        .name = "invalid-permissions",
        .description = "Unknown permission scope or invalid permission level",
        .severity = .@"error",
        .category = .permissions,
        .check_workflow = checkInvalidPermissions,
    },
};

test "PERM001: detect write-all scope" {
    const wf = Workflow{
        .on = test_support.empty_trigger,
        .permissions = .{ .write_all = true },
        .jobs = &.{},
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkBroadPermissions(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("PERM001", diags.get(0).rule_id);
}

test "PERM001: detect contents write" {
    const wf = Workflow{
        .on = test_support.empty_trigger,
        .permissions = .{ .contents = .write },
        .jobs = &.{},
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkBroadPermissions(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
}

test "PERM001: no warning for read-only" {
    const wf = Workflow{
        .on = test_support.empty_trigger,
        .permissions = .{ .contents = .read },
        .jobs = &.{},
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkBroadPermissions(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERM001: no warning for read-all scope" {
    const wf = Workflow{
        .on = test_support.empty_trigger,
        .permissions = .{ .read_all = true },
        .jobs = &.{},
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkBroadPermissions(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERM001: detect broad permissions at job level" {
    const jobs = [_]Job{
        .{
            .id = "deploy",
            .permissions = .{ .write_all = true },
        },
    };
    const wf = Workflow{
        .on = test_support.empty_trigger,
        .jobs = &jobs,
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkBroadPermissions(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
}

test "PERM001: detect multiple write permissions" {
    const wf = Workflow{
        .on = test_support.empty_trigger,
        .permissions = .{ .contents = .write, .packages = .write },
        .jobs = &.{},
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkBroadPermissions(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 2), diags.len());
}

test "PERM002: detect missing permissions with third-party action" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("actions/checkout@v4") },
            Step{ .uses = ActionRef.parse("some-org/some-action@v1") },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkJobPermissions(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("PERM002", diags.get(0).rule_id);
}

test "PERM002: no warning when permissions are set" {
    const job = Job{
        .id = "build",
        .permissions = .{ .read_all = true },
        .steps = &.{
            Step{ .uses = ActionRef.parse("some-org/some-action@v1") },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkJobPermissions(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERM002: no warning with only first-party actions" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("actions/checkout@v4") },
            Step{ .uses = ActionRef.parse("github/codeql-action/init@v2") },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkJobPermissions(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERM002: no warning with only local actions" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("./.github/actions/my-action") },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkJobPermissions(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERM002: no warning with only run steps" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .run = "echo hello" },
        },
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkJobPermissions(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

fn perm002On(job: Job, wf_perms: ?Permissions) DiagnosticList {
    const jobs = [_]Job{job};
    const wf = Workflow{
        .on = test_support.empty_trigger,
        .jobs = &jobs,
        .permissions = wf_perms,
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    checkMissingJobPermissions(&wf, &diags);
    return diags;
}

test "PERM002: workflow-level permissions decide whether the job warning fires (#334)" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("some-org/some-action@v1") },
        },
    };
    const cases = [_]struct { perms: ?Permissions, warn: bool }{
        .{ .perms = .{ .contents = .read }, .warn = false },
        .{ .perms = .{ .read_all = true }, .warn = false },
        .{ .perms = .{}, .warn = false },
        .{ .perms = .{ .write_all = true }, .warn = true },
        .{ .perms = .{ .contents = .write }, .warn = true },
        .{ .perms = .{ .id_token = .write }, .warn = true },
        .{ .perms = .{ .contents = .read, .packages = .write }, .warn = true },
        .{ .perms = null, .warn = true },
    };
    for (cases) |c| {
        var diags = perm002On(job, c.perms);
        defer diags.deinit();
        try std.testing.expectEqual(c.warn, diags.len() == 1);
        if (c.warn) try std.testing.expectEqualStrings("PERM002", diags.get(0).rule_id);
    }
}

test "PERM002: fix metadata is attached with .unsafe" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("some-org/some-action@v1") },
        },
        .job_indent = 3,
        .permissions_insertion_byte = 50,
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkJobPermissions(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestExpectedNonNull;
    try std.testing.expect(fix.safety == .unsafe);
    try std.testing.expectEqualStrings("insert job-level permissions: contents: read", fix.description);
}

test "PERM002: fix is null when permissions_insertion_byte is missing" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("some-org/some-action@v1") },
        },
        .job_indent = 3,
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkJobPermissions(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "PERM002: fix is null when job_indent is zero" {
    const job = Job{
        .id = "build",
        .steps = &.{
            Step{ .uses = ActionRef.parse("some-org/some-action@v1") },
        },
        .job_indent = 0,
        .permissions_insertion_byte = 50,
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkJobPermissions(&job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "PERM002: autofix inserts permissions block after runs-on" {
    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: some-org/some-action@v1
        \\
    ;

    const result = try test_support.lintAndFix(std.testing.allocator, source, .{ .workflow = &checkMissingJobPermissions }, true);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.diagnostic_count);

    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
    try std.testing.expectEqualStrings(
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    permissions:
        \\      contents: read
        \\    steps:
        \\      - uses: some-org/some-action@v1
        \\
    ,
        result.content,
    );
}

test "PERM002: fix lands before the next key when runs-on is a block scalar (#172)" {
    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: |
        \\      ubuntu-latest
        \\    steps:
        \\      - uses: some-org/some-action@v1
        \\
    ;
    const result = try test_support.lintAndFix(std.testing.allocator, source, .{ .workflow = &checkMissingJobPermissions }, true);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
    try std.testing.expectEqualStrings(
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: |
        \\      ubuntu-latest
        \\    permissions:
        \\      contents: read
        \\    steps:
        \\      - uses: some-org/some-action@v1
        \\
    ,
        result.content,
    );
}

test "PERM002: multiple jobs get fixes applied in back-to-front order" {
    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: some-org/some-action@v1
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: another-org/another-action@v2
        \\
    ;

    const result = try test_support.lintAndFix(std.testing.allocator, source, .{ .workflow = &checkMissingJobPermissions }, true);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), result.diagnostic_count);
    try std.testing.expectEqual(@as(usize, 2), result.fix_count);
    try std.testing.expectEqual(@as(usize, 2), result.edits_applied);
    try std.testing.expectEqualStrings(
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    permissions:
        \\      contents: read
        \\    steps:
        \\      - uses: some-org/some-action@v1
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    permissions:
        \\      contents: read
        \\    steps:
        \\      - uses: another-org/another-action@v2
        \\
    ,
        result.content,
    );
}

test "PERM001: autofix replaces write-all with minimal permissions" {
    const fix_engine = @import("../fix/engine.zig");
    const source = "permissions: write-all\njobs:";
    const value_span = Span{
        .start_line = 1,
        .start_col = 14,
        .end_line = 1,
        .end_col = 23,
        .start_byte = 13,
        .end_byte = 22,
    };
    const perms = Permissions{ .write_all = true, .value_span = value_span };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPermissionsScope(perms, null, spans.workflow_head, .workflow, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try std.testing.expectEqualStrings("PERM001", diag.rule_id);
    try std.testing.expect(diag.fix != null);

    const fix = diag.fix.?;
    try std.testing.expectEqual(diagnostics.FixSafety.safe, fix.safety);

    const result = try fix_engine.applyFixes(std.testing.allocator, source, &.{fix});
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("permissions: {contents: read}\njobs:", result.content);
}

test "PERM001: no fix when value_span is null" {
    const perms = Permissions{ .write_all = true };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPermissionsScope(perms, null, spans.workflow_head, .workflow, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "PERM001: no fix for individual write when meta is null" {
    const perms = Permissions{ .contents = .write };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPermissionsScope(perms, null, spans.workflow_head, .workflow, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "PERM001: per-field autofix downgrades contents: write to read" {
    const fix_engine = @import("../fix/engine.zig");
    const source = "permissions:\n  contents: write\n";
    // `write` occupies cols 13..17 on line 2, bytes 25..30 (0-based end exclusive).
    const value_span = Span{
        .start_line = 2,
        .start_col = 13,
        .end_line = 2,
        .end_col = 18,
        .start_byte = 25,
        .end_byte = 30,
    };
    const perms = Permissions{ .contents = .write };
    const meta = PermissionsMeta{ .contents = value_span };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPermissionsScope(perms, meta, spans.workflow_head, .workflow, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try std.testing.expectEqualStrings("PERM001", diag.rule_id);
    try std.testing.expectEqual(diagnostics.Severity.info, diag.severity);
    const fix = diag.fix orelse return error.TestExpectedNonNull;
    try std.testing.expectEqual(diagnostics.FixSafety.unsafe, fix.safety);

    const result = try fix_engine.applyFixes(std.testing.allocator, source, &.{fix});
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("permissions:\n  contents: read\n", result.content);
}

/// The scopes PERM001 leaves alone at job level: each is the documented
/// minimum for a common workflow — CodeQL uploads (`security-events`), trusted
/// publishing (`id-token`), a Pages deploy (`pages`), a labeler (`issues`), a
/// review bot (`pull-requests`, `checks`, `statuses`), provenance
/// (`attestations`).
const metadata_write_perms = Permissions{
    .attestations = .write,
    .checks = .write,
    .discussions = .write,
    .id_token = .write,
    .issues = .write,
    .pages = .write,
    .pull_requests = .write,
    .repository_projects = .write,
    .security_events = .write,
    .statuses = .write,
};

test "PERM001: metadata scopes at write are not reported on the job that needs them" {
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPermissionsScope(metadata_write_perms, null, spans.workflow_head, .job, &diags);

    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERM001: metadata scopes at write are reported at workflow level" {
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPermissionsScope(metadata_write_perms, null, spans.workflow_head, .workflow, &diags);

    // Every scope set above, since a workflow-level grant reaches every job.
    try std.testing.expectEqual(@as(usize, 10), diags.len());
    for (0..diags.len()) |i| {
        // No autofix: lowering the level would break the job that needs it;
        // the entry has to move to that job instead.
        try std.testing.expect(diags.get(i).fix == null);
    }
}

test "PERM001: every escalating scope at write is reported at job level" {
    const perms = Permissions{
        .actions = .write,
        .contents = .write,
        .deployments = .write,
        .packages = .write,
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPermissionsScope(perms, null, spans.workflow_head, .job, &diags);

    try std.testing.expectEqual(escalating_scopes.len, diags.len());
}

test "PERM001: autofix applies to an escalating scope via the engine" {
    const fix_engine = @import("../fix/engine.zig");
    const source = "permissions:\n  packages: write\n";
    // `write` at bytes 25..30.
    const value_span = Span{
        .start_line = 2,
        .start_col = 13,
        .end_line = 2,
        .end_col = 18,
        .start_byte = 25,
        .end_byte = 30,
    };
    const perms = Permissions{ .packages = .write };
    const meta = PermissionsMeta{ .packages = value_span };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPermissionsScope(perms, meta, spans.workflow_head, .job, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestExpectedNonNull;
    const result = try fix_engine.applyFixes(std.testing.allocator, source, &.{fix});
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("permissions:\n  packages: read\n", result.content);
}

test "PERM001: id-token alongside contents: write leaves id-token untouched" {
    const source =
        \\permissions:
        \\  contents: write
        \\  id-token: write
        \\
    ;
    const fix_engine = @import("../fix/engine.zig");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const wrapped = try std.fmt.allocPrint(alloc,
        \\name: t
        \\on: push
        \\{s}jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
        \\
    , .{source});

    const wf = try test_support.parseWorkflowSource(alloc, wrapped);

    var diags = DiagnosticList.init(alloc);
    checkBroadPermissions(&wf, &diags);

    // Both are workflow-level, so both are reported; only `contents` is fixable.
    try std.testing.expectEqual(@as(usize, 2), diags.len());
    var fix_count: usize = 0;
    for (0..diags.len()) |i| {
        if (diags.get(i).fix != null) fix_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), fix_count);

    var fixes_buf: [1]Fix = undefined;
    var n: usize = 0;
    for (0..diags.len()) |i| {
        if (diags.get(i).fix) |f| {
            fixes_buf[n] = f;
            n += 1;
        }
    }
    const result = try fix_engine.applyFixes(std.testing.allocator, wrapped, fixes_buf[0..n]);
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "contents: read") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "id-token: write") != null);
}

fn runInvalidPermissions(alloc: std.mem.Allocator, source: []const u8, diags: *DiagnosticList) !void {
    const wf = try test_support.parseWorkflowSource(alloc, source);
    checkInvalidPermissions(&wf, diags);
}

test "PERM003: report an invalid permission level" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(arena.allocator());

    try runInvalidPermissions(arena.allocator(),
        \\name: t
        \\on: push
        \\permissions:
        \\  contents: raed
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    , &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try std.testing.expectEqualStrings("PERM003", diag.rule_id);
    try std.testing.expectEqual(diagnostics.Severity.@"error", diag.severity);
    try std.testing.expectEqualStrings(
        "invalid permission level \"raed\" for \"contents\". expected \"read\", \"write\" or \"none\"",
        diag.message,
    );
    try std.testing.expectEqual(@as(u32, 4), diag.span.start_line);
}

test "PERM003: a missing level is reported on the key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(arena.allocator());

    try runInvalidPermissions(arena.allocator(),
        \\name: t
        \\on: push
        \\permissions:
        \\  contents:
        \\  actions: read
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    , &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try std.testing.expectEqualStrings(
        "missing permission level for \"contents\". expected \"read\", \"write\" or \"none\"",
        diag.message,
    );
    // The key, not the next entry: a null value's span is the following token.
    try std.testing.expectEqual(@as(u32, 4), diag.span.start_line);
}

test "PERM003: report an unknown scope with a suggestion" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(arena.allocator());

    try runInvalidPermissions(arena.allocator(),
        \\name: t
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    permissions:
        \\      content: read
        \\    steps:
        \\      - run: echo hi
        \\
    , &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings(
        "unknown permission scope \"content\". did you mean \"contents\"?",
        diags.get(0).message,
    );
}

test "PERM003: report an unknown scope without a near match" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(arena.allocator());

    try runInvalidPermissions(arena.allocator(),
        \\name: t
        \\on: push
        \\permissions:
        \\  nonsense: read
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    , &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings(
        "unknown permission scope \"nonsense\"",
        diags.get(0).message,
    );
}

test "PERM003: report an invalid all-scopes value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(arena.allocator());

    try runInvalidPermissions(arena.allocator(),
        \\name: t
        \\on: push
        \\permissions: read
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    , &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings(
        "invalid permission \"read\" for all scopes. expected \"read-all\" or \"write-all\"",
        diags.get(0).message,
    );
}

test "PERM003: valid permissions produce no diagnostics" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(arena.allocator());

    try runInvalidPermissions(arena.allocator(),
        \\name: t
        \\on: push
        \\permissions: read-all
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    permissions:
        \\      contents: read
        \\      id-token: write
        \\      artifact-metadata: read
        \\      models: read
        \\    steps:
        \\      - run: echo hi
        \\  other:
        \\    runs-on: ubuntu-latest
        \\    permissions: {}
        \\    steps:
        \\      - run: echo hi
        \\
    , &diags);

    try std.testing.expectEqual(@as(usize, 0), diags.len());
}
