const std = @import("std");
const test_support = @import("../test_support.zig");
const engine = @import("engine.zig");
const fix_builder = @import("../fix/builder.zig");
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
        checkPermissionsScope(perms, wf.permissions_meta, spans.workflow_head, diag_list);
    }

    for (wf.jobs) |job| {
        if (job.permissions) |perms| {
            checkPermissionsScope(perms, job.permissions_meta, job.span, diag_list);
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

/// `fallback` is the span reported when the parser captured no span for the
/// offending permissions entry (e.g. a flow-style `permissions:` mapping).
fn checkPermissionsScope(perms: Permissions, meta: ?PermissionsMeta, fallback: Span, diag_list: *DiagnosticList) void {
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
    // key list. `id-token` gets a dedicated hint (OIDC context) and no autofix,
    // because the GitHub Actions spec does not allow `id-token: read`.
    inline for (workflow_types.permission_scopes) |field| {
        const key: []const u8 = comptime workflow_types.permissionScopeKey(field);
        const level: ?workflow_types.PermissionLevel = @field(perms, field);
        const value_span: ?Span = if (meta) |m| @field(m, field) else null;
        if (level) |lvl| {
            if (lvl == .write) {
                const is_id_token = comptime std.mem.eql(u8, key, "id-token");
                const span = value_span orelse fallback;
                if (is_id_token) {
                    diag_list.append(.{
                        .rule_id = "PERM001",
                        .severity = .info,
                        .message = "id-token: write grants OIDC token issuance. Ensure this job needs OIDC.",
                        .span = span,
                        .fix_hint = "id-token: write enables OIDC. Remove this entry if OIDC is not used.",
                    }) catch return;
                } else {
                    diag_list.append(.{
                        .rule_id = "PERM001",
                        .severity = .info,
                        .message = "Broad write permission detected. Ensure this is necessary.",
                        .span = span,
                        .fix_hint = "Consider if 'read' permission would suffice instead of 'write'.",
                        .fix = if (value_span) |vs| makeDowngradeToReadFix(diag_list, key, vs) else null,
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
        }) catch return;
    }
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
        .check_job = checkJobPermissions,
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

    const result = try test_support.lintAndFix(std.testing.allocator, source, .{ .job = &checkJobPermissions }, true);
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

    const result = try test_support.lintAndFix(std.testing.allocator, source, .{ .job = &checkJobPermissions }, true);
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
    checkPermissionsScope(perms, null, spans.workflow_head, &diags);

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
    checkPermissionsScope(perms, null, spans.workflow_head, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expect(diags.get(0).fix == null);
}

test "PERM001: no fix for individual write when meta is null" {
    const perms = Permissions{ .contents = .write };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPermissionsScope(perms, null, spans.workflow_head, &diags);

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
    checkPermissionsScope(perms, meta, spans.workflow_head, &diags);

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

test "PERM001: id-token: write emits dedicated hint without autofix" {
    const value_span = Span{
        .start_line = 2,
        .start_col = 13,
        .end_line = 2,
        .end_col = 18,
        .start_byte = 26,
        .end_byte = 31,
    };
    const perms = Permissions{ .id_token = .write };
    const meta = PermissionsMeta{ .id_token = value_span };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPermissionsScope(perms, meta, spans.workflow_head, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try std.testing.expectEqualStrings("PERM001", diag.rule_id);
    try std.testing.expect(diag.fix == null);
    const hint = diag.fix_hint orelse return error.TestExpectedNonNull;
    try std.testing.expect(std.mem.indexOf(u8, hint, "OIDC") != null);
    try std.testing.expect(std.mem.indexOf(u8, hint, "'read'") == null);
}

test "PERM001: detects write on previously uncovered scopes (attestations/discussions/pages/repository-projects)" {
    const perms = Permissions{
        .attestations = .write,
        .discussions = .write,
        .pages = .write,
        .repository_projects = .write,
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPermissionsScope(perms, null, spans.workflow_head, &diags);

    try std.testing.expectEqual(@as(usize, 4), diags.len());
}

test "PERM001: autofix applies to all 13 non-id-token scopes via the engine" {
    const fix_engine = @import("../fix/engine.zig");
    const source = "permissions:\n  pages: write\n";
    // `write` at bytes 22..27.
    const value_span = Span{
        .start_line = 2,
        .start_col = 10,
        .end_line = 2,
        .end_col = 15,
        .start_byte = 22,
        .end_byte = 27,
    };
    const perms = Permissions{ .pages = .write };
    const meta = PermissionsMeta{ .pages = value_span };

    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkPermissionsScope(perms, meta, spans.workflow_head, &diags);

    try std.testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix orelse return error.TestExpectedNonNull;
    const result = try fix_engine.applyFixes(std.testing.allocator, source, &.{fix});
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("permissions:\n  pages: read\n", result.content);
}

test "PERM001: id-token mixed with other writes produces per-field fixes except id-token" {
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

    try std.testing.expectEqual(@as(usize, 2), diags.len());
    var fix_count: usize = 0;
    var has_id_token_diag = false;
    for (0..diags.len()) |i| {
        const diag = diags.get(i);
        if (diag.fix != null) fix_count += 1;
        if (std.mem.indexOf(u8, diag.message, "id-token") != null) has_id_token_diag = true;
    }
    try std.testing.expectEqual(@as(usize, 1), fix_count);
    try std.testing.expect(has_id_token_diag);

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
