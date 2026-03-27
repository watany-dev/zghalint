const std = @import("std");
const engine = @import("engine.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_types = @import("../yaml/types.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const Step = engine.Step;
const Workflow = engine.Workflow;
const DiagnosticList = engine.DiagnosticList;
const Permissions = workflow_types.Permissions;
const Span = yaml_types.Span;
const ActionRef = workflow_types.ActionRef;

// ── PERM001: Overly broad permissions ──

fn checkBroadPermissions(wf: *const Workflow, diag_list: *DiagnosticList) void {
    if (wf.permissions) |perms| {
        checkPermissionsScope(perms, diag_list);
    }

    for (wf.jobs) |job| {
        if (job.permissions) |perms| {
            checkPermissionsScope(perms, diag_list);
        }
    }
}

fn checkPermissionsScope(perms: Permissions, diag_list: *DiagnosticList) void {
    if (perms.write_all) {
        diag_list.append(.{
            .rule_id = "PERM001",
            .severity = .warning,
            .message = "Overly broad 'write-all' permissions. Apply principle of least privilege.",
            .span = Span.point(0, 0, 0),
            .fix_hint = "Replace 'write-all' with specific permissions needed.",
        });
        return;
    }

    // Check individual write permissions
    const write_fields = .{
        perms.contents,
        perms.packages,
        perms.actions,
        perms.security_events,
        perms.deployments,
        perms.id_token,
        perms.pull_requests,
        perms.issues,
        perms.statuses,
        perms.checks,
    };

    inline for (write_fields) |field| {
        if (field) |level| {
            if (level == .write) {
                diag_list.append(.{
                    .rule_id = "PERM001",
                    .severity = .info,
                    .message = "Broad write permission detected. Ensure this is necessary.",
                    .span = Span.point(0, 0, 0),
                    .fix_hint = "Consider if 'read' permission would suffice instead of 'write'.",
                });
            }
        }
    }
}

// ── PERM002: Missing job-level permissions with third-party actions ──

fn checkJobPermissions(job: *const Job, diag_list: *DiagnosticList) void {
    if (job.permissions != null) return;

    for (job.steps) |step| {
        if (step.uses) |action_ref| {
            if (action_ref.is_local or action_ref.is_docker) continue;

            const owner = action_ref.owner orelse continue;
            if (std.mem.eql(u8, owner, "actions") or std.mem.eql(u8, owner, "github")) continue;

            diag_list.append(.{
                .rule_id = "PERM002",
                .severity = .warning,
                .message = "Job uses third-party actions without job-level 'permissions'. Define explicit permissions to limit token scope.",
                .span = Span.point(0, 0, 0),
                .fix_hint = "Add a 'permissions' block to this job to restrict the GITHUB_TOKEN scope.",
            });
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
};

// ── Tests ──

fn makeEmptyTrigger() workflow_types.Trigger {
    return .{ .events = &.{} };
}

test "PERM001: detect write-all scope" {
    const wf = Workflow{
        .on = makeEmptyTrigger(),
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
        .on = makeEmptyTrigger(),
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
        .on = makeEmptyTrigger(),
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
        .on = makeEmptyTrigger(),
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
        .on = makeEmptyTrigger(),
        .jobs = &jobs,
    };
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    checkBroadPermissions(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
}

test "PERM001: detect multiple write permissions" {
    const wf = Workflow{
        .on = makeEmptyTrigger(),
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
