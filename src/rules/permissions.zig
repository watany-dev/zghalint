const std = @import("std");
const engine = @import("engine.zig");
const types = @import("../workflow/types.zig");
const Rule = engine.Rule;
const Job = engine.Job;
const Workflow = engine.Workflow;
const DiagnosticList = engine.DiagnosticList;

// ── PERM001: Overly broad permissions ──

const broad_permissions = [_]struct { key: []const u8, value: []const u8 }{
    .{ .key = "contents", .value = "write" },
    .{ .key = "packages", .value = "write" },
    .{ .key = "actions", .value = "write" },
    .{ .key = "security-events", .value = "write" },
    .{ .key = "deployments", .value = "write" },
    .{ .key = "id-token", .value = "write" },
    .{ .key = "pull-requests", .value = "write" },
    .{ .key = "issues", .value = "write" },
    .{ .key = "statuses", .value = "write" },
    .{ .key = "checks", .value = "write" },
};

fn checkBroadPermissions(wf: *const Workflow, diagnostics: *DiagnosticList) void {
    // Check workflow-level permissions
    if (wf.permissions) |perms| {
        checkPermissionsScope(perms, "workflow", diagnostics);
    }

    // Check job-level permissions
    for (wf.jobs) |job| {
        if (job.permissions) |perms| {
            checkPermissionsScope(perms, job.id, diagnostics);
        }
    }
}

fn checkPermissionsScope(perms: types.Permissions, context: []const u8, diagnostics: *DiagnosticList) void {
    // Check for write-all scope
    if (perms.scope) |scope| {
        if (std.mem.eql(u8, scope, "write-all")) {
            diagnostics.append(.{
                .rule_id = "PERM001",
                .severity = .warning,
                .message = "Overly broad 'write-all' permissions scope. Apply principle of least privilege.",
                .fix_hint = "Replace 'write-all' with specific permissions needed.",
            });
            return;
        }
    }

    _ = context;

    // Check individual permissions for broad write access
    const individual = perms.individual orelse return;
    for (broad_permissions) |bp| {
        if (individual.get(bp.key)) |val| {
            if (std.mem.eql(u8, val, bp.value)) {
                diagnostics.append(.{
                    .rule_id = "PERM001",
                    .severity = .info,
                    .message = "Broad write permission detected. Ensure this is necessary.",
                    .fix_hint = "Consider if 'read' permission would suffice instead of 'write'.",
                });
            }
        }
    }
}

// ── PERM002: Missing job-level permissions with third-party actions ──

fn checkJobPermissions(job: *const Job, diagnostics: *DiagnosticList) void {
    if (job.permissions != null) return;

    for (job.steps) |step| {
        if (step.uses) |action_ref| {
            if (action_ref.is_local or action_ref.is_docker) continue;

            // Check if it's a third-party action (not actions/* or github/*)
            const owner = action_ref.owner orelse continue;
            if (std.mem.eql(u8, owner, "actions") or std.mem.eql(u8, owner, "github")) continue;

            diagnostics.append(.{
                .rule_id = "PERM002",
                .severity = .warning,
                .message = "Job uses third-party actions without job-level 'permissions'. Define explicit permissions to limit token scope.",
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

test "PERM001: detect write-all scope" {
    const allocator = std.testing.allocator;
    const wf = Workflow{
        .on = .{ .events = &.{} },
        .permissions = .{ .scope = "write-all" },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkBroadPermissions(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("PERM001", diags.get(0).rule_id);
}

test "PERM001: detect contents:write" {
    const allocator = std.testing.allocator;
    const keys = [_][]const u8{"contents"};
    const vals = [_][]const u8{"write"};
    const wf = Workflow{
        .on = .{ .events = &.{} },
        .permissions = .{
            .individual = .{ .keys = &keys, .values = &vals },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkBroadPermissions(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
}

test "PERM001: no warning for read-only" {
    const allocator = std.testing.allocator;
    const keys = [_][]const u8{"contents"};
    const vals = [_][]const u8{"read"};
    const wf = Workflow{
        .on = .{ .events = &.{} },
        .permissions = .{
            .individual = .{ .keys = &keys, .values = &vals },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkBroadPermissions(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERM001: no warning for read-all scope" {
    const allocator = std.testing.allocator;
    const wf = Workflow{
        .on = .{ .events = &.{} },
        .permissions = .{ .scope = "read-all" },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkBroadPermissions(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERM001: detect broad permissions at job level" {
    const allocator = std.testing.allocator;
    const jobs = [_]Job{
        .{
            .id = "deploy",
            .permissions = .{ .scope = "write-all" },
        },
    };
    const wf = Workflow{
        .on = .{ .events = &.{} },
        .jobs = &jobs,
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkBroadPermissions(&wf, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
}

test "PERM002: detect missing permissions with third-party action" {
    const allocator = std.testing.allocator;
    const job = Job{
        .id = "build",
        .steps = &.{
            .{ .uses = types.ActionRef.parse("actions/checkout@v4") },
            .{ .uses = types.ActionRef.parse("some-org/some-action@v1") },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkJobPermissions(&job, &diags);
    try std.testing.expectEqual(@as(usize, 1), diags.len());
    try std.testing.expectEqualStrings("PERM002", diags.get(0).rule_id);
}

test "PERM002: no warning when permissions are set" {
    const allocator = std.testing.allocator;
    const job = Job{
        .id = "build",
        .permissions = .{ .scope = "read-all" },
        .steps = &.{
            .{ .uses = types.ActionRef.parse("some-org/some-action@v1") },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkJobPermissions(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERM002: no warning with only first-party actions" {
    const allocator = std.testing.allocator;
    const job = Job{
        .id = "build",
        .steps = &.{
            .{ .uses = types.ActionRef.parse("actions/checkout@v4") },
            .{ .uses = types.ActionRef.parse("github/codeql-action/init@v2") },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkJobPermissions(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERM002: no warning with only local actions" {
    const allocator = std.testing.allocator;
    const job = Job{
        .id = "build",
        .steps = &.{
            .{ .uses = types.ActionRef.parse("./.github/actions/my-action") },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkJobPermissions(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "PERM002: no warning with only run steps" {
    const allocator = std.testing.allocator;
    const job = Job{
        .id = "build",
        .steps = &.{
            .{ .run = "echo hello" },
        },
    };
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    checkJobPermissions(&job, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}
