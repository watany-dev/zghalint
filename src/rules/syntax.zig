const std = @import("std");
const engine = @import("engine.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const DiagnosticList = engine.DiagnosticList;

// ── SYN008: Duplicated job ID in `needs` ──

fn checkDuplicateNeeds(job: *const Job, diag_list: *DiagnosticList) void {
    for (job.needs, 0..) |dep, i| {
        // Job IDs are case-insensitive in GitHub Actions. Report on the second
        // occurrence only, so an ID repeated three or more times still yields
        // a single diagnostic.
        var prior: usize = 0;
        for (job.needs[0..i]) |earlier| {
            if (std.ascii.eqlIgnoreCase(earlier, dep)) prior += 1;
        }
        if (prior != 1) continue;

        diag_list.append(.{
            .rule_id = "SYN008",
            .severity = .warning,
            .message = "job ID is duplicated in 'needs'",
            .span = job.span,
            .fix_hint = "remove the repeated job ID from 'needs'",
        }) catch return;
    }
}

pub const rules = [_]Rule{
    .{
        .id = "SYN008",
        .name = "duplicate-needs",
        .description = "the same job ID is listed more than once in 'needs'",
        .severity = .warning,
        .category = .syntax,
        .check_job = &checkDuplicateNeeds,
    },
};

// ============================================================
// Tests
// ============================================================

const testing = std.testing;

fn runOnNeeds(needs: []const []const u8, diags: *DiagnosticList) void {
    const job = Job{ .id = "test", .runs_on = "ubuntu-latest", .needs = needs };
    checkDuplicateNeeds(&job, diags);
}

test "SYN008: duplicated job ID is reported" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOnNeeds(&.{ "build", "build" }, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("SYN008", diag.rule_id);
    try testing.expect(diag.severity == .warning);
}

test "SYN008: duplicate detection is case-insensitive" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOnNeeds(&.{ "Build", "bUILD" }, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
}

test "SYN008: a job ID repeated three times reports once" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOnNeeds(&.{ "build", "build", "build" }, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
}

test "SYN008: distinct job IDs produce no diagnostic" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOnNeeds(&.{ "build", "lint" }, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}
