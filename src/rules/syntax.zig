const std = @import("std");
const engine = @import("engine.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const DiagnosticList = engine.DiagnosticList;

// ── SYN008: Duplicated job ID in `needs` ──

/// Number of entries before `index` that name the same job as `needs[index]`.
/// Job IDs are case-insensitive in GitHub Actions, so compare accordingly.
fn priorOccurrences(needs: []const []const u8, index: usize) usize {
    var count: usize = 0;
    for (needs[0..index]) |earlier| {
        if (std.ascii.eqlIgnoreCase(earlier, needs[index])) count += 1;
    }
    return count;
}

fn checkDuplicateNeeds(job: *const Job, diag_list: *DiagnosticList) void {
    for (job.needs, 0..) |_, i| {
        // Report on the second occurrence only, so a job ID repeated three
        // or more times still yields a single diagnostic.
        if (priorOccurrences(job.needs, i) != 1) continue;

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

test "SYN008: two distinct duplicated job IDs report once each" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOnNeeds(&.{ "build", "lint", "build", "lint" }, &diags);

    try testing.expectEqual(@as(usize, 2), diags.len());
}

test "SYN008: distinct job IDs produce no diagnostic" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOnNeeds(&.{ "build", "lint" }, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN008: job without needs produces no diagnostic" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOnNeeds(&.{}, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}
