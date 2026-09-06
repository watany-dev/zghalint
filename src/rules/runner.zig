const std = @import("std");
const engine = @import("engine.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_types = @import("../yaml/types.zig");
const diagnostics_mod = @import("../diagnostics.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const DiagnosticList = engine.DiagnosticList;
const Severity = engine.Severity;
const Diagnostic = diagnostics_mod.Diagnostic;
const Fix = diagnostics_mod.Fix;
const Span = yaml_types.Span;

const LabelStatus = enum {
    /// Currently offered by GitHub (or a self-hosted convention label).
    current,
    deprecated,
    retired,

    /// A retired label makes the run fail outright; a deprecated one still works.
    fn severity(self: LabelStatus) Severity {
        return switch (self) {
            .retired => .@"error",
            .deprecated, .current => .warning,
        };
    }

    fn message(self: LabelStatus) []const u8 {
        return switch (self) {
            .retired => "runs-on label is retired and the workflow will fail to start",
            .deprecated, .current => "runs-on label is deprecated and scheduled for retirement",
        };
    }
};

/// Every `runs-on` label zghalint recognises, in one pile: RUNNER001 reports
/// the retired/deprecated ones, RUNNER002 treats membership here (plus the
/// user's own `runner.labels`) as the definition of "known".
const KnownLabel = struct {
    label: []const u8,
    status: LabelStatus = .current,
    /// Only meaningful for deprecated/retired labels.
    replacement: []const u8 = "",
};

const known_labels = [_]KnownLabel{
    // GitHub-hosted, currently offered.
    .{ .label = "ubuntu-latest" },
    .{ .label = "ubuntu-24.04" },
    .{ .label = "ubuntu-22.04" },
    .{ .label = "ubuntu-24.04-arm" },
    .{ .label = "ubuntu-22.04-arm" },
    .{ .label = "windows-latest" },
    .{ .label = "windows-2025" },
    .{ .label = "windows-2022" },
    .{ .label = "windows-11-arm" },
    .{ .label = "macos-latest" },
    .{ .label = "macos-26" },
    .{ .label = "macos-15" },
    .{ .label = "macos-14" },
    .{ .label = "macos-13" },
    // Self-hosted convention labels (GitHub adds these automatically).
    .{ .label = "self-hosted" },
    .{ .label = "linux" },
    .{ .label = "windows" },
    .{ .label = "macos" },
    .{ .label = "x64" },
    .{ .label = "x86" },
    .{ .label = "arm" },
    .{ .label = "arm64" },
    // Withdrawn or on the way out.
    .{ .label = "ubuntu-18.04", .status = .retired, .replacement = "ubuntu-22.04" },
    .{ .label = "ubuntu-20.04", .status = .retired, .replacement = "ubuntu-22.04" },
    .{ .label = "macos-11", .status = .retired, .replacement = "macos-13" },
    .{ .label = "macos-12", .status = .retired, .replacement = "macos-13" },
    .{ .label = "windows-2019", .status = .deprecated, .replacement = "windows-2022" },
};

fn checkDeprecatedRunner(job: *const Job, diag_list: *DiagnosticList) void {
    const runs_on = job.runs_on orelse return;

    for (known_labels) |entry| {
        if (entry.status == .current) continue;
        if (!std.mem.eql(u8, runs_on, entry.label)) continue;

        const span = job.runs_on_value_span orelse job.span;
        const fix: ?Fix = if (job.runs_on_value_span) |vs| blk: {
            const edits = diag_list.allocEdit(.{
                .start_byte = vs.start_byte,
                .end_byte = vs.end_byte,
                .replacement = entry.replacement,
            }) orelse break :blk null;
            break :blk Fix{
                .description = "Replace with supported runner label",
                .safety = .unsafe,
                .edits = edits,
            };
        } else null;

        diag_list.append(.{
            .rule_id = "RUNNER001",
            .severity = entry.status.severity(),
            .message = entry.status.message(),
            .span = span,
            .fix_hint = entry.replacement,
            .fix = fix,
        }) catch return;
        return;
    }
}

pub const rules = [_]Rule{
    .{
        .id = "RUNNER001",
        .name = "deprecated-runner",
        .description = "runs-on label is retired or scheduled for retirement by GitHub",
        .severity = .warning,
        .category = .runner,
        .check_job = &checkDeprecatedRunner,
    },
};

const testing = std.testing;
const test_support = @import("../test_support.zig");

const dummySpan = test_support.dummySpan;

test "RUNNER001: retired ubuntu-20.04 emits error with unsafe fix" {
    const job = Job{
        .id = "build",
        .runs_on = "ubuntu-20.04",
        .runs_on_value_span = dummySpan(100, 112),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkDeprecatedRunner(&job, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("RUNNER001", diag.rule_id);
    try testing.expect(diag.severity == .@"error");

    const fix = diag.fix orelse return error.TestUnexpectedResult;
    try testing.expect(fix.safety == .unsafe);
    try testing.expectEqual(@as(usize, 1), fix.edits.len);
    try testing.expectEqualStrings("ubuntu-22.04", fix.edits[0].replacement);
    try testing.expectEqual(@as(usize, 100), fix.edits[0].start_byte);
    try testing.expectEqual(@as(usize, 112), fix.edits[0].end_byte);
}

test "RUNNER001: deprecated windows-2019 emits warning" {
    const job = Job{
        .id = "build",
        .runs_on = "windows-2019",
        .runs_on_value_span = dummySpan(50, 62),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkDeprecatedRunner(&job, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(diag.severity == .warning);
    const fix = diag.fix orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("windows-2022", fix.edits[0].replacement);
}

test "RUNNER001: current runner produces no diagnostic" {
    const job = Job{
        .id = "build",
        .runs_on = "ubuntu-24.04",
        .runs_on_value_span = dummySpan(10, 22),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkDeprecatedRunner(&job, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RUNNER001: reusable workflow job without runs-on is ignored" {
    const job = Job{
        .id = "call",
        .runs_on = null,
        .uses = "./.github/workflows/reusable.yml",
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkDeprecatedRunner(&job, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RUNNER001: unknown label produces no diagnostic" {
    const job = Job{
        .id = "build",
        .runs_on = "self-hosted-custom",
        .runs_on_value_span = dummySpan(10, 28),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkDeprecatedRunner(&job, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RUNNER001: autofix end-to-end replaces label in YAML source" {
    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-20.04
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const result = try test_support.lintAndFix(testing.allocator, source, .{ .job = &checkDeprecatedRunner }, true);
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), result.diagnostic_count);
    try testing.expectEqual(@as(usize, 1), result.edits_applied);
    try testing.expect(std.mem.indexOf(u8, result.content, "ubuntu-22.04") != null);
    try testing.expect(std.mem.indexOf(u8, result.content, "ubuntu-20.04") == null);
}
