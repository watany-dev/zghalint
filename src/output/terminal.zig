const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const Diagnostic = diagnostics.Diagnostic;
const DiagnosticList = diagnostics.DiagnosticList;
const Severity = diagnostics.Severity;

const Color = struct {
    const reset = "\x1b[0m";
    const bold = "\x1b[1m";
    const gray = "\x1b[90m";
    const bold_red = "\x1b[1;31m";
    const bold_yellow = "\x1b[1;33m";
    const bold_blue = "\x1b[1;34m";
    const bold_gray = "\x1b[1;90m";
};

fn severityColor(sev: Severity) []const u8 {
    return switch (sev) {
        .@"error" => Color.bold_red,
        .warning => Color.bold_yellow,
        .info => Color.bold_blue,
        .hint => Color.bold_gray,
    };
}

/// Control characters (< 0x20) and DEL in attacker-influenced strings (file
/// path, diagnostic message, source line) are rewritten as `\xHH` so a
/// malicious workflow cannot inject colors, clear the screen, or hide
/// warnings in a CI log pipeline. Tab is preserved for source alignment.
fn writeSanitized(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        if (c == '\t') {
            try writer.writeByte(c);
        } else if (c < 0x20 or c == 0x7f) {
            try writer.print("\\x{x:0>2}", .{c});
        } else {
            try writer.writeByte(c);
        }
    }
}

pub fn renderDiagnostic(writer: anytype, diag: Diagnostic, use_color: bool) !void {
    const file_str = diag.file orelse "<unknown>";
    const sev_str = @tagName(diag.severity);
    const sev_color = if (use_color) severityColor(diag.severity) else "";
    const bold = if (use_color) Color.bold else "";
    const reset = if (use_color) Color.reset else "";
    const gray = if (use_color) Color.gray else "";

    try writer.print("{s}", .{bold});
    try writeSanitized(writer, file_str);
    try writer.print(":{d}:{d}:{s} {s}{s}[{s}]{s}: ", .{
        diag.span.start_line,
        diag.span.start_col,
        reset,
        sev_color,
        sev_str,
        diag.rule_id,
        reset,
    });
    try writeSanitized(writer, diag.message);
    try writer.writeByte('\n');

    if (diag.fix_hint) |hint| {
        try writer.print("  {s}={s} {s}help:{s} ", .{ gray, reset, bold, reset });
        try writeSanitized(writer, hint);
        try writer.writeByte('\n');
    }
}

pub fn renderDiagnostics(writer: anytype, list: DiagnosticList, use_color: bool) !void {
    for (list.items.items) |diag| {
        try renderDiagnostic(writer, diag, use_color);
        try writer.writeAll("\n");
    }

    try renderSummary(writer, list, use_color);
}

pub fn renderSummary(writer: anytype, list: DiagnosticList, use_color: bool) !void {
    const counts = list.countBySeverity();
    const errors = counts.@"error";
    const warnings = counts.warning;
    const infos = counts.info;
    const hints = counts.hint;

    const bold = if (use_color) Color.bold else "";
    const reset = if (use_color) Color.reset else "";
    const red = if (use_color) Color.bold_red else "";
    const yellow = if (use_color) Color.bold_yellow else "";

    if (list.len() == 0) {
        try writer.print("{s}No issues found.{s}\n", .{ bold, reset });
    } else {
        try writer.print("{s}Found {d} issue(s):{s} ", .{ bold, list.len(), reset });
        if (errors > 0) try writer.print("{s}{d} error(s){s} ", .{ red, errors, reset });
        if (warnings > 0) try writer.print("{s}{d} warning(s){s} ", .{ yellow, warnings, reset });
        if (infos > 0) try writer.print("{d} info ", .{infos});
        if (hints > 0) try writer.print("{d} hint(s) ", .{hints});
        try writer.writeAll("\n");
    }
}

const Span = @import("../yaml/types.zig").Span;

test "renderDiagnostic with color" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    const diag = Diagnostic{
        .rule_id = "SEC002",
        .severity = .@"error",
        .message = "Potential script injection via github.event.issue.title",
        .file = ".github/workflows/ci.yml",
        .span = .{
            .start_line = 15,
            .start_col = 14,
            .end_line = 15,
            .end_col = 48,
            .start_byte = 200,
            .end_byte = 234,
        },
        .fix_hint = "Use an environment variable instead",
    };

    try renderDiagnostic(writer, diag, true);
    const output = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, output, "SEC002") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "error") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "15:14") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "script injection") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "help:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "environment variable") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\x1b[") != null);
}

test "renderDiagnostic without color" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    const diag = Diagnostic{
        .rule_id = "BP001",
        .severity = .warning,
        .message = "missing timeout",
        .file = "ci.yml",
        .span = Span.point(5, 3, 40),
        .fix_hint = "add timeout-minutes",
    };

    try renderDiagnostic(writer, diag, false);
    const output = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, output, "ci.yml:5:3:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "warning[BP001]") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "missing timeout") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "help:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\x1b[") == null);
}

test "renderDiagnostic sanitizes ANSI escapes in attacker-controlled fields" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    // Evil file path, message, and fix hint all carry ESC (0x1b)
    // — a malicious workflow or filename must not be able to inject ANSI
    // sequences into the CI operator's terminal.
    const diag = Diagnostic{
        .rule_id = "SEC001",
        .severity = .@"error",
        .file = ".github/workflows/\x1b[31mevil\x1b[0m.yml",
        .message = "\x1b[2Jpwned",
        .fix_hint = "\x1b[Hcursor-home",
        .span = Span.point(1, 1, 0),
    };

    try renderDiagnostic(writer, diag, false);
    const output = buf.items;

    // No raw ESC (0x1b) anywhere in the output — the sanitizer must rewrite
    // every attacker-supplied byte before it hits the terminal.
    try std.testing.expect(std.mem.indexOfScalar(u8, output, 0x1b) == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\\x1b") != null);
}

test "renderDiagnostic no hint" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    const diag = Diagnostic{
        .rule_id = "PERF001",
        .severity = .info,
        .message = "consider adding cache",
        .span = Span.point(1, 1, 0),
    };

    try renderDiagnostic(writer, diag, false);
    const output = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, output, "<unknown>:1:1:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "info[PERF001]") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "help:") == null);
}

test "renderSummary counts" {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{ .rule_id = "E1", .severity = .@"error", .message = "e", .span = Span.point(1, 1, 0) });
    try list.append(.{ .rule_id = "E2", .severity = .@"error", .message = "e", .span = Span.point(2, 1, 0) });
    try list.append(.{ .rule_id = "W1", .severity = .warning, .message = "w", .span = Span.point(3, 1, 0) });

    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    try renderSummary(buf.writer(std.testing.allocator), list, false);
    const output = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, output, "3 issue(s)") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "2 error(s)") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "1 warning(s)") != null);
}

test "renderSummary no issues" {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    try renderSummary(buf.writer(std.testing.allocator), list, false);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "No issues found") != null);
}

test "renderDiagnostics renders multiple items with summary" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{ .rule_id = "E1", .severity = .@"error", .message = "err msg", .file = "a.yml", .span = Span.point(1, 1, 0) });
    try list.append(.{ .rule_id = "W1", .severity = .warning, .message = "warn msg", .file = "a.yml", .span = Span.point(2, 1, 0) });

    try renderDiagnostics(writer, list, false);
    const output = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, output, "err msg") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "warn msg") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "2 issue(s)") != null);
}

test "renderSummary with all severity types" {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{ .rule_id = "E1", .severity = .@"error", .message = "e", .span = Span.point(1, 1, 0) });
    try list.append(.{ .rule_id = "W1", .severity = .warning, .message = "w", .span = Span.point(2, 1, 0) });
    try list.append(.{ .rule_id = "I1", .severity = .info, .message = "i", .span = Span.point(3, 1, 0) });
    try list.append(.{ .rule_id = "H1", .severity = .hint, .message = "h", .span = Span.point(4, 1, 0) });

    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    try renderSummary(buf.writer(std.testing.allocator), list, false);
    const output = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, output, "4 issue(s)") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "1 error(s)") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "1 warning(s)") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "1 info") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "1 hint(s)") != null);
}

test "renderSummary with color" {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{ .rule_id = "E1", .severity = .@"error", .message = "e", .span = Span.point(1, 1, 0) });

    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    try renderSummary(buf.writer(std.testing.allocator), list, true);
    const output = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, output, "\x1b[") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "1 error(s)") != null);
}

test "severityColor returns correct codes" {
    try std.testing.expectEqualStrings(Color.bold_red, severityColor(.@"error"));
    try std.testing.expectEqualStrings(Color.bold_yellow, severityColor(.warning));
    try std.testing.expectEqualStrings(Color.bold_blue, severityColor(.info));
    try std.testing.expectEqualStrings(Color.bold_gray, severityColor(.hint));
}

test "renderDiagnostic with no file shows unknown" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{
        .rule_id = "T1",
        .severity = .hint,
        .message = "a hint",
        .span = Span.point(1, 1, 0),
    });

    try renderDiagnostics(writer, list, false);
    const output = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, output, "a hint") != null);
}
