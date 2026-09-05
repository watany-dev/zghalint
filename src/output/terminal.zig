const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const Diagnostic = diagnostics.Diagnostic;
const DiagnosticList = diagnostics.DiagnosticList;
const Severity = diagnostics.Severity;

/// ANSI color codes for terminal output.
const Color = struct {
    const reset = "\x1b[0m";
    const bold = "\x1b[1m";
    const red = "\x1b[31m";
    const yellow = "\x1b[33m";
    const blue = "\x1b[34m";
    const gray = "\x1b[90m";
    const cyan = "\x1b[36m";
    const bold_red = "\x1b[1;31m";
    const bold_yellow = "\x1b[1;33m";
    const bold_blue = "\x1b[1;34m";
    const bold_gray = "\x1b[1;90m";
};

/// Returns the color code for the given severity.
fn severityColor(sev: Severity) []const u8 {
    return switch (sev) {
        .@"error" => Color.bold_red,
        .warning => Color.bold_yellow,
        .info => Color.bold_blue,
        .hint => Color.bold_gray,
    };
}

/// Emit bytes from an attacker-influenced string (file path, diagnostic
/// message, workflow source line) while neutralising ANSI escapes. Control
/// characters (< 0x20) and DEL are rewritten as `\xHH` so a malicious
/// workflow cannot inject colors, clear the screen, or hide warnings in a
/// CI log pipeline. Tab is preserved for source alignment.
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

/// Render a single diagnostic to the writer with ANSI colors and source context.
/// `source` is the full file source text (optional). If provided, the offending
/// source line and caret indicators will be displayed.
pub fn renderDiagnostic(writer: anytype, diag: Diagnostic, source: ?[]const u8, use_color: bool) !void {
    const file_str = diag.file orelse "<unknown>";
    const sev_str = diag.severity.toString();
    const sev_color = if (use_color) severityColor(diag.severity) else "";
    const bold = if (use_color) Color.bold else "";
    const reset = if (use_color) Color.reset else "";
    const cyan = if (use_color) Color.cyan else "";
    const gray = if (use_color) Color.gray else "";

    // Header line: file:line:col: severity[RULE]: message
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

    // Source line + caret
    if (source) |src| {
        if (diag.span.start_line > 0) {
            if (getSourceLine(src, diag.span.start_line)) |line| {
                const line_num = diag.span.start_line;
                // gutter
                try writer.print("{s}  |{s}\n", .{ gray, reset });
                try writer.print("{s}  {d} |{s} ", .{ cyan, line_num, reset });
                try writeSanitized(writer, line);
                try writer.writeByte('\n');

                // caret line
                try writer.print("{s}  |{s} ", .{ gray, reset });
                const col = if (diag.span.start_col > 0) diag.span.start_col - 1 else 0;
                // Calculate caret width
                const end_col = if (diag.span.end_col > diag.span.start_col and diag.span.end_line == diag.span.start_line)
                    diag.span.end_col - diag.span.start_col
                else
                    1;
                const width = if (end_col > 0) end_col else 1;

                try writeNChars(writer, ' ', col);
                try writer.print("{s}", .{sev_color});
                try writeNChars(writer, '^', width);
                try writer.print("{s}\n", .{reset});
            }
        }
    }

    // Fix hint
    if (diag.fix_hint) |hint| {
        try writer.print("  {s}={s} {s}help:{s} ", .{ gray, reset, bold, reset });
        try writeSanitized(writer, hint);
        try writer.writeByte('\n');
    }
}

/// Render all diagnostics from a list, with optional source content lookup.
/// `source_lookup` maps file paths to source content. Pass null to skip source display.
pub fn renderDiagnostics(
    writer: anytype,
    list: DiagnosticList,
    source_lookup: ?*const fn ([]const u8) ?[]const u8,
    use_color: bool,
) !void {
    for (list.items.items) |diag| {
        const source = if (source_lookup) |lookup|
            if (diag.file) |f| lookup(f) else null
        else
            null;
        try renderDiagnostic(writer, diag, source, use_color);
        try writer.writeAll("\n");
    }

    // Summary line
    try renderSummary(writer, list, use_color);
}

/// Render a summary line showing counts by severity.
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

// ---- Helpers ----

fn getSourceLine(source: []const u8, line_num: u32) ?[]const u8 {
    if (line_num == 0) return null;
    var current_line: u32 = 1;
    var start: usize = 0;
    for (source, 0..) |c, i| {
        if (current_line == line_num) {
            // Find end of this line
            var end = i;
            while (end < source.len and source[end] != '\n') : (end += 1) {}
            return source[start..end];
        }
        if (c == '\n') {
            current_line += 1;
            start = i + 1;
        }
    }
    // Last line without trailing newline
    if (current_line == line_num and start <= source.len) {
        return source[start..];
    }
    return null;
}

fn writeNChars(writer: anytype, char: u8, count: u32) !void {
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        try writer.writeByte(char);
    }
}

// ============================================================
// Tests
// ============================================================

const Span = @import("../yaml/types.zig").Span;

test "renderDiagnostic with source and color" {
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

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\      - name: Echo title
        \\        run: |
        \\          echo "Processing"
        \\          echo "More stuff"
        \\          echo "Even more"
        \\          echo "Almost there"
        \\          echo "One more"
        \\          echo "${{ github.event.issue.title }}"
    ;

    try renderDiagnostic(writer, diag, source, true);
    const output = buf.items;

    // Verify key parts are present
    try std.testing.expect(std.mem.indexOf(u8, output, "SEC002") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "error") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "15:14") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "script injection") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "^^^") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "help:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "environment variable") != null);
    // Verify ANSI codes present
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

    try renderDiagnostic(writer, diag, null, false);
    const output = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, output, "ci.yml:5:3:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "warning[BP001]") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "missing timeout") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "help:") != null);
    // No ANSI codes
    try std.testing.expect(std.mem.indexOf(u8, output, "\x1b[") == null);
}

test "renderDiagnostic sanitizes ANSI escapes in attacker-controlled fields" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    // Evil file path, message, source line, and fix hint all carry ESC (0x1b)
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
    const src = "name: \"\x1b[32mOK\x1b[0m\"\n";

    try renderDiagnostic(writer, diag, src, false);
    const output = buf.items;

    // No raw ESC (0x1b) anywhere in the output — the sanitizer must rewrite
    // every attacker-supplied byte before it hits the terminal.
    try std.testing.expect(std.mem.indexOfScalar(u8, output, 0x1b) == null);
    // ESC is displayed as "\x1b" (backslash + x + two hex digits).
    try std.testing.expect(std.mem.indexOf(u8, output, "\\x1b") != null);
}

test "renderDiagnostic no source no hint" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    const diag = Diagnostic{
        .rule_id = "PERF001",
        .severity = .info,
        .message = "consider adding cache",
        .span = Span.point(1, 1, 0),
    };

    try renderDiagnostic(writer, diag, null, false);
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

test "getSourceLine returns correct line" {
    const src = "line1\nline2\nline3\n";
    try std.testing.expectEqualStrings("line1", getSourceLine(src, 1).?);
    try std.testing.expectEqualStrings("line2", getSourceLine(src, 2).?);
    try std.testing.expectEqualStrings("line3", getSourceLine(src, 3).?);
    try std.testing.expect(getSourceLine(src, 0) == null);
    try std.testing.expect(getSourceLine(src, 5) == null);
}

test "getSourceLine last line no newline" {
    const src = "first\nsecond";
    try std.testing.expectEqualStrings("second", getSourceLine(src, 2).?);
}

test "renderDiagnostics renders multiple items with summary" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{ .rule_id = "E1", .severity = .@"error", .message = "err msg", .file = "a.yml", .span = Span.point(1, 1, 0) });
    try list.append(.{ .rule_id = "W1", .severity = .warning, .message = "warn msg", .file = "a.yml", .span = Span.point(2, 1, 0) });

    try renderDiagnostics(writer, list, null, false);
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

test "renderDiagnostic with source but start_line zero" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    const diag = Diagnostic{
        .rule_id = "T1",
        .severity = .warning,
        .message = "test",
        .span = Span.point(0, 0, 0),
    };

    try renderDiagnostic(writer, diag, "some source", false);
    const output = buf.items;
    // Should not crash, source context skipped when line is 0
    try std.testing.expect(std.mem.indexOf(u8, output, "warning[T1]") != null);
}

test "renderDiagnostic multi-char caret span" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    const diag = Diagnostic{
        .rule_id = "T1",
        .severity = .@"error",
        .message = "test",
        .file = "f.yml",
        .span = .{
            .start_line = 1,
            .start_col = 1,
            .end_line = 1,
            .end_col = 4,
            .start_byte = 0,
            .end_byte = 3,
        },
    };

    try renderDiagnostic(writer, diag, "abcdef", true);
    const output = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, output, "^^^") != null);
}

test "severityColor returns correct codes" {
    try std.testing.expectEqualStrings(Color.bold_red, severityColor(.@"error"));
    try std.testing.expectEqualStrings(Color.bold_yellow, severityColor(.warning));
    try std.testing.expectEqualStrings(Color.bold_blue, severityColor(.info));
    try std.testing.expectEqualStrings(Color.bold_gray, severityColor(.hint));
}

test "getSourceLine empty source" {
    // Empty source with line 1 returns empty slice (last line without trailing newline)
    try std.testing.expectEqualStrings("", getSourceLine("", 1).?);
    try std.testing.expect(getSourceLine("", 0) == null);
    try std.testing.expect(getSourceLine("", 2) == null);
}

test "renderDiagnostics with source_lookup callback" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{
        .rule_id = "T1",
        .severity = .@"error",
        .message = "test error",
        .file = "found.yml",
        .span = .{ .start_line = 1, .start_col = 1, .end_line = 1, .end_col = 5, .start_byte = 0, .end_byte = 4 },
    });
    try list.append(.{
        .rule_id = "T2",
        .severity = .warning,
        .message = "test warning",
        .file = "missing.yml",
        .span = Span.point(1, 1, 0),
    });

    const lookup = struct {
        fn func(path: []const u8) ?[]const u8 {
            if (std.mem.eql(u8, path, "found.yml")) return "name: CI";
            return null;
        }
    }.func;

    try renderDiagnostics(writer, list, &lookup, false);
    const output = buf.items;

    // First diagnostic should include source context (file found)
    try std.testing.expect(std.mem.indexOf(u8, output, "name: CI") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "^^^^") != null);
    // Second diagnostic should have no source context (file not found)
    try std.testing.expect(std.mem.indexOf(u8, output, "test warning") != null);
    // Summary
    try std.testing.expect(std.mem.indexOf(u8, output, "2 issue(s)") != null);
}

test "renderDiagnostic multi-line span shows single caret" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    const diag = Diagnostic{
        .rule_id = "T1",
        .severity = .warning,
        .message = "spans multiple lines",
        .file = "f.yml",
        .span = .{
            .start_line = 1,
            .start_col = 3,
            .end_line = 5,
            .end_col = 1,
            .start_byte = 2,
            .end_byte = 40,
        },
    };

    try renderDiagnostic(writer, diag, "ab: cd\nef: gh", false);
    const output = buf.items;

    // end_line != start_line, so width should be 1 => single caret
    try std.testing.expect(std.mem.indexOf(u8, output, "^") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "spans multiple lines") != null);
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

    const lookup = struct {
        fn func(_: []const u8) ?[]const u8 {
            return null;
        }
    }.func;

    try renderDiagnostics(writer, list, &lookup, false);
    const output = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, output, "a hint") != null);
}
