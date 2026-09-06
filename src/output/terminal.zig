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

/// Attacker-influenced strings (file path, diagnostic message, source line)
/// are rewritten so a malicious workflow cannot inject colors, clear the
/// screen, or hide warnings in a CI log pipeline. ASCII control characters
/// and DEL become `\xHH`; C1 controls (U+0080–U+009F, e.g. the 8-bit CSI)
/// and Unicode bidi embedding/override/isolate controls become `\u{XXXX}`;
/// bytes that are not valid UTF-8 become `\xHH`. Tab is preserved for
/// source alignment, and every other code point is copied through intact.
fn writeSanitized(writer: anytype, s: []const u8) !void {
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c < 0x80) {
            if (c == '\t' or (c >= 0x20 and c != 0x7f)) {
                try writer.writeByte(c);
            } else {
                try writer.print("\\x{x:0>2}", .{c});
            }
            i += 1;
            continue;
        }

        const seq = decodeUtf8(s[i..]) orelse {
            try writer.print("\\x{x:0>2}", .{c});
            i += 1;
            continue;
        };
        if (isInvisibleControl(seq.cp)) {
            try writer.print("\\u{{{x:0>4}}}", .{seq.cp});
        } else {
            try writer.writeAll(s[i .. i + seq.len]);
        }
        i += seq.len;
    }
}

/// The well-formed UTF-8 sequence at the start of `s`, or null when the lead
/// byte is invalid, the sequence is truncated, or it does not decode
/// (overlong form, surrogate, out of range).
fn decodeUtf8(s: []const u8) ?struct { len: usize, cp: u21 } {
    const len = std.unicode.utf8ByteSequenceLength(s[0]) catch return null;
    if (len > s.len) return null;
    const cp = std.unicode.utf8Decode(s[0..len]) catch return null;
    return .{ .len = len, .cp = cp };
}

/// Code points that alter how surrounding text is displayed without being
/// visible themselves: C1 controls and the bidirectional formatting
/// characters used in "Trojan Source" style attacks.
fn isInvisibleControl(cp: u21) bool {
    return (cp >= 0x80 and cp <= 0x9f) or
        (cp >= 0x202a and cp <= 0x202e) or
        (cp >= 0x2066 and cp <= 0x2069);
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

test "writeSanitized passes multi-byte UTF-8 through unchanged" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    // Japanese text contains continuation bytes in 0x80–0x9F; they must never
    // be byte-escaped. Tab is kept as-is.
    const input = "ワークフロー\tcafé 🚀";
    try writeSanitized(writer, input);
    try std.testing.expectEqualStrings(input, buf.items);
}

test "writeSanitized escapes C1 and bidi controls but not invalid-looking text" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    // U+009B is the 8-bit CSI; U+202E is RIGHT-TO-LEFT OVERRIDE; U+2066 is
    // LEFT-TO-RIGHT ISOLATE.
    try writeSanitized(writer, "a\u{9b}b\u{202e}c\u{2066}d");
    try std.testing.expectEqualStrings("a\\u{009b}b\\u{202e}c\\u{2066}d", buf.items);
}

test "writeSanitized escapes bytes that are not valid UTF-8" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    // Lone continuation byte, truncated 3-byte sequence at end of input, and
    // an overlong/invalid lead byte.
    try writeSanitized(writer, "x\x9by\xe3\x81");
    try std.testing.expectEqualStrings("x\\x9by\\xe3\\x81", buf.items);

    buf.clearRetainingCapacity();
    try writeSanitized(writer, "\xffz\x7f");
    try std.testing.expectEqualStrings("\\xffz\\x7f", buf.items);
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
