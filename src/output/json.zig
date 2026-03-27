const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const Diagnostic = diagnostics.Diagnostic;
const DiagnosticList = diagnostics.DiagnosticList;
const Severity = diagnostics.Severity;

/// Render diagnostics as a JSON object to the writer.
/// Output format:
/// {
///   "diagnostics": [ { "file", "line", "column", "end_line", "end_column",
///                       "severity", "rule_id", "message", "fix_hint" }, ... ],
///   "summary": { "errors": N, "warnings": N, "infos": N, "hints": N, "total": N,
///                "files_checked": N }
/// }
pub fn renderJson(writer: anytype, list: DiagnosticList, files_checked: usize) !void {
    var errors: usize = 0;
    var warnings: usize = 0;
    var infos: usize = 0;
    var hints: usize = 0;

    try writer.writeAll("{\"diagnostics\":[");

    for (list.items.items, 0..) |diag, i| {
        if (i > 0) try writer.writeAll(",");
        try writeDiagnosticJson(writer, diag);
        switch (diag.severity) {
            .@"error" => errors += 1,
            .warning => warnings += 1,
            .info => infos += 1,
            .hint => hints += 1,
        }
    }

    try writer.writeAll("],\"summary\":{");
    try writer.print("\"errors\":{d},\"warnings\":{d},\"infos\":{d},\"hints\":{d},\"total\":{d},\"files_checked\":{d}", .{
        errors,
        warnings,
        infos,
        hints,
        list.len(),
        files_checked,
    });
    try writer.writeAll("}}");
}

fn writeDiagnosticJson(writer: anytype, diag: Diagnostic) !void {
    try writer.writeAll("{\"file\":");
    try writeJsonString(writer, diag.file orelse "<unknown>");

    try writer.print(",\"line\":{d},\"column\":{d},\"end_line\":{d},\"end_column\":{d}", .{
        diag.span.start_line,
        diag.span.start_col,
        diag.span.end_line,
        diag.span.end_col,
    });

    try writer.writeAll(",\"severity\":");
    try writeJsonString(writer, diag.severity.toString());

    try writer.writeAll(",\"rule_id\":");
    try writeJsonString(writer, diag.rule_id);

    try writer.writeAll(",\"message\":");
    try writeJsonString(writer, diag.message);

    try writer.writeAll(",\"fix_hint\":");
    if (diag.fix_hint) |hint| {
        try writeJsonString(writer, hint);
    } else {
        try writer.writeAll("null");
    }

    try writer.writeAll("}");
}

/// Write a JSON-escaped string (with surrounding quotes).
fn writeJsonString(writer: anytype, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
    try writer.writeByte('"');
}

// ============================================================
// Tests
// ============================================================

const Span = @import("../yaml/types.zig").Span;

test "renderJson empty diagnostics" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try renderJson(buf.writer(std.testing.allocator), list, 3);
    const output = buf.items;

    // Valid JSON structure
    try std.testing.expect(std.mem.indexOf(u8, output, "\"diagnostics\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"total\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"files_checked\":3") != null);
}

test "renderJson single diagnostic" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    list.append(.{
        .rule_id = "SEC002",
        .severity = .@"error",
        .message = "Potential script injection",
        .file = ".github/workflows/ci.yml",
        .span = .{
            .start_line = 15,
            .start_col = 9,
            .end_line = 15,
            .end_col = 45,
            .start_byte = 200,
            .end_byte = 236,
        },
        .fix_hint = "Use an environment variable instead",
    });

    try renderJson(buf.writer(std.testing.allocator), list, 1);
    const output = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, output, "\"rule_id\":\"SEC002\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"severity\":\"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"line\":15") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"column\":9") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"fix_hint\":\"Use an environment variable instead\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"errors\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"total\":1") != null);
}

test "renderJson multiple diagnostics" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    list.append(.{ .rule_id = "E1", .severity = .@"error", .message = "err", .file = "a.yml", .span = Span.point(1, 1, 0) });
    list.append(.{ .rule_id = "W1", .severity = .warning, .message = "warn", .file = "a.yml", .span = Span.point(2, 1, 0), .fix_hint = "fix it" });

    try renderJson(buf.writer(std.testing.allocator), list, 1);
    const output = buf.items;

    // Should have two entries separated by comma
    try std.testing.expect(std.mem.indexOf(u8, output, "\"errors\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"warnings\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"total\":2") != null);
}

test "renderJson null fix_hint" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    list.append(.{ .rule_id = "T1", .severity = .info, .message = "test", .span = Span.point(1, 1, 0) });

    try renderJson(buf.writer(std.testing.allocator), list, 0);
    const output = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, output, "\"fix_hint\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"file\":\"<unknown>\"") != null);
}

test "writeJsonString escapes special chars" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    try writeJsonString(buf.writer(std.testing.allocator), "hello \"world\"\nnew\\line");
    try std.testing.expectEqualStrings("\"hello \\\"world\\\"\\nnew\\\\line\"", buf.items);
}

test "renderJson is valid JSON structure" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    list.append(.{ .rule_id = "R1", .severity = .@"error", .message = "msg", .span = Span.point(1, 1, 0) });

    try renderJson(buf.writer(std.testing.allocator), list, 1);
    const output = buf.items;

    // Starts with { ends with }
    try std.testing.expect(output[0] == '{');
    try std.testing.expect(output[output.len - 1] == '}');
}
