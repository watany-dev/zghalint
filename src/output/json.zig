const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const Diagnostic = diagnostics.Diagnostic;
const DiagnosticList = diagnostics.DiagnosticList;

/// The object shape is fixed, so every key is a literal and each diagnostic
/// costs one `print` plus one escape scan per string. `std.json.Stringify`
/// would re-derive the same layout from the type on every diagnostic; on a
/// 45k-diagnostic run that generic path was 16% of the instructions.
pub fn renderJson(writer: *std.Io.Writer, list: DiagnosticList, files_checked: usize) !void {
    const counts = list.countBySeverity();

    try writer.writeAll("{\"diagnostics\":[");
    for (list.items.items, 0..) |diag, i| {
        if (i > 0) try writer.writeByte(',');
        try writeDiagnosticJson(writer, diag);
    }
    try writer.print(
        "],\"summary\":{{\"errors\":{d},\"warnings\":{d},\"infos\":{d},\"hints\":{d}," ++
            "\"total\":{d},\"files_checked\":{d}}}}}",
        .{ counts.@"error", counts.warning, counts.info, counts.hint, list.len(), files_checked },
    );
}

fn writeDiagnosticJson(writer: *std.Io.Writer, diag: Diagnostic) !void {
    try writer.writeAll("{\"file\":");
    try writeJsonString(writer, diag.file orelse "<unknown>");
    try writer.print(
        ",\"line\":{d},\"column\":{d},\"end_line\":{d},\"end_column\":{d},\"severity\":\"{s}\",\"rule_id\":",
        .{
            diag.span.start_line,
            diag.span.start_col,
            diag.span.end_line,
            diag.span.end_col,
            @tagName(diag.severity),
        },
    );
    try writeJsonString(writer, diag.rule_id);
    try writer.writeAll(",\"message\":");
    try writeJsonString(writer, diag.message);
    try writer.writeAll(",\"fix_hint\":");
    if (diag.fix_hint) |hint| {
        try writeJsonString(writer, hint);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeByte('}');
}

/// Same encoding as `std.json.Stringify` with default options: only `"`,
/// `\` and C0 controls are escaped, and non-ASCII bytes pass through as-is.
/// Runs between escapes are emitted with a single `writeAll`, so a string
/// that needs no escaping (the common case) costs one scan and one copy.
fn writeJsonString(writer: *std.Io.Writer, s: []const u8) !void {
    try writer.writeByte('"');
    var run_start: usize = 0;
    for (s, 0..) |c, i| {
        const escape = switch (c) {
            '"' => "\\\"",
            '\\' => "\\\\",
            0x08 => "\\b",
            0x0c => "\\f",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            0x00...0x07, 0x0b, 0x0e...0x1f => "",
            else => continue,
        };
        try writer.writeAll(s[run_start..i]);
        if (escape.len == 0) {
            try writer.print("\\u{x:0>4}", .{c});
        } else {
            try writer.writeAll(escape);
        }
        run_start = i + 1;
    }
    try writer.writeAll(s[run_start..]);
    try writer.writeByte('"');
}

const Span = @import("../yaml/types.zig").Span;

test "renderJson empty diagnostics" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try renderJson(&out.writer, list, 3);
    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "\"diagnostics\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"total\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"files_checked\":3") != null);
}

test "renderJson single diagnostic" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{
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

    try renderJson(&out.writer, list, 1);
    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "\"rule_id\":\"SEC002\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"severity\":\"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"line\":15") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"column\":9") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"fix_hint\":\"Use an environment variable instead\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"errors\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"total\":1") != null);
}

test "renderJson multiple diagnostics" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{ .rule_id = "E1", .severity = .@"error", .message = "err", .file = "a.yml", .span = Span.point(1, 1, 0) });
    try list.append(.{ .rule_id = "W1", .severity = .warning, .message = "warn", .file = "a.yml", .span = Span.point(2, 1, 0), .fix_hint = "fix it" });

    try renderJson(&out.writer, list, 1);
    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "\"errors\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"warnings\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"total\":2") != null);
}

test "renderJson null fix_hint" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{ .rule_id = "T1", .severity = .info, .message = "test", .span = Span.point(1, 1, 0) });

    try renderJson(&out.writer, list, 0);
    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "\"fix_hint\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"file\":\"<unknown>\"") != null);
}

test "renderJson is valid JSON structure" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{ .rule_id = "R1", .severity = .@"error", .message = "msg", .span = Span.point(1, 1, 0) });

    try renderJson(&out.writer, list, 1);
    const output = out.written();

    try std.testing.expect(output[0] == '{');
    try std.testing.expect(output[output.len - 1] == '}');
}

test "renderJson with hint severity" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{ .rule_id = "H1", .severity = .hint, .message = "hint msg", .span = Span.point(1, 1, 0) });

    try renderJson(&out.writer, list, 1);
    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "\"hints\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"severity\":\"hint\"") != null);
}

test "renderJson escapes quotes, backslashes and control characters" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{
        .rule_id = "E1",
        .severity = .@"error",
        .message = "say \"hi\"\\ then\nstop\x01",
        .file = "a\tb.yml",
        .span = Span.point(1, 1, 0),
    });

    try renderJson(&out.writer, list, 1);
    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "\"file\":\"a\\tb.yml\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"message\":\"say \\\"hi\\\"\\\\ then\\nstop\\u0001\"") != null);
}

test "renderJson passes multi-byte UTF-8 through unescaped" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{
        .rule_id = "E1",
        .severity = .@"error",
        .message = "ワークフロー 🚀",
        .span = Span.point(1, 1, 0),
    });

    try renderJson(&out.writer, list, 1);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"message\":\"ワークフロー 🚀\"") != null);
}

test "renderJson output parses as JSON" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{ .rule_id = "E1", .severity = .@"error", .message = "a \"quoted\" msg", .file = "a.yml", .span = Span.point(1, 2, 0) });
    try list.append(.{ .rule_id = "W1", .severity = .warning, .message = "b", .file = "b.yml", .span = Span.point(3, 4, 0), .fix_hint = "do\nit" });

    try renderJson(&out.writer, list, 2);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, out.written(), .{});
    defer parsed.deinit();

    const diags = parsed.value.object.get("diagnostics").?.array;
    try std.testing.expectEqual(@as(usize, 2), diags.items.len);
    try std.testing.expectEqualStrings("a \"quoted\" msg", diags.items[0].object.get("message").?.string);
    try std.testing.expectEqual(@as(i64, 2), diags.items[0].object.get("column").?.integer);
    try std.testing.expectEqual(std.json.Value.null, diags.items[0].object.get("fix_hint").?);
    try std.testing.expectEqualStrings("do\nit", diags.items[1].object.get("fix_hint").?.string);
    try std.testing.expectEqualStrings("warning", diags.items[1].object.get("severity").?.string);
    try std.testing.expectEqual(@as(i64, 2), parsed.value.object.get("summary").?.object.get("files_checked").?.integer);
}

test "renderJson with info severity" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{ .rule_id = "I1", .severity = .info, .message = "info msg", .span = Span.point(1, 1, 0) });

    try renderJson(&out.writer, list, 1);
    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "\"infos\":1") != null);
}
