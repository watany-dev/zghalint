const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const Diagnostic = diagnostics.Diagnostic;
const DiagnosticList = diagnostics.DiagnosticList;

/// The object shape is fixed, so it is written from literals rather than
/// through `std.json.Stringify`, which re-derived the same layout from the
/// type for every diagnostic — 16% of the instructions on a 45k-diagnostic
/// run (#191).
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
///
/// A file path or message can carry bytes that are not valid UTF-8, and a
/// JSON string may only hold Unicode, so each such byte becomes U+FFFD —
/// without it the document would not parse.
fn writeJsonString(writer: *std.Io.Writer, s: []const u8) !void {
    try writer.writeByte('"');
    if (std.unicode.utf8ValidateSlice(s)) {
        try writeJsonChars(writer, s);
    } else {
        var i: usize = 0;
        while (i < s.len) {
            const len: usize = std.unicode.utf8ByteSequenceLength(s[i]) catch 0;
            if (len == 0 or i + len > s.len or !std.unicode.utf8ValidateSlice(s[i..][0..len])) {
                try writer.writeAll("\\ufffd");
                i += 1;
                continue;
            }
            try writeJsonChars(writer, s[i..][0..len]);
            i += len;
        }
    }
    try writer.writeByte('"');
}

fn writeJsonChars(writer: *std.Io.Writer, s: []const u8) !void {
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

test "renderJson replaces bytes that are not valid UTF-8" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    // A file name can hold any byte the filesystem accepts, but a JSON
    // string may only hold Unicode — the output must still parse.
    try list.append(.{
        .rule_id = "E1",
        .severity = .@"error",
        .message = "lone continuation \x9b and a truncated \xe3\x81",
        .file = "b\xffad.yml",
        .span = Span.point(1, 1, 0),
    });

    try renderJson(&out.writer, list, 1);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, out.written(), .{});
    defer parsed.deinit();

    const diag = parsed.value.object.get("diagnostics").?.array.items[0].object;
    try std.testing.expectEqualStrings("b\u{fffd}ad.yml", diag.get("file").?.string);
    try std.testing.expectEqualStrings(
        "lone continuation \u{fffd} and a truncated \u{fffd}\u{fffd}",
        diag.get("message").?.string,
    );
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
