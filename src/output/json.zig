const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const Diagnostic = diagnostics.Diagnostic;
const DiagnosticList = diagnostics.DiagnosticList;

/// Render diagnostics as a JSON object to the writer.
/// Output format:
/// {
///   "diagnostics": [ { "file", "line", "column", "end_line", "end_column",
///                       "severity", "rule_id", "message", "fix_hint" }, ... ],
///   "summary": { "errors": N, "warnings": N, "infos": N, "hints": N, "total": N,
///                "files_checked": N }
/// }
pub fn renderJson(writer: *std.Io.Writer, list: DiagnosticList, files_checked: usize) !void {
    var errors: usize = 0;
    var warnings: usize = 0;
    var infos: usize = 0;
    var hints: usize = 0;

    var js: std.json.Stringify = .{ .writer = writer };

    try js.beginObject();
    try js.objectField("diagnostics");
    try js.beginArray();
    for (list.items.items) |diag| {
        try writeDiagnosticJson(&js, diag);
        switch (diag.severity) {
            .@"error" => errors += 1,
            .warning => warnings += 1,
            .info => infos += 1,
            .hint => hints += 1,
        }
    }
    try js.endArray();

    try js.objectField("summary");
    try js.write(.{
        .errors = errors,
        .warnings = warnings,
        .infos = infos,
        .hints = hints,
        .total = list.len(),
        .files_checked = files_checked,
    });
    try js.endObject();
}

fn writeDiagnosticJson(js: *std.json.Stringify, diag: Diagnostic) !void {
    try js.write(.{
        .file = diag.file orelse "<unknown>",
        .line = diag.span.start_line,
        .column = diag.span.start_col,
        .end_line = diag.span.end_line,
        .end_column = diag.span.end_col,
        .severity = diag.severity,
        .rule_id = diag.rule_id,
        .message = diag.message,
        .fix_hint = diag.fix_hint,
    });
}

// ============================================================
// Tests
// ============================================================

const Span = @import("../yaml/types.zig").Span;

test "renderJson empty diagnostics" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try renderJson(&out.writer, list, 3);
    const output = out.written();

    // Valid JSON structure
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

    // Should have two entries separated by comma
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

    // Starts with { ends with }
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
