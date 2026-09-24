const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const Diagnostic = diagnostics.Diagnostic;
const DiagnosticList = diagnostics.DiagnosticList;
const Severity = diagnostics.Severity;

/// GitHub Actions workflow commands (`::error file=,line=,col=::`).
///
/// `%` / CR / LF are percent-encoded in both properties and the message;
/// `:` / `,` are encoded only in properties so a path cannot split the command
/// (https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#setting-an-error-message).
pub fn renderGithub(writer: *std.Io.Writer, list: DiagnosticList) !void {
    for (list.items.items) |diag| {
        try writeCommand(writer, diag);
    }
}

fn writeCommand(writer: *std.Io.Writer, diag: Diagnostic) !void {
    try writer.print("::{s} ", .{commandName(diag.severity)});
    if (diag.file) |file| {
        try writer.writeAll("file=");
        try writeEscaped(writer, file, true);
        try writer.writeByte(',');
    }
    try writer.print("line={d},col={d}::", .{ diag.span.start_line, diag.span.start_col });
    try writeEscaped(writer, diag.message, false);
    try writer.writeAll(" [");
    try writeEscaped(writer, diag.rule_id, false);
    try writer.writeAll("]\n");
}

fn commandName(sev: Severity) []const u8 {
    return switch (sev) {
        .@"error" => "error",
        .warning => "warning",
        .info, .hint => "notice",
    };
}

fn writeEscaped(writer: *std.Io.Writer, s: []const u8, property: bool) !void {
    for (s) |c| {
        switch (c) {
            '%' => try writer.writeAll("%25"),
            '\r' => try writer.writeAll("%0D"),
            '\n' => try writer.writeAll("%0A"),
            ':' => if (property) try writer.writeAll("%3A") else try writer.writeByte(':'),
            ',' => if (property) try writer.writeAll("%2C") else try writer.writeByte(','),
            else => try writer.writeByte(c),
        }
    }
}

const Span = @import("../yaml/types.zig").Span;

test "renderGithub maps severity and includes file, line, col, rule id" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();
    try list.append(.{
        .rule_id = "SEC001",
        .severity = .warning,
        .message = "unpinned",
        .file = ".github/workflows/ci.yml",
        .span = Span.point(12, 7, 0),
    });
    try list.append(.{
        .rule_id = "SEC002",
        .severity = .@"error",
        .message = "inject",
        .file = "w.yml",
        .span = Span.point(3, 1, 0),
    });
    try list.append(.{
        .rule_id = "BP001",
        .severity = .info,
        .message = "timeout",
        .file = "w.yml",
        .span = Span.point(4, 2, 0),
    });
    try list.append(.{
        .rule_id = "HINT1",
        .severity = .hint,
        .message = "hint",
        .span = Span.point(1, 1, 0),
    });

    try renderGithub(&out.writer, list);
    try std.testing.expectEqualStrings(
        \\::warning file=.github/workflows/ci.yml,line=12,col=7::unpinned [SEC001]
        \\::error file=w.yml,line=3,col=1::inject [SEC002]
        \\::notice file=w.yml,line=4,col=2::timeout [BP001]
        \\::notice line=1,col=1::hint [HINT1]
        \\
    , out.written());
}

test "renderGithub percent-encodes workflow command metacharacters" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();
    try list.append(.{
        .rule_id = "SEC002",
        .severity = .@"error",
        .message = "a%b\nc,d:e",
        .file = "dir:name,x.yml",
        .span = Span.point(1, 1, 0),
    });

    try renderGithub(&out.writer, list);
    try std.testing.expectEqualStrings(
        "::error file=dir%3Aname%2Cx.yml,line=1,col=1::a%25b%0Ac,d:e [SEC002]\n",
        out.written(),
    );
}

test "renderGithub empty list writes nothing" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();
    try renderGithub(&out.writer, list);
    try std.testing.expectEqualStrings("", out.written());
}
