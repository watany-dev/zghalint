const std = @import("std");

/// Return the action base name (part before `@`) from a raw action ref.
/// Example: "actions/checkout@v4" -> "actions/checkout".
pub fn actionBaseName(raw: []const u8) []const u8 {
    return if (std.mem.indexOf(u8, raw, "@")) |pos| raw[0..pos] else raw;
}

/// Write a JSON-escaped string (with surrounding quotes) to the writer.
/// Control characters below 0x20 are emitted as `\uXXXX` escapes.
pub fn writeJsonString(writer: anytype, s: []const u8) !void {
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

test "actionBaseName strips version suffix" {
    try std.testing.expectEqualStrings("actions/checkout", actionBaseName("actions/checkout@v4"));
    try std.testing.expectEqualStrings("actions/checkout", actionBaseName("actions/checkout@abc123"));
    try std.testing.expectEqualStrings("actions/checkout", actionBaseName("actions/checkout"));
    try std.testing.expectEqualStrings("", actionBaseName(""));
    try std.testing.expectEqualStrings("", actionBaseName("@v1"));
}

test "writeJsonString escapes special characters" {
    const allocator = std.testing.allocator;

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);

    try writeJsonString(buf.writer(allocator), "hello");
    try std.testing.expectEqualStrings("\"hello\"", buf.items);

    buf.clearRetainingCapacity();
    try writeJsonString(buf.writer(allocator), "a\"b\\c");
    try std.testing.expectEqualStrings("\"a\\\"b\\\\c\"", buf.items);

    buf.clearRetainingCapacity();
    try writeJsonString(buf.writer(allocator), "line1\nline2\tend\r");
    try std.testing.expectEqualStrings("\"line1\\nline2\\tend\\r\"", buf.items);

    buf.clearRetainingCapacity();
    try writeJsonString(buf.writer(allocator), "\x01");
    try std.testing.expectEqualStrings("\"\\u0001\"", buf.items);
}
