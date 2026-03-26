const std = @import("std");

/// Source location span for diagnostics
pub const Span = struct {
    start_line: u32,
    start_col: u32,
    end_line: u32,
    end_col: u32,
    start_byte: usize,
    end_byte: usize,

    pub fn merge(a: Span, b: Span) Span {
        return .{
            .start_line = @min(a.start_line, b.start_line),
            .start_col = if (a.start_line <= b.start_line) a.start_col else b.start_col,
            .end_line = @max(a.end_line, b.end_line),
            .end_col = if (a.end_line >= b.end_line) a.end_col else b.end_col,
            .start_byte = @min(a.start_byte, b.start_byte),
            .end_byte = @max(a.end_byte, b.end_byte),
        };
    }

    pub fn point(line: u32, col: u32, byte_offset: usize) Span {
        return .{
            .start_line = line,
            .start_col = col,
            .end_line = line,
            .end_col = col,
            .start_byte = byte_offset,
            .end_byte = byte_offset,
        };
    }
};

pub const ScalarStyle = enum {
    plain,
    single_quoted,
    double_quoted,
    literal,
    folded,
};

/// A YAML value node
pub const Node = union(enum) {
    scalar: Scalar,
    sequence: Sequence,
    mapping: Mapping,
    null_value: Span,

    pub fn getSpan(self: Node) Span {
        return switch (self) {
            .scalar => |s| s.span,
            .sequence => |s| s.span,
            .mapping => |m| m.span,
            .null_value => |s| s,
        };
    }
};

pub const Scalar = struct {
    value: []const u8,
    style: ScalarStyle,
    span: Span,
};

pub const Sequence = struct {
    items: []Node,
    span: Span,
};

pub const MappingEntry = struct {
    key: Scalar,
    value: Node,
    span: Span,
};

pub const Mapping = struct {
    entries: []MappingEntry,
    span: Span,

    /// Look up a value by key name
    pub fn get(self: Mapping, key: []const u8) ?Node {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.key.value, key)) {
                return entry.value;
            }
        }
        return null;
    }

    /// Get a scalar value by key name
    pub fn getScalar(self: Mapping, key: []const u8) ?[]const u8 {
        if (self.get(key)) |node| {
            switch (node) {
                .scalar => |s| return s.value,
                else => return null,
            }
        }
        return null;
    }
};

// ============================================================
// Tests
// ============================================================

test "span point" {
    const span = Span.point(1, 1, 0);
    try std.testing.expectEqual(@as(u32, 1), span.start_line);
    try std.testing.expectEqual(@as(u32, 1), span.end_line);
}

test "span merge" {
    const a = Span{ .start_line = 1, .start_col = 1, .end_line = 1, .end_col = 5, .start_byte = 0, .end_byte = 4 };
    const b = Span{ .start_line = 2, .start_col = 3, .end_line = 3, .end_col = 10, .start_byte = 10, .end_byte = 30 };
    const merged = Span.merge(a, b);
    try std.testing.expectEqual(@as(u32, 1), merged.start_line);
    try std.testing.expectEqual(@as(u32, 3), merged.end_line);
    try std.testing.expectEqual(@as(usize, 0), merged.start_byte);
    try std.testing.expectEqual(@as(usize, 30), merged.end_byte);
}

test "node getSpan scalar" {
    const span = Span.point(1, 1, 0);
    const node = Node{ .scalar = .{ .value = "test", .style = .plain, .span = span } };
    try std.testing.expectEqual(@as(u32, 1), node.getSpan().start_line);
}

test "mapping get" {
    const span = Span.point(1, 1, 0);
    var entries = [_]MappingEntry{
        .{
            .key = .{ .value = "name", .style = .plain, .span = span },
            .value = .{ .scalar = .{ .value = "CI", .style = .plain, .span = span } },
            .span = span,
        },
        .{
            .key = .{ .value = "on", .style = .plain, .span = span },
            .value = .{ .scalar = .{ .value = "push", .style = .plain, .span = span } },
            .span = span,
        },
    };
    const mapping = Mapping{ .entries = &entries, .span = span };
    const name = mapping.getScalar("name");
    try std.testing.expect(name != null);
    try std.testing.expectEqualStrings("CI", name.?);
    try std.testing.expect(mapping.get("nonexistent") == null);
}

test "mapping getScalar returns null for non-scalar" {
    const span = Span.point(1, 1, 0);
    var items = [_]Node{.{ .scalar = .{ .value = "a", .style = .plain, .span = span } }};
    var entries = [_]MappingEntry{
        .{
            .key = .{ .value = "list", .style = .plain, .span = span },
            .value = .{ .sequence = .{ .items = &items, .span = span } },
            .span = span,
        },
    };
    const mapping = Mapping{ .entries = &entries, .span = span };
    try std.testing.expect(mapping.getScalar("list") == null);
}
