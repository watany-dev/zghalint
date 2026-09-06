const std = @import("std");

pub const Span = struct {
    start_line: u32,
    start_col: u32,
    end_line: u32,
    end_col: u32,
    start_byte: usize,
    end_byte: usize,

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

    /// Structural equality, ignoring source positions and scalar style: `'a'`
    /// and `a` denote the same value, and mapping entries may appear in any
    /// order. Used to compare matrix values, which can be scalars, sequences,
    /// or mappings.
    pub fn eql(self: Node, other: Node) bool {
        return switch (self) {
            .scalar => |a| switch (other) {
                .scalar => |b| std.mem.eql(u8, a.value, b.value),
                else => false,
            },
            .sequence => |a| switch (other) {
                .sequence => |b| blk: {
                    if (a.items.len != b.items.len) break :blk false;
                    for (a.items, b.items) |x, y| {
                        if (!x.eql(y)) break :blk false;
                    }
                    break :blk true;
                },
                else => false,
            },
            .mapping => |a| switch (other) {
                .mapping => |b| blk: {
                    if (a.entries.len != b.entries.len) break :blk false;
                    // Checked both ways: with a duplicate key on one side, an
                    // entry-by-entry walk of that side alone can match a
                    // mapping that holds a key the other one lacks.
                    for (a.entries) |entry| {
                        const counterpart = b.get(entry.key.value) orelse break :blk false;
                        if (!entry.value.eql(counterpart)) break :blk false;
                    }
                    for (b.entries) |entry| {
                        const counterpart = a.get(entry.key.value) orelse break :blk false;
                        if (!entry.value.eql(counterpart)) break :blk false;
                    }
                    break :blk true;
                },
                else => false,
            },
            .null_value => other == .null_value,
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
    /// Byte range that can safely remove the entire entry from block-style YAML.
    /// Null when the parser cannot determine a stable removable range.
    full_span: ?Span = null,
};

pub const Mapping = struct {
    entries: []MappingEntry,
    span: Span,

    pub fn get(self: Mapping, key: []const u8) ?Node {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.key.value, key)) {
                return entry.value;
            }
        }
        return null;
    }

    /// Span of the key token for `key`, or null when the key is absent.
    /// Distinguishes "key present with an empty value" from "key missing",
    /// which `get` alone cannot express.
    pub fn getKeySpan(self: Mapping, key: []const u8) ?Span {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.key.value, key)) {
                return entry.key.span;
            }
        }
        return null;
    }

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

test "span point" {
    const span = Span.point(1, 1, 0);
    try std.testing.expectEqual(@as(u32, 1), span.start_line);
    try std.testing.expectEqual(@as(u32, 1), span.end_line);
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

test "mapping getKeySpan finds present keys and rejects missing ones" {
    const span = Span.point(3, 5, 40);
    var items = [_]Node{};
    var entries = [_]MappingEntry{
        .{
            .key = .{ .value = "branches", .style = .plain, .span = span },
            .value = .{ .sequence = .{ .items = &items, .span = span } },
            .span = span,
        },
    };
    const mapping = Mapping{ .entries = &entries, .span = span };

    const found = mapping.getKeySpan("branches") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 40), found.start_byte);
    try std.testing.expect(mapping.getKeySpan("branches-ignore") == null);
}

test "node eql ignores scalar style" {
    const span = Span.point(1, 1, 0);
    const plain = Node{ .scalar = .{ .value = "ubuntu-latest", .style = .plain, .span = span } };
    const quoted = Node{ .scalar = .{ .value = "ubuntu-latest", .style = .single_quoted, .span = Span.point(9, 3, 40) } };
    const other = Node{ .scalar = .{ .value = "macos-latest", .style = .plain, .span = span } };

    try std.testing.expect(plain.eql(quoted));
    try std.testing.expect(!plain.eql(other));
    try std.testing.expect(!plain.eql(.{ .null_value = span }));
}

test "node eql compares sequences elementwise" {
    const span = Span.point(1, 1, 0);
    var a = [_]Node{
        .{ .scalar = .{ .value = "1", .style = .plain, .span = span } },
        .{ .scalar = .{ .value = "2", .style = .plain, .span = span } },
    };
    var b = [_]Node{
        .{ .scalar = .{ .value = "2", .style = .plain, .span = span } },
        .{ .scalar = .{ .value = "1", .style = .plain, .span = span } },
    };
    var short = [_]Node{.{ .scalar = .{ .value = "1", .style = .plain, .span = span } }};

    const seq_a = Node{ .sequence = .{ .items = &a, .span = span } };
    try std.testing.expect(seq_a.eql(.{ .sequence = .{ .items = &a, .span = span } }));
    try std.testing.expect(!seq_a.eql(.{ .sequence = .{ .items = &b, .span = span } }));
    try std.testing.expect(!seq_a.eql(.{ .sequence = .{ .items = &short, .span = span } }));
}

test "node eql ignores mapping entry order" {
    const span = Span.point(1, 1, 0);
    const os_entry = MappingEntry{
        .key = .{ .value = "os", .style = .plain, .span = span },
        .value = .{ .scalar = .{ .value = "ubuntu-latest", .style = .plain, .span = span } },
        .span = span,
    };
    const node_entry = MappingEntry{
        .key = .{ .value = "node", .style = .plain, .span = span },
        .value = .{ .scalar = .{ .value = "18", .style = .plain, .span = span } },
        .span = span,
    };
    var forward = [_]MappingEntry{ os_entry, node_entry };
    var reversed = [_]MappingEntry{ node_entry, os_entry };
    var partial = [_]MappingEntry{os_entry};

    const map = Node{ .mapping = .{ .entries = &forward, .span = span } };
    try std.testing.expect(map.eql(.{ .mapping = .{ .entries = &reversed, .span = span } }));
    try std.testing.expect(!map.eql(.{ .mapping = .{ .entries = &partial, .span = span } }));
}

test "node eql rejects a mapping whose duplicate key hides a missing one" {
    const span = Span.point(1, 1, 0);
    const os_entry = MappingEntry{
        .key = .{ .value = "os", .style = .plain, .span = span },
        .value = .{ .scalar = .{ .value = "ubuntu-latest", .style = .plain, .span = span } },
        .span = span,
    };
    const node_entry = MappingEntry{
        .key = .{ .value = "node", .style = .plain, .span = span },
        .value = .{ .scalar = .{ .value = "18", .style = .plain, .span = span } },
        .span = span,
    };
    var repeated = [_]MappingEntry{ os_entry, os_entry };
    var distinct = [_]MappingEntry{ os_entry, node_entry };

    const a = Node{ .mapping = .{ .entries = &repeated, .span = span } };
    const b = Node{ .mapping = .{ .entries = &distinct, .span = span } };
    try std.testing.expect(!a.eql(b));
    try std.testing.expect(!b.eql(a));
}
