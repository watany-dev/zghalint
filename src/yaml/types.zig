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
    /// Nothing but blanks or a `#` comment follows the scalar on its line.
    /// Autofixes that append a trailing comment need this: inside a flow
    /// collection (`{uses: a@v4}`) the `#` would swallow the closing brace.
    /// Defaults to false so a synthesized scalar is never assumed safe.
    ends_line: bool = false,
    /// Text of the `#` comment that follows the scalar on its line, without
    /// the `#` and surrounding blanks. Null when the line carries no comment.
    /// SC003 reads the `# v1.2.3` convention next to a SHA-pinned `uses:`.
    line_comment: ?[]const u8 = null,
    /// Byte offset of `line_comment` in the source. SC003's bump rewrite
    /// replaces the first word of an existing pin comment in place.
    line_comment_start_byte: ?usize = null,
    /// A quoted scalar that never met its closing quote, so it ran to the end
    /// of the file. Its span has no boundary after it: text an autofix writes
    /// there becomes more quoted content instead of the key it was meant to be.
    unterminated: bool = false,
};

/// What one sequence item costs the source text, so an autofix can take it
/// out. `fix.builder.deleteSequenceItems` is the only intended consumer.
pub const ItemDelete = struct {
    /// The item plus the separator that follows it: its own lines including
    /// the trailing newline in a block sequence, and the comma up to the next
    /// item in a flow one. The last item of a flow sequence has no separator
    /// after it, so its range stops at its own text. Only the byte offsets are
    /// meaningful: a flow item's line and column describe the sequence's
    /// opening bracket, not the item.
    span: Span,
    /// Where the previous item's text ends — the start of the separator this
    /// item is preceded by. Deleting a run that reaches the end of a flow
    /// sequence starts here instead of at `span.start_byte`, so `[a, b, c]`
    /// losing `b` and `c` leaves `[a]` rather than `[a, ]`. Equal to
    /// `span.start_byte` for the first item and throughout a block sequence,
    /// where every item carries its own line.
    prev_end: usize,
};

pub const Sequence = struct {
    items: []Node,
    span: Span,
    /// Byte just past the closing `]` of a flow sequence, when the parser saw
    /// one. `span` covers the opening indicator alone, so a sequence written
    /// across lines needs this to say where its text really stops.
    close_byte: ?usize = null,
    /// Written with `[ ]` rather than as a block. A flow sequence with no
    /// `close_byte` was never closed, and its text stops nowhere.
    flow: bool = false,
    /// How to remove each item, parallel to `items`. Empty when the parser
    /// can offer no stable range — an alias expansion, whose text lives at
    /// the anchor rather than here.
    item_deletes: []const ItemDelete = &.{},
};

pub const MappingEntry = struct {
    key: Scalar,
    value: Node,
    span: Span,
    /// Byte range that can safely remove the entire entry from block-style YAML.
    /// Null when the parser cannot determine a stable removable range.
    full_span: ?Span = null,
    /// Byte just past the entry's text, measured while the token stream still
    /// said where it stopped. Recomputing it from the source alone cannot see
    /// a token that opens on the entry's line and closes below. Null for a
    /// flow entry, whose text is bounded by the closing brace instead.
    extent_end: ?usize = null,
    /// Lines the parser dropped sit under this entry's key, inside its extent.
    /// An insertion anchored at the value's own end lands above them, where a
    /// block key it opens adopts them (fuzz).
    has_indented_tail: bool = false,
};

pub const Mapping = struct {
    entries: []MappingEntry,
    span: Span,
    /// Byte just past the closing `}` of a flow mapping. See
    /// `Sequence.close_byte`.
    close_byte: ?usize = null,
    /// Written with `{ }` rather than as a block. See `Sequence.flow`.
    flow: bool = false,
    /// `<<` key tokens collected for the whole document. GitHub Actions
    /// rejects `<<`, so SYN026 reports these spans after the parser has
    /// already expanded them. Nested mappings leave this empty; only the
    /// document root holds the list.
    merge_key_spans: []const Span = &.{},

    pub fn get(self: Mapping, key: []const u8) ?Node {
        const entry = self.findEntry(key) orelse return null;
        return entry.value;
    }

    /// Span of the key token for `key`, or null when the key is absent.
    /// Distinguishes "key present with an empty value" from "key missing",
    /// which `get` alone cannot express.
    pub fn getKeySpan(self: Mapping, key: []const u8) ?Span {
        const entry = self.findEntry(key) orelse return null;
        return entry.key.span;
    }

    /// Span covering the whole `key: value` entry, or null when the key is
    /// absent or the entry has no span that removes it and nothing else.
    pub fn getFullSpan(self: Mapping, key: []const u8) ?Span {
        const entry = self.findEntry(key) orelse return null;
        return entry.full_span;
    }

    /// Whether `key`'s entry took lines the parser dropped under it. False
    /// when the key is absent.
    pub fn hasIndentedTail(self: Mapping, key: []const u8) bool {
        const entry = self.findEntry(key) orelse return false;
        return entry.has_indented_tail;
    }

    pub fn getScalar(self: Mapping, key: []const u8) ?[]const u8 {
        const node = self.get(key) orelse return null;
        return switch (node) {
            .scalar => |s| s.value,
            else => null,
        };
    }

    fn findEntry(self: Mapping, key: []const u8) ?MappingEntry {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.key.value, key)) return entry;
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
