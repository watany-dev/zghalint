const std = @import("std");
const Tokenizer = @import("tokenizer.zig").Tokenizer;
const TokenKind = @import("tokenizer.zig").TokenKind;
const Token = @import("tokenizer.zig").Token;
const types = @import("types.zig");
const Node = types.Node;
const Scalar = types.Scalar;
const Sequence = types.Sequence;
const Mapping = types.Mapping;
const MappingEntry = types.MappingEntry;
const Span = types.Span;
const ScalarStyle = types.ScalarStyle;

pub const ParseError = error{
    UnexpectedToken,
    OutOfMemory,
    MaxDepthExceeded,
};

/// Hard cap on nested mappings/sequences/flow containers. A well-formed
/// Actions workflow nests ~6 levels deep; 256 leaves ample headroom while
/// preventing an attacker-controlled YAML from recursing the parser into
/// a stack overflow (SIGSEGV) during CI runs.
pub const max_parse_depth: u16 = 256;

pub const Parser = struct {
    allocator: std.mem.Allocator,
    tokenizer: Tokenizer,
    current: Token,
    source: []const u8,
    depth: u16,

    pub fn init(allocator: std.mem.Allocator, source: []const u8) Parser {
        var tokenizer = Tokenizer.init(source);
        const first = tokenizer.next();
        _ = first;
        const current = tokenizer.next();
        return .{
            .allocator = allocator,
            .tokenizer = tokenizer,
            .current = current,
            .source = source,
            .depth = 0,
        };
    }

    pub fn parse(self: *Parser) ParseError!Node {
        if (self.current.kind == .document_start) {
            self.advance();
            self.skipNewlines();
        }

        return self.parseNode(0);
    }

    fn parseNode(self: *Parser, min_indent: u32) ParseError!Node {
        if (self.depth >= max_parse_depth) return error.MaxDepthExceeded;
        self.depth += 1;
        defer self.depth -= 1;

        self.skipNewlines();

        if (self.current.kind == .eof) {
            return Node{ .null_value = self.spanFromToken(self.current) };
        }

        if (self.current.kind == .sequence_entry) {
            return self.parseBlockSequence();
        }

        if (self.current.kind == .flow_mapping_start) {
            return self.parseFlowMapping();
        }

        if (self.current.kind == .flow_sequence_start) {
            return self.parseFlowSequence();
        }

        if (self.current.kind == .scalar) {
            const scalar_token = self.current;
            self.advance();

            if (self.current.kind == .mapping_value) {
                return self.parseBlockMapping(scalar_token, min_indent);
            }

            return Node{ .scalar = self.scalarFromToken(scalar_token) };
        }

        if (self.current.kind == .mapping_value) {
            self.advance();
            return self.parseNode(min_indent);
        }

        if (self.current.kind == .comment) {
            self.advance();
            return self.parseNode(min_indent);
        }

        return Node{ .null_value = self.spanFromToken(self.current) };
    }

    fn parseBlockMapping(self: *Parser, first_key_token: Token, min_indent: u32) ParseError!Node {
        var entries = std.ArrayList(MappingEntry){};

        const key_indent = first_key_token.column;
        var current_key = first_key_token;

        while (true) {
            if (self.current.kind != .mapping_value) break;
            self.advance();

            const value = if (self.current.kind == .newline or self.current.kind == .eof) blk: {
                self.skipNewlines();
                if (self.current.kind != .eof and self.current.column > key_indent) {
                    break :blk try self.parseNode(key_indent + 1);
                } else {
                    break :blk Node{ .null_value = self.spanFromToken(self.current) };
                }
            } else try self.parseNode(key_indent + 1);

            const key_scalar = self.scalarFromToken(current_key);
            try entries.append(self.allocator, .{
                .key = key_scalar,
                .value = value,
                .span = key_scalar.span,
                .full_span = self.blockEntryFullSpan(key_scalar, value),
            });

            self.skipNewlines();
            if (self.current.kind == .comment) {
                self.advance();
                self.skipNewlines();
            }

            if (self.current.kind == .eof) break;
            if (self.current.column < key_indent) break;
            if (self.current.column > key_indent) break;
            if (self.current.column < min_indent) break;

            if (self.current.kind == .scalar) {
                current_key = self.current;
                self.advance();
                continue;
            }

            break;
        }

        const owned_entries = entries.toOwnedSlice(self.allocator) catch return ParseError.OutOfMemory;
        const span = if (owned_entries.len > 0)
            Span{
                .start_line = owned_entries[0].key.span.start_line,
                .start_col = owned_entries[0].key.span.start_col,
                .end_line = owned_entries[owned_entries.len - 1].span.end_line,
                .end_col = owned_entries[owned_entries.len - 1].span.end_col,
                .start_byte = owned_entries[0].key.span.start_byte,
                .end_byte = owned_entries[owned_entries.len - 1].span.end_byte,
            }
        else
            self.spanFromToken(first_key_token);

        return Node{ .mapping = .{ .entries = owned_entries, .span = span } };
    }

    fn parseBlockSequence(self: *Parser) ParseError!Node {
        var items = std.ArrayList(Node){};
        const seq_indent = self.current.column;

        while (self.current.kind == .sequence_entry and self.current.column == seq_indent) {
            self.advance();

            if (self.current.kind == .newline or self.current.kind == .eof) {
                self.skipNewlines();
                if (self.current.kind != .eof and self.current.column > seq_indent) {
                    try items.append(self.allocator, try self.parseNode(seq_indent + 1));
                } else {
                    try items.append(self.allocator, Node{ .null_value = self.spanFromToken(self.current) });
                }
            } else {
                try items.append(self.allocator, try self.parseNode(seq_indent + 1));
            }

            self.skipNewlines();
            if (self.current.kind == .comment) {
                self.advance();
                self.skipNewlines();
            }
        }

        const owned_items = items.toOwnedSlice(self.allocator) catch return ParseError.OutOfMemory;
        const span = Span.point(
            if (owned_items.len > 0) owned_items[0].getSpan().start_line else self.current.line,
            seq_indent,
            if (owned_items.len > 0) owned_items[0].getSpan().start_byte else self.current.start,
        );

        return Node{ .sequence = .{ .items = owned_items, .span = span } };
    }

    fn parseFlowMapping(self: *Parser) ParseError!Node {
        var entries = std.ArrayList(MappingEntry){};
        const start_span = self.spanFromToken(self.current);
        self.advance();

        while (self.current.kind != .flow_mapping_end and self.current.kind != .eof) {
            self.skipNewlinesAndComments();
            if (self.current.kind == .flow_mapping_end) break;

            if (self.current.kind != .scalar) break;
            const key_token = self.current;
            self.advance();

            if (self.current.kind != .mapping_value) break;
            self.advance();

            const value = try self.parseFlowValue();

            const key_scalar = self.scalarFromToken(key_token);
            try entries.append(self.allocator, .{
                .key = key_scalar,
                .value = value,
                .span = key_scalar.span,
            });

            if (self.current.kind == .flow_entry) {
                self.advance();
            }
        }

        if (self.current.kind == .flow_mapping_end) {
            self.advance();
        }

        const owned_entries = entries.toOwnedSlice(self.allocator) catch return ParseError.OutOfMemory;
        return Node{ .mapping = .{ .entries = owned_entries, .span = start_span } };
    }

    fn parseFlowSequence(self: *Parser) ParseError!Node {
        var items = std.ArrayList(Node){};
        const start_span = self.spanFromToken(self.current);
        self.advance();

        while (self.current.kind != .flow_sequence_end and self.current.kind != .eof) {
            self.skipNewlinesAndComments();
            if (self.current.kind == .flow_sequence_end) break;

            const before = self.current.start;
            try items.append(self.allocator, try self.parseFlowValue());

            if (self.current.kind == .flow_entry) {
                self.advance();
                continue;
            }
            // `parseFlowValue` returns a null node *without* consuming a token it
            // does not understand — `[` running into block content such as
            // `[\nname: CI` leaves the `:` in place. Stop instead of spinning on
            // it forever.
            if (self.current.start == before) break;
        }

        if (self.current.kind == .flow_sequence_end) {
            self.advance();
        }

        const owned_items = items.toOwnedSlice(self.allocator) catch return ParseError.OutOfMemory;
        return Node{ .sequence = .{ .items = owned_items, .span = start_span } };
    }

    /// Flow collections recurse through this without passing `parseNode`, so
    /// the depth guard is applied here as well.
    fn parseFlowValue(self: *Parser) ParseError!Node {
        if (self.depth >= max_parse_depth) return error.MaxDepthExceeded;
        self.depth += 1;
        defer self.depth -= 1;

        self.skipNewlinesAndComments();

        if (self.current.kind == .flow_mapping_start) {
            return self.parseFlowMapping();
        }
        if (self.current.kind == .flow_sequence_start) {
            return self.parseFlowSequence();
        }
        if (self.current.kind == .scalar) {
            const token = self.current;
            self.advance();
            return Node{ .scalar = self.scalarFromToken(token) };
        }

        return Node{ .null_value = self.spanFromToken(self.current) };
    }

    fn advance(self: *Parser) void {
        self.current = self.tokenizer.next();
    }

    fn skipNewlines(self: *Parser) void {
        while (self.current.kind == .newline) {
            self.advance();
        }
    }

    fn skipNewlinesAndComments(self: *Parser) void {
        while (self.current.kind == .newline or self.current.kind == .comment) {
            self.advance();
        }
    }

    fn spanFromToken(self: *Parser, token: Token) Span {
        _ = self;
        return .{
            .start_line = token.line,
            .start_col = token.column,
            .end_line = token.line,
            .end_col = token.column + @as(u32, @intCast(token.end - token.start)),
            .start_byte = token.start,
            .end_byte = token.end,
        };
    }

    fn scalarFromToken(self: *Parser, token: Token) Scalar {
        const raw = token.slice(self.source);
        if (raw.len >= 2 and (raw[0] == '\'' or raw[0] == '"')) {
            return .{
                .value = raw[1 .. raw.len - 1],
                .style = if (raw[0] == '\'') .single_quoted else .double_quoted,
                .span = self.spanFromToken(token),
            };
        }
        if (raw.len >= 1 and (raw[0] == '|' or raw[0] == '>')) {
            const style: ScalarStyle = if (raw[0] == '|') .literal else .folded;
            const content_start = if (std.mem.indexOfScalar(u8, raw, '\n')) |nl| nl + 1 else 0;
            return .{
                .value = if (content_start < raw.len) raw[content_start..] else "",
                .style = style,
                .span = self.spanFromToken(token),
            };
        }
        return .{
            .value = raw,
            .style = .plain,
            .span = self.spanFromToken(token),
        };
    }

    fn blockEntryFullSpan(self: *Parser, key: Scalar, value: Node) ?Span {
        const line_start = self.lineStartByte(key.span.start_byte);

        // A scalar value sits on the key's own line, so its end line / column
        // follow the value itself. Every other shape keeps the key line as the
        // end anchor and differs only in where the entry's bytes stop.
        if (value == .scalar) {
            const scalar = value.scalar;
            // A block scalar's span already ends at the start of the line that
            // closes it (or at EOF), trailing newline included. Scanning on to
            // the next '\n' from there would swallow the next sibling key line.
            const is_block = scalar.style == .literal or scalar.style == .folded;
            var end_byte = scalar.span.end_byte;
            if (!is_block) {
                while (end_byte < self.source.len and self.source[end_byte] != '\n') {
                    end_byte += 1;
                }
                if (end_byte < self.source.len) end_byte += 1;
            }

            const newlines: u32 = @intCast(std.mem.count(u8, self.source[line_start..end_byte], "\n"));
            return .{
                .start_line = key.span.start_line,
                .start_col = 1,
                .end_line = key.span.start_line + newlines,
                .end_col = @as(u32, @intCast(end_byte - self.lineStartByte(end_byte) + 1)),
                .start_byte = line_start,
                .end_byte = end_byte,
            };
        }

        // An empty or null value has no body: end at the key's own line. The
        // value's span may point at a far-away token (the next sibling), so we
        // anchor on `key.span.end_byte` instead.
        const key_line_end = self.scanLineEndInclusive(key.span.end_byte);
        const end_byte = switch (value) {
            .scalar => unreachable,
            .null_value => key_line_end,
            .mapping => |m| if (m.entries.len == 0) key_line_end else blk: {
                const last = m.entries[m.entries.len - 1];
                const last_full = self.blockEntryFullSpan(last.key, last.value) orelse return null;
                break :blk last_full.end_byte;
            },
            .sequence => |seq| if (seq.items.len == 0)
                key_line_end
            else
                self.scanLineEndInclusive(seq.items[seq.items.len - 1].getSpan().end_byte),
        };

        return keyLineSpan(key, line_start, end_byte);
    }

    /// The line / column pair describes the key line only; the byte range is
    /// what callers rewrite.
    fn keyLineSpan(key: Scalar, line_start: usize, end_byte: usize) Span {
        return .{
            .start_line = key.span.start_line,
            .start_col = 1,
            .end_line = key.span.start_line,
            .end_col = key.span.start_col,
            .start_byte = line_start,
            .end_byte = end_byte,
        };
    }

    fn scanLineEndInclusive(self: *Parser, start: usize) usize {
        var end = start;
        while (end < self.source.len and self.source[end] != '\n') end += 1;
        if (end < self.source.len and self.source[end] == '\n') end += 1;
        return end;
    }

    fn lineStartByte(self: *Parser, byte_offset: usize) usize {
        var start = byte_offset;
        while (start > 0 and self.source[start - 1] != '\n') {
            start -= 1;
        }
        return start;
    }
};

test "parse simple mapping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "name: CI");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            try std.testing.expectEqual(@as(usize, 1), m.entries.len);
            try std.testing.expectEqualStrings("name", m.entries[0].key.value);
            switch (m.entries[0].value) {
                .scalar => |s| try std.testing.expectEqualStrings("CI", s.value),
                else => return error.UnexpectedToken,
            }
        },
        else => return error.UnexpectedToken,
    }
}

test "parse multi-key mapping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "name: CI\non: push");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            try std.testing.expectEqual(@as(usize, 2), m.entries.len);
            try std.testing.expectEqualStrings("name", m.entries[0].key.value);
            try std.testing.expectEqualStrings("on", m.entries[1].key.value);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse sequence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "- item1\n- item2\n- item3");
    const node = try parser.parse();
    switch (node) {
        .sequence => |s| {
            try std.testing.expectEqual(@as(usize, 3), s.items.len);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse nested mapping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(),
        \\name: CI
        \\on:
        \\  push:
        \\    branches:
        \\      - main
    );
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            try std.testing.expectEqual(@as(usize, 2), m.entries.len);
            try std.testing.expectEqualStrings("name", m.entries[0].key.value);
            try std.testing.expectEqualStrings("on", m.entries[1].key.value);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse flow mapping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "{name: CI, on: push}");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            try std.testing.expectEqual(@as(usize, 2), m.entries.len);
            try std.testing.expectEqualStrings("name", m.entries[0].key.value);
            try std.testing.expectEqualStrings("on", m.entries[1].key.value);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse flow sequence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "[main, dev, release]");
    const node = try parser.parse();
    switch (node) {
        .sequence => |s| {
            try std.testing.expectEqual(@as(usize, 3), s.items.len);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse document start marker" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "---\nname: CI");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            try std.testing.expectEqual(@as(usize, 1), m.entries.len);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse empty input" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "");
    const node = try parser.parse();
    switch (node) {
        .null_value => {},
        else => return error.UnexpectedToken,
    }
}

test "parse quoted strings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "name: 'hello world'");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            try std.testing.expectEqual(@as(usize, 1), m.entries.len);
            switch (m.entries[0].value) {
                .scalar => |s| {
                    try std.testing.expectEqualStrings("hello world", s.value);
                    try std.testing.expectEqual(ScalarStyle.single_quoted, s.style);
                },
                else => return error.UnexpectedToken,
            }
        },
        else => return error.UnexpectedToken,
    }
}

test "parse mapping with get helper" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "name: CI\non: push");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            const name = m.getScalar("name");
            try std.testing.expect(name != null);
            try std.testing.expectEqualStrings("CI", name.?);
            try std.testing.expect(m.get("nonexistent") == null);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse rejects input nested past max_parse_depth" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const levels = @as(usize, max_parse_depth) + 16;
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    for (0..levels) |i| {
        try buf.appendNTimes(std.testing.allocator, ' ', i);
        try buf.appendSlice(std.testing.allocator, "k:\n");
    }

    var parser = Parser.init(arena.allocator(), buf.items);
    try std.testing.expectError(error.MaxDepthExceeded, parser.parse());
}

test "parse rejects flow collections nested past max_parse_depth" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const levels = @as(usize, max_parse_depth) + 16;
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    try buf.appendSlice(std.testing.allocator, "a: ");
    try buf.appendNTimes(std.testing.allocator, '[', levels);
    try buf.appendNTimes(std.testing.allocator, ']', levels);

    var parser = Parser.init(arena.allocator(), buf.items);
    try std.testing.expectError(error.MaxDepthExceeded, parser.parse());

    buf.clearRetainingCapacity();
    try buf.appendSlice(std.testing.allocator, "a: ");
    for (0..levels) |_| try buf.appendSlice(std.testing.allocator, "{k: ");
    try buf.appendNTimes(std.testing.allocator, '}', levels);

    var parser2 = Parser.init(arena.allocator(), buf.items);
    try std.testing.expectError(error.MaxDepthExceeded, parser2.parse());
}

test "parse accepts moderately nested flow collections" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var parser = Parser.init(arena.allocator(), "a: [[1, 2], {b: [3, {c: 4}]}]");
    _ = try parser.parse();
}

test "parse terminates on an unclosed flow sequence running into block content" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // The `:` after `name` starts no flow value, so the flow-sequence loop used
    // to append null nodes forever without consuming it.
    var parser = Parser.init(arena.allocator(), "[\nname: CI");
    _ = try parser.parse();
}

fn entryFullSpanText(source: []const u8, mapping: Mapping, key: []const u8) ?[]const u8 {
    for (mapping.entries) |entry| {
        if (!std.mem.eql(u8, entry.key.value, key)) continue;
        const fs = entry.full_span orelse return null;
        return source[fs.start_byte..fs.end_byte];
    }
    return null;
}

test "full_span of a block scalar entry stops before the next sibling key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\job:
        \\  runs-on: |
        \\    ubuntu-latest
        \\  steps: []
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const job = root.mapping.entries[0].value.mapping;

    try std.testing.expectEqualStrings(
        "  runs-on: |\n    ubuntu-latest\n",
        entryFullSpanText(source, job, "runs-on").?,
    );
}

test "full_span of a block scalar entry at EOF without a trailing newline" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source = "job:\n  runs-on: |\n    ubuntu-latest";
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const job = root.mapping.entries[0].value.mapping;

    try std.testing.expectEqualStrings(
        "  runs-on: |\n    ubuntu-latest",
        entryFullSpanText(source, job, "runs-on").?,
    );
}

test "full_span of a plain scalar entry still covers its whole line" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source = "job:\n  runs-on: ubuntu-latest\n  steps: []\n";
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const job = root.mapping.entries[0].value.mapping;

    try std.testing.expectEqualStrings(
        "  runs-on: ubuntu-latest\n",
        entryFullSpanText(source, job, "runs-on").?,
    );
}

test "full_span end_line follows a multi-line quoted scalar" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source = "job:\n  name: \"a\n    b\"\n  steps: []\n";
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const job = root.mapping.entries[0].value.mapping;

    // end_line points just past the consumed trailing newline, as it does for
    // a single-line entry; the value itself ends on line 3.
    const fs = job.entries[0].full_span.?;
    try std.testing.expectEqual(@as(u32, 2), fs.start_line);
    try std.testing.expectEqual(@as(u32, 4), fs.end_line);
    try std.testing.expectEqualStrings("  name: \"a\n    b\"\n", source[fs.start_byte..fs.end_byte]);
}
