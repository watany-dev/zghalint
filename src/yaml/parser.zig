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
    InvalidYaml,
};

pub const Parser = struct {
    allocator: std.mem.Allocator,
    tokenizer: Tokenizer,
    current: Token,
    source: []const u8,
    errors: std.ArrayList(DiagnosticError),

    pub const DiagnosticError = struct {
        message: []const u8,
        line: u32,
        column: u32,
    };

    pub fn init(allocator: std.mem.Allocator, source: []const u8) Parser {
        var tokenizer = Tokenizer.init(source);
        const first = tokenizer.next(); // stream_start
        _ = first;
        const current = tokenizer.next();
        return .{
            .allocator = allocator,
            .tokenizer = tokenizer,
            .current = current,
            .source = source,
            .errors = .{},
        };
    }

    pub fn deinit(self: *Parser) void {
        self.errors.deinit(self.allocator);
    }

    pub fn parse(self: *Parser) ParseError!Node {
        // Skip document start marker if present
        if (self.current.kind == .document_start) {
            self.advance();
            self.skipNewlines();
        }

        return self.parseNode(0);
    }

    fn parseNode(self: *Parser, min_indent: u32) ParseError!Node {
        self.skipNewlines();

        if (self.current.kind == .eof) {
            return Node{ .null_value = self.spanFromToken(self.current) };
        }

        // Sequence entry (- item)
        if (self.current.kind == .sequence_entry) {
            return self.parseBlockSequence(min_indent);
        }

        // Flow mapping {
        if (self.current.kind == .flow_mapping_start) {
            return self.parseFlowMapping();
        }

        // Flow sequence [
        if (self.current.kind == .flow_sequence_start) {
            return self.parseFlowSequence();
        }

        // Scalar - could be start of mapping or standalone value
        if (self.current.kind == .scalar) {
            const scalar_token = self.current;
            self.advance();

            // Check if this is a mapping key (followed by :)
            if (self.current.kind == .mapping_value) {
                return self.parseBlockMapping(scalar_token, min_indent);
            }

            // Standalone scalar
            return Node{ .scalar = self.scalarFromToken(scalar_token) };
        }

        // Mapping value directly (shouldn't normally happen)
        if (self.current.kind == .mapping_value) {
            self.advance();
            return self.parseNode(min_indent);
        }

        // Comment - skip and continue
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
            // We have a key, now expect ':'
            if (self.current.kind != .mapping_value) break;
            self.advance(); // consume ':'

            // Parse value
            self.skipNonNewlineWhitespace();
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
            });

            // Look for next key at same indent level
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

    fn parseBlockSequence(self: *Parser, min_indent: u32) ParseError!Node {
        var items = std.ArrayList(Node){};
        const seq_indent = self.current.column;
        _ = min_indent;

        while (self.current.kind == .sequence_entry and self.current.column == seq_indent) {
            self.advance(); // consume '-'

            // Parse item value
            self.skipNonNewlineWhitespace();
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
        self.advance(); // consume '{'

        while (self.current.kind != .flow_mapping_end and self.current.kind != .eof) {
            self.skipNewlinesAndComments();
            if (self.current.kind == .flow_mapping_end) break;

            // Key
            if (self.current.kind != .scalar) break;
            const key_token = self.current;
            self.advance();

            // Expect ':'
            if (self.current.kind != .mapping_value) break;
            self.advance();

            // Value
            self.skipNonNewlineWhitespace();
            const value = try self.parseFlowValue();

            const key_scalar = self.scalarFromToken(key_token);
            try entries.append(self.allocator, .{
                .key = key_scalar,
                .value = value,
                .span = key_scalar.span,
            });

            // Optional comma
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
        self.advance(); // consume '['

        while (self.current.kind != .flow_sequence_end and self.current.kind != .eof) {
            self.skipNewlinesAndComments();
            if (self.current.kind == .flow_sequence_end) break;

            try items.append(self.allocator, try self.parseFlowValue());

            if (self.current.kind == .flow_entry) {
                self.advance();
            }
        }

        if (self.current.kind == .flow_sequence_end) {
            self.advance();
        }

        const owned_items = items.toOwnedSlice(self.allocator) catch return ParseError.OutOfMemory;
        return Node{ .sequence = .{ .items = owned_items, .span = start_span } };
    }

    fn parseFlowValue(self: *Parser) ParseError!Node {
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
        // Skip whitespace-only tokens in the main advance
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

    fn skipNonNewlineWhitespace(_: *Parser) void {
        // The tokenizer already skips spaces, so this is a no-op
        // but kept for clarity in the parse logic
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
        // Strip quotes from quoted scalars
        if (raw.len >= 2 and (raw[0] == '\'' or raw[0] == '"')) {
            return .{
                .value = raw[1 .. raw.len - 1],
                .style = if (raw[0] == '\'') .single_quoted else .double_quoted,
                .span = self.spanFromToken(token),
            };
        }
        // Block scalars - extract content after indicator line
        if (raw.len >= 1 and (raw[0] == '|' or raw[0] == '>')) {
            const style: ScalarStyle = if (raw[0] == '|') .literal else .folded;
            // Find first newline
            var content_start: usize = 0;
            for (raw, 0..) |ch, i| {
                if (ch == '\n') {
                    content_start = i + 1;
                    break;
                }
            }
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
};

// ============================================================
// Tests
// ============================================================

test "parse simple mapping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "name: CI");
    defer parser.deinit();
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
    defer parser.deinit();
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
    defer parser.deinit();
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
    defer parser.deinit();
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
    defer parser.deinit();
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
    defer parser.deinit();
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
    defer parser.deinit();
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
    defer parser.deinit();
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
    defer parser.deinit();
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
    defer parser.deinit();
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

test "parser deinit cleans up" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "a: b");
    parser.deinit();
}

// ============================================================
// Fuzz / Property-Based Tests
// ============================================================

test "fuzz: yaml parser never panics" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, input: []const u8) anyerror!void {
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena.deinit();
            var parser = Parser.init(arena.allocator(), input);
            defer parser.deinit();
            _ = parser.parse() catch {};
        }
    }.testOne, .{ .corpus = &.{
        "name: CI\non: push",
        "- a\n- b",
        "{a: b}",
        "[1, 2, 3]",
        "---\nkey: val",
        "'quoted': value",
        "",
    } });
}
