//! Canonical YAML emitter for the round-trip invariant
//! `parse(s) == parse(emit(parse(s)))` (`Node.eql`, ignoring spans and style).
//!
//! The parser stores quoted-scalar *inner text* without unescaping, so this
//! emitter never inserts `\"` / `''` escapes that would become part of the
//! stored value. A scalar that contains both `'` and `"` cannot be re-encoded
//! faithfully; `emit` returns `error.UnrepresentableScalar` so callers skip it.

const std = @import("std");
const parser_mod = @import("parser.zig");
const types = @import("types.zig");

const Parser = parser_mod.Parser;
const Node = types.Node;

pub const EmitError = error{
    OutOfMemory,
    MaxDepthExceeded,
    UnrepresentableScalar,
};

pub fn emit(allocator: std.mem.Allocator, node: Node) EmitError![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try emitNode(allocator, &buf, node, 0, 0, .root);
    if (buf.items.len == 0 or buf.items[buf.items.len - 1] != '\n') {
        try buf.append(allocator, '\n');
    }
    return buf.toOwnedSlice(allocator);
}

pub fn roundtrip(allocator: std.mem.Allocator, source: []const u8) !bool {
    var first_arena = std.heap.ArenaAllocator.init(allocator);
    defer first_arena.deinit();
    var first_parser = Parser.init(first_arena.allocator(), source);
    const first = first_parser.parse() catch return false;

    const serialized = emit(allocator, first) catch |err| switch (err) {
        error.UnrepresentableScalar => return error.UnrepresentableScalar,
        else => |e| return e,
    };
    defer allocator.free(serialized);

    var second_arena = std.heap.ArenaAllocator.init(allocator);
    defer second_arena.deinit();
    var second_parser = Parser.init(second_arena.allocator(), serialized);
    const second = try second_parser.parse();
    return first.eql(second);
}

const Parent = enum { root, mapping, sequence };

fn emitNode(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    node: Node,
    indent: usize,
    depth: u16,
    parent: Parent,
) EmitError!void {
    if (depth > parser_mod.max_parse_depth) return error.MaxDepthExceeded;
    switch (node) {
        .null_value => {},
        .scalar => |s| try emitScalar(allocator, buf, s.value),
        .sequence => |seq| try emitSequence(allocator, buf, seq.items, indent, depth, parent),
        .mapping => |map| try emitMapping(allocator, buf, map.entries, indent, depth, parent),
    }
}

fn emitScalar(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    value: []const u8,
) EmitError!void {
    if (isPlainSafe(value)) {
        try buf.appendSlice(allocator, value);
        return;
    }
    if (std.mem.indexOfScalar(u8, value, '"') == null) {
        try buf.append(allocator, '"');
        try buf.appendSlice(allocator, value);
        try buf.append(allocator, '"');
        return;
    }
    if (std.mem.indexOfScalar(u8, value, '\'') == null) {
        try buf.append(allocator, '\'');
        try buf.appendSlice(allocator, value);
        try buf.append(allocator, '\'');
        return;
    }
    return error.UnrepresentableScalar;
}

fn isPlainSafe(s: []const u8) bool {
    if (s.len == 0) return false;
    switch (s[0]) {
        ' ', '\t', '-', '?', ':', ',', '{', '}', '[', ']', '&', '*', '#', '|', '>', '!', '%', '@', '`', '\'', '"' => return false,
        else => {},
    }
    if (s[s.len - 1] == ' ' or s[s.len - 1] == '\t') return false;
    if (std.mem.indexOfScalar(u8, s, '\n') != null) return false;
    if (std.mem.indexOfScalar(u8, s, '\r') != null) return false;
    if (std.mem.indexOfScalar(u8, s, '#') != null) return false;
    if (std.mem.indexOf(u8, s, ": ") != null) return false;
    if (std.mem.indexOfScalar(u8, s, ':') != null and s[s.len - 1] == ':') return false;
    return true;
}

fn emitSequence(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    items: []const Node,
    indent: usize,
    depth: u16,
    parent: Parent,
) EmitError!void {
    if (items.len == 0) {
        try buf.appendSlice(allocator, "[]");
        return;
    }
    for (items, 0..) |item, i| {
        if (i > 0 or parent != .root) {
            try buf.append(allocator, '\n');
            try buf.appendNTimes(allocator, ' ', indent);
        }
        try buf.appendSlice(allocator, "- ");
        try emitNode(allocator, buf, item, indent + 2, depth + 1, .sequence);
    }
}

fn emitMapping(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    entries: []const types.MappingEntry,
    indent: usize,
    depth: u16,
    parent: Parent,
) EmitError!void {
    if (entries.len == 0) {
        try buf.appendSlice(allocator, "{}");
        return;
    }
    for (entries, 0..) |entry, i| {
        if (i == 0 and parent == .sequence) {
            // Sequence already wrote `- `; the first key stays on that line.
        } else if (i > 0 or parent != .root) {
            try buf.append(allocator, '\n');
            try buf.appendNTimes(allocator, ' ', indent);
        }
        try emitScalar(allocator, buf, entry.key.value);
        if (entry.value == .null_value) {
            try buf.append(allocator, ':');
            continue;
        }
        const nested = entry.value == .mapping or entry.value == .sequence;
        const empty_nested = switch (entry.value) {
            .mapping => |m| m.entries.len == 0,
            .sequence => |s| s.items.len == 0,
            else => false,
        };
        if (nested and !empty_nested) {
            try buf.append(allocator, ':');
            try emitNode(allocator, buf, entry.value, indent + 2, depth + 1, .mapping);
        } else {
            try buf.appendSlice(allocator, ": ");
            try emitNode(allocator, buf, entry.value, indent + 2, depth + 1, .mapping);
        }
    }
}

const fixtures = [_][]const u8{
    "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
    "name: CI\non: push\njobs:\n  job0:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
    "a: {b: [1, 2], c: 'x'}\n",
    "items:\n  - one\n  - two\n",
    "empty-map: {}\nempty-list: []\n",
    "quoted: \"hello\"\n",
    "name: CI\non: [push, pull_request]\njobs:\n  t:\n    runs-on: macos-latest\n    timeout-minutes: 10\n    steps:\n      - run: npm test\n",
};

test "roundtrip: fixture workflows keep the same AST" {
    for (fixtures) |src| {
        try std.testing.expect(try roundtrip(std.testing.allocator, src));
    }
}

test "roundtrip: empty mapping and sequence" {
    try std.testing.expect(try roundtrip(std.testing.allocator, "a: {}\nb: []\n"));
}

test "roundtrip: empty key is null_value not scalar null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p = Parser.init(arena.allocator(), "name: x\npermissions:\nconcurrency:\n");
    const node = try p.parse();
    try std.testing.expectEqualStrings("permissions", node.mapping.entries[1].key.value);
    try std.testing.expect(node.mapping.entries[1].value == .null_value);
    try std.testing.expect(try roundtrip(std.testing.allocator, "name: x\npermissions:\nconcurrency:\n"));
}

test "roundtrip: a value that cannot be re-encoded is reported" {
    const src = "x: |\n  a'b\"c\n";
    try std.testing.expectError(error.UnrepresentableScalar, roundtrip(std.testing.allocator, src));
}

test "emit of a mapping starts at column 0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p = Parser.init(arena.allocator(), "on: push\n");
    const node = try p.parse();
    const out = try emit(std.testing.allocator, node);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("on: push\n", out);
}
