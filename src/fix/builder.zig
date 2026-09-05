//! Centralizes the byte-level edit construction used by rules so that each
//! rule only needs to supply span / indent / key / value and a FixSafety
//! classification of its own. Returning `null` signals "unable to build this
//! edit" (OOM, unsupported scalar style, or missing span); callers propagate
//! that up as `diag.fix = null`, matching the historical behavior.

const std = @import("std");
const yaml_types = @import("../yaml/types.zig");
const diagnostics = @import("../diagnostics.zig");

const Edit = diagnostics.Edit;
const Span = yaml_types.Span;
const ScalarStyle = yaml_types.ScalarStyle;

/// Every builder here produces exactly one edit; only its byte range and
/// replacement text differ.
fn oneEdit(alloc: std.mem.Allocator, start_byte: usize, end_byte: usize, replacement: []const u8) ?[]const Edit {
    const edits = alloc.alloc(Edit, 1) catch return null;
    edits[0] = .{ .start_byte = start_byte, .end_byte = end_byte, .replacement = replacement };
    return edits;
}

pub const InsertPos = struct {
    byte: usize,
    indent: u32,
};

pub const SubEntry = struct {
    key: []const u8,
    value: []const u8,
};

/// Use when the anchor is the start of a physical line (column 1), such as the
/// byte just after a `full_span` of a prior entry.
pub fn insertMappingEntry(
    alloc: std.mem.Allocator,
    pos: InsertPos,
    key: []const u8,
    value: []const u8,
) ?[]const Edit {
    const indent_len: usize = pos.indent;
    const total = indent_len + key.len + ": ".len + value.len + "\n".len;
    const buf = alloc.alloc(u8, total) catch return null;

    var i: usize = 0;
    @memset(buf[0..indent_len], ' ');
    i += indent_len;
    @memcpy(buf[i..][0..key.len], key);
    i += key.len;
    @memcpy(buf[i..][0..2], ": ");
    i += 2;
    @memcpy(buf[i..][0..value.len], value);
    i += value.len;
    buf[i] = '\n';

    return oneEdit(alloc, pos.byte, pos.byte, buf);
}

/// Use when the anchor sits at an already-indented sibling key (e.g. `runs-on:`);
/// the surrounding leading whitespace on the line is preserved and becomes the
/// indent of the new entry, while the trailing `\n<indent>` restores indentation
/// for the displaced sibling key.
pub fn insertMappingEntryBefore(
    alloc: std.mem.Allocator,
    pos: InsertPos,
    key: []const u8,
    value: []const u8,
) ?[]const Edit {
    const indent_len: usize = pos.indent;
    const total = key.len + ": ".len + value.len + "\n".len + indent_len;
    const buf = alloc.alloc(u8, total) catch return null;

    var i: usize = 0;
    @memcpy(buf[i..][0..key.len], key);
    i += key.len;
    @memcpy(buf[i..][0..2], ": ");
    i += 2;
    @memcpy(buf[i..][0..value.len], value);
    i += value.len;
    buf[i] = '\n';
    i += 1;
    @memset(buf[i..][0..indent_len], ' ');

    return oneEdit(alloc, pos.byte, pos.byte, buf);
}

/// Use when extending an existing mapping whose last entry ends at `after_byte`
/// (without a trailing newline).
pub fn appendMappingEntry(
    alloc: std.mem.Allocator,
    after_byte: usize,
    indent: u32,
    key: []const u8,
    value: []const u8,
) ?[]const Edit {
    const indent_len: usize = indent;
    const total = "\n".len + indent_len + key.len + ": ".len + value.len;
    const buf = alloc.alloc(u8, total) catch return null;

    buf[0] = '\n';
    var i: usize = 1;
    @memset(buf[i..][0..indent_len], ' ');
    i += indent_len;
    @memcpy(buf[i..][0..key.len], key);
    i += key.len;
    @memcpy(buf[i..][0..2], ": ");
    i += 2;
    @memcpy(buf[i..][0..value.len], value);

    return oneEdit(alloc, after_byte, after_byte, buf);
}

/// `uses_key_col` is the 1-based column of the step's `uses:` key, which the
/// new `with:` aligns with.
pub fn insertWithEntry(
    alloc: std.mem.Allocator,
    after_byte: usize,
    uses_key_col: u32,
    key: []const u8,
    value: []const u8,
) ?[]const Edit {
    if (uses_key_col == 0) return null;
    const parent_indent = alloc.alloc(u8, uses_key_col - 1) catch return null;
    @memset(parent_indent, ' ');
    const child_indent = alloc.alloc(u8, uses_key_col + 1) catch return null;
    @memset(child_indent, ' ');
    const replacement = std.fmt.allocPrint(
        alloc,
        "\n{s}with:\n{s}{s}: {s}",
        .{ parent_indent, child_indent, key, value },
    ) catch return null;

    return oneEdit(alloc, after_byte, after_byte, replacement);
}

/// Use when the anchor is at the start of a physical line (e.g. just after a
/// prior entry's `full_span`). Empty `sub_entries` yields null to avoid
/// producing a key with no mapping children.
pub fn insertMappingEntryBlock(
    alloc: std.mem.Allocator,
    pos: InsertPos,
    key: []const u8,
    sub_entries: []const SubEntry,
    child_indent: u32,
) ?[]const Edit {
    if (sub_entries.len == 0) return null;

    const parent_indent: usize = pos.indent;
    const sub_indent: usize = parent_indent + child_indent;

    var total: usize = parent_indent + key.len + ":\n".len;
    for (sub_entries) |sub| {
        total += sub_indent + sub.key.len + ": ".len + sub.value.len + "\n".len;
    }

    const buf = alloc.alloc(u8, total) catch return null;

    var i: usize = 0;
    @memset(buf[i..][0..parent_indent], ' ');
    i += parent_indent;
    @memcpy(buf[i..][0..key.len], key);
    i += key.len;
    @memcpy(buf[i..][0..2], ":\n");
    i += 2;

    for (sub_entries) |sub| {
        @memset(buf[i..][0..sub_indent], ' ');
        i += sub_indent;
        @memcpy(buf[i..][0..sub.key.len], sub.key);
        i += sub.key.len;
        @memcpy(buf[i..][0..2], ": ");
        i += 2;
        @memcpy(buf[i..][0..sub.value.len], sub.value);
        i += sub.value.len;
        buf[i] = '\n';
        i += 1;
    }

    return oneEdit(alloc, pos.byte, pos.byte, buf);
}

/// Honors the original `style` so quote characters stay intact.
///
/// Returns null for `literal` / `folded` block scalars, matching the existing
/// BP003 / DEP002 behavior: multi-line block scalars can't be rewritten safely
/// with a byte-level swap.
pub fn replaceScalar(
    alloc: std.mem.Allocator,
    value_span: Span,
    style: ScalarStyle,
    new_value: []const u8,
) ?[]const Edit {
    const quote_offset: usize = switch (style) {
        .plain => 0,
        .single_quoted, .double_quoted => 1,
        .literal, .folded => return null,
    };

    if (value_span.end_byte < value_span.start_byte) return null;
    const content_end = value_span.end_byte - quote_offset;
    const content_start = value_span.start_byte + quote_offset;
    if (content_end < content_start) return null;

    return oneEdit(alloc, content_start, content_end, new_value);
}

/// Typical usage is with `MappingEntry.full_span`, which covers the key line
/// plus its trailing newline, so no blank line is left behind.
pub fn deleteMappingEntry(alloc: std.mem.Allocator, entry_span: Span) ?[]const Edit {
    return oneEdit(alloc, entry_span.start_byte, entry_span.end_byte, "");
}

const testing = std.testing;

fn mkSpan(start_byte: usize, end_byte: usize) Span {
    return .{
        .start_line = 1,
        .start_col = 1,
        .end_line = 1,
        .end_col = 1,
        .start_byte = start_byte,
        .end_byte = end_byte,
    };
}

test "insertMappingEntry produces indented key: value line" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const edits = insertMappingEntry(
        arena.allocator(),
        .{ .byte = 42, .indent = 4 },
        "timeout-minutes",
        "30",
    ) orelse return error.TestExpectedNonNull;

    try testing.expectEqual(@as(usize, 1), edits.len);
    try testing.expectEqual(@as(usize, 42), edits[0].start_byte);
    try testing.expectEqual(@as(usize, 42), edits[0].end_byte);
    try testing.expectEqualStrings("    timeout-minutes: 30\n", edits[0].replacement);
}

test "insertMappingEntry indent=0" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const edits = insertMappingEntry(
        arena.allocator(),
        .{ .byte = 0, .indent = 0 },
        "permissions",
        "read-all",
    ) orelse return error.TestExpectedNonNull;
    try testing.expectEqualStrings("permissions: read-all\n", edits[0].replacement);
}

test "insertMappingEntryBefore produces key first then trailing indent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const edits = insertMappingEntryBefore(
        arena.allocator(),
        .{ .byte = 20, .indent = 4 },
        "timeout-minutes",
        "30",
    ) orelse return error.TestExpectedNonNull;

    try testing.expectEqual(@as(usize, 20), edits[0].start_byte);
    try testing.expectEqual(@as(usize, 20), edits[0].end_byte);
    try testing.expectEqualStrings("timeout-minutes: 30\n    ", edits[0].replacement);
}

test "appendMappingEntry prepends newline + indent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const edits = appendMappingEntry(
        arena.allocator(),
        100,
        6,
        "persist-credentials",
        "false",
    ) orelse return error.TestExpectedNonNull;

    try testing.expectEqual(@as(usize, 100), edits[0].start_byte);
    try testing.expectEqual(@as(usize, 100), edits[0].end_byte);
    try testing.expectEqualStrings("\n      persist-credentials: false", edits[0].replacement);
}

test "replaceScalar plain strips no quotes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const edits = replaceScalar(arena.allocator(), mkSpan(10, 15), .plain, "deny") orelse return error.TestExpectedNonNull;
    try testing.expectEqual(@as(usize, 10), edits[0].start_byte);
    try testing.expectEqual(@as(usize, 15), edits[0].end_byte);
    try testing.expectEqualStrings("deny", edits[0].replacement);
}

test "replaceScalar single_quoted preserves outer quotes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // Source: 'allow' with quotes at 10 and 16, inner text at 11..16.
    const edits = replaceScalar(arena.allocator(), mkSpan(10, 17), .single_quoted, "deny") orelse return error.TestExpectedNonNull;
    try testing.expectEqual(@as(usize, 11), edits[0].start_byte);
    try testing.expectEqual(@as(usize, 16), edits[0].end_byte);
    try testing.expectEqualStrings("deny", edits[0].replacement);
}

test "replaceScalar double_quoted preserves outer quotes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const edits = replaceScalar(arena.allocator(), mkSpan(20, 27), .double_quoted, "v4") orelse return error.TestExpectedNonNull;
    try testing.expectEqual(@as(usize, 21), edits[0].start_byte);
    try testing.expectEqual(@as(usize, 26), edits[0].end_byte);
    try testing.expectEqualStrings("v4", edits[0].replacement);
}

test "replaceScalar literal returns null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expect(replaceScalar(arena.allocator(), mkSpan(0, 10), .literal, "x") == null);
}

test "replaceScalar folded returns null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expect(replaceScalar(arena.allocator(), mkSpan(0, 10), .folded, "x") == null);
}

test "deleteMappingEntry produces empty-replacement edit" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const edits = deleteMappingEntry(arena.allocator(), mkSpan(50, 90)) orelse return error.TestExpectedNonNull;
    try testing.expectEqual(@as(usize, 50), edits[0].start_byte);
    try testing.expectEqual(@as(usize, 90), edits[0].end_byte);
    try testing.expectEqualStrings("", edits[0].replacement);
}

test "insertMappingEntryBlock: single sub entry at indent=0" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const subs = [_]SubEntry{.{ .key = "group", .value = "main" }};
    const edits = insertMappingEntryBlock(
        arena.allocator(),
        .{ .byte = 12, .indent = 0 },
        "concurrency",
        &subs,
        2,
    ) orelse return error.TestExpectedNonNull;

    try testing.expectEqual(@as(usize, 1), edits.len);
    try testing.expectEqual(@as(usize, 12), edits[0].start_byte);
    try testing.expectEqual(@as(usize, 12), edits[0].end_byte);
    try testing.expectEqualStrings("concurrency:\n  group: main\n", edits[0].replacement);
}

test "insertMappingEntryBlock: multiple sub entries" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const subs = [_]SubEntry{
        .{ .key = "group", .value = "main" },
        .{ .key = "cancel-in-progress", .value = "true" },
    };
    const edits = insertMappingEntryBlock(
        arena.allocator(),
        .{ .byte = 0, .indent = 0 },
        "concurrency",
        &subs,
        2,
    ) orelse return error.TestExpectedNonNull;

    try testing.expectEqualStrings(
        "concurrency:\n  group: main\n  cancel-in-progress: true\n",
        edits[0].replacement,
    );
}

test "insertMappingEntryBlock: indented mapping (indent=2, child=2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const subs = [_]SubEntry{.{ .key = "contents", .value = "read" }};
    const edits = insertMappingEntryBlock(
        arena.allocator(),
        .{ .byte = 30, .indent = 2 },
        "permissions",
        &subs,
        2,
    ) orelse return error.TestExpectedNonNull;

    try testing.expectEqualStrings("  permissions:\n    contents: read\n", edits[0].replacement);
}

test "insertMappingEntryBlock: empty sub_entries returns null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const subs = [_]SubEntry{};
    try testing.expect(insertMappingEntryBlock(
        arena.allocator(),
        .{ .byte = 0, .indent = 0 },
        "permissions",
        &subs,
        2,
    ) == null);
}
