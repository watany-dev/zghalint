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
fn oneEdit(alloc: std.mem.Allocator, start_byte: usize, end_byte: usize, replacement: []const u8) ?[]Edit {
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
    if (value_span.end_byte < quote_offset) return null;
    const content_end = value_span.end_byte - quote_offset;
    const content_start = value_span.start_byte + quote_offset;
    if (content_end < content_start) return null;

    return oneEdit(alloc, content_start, content_end, new_value);
}

/// The key-side counterpart of `replaceScalar`: renames a token that a rule has
/// already reported, such as a mapping key, an event name, or an identifier
/// inside a `${{ }}` path.
///
/// `span` must cover exactly `old_text`, optionally wrapped in one pair of
/// quotes; only the text itself is replaced, so the quoting survives.
///
/// The width alone does not prove that: a `|` / `>` block scalar drops the
/// indicator and the newline from its value, so its span is two bytes wider
/// too, and a fallback span standing in for a token span the parser never
/// captured can be any width at all. The edit therefore carries `expects`, and
/// `fix/engine.zig` drops it unless those bytes really are `old_text`.
pub fn renameToken(
    alloc: std.mem.Allocator,
    span: Span,
    old_text: []const u8,
    new_text: []const u8,
) ?[]const Edit {
    if (span.end_byte < span.start_byte) return null;
    const width = span.end_byte - span.start_byte;

    // `'push'` / `"push"`: the span covers the quotes, the replacement must not.
    const quote_offset: usize = if (width == old_text.len)
        0
    else if (width == old_text.len + 2)
        1
    else
        return null;

    const edits = oneEdit(
        alloc,
        span.start_byte + quote_offset,
        span.end_byte - quote_offset,
        new_text,
    ) orelse return null;
    edits[0].expects = old_text;
    return edits;
}

/// Typical usage is with `MappingEntry.full_span`, which covers the key line
/// plus its trailing newline, so no blank line is left behind.
pub fn deleteMappingEntry(alloc: std.mem.Allocator, entry_span: Span) ?[]const Edit {
    return oneEdit(alloc, entry_span.start_byte, entry_span.end_byte, "");
}

/// Removes items from the *same* sequence, given the sequence's per-item
/// `yaml.ItemDelete` array and the indices of the items to drop.
///
/// Returns null when the removal would empty the sequence: `needs: []` and
/// `matrix: { os: [] }` are not what the diagnostic asked for, and an empty
/// block sequence cannot even be written by dropping lines. It also returns
/// null when the parser recorded no ranges (`items.len` shorter than the
/// sequence, e.g. an alias expansion) — the caller passes the array it got.
///
/// Adjacent indices become one edit. `fix.engine` drops a fix whose own edits
/// overlap, and a deletion running to the end of a flow sequence has to start
/// at the comma *before* its first item so `[a, b, c]` losing `b` and `c`
/// leaves `[a]` and not `[a, ]`; both need the run, not the item, as the unit.
pub fn deleteSequenceItems(
    alloc: std.mem.Allocator,
    items: []const yaml_types.ItemDelete,
    indices: []const usize,
) ?[]const Edit {
    if (items.len == 0 or indices.len == 0 or indices.len >= items.len) return null;

    const sorted = alloc.alloc(usize, indices.len) catch return null;
    @memcpy(sorted, indices);
    std.mem.sort(usize, sorted, {}, std.sort.asc(usize));
    for (sorted, 0..) |idx, i| {
        if (idx >= items.len) return null;
        if (i > 0 and idx == sorted[i - 1]) return null;
    }

    const edits = alloc.alloc(Edit, sorted.len) catch return null;
    var count: usize = 0;
    var run_start: usize = 0;
    while (run_start < sorted.len) {
        var run_end = run_start;
        while (run_end + 1 < sorted.len and sorted[run_end + 1] == sorted[run_end] + 1) run_end += 1;

        const first = items[sorted[run_start]];
        const last = items[sorted[run_end]];
        // A run reaching the sequence's last item leaves no following separator
        // to absorb, so it swallows the one in front of it instead.
        const takes_preceding = sorted[run_end] + 1 == items.len and sorted[run_start] > 0;
        const start_byte = if (takes_preceding) first.prev_end else first.span.start_byte;
        edits[count] = .{ .start_byte = start_byte, .end_byte = last.span.end_byte, .replacement = "" };
        count += 1;
        run_start = run_end + 1;
    }

    return edits[0..count];
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

fn mkDelete(start_byte: usize, end_byte: usize, prev_end: usize) yaml_types.ItemDelete {
    return .{ .span = mkSpan(start_byte, end_byte), .prev_end = prev_end };
}

test "deleteSequenceItems removes one item of several" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const items = [_]yaml_types.ItemDelete{
        mkDelete(0, 10, 0),
        mkDelete(10, 20, 10),
        mkDelete(20, 30, 20),
    };
    const edits = deleteSequenceItems(arena.allocator(), &items, &.{1}) orelse return error.TestExpectedNonNull;

    try testing.expectEqual(@as(usize, 1), edits.len);
    try testing.expectEqual(@as(usize, 10), edits[0].start_byte);
    try testing.expectEqual(@as(usize, 20), edits[0].end_byte);
    try testing.expectEqualStrings("", edits[0].replacement);
}

test "deleteSequenceItems keeps non-adjacent items as separate edits, sorted" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const items = [_]yaml_types.ItemDelete{
        mkDelete(0, 10, 0),
        mkDelete(10, 20, 10),
        mkDelete(20, 30, 20),
        mkDelete(30, 40, 30),
    };
    const edits = deleteSequenceItems(arena.allocator(), &items, &.{ 2, 0 }) orelse return error.TestExpectedNonNull;

    try testing.expectEqual(@as(usize, 2), edits.len);
    try testing.expectEqual(@as(usize, 0), edits[0].start_byte);
    try testing.expectEqual(@as(usize, 20), edits[1].start_byte);
    try testing.expectEqual(@as(usize, 30), edits[1].end_byte);
}

test "deleteSequenceItems merges adjacent items into one edit" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const items = [_]yaml_types.ItemDelete{
        mkDelete(0, 10, 0),
        mkDelete(10, 20, 10),
        mkDelete(20, 30, 20),
    };
    const edits = deleteSequenceItems(arena.allocator(), &items, &.{ 0, 1 }) orelse return error.TestExpectedNonNull;

    try testing.expectEqual(@as(usize, 1), edits.len);
    try testing.expectEqual(@as(usize, 0), edits[0].start_byte);
    try testing.expectEqual(@as(usize, 20), edits[0].end_byte);
}

test "deleteSequenceItems takes the preceding comma when a run ends the sequence" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // `[a, b, c]`: item text at 1..2, 4..5, 7..8; non-last items reach the
    // next item's start.
    const items = [_]yaml_types.ItemDelete{
        mkDelete(1, 4, 1),
        mkDelete(4, 7, 2),
        mkDelete(7, 8, 5),
    };
    const edits = deleteSequenceItems(arena.allocator(), &items, &.{ 1, 2 }) orelse return error.TestExpectedNonNull;

    try testing.expectEqual(@as(usize, 1), edits.len);
    try testing.expectEqual(@as(usize, 2), edits[0].start_byte);
    try testing.expectEqual(@as(usize, 8), edits[0].end_byte);
}

test "deleteSequenceItems keeps its own start when the run begins at index 0" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // `[a, b, c]` losing `a` and `b`: there is no comma in front of `a` to
    // take, and the one after `b` goes with it.
    const items = [_]yaml_types.ItemDelete{
        mkDelete(1, 4, 1),
        mkDelete(4, 7, 2),
        mkDelete(7, 8, 5),
    };
    const edits = deleteSequenceItems(arena.allocator(), &items, &.{ 0, 1 }) orelse return error.TestExpectedNonNull;
    try testing.expectEqual(@as(usize, 1), edits[0].start_byte);
    try testing.expectEqual(@as(usize, 7), edits[0].end_byte);
}

test "deleteSequenceItems refuses to empty the sequence" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const items = [_]yaml_types.ItemDelete{ mkDelete(0, 10, 0), mkDelete(10, 20, 10) };
    try testing.expect(deleteSequenceItems(arena.allocator(), &items, &.{ 0, 1 }) == null);
}

test "deleteSequenceItems with no indices returns null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const items = [_]yaml_types.ItemDelete{ mkDelete(0, 10, 0), mkDelete(10, 20, 10) };
    try testing.expect(deleteSequenceItems(arena.allocator(), &items, &.{}) == null);
}

test "deleteSequenceItems rejects an out-of-range or repeated index" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const items = [_]yaml_types.ItemDelete{ mkDelete(0, 10, 0), mkDelete(10, 20, 10), mkDelete(20, 30, 20) };
    try testing.expect(deleteSequenceItems(arena.allocator(), &items, &.{5}) == null);
    try testing.expect(deleteSequenceItems(arena.allocator(), &items, &.{ 1, 1 }) == null);
}

test "deleteSequenceItems returns null when the parser recorded no ranges" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expect(deleteSequenceItems(arena.allocator(), &.{}, &.{0}) == null);
}

test "renameToken replaces an unquoted token" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const edits = renameToken(arena.allocator(), mkSpan(10, 14), "pusg", "push") orelse
        return error.TestExpectedNonNull;
    try testing.expectEqual(@as(usize, 1), edits.len);
    try testing.expectEqual(@as(usize, 10), edits[0].start_byte);
    try testing.expectEqual(@as(usize, 14), edits[0].end_byte);
    try testing.expectEqualStrings("push", edits[0].replacement);
}

test "renameToken keeps the quotes of a quoted token" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const edits = renameToken(arena.allocator(), mkSpan(10, 16), "pusg", "push") orelse
        return error.TestExpectedNonNull;
    try testing.expectEqual(@as(usize, 11), edits[0].start_byte);
    try testing.expectEqual(@as(usize, 15), edits[0].end_byte);
    try testing.expectEqualStrings("push", edits[0].replacement);
}

test "renameToken records the bytes it expects to replace" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const plain = renameToken(arena.allocator(), mkSpan(10, 14), "pusg", "push").?;
    try testing.expectEqualStrings("pusg", plain[0].expects.?);

    // The quoted branch guesses; `expects` is what makes the guess checkable.
    const quoted = renameToken(arena.allocator(), mkSpan(10, 16), "pusg", "push").?;
    try testing.expectEqual(@as(usize, 11), quoted[0].start_byte);
    try testing.expectEqualStrings("pusg", quoted[0].expects.?);
}

test "renameToken rejects a span that does not cover the token" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // A step span standing in for a token span the parser never captured.
    try testing.expect(renameToken(arena.allocator(), mkSpan(0, 120), "pusg", "push") == null);
    try testing.expect(renameToken(arena.allocator(), mkSpan(10, 10), "pusg", "push") == null);
    try testing.expect(renameToken(arena.allocator(), mkSpan(14, 10), "pusg", "push") == null);
}
