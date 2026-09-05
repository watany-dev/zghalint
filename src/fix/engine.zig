const std = @import("std");
const diagnostics = @import("../diagnostics.zig");

pub const Fix = diagnostics.Fix;
pub const Edit = diagnostics.Edit;
pub const Diagnostic = diagnostics.Diagnostic;

pub fn collectFixes(
    allocator: std.mem.Allocator,
    diags: []const Diagnostic,
    include_unsafe: bool,
) ![]const Fix {
    var list = std.ArrayList(Fix){};
    defer list.deinit(allocator);

    for (diags) |d| {
        if (d.fix) |f| {
            if (include_unsafe or f.safety == .safe) {
                try list.append(allocator, f);
            }
        }
    }

    return list.toOwnedSlice(allocator);
}

/// Edits come back sorted by start_byte descending so they can be applied
/// back-to-front without offset shifting. Overlapping edits are dropped (first
/// wins by position), as are edits with invalid byte ranges.
fn flattenAndSort(allocator: std.mem.Allocator, fixes: []const Fix, source_len: usize) ![]Edit {
    var total: usize = 0;
    for (fixes) |f| {
        total += f.edits.len;
    }

    if (total == 0) return &.{};

    const edits = try allocator.alloc(Edit, total);
    errdefer allocator.free(edits);

    var idx: usize = 0;
    for (fixes) |f| {
        for (f.edits) |e| {
            if (!isValidEdit(e, source_len)) continue;
            edits[idx] = e;
            idx += 1;
        }
    }

    const filtered = edits[0..idx];

    // Ascending for overlap detection; reversed below.
    std.mem.sort(Edit, filtered, {}, struct {
        fn lessThan(_: void, a: Edit, b: Edit) bool {
            if (a.start_byte != b.start_byte) return a.start_byte < b.start_byte;
            return a.end_byte < b.end_byte;
        }
    }.lessThan);

    var write_idx: usize = 0;
    var last_end: usize = 0;
    for (filtered) |e| {
        if (write_idx > 0 and e.start_byte < last_end) {
            continue;
        }
        filtered[write_idx] = e;
        last_end = e.end_byte;
        write_idx += 1;
    }

    // Hand back an exactly-sized allocation so the caller can free it directly.
    std.mem.reverse(Edit, filtered[0..write_idx]);
    return allocator.realloc(edits, write_idx);
}

/// Invalid edits are dropped by `flattenAndSort` to avoid arithmetic underflow or
/// out-of-bounds reads in `applyFixes`.
fn isValidEdit(e: Edit, source_len: usize) bool {
    if (e.end_byte < e.start_byte) return false;
    if (e.end_byte > source_len) return false;
    return true;
}

/// Edits are applied back-to-front to avoid offset invalidation.
pub fn applyFixes(
    allocator: std.mem.Allocator,
    source: []const u8,
    fixes: []const Fix,
) !ApplyResult {
    const edits = try flattenAndSort(allocator, fixes, source.len);
    defer allocator.free(edits);

    if (edits.len == 0) {
        return .{ .content = try allocator.dupe(u8, source), .edits_applied = 0 };
    }

    var result_len: usize = source.len;
    for (edits) |e| {
        result_len = result_len - (e.end_byte - e.start_byte) + e.replacement.len;
    }

    var result = try allocator.alloc(u8, result_len);
    var src_pos: usize = source.len;
    var dst_pos: usize = result_len;

    for (edits) |e| {
        const after_len = src_pos - e.end_byte;
        dst_pos -= after_len;
        @memcpy(result[dst_pos..][0..after_len], source[e.end_byte..][0..after_len]);

        dst_pos -= e.replacement.len;
        @memcpy(result[dst_pos..][0..e.replacement.len], e.replacement);

        src_pos = e.start_byte;
    }

    if (src_pos > 0) {
        dst_pos -= src_pos;
        @memcpy(result[dst_pos..][0..src_pos], source[0..src_pos]);
    }

    return .{ .content = result, .edits_applied = edits.len };
}

pub const ApplyResult = struct {
    content: []const u8,
    edits_applied: usize,

    pub fn deinit(self: ApplyResult, allocator: std.mem.Allocator) void {
        allocator.free(self.content);
    }
};

test "single replacement edit" {
    const allocator = std.testing.allocator;
    const source = "uses: actions/checkout@v4";
    const edits = [_]Edit{
        .{ .start_byte = 6, .end_byte = 25, .replacement = "actions/checkout@abc123def456" },
    };
    const fixes = [_]Fix{
        .{ .description = "pin action", .safety = .safe, .edits = &edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("uses: actions/checkout@abc123def456", result.content);
    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
}

test "insertion edit (start_byte == end_byte)" {
    const allocator = std.testing.allocator;
    const source = "name: CI";
    const edits = [_]Edit{
        .{ .start_byte = 8, .end_byte = 8, .replacement = "\ntimeout-minutes: 30" },
    };
    const fixes = [_]Fix{
        .{ .description = "add timeout", .safety = .safe, .edits = &edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("name: CI\ntimeout-minutes: 30", result.content);
}

test "deletion edit (empty replacement)" {
    const allocator = std.testing.allocator;
    const source = "line1\nDELETE_ME\nline3";
    const edits = [_]Edit{
        .{ .start_byte = 6, .end_byte = 15, .replacement = "" },
    };
    const fixes = [_]Fix{
        .{ .description = "delete line", .safety = .safe, .edits = &edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("line1\n\nline3", result.content);
}

test "multiple non-overlapping edits" {
    const allocator = std.testing.allocator;
    const source = "AAA BBB CCC";
    const edits1 = [_]Edit{
        .{ .start_byte = 0, .end_byte = 3, .replacement = "XXX" },
    };
    const edits2 = [_]Edit{
        .{ .start_byte = 8, .end_byte = 11, .replacement = "ZZZ" },
    };
    const fixes = [_]Fix{
        .{ .description = "fix1", .safety = .safe, .edits = &edits1 },
        .{ .description = "fix2", .safety = .safe, .edits = &edits2 },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("XXX BBB ZZZ", result.content);
    try std.testing.expectEqual(@as(usize, 2), result.edits_applied);
}

test "overlapping edits — first by position wins" {
    const allocator = std.testing.allocator;
    const source = "ABCDEFGH";
    const edits1 = [_]Edit{
        .{ .start_byte = 2, .end_byte = 5, .replacement = "XX" },
    };
    const edits2 = [_]Edit{
        .{ .start_byte = 3, .end_byte = 6, .replacement = "YY" },
    };
    const fixes = [_]Fix{
        .{ .description = "fix1", .safety = .safe, .edits = &edits1 },
        .{ .description = "fix2", .safety = .safe, .edits = &edits2 },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("ABXXFGH", result.content);
    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
}

test "empty fixes — returns source unchanged" {
    const allocator = std.testing.allocator;
    const source = "unchanged content";
    const fixes = [_]Fix{};
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("unchanged content", result.content);
    try std.testing.expectEqual(@as(usize, 0), result.edits_applied);
}

test "collectFixes filters by safety" {
    const allocator = std.testing.allocator;
    const span = @import("../yaml/types.zig").Span.point(1, 1, 0);

    const safe_edits = [_]Edit{
        .{ .start_byte = 0, .end_byte = 3, .replacement = "xxx" },
    };
    const unsafe_edits = [_]Edit{
        .{ .start_byte = 10, .end_byte = 15, .replacement = "yyy" },
    };

    const diags = [_]Diagnostic{
        .{
            .rule_id = "R001",
            .severity = .warning,
            .message = "safe issue",
            .span = span,
            .fix = .{ .description = "safe fix", .safety = .safe, .edits = &safe_edits },
        },
        .{
            .rule_id = "R002",
            .severity = .warning,
            .message = "unsafe issue",
            .span = span,
            .fix = .{ .description = "unsafe fix", .safety = .unsafe, .edits = &unsafe_edits },
        },
        .{
            .rule_id = "R003",
            .severity = .info,
            .message = "no fix",
            .span = span,
        },
    };

    const safe_fixes = try collectFixes(allocator, &diags, false);
    defer allocator.free(safe_fixes);
    try std.testing.expectEqual(@as(usize, 1), safe_fixes.len);
    try std.testing.expectEqualStrings("safe fix", safe_fixes[0].description);

    const all_fixes = try collectFixes(allocator, &diags, true);
    defer allocator.free(all_fixes);
    try std.testing.expectEqual(@as(usize, 2), all_fixes.len);
}

test "fix with multiple edits in single fix" {
    const allocator = std.testing.allocator;
    const source = "AABBCC";
    const edits = [_]Edit{
        .{ .start_byte = 0, .end_byte = 2, .replacement = "XX" },
        .{ .start_byte = 4, .end_byte = 6, .replacement = "ZZ" },
    };
    const fixes = [_]Fix{
        .{ .description = "multi-edit fix", .safety = .safe, .edits = &edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("XXBBZZ", result.content);
    try std.testing.expectEqual(@as(usize, 2), result.edits_applied);
}

test "invalid edit: end_byte > source.len is skipped" {
    const allocator = std.testing.allocator;
    const source = "hello";
    const edits = [_]Edit{
        .{ .start_byte = 0, .end_byte = 100, .replacement = "x" },
    };
    const fixes = [_]Fix{
        .{ .description = "bad", .safety = .safe, .edits = &edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("hello", result.content);
    try std.testing.expectEqual(@as(usize, 0), result.edits_applied);
}

test "invalid edit: end_byte < start_byte is skipped" {
    const allocator = std.testing.allocator;
    const source = "hello world";
    const edits = [_]Edit{
        .{ .start_byte = 5, .end_byte = 2, .replacement = "x" },
    };
    const fixes = [_]Fix{
        .{ .description = "inverted", .safety = .safe, .edits = &edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("hello world", result.content);
    try std.testing.expectEqual(@as(usize, 0), result.edits_applied);
}

test "mixed valid and invalid edits: valid ones still apply" {
    const allocator = std.testing.allocator;
    const source = "AAA BBB";
    const valid_edits = [_]Edit{
        .{ .start_byte = 0, .end_byte = 3, .replacement = "XXX" },
    };
    const invalid_edits = [_]Edit{
        .{ .start_byte = 4, .end_byte = 999, .replacement = "!" },
    };
    const fixes = [_]Fix{
        .{ .description = "valid", .safety = .safe, .edits = &valid_edits },
        .{ .description = "invalid", .safety = .safe, .edits = &invalid_edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("XXX BBB", result.content);
    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
}

test "all edits invalid: returns source unchanged" {
    const allocator = std.testing.allocator;
    const source = "unchanged";
    const edits = [_]Edit{
        .{ .start_byte = 20, .end_byte = 30, .replacement = "x" },
        .{ .start_byte = 5, .end_byte = 3, .replacement = "y" },
    };
    const fixes = [_]Fix{
        .{ .description = "bad1", .safety = .safe, .edits = edits[0..1] },
        .{ .description = "bad2", .safety = .safe, .edits = edits[1..2] },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("unchanged", result.content);
    try std.testing.expectEqual(@as(usize, 0), result.edits_applied);
}

test "edit at exact source end (end_byte == source.len) is valid" {
    const allocator = std.testing.allocator;
    const source = "abc";
    const edits = [_]Edit{
        .{ .start_byte = 3, .end_byte = 3, .replacement = "!" },
    };
    const fixes = [_]Fix{
        .{ .description = "append", .safety = .safe, .edits = &edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("abc!", result.content);
    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
}
