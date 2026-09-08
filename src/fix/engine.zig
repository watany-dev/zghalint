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

/// Which fix an edit came from, so a conflict can be resolved for the fix as a
/// whole rather than for the single edit that happened to lose.
const OwnedEdit = struct {
    edit: Edit,
    fix_index: usize,
};

const Selection = struct {
    /// Sorted by start_byte descending, so `applyFixes` can copy back-to-front
    /// without offset shifting.
    edits: []Edit,
    /// Fixes dropped whole because one of their edits overlapped a *different*
    /// fix that won. Surfaced to the user: those diagnostics come back, and a
    /// second run applies them. A fix whose own edits overlap each other is
    /// dropped without being counted — a rule that emits such a fix is buggy,
    /// and re-running would drop it again.
    fixes_skipped: usize,
};

/// Selects the edits to apply. When two edits overlap, the one that starts
/// earlier wins and the *other edit's whole fix* is dropped: applying only
/// part of a multi-edit fix produces a file that matches no rule's intent
/// (#223). The loser is decided at the overlap, so the fix that survives is
/// the one owning the earlier edit of the conflicting pair, not necessarily
/// the one that starts earlier in the file.
/// Edits with invalid byte ranges are dropped without penalising their fix.
fn flattenAndSort(allocator: std.mem.Allocator, fixes: []const Fix, source: []const u8) !Selection {
    var total: usize = 0;
    for (fixes) |f| {
        total += f.edits.len;
    }

    if (total == 0) return .{ .edits = &.{}, .fixes_skipped = 0 };

    const owned = try allocator.alloc(OwnedEdit, total);
    defer allocator.free(owned);

    var idx: usize = 0;
    for (fixes, 0..) |f, fix_index| {
        for (f.edits) |e| {
            if (!isValidEdit(e, source)) continue;
            owned[idx] = .{ .edit = snapInsertionToLineEnd(e, source), .fix_index = fix_index };
            idx += 1;
        }
    }

    const flat = owned[0..idx];

    // Ascending for overlap detection; reversed below. `fix_index` is an
    // explicit tie-break rather than a reliance on sort stability, so two
    // insertions at the same byte keep the registry order `all_rules` gives
    // them however the sort is implemented.
    std.mem.sort(OwnedEdit, flat, {}, struct {
        fn lessThan(_: void, a: OwnedEdit, b: OwnedEdit) bool {
            if (a.edit.start_byte != b.edit.start_byte) return a.edit.start_byte < b.edit.start_byte;
            if (a.edit.end_byte != b.edit.end_byte) return a.edit.end_byte < b.edit.end_byte;
            return a.fix_index < b.fix_index;
        }
    }.lessThan);

    const dropped = try allocator.alloc(bool, fixes.len);
    defer allocator.free(dropped);
    @memset(dropped, false);

    const selected = try allocator.alloc(Edit, idx);
    errdefer allocator.free(selected);

    // Who each dropped fix lost to. Counting skips inside the sweep would be
    // premature: a winner can itself be dropped by a later pass, and a fix
    // that lost to a dropped one is not re-runnable either.
    const no_loser = std.math.maxInt(usize);
    const lost_to = try allocator.alloc(usize, fixes.len);
    defer allocator.free(lost_to);
    @memset(lost_to, no_loser);

    // Dropping a fix can free the range its winner had claimed, so the sweep
    // restarts after each drop. Every pass drops at most one fix, so this
    // terminates in at most `fixes.len` passes.
    var count: usize = 0;
    while (true) {
        count = 0;
        var last_end: usize = 0;
        var last_fix: usize = 0;
        var dropped_one = false;
        for (flat) |oe| {
            if (dropped[oe.fix_index]) continue;
            if (oe.edit.start_byte == oe.edit.end_byte) {
                // Two rules can reach the same conclusion about the same
                // anchor (SEC015 and SEC018 both add `persist-credentials:
                // false` to a checkout step, #300). Applying both writes the
                // key twice, so an identical insertion is applied once.
                if (priorInsertionOfSameKey(selected[0..count], oe.edit)) |prior| {
                    if (std.mem.eql(u8, prior.replacement, oe.edit.replacement)) continue;
                    // Same key, different body: neither can be trusted, so
                    // every fix inserting that key here is dropped — the ones
                    // deduped above included, or a rejected body survives as
                    // the twin of the one that was dropped.
                    dropInsertionGroup(flat, oe.edit, dropped);
                    dropped_one = true;
                    break;
                }
            }
            if (count > 0 and oe.edit.start_byte < last_end) {
                dropped[oe.fix_index] = true;
                lost_to[oe.fix_index] = last_fix;
                dropped_one = true;
                break;
            }
            selected[count] = oe.edit;
            last_end = oe.edit.end_byte;
            last_fix = oe.fix_index;
            count += 1;
        }
        if (!dropped_one) break;
    }

    // Report only a fix a second run would actually apply: it must have lost
    // to a *different* fix (a self-overlapping fix never applies), and that
    // winner must have survived so its diagnostic is gone next time.
    var fixes_skipped: usize = 0;
    for (lost_to, 0..) |winner, i| {
        if (winner == no_loser or winner == i) continue;
        if (!dropped[winner]) fixes_skipped += 1;
    }

    if (count == 0) {
        allocator.free(selected);
        return .{ .edits = &.{}, .fixes_skipped = fixes_skipped };
    }

    // Hand back an exactly-sized allocation so the caller can free it directly.
    std.mem.reverse(Edit, selected[0..count]);
    return .{
        .edits = try allocator.realloc(selected, count),
        .fixes_skipped = fixes_skipped,
    };
}

/// The already-selected insertion that would collide with `e`: same anchor and
/// same first key. Insertions that introduce different keys at one anchor are
/// not a collision — a job can gain both `timeout-minutes:` and `permissions:`.
/// `selected` is ascending by `start_byte`, so the scan stops at the anchor.
fn priorInsertionOfSameKey(selected: []const Edit, e: Edit) ?Edit {
    const key = firstInsertedKey(e.replacement) orelse return null;
    var i = selected.len;
    while (i > 0) {
        i -= 1;
        const prior = selected[i];
        if (prior.start_byte != e.start_byte) return null;
        if (prior.end_byte != e.end_byte) continue;
        const prior_key = firstInsertedKey(prior.replacement) orelse continue;
        if (std.mem.eql(u8, prior_key, key)) return prior;
    }
    return null;
}

/// Drops every fix that inserts `e`'s key at `e`'s anchor. A conflict there is
/// unresolvable, so no candidate may be applied — leaving one behind would pick
/// a winner by sweep order.
fn dropInsertionGroup(flat: []const OwnedEdit, e: Edit, dropped: []bool) void {
    const key = firstInsertedKey(e.replacement) orelse return;
    for (flat) |oe| {
        if (oe.edit.start_byte != e.start_byte or oe.edit.end_byte != e.end_byte) continue;
        const other_key = firstInsertedKey(oe.edit.replacement) orelse continue;
        if (std.mem.eql(u8, other_key, key)) dropped[oe.fix_index] = true;
    }
}

/// The mapping key an insertion opens with, e.g. `with` for
/// "\n  with:\n    persist-credentials: false". Null when the text does not
/// start a `key:` entry.
fn firstInsertedKey(replacement: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < replacement.len and (replacement[i] == '\n' or replacement[i] == '\r' or replacement[i] == ' ')) : (i += 1) {}
    const start = i;
    while (i < replacement.len and replacement[i] != ':' and replacement[i] != '\n' and replacement[i] != '\r') : (i += 1) {}
    if (i == start or i == replacement.len or replacement[i] != ':') return null;
    return replacement[start..i];
}

/// A pure insertion whose replacement opens a new line is meant to land after
/// the current physical line. Rules anchor it at the end of a value's span,
/// which stops before a trailing `# comment`; inserting there would carry the
/// comment onto the new line. For `uses: owner/repo@<sha> # v1.2.3` that
/// detaches the version tag Dependabot and Renovate read next to the pin.
fn snapInsertionToLineEnd(e: Edit, source: []const u8) Edit {
    if (e.start_byte != e.end_byte) return e;
    if (e.replacement.len == 0 or e.replacement[0] != '\n') return e;

    var i = e.start_byte;
    while (i < source.len and (source[i] == ' ' or source[i] == '\t')) : (i += 1) {}
    if (i < source.len and source[i] == '#') {
        while (i < source.len and source[i] != '\n' and source[i] != '\r') : (i += 1) {}
    }
    // Only whitespace or a comment may separate the anchor from the line end;
    // anything else means the anchor is mid-line and must not move.
    if (i < source.len and source[i] != '\n' and source[i] != '\r') return e;

    var snapped = e;
    snapped.start_byte = i;
    snapped.end_byte = i;
    return snapped;
}

/// Invalid edits are dropped by `flattenAndSort` to avoid arithmetic underflow or
/// out-of-bounds reads in `applyFixes`.
fn isValidEdit(e: Edit, source: []const u8) bool {
    if (e.end_byte < e.start_byte) return false;
    if (e.end_byte > source.len) return false;
    if (e.expects) |x| {
        if (!std.mem.eql(u8, source[e.start_byte..e.end_byte], x)) return false;
    }
    return true;
}

/// Edits are applied back-to-front to avoid offset invalidation.
pub fn applyFixes(
    allocator: std.mem.Allocator,
    source: []const u8,
    fixes: []const Fix,
) !ApplyResult {
    const selection = try flattenAndSort(allocator, fixes, source);
    const edits = selection.edits;
    defer allocator.free(edits);

    if (edits.len == 0) {
        return .{
            .content = try allocator.dupe(u8, source),
            .edits_applied = 0,
            .fixes_skipped = selection.fixes_skipped,
        };
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

    return .{
        .content = result,
        .edits_applied = edits.len,
        .fixes_skipped = selection.fixes_skipped,
    };
}

pub const ApplyResult = struct {
    content: []const u8,
    edits_applied: usize,
    /// Fixes that conflicted with a fix that won and were dropped whole.
    /// Non-zero means a second `--fix` run has work left to do.
    fixes_skipped: usize = 0,

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

test "an edit whose `expects` does not match the source is dropped" {
    const allocator = std.testing.allocator;
    const source = "on: >\n pusg";
    const edits = [_]Edit{
        // The span of the block scalar is two bytes wider than its value, so a
        // width-based builder lands one byte to the left of the name.
        .{ .start_byte = 5, .end_byte = 10, .replacement = "push", .expects = " pusg" },
    };
    const fixes = [_]Fix{
        .{ .description = "rename to \"push\"", .safety = .safe, .edits = &edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings(source, result.content);
    try std.testing.expectEqual(@as(usize, 0), result.edits_applied);
}

test "an edit whose `expects` matches is applied" {
    const allocator = std.testing.allocator;
    const source = "on: 'pusg'";
    const edits = [_]Edit{
        .{ .start_byte = 5, .end_byte = 9, .replacement = "push", .expects = "pusg" },
    };
    const fixes = [_]Fix{
        .{ .description = "rename to \"push\"", .safety = .safe, .edits = &edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("on: 'push'", result.content);
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

test "a losing fix is dropped whole, not edit by edit (#223)" {
    const allocator = std.testing.allocator;
    const source = "AB";
    // The counterexample from the TLA+ model: fix2's insertion does not
    // overlap anything, but its replacement loses to fix1. Applying only the
    // insertion would leave a file matching neither rule's intent.
    const edits1 = [_]Edit{
        .{ .start_byte = 0, .end_byte = 1, .replacement = "X" },
    };
    const edits2 = [_]Edit{
        .{ .start_byte = 0, .end_byte = 0, .replacement = "ins" },
        .{ .start_byte = 0, .end_byte = 1, .replacement = "Y" },
    };
    const fixes = [_]Fix{
        .{ .description = "fix1", .safety = .safe, .edits = &edits1 },
        .{ .description = "fix2", .safety = .safe, .edits = &edits2 },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("XB", result.content);
    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
    try std.testing.expectEqual(@as(usize, 1), result.fixes_skipped);
}

test "dropping a fix frees the range it had claimed" {
    const allocator = std.testing.allocator;
    const source = "ABCDEFGH";
    // fix1 wins at 0..2, so fix2 is dropped whole — including its edit at
    // 4..6, which then leaves fix3 free to apply there.
    const edits1 = [_]Edit{
        .{ .start_byte = 0, .end_byte = 2, .replacement = "1" },
    };
    const edits2 = [_]Edit{
        .{ .start_byte = 1, .end_byte = 3, .replacement = "2" },
        .{ .start_byte = 4, .end_byte = 6, .replacement = "2" },
    };
    const edits3 = [_]Edit{
        .{ .start_byte = 5, .end_byte = 7, .replacement = "3" },
    };
    const fixes = [_]Fix{
        .{ .description = "fix1", .safety = .safe, .edits = &edits1 },
        .{ .description = "fix2", .safety = .safe, .edits = &edits2 },
        .{ .description = "fix3", .safety = .safe, .edits = &edits3 },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("1CDE3H", result.content);
    try std.testing.expectEqual(@as(usize, 2), result.edits_applied);
    try std.testing.expectEqual(@as(usize, 1), result.fixes_skipped);
}

test "a fix whose own edits overlap applies none of them" {
    const allocator = std.testing.allocator;
    const source = "ABCD";
    const edits = [_]Edit{
        .{ .start_byte = 0, .end_byte = 2, .replacement = "X" },
        .{ .start_byte = 1, .end_byte = 3, .replacement = "Y" },
    };
    const fixes = [_]Fix{
        .{ .description = "self-conflicting", .safety = .safe, .edits = &edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("ABCD", result.content);
    try std.testing.expectEqual(@as(usize, 0), result.edits_applied);
    // Not reported: re-running would drop it again, so telling the user to
    // re-run would never stop being true.
    try std.testing.expectEqual(@as(usize, 0), result.fixes_skipped);
}

test "a fix that loses to a self-conflicting fix is not reported" {
    const allocator = std.testing.allocator;
    const source = "ABCDEFGHIJ";
    // fix1's first edit beats fix2, then fix1 falls to its own second edit.
    // Nothing was applied, so pointing the user at a re-run would be a lie:
    // the same two fixes would collide the same way again.
    const edits1 = [_]Edit{
        .{ .start_byte = 0, .end_byte = 6, .replacement = "1" },
        .{ .start_byte = 2, .end_byte = 8, .replacement = "1" },
    };
    const edits2 = [_]Edit{.{ .start_byte = 1, .end_byte = 3, .replacement = "2" }};
    const fixes = [_]Fix{
        .{ .description = "self-conflicting", .safety = .safe, .edits = &edits1 },
        .{ .description = "victim", .safety = .safe, .edits = &edits2 },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("ABCDEFGHIJ", result.content);
    try std.testing.expectEqual(@as(usize, 0), result.edits_applied);
    try std.testing.expectEqual(@as(usize, 0), result.fixes_skipped);
}

test "a drop that frees a range takes two sweeps to settle" {
    const allocator = std.testing.allocator;
    const source = "ABCDEFGHIJ";
    // fix1 wins at 0..2 and drops fix2; fix2's 4..6 edit going away lets fix3
    // in at 5..7, which in turn drops fix4 — a second sweep decides fix4.
    const edits1 = [_]Edit{.{ .start_byte = 0, .end_byte = 2, .replacement = "1" }};
    const edits2 = [_]Edit{
        .{ .start_byte = 1, .end_byte = 3, .replacement = "2" },
        .{ .start_byte = 4, .end_byte = 6, .replacement = "2" },
    };
    const edits3 = [_]Edit{.{ .start_byte = 5, .end_byte = 7, .replacement = "3" }};
    const edits4 = [_]Edit{.{ .start_byte = 6, .end_byte = 8, .replacement = "4" }};
    const fixes = [_]Fix{
        .{ .description = "fix1", .safety = .safe, .edits = &edits1 },
        .{ .description = "fix2", .safety = .safe, .edits = &edits2 },
        .{ .description = "fix3", .safety = .safe, .edits = &edits3 },
        .{ .description = "fix4", .safety = .safe, .edits = &edits4 },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("1CDE3HIJ", result.content);
    try std.testing.expectEqual(@as(usize, 2), result.edits_applied);
    try std.testing.expectEqual(@as(usize, 2), result.fixes_skipped);
}

test "two insertions at the same byte both survive, in registry order" {
    const allocator = std.testing.allocator;
    const source = "AB";
    const edits1 = [_]Edit{
        .{ .start_byte = 1, .end_byte = 1, .replacement = "1" },
    };
    const edits2 = [_]Edit{
        .{ .start_byte = 1, .end_byte = 1, .replacement = "2" },
    };
    const fixes = [_]Fix{
        .{ .description = "fix1", .safety = .safe, .edits = &edits1 },
        .{ .description = "fix2", .safety = .safe, .edits = &edits2 },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("A12B", result.content);
    try std.testing.expectEqual(@as(usize, 2), result.edits_applied);
    try std.testing.expectEqual(@as(usize, 0), result.fixes_skipped);
}

test "identical insertions at the same anchor are applied once (#300)" {
    const allocator = std.testing.allocator;
    const source = "  uses: actions/checkout@v4\n";
    const anchor = std.mem.indexOfScalar(u8, source, '\n').?;
    const with_block = "\n  with:\n    persist-credentials: false";
    const edits1 = [_]Edit{
        .{ .start_byte = anchor, .end_byte = anchor, .replacement = with_block },
    };
    const edits2 = [_]Edit{
        .{ .start_byte = anchor, .end_byte = anchor, .replacement = with_block },
    };
    const fixes = [_]Fix{
        .{ .description = "SEC015", .safety = .unsafe, .edits = &edits1 },
        .{ .description = "SEC018", .safety = .unsafe, .edits = &edits2 },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings(
        "  uses: actions/checkout@v4\n  with:\n    persist-credentials: false\n",
        result.content,
    );
    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
    try std.testing.expectEqual(@as(usize, 0), result.fixes_skipped);
}

test "insertions of the same key with different bodies drop both fixes" {
    const allocator = std.testing.allocator;
    const source = "  uses: actions/setup-node@v4\n";
    const anchor = std.mem.indexOfScalar(u8, source, '\n').?;
    const edits1 = [_]Edit{
        .{ .start_byte = anchor, .end_byte = anchor, .replacement = "\n  with:\n    cache: npm" },
    };
    const edits2 = [_]Edit{
        .{ .start_byte = anchor, .end_byte = anchor, .replacement = "\n  with:\n    cache: yarn" },
    };
    const fixes = [_]Fix{
        .{ .description = "fix1", .safety = .safe, .edits = &edits1 },
        .{ .description = "fix2", .safety = .safe, .edits = &edits2 },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings(source, result.content);
    try std.testing.expectEqual(@as(usize, 0), result.edits_applied);
    try std.testing.expectEqual(@as(usize, 0), result.fixes_skipped);
}

test "a conflicting key drops its duplicates too, not just the pair" {
    const allocator = std.testing.allocator;
    const source = "  uses: actions/setup-node@v4\n";
    const anchor = std.mem.indexOfScalar(u8, source, '\n').?;
    const npm = "\n  with:\n    cache: npm";
    const edits1 = [_]Edit{.{ .start_byte = anchor, .end_byte = anchor, .replacement = npm }};
    const edits2 = [_]Edit{.{ .start_byte = anchor, .end_byte = anchor, .replacement = npm }};
    const edits3 = [_]Edit{
        .{ .start_byte = anchor, .end_byte = anchor, .replacement = "\n  with:\n    cache: yarn" },
    };
    const fixes = [_]Fix{
        .{ .description = "fix1", .safety = .safe, .edits = &edits1 },
        .{ .description = "fix2", .safety = .safe, .edits = &edits2 },
        .{ .description = "fix3", .safety = .safe, .edits = &edits3 },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings(source, result.content);
    try std.testing.expectEqual(@as(usize, 0), result.edits_applied);
    try std.testing.expectEqual(@as(usize, 0), result.fixes_skipped);
}

test "insertions of different keys at one anchor both survive" {
    const allocator = std.testing.allocator;
    const source = "  build:\n";
    const anchor: usize = 0;
    const edits1 = [_]Edit{
        .{ .start_byte = anchor, .end_byte = anchor, .replacement = "  timeout-minutes: 30\n" },
    };
    const edits2 = [_]Edit{
        .{ .start_byte = anchor, .end_byte = anchor, .replacement = "  permissions:\n    contents: read\n" },
    };
    const fixes = [_]Fix{
        .{ .description = "BP001", .safety = .safe, .edits = &edits1 },
        .{ .description = "PERM", .safety = .safe, .edits = &edits2 },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings(
        "  timeout-minutes: 30\n  permissions:\n    contents: read\n  build:\n",
        result.content,
    );
    try std.testing.expectEqual(@as(usize, 2), result.edits_applied);
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

test "applyFixes: newline insertion after a value skips the trailing comment" {
    const allocator = std.testing.allocator;
    const source = "uses: actions/checkout@abc # v4.2.2\nrun: x";
    const value_end = std.mem.indexOf(u8, source, " # v4").?;
    const edits = [_]Edit{.{ .start_byte = value_end, .end_byte = value_end, .replacement = "\nwith:\n  persist-credentials: false" }};
    const fixes = [_]Fix{.{ .description = "t", .safety = .safe, .edits = &edits }};

    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);
    try std.testing.expectEqualStrings(
        "uses: actions/checkout@abc # v4.2.2\nwith:\n  persist-credentials: false\nrun: x",
        result.content,
    );
}

test "applyFixes: newline insertion keeps CRLF line ending after the comment" {
    const allocator = std.testing.allocator;
    const source = "uses: a@b # v1\r\nrun: x";
    const value_end = std.mem.indexOf(u8, source, " # v1").?;
    const edits = [_]Edit{.{ .start_byte = value_end, .end_byte = value_end, .replacement = "\nwith: {}" }};
    const fixes = [_]Fix{.{ .description = "t", .safety = .safe, .edits = &edits }};

    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);
    try std.testing.expectEqualStrings("uses: a@b # v1\nwith: {}\r\nrun: x", result.content);
}

test "applyFixes: newline insertion does not move past non-comment text" {
    const allocator = std.testing.allocator;
    const source = "key: value rest";
    const edits = [_]Edit{.{ .start_byte = 10, .end_byte = 10, .replacement = "\nnew: 1" }};
    const fixes = [_]Fix{.{ .description = "t", .safety = .safe, .edits = &edits }};

    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);
    try std.testing.expectEqualStrings("key: value\nnew: 1 rest", result.content);
}

test "applyFixes: replacement edits are never snapped" {
    const allocator = std.testing.allocator;
    const source = "a: b # c";
    const edits = [_]Edit{.{ .start_byte = 3, .end_byte = 4, .replacement = "\nz" }};
    const fixes = [_]Fix{.{ .description = "t", .safety = .safe, .edits = &edits }};

    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);
    try std.testing.expectEqualStrings("a: \nz # c", result.content);
}
