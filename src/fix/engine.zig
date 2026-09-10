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
/// A fix holding an edit with an invalid byte range is dropped whole and not
/// counted as skipped: a second run reads the same source and drops it again.
fn flattenAndSort(allocator: std.mem.Allocator, fixes: []const Fix, source: []const u8) !Selection {
    var total: usize = 0;
    for (fixes) |f| {
        total += f.edits.len;
    }

    if (total == 0) return .{ .edits = &.{}, .fixes_skipped = 0 };

    const owned = try allocator.alloc(OwnedEdit, total);
    defer allocator.free(owned);

    const dropped = try allocator.alloc(bool, fixes.len);
    defer allocator.free(dropped);
    @memset(dropped, false);

    var idx: usize = 0;
    for (fixes, 0..) |f, fix_index| {
        // An edit the source does not match means the rule read the file
        // differently than it is written, so its siblings are no safer. The
        // `run:` rewrite of an env binding landed on an alias and failed while
        // the `env:` insertion beside it applied, so the file grew a binding
        // every round and never settled (fuzz).
        for (f.edits) |e| {
            if (!isValidEdit(e, source)) dropped[fix_index] = true;
        }
        if (dropped[fix_index]) continue;
        for (f.edits) |e| {
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

    dropRenameInsertCollisions(flat, source, dropped);

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

/// Drops an insertion of key K when a rename in the same mapping produces K.
/// SYN001 rewriting `prmissions:` to `permissions:` and SEC007 inserting a
/// new `permissions:` would otherwise both fire and leave SYN002 (#348).
/// The rename is kept: it preserves the existing block.
fn dropRenameInsertCollisions(flat: []const OwnedEdit, source: []const u8, dropped: []bool) void {
    for (flat) |insert_oe| {
        if (dropped[insert_oe.fix_index]) continue;
        if (insert_oe.edit.start_byte != insert_oe.edit.end_byte) continue;
        const insert_key = firstInsertedKey(insert_oe.edit.replacement) orelse continue;
        const insert_indent = insertedKeyIndent(source, insert_oe.edit);

        for (flat) |rename_oe| {
            if (rename_oe.fix_index == insert_oe.fix_index) continue;
            if (dropped[rename_oe.fix_index]) continue;
            const new_key = renamedMappingKey(source, rename_oe.edit) orelse continue;
            if (!std.ascii.eqlIgnoreCase(new_key, insert_key)) continue;
            if (lineIndent(source, rename_oe.edit.start_byte) != insert_indent) continue;
            if (!sameMappingBlock(source, insert_oe.edit.start_byte, rename_oe.edit.start_byte, insert_indent)) {
                continue;
            }
            dropped[insert_oe.fix_index] = true;
            break;
        }
    }
}

fn lineIndent(source: []const u8, byte: usize) u32 {
    var i = byte;
    while (i > 0 and source[i - 1] != '\n' and source[i - 1] != '\r') : (i -= 1) {}
    var indent: u32 = 0;
    while (i < source.len and source[i] == ' ') : (i += 1) indent += 1;
    return indent;
}

/// The key a replacement rewrites a mapping key to. Null when the edit is not
/// a key token (a value rename such as `opend` → `opened` is followed by
/// something other than `:`).
fn renamedMappingKey(source: []const u8, e: Edit) ?[]const u8 {
    if (e.start_byte == e.end_byte) return null;
    if (e.replacement.len == 0) return null;
    if (std.mem.indexOfAny(u8, e.replacement, ":\n\r \t") != null) return null;
    var i = e.end_byte;
    if (i < source.len and (source[i] == '\'' or source[i] == '"')) i += 1;
    if (i < source.len and source[i] == ':') return e.replacement;
    return null;
}

fn insertedKeyIndent(source: []const u8, e: Edit) u32 {
    const r = e.replacement;
    var i: usize = 0;
    var new_line = false;
    while (i < r.len and (r[i] == '\n' or r[i] == '\r')) : (i += 1) new_line = true;
    var indent: u32 = 0;
    while (i < r.len and r[i] == ' ') : (i += 1) indent += 1;
    if (new_line) return indent;
    return lineIndent(source, e.start_byte) + indent;
}

/// True when `a` and `b` sit in the same mapping: no intervening line is
/// indented less than `indent`. Indent 0 is the document root, so every pair
/// is in the same mapping.
fn sameMappingBlock(source: []const u8, a: usize, b: usize, indent: u32) bool {
    if (indent == 0) return true;
    const lo = @min(a, b);
    const hi = @max(a, b);
    var i = lo;
    while (i < hi) {
        while (i < hi and source[i] != '\n' and source[i] != '\r') : (i += 1) {}
        if (i >= hi) break;
        if (source[i] == '\r') i += 1;
        if (i < source.len and source[i] == '\n') i += 1;
        if (i >= hi) break;
        var spaces: u32 = 0;
        var j = i;
        while (j < source.len and source[j] == ' ') : (j += 1) spaces += 1;
        if (j >= source.len) break;
        if (source[j] == '\n' or source[j] == '\r' or source[j] == '#') continue;
        if (spaces < indent) return false;
    }
    return true;
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

/// How many of the leading (highest-byte) edits are appended at the very end of
/// a file that has no final newline, when the earliest of them would otherwise
/// continue the last line: `on: []` plus an inserted `permissions:` becomes
/// `on: []permissions: ...`, where the new key is not a key at all, so the rule
/// inserts it again every round (fuzz). Zero when no newline is owed.
///
/// `edits` is sorted descending by position, so these are exactly its first `n`
/// entries and the newline belongs in front of the `n`-th.
fn trailingInsertRun(edits: []const Edit, source: []const u8) usize {
    if (source.len == 0) return 0;
    if (source[source.len - 1] == '\n' or source[source.len - 1] == '\r') return 0;

    var n: usize = 0;
    while (n < edits.len) : (n += 1) {
        const e = edits[n];
        if (e.start_byte != source.len or e.end_byte != source.len) break;
    }
    if (n == 0) return 0;

    const first_in_source_order = edits[n - 1].replacement;
    if (first_in_source_order.len == 0) return 0;
    if (first_in_source_order[0] == '\n' or first_in_source_order[0] == '\r') return 0;
    // Only a whole line owes a newline in front of it. A replacement that does
    // not close its own line is a token meant to continue the last one.
    if (first_in_source_order[first_in_source_order.len - 1] != '\n') return 0;
    return n;
}

/// Invalid edits are dropped by `flattenAndSort` to avoid arithmetic underflow or
/// out-of-bounds reads in `applyFixes`.
fn isValidEdit(e: Edit, source: []const u8) bool {
    if (e.end_byte < e.start_byte) return false;
    if (e.end_byte > source.len) return false;
    if (e.expects) |x| {
        if (!std.mem.eql(u8, source[e.start_byte..e.end_byte], x)) return false;
    }
    if (removesLiveAnchor(e, source)) return false;
    return true;
}

fn isMarkerLead(c: u8) bool {
    return switch (c) {
        ' ', '\t', '\n', '-', ':', '[', '{', ',' => true,
        else => false,
    };
}

/// The anchor or alias name at `at`, which points at the `&` or `*`. Empty when
/// the byte is not in a position where YAML reads one, so a `&&` in a `run:`
/// script names nothing.
fn markerName(source: []const u8, at: usize) []const u8 {
    if (at > 0 and !isMarkerLead(source[at - 1])) return &.{};
    var end = at + 1;
    while (end < source.len and (std.ascii.isAlphanumeric(source[end]) or source[end] == '-' or source[end] == '_')) {
        end += 1;
    }
    return source[at + 1 .. end];
}

/// True when `e` removes an anchor something outside its range still aliases.
/// SYN011 dropping a filter key took the `&b` written on it with it, and the
/// `*b` below stopped resolving -- the next parse read no diagnostics at all.
/// A fix that cannot keep the file parsing is worse than none (fuzz).
fn removesLiveAnchor(e: Edit, source: []const u8) bool {
    var i = e.start_byte;
    while (std.mem.indexOfScalarPos(u8, source[0..e.end_byte], i, '&')) |at| {
        i = at + 1;
        const name = markerName(source, at);
        if (name.len == 0) continue;
        var j: usize = 0;
        while (std.mem.indexOfScalarPos(u8, source, j, '*')) |use| {
            j = use + 1;
            if (use >= e.start_byte and use < e.end_byte) continue;
            if (std.mem.eql(u8, markerName(source, use), name)) return true;
        }
    }
    return false;
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

    var trailing_run = trailingInsertRun(edits, source);
    var result_len: usize = source.len;
    for (edits) |e| {
        result_len = result_len - (e.end_byte - e.start_byte) + e.replacement.len;
    }
    if (trailing_run > 0) result_len += 1;

    var result = try allocator.alloc(u8, result_len);
    var src_pos: usize = source.len;
    var dst_pos: usize = result_len;

    for (edits) |e| {
        const after_len = src_pos - e.end_byte;
        dst_pos -= after_len;
        @memcpy(result[dst_pos..][0..after_len], source[e.end_byte..][0..after_len]);

        dst_pos -= e.replacement.len;
        @memcpy(result[dst_pos..][0..e.replacement.len], e.replacement);

        if (trailing_run > 0) {
            trailing_run -= 1;
            if (trailing_run == 0) {
                dst_pos -= 1;
                result[dst_pos] = '\n';
            }
        }

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

test "one edit the source does not match drops the whole fix (fuzz)" {
    const allocator = std.testing.allocator;
    // The env binding rewrites the `run:` body and inserts the `env:` key that
    // body will read. Applying only the insertion leaves a binding nothing
    // references, and the next run inserts another one.
    const source = "run: x\n";
    const edits = [_]Edit{
        .{ .start_byte = 0, .end_byte = 0, .replacement = "env:\n  T: y\n" },
        .{ .start_byte = 5, .end_byte = 6, .replacement = "$T", .expects = "y" },
    };
    const fixes = [_]Fix{
        .{ .description = "bind to env:", .safety = .unsafe, .edits = &edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings(source, result.content);
    try std.testing.expectEqual(@as(usize, 0), result.edits_applied);
    try std.testing.expectEqual(@as(usize, 0), result.fixes_skipped);
}

test "an edit that removes an anchor still aliased below is dropped (fuzz)" {
    const allocator = std.testing.allocator;
    // SYN011 removes the filter `d:` the event does not accept, and the `&b`
    // written on it goes too. The `*b` below then resolves to nothing and the
    // whole file stops parsing, so the fix is worth less than the diagnostic.
    const source = "on:\n workflow_call:\n  d: &b \njobs: *b\n";
    const edits = [_]Edit{
        .{ .start_byte = 20, .end_byte = 29, .replacement = "" },
    };
    const fixes = [_]Fix{
        .{ .description = "remove \"d\"", .safety = .safe, .edits = &edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings(source, result.content);
    try std.testing.expectEqual(@as(usize, 0), result.edits_applied);
}

test "an edit that removes an anchor nothing aliases is applied (fuzz)" {
    const allocator = std.testing.allocator;
    const source = "on:\n workflow_call:\n  d: &b \njobs: x\n";
    const edits = [_]Edit{
        .{ .start_byte = 20, .end_byte = 29, .replacement = "" },
    };
    const fixes = [_]Fix{
        .{ .description = "remove \"d\"", .safety = .safe, .edits = &edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("on:\n workflow_call:\njobs: x\n", result.content);
    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
}

test "a `&&` in a run script is not an anchor (fuzz)" {
    const allocator = std.testing.allocator;
    // `*` and `&` are shell operators far more often than YAML markers, and
    // dropping the fix over them would cost every fix inside a `run:` block.
    const source = "on: push\nx: a && b\ny: c *b\n";
    const edits = [_]Edit{
        .{ .start_byte = 9, .end_byte = 19, .replacement = "" },
    };
    const fixes = [_]Fix{
        .{ .description = "remove \"x\"", .safety = .safe, .edits = &edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("on: push\ny: c *b\n", result.content);
    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
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

test "a block entry appended to a file with no final newline opens its own line (fuzz)" {
    const allocator = std.testing.allocator;
    const source = "on: []";
    const edits = [_]Edit{
        .{ .start_byte = 6, .end_byte = 6, .replacement = "permissions: {contents: read}\n" },
    };
    const fixes = [_]Fix{
        .{ .description = "add permissions", .safety = .unsafe, .edits = &edits },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("on: []\npermissions: {contents: read}\n", result.content);
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

test "a rename onto a key drops an insertion of the same key (#348)" {
    const allocator = std.testing.allocator;
    const source =
        \\on: push
        \\prmissions:
        \\  contents: read
        \\jobs:
        \\  a:
        \\    runs-on: ubuntu-latest
        \\
    ;
    const key = std.mem.indexOf(u8, source, "prmissions").?;
    const rename = [_]Edit{
        .{ .start_byte = key, .end_byte = key + "prmissions".len, .replacement = "permissions" },
    };
    const insert = [_]Edit{
        .{ .start_byte = key, .end_byte = key, .replacement = "permissions: {contents: read}\n" },
    };
    const fixes = [_]Fix{
        .{ .description = "SYN001", .safety = .safe, .edits = &rename },
        .{ .description = "SEC007", .safety = .unsafe, .edits = &insert },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\on: push
        \\permissions:
        \\  contents: read
        \\jobs:
        \\  a:
        \\    runs-on: ubuntu-latest
        \\
    , result.content);
    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
    try std.testing.expectEqual(@as(usize, 0), result.fixes_skipped);
}

test "a job-level rename does not drop a workflow-level insertion of the same key" {
    const allocator = std.testing.allocator;
    const source =
        \\on: push
        \\jobs:
        \\  a:
        \\    permssions:
        \\      contents: read
        \\    runs-on: ubuntu-latest
        \\
    ;
    const key = std.mem.indexOf(u8, source, "permssions").?;
    const insert_at = std.mem.indexOf(u8, source, "jobs:").?;
    const rename = [_]Edit{
        .{ .start_byte = key, .end_byte = key + "permssions".len, .replacement = "permissions" },
    };
    const insert = [_]Edit{
        .{ .start_byte = insert_at, .end_byte = insert_at, .replacement = "permissions: {contents: read}\n" },
    };
    const fixes = [_]Fix{
        .{ .description = "SYN001", .safety = .safe, .edits = &rename },
        .{ .description = "SEC007", .safety = .unsafe, .edits = &insert },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\on: push
        \\permissions: {contents: read}
        \\jobs:
        \\  a:
        \\    permissions:
        \\      contents: read
        \\    runs-on: ubuntu-latest
        \\
    , result.content);
    try std.testing.expectEqual(@as(usize, 2), result.edits_applied);
}

test "a value rename does not drop an insertion of a matching key name" {
    const allocator = std.testing.allocator;
    const source =
        \\on:
        \\  pull_request:
        \\    types: [opend]
        \\jobs:
        \\  a:
        \\    runs-on: ubuntu-latest
        \\
    ;
    const value = std.mem.indexOf(u8, source, "opend").?;
    const insert_at = std.mem.indexOf(u8, source, "jobs:").?;
    const rename = [_]Edit{
        .{ .start_byte = value, .end_byte = value + "opend".len, .replacement = "opened" },
    };
    const insert = [_]Edit{
        .{ .start_byte = insert_at, .end_byte = insert_at, .replacement = "opened: true\n" },
    };
    const fixes = [_]Fix{
        .{ .description = "SYN010", .safety = .safe, .edits = &rename },
        .{ .description = "other", .safety = .safe, .edits = &insert },
    };
    const result = try applyFixes(allocator, source, &fixes);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\on:
        \\  pull_request:
        \\    types: [opened]
        \\opened: true
        \\jobs:
        \\  a:
        \\    runs-on: ubuntu-latest
        \\
    , result.content);
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
