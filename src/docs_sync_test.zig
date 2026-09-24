//! Keeps `docs/rules.md` and the rule registry from drifting apart.
//!
//! `docs/rules.md` is the user-facing rule reference. Nothing forced it to be
//! updated when a rule was added, and RW001 shipped without a row in the table
//! as a result. These tests fail the build when the two sides disagree, in
//! either direction. ID presence is checked, plus the rule counts the prose
//! advertises; the rest of the prose stays free-form.

const std = @import("std");
const registry = @import("rules/registry.zig");
const expressions = @import("rules/expressions.zig");

const rules_md = @embedFile("docs_rules_md");
const readme_md = @embedFile("readme_md");
/// Every source that writes an `EXPRnnn` rule ID. The scan below reads these
/// so a new sub-ID cannot be introduced in one of them and stay undocumented.
const expression_sources: []const []const u8 = &.{
    @embedFile("rules/expressions.zig"),
    @embedFile("rules/inputs_context.zig"),
    @embedFile("rules/matrix_context.zig"),
    @embedFile("rules/needs_context.zig"),
    @embedFile("rules/secrets_context.zig"),
    @embedFile("rules/steps_ref.zig"),
    @embedFile("rules/expr_availability.zig"),
    @embedFile("rules/background_sync.zig"),
};

const testing = std.testing;

/// A rule row looks like `| SEC001 | unpinned-action | warning | ... |`.
/// Returns the ID cell when the line is such a row, otherwise null. Header
/// rows (`| ID | Name | ...`) and separators (`|----|---|`) fall out because
/// their first cell is not an uppercase-prefixed ID.
fn ruleRowId(line: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, line, "|")) return null;
    const rest = line[1..];
    const end = std.mem.findScalar(u8, rest, '|') orelse return null;
    const id = std.mem.trim(u8, rest[0..end], " ");
    if (id.len < 4) return null;

    var seen_digit = false;
    for (id) |c| {
        if (std.ascii.isDigit(c)) {
            seen_digit = true;
        } else if (!std.ascii.isUpper(c) or seen_digit) {
            return null;
        }
    }
    return if (seen_digit) id else null;
}

fn collectDocumentedIds(alloc: std.mem.Allocator) !std.array_hash_map.String(void) {
    var ids: std.array_hash_map.String(void) = .empty;
    var lines = std.mem.splitScalar(u8, rules_md, '\n');
    while (lines.next()) |line| {
        const id = ruleRowId(std.mem.trimEnd(u8, line, "\r")) orelse continue;
        try ids.put(alloc, id, {});
    }
    return ids;
}

test "docs/rules.md documents every registered rule" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var documented = try collectDocumentedIds(alloc);

    var missing = false;
    for (registry.documented_rule_ids) |id| {
        if (documented.contains(id)) continue;
        std.debug.print("rule {s} has no row in docs/rules.md\n", .{id});
        missing = true;
    }
    if (missing) return error.RuleMissingFromDocs;
}

test "docs/rules.md documents no rule that is not registered" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var documented = try collectDocumentedIds(alloc);

    var registered: std.array_hash_map.String(void) = .empty;
    for (registry.documented_rule_ids) |id| try registered.put(alloc, id, {});

    var stale = false;
    for (documented.keys()) |id| {
        if (registered.contains(id)) continue;
        std.debug.print("docs/rules.md documents {s}, which no rule emits\n", .{id});
        stale = true;
    }
    if (stale) return error.DocumentedRuleNotImplemented;
}

/// Reads the rule count written just before `pos`, which points at ` rules`.
/// Covers both spellings the docs use: `**110 rules**` and `(24 rules)`.
fn countEndingAt(src: []const u8, pos: usize) ?usize {
    var start = pos;
    while (start > 0 and std.ascii.isDigit(src[start - 1])) start -= 1;
    if (start == pos) return null;
    return std.fmt.parseInt(usize, src[start..pos], 10) catch null;
}

/// Every `<digits> rules` in `src`, in document order.
fn advertisedCounts(alloc: std.mem.Allocator, src: []const u8) ![]usize {
    var counts: std.ArrayList(usize) = .empty;
    var i: usize = 0;
    while (std.mem.findPos(u8, src, i, " rules")) |pos| {
        i = pos + " rules".len;
        const count = countEndingAt(src, pos) orelse continue;
        try counts.append(alloc, count);
    }
    return counts.toOwnedSlice(alloc);
}

test "docs advertise the registered rule count" {
    // The ID-set tests above pass no matter what the prose claims, so the
    // headline number drifted for two releases before anyone noticed.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    for ([_][]const u8{ rules_md, readme_md }) |src| {
        const counts = try advertisedCounts(alloc, src);
        try testing.expect(counts.len > 0);
        try testing.expectEqual(registry.documented_rule_ids.len, counts[0]);
    }
}

test "README category counts sum to the registered rule count" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const counts = try advertisedCounts(alloc, readme_md);
    var sum: usize = 0;
    for (counts[1..]) |count| sum += count;
    try testing.expectEqual(registry.documented_rule_ids.len, sum);
}

test "expressions: sub_rule_ids covers every emitted ID" {
    // The `EXPR` rule registers once but emits EXPR001..EXPR017, so the docs
    // check reads `sub_rule_ids` instead of the registry entry. Scanning the
    // sources keeps that list honest. Only quoted IDs count: those are the
    // string literals that end up in a diagnostic's `rule_id`, whereas prose
    // in comments mentions ranges of IDs that no rule emits.
    const needle = "\"EXPR";
    for (expression_sources) |src| {
        var i: usize = 0;
        while (std.mem.findPos(u8, src, i, needle)) |pos| {
            i = pos + needle.len;
            const id_start = pos + 1;
            const id_end = i + 3;
            if (id_end >= src.len) continue;
            const digits = src[i..id_end];
            if (!std.ascii.isDigit(digits[0]) or !std.ascii.isDigit(digits[1]) or !std.ascii.isDigit(digits[2])) continue;
            if (src[id_end] != '"') continue;

            const id = src[id_start..id_end];
            const listed = for (expressions.sub_rule_ids) |sub_id| {
                if (std.mem.eql(u8, sub_id, id)) break true;
            } else false;
            // EXPR010 and EXPR012 are registered as rules of their own.
            const owned_elsewhere = for (registry.all_rules) |rule| {
                if (std.mem.eql(u8, rule.id, id)) break true;
            } else false;
            if (!listed and !owned_elsewhere) {
                std.debug.print("{s} is emitted by an expression source but missing from sub_rule_ids\n", .{id});
                return error.SubRuleIdNotListed;
            }
        }
    }
}
