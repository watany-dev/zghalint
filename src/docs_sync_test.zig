//! Keeps `docs/rules.md` and the rule registry from drifting apart.
//!
//! `docs/rules.md` is the user-facing rule reference. Nothing forced it to be
//! updated when a rule was added, and RW001 shipped without a row in the table
//! as a result. These tests fail the build when the two sides disagree, in
//! either direction. Only ID presence is checked — the prose stays free-form.

const std = @import("std");
const registry = @import("rules/registry.zig");
const expressions = @import("rules/expressions.zig");

const rules_md = @embedFile("docs_rules_md");
/// Every source that writes an `EXPRnnn` rule ID. The scan below reads these
/// so a new sub-ID cannot be introduced in one of them and stay undocumented.
const expression_sources: []const []const u8 = &.{
    @embedFile("rules/expressions.zig"),
    @embedFile("rules/needs_context.zig"),
    @embedFile("rules/steps_ref.zig"),
};

const testing = std.testing;

/// A rule row looks like `| SEC001 | unpinned-action | warning | ... |`.
/// Returns the ID cell when the line is such a row, otherwise null. Header
/// rows (`| ID | Name | ...`) and separators (`|----|---|`) fall out because
/// their first cell is not an uppercase-prefixed ID.
fn ruleRowId(line: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, line, "|")) return null;
    const rest = line[1..];
    const end = std.mem.indexOfScalar(u8, rest, '|') orelse return null;
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

fn collectDocumentedIds(alloc: std.mem.Allocator) !std.StringArrayHashMapUnmanaged(void) {
    var ids: std.StringArrayHashMapUnmanaged(void) = .empty;
    var lines = std.mem.splitScalar(u8, rules_md, '\n');
    while (lines.next()) |line| {
        const id = ruleRowId(std.mem.trimRight(u8, line, "\r")) orelse continue;
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

    var registered: std.StringArrayHashMapUnmanaged(void) = .empty;
    for (registry.documented_rule_ids) |id| try registered.put(alloc, id, {});

    var stale = false;
    for (documented.keys()) |id| {
        if (registered.contains(id)) continue;
        std.debug.print("docs/rules.md documents {s}, which no rule emits\n", .{id});
        stale = true;
    }
    if (stale) return error.DocumentedRuleNotImplemented;
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
        while (std.mem.indexOfPos(u8, src, i, needle)) |pos| {
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
