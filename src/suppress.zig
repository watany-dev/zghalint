//! Inline `# zghalint-disable-line` / `zghalint-disable-next-line` comments.
//!
//! The YAML AST drops comments, so this walks tokenizer comment tokens on the
//! source and matches them against diagnostic start lines (C3 / #558).

const std = @import("std");
const tokenizer = @import("yaml/tokenizer.zig");

pub const Suppression = struct {
    line: u32,
    /// Empty means every rule on `line`.
    ids: []const []const u8,
};

pub fn covers(suppressions: []const Suppression, line: u32, rule_id: []const u8) bool {
    for (suppressions) |item| {
        if (item.line != line) continue;
        if (item.ids.len == 0) return true;
        for (item.ids) |id| {
            if (std.mem.eql(u8, id, rule_id)) return true;
        }
    }
    return false;
}

pub fn collect(allocator: std.mem.Allocator, source: []const u8) std.mem.Allocator.Error![]Suppression {
    var tok = tokenizer.Tokenizer.init(source);
    var list: std.ArrayList(Suppression) = .empty;
    errdefer list.deinit(allocator);

    while (true) {
        const token = tok.next();
        if (token.kind == .eof) break;
        if (token.kind != .comment) continue;
        const parsed = parseDirective(token.slice(source)) orelse continue;
        const ids = try splitIds(allocator, parsed.ids_text);
        try list.append(allocator, .{
            .line = if (parsed.next_line) token.line + 1 else token.line,
            .ids = ids,
        });
    }
    return list.toOwnedSlice(allocator);
}

const Parsed = struct {
    next_line: bool,
    ids_text: []const u8,
};

fn parseDirective(comment: []const u8) ?Parsed {
    if (comment.len == 0 or comment[0] != '#') return null;
    var rest = std.mem.trim(u8, comment[1..], " \t");
    const next_kw = "zghalint-disable-next-line";
    const line_kw = "zghalint-disable-line";
    const next_line = std.mem.startsWith(u8, rest, next_kw);
    const kw = if (next_line) next_kw else if (std.mem.startsWith(u8, rest, line_kw)) line_kw else return null;
    rest = rest[kw.len..];
    if (rest.len > 0 and rest[0] != ' ' and rest[0] != '\t') return null;
    return .{ .next_line = next_line, .ids_text = std.mem.trim(u8, rest, " \t") };
}

fn splitIds(allocator: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]const []const u8 {
    if (text.len == 0) return &.{};
    var list: std.ArrayList([]const u8) = .empty;
    errdefer list.deinit(allocator);
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |part| {
        const id = std.mem.trim(u8, part, " \t");
        if (id.len == 0) continue;
        try list.append(allocator, id);
    }
    return list.toOwnedSlice(allocator);
}

test "parseDirective recognizes line and next-line" {
    const line = parseDirective("# zghalint-disable-line SEC001, SEC002").?;
    try std.testing.expect(!line.next_line);
    try std.testing.expectEqualStrings("SEC001, SEC002", line.ids_text);

    const next = parseDirective("#  zghalint-disable-next-line").?;
    try std.testing.expect(next.next_line);
    try std.testing.expectEqualStrings("", next.ids_text);

    try std.testing.expect(parseDirective("# zghalint-disable-lineSEC001") == null);
    try std.testing.expect(parseDirective("# zizmor: ignore[unpinned-uses]") == null);
}

test "collect maps comments onto diagnostic lines" {
    const source =
        \\# zghalint-disable-next-line SEC001
        \\- uses: actions/checkout@v4
        \\- uses: actions/setup-node@v4  # zghalint-disable-line SEC001,SEC002
        \\
    ;
    const items = try collect(std.testing.allocator, source);
    defer {
        for (items) |item| std.testing.allocator.free(item.ids);
        std.testing.allocator.free(items);
    }
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqual(@as(u32, 2), items[0].line);
    try std.testing.expectEqual(@as(usize, 1), items[0].ids.len);
    try std.testing.expectEqualStrings("SEC001", items[0].ids[0]);
    try std.testing.expectEqual(@as(u32, 3), items[1].line);
    try std.testing.expectEqual(@as(usize, 2), items[1].ids.len);
    try std.testing.expect(covers(items, 2, "SEC001"));
    try std.testing.expect(!covers(items, 2, "SEC002"));
    try std.testing.expect(covers(items, 3, "SEC002"));
    try std.testing.expect(!covers(items, 3, "BP001"));
}

test "empty id list suppresses every rule on that line" {
    const source = "- uses: x@v1  # zghalint-disable-line\n";
    const items = try collect(std.testing.allocator, source);
    defer std.testing.allocator.free(items);
    try std.testing.expect(covers(items, 1, "SEC001"));
    try std.testing.expect(covers(items, 1, "BP001"));
    try std.testing.expect(!covers(items, 2, "SEC001"));
}
