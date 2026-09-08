//! ネットワーク由来のルールが GitHub API からデータを得られなかったことを
//! 記録する。取得失敗を握り潰すと「指摘が無かった」と「調べられなかった」が
//! 利用者から区別できず、CI がグリーンのまま実問題を見逃す (#304)。

const std = @import("std");

pub const Rule = enum {
    sc003,
    sc004,
    sc005,
    sc006,
    sc008,

    pub fn id(self: Rule) []const u8 {
        return switch (self) {
            .sc003 => "SC003",
            .sc004 => "SC004",
            .sc005 => "SC005",
            .sc006 => "SC006",
            .sc008 => "SC008",
        };
    }
};

pub const rule_count = @typeInfo(Rule).@"enum".fields.len;

var unavailable: u8 = 0;

fn bit(rule: Rule) u8 {
    return @as(u8, 1) << @intFromEnum(rule);
}

pub fn markUnavailable(rule: Rule) void {
    unavailable |= bit(rule);
}

pub fn isUnavailable(rule: Rule) bool {
    return unavailable & bit(rule) != 0;
}

pub fn reset() void {
    unavailable = 0;
}

/// `note: SC003, SC005 skipped (github api unreachable)` の 1 行を書く。
pub fn writeNote(w: *std.Io.Writer, ids: []const []const u8) !void {
    if (ids.len == 0) return;
    try w.writeAll("note: ");
    for (ids, 0..) |id, i| {
        if (i > 0) try w.writeAll(", ");
        try w.writeAll(id);
    }
    try w.writeAll(" skipped (github api unreachable)\n");
}

const testing = std.testing;

test "reset clears every mark" {
    reset();
    markUnavailable(.sc003);
    markUnavailable(.sc008);
    try testing.expect(isUnavailable(.sc003));
    try testing.expect(isUnavailable(.sc008));

    reset();
    for (std.enums.values(Rule)) |rule| {
        try testing.expect(!isUnavailable(rule));
    }
}

test "markUnavailable is idempotent and independent per rule" {
    reset();
    defer reset();

    markUnavailable(.sc005);
    markUnavailable(.sc005);
    try testing.expect(isUnavailable(.sc005));
    try testing.expect(!isUnavailable(.sc004));
    try testing.expect(!isUnavailable(.sc006));
}

test "writeNote formats a single line" {
    var buf: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeNote(&w, &.{ "SC003", "SC005" });
    try testing.expectEqualStrings("note: SC003, SC005 skipped (github api unreachable)\n", w.buffered());
}

test "writeNote is silent for an empty list" {
    var buf: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeNote(&w, &.{});
    try testing.expectEqualStrings("", w.buffered());
}
