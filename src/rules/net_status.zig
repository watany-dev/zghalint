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

/// ルール実行は現状シングルスレッドだが、将来 lint パスを並列化しても
/// マークが失われないよう atomic なビットマスクで持つ。
var unavailable = std.atomic.Value(u8).init(0);

fn bit(rule: Rule) u8 {
    return @as(u8, 1) << @intFromEnum(rule);
}

pub fn markUnavailable(rule: Rule) void {
    _ = unavailable.fetchOr(bit(rule), .monotonic);
}

pub fn isUnavailable(rule: Rule) bool {
    return unavailable.load(.monotonic) & bit(rule) != 0;
}

pub fn reset() void {
    unavailable.store(0, .monotonic);
}

/// `buf` に取得失敗したルール ID を Rule の宣言順 (= SC 番号順) で書き出し、
/// 埋まった範囲を返す。呼び出し側が無効化ルールを間引けるよう、整形前の
/// ID 列をそのまま渡す。
pub fn collectUnavailable(buf: *[rule_count][]const u8) []const []const u8 {
    var n: usize = 0;
    for (std.enums.values(Rule)) |rule| {
        if (!isUnavailable(rule)) continue;
        buf[n] = rule.id();
        n += 1;
    }
    return buf[0..n];
}

/// `note: SC003, SC005 skipped (github api unreachable)` の 1 行を書く。
/// 終了コードは変えない — 既存の 0/1/2 の意味を動かすと CI を壊すため。
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

test "collectUnavailable returns ids in rule order" {
    reset();
    defer reset();

    var buf: [rule_count][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 0), collectUnavailable(&buf).len);

    markUnavailable(.sc006);
    markUnavailable(.sc003);
    const ids = collectUnavailable(&buf);
    try testing.expectEqual(@as(usize, 2), ids.len);
    try testing.expectEqualStrings("SC003", ids[0]);
    try testing.expectEqualStrings("SC006", ids[1]);
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
