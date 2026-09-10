const std = @import("std");
const runtime = @import("runtime.zig");
const builtin = @import("builtin");
const EmptySection = @import("workflow/types.zig").EmptySection;

/// The section key was present in source but empty (`with: {}`, `with:`), so a
/// rule must not insert a second one of its own.
pub fn hasEmptySection(sections: []const EmptySection, name: []const u8) bool {
    for (sections) |section| {
        if (std.mem.eql(u8, section.name, name)) return true;
    }
    return false;
}

pub fn actionBaseName(raw: []const u8) []const u8 {
    return if (std.mem.find(u8, raw, "@")) |pos| raw[0..pos] else raw;
}

/// ASCII-only. Inputs longer than MAX_LEN yield `std.math.maxInt(usize)` to
/// avoid pathological allocations.
pub fn levenshteinDistance(a: []const u8, b: []const u8) usize {
    return levenshteinDistanceBounded(a, b, std.math.maxInt(usize));
}

/// `levenshteinDistance`, except that it returns `maxInt(usize)` as soon as
/// the distance is known to exceed `bound`. The length difference is a lower
/// bound, and so is the smallest entry of a finished DP row, so a hopeless
/// candidate costs at most a row or two instead of the full table.
pub fn levenshteinDistanceBounded(a: []const u8, b: []const u8, bound: usize) usize {
    const MAX_LEN: usize = 64;
    if (a.len > MAX_LEN or b.len > MAX_LEN) return std.math.maxInt(usize);
    if (@max(a.len, b.len) - @min(a.len, b.len) > bound) return std.math.maxInt(usize);
    if (a.len == 0) return b.len;
    if (b.len == 0) return a.len;

    var prev: [MAX_LEN + 1]usize = undefined;
    var curr: [MAX_LEN + 1]usize = undefined;
    var i: usize = 0;
    while (i <= b.len) : (i += 1) prev[i] = i;

    i = 1;
    while (i <= a.len) : (i += 1) {
        curr[0] = i;
        var row_min: usize = curr[0];
        var j: usize = 1;
        while (j <= b.len) : (j += 1) {
            const cost: usize = if (a[i - 1] == b[j - 1]) 0 else 1;
            const del = prev[j] + 1;
            const ins = curr[j - 1] + 1;
            const sub = prev[j - 1] + cost;
            curr[j] = @min(@min(del, ins), sub);
            row_min = @min(row_min, curr[j]);
        }
        if (row_min > bound) return std.math.maxInt(usize);
        @memcpy(prev[0 .. b.len + 1], curr[0 .. b.len + 1]);
    }
    if (prev[b.len] > bound) return std.math.maxInt(usize);
    return prev[b.len];
}

/// The nearest `candidates` entry within edit distance 2, or null when the
/// input matches one exactly or two candidates tie for nearest.
pub fn didYouMean(key: []const u8, candidates: []const []const u8) ?[]const u8 {
    const max_dist: usize = 2;
    var best: ?[]const u8 = null;
    var best_dist: usize = std.math.maxInt(usize);
    var ties: usize = 0;

    for (candidates) |candidate| {
        const dist = levenshteinDistanceBounded(key, candidate, max_dist);
        if (dist == 0 or dist > max_dist) continue;
        if (dist < best_dist) {
            best = candidate;
            best_dist = dist;
            ties = 1;
        } else if (dist == best_dist) {
            ties += 1;
        }
    }

    if (ties != 1) return null;
    return best;
}

test "levenshteinDistanceBounded matches the exact distance within the bound" {
    try std.testing.expectEqual(@as(usize, 2), levenshteinDistanceBounded("kitten", "sittin", 2));
    try std.testing.expectEqual(@as(usize, 1), levenshteinDistanceBounded("chekout", "checkout", 1));
    try std.testing.expectEqual(@as(usize, 0), levenshteinDistanceBounded("abc", "abc", 0));
    try std.testing.expectEqual(std.math.maxInt(usize), levenshteinDistanceBounded("a", "abcd", 2));
    try std.testing.expectEqual(std.math.maxInt(usize), levenshteinDistanceBounded("kitten", "sitting", 2));
    try std.testing.expectEqual(std.math.maxInt(usize), levenshteinDistanceBounded("Asia/Tokyo", "Europe/Rome", 2));
}

test "levenshteinDistance basic cases" {
    try std.testing.expectEqual(@as(usize, 0), levenshteinDistance("abc", "abc"));
    try std.testing.expectEqual(@as(usize, 1), levenshteinDistance("chekout", "checkout"));
    try std.testing.expectEqual(@as(usize, 1), levenshteinDistance("runs", "run"));
    try std.testing.expectEqual(@as(usize, 1), levenshteinDistance("cache", "cach"));
    try std.testing.expectEqual(@as(usize, 2), levenshteinDistance("kitten", "sittin"));
    try std.testing.expectEqual(@as(usize, 3), levenshteinDistance("kitten", "sitting"));
    try std.testing.expectEqual(
        std.math.maxInt(usize),
        levenshteinDistance("a" ** 65, "b"),
    );
}

test "actionBaseName strips version suffix" {
    try std.testing.expectEqualStrings("actions/checkout", actionBaseName("actions/checkout@v4"));
    try std.testing.expectEqualStrings("actions/checkout", actionBaseName("actions/checkout@abc123"));
    try std.testing.expectEqualStrings("actions/checkout", actionBaseName("actions/checkout"));
    try std.testing.expectEqualStrings("", actionBaseName(""));
    try std.testing.expectEqualStrings("", actionBaseName("@v1"));
}

test "hasEmptySection matches by name" {
    const yaml_types = @import("yaml/types.zig");
    const sections = [_]EmptySection{.{ .name = "with", .span = yaml_types.Span.point(1, 1, 0) }};
    try std.testing.expect(hasEmptySection(&sections, "with"));
    try std.testing.expect(!hasEmptySection(&sections, "env"));
    try std.testing.expect(!hasEmptySection(&.{}, "with"));
}

/// `readLink` is the portable "is this path a symlink" probe, but Windows
/// answers a plain file with STATUS_NOT_A_REPARSE_POINT, which the standard
/// library has no mapping for and surfaces as `Unexpected`.
pub fn isSymlink(dir: std.Io.Dir, sub_path: []const u8) !bool {
    var link_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    if (dir.readLink(runtime.io(), sub_path, &link_buf)) |_| {
        return true;
    } else |err| switch (err) {
        error.NotLink, error.FileNotFound => return false,
        error.Unexpected => {
            if (builtin.os.tag == .windows) return false;
            return err;
        },
        else => return err,
    }
}

test "isSymlink: a plain file is not a link" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(runtime.io(), .{ .sub_path = "plain.yml", .data = "name: ci\n" });
    try std.testing.expect(!try isSymlink(tmp.dir, "plain.yml"));
    try std.testing.expect(!try isSymlink(tmp.dir, "missing.yml"));
}
