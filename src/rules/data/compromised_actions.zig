const std = @import("std");

pub const CompromisedAction = struct {
    owner: []const u8,
    repo: []const u8,
    shas: []const []const u8,
    tags: []const []const u8,
    advisory_url: []const u8,
    disclosed: []const u8,
};

/// `{"v1", "v2", ... "v<last>"}` — the tj-actions advisory covers every major
/// tag, so generate them instead of listing 45 literals.
fn majorTagRange(comptime first: u8, comptime last: u8) [last - first + 1][]const u8 {
    @setEvalBranchQuota(10_000);
    var out: [last - first + 1][]const u8 = undefined;
    for (&out, first..) |*slot, major| {
        slot.* = std.fmt.comptimePrint("v{d}", .{major});
    }
    return out;
}

pub const compromised_actions = [_]CompromisedAction{
    // tj-actions/changed-files compromise (GHSA-mrrh-fwg8-r2c3, 2025-03-14).
    // Many existing tags were retroactively re-pointed to the malicious commit.
    .{
        .owner = "tj-actions",
        .repo = "changed-files",
        .shas = &.{
            "0e58ed8671d6b60d0890c21b07f8835ace038e67",
        },
        .tags = &majorTagRange(1, 45),
        .advisory_url = "https://github.com/advisories/GHSA-mrrh-fwg8-r2c3",
        .disclosed = "2025-03-14",
    },
    // reviewdog/action-setup compromise (GHSA-jw3v-8pjj-r4q9, 2025-03-11).
    // Cascading supply-chain incident leading to tj-actions compromise.
    .{
        .owner = "reviewdog",
        .repo = "action-setup",
        .shas = &.{
            "f0d342625c5d40c98e7c1a0cd6c0d8bc2f7f9e4e",
        },
        .tags = &.{
            "v1",
        },
        .advisory_url = "https://github.com/advisories/GHSA-jw3v-8pjj-r4q9",
        .disclosed = "2025-03-11",
    },
};

// ── Integrity tests ──

fn isHexLower(s: []const u8) bool {
    for (s) |c| {
        if (!std.ascii.isHex(c) or std.ascii.isUpper(c)) return false;
    }
    return true;
}

fn isYyyyMmDd(s: []const u8) bool {
    if (s.len != 10) return false;
    if (s[4] != '-' or s[7] != '-') return false;
    for ([_]usize{ 0, 1, 2, 3, 5, 6, 8, 9 }) |i| {
        if (!std.ascii.isDigit(s[i])) return false;
    }
    return true;
}

test "compromised_actions: SHA entries are 40-char lowercase hex" {
    for (compromised_actions) |entry| {
        for (entry.shas) |sha| {
            try std.testing.expectEqual(@as(usize, 40), sha.len);
            try std.testing.expect(isHexLower(sha));
        }
    }
}

test "compromised_actions: disclosed dates are YYYY-MM-DD" {
    for (compromised_actions) |entry| {
        try std.testing.expect(isYyyyMmDd(entry.disclosed));
    }
}

test "compromised_actions: advisory_url and owner/repo are non-empty" {
    for (compromised_actions) |entry| {
        try std.testing.expect(entry.advisory_url.len > 0);
        try std.testing.expect(entry.owner.len > 0);
        try std.testing.expect(entry.repo.len > 0);
        try std.testing.expect(entry.shas.len > 0 or entry.tags.len > 0);
    }
}
