const std = @import("std");

pub const CompromisedAction = struct {
    owner: []const u8,
    repo: []const u8,
    shas: []const []const u8,
    tags: []const []const u8,
    advisory_url: []const u8,
    disclosed: []const u8,
};

pub const compromised_actions = [_]CompromisedAction{
    // tj-actions/changed-files compromise (GHSA-mrrh-fwg8-r2c3, 2025-03-14).
    // Many existing tags were retroactively re-pointed to the malicious commit.
    .{
        .owner = "tj-actions",
        .repo = "changed-files",
        .shas = &.{
            "0e58ed8671d6b60d0890c21b07f8835ace038e67",
        },
        .tags = &.{
            "v1",
            "v2",
            "v3",
            "v4",
            "v5",
            "v6",
            "v7",
            "v8",
            "v9",
            "v10",
            "v11",
            "v12",
            "v13",
            "v14",
            "v15",
            "v16",
            "v17",
            "v18",
            "v19",
            "v20",
            "v21",
            "v22",
            "v23",
            "v24",
            "v25",
            "v26",
            "v27",
            "v28",
            "v29",
            "v30",
            "v31",
            "v32",
            "v33",
            "v34",
            "v35",
            "v36",
            "v37",
            "v38",
            "v39",
            "v40",
            "v41",
            "v42",
            "v43",
            "v44",
            "v45",
        },
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
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return false;
    }
    return true;
}

fn isYyyyMmDd(s: []const u8) bool {
    if (s.len != 10) return false;
    if (s[4] != '-' or s[7] != '-') return false;
    for ([_]usize{ 0, 1, 2, 3, 5, 6, 8, 9 }) |i| {
        if (s[i] < '0' or s[i] > '9') return false;
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
