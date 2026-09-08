const std = @import("std");
const util = @import("../../util.zig");

pub const TrustedAction = struct {
    owner: []const u8,
    repo: []const u8,
};

/// `owner` is how the list grows past `actions/*` later. The initial set is
/// that org only (ADR 0006 D8), so a fork such as `myorg/chekout` cannot match.
pub const trusted_actions = [_]TrustedAction{
    .{ .owner = "actions", .repo = "checkout" },
    .{ .owner = "actions", .repo = "setup-node" },
    .{ .owner = "actions", .repo = "setup-python" },
    .{ .owner = "actions", .repo = "setup-go" },
    .{ .owner = "actions", .repo = "setup-java" },
    .{ .owner = "actions", .repo = "cache" },
    .{ .owner = "actions", .repo = "upload-artifact" },
    .{ .owner = "actions", .repo = "download-artifact" },
};

test "TrustedAction: entries are well-formed" {
    for (trusted_actions) |entry| {
        try std.testing.expect(entry.owner.len > 0);
        try std.testing.expect(entry.repo.len > 0);
    }
}

test "TrustedAction: same-owner repos are more than distance 2 apart" {
    for (trusted_actions, 0..) |a, i| {
        for (trusted_actions[i + 1 ..]) |b| {
            if (!std.mem.eql(u8, a.owner, b.owner)) continue;
            try std.testing.expect(util.levenshteinDistance(a.repo, b.repo) > 2);
        }
    }
}
