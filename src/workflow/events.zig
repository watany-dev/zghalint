//! The `on:` trigger name table.
//!
//! A misspelled trigger name is not rejected by GitHub: the workflow simply
//! never runs. SYN009 catches that by checking every `on:` key against this
//! table.

const std = @import("std");

/// Every name accepted under `on:`: the webhook events plus the three
/// non-webhook triggers (`schedule`, `workflow_call`, `workflow_dispatch`).
///
/// The Projects Classic triggers (`project`, `project_card`, `project_column`)
/// are kept even though GitHub has retired the boards behind them, because a
/// diagnostic that calls a real — if dead — event name a typo is worse than
/// staying quiet about it.
pub const trigger_names = [_][]const u8{
    "branch_protection_rule",
    "check_run",
    "check_suite",
    "create",
    "delete",
    "deployment",
    "deployment_status",
    "discussion",
    "discussion_comment",
    "fork",
    "gollum",
    "image_version",
    "issue_comment",
    "issues",
    "label",
    "merge_group",
    "milestone",
    "page_build",
    "project",
    "project_card",
    "project_column",
    "public",
    "pull_request",
    "pull_request_review",
    "pull_request_review_comment",
    "pull_request_target",
    "push",
    "registry_package",
    "release",
    "repository_dispatch",
    "schedule",
    "status",
    "watch",
    "workflow_call",
    "workflow_dispatch",
    "workflow_run",
};

/// Trigger names are case-sensitive on GitHub, so `Push` is a typo, not `push`.
pub fn isKnown(name: []const u8) bool {
    for (trigger_names) |trigger| {
        if (std.mem.eql(u8, trigger, name)) return true;
    }
    return false;
}

test "isKnown accepts webhook and non-webhook triggers" {
    try std.testing.expect(isKnown("push"));
    try std.testing.expect(isKnown("pull_request"));
    try std.testing.expect(isKnown("discussion_comment"));
    try std.testing.expect(isKnown("merge_group"));
    try std.testing.expect(isKnown("schedule"));
    try std.testing.expect(isKnown("workflow_dispatch"));
    try std.testing.expect(isKnown("workflow_call"));
}

test "isKnown rejects typos and unrelated names" {
    try std.testing.expect(!isKnown("pull_reqeust"));
    try std.testing.expect(!isKnown("push_tag"));
    try std.testing.expect(!isKnown("Push"));
    try std.testing.expect(!isKnown(""));
}

test "trigger_names is sorted and free of duplicates" {
    for (trigger_names[1..], 1..) |name, i| {
        try std.testing.expect(std.mem.order(u8, trigger_names[i - 1], name) == .lt);
    }
}
