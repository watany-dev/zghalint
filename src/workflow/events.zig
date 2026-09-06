//! The `on:` trigger table.
//!
//! A misspelled trigger name is not rejected by GitHub: the workflow simply
//! never runs. The same is true of a bogus activity type or a filter the event
//! ignores. SYN009, SYN010 and SYN011 all read this one table so the three
//! diagnostics can never disagree about what an event accepts.

const std = @import("std");

/// Ref and path filters, by the sets GitHub actually offers.
const push_filters = &[_][]const u8{ "branches", "branches-ignore", "tags", "tags-ignore", "paths", "paths-ignore" };
/// `pull_request` runs on a branch, so the tag filters do not apply to it.
const pull_request_filters = &[_][]const u8{ "branches", "branches-ignore", "paths", "paths-ignore" };
/// `workflow_run` filters on the branch of the *triggering* run only.
const workflow_run_filters = &[_][]const u8{ "branches", "branches-ignore" };

/// `pull_request` and `pull_request_target` carry the same activity types.
const pull_request_types = &[_][]const u8{
    "assigned",           "auto_merge_disabled", "auto_merge_enabled", "closed",
    "converted_to_draft", "demilestoned",        "dequeued",           "edited",
    "enqueued",           "labeled",             "locked",             "milestoned",
    "opened",             "ready_for_review",    "reopened",           "review_request_removed",
    "review_requested",   "synchronize",         "unassigned",         "unlabeled",
    "unlocked",
};

const created_edited_deleted = &[_][]const u8{ "created", "deleted", "edited" };

pub const EventSpec = struct {
    name: []const u8,
    /// Activity types accepted under `types:`.
    ///
    /// An empty slice means the event has no activity types at all, so writing
    /// `types:` for it is itself the bug. `null` means the set is not fixed —
    /// `repository_dispatch` names are chosen by whoever sends the dispatch —
    /// so the key is accepted and its values are left unchecked.
    activity_types: ?[]const []const u8 = &.{},
    /// Ref and path filters the event accepts.
    filters: []const []const u8 = &.{},
    /// Keys that are neither `types` nor a filter, such as `workflow_call`'s
    /// `inputs`. Listed so a misspelling of one is still caught.
    extra_keys: []const []const u8 = &.{},

    /// True when `types:` may appear under the event, whether or not zghalint
    /// validates the individual names.
    pub fn acceptsTypes(self: EventSpec) bool {
        const types = self.activity_types orelse return true;
        return types.len > 0;
    }

    pub fn acceptsFilter(self: EventSpec, name: []const u8) bool {
        for (self.filters) |filter| {
            if (std.mem.eql(u8, filter, name)) return true;
        }
        return false;
    }

    /// Every key the event may carry, for "unknown key" reporting and for the
    /// edit-distance suggestion that goes with it.
    pub fn keyCandidates(self: EventSpec, buf: *[16][]const u8) []const []const u8 {
        var n: usize = 0;
        if (self.acceptsTypes()) {
            buf[n] = "types";
            n += 1;
        }
        for (self.filters) |filter| {
            buf[n] = filter;
            n += 1;
        }
        for (self.extra_keys) |key| {
            buf[n] = key;
            n += 1;
        }
        return buf[0..n];
    }
};

/// Every name accepted under `on:`: the webhook events plus the three
/// non-webhook triggers (`schedule`, `workflow_call`, `workflow_dispatch`).
///
/// The Projects Classic triggers (`project`, `project_card`, `project_column`)
/// are kept even though GitHub has retired the boards behind them, because a
/// diagnostic that calls a real — if dead — event name a typo is worse than
/// staying quiet about it.
pub const events = [_]EventSpec{
    .{ .name = "branch_protection_rule", .activity_types = created_edited_deleted },
    .{ .name = "check_run", .activity_types = &.{ "completed", "created", "requested_action", "rerequested" } },
    .{ .name = "check_suite", .activity_types = &.{ "completed", "requested", "rerequested" } },
    .{ .name = "create" },
    .{ .name = "delete" },
    .{ .name = "deployment" },
    .{ .name = "deployment_status" },
    .{ .name = "discussion", .activity_types = &.{
        "answered",    "category_changed", "created",   "deleted",
        "edited",      "labeled",          "locked",    "pinned",
        "transferred", "unanswered",       "unlabeled", "unlocked",
        "unpinned",
    } },
    .{ .name = "discussion_comment", .activity_types = created_edited_deleted },
    .{ .name = "fork" },
    .{ .name = "gollum" },
    // A preview trigger whose activity types GitHub has not documented as a
    // closed set; accept `types:` without judging the names.
    .{ .name = "image_version", .activity_types = null },
    .{ .name = "issue_comment", .activity_types = created_edited_deleted },
    .{ .name = "issues", .activity_types = &.{
        "assigned", "closed",     "deleted",   "demilestoned",
        "edited",   "labeled",    "locked",    "milestoned",
        "opened",   "pinned",     "reopened",  "transferred",
        "typed",    "unassigned", "unlabeled", "unlocked",
        "unpinned", "untyped",
    } },
    .{ .name = "label", .activity_types = created_edited_deleted },
    .{ .name = "merge_group", .activity_types = &.{ "checks_requested", "destroyed" } },
    .{ .name = "milestone", .activity_types = &.{ "closed", "created", "deleted", "edited", "opened" } },
    .{ .name = "page_build" },
    .{ .name = "project", .activity_types = &.{ "closed", "created", "deleted", "edited", "reopened" } },
    .{ .name = "project_card", .activity_types = &.{ "converted", "created", "deleted", "edited", "moved" } },
    .{ .name = "project_column", .activity_types = &.{ "created", "deleted", "moved", "updated" } },
    .{ .name = "public" },
    .{ .name = "pull_request", .activity_types = pull_request_types, .filters = pull_request_filters },
    .{ .name = "pull_request_review", .activity_types = &.{ "dismissed", "edited", "submitted" } },
    .{ .name = "pull_request_review_comment", .activity_types = created_edited_deleted },
    .{ .name = "pull_request_target", .activity_types = pull_request_types, .filters = pull_request_filters },
    .{ .name = "push", .filters = push_filters },
    .{ .name = "registry_package", .activity_types = &.{ "published", "updated" } },
    .{ .name = "release", .activity_types = &.{
        "created",   "deleted",  "edited",      "prereleased",
        "published", "released", "unpublished",
    } },
    // The type names belong to whoever POSTs the dispatch, so they cannot be
    // checked against a table.
    .{ .name = "repository_dispatch", .activity_types = null },
    .{ .name = "schedule" },
    .{ .name = "status" },
    .{ .name = "watch", .activity_types = &.{"started"} },
    .{ .name = "workflow_call", .extra_keys = &.{ "inputs", "outputs", "secrets" } },
    .{ .name = "workflow_dispatch", .extra_keys = &.{"inputs"} },
    .{
        .name = "workflow_run",
        .activity_types = &.{ "completed", "in_progress", "requested" },
        .filters = workflow_run_filters,
        .extra_keys = &.{"workflows"},
    },
};

/// The names alone, for edit-distance suggestions on an unknown trigger.
pub const trigger_names = blk: {
    var names: [events.len][]const u8 = undefined;
    for (events, 0..) |spec, i| names[i] = spec.name;
    break :blk names;
};

/// Trigger names are case-sensitive on GitHub, so `Push` is a typo, not `push`.
pub fn find(name: []const u8) ?EventSpec {
    for (events) |spec| {
        if (std.mem.eql(u8, spec.name, name)) return spec;
    }
    return null;
}

pub fn isKnown(name: []const u8) bool {
    return find(name) != null;
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

test "activity type tables are sorted and free of duplicates" {
    for (events) |spec| {
        const types = spec.activity_types orelse continue;
        if (types.len == 0) continue;
        for (types[1..], 1..) |name, i| {
            try std.testing.expect(std.mem.order(u8, types[i - 1], name) == .lt);
        }
    }
}

test "acceptsTypes distinguishes the three table shapes" {
    try std.testing.expect(find("issues").?.acceptsTypes());
    try std.testing.expect(find("repository_dispatch").?.acceptsTypes());
    try std.testing.expect(!find("push").?.acceptsTypes());
}

test "filters are event specific" {
    try std.testing.expect(find("push").?.acceptsFilter("tags"));
    try std.testing.expect(!find("pull_request").?.acceptsFilter("tags"));
    try std.testing.expect(find("pull_request").?.acceptsFilter("branches"));
    try std.testing.expect(find("workflow_run").?.acceptsFilter("branches-ignore"));
    try std.testing.expect(!find("workflow_run").?.acceptsFilter("paths"));
    try std.testing.expect(!find("issues").?.acceptsFilter("branches"));
}

test "keyCandidates covers types, filters and extras" {
    var buf: [16][]const u8 = undefined;
    const push_keys = find("push").?.keyCandidates(&buf);
    try std.testing.expectEqual(@as(usize, 6), push_keys.len);

    var call_buf: [16][]const u8 = undefined;
    const call_keys = find("workflow_call").?.keyCandidates(&call_buf);
    try std.testing.expectEqualStrings("inputs", call_keys[0]);
    try std.testing.expectEqual(@as(usize, 3), call_keys.len);
}
