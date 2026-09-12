const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");

const engine = @import("engine.zig");
const rest_fallback = @import("rest_fallback.zig");
const net_status = @import("net_status.zig");
const ref_cache = @import("ref_cache.zig");

const Allocator = std.mem.Allocator;
const DiagnosticList = diagnostics.DiagnosticList;
const spans = @import("spans.zig");
const Step = workflow_types.Step;
const ActionRef = workflow_types.ActionRef;
const Job = workflow_types.Job;
const Workflow = workflow_types.Workflow;
const isValidGitHubComponent = engine.isValidGitHubComponent;

var cache: ref_cache.RefCache(bool) = .{};

pub fn initArchived(backing_allocator: Allocator, offline: bool) void {
    cache.init(backing_allocator, offline);
}

pub fn deinitArchived() void {
    cache.deinit();
}

pub fn isActive() bool {
    return cache.isActive();
}

pub fn checkArchivedAction(step: *const Step, list: *DiagnosticList) void {
    const alloc = cache.allocator() orelse return;

    const action_ref = step.uses orelse return;
    if (action_ref.is_local or action_ref.is_docker) return;
    const owner = action_ref.owner orelse return;
    const repo = action_ref.repo orelse return;
    if (!isValidGitHubComponent(owner) or !isValidGitHubComponent(repo)) return;

    // 取得できなければアーカイブ済みかどうかを判定していない。無指摘と
    // 区別できるよう記録する (#304)。
    const is_archived = lookupOrFetch(alloc, owner, repo) orelse {
        net_status.markUnavailable(.sc004);
        return;
    };

    if (is_archived) {
        list.append(.{
            .rule_id = "SC004",
            .severity = .warning,
            .message = "action references an archived repository that is no longer maintained",
            .span = spans.usesSpan(step),
            .fix_hint = "migrate to an actively maintained alternative",
        }) catch return;
    }
}

pub fn setCachedResult(owner: []const u8, repo: []const u8, is_archived: bool) void {
    const key = cache.makeKey("{s}/{s}", .{ owner, repo }) orelse return;
    cache.put(key, is_archived);
}

/// Lets the prefetch pipeline tell "already answered" apart from "still to
/// fetch" without triggering the REST fallback `lookupOrFetch` would.
pub fn hasCachedResult(owner: []const u8, repo: []const u8) bool {
    const key = cache.makeKey("{s}/{s}", .{ owner, repo }) orelse return false;
    return cache.contains(key);
}

fn lookupOrFetch(alloc: Allocator, owner: []const u8, repo: []const u8) ?bool {
    const key = cache.makeKey("{s}/{s}", .{ owner, repo }) orelse return null;
    if (cache.get(key)) |cached| return cached;

    const result = rest_fallback.fetchArchiveStatus(alloc, owner, repo) catch return null;
    cache.put(key, result);
    return result;
}

const testing = std.testing;

const sc004_rule = [_]engine.Rule{
    .{
        .id = "SC004",
        .name = "archived-uses",
        .description = "test",
        .severity = .warning,
        .category = .dependency,
        .check_step = &checkArchivedAction,
    },
};

test "SC004: offline mode produces no diagnostics" {
    const steps = [_]Step{.{ .uses = ActionRef.parse("some-org/some-repo@v1") }};
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .name = "CI", .on = .{ .events = &.{} }, .jobs = &jobs };

    const eng = engine.Engine.init(&sc004_rule);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.items.items.len);
}

test "SC004: detects archived action" {
    initArchived(testing.allocator, false);
    defer deinitArchived();

    setCachedResult("archived-org", "archived-repo", true);

    const steps = [_]Step{.{ .uses = ActionRef.parse("archived-org/archived-repo@v1") }};
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .name = "CI", .on = .{ .events = &.{} }, .jobs = &jobs };

    const eng = engine.Engine.init(&sc004_rule);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.items.items.len);
    try testing.expectEqualStrings("SC004", list.items.items[0].rule_id);
}

test "SC004: active repo not flagged" {
    initArchived(testing.allocator, false);
    defer deinitArchived();

    setCachedResult("active-org", "active-repo", false);

    const steps = [_]Step{.{ .uses = ActionRef.parse("active-org/active-repo@v1") }};
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .name = "CI", .on = .{ .events = &.{} }, .jobs = &jobs };

    const eng = engine.Engine.init(&sc004_rule);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.items.items.len);
}

test "SC004: local action skipped" {
    initArchived(testing.allocator, false);
    defer deinitArchived();

    const steps = [_]Step{.{ .uses = ActionRef.parse("./local-action") }};
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .name = "CI", .on = .{ .events = &.{} }, .jobs = &jobs };

    const eng = engine.Engine.init(&sc004_rule);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.items.items.len);
}

test "SC004: docker action skipped" {
    initArchived(testing.allocator, false);
    defer deinitArchived();

    const steps = [_]Step{.{ .uses = ActionRef.parse("docker://alpine:3.18") }};
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .name = "CI", .on = .{ .events = &.{} }, .jobs = &jobs };

    const eng = engine.Engine.init(&sc004_rule);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.items.items.len);
}

test "SC004: step without uses skipped" {
    initArchived(testing.allocator, false);
    defer deinitArchived();

    const steps = [_]Step{.{ .run = "echo hello" }};
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .name = "CI", .on = .{ .events = &.{} }, .jobs = &jobs };

    const eng = engine.Engine.init(&sc004_rule);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.items.items.len);
}

test "SC004: same repo flagged in multiple steps (cache hit)" {
    initArchived(testing.allocator, false);
    defer deinitArchived();

    setCachedResult("archived-org", "archived-repo", true);

    const steps = [_]Step{
        .{ .uses = ActionRef.parse("archived-org/archived-repo@v1") },
        .{ .uses = ActionRef.parse("archived-org/archived-repo@v2") },
    };
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .name = "CI", .on = .{ .events = &.{} }, .jobs = &jobs };

    const eng = engine.Engine.init(&sc004_rule);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 2), list.items.items.len);
}

test "SC004: SHA-pinned archived action still detected" {
    initArchived(testing.allocator, false);
    defer deinitArchived();

    setCachedResult("archived-org", "archived-repo", true);

    const steps = [_]Step{
        .{ .uses = ActionRef.parse("archived-org/archived-repo@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0") },
    };
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .name = "CI", .on = .{ .events = &.{} }, .jobs = &jobs };

    const eng = engine.Engine.init(&sc004_rule);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.items.items.len);
}

test "SC004: invalid owner characters rejected" {
    initArchived(testing.allocator, false);
    defer deinitArchived();

    setCachedResult("archived-org", "archived-repo", true);

    const steps = [_]Step{.{ .uses = ActionRef.parse("archived?org/archived-repo@v1") }};
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .name = "CI", .on = .{ .events = &.{} }, .jobs = &jobs };

    const eng = engine.Engine.init(&sc004_rule);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.items.items.len);
}

test "SC004: invalid repo characters rejected" {
    initArchived(testing.allocator, false);
    defer deinitArchived();

    setCachedResult("archived-org", "archived-repo", true);

    const steps = [_]Step{.{ .uses = ActionRef.parse("archived-org/archived#repo@v1") }};
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .name = "CI", .on = .{ .events = &.{} }, .jobs = &jobs };

    const eng = engine.Engine.init(&sc004_rule);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.items.items.len);
}
