const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml = @import("../yaml/types.zig");

const engine = @import("engine.zig");
const rest_fallback = @import("rest_fallback.zig");

const Allocator = std.mem.Allocator;
const DiagnosticList = diagnostics.DiagnosticList;
const Span = yaml.Span;
const Step = workflow_types.Step;
const ActionRef = workflow_types.ActionRef;
const Job = workflow_types.Job;
const Workflow = workflow_types.Workflow;
const isValidGitHubComponent = engine.isValidGitHubComponent;

// ============================================================
// Module-level state for lazy caching
// ============================================================

// Use unmanaged map to avoid storing allocator (pointer stability issue).
const CacheMap = std.StringArrayHashMapUnmanaged(bool);

var archived_cache: CacheMap = .{};
var archived_arena: ?std.heap.ArenaAllocator = null;
var is_offline: bool = true;

// ============================================================
// Public API
// ============================================================

/// Initialize archived-repo check.
pub fn initArchived(backing_allocator: Allocator, offline: bool) void {
    if (offline) return;
    archived_arena = std.heap.ArenaAllocator.init(backing_allocator);
    is_offline = false;
}

/// Release all archived-check memory.
pub fn deinitArchived() void {
    if (archived_arena) |*arena| {
        archived_cache = .{};
        arena.deinit();
        archived_arena = null;
    }
    is_offline = true;
}

/// Returns `true` if archived checks are live (non-offline) so a prefetcher
/// can decide whether to issue network requests for it.
pub fn isActive() bool {
    return !is_offline and archived_arena != null;
}

/// Fetch archive status via GitHub REST. Exposed so the prefetch
/// orchestrator can batch calls outside the lazy per-step path.
pub fn fetchArchiveStatusPub(allocator: Allocator, owner: []const u8, repo: []const u8) !bool {
    return rest_fallback.fetchArchiveStatus(allocator, owner, repo);
}

/// Return the arena allocator used for cache keys, so the prefetch
/// orchestrator can stage allocations that live for the rule's lifetime.
pub fn getArenaAllocator() ?Allocator {
    return if (archived_arena) |*arena| arena.allocator() else null;
}

/// SC004 rule check: detect archived repository actions.
pub fn checkArchivedAction(step: *const Step, list: *DiagnosticList) void {
    if (is_offline) return;

    // Get stable pointer to module-level arena via |*a| capture
    const alloc = if (archived_arena) |*a| a.allocator() else return;

    const action_ref = step.uses orelse return;
    if (action_ref.is_local or action_ref.is_docker) return;
    const owner = action_ref.owner orelse return;
    const repo = action_ref.repo orelse return;
    if (!isValidGitHubComponent(owner) or !isValidGitHubComponent(repo)) return;

    const is_archived = lookupOrFetch(alloc, owner, repo) orelse return;

    if (is_archived) {
        list.append(.{
            .rule_id = "SC004",
            .severity = .warning,
            .message = "action references an archived repository that is no longer maintained",
            .span = Span.point(0, 0, 0),
            .fix_hint = "migrate to an actively maintained alternative",
        }) catch return;
    }
}

// ============================================================
// Testing helpers
// ============================================================

/// For unit tests: initialize cache without network.
pub fn initForTesting(allocator: Allocator) void {
    archived_arena = std.heap.ArenaAllocator.init(allocator);
    is_offline = false;
}

/// For unit tests: pre-populate a cache entry.
pub fn setCachedResult(owner: []const u8, repo: []const u8, is_archived: bool) void {
    const alloc = if (archived_arena) |*a| a.allocator() else return;
    const key = std.fmt.allocPrint(alloc, "{s}/{s}", .{ owner, repo }) catch return;
    archived_cache.put(alloc, key, is_archived) catch return;
}

// ============================================================
// Cache lookup with lazy fetch
// ============================================================

fn lookupOrFetch(alloc: Allocator, owner: []const u8, repo: []const u8) ?bool {
    // Build lookup key on stack to avoid allocation on cache hit
    var buf: [512]u8 = undefined;
    const key = std.fmt.bufPrint(&buf, "{s}/{s}", .{ owner, repo }) catch return null;

    if (archived_cache.get(key)) |cached| return cached;

    // Cache miss — fetch from GitHub API
    const result = rest_fallback.fetchArchiveStatus(alloc, owner, repo) catch return null;

    // Store with arena-allocated permanent key
    const permanent_key = std.fmt.allocPrint(alloc, "{s}/{s}", .{ owner, repo }) catch return null;
    archived_cache.put(alloc, permanent_key, result) catch return null;

    return result;
}

// ============================================================
// Tests
// ============================================================

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
    is_offline = true;
    archived_cache = .{};
    archived_arena = null;

    const steps = [_]Step{.{ .uses = ActionRef.parse("some-org/some-repo@v1") }};
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .name = "CI", .on = .{ .events = &.{} }, .jobs = &jobs };

    const eng = engine.Engine.init(&sc004_rule);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.items.items.len);
}

test "SC004: detects archived action" {
    initForTesting(testing.allocator);
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
    initForTesting(testing.allocator);
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
    initForTesting(testing.allocator);
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
    initForTesting(testing.allocator);
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
    initForTesting(testing.allocator);
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
    initForTesting(testing.allocator);
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
    initForTesting(testing.allocator);
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
    initForTesting(testing.allocator);
    defer deinitArchived();

    setCachedResult("archived-org", "archived-repo", true);

    // URL-unsafe owner should be silently rejected
    const steps = [_]Step{.{ .uses = ActionRef.parse("archived?org/archived-repo@v1") }};
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .name = "CI", .on = .{ .events = &.{} }, .jobs = &jobs };

    const eng = engine.Engine.init(&sc004_rule);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.items.items.len);
}

test "SC004: invalid repo characters rejected" {
    initForTesting(testing.allocator);
    defer deinitArchived();

    setCachedResult("archived-org", "archived-repo", true);

    // URL-unsafe repo should be silently rejected
    const steps = [_]Step{.{ .uses = ActionRef.parse("archived-org/archived#repo@v1") }};
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .name = "CI", .on = .{ .events = &.{} }, .jobs = &jobs };

    const eng = engine.Engine.init(&sc004_rule);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.items.items.len);
}
