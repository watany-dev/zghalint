const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml = @import("../yaml/types.zig");

const engine = @import("engine.zig");
const rest_fallback = @import("rest_fallback.zig");

const Allocator = std.mem.Allocator;
const DiagnosticList = diagnostics.DiagnosticList;
const spans = @import("spans.zig");
const Step = workflow_types.Step;
const isValidGitHubComponent = engine.isValidGitHubComponent;

// ============================================================
// Types
// ============================================================

/// Re-exported from `rest_fallback.zig` so callers and tests that imported
/// `stale_refs.TagResolution` keep working. The canonical definition lives
/// alongside the REST resolver to avoid a circular import.
pub const TagResolution = rest_fallback.TagResolution;

// ============================================================
// Module-level cache
// ============================================================

/// Maps "owner/repo@sha" -> TagResolution.
/// null means offline mode.
var tag_cache: ?std.StringHashMap(TagResolution) = null;
var stale_refs_arena: ?std.heap.ArenaAllocator = null;

// ============================================================
// Public API
// ============================================================

/// Initialize stale-ref checker. Lazy: only sets up cache; API calls happen per-lookup.
pub fn initStaleRefs(backing_allocator: Allocator, offline: bool) void {
    if (offline) return;
    stale_refs_arena = std.heap.ArenaAllocator.init(backing_allocator);
    if (stale_refs_arena) |*arena| {
        tag_cache = std.StringHashMap(TagResolution).init(arena.allocator());
    }
}

/// Release all memory.
pub fn deinitStaleRefs() void {
    if (stale_refs_arena) |*arena| {
        arena.deinit();
        stale_refs_arena = null;
    }
    tag_cache = null;
}

/// Returns `true` if stale-refs is live (non-offline) so a prefetcher can
/// decide whether to issue network requests for it.
pub fn isActive() bool {
    return tag_cache != null;
}

/// Look up the cached tag resolution for `(owner, repo, sha)`. Returns
/// `null` if the cache is offline or has no entry. Exposed so engine
/// post-processing can decide whether SC005 actually fired for a step
/// when deciding to dedupe overlapping SC008 verdicts.
pub fn lookupCachedTagResult(
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
) ?TagResolution {
    const cache = tag_cache orelse return null;
    const alloc = if (stale_refs_arena) |*arena| arena.allocator() else return null;
    const key = std.fmt.allocPrint(alloc, "{s}/{s}@{s}", .{ owner, repo, sha }) catch return null;
    return cache.get(key);
}

/// Pre-populate the tag resolution cache. Used by the prefetch orchestrator
/// to install batched GraphQL/REST results before the engine runs.
pub fn setCachedTagResult(
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
    resolution: TagResolution,
) void {
    if (tag_cache == null) return;
    const alloc = if (stale_refs_arena) |*arena| arena.allocator() else return;
    const key = std.fmt.allocPrint(alloc, "{s}/{s}@{s}", .{ owner, repo, sha }) catch return;
    tag_cache.?.put(key, resolution) catch return;
}

/// Rule check function for SC005.
pub fn checkStaleActionRef(step: *const Step, list: *DiagnosticList) void {
    var cache = &(tag_cache orelse return); // null => offline, skip
    const action_ref = step.uses orelse return;
    if (!action_ref.is_pinned) return;
    if (action_ref.is_local or action_ref.is_docker) return;
    const owner = action_ref.owner orelse return;
    const repo = action_ref.repo orelse return;
    const sha = action_ref.ref orelse return;
    if (!isValidGitHubComponent(owner) or !isValidGitHubComponent(repo)) return;

    const allocator = if (stale_refs_arena) |*arena| arena.allocator() else return;
    const key = std.fmt.allocPrint(allocator, "{s}/{s}@{s}", .{ owner, repo, sha }) catch return;

    const resolution = cache.get(key) orelse blk: {
        const result = rest_fallback.resolveTagForSha(allocator, owner, repo, sha) catch TagResolution.unknown;
        cache.put(key, result) catch return;
        break :blk result;
    };

    if (resolution == .no_tag) {
        list.append(.{
            .rule_id = "SC005",
            .severity = .info,
            .message = "SHA-pinned action does not correspond to any known Git tag",
            .span = spans.usesSpan(step),
            .fix_hint = "verify the SHA corresponds to a tagged release",
        }) catch return;
    }
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;
const test_support = @import("../test_support.zig");
const ActionRef = workflow_types.ActionRef;
const Workflow = workflow_types.Workflow;
const Job = workflow_types.Job;
const Trigger = workflow_types.Trigger;
const Rule = engine.Rule;
const Engine = engine.Engine;
const security = @import("security.zig");

const hasDiagnostic = test_support.hasDiagnostic;

// -- Check function tests (using mock cache) --
// -- Check function tests (using mock cache) --

const TagCacheEntry = struct { key: []const u8, resolution: TagResolution };

/// Run SC005 over a one-step workflow whose step `uses` the given ref, or runs a
/// shell command when it is null, with `entries` preloaded into the tag cache.
/// A null `entries` reproduces offline mode, where there is no cache at all.
/// Module state is saved and restored so tests stay independent of each other.
/// Diagnostics only borrow string literals, so the arena can go away here.
fn runWithTagCache(entries: ?[]const TagCacheEntry, uses_ref: ?[]const u8) DiagnosticList {
    const prev_cache = tag_cache;
    const prev_arena = stale_refs_arena;
    defer {
        tag_cache = prev_cache;
        stale_refs_arena = prev_arena;
    }

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    if (entries) |es| {
        var cache = std.StringHashMap(TagResolution).init(arena.allocator());
        for (es) |e| cache.put(e.key, e.resolution) catch unreachable;
        tag_cache = cache;
        stale_refs_arena = arena;
    } else {
        tag_cache = null;
    }

    var steps = [_]Step{.{
        .uses = if (uses_ref) |r| ActionRef.parse(r) else null,
        .run = if (uses_ref == null) "echo hello" else null,
    }};
    var jobs = [_]Job{.{ .id = "test", .steps = &steps }};
    const wf = Workflow{ .jobs = &jobs, .on = .{ .events = &.{} } };

    const rules_arr = [_]Rule{.{
        .id = "SC005",
        .name = "stale-action-refs",
        .description = "SHA-pinned action does not correspond to any known Git tag",
        .severity = .info,
        .category = .dependency,
        .check_step = &checkStaleActionRef,
    }};
    return Engine.init(&rules_arr).run(testing.allocator, &wf);
}

test "SC005: stale SHA (no_tag) produces info diagnostic" {
    const sha_ref = "evil/action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    var list = runWithTagCache(&.{.{ .key = sha_ref, .resolution = .no_tag }}, sha_ref);
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SC005"));
    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expectEqual(diagnostics.Severity.info, list.get(0).severity);
}

test "SC005: tagged SHA (has_tag) produces no diagnostic" {
    const sha_ref = "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11";
    var list = runWithTagCache(&.{.{ .key = sha_ref, .resolution = .has_tag }}, sha_ref);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC005"));
}

test "SC005: unknown resolution produces no diagnostic" {
    const sha_ref = "private/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var list = runWithTagCache(&.{.{ .key = sha_ref, .resolution = .unknown }}, sha_ref);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC005"));
}

test "SC005: non-pinned action (tag ref) is skipped" {
    var list = runWithTagCache(&.{}, "actions/checkout@v4");
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC005"));
}

test "SC005: local action is skipped" {
    var list = runWithTagCache(&.{}, "./local-action");
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC005"));
}

test "SC005: docker action is skipped" {
    var list = runWithTagCache(&.{}, "docker://alpine:3.18");
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC005"));
}

test "SC005: step without uses is skipped" {
    var list = runWithTagCache(&.{}, null);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC005"));
}

test "SC005: offline mode (null cache) produces no diagnostic" {
    var list = runWithTagCache(null, "evil/action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC005"));
}

test "SC005: invalid owner characters rejected" {
    // URL-unsafe owner should be silently rejected.
    var list = runWithTagCache(&.{}, "evil?org/action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.items.items.len);
}
