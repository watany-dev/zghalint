const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml = @import("../yaml/types.zig");

const engine = @import("engine.zig");
const rest_fallback = @import("rest_fallback.zig");

const Allocator = std.mem.Allocator;
const DiagnosticList = diagnostics.DiagnosticList;
const spans = @import("spans.zig");
const Span = yaml.Span;
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

/// Return the arena allocator used for cache keys, so the prefetch
/// orchestrator can stage allocations that live for the rule's lifetime.
pub fn getArenaAllocator() ?Allocator {
    return if (stale_refs_arena) |*arena| arena.allocator() else null;
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

test "SC005: stale SHA (no_tag) produces info diagnostic" {
    // Save and restore module state
    const prev_cache = tag_cache;
    const prev_arena = stale_refs_arena;
    defer {
        tag_cache = prev_cache;
        stale_refs_arena = prev_arena;
    }

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var cache = std.StringHashMap(TagResolution).init(alloc);
    cache.put("evil/action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", .no_tag) catch unreachable;
    tag_cache = cache;
    stale_refs_arena = arena;

    var steps = [_]Step{.{
        .uses = ActionRef.parse("evil/action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
    }};
    var jobs = [_]Job{.{ .id = "test", .steps = &steps }};
    const wf = Workflow{
        .jobs = &jobs,
        .on = .{ .events = &.{} },
    };

    const rules_arr = [_]Rule{.{
        .id = "SC005",
        .name = "stale-action-refs",
        .description = "SHA-pinned action does not correspond to any known Git tag",
        .severity = .info,
        .category = .dependency,
        .check_step = &checkStaleActionRef,
    }};
    const eng = Engine.init(&rules_arr);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SC005"));
    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expectEqual(diagnostics.Severity.info, list.get(0).severity);
}

test "SC005: tagged SHA (has_tag) produces no diagnostic" {
    const prev_cache = tag_cache;
    const prev_arena = stale_refs_arena;
    defer {
        tag_cache = prev_cache;
        stale_refs_arena = prev_arena;
    }

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var cache = std.StringHashMap(TagResolution).init(alloc);
    cache.put("actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11", .has_tag) catch unreachable;
    tag_cache = cache;
    stale_refs_arena = arena;

    var steps = [_]Step{.{
        .uses = ActionRef.parse("actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"),
    }};
    var jobs = [_]Job{.{ .id = "test", .steps = &steps }};
    const wf = Workflow{
        .jobs = &jobs,
        .on = .{ .events = &.{} },
    };

    const rules_arr = [_]Rule{.{
        .id = "SC005",
        .name = "stale-action-refs",
        .description = "test",
        .severity = .info,
        .category = .dependency,
        .check_step = &checkStaleActionRef,
    }};
    const eng = Engine.init(&rules_arr);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC005"));
}

test "SC005: unknown resolution produces no diagnostic" {
    const prev_cache = tag_cache;
    const prev_arena = stale_refs_arena;
    defer {
        tag_cache = prev_cache;
        stale_refs_arena = prev_arena;
    }

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var cache = std.StringHashMap(TagResolution).init(alloc);
    cache.put("private/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", .unknown) catch unreachable;
    tag_cache = cache;
    stale_refs_arena = arena;

    var steps = [_]Step{.{
        .uses = ActionRef.parse("private/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    }};
    var jobs = [_]Job{.{ .id = "test", .steps = &steps }};
    const wf = Workflow{
        .jobs = &jobs,
        .on = .{ .events = &.{} },
    };

    const rules_arr = [_]Rule{.{
        .id = "SC005",
        .name = "stale-action-refs",
        .description = "test",
        .severity = .info,
        .category = .dependency,
        .check_step = &checkStaleActionRef,
    }};
    const eng = Engine.init(&rules_arr);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC005"));
}

test "SC005: non-pinned action (tag ref) is skipped" {
    const prev_cache = tag_cache;
    const prev_arena = stale_refs_arena;
    defer {
        tag_cache = prev_cache;
        stale_refs_arena = prev_arena;
    }

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const cache = std.StringHashMap(TagResolution).init(arena.allocator());
    tag_cache = cache;
    stale_refs_arena = arena;

    var steps = [_]Step{.{
        .uses = ActionRef.parse("actions/checkout@v4"),
    }};
    var jobs = [_]Job{.{ .id = "test", .steps = &steps }};
    const wf = Workflow{
        .jobs = &jobs,
        .on = .{ .events = &.{} },
    };

    const rules_arr = [_]Rule{.{
        .id = "SC005",
        .name = "stale-action-refs",
        .description = "test",
        .severity = .info,
        .category = .dependency,
        .check_step = &checkStaleActionRef,
    }};
    const eng = Engine.init(&rules_arr);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC005"));
}

test "SC005: local action is skipped" {
    const prev_cache = tag_cache;
    const prev_arena = stale_refs_arena;
    defer {
        tag_cache = prev_cache;
        stale_refs_arena = prev_arena;
    }

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const cache = std.StringHashMap(TagResolution).init(arena.allocator());
    tag_cache = cache;
    stale_refs_arena = arena;

    var steps = [_]Step{.{
        .uses = ActionRef.parse("./local-action"),
    }};
    var jobs = [_]Job{.{ .id = "test", .steps = &steps }};
    const wf = Workflow{
        .jobs = &jobs,
        .on = .{ .events = &.{} },
    };

    const rules_arr = [_]Rule{.{
        .id = "SC005",
        .name = "stale-action-refs",
        .description = "test",
        .severity = .info,
        .category = .dependency,
        .check_step = &checkStaleActionRef,
    }};
    const eng = Engine.init(&rules_arr);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC005"));
}

test "SC005: docker action is skipped" {
    const prev_cache = tag_cache;
    const prev_arena = stale_refs_arena;
    defer {
        tag_cache = prev_cache;
        stale_refs_arena = prev_arena;
    }

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const cache = std.StringHashMap(TagResolution).init(arena.allocator());
    tag_cache = cache;
    stale_refs_arena = arena;

    var steps = [_]Step{.{
        .uses = ActionRef.parse("docker://alpine:3.18"),
    }};
    var jobs = [_]Job{.{ .id = "test", .steps = &steps }};
    const wf = Workflow{
        .jobs = &jobs,
        .on = .{ .events = &.{} },
    };

    const rules_arr = [_]Rule{.{
        .id = "SC005",
        .name = "stale-action-refs",
        .description = "test",
        .severity = .info,
        .category = .dependency,
        .check_step = &checkStaleActionRef,
    }};
    const eng = Engine.init(&rules_arr);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC005"));
}

test "SC005: step without uses is skipped" {
    const prev_cache = tag_cache;
    const prev_arena = stale_refs_arena;
    defer {
        tag_cache = prev_cache;
        stale_refs_arena = prev_arena;
    }

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const cache = std.StringHashMap(TagResolution).init(arena.allocator());
    tag_cache = cache;
    stale_refs_arena = arena;

    var steps = [_]Step{.{
        .run = "echo hello",
    }};
    var jobs = [_]Job{.{ .id = "test", .steps = &steps }};
    const wf = Workflow{
        .jobs = &jobs,
        .on = .{ .events = &.{} },
    };

    const rules_arr = [_]Rule{.{
        .id = "SC005",
        .name = "stale-action-refs",
        .description = "test",
        .severity = .info,
        .category = .dependency,
        .check_step = &checkStaleActionRef,
    }};
    const eng = Engine.init(&rules_arr);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC005"));
}

test "SC005: offline mode (null cache) produces no diagnostic" {
    const prev_cache = tag_cache;
    const prev_arena = stale_refs_arena;
    defer {
        tag_cache = prev_cache;
        stale_refs_arena = prev_arena;
    }

    tag_cache = null;
    stale_refs_arena = null;

    var steps = [_]Step{.{
        .uses = ActionRef.parse("evil/action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
    }};
    var jobs = [_]Job{.{ .id = "test", .steps = &steps }};
    const wf = Workflow{
        .jobs = &jobs,
        .on = .{ .events = &.{} },
    };

    const rules_arr = [_]Rule{.{
        .id = "SC005",
        .name = "stale-action-refs",
        .description = "test",
        .severity = .info,
        .category = .dependency,
        .check_step = &checkStaleActionRef,
    }};
    const eng = Engine.init(&rules_arr);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC005"));
}

test "SC005: invalid owner characters rejected" {
    const prev_cache = tag_cache;
    const prev_arena = stale_refs_arena;
    defer {
        tag_cache = prev_cache;
        stale_refs_arena = prev_arena;
    }

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const cache = std.StringHashMap(TagResolution).init(arena.allocator());
    tag_cache = cache;
    stale_refs_arena = arena;

    // URL-unsafe owner should be silently rejected
    var steps = [_]Step{.{
        .uses = ActionRef.parse("evil?org/action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
    }};
    var jobs = [_]Job{.{ .id = "test", .steps = &steps }};
    const wf = Workflow{ .jobs = &jobs, .on = .{ .events = &.{} } };

    const rules_arr = [_]Rule{.{
        .id = "SC005",
        .name = "stale-action-refs",
        .description = "test",
        .severity = .info,
        .category = .dependency,
        .check_step = &checkStaleActionRef,
    }};
    const eng = Engine.init(&rules_arr);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.items.items.len);
}
