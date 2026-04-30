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
const Rule = engine.Rule;
const isValidGitHubComponent = engine.isValidGitHubComponent;
const isValidGitRef = engine.isValidGitRef;

// ============================================================
// Ref confusion status
// ============================================================

/// Re-exported from `rest_fallback.zig` so callers and tests that imported
/// `refconfusion.RefStatus` keep working. The canonical definition lives
/// alongside the REST resolver to avoid a circular import.
pub const RefStatus = rest_fallback.RefStatus;

// ============================================================
// Module-level state
// ============================================================

var ref_cache: ?std.StringHashMap(RefStatus) = null;
var ref_arena: ?std.heap.ArenaAllocator = null;

// ============================================================
// Public API
// ============================================================

/// Initialize ref-confusion checker.
/// When offline, skips initialization (cache stays null → offline mode).
pub fn initRefConfusion(backing_allocator: Allocator, offline: bool) void {
    if (offline) return;
    ref_arena = std.heap.ArenaAllocator.init(backing_allocator);
    if (ref_arena) |*arena| {
        ref_cache = std.StringHashMap(RefStatus).init(arena.allocator());
    }
    rest_fallback.resetRateLimit();
}

/// Release all ref-confusion memory.
pub fn deinitRefConfusion() void {
    if (ref_arena) |*arena| {
        arena.deinit();
        ref_arena = null;
    }
    ref_cache = null;
    rest_fallback.resetRateLimit();
}

/// Returns `true` if ref-confusion is live (non-offline) so a prefetcher
/// can decide whether to issue network requests for it.
pub fn isActive() bool {
    return ref_cache != null;
}

/// Pre-populate the ref cache. Used by the prefetch orchestrator to
/// install batched results before the engine runs.
pub fn setCachedRefResult(
    owner: []const u8,
    repo: []const u8,
    ref: []const u8,
    status: RefStatus,
) void {
    if (ref_cache == null) return;
    const alloc = if (ref_arena) |*arena| arena.allocator() else return;
    const key = std.fmt.allocPrint(alloc, "{s}/{s}@{s}", .{ owner, repo, ref }) catch return;
    ref_cache.?.put(key, status) catch return;
}

/// Query GitHub for the status of a ref. Exposed for the prefetch
/// orchestrator so it can batch ref lookups instead of hitting the
/// lazy per-step path.
pub fn queryRefStatusPub(
    allocator: Allocator,
    owner: []const u8,
    repo: []const u8,
    ref: []const u8,
) RefStatus {
    return rest_fallback.queryRefStatus(allocator, owner, repo, ref);
}

/// Return the arena allocator used for cache keys, so the prefetch
/// orchestrator can stage allocations that live for the rule's lifetime.
pub fn getArenaAllocator() ?Allocator {
    return if (ref_arena) |*arena| arena.allocator() else null;
}

/// Rule check function for SC006.
/// Detects when an action ref matches both a tag and a branch.
pub fn checkRefConfusion(step: *const Step, list: *DiagnosticList) void {
    const action_ref = step.uses orelse return;
    if (action_ref.is_local or action_ref.is_docker or action_ref.is_pinned) return;
    const owner = action_ref.owner orelse return;
    const repo = action_ref.repo orelse return;
    const ref = action_ref.ref orelse return;
    if (!isValidGitHubComponent(owner) or !isValidGitHubComponent(repo) or !isValidGitRef(ref)) return;

    const allocator = if (ref_arena) |*arena| arena.allocator() else return;
    var cache = ref_cache orelse return; // offline → skip

    // Build cache key
    const key = std.fmt.allocPrint(allocator, "{s}/{s}@{s}", .{ owner, repo, ref }) catch return;

    // Check cache
    if (cache.get(key)) |status| {
        if (status == .ambiguous) {
            emitDiagnostic(list, owner, repo, ref);
        }
        return;
    }

    // Query GitHub API
    const status = rest_fallback.queryRefStatus(allocator, owner, repo, ref);
    cache.put(key, status) catch return;

    if (status == .ambiguous) {
        emitDiagnostic(list, owner, repo, ref);
    }
}

// ============================================================
// Diagnostic emission
// ============================================================

fn emitDiagnostic(list: *DiagnosticList, owner: []const u8, repo: []const u8, ref: []const u8) void {
    const alloc = list.fixAllocator();
    const message = std.fmt.allocPrint(alloc, "action ref '{s}' matches both a tag and a branch in {s}/{s}; an attacker could create a tag to hijack this reference", .{ ref, owner, repo }) catch return;
    list.append(.{
        .rule_id = "SC006",
        .severity = .warning,
        .message = message,
        .span = Span.point(0, 0, 0),
        .fix_hint = "pin to a full 40-character commit SHA to avoid ref confusion",
    }) catch return;
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;

test "SC006: offline mode produces no diagnostics" {
    // ref_cache defaults to null (offline), so check should be a no-op
    const prev_cache = ref_cache;
    ref_cache = null;
    defer ref_cache = prev_cache;

    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    const step = Step{ .uses = ActionRef.parse("owner/repo@main") };
    checkRefConfusion(&step, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: detects ambiguous ref from cache" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var cache = std.StringHashMap(RefStatus).init(arena.allocator());
    cache.put("owner/repo@main", .ambiguous) catch unreachable;

    const prev_cache = ref_cache;
    const prev_arena = ref_arena;
    ref_cache = cache;
    ref_arena = arena;
    defer {
        ref_cache = prev_cache;
        ref_arena = prev_arena;
    }

    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    const step = Step{ .uses = ActionRef.parse("owner/repo@main") };
    checkRefConfusion(&step, &list);
    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expectEqualStrings("SC006", list.get(0).rule_id);
}

test "SC006: non-ambiguous ref (no false positive)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var cache = std.StringHashMap(RefStatus).init(arena.allocator());
    cache.put("owner/repo@v1", .not_ambiguous) catch unreachable;

    const prev_cache = ref_cache;
    const prev_arena = ref_arena;
    ref_cache = cache;
    ref_arena = arena;
    defer {
        ref_cache = prev_cache;
        ref_arena = prev_arena;
    }

    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    const step = Step{ .uses = ActionRef.parse("owner/repo@v1") };
    checkRefConfusion(&step, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: fetch failed (no false positive, fail-open)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var cache = std.StringHashMap(RefStatus).init(arena.allocator());
    cache.put("owner/repo@develop", .fetch_failed) catch unreachable;

    const prev_cache = ref_cache;
    const prev_arena = ref_arena;
    ref_cache = cache;
    ref_arena = arena;
    defer {
        ref_cache = prev_cache;
        ref_arena = prev_arena;
    }

    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    const step = Step{ .uses = ActionRef.parse("owner/repo@develop") };
    checkRefConfusion(&step, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: pinned SHA (no false positive)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const cache = std.StringHashMap(RefStatus).init(arena.allocator());

    const prev_cache = ref_cache;
    const prev_arena = ref_arena;
    ref_cache = cache;
    ref_arena = arena;
    defer {
        ref_cache = prev_cache;
        ref_arena = prev_arena;
    }

    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    const step = Step{ .uses = ActionRef.parse("owner/repo@a5ac7e51b41094c92402da3b24376905380afc29") };
    checkRefConfusion(&step, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: local action (no false positive)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const cache = std.StringHashMap(RefStatus).init(arena.allocator());

    const prev_cache = ref_cache;
    const prev_arena = ref_arena;
    ref_cache = cache;
    ref_arena = arena;
    defer {
        ref_cache = prev_cache;
        ref_arena = prev_arena;
    }

    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    const step = Step{ .uses = ActionRef.parse("./local") };
    checkRefConfusion(&step, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: docker action (no false positive)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const cache = std.StringHashMap(RefStatus).init(arena.allocator());

    const prev_cache = ref_cache;
    const prev_arena = ref_arena;
    ref_cache = cache;
    ref_arena = arena;
    defer {
        ref_cache = prev_cache;
        ref_arena = prev_arena;
    }

    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    const step = Step{ .uses = ActionRef.parse("docker://alpine:3.8") };
    checkRefConfusion(&step, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: step without uses (no false positive)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const cache = std.StringHashMap(RefStatus).init(arena.allocator());

    const prev_cache = ref_cache;
    const prev_arena = ref_arena;
    ref_cache = cache;
    ref_arena = arena;
    defer {
        ref_cache = prev_cache;
        ref_arena = prev_arena;
    }

    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    const step = Step{ .run = "echo hello" };
    checkRefConfusion(&step, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: invalid owner characters rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var cache = std.StringHashMap(RefStatus).init(arena.allocator());
    cache.put("evil?org/repo@main", .ambiguous) catch unreachable;

    const prev_cache = ref_cache;
    const prev_arena = ref_arena;
    ref_cache = cache;
    ref_arena = arena;
    defer {
        ref_cache = prev_cache;
        ref_arena = prev_arena;
    }

    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    // URL-unsafe owner should be silently rejected
    const step = Step{ .uses = ActionRef.parse("evil?org/repo@main") };
    checkRefConfusion(&step, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: invalid ref characters rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const cache = std.StringHashMap(RefStatus).init(arena.allocator());

    const prev_cache = ref_cache;
    const prev_arena = ref_arena;
    ref_cache = cache;
    ref_arena = arena;
    defer {
        ref_cache = prev_cache;
        ref_arena = prev_arena;
    }

    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    // ref with URL-unsafe characters should be rejected
    const step = Step{ .uses = ActionRef.parse("owner/repo@ref?query") };
    checkRefConfusion(&step, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
}
