const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml = @import("../yaml/types.zig");

const engine = @import("engine.zig");
const http_client = @import("http_client.zig");

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
    return fetchArchiveStatus(allocator, owner, repo);
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
    const result = fetchArchiveStatus(alloc, owner, repo) catch return null;

    // Store with arena-allocated permanent key
    const permanent_key = std.fmt.allocPrint(alloc, "{s}/{s}", .{ owner, repo }) catch return null;
    archived_cache.put(alloc, permanent_key, result) catch return null;

    return result;
}

// ============================================================
// HTTP fetch
// ============================================================

fn fetchArchiveStatus(allocator: Allocator, owner: []const u8, repo: []const u8) !bool {
    const url = try std.fmt.allocPrint(allocator, "https://api.github.com/repos/{s}/{s}", .{ owner, repo });
    defer allocator.free(url);

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    const auth_value = http_client.getAuthHeader(allocator);
    defer if (auth_value) |auth| allocator.free(auth);

    var headers_buf: [3]std.http.Header = undefined;
    const header_count = http_client.writeStandardHeaders(&headers_buf, auth_value);

    const result = http_client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &aw.writer,
        .headers = .{ .user_agent = .{ .override = http_client.user_agent } },
        .extra_headers = headers_buf[0..header_count],
    }) catch return error.FetchFailed;

    if (result.status != .ok) return error.HttpError;

    var response_list = aw.toArrayList();
    defer response_list.deinit(allocator);

    return parseArchivedField(allocator, response_list.items);
}

// ============================================================
// JSON parsing
// ============================================================

fn parseArchivedField(allocator: Allocator, body: []const u8) !bool {
    const root = std.json.parseFromSliceLeaky(std.json.Value, allocator, body, .{}) catch return error.JsonParseError;

    const obj = switch (root) {
        .object => |o| o,
        else => return error.UnexpectedFormat,
    };

    const archived_val = obj.get("archived") orelse return error.MissingField;
    return switch (archived_val) {
        .bool => |b| b,
        else => error.UnexpectedFormat,
    };
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

test "parseArchivedField: archived true" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\{"id":1,"name":"test-repo","archived":true,"disabled":false}
    ;
    const result = try parseArchivedField(arena.allocator(), body);
    try testing.expect(result);
}

test "parseArchivedField: archived false" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\{"id":1,"name":"test-repo","archived":false,"disabled":false}
    ;
    const result = try parseArchivedField(arena.allocator(), body);
    try testing.expect(!result);
}

test "parseArchivedField: malformed JSON" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body = "not json at all";
    try testing.expectError(error.JsonParseError, parseArchivedField(arena.allocator(), body));
}

test "parseArchivedField: missing archived field" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\{"id":1,"name":"test-repo","disabled":false}
    ;
    try testing.expectError(error.MissingField, parseArchivedField(arena.allocator(), body));
}

test "parseArchivedField: non-object root returns UnexpectedFormat" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(
        error.UnexpectedFormat,
        parseArchivedField(arena.allocator(), "[1,2,3]"),
    );
}

test "parseArchivedField: non-bool archived returns UnexpectedFormat" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\{"archived":"yes"}
    ;
    try testing.expectError(
        error.UnexpectedFormat,
        parseArchivedField(arena.allocator(), body),
    );
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
