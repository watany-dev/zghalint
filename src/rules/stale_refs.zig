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
const isValidGitHubComponent = engine.isValidGitHubComponent;

// ============================================================
// Types
// ============================================================

pub const TagResolution = enum {
    has_tag,
    no_tag,
    unknown,
};

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

/// Resolve the tag relationship for a SHA by calling GitHub's REST API.
/// Exposed so the prefetch orchestrator can batch calls without going
/// through the lazy per-step path.
pub fn resolveTagForShaPub(
    allocator: Allocator,
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
) !TagResolution {
    return resolveTagForSha(allocator, owner, repo, sha);
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
        const result = resolveTagForSha(allocator, owner, repo, sha) catch TagResolution.unknown;
        cache.put(key, result) catch return;
        break :blk result;
    };

    if (resolution == .no_tag) {
        list.append(.{
            .rule_id = "SC005",
            .severity = .info,
            .message = "SHA-pinned action does not correspond to any known Git tag",
            .span = Span.point(0, 0, 0),
            .fix_hint = "verify the SHA corresponds to a tagged release",
        }) catch return;
    }
}

// ============================================================
// HTTP fetch
// ============================================================

fn resolveTagForSha(allocator: Allocator, owner: []const u8, repo: []const u8, sha: []const u8) !TagResolution {
    const url = try std.fmt.allocPrint(
        allocator,
        "https://api.github.com/repos/{s}/{s}/git/matching-refs/tags/?per_page=100",
        .{ owner, repo },
    );

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

    if (result.status != .ok) return TagResolution.unknown;

    var response_list = aw.toArrayList();
    defer response_list.deinit(allocator);

    return matchShaInRefs(allocator, response_list.items, sha, owner, repo);
}

// ============================================================
// JSON parsing and SHA matching
// ============================================================

fn matchShaInRefs(allocator: Allocator, body: []const u8, target_sha: []const u8, owner: []const u8, repo: []const u8) TagResolution {
    const root = std.json.parseFromSliceLeaky(std.json.Value, allocator, body, .{}) catch return .unknown;

    const items = switch (root) {
        .array => |arr| arr.items,
        else => return .unknown,
    };

    if (items.len == 0) return .unknown;

    // Collect annotated tag SHAs for deferred dereferencing
    var annotated_shas: [64][]const u8 = undefined;
    var annotated_count: usize = 0;

    // Pass 1: check lightweight tags (object.type == "commit")
    for (items) |item| {
        const obj = switch (item) {
            .object => |o| o,
            else => continue,
        };
        const ref_obj_val = obj.get("object") orelse continue;
        const ref_obj = switch (ref_obj_val) {
            .object => |o| o,
            else => continue,
        };

        const obj_sha = getJsonString(ref_obj, "sha") orelse continue;
        const obj_type = getJsonString(ref_obj, "type") orelse continue;

        if (std.mem.eql(u8, obj_type, "commit")) {
            if (std.mem.eql(u8, obj_sha, target_sha)) return .has_tag;
        } else if (std.mem.eql(u8, obj_type, "tag")) {
            if (annotated_count < annotated_shas.len) {
                annotated_shas[annotated_count] = obj_sha;
                annotated_count += 1;
            }
        }
    }

    // Pass 2: dereference annotated tags
    for (annotated_shas[0..annotated_count]) |tag_sha| {
        const commit_sha = dereferenceAnnotatedTag(allocator, owner, repo, tag_sha) catch continue;
        if (std.mem.eql(u8, commit_sha, target_sha)) return .has_tag;
    }

    // Pagination guard: if we got a full page, there may be more tags
    if (items.len >= 100) return .unknown;

    return .no_tag;
}

fn dereferenceAnnotatedTag(allocator: Allocator, owner: []const u8, repo: []const u8, tag_sha: []const u8) ![]const u8 {
    const url = try std.fmt.allocPrint(
        allocator,
        "https://api.github.com/repos/{s}/{s}/git/tags/{s}",
        .{ owner, repo, tag_sha },
    );

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

    return parseTagObject(response_list.items);
}

/// Parse a Git tag object response and extract the target commit SHA.
/// Response format: { "object": { "sha": "...", "type": "commit" } }
fn parseTagObject(body: []const u8) ![]const u8 {
    // Use a stack-allocated buffer to avoid leaking into the arena
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);

    const root = std.json.parseFromSliceLeaky(std.json.Value, fba.allocator(), body, .{}) catch return error.JsonParseError;

    const obj = switch (root) {
        .object => |o| o,
        else => return error.UnexpectedFormat,
    };

    const inner_val = obj.get("object") orelse return error.UnexpectedFormat;
    const inner = switch (inner_val) {
        .object => |o| o,
        else => return error.UnexpectedFormat,
    };

    const obj_type = getJsonString(inner, "type") orelse return error.UnexpectedFormat;
    // Only dereference one level; nested tag objects are treated as unknown
    if (!std.mem.eql(u8, obj_type, "commit")) return error.UnexpectedFormat;

    return getJsonString(inner, "sha") orelse error.UnexpectedFormat;
}

fn getJsonString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;
const ActionRef = workflow_types.ActionRef;
const Workflow = workflow_types.Workflow;
const Job = workflow_types.Job;
const Trigger = workflow_types.Trigger;
const Rule = engine.Rule;
const Engine = engine.Engine;
const security = @import("security.zig");

fn hasDiagnostic(list: *DiagnosticList, rule_id: []const u8) bool {
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, rule_id)) return true;
    }
    return false;
}

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

// -- JSON parsing tests --

test "matchShaInRefs: lightweight tag match" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\[{"ref":"refs/tags/v1.0.0","object":{"sha":"abc123abc123abc123abc123abc123abc123abc1","type":"commit"}}]
    ;
    const result = matchShaInRefs(arena.allocator(), body, "abc123abc123abc123abc123abc123abc123abc1", "o", "r");
    try testing.expectEqual(TagResolution.has_tag, result);
}

test "matchShaInRefs: no match returns no_tag" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\[{"ref":"refs/tags/v1.0.0","object":{"sha":"abc123abc123abc123abc123abc123abc123abc1","type":"commit"}}]
    ;
    const result = matchShaInRefs(arena.allocator(), body, "ffffffffffffffffffffffffffffffffffffffff", "o", "r");
    try testing.expectEqual(TagResolution.no_tag, result);
}

test "matchShaInRefs: empty array returns unknown" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body = "[]";
    const result = matchShaInRefs(arena.allocator(), body, "abc123abc123abc123abc123abc123abc123abc1", "o", "r");
    try testing.expectEqual(TagResolution.unknown, result);
}

test "matchShaInRefs: invalid JSON returns unknown" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body = "not json";
    const result = matchShaInRefs(arena.allocator(), body, "abc123abc123abc123abc123abc123abc123abc1", "o", "r");
    try testing.expectEqual(TagResolution.unknown, result);
}

test "matchShaInRefs: non-array JSON returns unknown" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\{"message":"Not Found"}
    ;
    const result = matchShaInRefs(arena.allocator(), body, "abc123abc123abc123abc123abc123abc123abc1", "o", "r");
    try testing.expectEqual(TagResolution.unknown, result);
}

test "matchShaInRefs: multiple lightweight tags, one matches" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\[
        \\  {"ref":"refs/tags/v1.0.0","object":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"commit"}},
        \\  {"ref":"refs/tags/v2.0.0","object":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","type":"commit"}}
        \\]
    ;
    const result = matchShaInRefs(arena.allocator(), body, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "o", "r");
    try testing.expectEqual(TagResolution.has_tag, result);
}

test "parseTagObject: valid commit tag object" {
    const body =
        \\{"tag":"v1.0.0","object":{"sha":"abc123abc123abc123abc123abc123abc123abc1","type":"commit"}}
    ;
    const sha = try parseTagObject(body);
    try testing.expectEqualStrings("abc123abc123abc123abc123abc123abc123abc1", sha);
}

test "parseTagObject: nested tag object returns error" {
    const body =
        \\{"tag":"v1.0.0","object":{"sha":"abc123","type":"tag"}}
    ;
    try testing.expectError(error.UnexpectedFormat, parseTagObject(body));
}

test "parseTagObject: malformed JSON returns error" {
    try testing.expectError(error.JsonParseError, parseTagObject("not json"));
}

test "parseTagObject: missing object field returns error" {
    const body =
        \\{"tag":"v1.0.0"}
    ;
    try testing.expectError(error.UnexpectedFormat, parseTagObject(body));
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
