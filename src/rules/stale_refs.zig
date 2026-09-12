const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");

const engine = @import("engine.zig");
const rest_fallback = @import("rest_fallback.zig");
const net_status = @import("net_status.zig");
const cache_mod = @import("ref_cache.zig");

const Allocator = std.mem.Allocator;
const DiagnosticList = diagnostics.DiagnosticList;
const spans = @import("spans.zig");
const Step = workflow_types.Step;
const isValidGitHubComponent = engine.isValidGitHubComponent;

var cache: cache_mod.RefCache(rest_fallback.TagResolution) = .{};

pub fn initStaleRefs(backing_allocator: Allocator, offline: bool) void {
    cache.init(backing_allocator, offline);
}

pub fn deinitStaleRefs() void {
    cache.deinit();
}

pub fn isActive() bool {
    return cache.isActive();
}

/// Exposed so engine post-processing can tell whether SC005 actually fired
/// for a step when deciding to dedupe overlapping SC008 verdicts.
pub fn lookupCachedTagResult(
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
) ?rest_fallback.TagResolution {
    const key = cache.makeKey("{s}/{s}@{s}", .{ owner, repo, sha }) orelse return null;
    return cache.get(key);
}

pub fn setCachedTagResult(
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
    resolution: rest_fallback.TagResolution,
) void {
    const key = cache.makeKey("{s}/{s}@{s}", .{ owner, repo, sha }) orelse return;
    cache.put(key, resolution);
}

pub fn checkStaleActionRef(step: *const Step, list: *DiagnosticList) void {
    const allocator = cache.allocator() orelse return;
    const action_ref = step.uses orelse return;
    if (!action_ref.is_pinned) return;
    if (action_ref.is_local or action_ref.is_docker) return;
    const owner = action_ref.owner orelse return;
    const repo = action_ref.repo orelse return;
    const sha = action_ref.ref orelse return;
    if (!isValidGitHubComponent(owner) or !isValidGitHubComponent(repo)) return;

    const key = cache.makeKey("{s}/{s}@{s}", .{ owner, repo, sha }) orelse return;

    const resolution = cache.get(key) orelse blk: {
        const result = rest_fallback.resolveTagForSha(allocator, owner, repo, sha) catch rest_fallback.TagResolution.unknown;
        cache.put(key, result);
        break :blk result;
    };

    // `.unknown` は取得失敗のみを表す (タグの有無が確定した場合は has_tag /
    // no_tag)。沈黙が無指摘と読まれないよう記録する (#304)。
    if (resolution == .unknown) {
        net_status.markUnavailable(.sc005);
        return;
    }

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

const TagCacheEntry = struct { key: []const u8, resolution: rest_fallback.TagResolution };

/// Module state is saved and restored so tests stay independent of each other.
/// Diagnostics only borrow string literals, so the arena can go away here.
fn runWithTagCache(entries: ?[]const TagCacheEntry, uses_ref: ?[]const u8) DiagnosticList {
    const prev = cache;
    defer cache = prev;

    cache = .{};
    defer if (cache.isActive()) cache.deinit();

    if (entries) |es| {
        cache.init(testing.allocator, false);
        for (es) |e| cache.put(e.key, e.resolution);
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

test "SC005: unknown resolution records the rule as unreachable" {
    net_status.reset();
    defer net_status.reset();

    const sha_ref = "private/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var list = runWithTagCache(&.{.{ .key = sha_ref, .resolution = .unknown }}, sha_ref);
    defer list.deinit();

    try testing.expect(net_status.isUnavailable(.sc005));
}

test "SC005: a decided resolution leaves the rule unmarked" {
    net_status.reset();
    defer net_status.reset();

    const sha_ref = "evil/action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    var list = runWithTagCache(&.{.{ .key = sha_ref, .resolution = .no_tag }}, sha_ref);
    defer list.deinit();

    try testing.expect(!net_status.isUnavailable(.sc005));
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
    var list = runWithTagCache(&.{}, "evil?org/action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.items.items.len);
}
