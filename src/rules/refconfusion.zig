const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const engine = @import("engine.zig");
const rest_fallback = @import("rest_fallback.zig");
const net_status = @import("net_status.zig");
const sha_pin = @import("sha_pin.zig");
const cache_mod = @import("ref_cache.zig");

const Allocator = std.mem.Allocator;
const DiagnosticList = diagnostics.DiagnosticList;
const spans = @import("spans.zig");
const Step = workflow_types.Step;
const ActionRef = workflow_types.ActionRef;
const isValidGitHubComponent = engine.isValidGitHubComponent;
const isValidGitRef = engine.isValidGitRef;

/// Re-exported from `rest_fallback.zig` so callers and tests that imported
/// `refconfusion.RefStatus` keep working. The canonical definition lives
/// alongside the REST resolver to avoid a circular import.
pub const RefStatus = rest_fallback.RefStatus;

var cache: cache_mod.RefCache(RefStatus) = .{};

pub fn initRefConfusion(backing_allocator: Allocator, offline: bool) void {
    cache.init(backing_allocator, offline);
    rest_fallback.resetRateLimit();
}

pub fn deinitRefConfusion() void {
    cache.deinit();
    rest_fallback.resetRateLimit();
}

pub fn isActive() bool {
    return cache.isActive();
}

pub fn setCachedRefResult(
    owner: []const u8,
    repo: []const u8,
    ref: []const u8,
    status: RefStatus,
) void {
    const key = cache.makeKey("{s}/{s}@{s}", .{ owner, repo, ref }) orelse return;
    cache.put(key, status);
}

pub fn checkRefConfusion(step: *const Step, list: *DiagnosticList) void {
    const action_ref = step.uses orelse return;
    if (action_ref.is_local or action_ref.is_docker or action_ref.is_pinned) return;
    const owner = action_ref.owner orelse return;
    const repo = action_ref.repo orelse return;
    const ref = action_ref.ref orelse return;
    if (!isValidGitHubComponent(owner) or !isValidGitHubComponent(repo) or !isValidGitRef(ref)) return;

    const allocator = cache.allocator() orelse return;
    const key = cache.makeKey("{s}/{s}@{s}", .{ owner, repo, ref }) orelse return;

    const status = cache.get(key) orelse blk: {
        const fetched = rest_fallback.queryRefStatus(allocator, owner, repo, ref);
        cache.put(key, fetched);
        break :blk fetched;
    };

    switch (status) {
        .ambiguous => emitDiagnostic(list, step, action_ref, owner, repo, ref),
        .not_ambiguous => {},
        // 曖昧かどうかを判定できていない。無指摘と区別できるよう記録する (#304)。
        .fetch_failed => net_status.markUnavailable(.sc006),
    }
}

fn emitDiagnostic(
    list: *DiagnosticList,
    step: *const Step,
    action_ref: ActionRef,
    owner: []const u8,
    repo: []const u8,
    ref: []const u8,
) void {
    const alloc = list.fixAllocator();
    const message = std.fmt.allocPrint(alloc, "action ref '{s}' matches both a tag and a branch in {s}/{s}; an attacker could create a tag to hijack this reference", .{ ref, owner, repo }) catch return;
    list.append(.{
        .rule_id = "SC006",
        .severity = .warning,
        .message = message,
        .span = spans.usesSpan(step),
        .fix_hint = "pin to a full 40-character commit SHA to avoid ref confusion",
        // Unsafe: the whole finding is that the name is ambiguous, so pinning
        // to the tag's commit decides on the author's behalf which of the two
        // they meant. That guess needs `--fix-unsafe` and a human to read it.
        .fix = sha_pin.buildPinFix(
            list,
            step,
            action_ref,
            .unsafe,
            "pin to the commit the tag of this name points at",
        ),
    }) catch return;
}

const testing = std.testing;
const test_support = @import("../test_support.zig");

const RefCacheEntry = struct { key: []const u8, status: RefStatus };

/// Module state is saved and restored so tests stay independent of each
/// other; the diagnostic's message lives in the returned list's own arena, so
/// the cache arena can go away here.
fn runWithRefCache(entries: ?[]const RefCacheEntry, uses_ref: ?[]const u8) DiagnosticList {
    const prev = cache;
    defer cache = prev;

    cache = .{};
    defer if (cache.isActive()) cache.deinit();

    if (entries) |es| {
        cache.init(testing.allocator, false);
        for (es) |e| cache.put(e.key, e.status);
    }

    const step = Step{
        .uses = if (uses_ref) |r| ActionRef.parse(r) else null,
        .run = if (uses_ref == null) "echo hello" else null,
    };
    var list = DiagnosticList.init(testing.allocator);
    checkRefConfusion(&step, &list);
    return list;
}

test "SC006: offline mode produces no diagnostics" {
    var list = runWithRefCache(null, "owner/repo@main");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: detects ambiguous ref from cache" {
    var list = runWithRefCache(&.{.{ .key = "owner/repo@main", .status = .ambiguous }}, "owner/repo@main");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expectEqualStrings("SC006", list.get(0).rule_id);
}

test "SC006: non-ambiguous ref (no false positive)" {
    var list = runWithRefCache(&.{.{ .key = "owner/repo@v1", .status = .not_ambiguous }}, "owner/repo@v1");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: fetch failed (no false positive, fail-open)" {
    var list = runWithRefCache(&.{.{ .key = "owner/repo@develop", .status = .fetch_failed }}, "owner/repo@develop");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: fetch failed records the rule as unreachable" {
    net_status.reset();
    defer net_status.reset();

    var list = runWithRefCache(&.{.{ .key = "owner/repo@develop", .status = .fetch_failed }}, "owner/repo@develop");
    defer list.deinit();
    try testing.expect(net_status.isUnavailable(.sc006));
}

test "SC006: a decided status leaves the rule unmarked" {
    net_status.reset();
    defer net_status.reset();

    var list = runWithRefCache(&.{.{ .key = "owner/repo@v1", .status = .not_ambiguous }}, "owner/repo@v1");
    defer list.deinit();
    try testing.expect(!net_status.isUnavailable(.sc006));
}

test "SC006: pinned SHA (no false positive)" {
    var list = runWithRefCache(&.{}, "owner/repo@a5ac7e51b41094c92402da3b24376905380afc29");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: local action (no false positive)" {
    var list = runWithRefCache(&.{}, "./local");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: docker action (no false positive)" {
    var list = runWithRefCache(&.{}, "docker://alpine:3.8");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: step without uses (no false positive)" {
    var list = runWithRefCache(&.{}, null);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: invalid owner characters rejected" {
    var list = runWithRefCache(&.{.{ .key = "evil?org/repo@main", .status = .ambiguous }}, "evil?org/repo@main");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC006: invalid ref characters rejected" {
    var list = runWithRefCache(&.{}, "owner/repo@ref?query");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}

const sc006_pin_oid = "a5ac7e51b41094c92402da3b24376905380afc29";

const sc006_source =
    \\name: t
    \\on: push
    \\jobs:
    \\  build:
    \\    runs-on: ubuntu-latest
    \\    steps:
    \\      - uses: owner/repo@v4
    \\
;

/// `lintAndFix` needs a real parsed step (the rewrite addresses source bytes),
/// which `runWithRefCache`'s synthetic `Step` cannot provide.
fn fixWithAmbiguousRef(include_unsafe: bool) !test_support.FixOutcome {
    const prev = cache;
    defer cache = prev;

    cache = .{};
    defer if (cache.isActive()) cache.deinit();
    cache.init(testing.allocator, false);
    cache.put("owner/repo@v4", .ambiguous);

    return test_support.lintAndFix(testing.allocator, sc006_source, .{ .step = &checkRefConfusion }, include_unsafe);
}

test "SC006: --fix-unsafe pins the ambiguous ref to the tag side" {
    sha_pin.initTagOids(testing.allocator, false, true);
    defer sha_pin.deinitTagOids();
    sha_pin.setCachedTagOid("owner", "repo", "v4", sc006_pin_oid, true);

    const result = try fixWithAmbiguousRef(true);
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), result.fix_count);
    try testing.expectEqual(diagnostics.FixSafety.unsafe, result.first_safety.?);
    try testing.expect(std.mem.find(u8, result.content, "uses: owner/repo@" ++ sc006_pin_oid ++ " # v4") != null);
}

test "SC006: plain --fix leaves the ambiguity for a human to resolve" {
    sha_pin.initTagOids(testing.allocator, false, true);
    defer sha_pin.deinitTagOids();
    sha_pin.setCachedTagOid("owner", "repo", "v4", sc006_pin_oid, true);

    const result = try fixWithAmbiguousRef(false);
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), result.diagnostic_count);
    try testing.expectEqual(@as(usize, 0), result.fix_count);
    try testing.expectEqualStrings(sc006_source, result.content);
}

test "SC006: without a known commit the diagnostic stands alone" {
    sha_pin.initTagOids(testing.allocator, true, true);
    defer sha_pin.deinitTagOids();

    const result = try fixWithAmbiguousRef(true);
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), result.diagnostic_count);
    try testing.expectEqual(@as(usize, 0), result.fix_count);
}
