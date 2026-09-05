const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml = @import("../yaml/types.zig");

const engine = @import("engine.zig");
const graphql = @import("graphql.zig");

const Allocator = std.mem.Allocator;
const DiagnosticList = diagnostics.DiagnosticList;
const spans = @import("spans.zig");
const Step = workflow_types.Step;
const isValidGitHubComponent = engine.isValidGitHubComponent;
const isValidSha = engine.isValidSha;

/// Reachability verdict for a SHA-pinned action ref.
/// - legitimate: SHA is reachable from a tag or branch of the upstream repo
/// - impostor:   SHA is not reachable from any ref (possible fork/PR-only commit)
/// - unknown:    could not determine (rate limit, deadline, missing token, etc.)
pub const ImpostorStatus = enum { legitimate, impostor, unknown };

/// Shared with the GraphQL layer so prefetch results can be handed over
/// without a copy.
pub const NamedOid = graphql.NamedOid;

pub const CachedResult = struct {
    status: ImpostorStatus,
    suggested_tags: []const NamedOid = &.{},
    suggested_default: ?NamedOid = null,
};

/// null means offline mode.
var impostor_cache: ?std.StringHashMap(CachedResult) = null;
var impostor_arena: ?std.heap.ArenaAllocator = null;

pub fn initImpostor(backing_allocator: Allocator, offline: bool) void {
    if (offline) return;
    impostor_arena = std.heap.ArenaAllocator.init(backing_allocator);
    if (impostor_arena) |*arena| {
        impostor_cache = std.StringHashMap(CachedResult).init(arena.allocator());
    }
}

pub fn deinitImpostor() void {
    if (impostor_arena) |*arena| {
        arena.deinit();
        impostor_arena = null;
    }
    impostor_cache = null;
}

pub fn isActive() bool {
    return impostor_cache != null;
}

/// prefetch stages cache keys and fix_hint candidate strings here so they
/// outlive the rule run.
pub fn getArenaAllocator() ?Allocator {
    return if (impostor_arena) |*arena| arena.allocator() else null;
}

pub fn setCachedImpostorResult(
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
    result: CachedResult,
) void {
    if (impostor_cache == null) return;
    const alloc = if (impostor_arena) |*arena| arena.allocator() else return;
    const key = std.fmt.allocPrint(alloc, "{s}/{s}@{s}", .{ owner, repo, sha }) catch return;
    impostor_cache.?.put(key, result) catch return;
}

pub fn lookupCachedImpostorResult(
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
) ?CachedResult {
    const cache = impostor_cache orelse return null;
    const alloc = if (impostor_arena) |*arena| arena.allocator() else return null;
    const key = std.fmt.allocPrint(alloc, "{s}/{s}@{s}", .{ owner, repo, sha }) catch return null;
    return cache.get(key);
}

/// Consulted by engine.postProcess to dedupe the overlapping SC005 info
/// diagnostic.
pub fn shaIsCachedImpostor(
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
) bool {
    const cached = lookupCachedImpostorResult(owner, repo, sha) orelse return false;
    return cached.status == .impostor;
}

/// Only fires when the verdict is `.impostor`; `.legitimate` and `.unknown`
/// are silent (fail-closed on uncertainty).
pub fn checkImpostorCommit(step: *const Step, list: *DiagnosticList) void {
    if (!isActive()) return;
    const action_ref = step.uses orelse return;
    if (!action_ref.is_pinned) return;
    if (action_ref.is_local or action_ref.is_docker) return;

    const owner = action_ref.owner orelse return;
    const repo = action_ref.repo orelse return;
    const sha = action_ref.ref orelse return;
    if (!isValidGitHubComponent(owner) or !isValidGitHubComponent(repo)) return;
    if (!isValidSha(sha)) return;

    const cached = lookupCachedImpostorResult(owner, repo, sha) orelse return;
    if (cached.status != .impostor) return;

    const alloc = list.fixAllocator();
    const message = std.fmt.allocPrint(
        alloc,
        "'{s}/{s}@{s}' is not reachable from any branch or tag of the upstream repo (possible impostor commit)",
        .{ owner, repo, sha },
    ) catch return;
    const hint = buildFixHint(alloc, cached) catch
        "SHA not reachable from upstream; verify against a known tag or the default branch.";

    list.append(.{
        .rule_id = "SC008",
        .severity = .warning,
        .message = message,
        .span = spans.usesSpan(step),
        .fix_hint = hint,
    }) catch return;
}

/// Allocated into `alloc` (DiagnosticList's fix arena) so the returned slice
/// lives for the diagnostic's lifetime.
fn buildFixHint(alloc: Allocator, cached: CachedResult) ![]const u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(alloc);

    try buf.appendSlice(alloc, "SHA not reachable from upstream. Consider pinning to ");

    var wrote_candidate = false;
    if (cached.suggested_tags.len > 0) {
        try buf.appendSlice(alloc, "a known tag (");
        const take = @min(cached.suggested_tags.len, 3);
        var i: usize = 0;
        while (i < take) : (i += 1) {
            if (i != 0) try buf.appendSlice(alloc, ", ");
            const tag = cached.suggested_tags[i];
            try buf.writer(alloc).print("{s}={s}", .{ tag.name, oidShort(tag.oid) });
        }
        try buf.appendSlice(alloc, ")");
        wrote_candidate = true;
    }

    if (cached.suggested_default) |def| {
        if (wrote_candidate) try buf.appendSlice(alloc, " or ");
        try buf.writer(alloc).print("the default branch ({s}={s})", .{ def.name, oidShort(def.oid) });
        wrote_candidate = true;
    }

    if (!wrote_candidate) {
        try buf.appendSlice(alloc, "a known tag or the default branch");
    }
    try buf.appendSlice(alloc, ".");

    return buf.toOwnedSlice(alloc);
}

fn oidShort(oid: []const u8) []const u8 {
    return if (oid.len >= 7) oid[0..7] else oid;
}

const testing = std.testing;
const test_support = @import("../test_support.zig");
const ActionRef = workflow_types.ActionRef;
const Workflow = workflow_types.Workflow;
const Job = workflow_types.Job;
const Rule = engine.Rule;
const Engine = engine.Engine;

const hasDiagnostic = test_support.hasDiagnostic;

const ImpostorCacheEntry = struct { key: []const u8, result: CachedResult };

/// Module state is saved and restored so tests stay independent of each
/// other. Diagnostic strings come from the list's own arena, so the impostor
/// arena can go away here.
fn runWithImpostorCache(entries: ?[]const ImpostorCacheEntry, uses_ref: ?[]const u8) !DiagnosticList {
    const prev_cache = impostor_cache;
    const prev_arena = impostor_arena;
    defer {
        impostor_cache = prev_cache;
        impostor_arena = prev_arena;
    }

    if (entries != null) {
        initImpostor(testing.allocator, false);
    } else {
        impostor_cache = null;
        impostor_arena = null;
    }
    defer if (entries != null) deinitImpostor();

    if (entries) |es| {
        for (es) |entry| {
            const alloc = getArenaAllocator() orelse return error.NotInitialized;
            const key = try alloc.dupe(u8, entry.key);
            try impostor_cache.?.put(key, entry.result);
        }
    }

    var steps = [_]Step{.{
        .uses = if (uses_ref) |r| ActionRef.parse(r) else null,
        .run = if (uses_ref == null) "echo hello" else null,
    }};
    var jobs = [_]Job{.{ .id = "test", .steps = &steps }};
    const wf = Workflow{
        .jobs = &jobs,
        .on = .{ .events = &.{} },
    };

    const rules_arr = [_]Rule{.{
        .id = "SC008",
        .name = "impostor-commit",
        .description = "impostor commit detection",
        .severity = .warning,
        .category = .dependency,
        .check_step = &checkImpostorCommit,
    }};
    const eng = Engine.init(&rules_arr);
    return eng.run(testing.allocator, &wf);
}

test "SC008: impostor status produces warning diagnostic" {
    var list = try runWithImpostorCache(
        &.{
            .{
                .key = "evil/action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                .result = .{ .status = .impostor },
            },
        },
        "evil/action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    );
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SC008"));
    try testing.expectEqual(diagnostics.Severity.warning, list.get(0).severity);
    try testing.expect(std.mem.indexOf(u8, list.get(0).message, "impostor commit") != null);
}

test "SC008: legitimate status produces no diagnostic" {
    var list = try runWithImpostorCache(
        &.{
            .{
                .key = "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
                .result = .{ .status = .legitimate },
            },
        },
        "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
    );
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC008"));
}

test "SC008: unknown status produces no diagnostic" {
    var list = try runWithImpostorCache(
        &.{
            .{
                .key = "actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                .result = .{ .status = .unknown },
            },
        },
        "actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC008"));
}

test "SC008: offline mode produces no diagnostic" {
    var list = try runWithImpostorCache(null, "evil/action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC008"));
}

test "SC008: non-pinned action (tag ref) is skipped" {
    var list = try runWithImpostorCache(&.{}, "actions/checkout@v4");
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC008"));
}

test "SC008: local action is skipped" {
    var list = try runWithImpostorCache(&.{}, "./local-action");
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC008"));
}

test "SC008: docker action is skipped" {
    var list = try runWithImpostorCache(&.{}, "docker://alpine:3.18");
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC008"));
}

test "SC008: non-hex SHA-like ref is rejected" {
    // ref starts with 'z' which is non-hex -> is_pinned=false, but also isValidSha=false.
    var list = try runWithImpostorCache(&.{}, "evil/action@zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC008"));
}

test "buildFixHint: lists tag candidates and default branch" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const tags = [_]NamedOid{
        .{ .name = "v4", .oid = "a81bbbf0000000000000000000000000000000aa" },
        .{ .name = "v4.2.2", .oid = "11bd71905000000000000000000000000000bb" },
        .{ .name = "v4.2.1", .oid = "ccccccccccccccccccccccccccccccccccccccc" },
        .{ .name = "v4.2.0", .oid = "dddddddddddddddddddddddddddddddddddddd" },
    };
    const hint = try buildFixHint(alloc, .{
        .status = .impostor,
        .suggested_tags = &tags,
        .suggested_default = .{
            .name = "main",
            .oid = "c85c95e0000000000000000000000000000000cc",
        },
    });

    try testing.expect(std.mem.indexOf(u8, hint, "v4=a81bbbf") != null);
    try testing.expect(std.mem.indexOf(u8, hint, "v4.2.2=11bd719") != null);
    try testing.expect(std.mem.indexOf(u8, hint, "v4.2.1=") != null);
    try testing.expect(std.mem.indexOf(u8, hint, "v4.2.0") == null);
    try testing.expect(std.mem.indexOf(u8, hint, "main=c85c95e") != null);
}

test "buildFixHint: falls back when no candidates" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const hint = try buildFixHint(alloc, .{ .status = .impostor });
    try testing.expect(std.mem.indexOf(u8, hint, "known tag or the default branch") != null);
}
