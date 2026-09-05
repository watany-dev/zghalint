//! Extracted from `prefetch.zig` so the orchestration file stays small
//! and the impostor classification path can be unit-tested in isolation.
//!
//! The module deliberately avoids importing `prefetch.zig` so that
//! `prefetch.zig` can import this without a cycle.

const std = @import("std");
const engine = @import("engine.zig");
const http_client = @import("http_client.zig");
const json_util = @import("json_util.zig");
const impostor = @import("impostor.zig");
const graphql = @import("graphql.zig");

const Allocator = std.mem.Allocator;

pub const PendingCompare = struct {
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
    default_branch: ?graphql.NamedOid,
    tag_oids: []const graphql.NamedOid,
    branch_oids: []const graphql.NamedOid,
};

pub const CompareStatus = enum { reachable, unreachable_, unknown };

pub const RefSweepResult = enum { legit, all_unreachable, unknown };

pub fn classifyImpostorFromGraphql(
    scratch: Allocator,
    res: graphql.RepoResult,
    pending: ?*std.ArrayList(PendingCompare),
) void {
    if (res.sha_results.len == 0) return;

    // Pagination incomplete on either listing means step1/step2 negative
    // verdicts can't be trusted; fail-closed to unknown for the whole
    // repo to avoid false-positive impostor flags.
    const refs_complete = res.tag_oids_complete and res.branch_oids_complete;

    for (res.sha_results) |sr| {
        if (!refs_complete) {
            impostor.setCachedImpostorResult(res.owner, res.repo, sr.sha, .{ .status = .unknown });
            continue;
        }

        if (oidIn(res.tag_oids, sr.sha)) {
            impostor.setCachedImpostorResult(res.owner, res.repo, sr.sha, .{ .status = .legitimate });
            continue;
        }

        if (oidIn(res.branch_oids, sr.sha)) {
            impostor.setCachedImpostorResult(res.owner, res.repo, sr.sha, .{ .status = .legitimate });
            continue;
        }

        if (pending) |list| {
            list.append(scratch, .{
                .owner = res.owner,
                .repo = res.repo,
                .sha = sr.sha,
                .default_branch = res.default_branch,
                .tag_oids = res.tag_oids,
                .branch_oids = res.branch_oids,
            }) catch {
                // Allocator failure: degrade to unknown so SC008 stays silent.
                impostor.setCachedImpostorResult(res.owner, res.repo, sr.sha, .{ .status = .unknown });
            };
        } else {
            impostor.setCachedImpostorResult(res.owner, res.repo, sr.sha, .{ .status = .unknown });
        }
    }
}

fn oidIn(refs: []const graphql.NamedOid, target: []const u8) bool {
    for (refs) |r| {
        if (std.mem.eql(u8, r.oid, target)) return true;
    }
    return false;
}

pub fn runImpostorCompares(scratch: Allocator, pending: []const PendingCompare) void {
    for (pending) |pc| {
        if (engine.isNetworkDeadlineExceeded()) {
            impostor.setCachedImpostorResult(pc.owner, pc.repo, pc.sha, .{ .status = .unknown });
            continue;
        }

        const verdict = classifyImpostorViaCompare(scratch, pc);
        impostor.setCachedImpostorResult(pc.owner, pc.repo, pc.sha, verdict);
    }
}

fn classifyImpostorViaCompare(
    scratch: Allocator,
    pc: PendingCompare,
) impostor.CachedResult {
    if (pc.default_branch) |def| {
        switch (compareRest(scratch, pc.owner, pc.repo, def.name, pc.sha)) {
            .reachable => return .{
                .status = .legitimate,
            },
            .unknown => {
                // Network/auth failure on the default-branch compare leaves
                // the verdict ambiguous; fail-closed.
                return .{ .status = .unknown };
            },
            .unreachable_ => {},
        }
    }

    // step4: try every other ref as a compare base. Branches first, then
    // tags — branches change more often, so an ahead/diverged sha is more
    // likely to surface there. Any reachable hit short-circuits to
    // legitimate.
    var saw_unknown = false;
    if (compareAllRefs(scratch, pc, pc.branch_oids, pc.default_branch)) |found_legit| {
        if (found_legit == .legit) return .{ .status = .legitimate };
        if (found_legit == .unknown) saw_unknown = true;
    }
    if (compareAllRefs(scratch, pc, pc.tag_oids, null)) |found_legit| {
        if (found_legit == .legit) return .{ .status = .legitimate };
        if (found_legit == .unknown) saw_unknown = true;
    }

    if (saw_unknown) return .{ .status = .unknown };

    return .{
        .status = .impostor,
        .suggested_tags = pc.tag_oids,
        .suggested_default = pc.default_branch,
    };
}

/// `skip` lets the caller avoid re-checking a ref already tried (the default
/// branch).
fn compareAllRefs(
    scratch: Allocator,
    pc: PendingCompare,
    refs: []const graphql.NamedOid,
    skip: ?graphql.NamedOid,
) ?RefSweepResult {
    if (refs.len == 0) return null;
    var saw_unknown = false;
    for (refs) |r| {
        if (engine.isNetworkDeadlineExceeded()) return .unknown;
        if (skip) |s| {
            if (std.mem.eql(u8, s.name, r.name)) continue;
        }
        switch (compareRest(scratch, pc.owner, pc.repo, r.name, pc.sha)) {
            .reachable => return .legit,
            .unknown => saw_unknown = true,
            .unreachable_ => {},
        }
    }
    if (saw_unknown) return .unknown;
    return .all_unreachable;
}

/// Any non-200 response or parse failure returns `.unknown` so SC008
/// fail-closes on uncertainty.
fn compareRest(
    scratch: Allocator,
    owner: []const u8,
    repo: []const u8,
    base: []const u8,
    head: []const u8,
) CompareStatus {
    if (!engine.isValidGitHubComponent(owner)) return .unknown;
    if (!engine.isValidGitHubComponent(repo)) return .unknown;
    if (!engine.isValidGitRef(base)) return .unknown;
    if (!engine.isValidSha(head)) return .unknown;

    // Branch/tag names can contain '/' (e.g. "release/v1.0"). Percent-encode
    // the base segment so the compare endpoint doesn't route those characters
    // as extra path components and force us into a fail-closed unknown.
    const base_encoded = percentEncodePathSegment(scratch, base) orelse return .unknown;

    const url = std.fmt.allocPrint(
        scratch,
        "https://api.github.com/repos/{s}/{s}/compare/{s}...{s}",
        .{ owner, repo, base_encoded, head },
    ) catch return .unknown;

    var resp = http_client.fetchAuthenticatedJson(scratch, url) catch return .unknown;
    defer resp.deinit();

    if (resp.status != .ok) return .unknown;

    return parseCompareStatus(scratch, resp.body);
}

fn parseCompareStatus(scratch: Allocator, body: []const u8) CompareStatus {
    const root = std.json.parseFromSliceLeaky(std.json.Value, scratch, body, .{}) catch return .unknown;
    const obj = json_util.asObject(root) orelse return .unknown;
    const status = json_util.stringField(obj, "status") orelse return .unknown;
    if (std.mem.eql(u8, status, "identical") or std.mem.eql(u8, status, "behind")) {
        return .reachable;
    }
    if (std.mem.eql(u8, status, "ahead") or std.mem.eql(u8, status, "diverged")) {
        return .unreachable_;
    }
    return .unknown;
}

fn percentEncodePathSegment(scratch: Allocator, s: []const u8) ?[]const u8 {
    for (s) |c| {
        if (!isUnreserved(c)) break;
    } else return s;

    var out: std.Io.Writer.Allocating = .init(scratch);
    std.Uri.Component.percentEncode(&out.writer, s, isUnreserved) catch return null;
    return out.written();
}

fn isUnreserved(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

const testing = std.testing;

test "classifyImpostorFromGraphql: tag oid match yields legitimate (no pending)" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const tag_oids = [_]graphql.NamedOid{.{ .name = "v1", .oid = sha }};
    const sha_results = [_]graphql.ShaTagResult{.{ .sha = sha, .resolution = .has_tag }};
    const res = graphql.RepoResult{
        .owner = "o",
        .repo = "r",
        .sha_results = &sha_results,
        .tag_oids = &tag_oids,
    };

    var pending = std.ArrayList(PendingCompare){};
    defer pending.deinit(alloc);
    classifyImpostorFromGraphql(alloc, res, &pending);

    try testing.expectEqual(@as(usize, 0), pending.items.len);
    const cached = impostor.lookupCachedImpostorResult("o", "r", sha) orelse return error.TestExpectedNonNull;
    try testing.expectEqual(impostor.ImpostorStatus.legitimate, cached.status);
}

test "classifyImpostorFromGraphql: branch HEAD match yields legitimate" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const sha = "0123456789abcdef0123456789abcdef01234567";
    const branch_oids = [_]graphql.NamedOid{.{ .name = "main", .oid = sha }};
    const sha_results = [_]graphql.ShaTagResult{.{ .sha = sha, .resolution = .no_tag }};
    const res = graphql.RepoResult{
        .owner = "o",
        .repo = "r",
        .sha_results = &sha_results,
        .branch_oids = &branch_oids,
    };

    var pending = std.ArrayList(PendingCompare){};
    defer pending.deinit(alloc);
    classifyImpostorFromGraphql(alloc, res, &pending);

    try testing.expectEqual(@as(usize, 0), pending.items.len);
    const cached = impostor.lookupCachedImpostorResult("o", "r", sha) orelse return error.TestExpectedNonNull;
    try testing.expectEqual(impostor.ImpostorStatus.legitimate, cached.status);
}

test "classifyImpostorFromGraphql: pagination incomplete fails closed to unknown" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const sha = "0011223344556677889900112233445566778899";
    const sha_results = [_]graphql.ShaTagResult{.{ .sha = sha, .resolution = .unknown }};
    const res = graphql.RepoResult{
        .owner = "o",
        .repo = "r",
        .sha_results = &sha_results,
        .tag_oids_complete = false,
    };

    var pending = std.ArrayList(PendingCompare){};
    defer pending.deinit(alloc);
    classifyImpostorFromGraphql(alloc, res, &pending);

    try testing.expectEqual(@as(usize, 0), pending.items.len);
    const cached = impostor.lookupCachedImpostorResult("o", "r", sha) orelse return error.TestExpectedNonNull;
    try testing.expectEqual(impostor.ImpostorStatus.unknown, cached.status);
}

test "classifyImpostorFromGraphql: no match queues pending compare entry" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const sha = "ffffffffffffffffffffffffffffffffffffffff";
    const tag_oids = [_]graphql.NamedOid{.{ .name = "v1", .oid = "aaaaaaaa" }};
    const branch_oids = [_]graphql.NamedOid{.{ .name = "main", .oid = "bbbbbbbb" }};
    const sha_results = [_]graphql.ShaTagResult{.{ .sha = sha, .resolution = .no_tag }};
    const default_branch = graphql.NamedOid{ .name = "main", .oid = "bbbbbbbb" };
    const res = graphql.RepoResult{
        .owner = "o",
        .repo = "r",
        .sha_results = &sha_results,
        .tag_oids = &tag_oids,
        .branch_oids = &branch_oids,
        .default_branch = default_branch,
    };

    var pending = std.ArrayList(PendingCompare){};
    defer pending.deinit(alloc);
    classifyImpostorFromGraphql(alloc, res, &pending);

    try testing.expectEqual(@as(usize, 1), pending.items.len);
    try testing.expectEqualStrings(sha, pending.items[0].sha);
    try testing.expect(pending.items[0].default_branch != null);
    try testing.expectEqualStrings("main", pending.items[0].default_branch.?.name);

    try testing.expect(impostor.lookupCachedImpostorResult("o", "r", sha) == null);
}

test "classifyImpostorFromGraphql: null pending forces unknown" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    _ = alloc;

    const sha = "1111111111111111111111111111111111111111";
    const sha_results = [_]graphql.ShaTagResult{.{ .sha = sha, .resolution = .no_tag }};
    const res = graphql.RepoResult{
        .owner = "o",
        .repo = "r",
        .sha_results = &sha_results,
    };

    classifyImpostorFromGraphql(testing.allocator, res, null);

    const cached = impostor.lookupCachedImpostorResult("o", "r", sha) orelse return error.TestExpectedNonNull;
    try testing.expectEqual(impostor.ImpostorStatus.unknown, cached.status);
}

test "parseCompareStatus: identical and behind are reachable" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqual(CompareStatus.reachable, parseCompareStatus(arena.allocator(), "{\"status\":\"identical\"}"));
    try testing.expectEqual(CompareStatus.reachable, parseCompareStatus(arena.allocator(), "{\"status\":\"behind\"}"));
}

test "parseCompareStatus: ahead and diverged are unreachable" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqual(CompareStatus.unreachable_, parseCompareStatus(arena.allocator(), "{\"status\":\"ahead\"}"));
    try testing.expectEqual(CompareStatus.unreachable_, parseCompareStatus(arena.allocator(), "{\"status\":\"diverged\"}"));
}

test "parseCompareStatus: unknown / malformed inputs map to unknown" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqual(CompareStatus.unknown, parseCompareStatus(arena.allocator(), "{\"status\":\"weird\"}"));
    try testing.expectEqual(CompareStatus.unknown, parseCompareStatus(arena.allocator(), "{}"));
    try testing.expectEqual(CompareStatus.unknown, parseCompareStatus(arena.allocator(), "not-json"));
    try testing.expectEqual(CompareStatus.unknown, parseCompareStatus(arena.allocator(), "[\"array\"]"));
}

test "runImpostorCompares: deadline-expired entries all map to unknown" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    engine.network_deadline_ns = std.time.nanoTimestamp() - 1;
    defer engine.clearNetworkDeadline();

    const pending = [_]PendingCompare{
        .{
            .owner = "o",
            .repo = "r",
            .sha = "2222222222222222222222222222222222222222",
            .default_branch = null,
            .tag_oids = &.{},
            .branch_oids = &.{},
        },
    };

    runImpostorCompares(alloc, &pending);

    const cached = impostor.lookupCachedImpostorResult("o", "r", "2222222222222222222222222222222222222222") orelse
        return error.TestExpectedNonNull;
    try testing.expectEqual(impostor.ImpostorStatus.unknown, cached.status);
}

test "compareRest: invalid component arguments fail closed to unknown without network" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    try testing.expectEqual(CompareStatus.unknown, compareRest(alloc, "..", "r", "main", "0000000000000000000000000000000000000000"));
    try testing.expectEqual(CompareStatus.unknown, compareRest(alloc, "o", "..", "main", "0000000000000000000000000000000000000000"));
    try testing.expectEqual(CompareStatus.unknown, compareRest(alloc, "o", "r", "../evil", "0000000000000000000000000000000000000000"));
    try testing.expectEqual(CompareStatus.unknown, compareRest(alloc, "o", "r", "main", "not-a-sha"));
}

test "percentEncodePathSegment: refs with slashes are encoded" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const out = percentEncodePathSegment(alloc, "release/v1.0").?;
    try testing.expectEqualStrings("release%2Fv1.0", out);
}

test "percentEncodePathSegment: plain ref passes through unchanged" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const s = "main";
    const out = percentEncodePathSegment(alloc, s).?;
    // Unchanged inputs return the original slice without allocation.
    try testing.expectEqual(s.ptr, out.ptr);
    try testing.expectEqualStrings("main", out);
}

test "percentEncodePathSegment: nested slashes and dots encode correctly" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const out = percentEncodePathSegment(alloc, "feature/foo/bar-1.2_3").?;
    try testing.expectEqualStrings("feature%2Ffoo%2Fbar-1.2_3", out);
}
