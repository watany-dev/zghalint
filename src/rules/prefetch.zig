//! Collects the unique `(owner, repo)`, `(owner, repo, sha)` and
//! `(owner, repo, ref)` triples across all workflows and fetches them up front
//! through the shared HTTP client, so the TLS handshake cost is paid once
//! even when many actions are referenced. The REST path stays available as a
//! fallback for unauthenticated users.

const std = @import("std");
const workflow_types = @import("../workflow/types.zig");
const engine = @import("engine.zig");

const advisory = @import("advisory.zig");
const archived = @import("archived.zig");
const stale_refs = @import("stale_refs.zig");
const refconfusion = @import("refconfusion.zig");
const impostor = @import("impostor.zig");
const impostor_compare = @import("impostor_compare.zig");
const graphql = @import("graphql.zig");
const disk_cache = @import("disk_cache.zig");
const http_client = @import("http_client.zig");
const rest_fallback = @import("rest_fallback.zig");

const PendingCompare = impostor_compare.PendingCompare;

const Allocator = std.mem.Allocator;
const Workflow = workflow_types.Workflow;

pub const Options = struct {
    no_cache: bool = false,
};

/// Threaded through the prefetch pipeline so every stage can skip the work
/// no rule asked for.
const ActiveRules = struct {
    archived: bool,
    stale: bool,
    refconf: bool,
    impostor: bool,

    fn detect() ActiveRules {
        return .{
            .archived = archived.isActive(),
            .stale = stale_refs.isActive(),
            .refconf = refconfusion.isActive(),
            .impostor = impostor.isActive(),
        };
    }

    fn any(self: ActiveRules) bool {
        return self.archived or self.stale or self.refconf or self.impostor;
    }
};

pub fn prefetchAllWithOptions(
    allocator: Allocator,
    workflows: []const Workflow,
    opts: Options,
) !void {
    advisory.prefetch();

    const active = ActiveRules.detect();
    if (!active.any()) return;

    var scratch_arena = std.heap.ArenaAllocator.init(allocator);
    defer scratch_arena.deinit();
    const scratch = scratch_arena.allocator();

    var ref_sets = try collectRefs(scratch, workflows);

    if (!opts.no_cache) {
        _ = applyDiskCache(scratch, &ref_sets, active);
    }

    // GraphQL first; falls back to REST on no-token, parse failure, or
    // rate-limit. SC008's REST compare phase rides on top of the same
    // GraphQL data so it shares whatever batches succeeded.
    var pending_compares = std.ArrayList(PendingCompare){};
    defer pending_compares.deinit(scratch);

    // Buffer GraphQL results so persistence runs after SC008's compare
    // phase has populated the impostor cache. Otherwise the disk_cache
    // entry would miss step3/4 verdicts on warm runs.
    var pending_persist = std.ArrayList(graphql.RepoResult){};
    defer pending_persist.deinit(scratch);

    const used_graphql = tryGraphQlBatch(
        scratch,
        ref_sets,
        active,
        &pending_compares,
        &pending_persist,
    );

    if (!used_graphql) {
        if (active.archived) fetchRepos(scratch, ref_sets.repos);
        if (active.stale) fetchShaRefs(scratch, ref_sets.sha_refs);
        if (active.refconf) fetchNamedRefs(scratch, ref_sets.named_refs);
    }

    if (active.impostor and pending_compares.items.len > 0) {
        impostor_compare.runImpostorCompares(scratch, pending_compares.items);
    }

    // Persisted only now that the impostor cache is fully populated.
    // Failures are non-fatal (best-effort warm-run hint).
    if (pending_persist.items.len > 0) {
        var cache_dir = disk_cache.getCacheDir(scratch);
        defer if (cache_dir) |*d| d.close();
        for (pending_persist.items) |res| {
            persistRepoResult(scratch, res, cache_dir);
        }
    }
}

const RepoKey = struct {
    owner: []const u8,
    repo: []const u8,
};

const ShaKey = struct {
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
};

const NamedKey = struct {
    owner: []const u8,
    repo: []const u8,
    ref: []const u8,
};

/// `"{owner}/{repo}@{ref}"` — each component is bounded by `engine.isValidGitRef`
/// (255 bytes), plus the `/` and `@` separators.
const max_ref_key_len = 255 * 3 + 2;

const RepoSet = std.StringHashMapUnmanaged(RepoKey);
const ShaSet = std.StringHashMapUnmanaged(ShaKey);
const NamedSet = std.StringHashMapUnmanaged(NamedKey);

const RefSets = struct {
    repos: RepoSet,
    sha_refs: ShaSet,
    named_refs: NamedSet,
};

/// `allocator` is the prefetch scratch arena, so the key allocated for an
/// already-present ref is simply dropped.
fn putRefKey(
    allocator: Allocator,
    set: anytype,
    owner: []const u8,
    repo: []const u8,
    ref: []const u8,
    value: anytype,
) !void {
    const key = try std.fmt.allocPrint(allocator, "{s}/{s}@{s}", .{ owner, repo, ref });
    if (set.contains(key)) return;
    try set.put(allocator, key, value);
}

fn collectRefs(allocator: Allocator, workflows: []const Workflow) !RefSets {
    var repos: RepoSet = .{};
    var sha_refs: ShaSet = .{};
    var named_refs: NamedSet = .{};

    for (workflows) |wf| {
        for (wf.jobs) |job| {
            for (job.steps) |step| {
                const action_ref = step.uses orelse continue;
                if (action_ref.is_local or action_ref.is_docker) continue;
                const owner = action_ref.owner orelse continue;
                const repo = action_ref.repo orelse continue;
                if (!engine.isValidGitHubComponent(owner)) continue;
                if (!engine.isValidGitHubComponent(repo)) continue;

                const repo_key = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ owner, repo });
                if (!repos.contains(repo_key)) {
                    try repos.put(allocator, repo_key, .{ .owner = owner, .repo = repo });
                }

                const ref = action_ref.ref orelse continue;
                if (action_ref.is_pinned) {
                    try putRefKey(allocator, &sha_refs, owner, repo, ref, ShaKey{ .owner = owner, .repo = repo, .sha = ref });
                } else {
                    if (!engine.isValidGitRef(ref)) continue;
                    try putRefKey(allocator, &named_refs, owner, repo, ref, NamedKey{ .owner = owner, .repo = repo, .ref = ref });
                }
            }
        }
    }

    return .{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };
}

/// Satisfied refs are removed from `sets` so the GraphQL / REST phase only
/// fetches what the disk cache could not supply.
fn applyDiskCache(
    scratch: Allocator,
    sets: *RefSets,
    active: ActiveRules,
) usize {
    var hits: usize = 0;

    // Opened once for the whole sweep: `disk_cache.load` resolves and opens
    // the cache directory per call, which is a per-repo open on a path that
    // never changes during a run.
    var cache_dir = disk_cache.getCacheDir(scratch) orelse return hits;
    defer cache_dir.close();

    // Iterate over a stable snapshot because `sets` is mutated while iterating.
    var repo_keys = std.ArrayList([]const u8){};
    defer repo_keys.deinit(scratch);
    var rk_it = sets.repos.keyIterator();
    while (rk_it.next()) |k| repo_keys.append(scratch, k.*) catch return hits;

    for (repo_keys.items) |repo_key| {
        const val_ptr = sets.repos.getPtr(repo_key) orelse continue;
        const owner = val_ptr.owner;
        const repo = val_ptr.repo;

        const entry = disk_cache.loadFromDir(cache_dir, scratch, owner, repo) orelse continue;
        hits += applyCacheEntry(sets, repo_key, owner, repo, entry, active);
    }

    return hits;
}

/// Factored out of `applyDiskCache` so tests can drive the mutation logic
/// without staging files on disk.
fn applyCacheEntry(
    sets: *RefSets,
    repo_key: []const u8,
    owner: []const u8,
    repo: []const u8,
    entry: disk_cache.CachedRepo,
    active: ActiveRules,
) usize {
    var hits: usize = 0;

    if (active.archived) {
        if (entry.archived) |b| {
            archived.setCachedResult(owner, repo, b);
            _ = sets.repos.remove(repo_key);
            hits += 1;
        }
    }

    if (active.stale) {
        for (entry.shas) |s| {
            var key_buf: [max_ref_key_len]u8 = undefined;
            const key = std.fmt.bufPrint(&key_buf, "{s}/{s}@{s}", .{ owner, repo, s.sha }) catch continue;
            if (sets.sha_refs.getPtr(key)) |_| {
                const mapped: stale_refs.TagResolution = switch (s.resolution) {
                    .has_tag => .has_tag,
                    .no_tag => .no_tag,
                    .unknown => .unknown,
                };
                stale_refs.setCachedTagResult(owner, repo, s.sha, mapped);
                _ = sets.sha_refs.remove(key);
                hits += 1;
            }
        }
    }

    if (active.refconf) {
        for (entry.named) |n| {
            var key_buf: [max_ref_key_len]u8 = undefined;
            const key = std.fmt.bufPrint(&key_buf, "{s}/{s}@{s}", .{ owner, repo, n.ref }) catch continue;
            if (sets.named_refs.getPtr(key)) |_| {
                const status: refconfusion.RefStatus = if (n.is_tag and n.is_branch)
                    .ambiguous
                else
                    .not_ambiguous;
                refconfusion.setCachedRefResult(owner, repo, n.ref, status);
                _ = sets.named_refs.remove(key);
                hits += 1;
            }
        }
    }

    // SC008 verdicts are keyed by the same (owner, repo, sha) tuple that
    // stale_refs uses, so we unconditionally seed the impostor cache from
    // disk when the rule is active. The fix_hint candidates are lost across
    // process boundaries because suggested_tags/default live in the arena;
    // the next compare phase re-supplies them if needed.
    if (active.impostor) {
        for (entry.impostor) |e| {
            impostor.setCachedImpostorResult(owner, repo, e.sha, .{ .status = e.status });
        }
    }

    return hits;
}

/// Non-fatal: failures are ignored so that a missing cache dir or permission
/// error never blocks the lint run.
///
/// SC008 verdicts are read back out of the impostor module's cache, so
/// callers must run `runImpostorCompares` first if step3/4 results are
/// expected on disk.
/// `dir` lets a caller persisting several repos reuse one cache-directory
/// handle; `null` resolves and opens it for this single entry.
fn persistRepoResult(scratch: Allocator, res: graphql.RepoResult, dir: ?std.fs.Dir) void {
    if (res.missing) return;
    const entry: disk_cache.CachedRepo = .{
        .cached_at = std.time.timestamp(),
        .archived = res.archived,
        .shas = res.sha_results,
        .named = res.named_results,
        .branches = res.branch_oids,
        .default_branch = res.default_branch,
        .impostor = blk: {
            if (!impostor.isActive() or res.sha_results.len == 0) break :blk &.{};
            var list = std.ArrayList(disk_cache.ImpostorEntry){};
            defer list.deinit(scratch);
            for (res.sha_results) |sr| {
                const cached = impostor.lookupCachedImpostorResult(res.owner, res.repo, sr.sha) orelse continue;
                list.append(scratch, .{ .sha = sr.sha, .status = cached.status }) catch break :blk &.{};
            }
            break :blk list.toOwnedSlice(scratch) catch &.{};
        },
    };
    if (dir) |d| {
        disk_cache.saveToDir(d, scratch, res.owner, res.repo, entry) catch return;
    } else {
        disk_cache.save(scratch, res.owner, res.repo, entry) catch return;
    }
}

fn tryGraphQlBatch(
    scratch: Allocator,
    sets: RefSets,
    active: ActiveRules,
    pending: *std.ArrayList(PendingCompare),
    persist_buffer: ?*std.ArrayList(graphql.RepoResult),
) bool {
    if (sets.repos.count() == 0) return false;

    const inputs = buildRepoInputs(scratch, sets, active) catch return false;

    var idx: usize = 0;
    while (idx < inputs.len) {
        if (engine.isNetworkDeadlineExceeded()) return idx > 0;
        // Recomputed per tail so purely SC004/5/6 batches keep the larger
        // per-post throughput.
        const batch_limit = graphql.maxReposPerBatch(inputs[idx..]);
        const end = @min(idx + batch_limit, inputs.len);
        const chunk = inputs[idx..end];

        const results = graphql.batchQuery(scratch, chunk) catch |err| switch (err) {
            error.NoToken => return false, // fall back to REST
            error.RateLimited => return idx > 0, // give up; keep what we have
            else => return false,
        };

        applyResults(
            scratch,
            results,
            active,
            pending,
            persist_buffer,
        );
        idx = end;
    }

    return true;
}

const RefsByRepo = std.StringHashMapUnmanaged(std.ArrayListUnmanaged([]const u8));

fn appendByRepo(
    scratch: Allocator,
    map: *RefsByRepo,
    owner: []const u8,
    repo: []const u8,
    value: []const u8,
) !void {
    const repo_key = try std.fmt.allocPrint(scratch, "{s}/{s}", .{ owner, repo });
    const gop = try map.getOrPut(scratch, repo_key);
    if (!gop.found_existing) gop.value_ptr.* = .{};
    try gop.value_ptr.append(scratch, value);
}

fn buildRepoInputs(
    scratch: Allocator,
    sets: RefSets,
    active: ActiveRules,
) ![]graphql.RepoInput {
    var inputs = try scratch.alloc(graphql.RepoInput, sets.repos.count());
    var shas_by_repo: RefsByRepo = .{};
    var named_by_repo: RefsByRepo = .{};

    // SC008 also needs per-repo SHA lists so it can decide which SHAs to
    // classify against branch/tag oids. Populate the shared map whenever
    // either SC005 or SC008 is active so SC008 doesn't silently lose data
    // when the user only opted into impostor checks.
    if (active.stale or active.impostor) {
        var it = sets.sha_refs.valueIterator();
        while (it.next()) |sha_key| {
            try appendByRepo(scratch, &shas_by_repo, sha_key.owner, sha_key.repo, sha_key.sha);
        }
    }
    if (active.refconf) {
        var it = sets.named_refs.valueIterator();
        while (it.next()) |named_key| {
            try appendByRepo(scratch, &named_by_repo, named_key.owner, named_key.repo, named_key.ref);
        }
    }

    var i: usize = 0;
    var repo_it = sets.repos.iterator();
    while (repo_it.next()) |entry| : (i += 1) {
        const repo_key = entry.key_ptr.*;
        const val = entry.value_ptr.*;

        const sha_slice: []const []const u8 = if (shas_by_repo.getPtr(repo_key)) |list|
            list.items
        else
            &.{};
        const named_slice: []const []const u8 = if (named_by_repo.getPtr(repo_key)) |list|
            list.items
        else
            &.{};

        inputs[i] = .{
            .owner = val.owner,
            .repo = val.repo,
            .sha_refs = sha_slice,
            .named_refs = named_slice,
            // SC008 only needs the extra branch + default fetch when there
            // are SHA-pinned refs to evaluate against. Without SHAs there's
            // nothing to classify even if impostor checking is on.
            .needs_impostor = active.impostor and sha_slice.len > 0,
        };
    }

    return inputs;
}

fn applyResults(
    scratch: Allocator,
    results: []const graphql.RepoResult,
    active: ActiveRules,
    pending: ?*std.ArrayList(PendingCompare),
    persist_buffer: ?*std.ArrayList(graphql.RepoResult),
) void {
    for (results) |res| {
        if (res.missing) continue;
        if (active.archived) {
            if (res.archived) |b| archived.setCachedResult(res.owner, res.repo, b);
        }
        if (active.stale) {
            for (res.sha_results) |sr| {
                const mapped: stale_refs.TagResolution = switch (sr.resolution) {
                    .has_tag => .has_tag,
                    .no_tag => .no_tag,
                    .unknown => .unknown,
                };
                stale_refs.setCachedTagResult(res.owner, res.repo, sr.sha, mapped);
            }
        }
        if (active.refconf) {
            for (res.named_results) |nr| {
                const status: refconfusion.RefStatus = if (nr.is_tag and nr.is_branch)
                    .ambiguous
                else
                    .not_ambiguous;
                refconfusion.setCachedRefResult(res.owner, res.repo, nr.ref, status);
            }
        }
        if (active.impostor) {
            impostor_compare.classifyImpostorFromGraphql(scratch, res, pending);
        }
        // When the caller buffers persistence (production path) we defer
        // until after SC008's compare phase so the impostor verdicts make
        // it into the disk_cache entry. With no buffer (test path) persist
        // immediately so single-test assertions still see the file land.
        if (persist_buffer) |buf| {
            buf.append(scratch, res) catch persistRepoResult(scratch, res, null);
        } else {
            persistRepoResult(scratch, res, null);
        }
    }
}

fn fetchRepos(scratch: Allocator, set: RepoSet) void {
    var it = set.valueIterator();
    while (it.next()) |key| {
        if (engine.isNetworkDeadlineExceeded()) return;
        const is_archived = rest_fallback.fetchArchiveStatus(scratch, key.owner, key.repo) catch continue;
        archived.setCachedResult(key.owner, key.repo, is_archived);
    }
}

const ShaGroup = struct {
    owner: []const u8,
    repo: []const u8,
    shas: std.ArrayListUnmanaged([]const u8) = .{},
};

/// The REST tag listing is per-repository, so grouping first turns "one
/// request per pinned SHA" into "one request per repository". Insertion order
/// is preserved so the deadline truncates the same prefix on every run.
fn groupShasByRepo(scratch: Allocator, set: ShaSet) std.StringArrayHashMapUnmanaged(ShaGroup) {
    var by_repo: std.StringArrayHashMapUnmanaged(ShaGroup) = .{};

    var it = set.valueIterator();
    while (it.next()) |key| {
        const repo_key = std.fmt.allocPrint(scratch, "{s}/{s}", .{ key.owner, key.repo }) catch continue;
        const gop = by_repo.getOrPut(scratch, repo_key) catch continue;
        if (!gop.found_existing) gop.value_ptr.* = .{ .owner = key.owner, .repo = key.repo };
        gop.value_ptr.shas.append(scratch, key.sha) catch continue;
    }

    return by_repo;
}

fn fetchShaRefs(scratch: Allocator, set: ShaSet) void {
    var by_repo = groupShasByRepo(scratch, set);

    var it = by_repo.iterator();
    while (it.next()) |entry| {
        if (engine.isNetworkDeadlineExceeded()) return;
        const group = entry.value_ptr;
        const shas = group.shas.items;

        const out = scratch.alloc(rest_fallback.TagResolution, shas.len) catch continue;
        // A transport failure leaves every entry `.unknown`, matching the
        // per-SHA fallback the loop used before batching.
        rest_fallback.resolveTagsForShas(scratch, group.owner, group.repo, shas, out) catch
            @memset(out, rest_fallback.TagResolution.unknown);

        for (shas, out) |sha, resolution| {
            stale_refs.setCachedTagResult(group.owner, group.repo, sha, resolution);
        }
    }
}

fn fetchNamedRefs(scratch: Allocator, set: NamedSet) void {
    var it = set.valueIterator();
    while (it.next()) |key| {
        if (engine.isNetworkDeadlineExceeded()) return;
        const status = rest_fallback.queryRefStatus(scratch, key.owner, key.repo, key.ref);
        refconfusion.setCachedRefResult(key.owner, key.repo, key.ref, status);
    }
}

const test_support = @import("../test_support.zig");
const testing = std.testing;
const ActionRef = workflow_types.ActionRef;
const Step = workflow_types.Step;
const Job = workflow_types.Job;

test "prefetchAllWithOptions: offline-only is a no-op" {
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &.{} };
    const wfs = [_]Workflow{wf};
    try prefetchAllWithOptions(testing.allocator, &wfs, .{});
}

test "groupShasByRepo: collapses one repo's SHAs into a single request unit" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const scratch = arena.allocator();

    const sha_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const sha_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const sha_c = "cccccccccccccccccccccccccccccccccccccccc";

    var set: ShaSet = .{};
    try putRefKey(scratch, &set, "actions", "checkout", sha_a, ShaKey{ .owner = "actions", .repo = "checkout", .sha = sha_a });
    try putRefKey(scratch, &set, "actions", "checkout", sha_b, ShaKey{ .owner = "actions", .repo = "checkout", .sha = sha_b });
    try putRefKey(scratch, &set, "actions", "setup-node", sha_c, ShaKey{ .owner = "actions", .repo = "setup-node", .sha = sha_c });

    var by_repo = groupShasByRepo(scratch, set);

    // Three pinned SHAs, but only two repositories to query.
    try testing.expectEqual(@as(usize, 2), by_repo.count());
    try testing.expectEqual(@as(usize, 2), by_repo.get("actions/checkout").?.shas.items.len);
    try testing.expectEqual(@as(usize, 1), by_repo.get("actions/setup-node").?.shas.items.len);
}

test "groupShasByRepo: empty set yields no groups" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var by_repo = groupShasByRepo(arena.allocator(), ShaSet{});
    try testing.expectEqual(@as(usize, 0), by_repo.count());
}

test "collectRefs: deduplicates repeated action refs" {
    const step_a = Step{ .uses = ActionRef.parse("actions/checkout@v4") };
    const step_b = Step{ .uses = ActionRef.parse("actions/checkout@v4") };
    const step_c = Step{ .uses = ActionRef.parse("actions/setup-node@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0") };
    const steps = [_]Step{ step_a, step_b, step_c };
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &jobs };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const sets = try collectRefs(arena.allocator(), &[_]Workflow{wf});

    try testing.expectEqual(@as(usize, 2), sets.repos.count());
    try testing.expectEqual(@as(usize, 1), sets.sha_refs.count());
    try testing.expectEqual(@as(usize, 1), sets.named_refs.count());
}

test "collectRefs: skips local and docker actions" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("./local-action") },
        .{ .uses = ActionRef.parse("docker://alpine:3.18") },
        .{ .run = "echo hi" },
    };
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &jobs };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const sets = try collectRefs(arena.allocator(), &[_]Workflow{wf});

    try testing.expectEqual(@as(usize, 0), sets.repos.count());
    try testing.expectEqual(@as(usize, 0), sets.sha_refs.count());
    try testing.expectEqual(@as(usize, 0), sets.named_refs.count());
}

test "collectRefs: rejects invalid owner/repo characters" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("evil?org/repo@main") },
        .{ .uses = ActionRef.parse("org/evil#repo@main") },
    };
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &jobs };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const sets = try collectRefs(arena.allocator(), &[_]Workflow{wf});
    try testing.expectEqual(@as(usize, 0), sets.repos.count());
}

test "buildRepoInputs groups sha and named refs by repo" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var repos: RepoSet = .{};
    try repos.put(alloc, "actions/checkout", .{ .owner = "actions", .repo = "checkout" });
    try repos.put(alloc, "actions/setup-node", .{ .owner = "actions", .repo = "setup-node" });

    var sha_refs: ShaSet = .{};
    try sha_refs.put(alloc, "actions/checkout@aa", .{ .owner = "actions", .repo = "checkout", .sha = "aa" });
    try sha_refs.put(alloc, "actions/checkout@bb", .{ .owner = "actions", .repo = "checkout", .sha = "bb" });
    try sha_refs.put(alloc, "actions/setup-node@cc", .{ .owner = "actions", .repo = "setup-node", .sha = "cc" });

    var named_refs: NamedSet = .{};
    try named_refs.put(alloc, "actions/checkout@v4", .{ .owner = "actions", .repo = "checkout", .ref = "v4" });

    const sets = RefSets{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };
    const inputs = try buildRepoInputs(alloc, sets, .{ .archived = true, .stale = true, .refconf = true, .impostor = false });

    try testing.expectEqual(@as(usize, 2), inputs.len);

    // Order is hash-map dependent; locate by owner/repo.
    var checkout_idx: usize = 0;
    var setup_idx: usize = 0;
    for (inputs, 0..) |input, i| {
        if (std.mem.eql(u8, input.repo, "checkout")) checkout_idx = i;
        if (std.mem.eql(u8, input.repo, "setup-node")) setup_idx = i;
    }

    try testing.expectEqual(@as(usize, 2), inputs[checkout_idx].sha_refs.len);
    try testing.expectEqual(@as(usize, 1), inputs[checkout_idx].named_refs.len);
    try testing.expectEqualStrings("v4", inputs[checkout_idx].named_refs[0]);
    try testing.expectEqual(@as(usize, 1), inputs[setup_idx].sha_refs.len);
    try testing.expectEqual(@as(usize, 0), inputs[setup_idx].named_refs.len);
}

test "buildRepoInputs: inactive rules leave slices empty" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var repos: RepoSet = .{};
    try repos.put(alloc, "o/r", .{ .owner = "o", .repo = "r" });
    var sha_refs: ShaSet = .{};
    try sha_refs.put(alloc, "o/r@ff", .{ .owner = "o", .repo = "r", .sha = "ff" });
    var named_refs: NamedSet = .{};
    try named_refs.put(alloc, "o/r@v1", .{ .owner = "o", .repo = "r", .ref = "v1" });

    const sets = RefSets{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };
    const inputs = try buildRepoInputs(alloc, sets, .{ .archived = true, .stale = false, .refconf = false, .impostor = false });
    try testing.expectEqual(@as(usize, 1), inputs.len);
    try testing.expectEqual(@as(usize, 0), inputs[0].sha_refs.len);
    try testing.expectEqual(@as(usize, 0), inputs[0].named_refs.len);
    try testing.expect(!inputs[0].needs_impostor);
}

test "applyCacheEntry: fresh hit drops repo/shas/named from sets and counts hits" {
    archived.initArchived(testing.allocator, false);
    defer archived.deinitArchived();
    stale_refs.initStaleRefs(testing.allocator, false);
    defer stale_refs.deinitStaleRefs();
    refconfusion.initRefConfusion(testing.allocator, false);
    defer refconfusion.deinitRefConfusion();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const repo_key = "o/r";
    var repos: RepoSet = .{};
    try repos.put(alloc, repo_key, .{ .owner = "o", .repo = "r" });
    var sha_refs: ShaSet = .{};
    const sha_key = "o/r@deadbeef";
    try sha_refs.put(alloc, sha_key, .{ .owner = "o", .repo = "r", .sha = "deadbeef" });
    var named_refs: NamedSet = .{};
    const named_key = "o/r@main";
    try named_refs.put(alloc, named_key, .{ .owner = "o", .repo = "r", .ref = "main" });
    var sets = RefSets{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };

    const shas = [_]disk_cache.ShaEntry{.{ .sha = "deadbeef", .resolution = .no_tag }};
    const named = [_]disk_cache.NamedEntry{.{ .ref = "main", .is_tag = true, .is_branch = true }};
    const entry = disk_cache.CachedRepo{
        .cached_at = std.time.timestamp(),
        .archived = true,
        .shas = @constCast(&shas),
        .named = @constCast(&named),
    };

    const hits = applyCacheEntry(&sets, repo_key, "o", "r", entry, .{ .archived = true, .stale = true, .refconf = true, .impostor = false });
    try testing.expectEqual(@as(usize, 3), hits);
    try testing.expectEqual(@as(usize, 0), sets.repos.count());
    try testing.expectEqual(@as(usize, 0), sets.sha_refs.count());
    try testing.expectEqual(@as(usize, 0), sets.named_refs.count());
}

test "applyCacheEntry: inactive rules skip corresponding categories" {
    archived.initArchived(testing.allocator, false);
    defer archived.deinitArchived();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var repos: RepoSet = .{};
    try repos.put(alloc, "o/r", .{ .owner = "o", .repo = "r" });
    var sha_refs: ShaSet = .{};
    try sha_refs.put(alloc, "o/r@ff", .{ .owner = "o", .repo = "r", .sha = "ff" });
    var named_refs: NamedSet = .{};
    try named_refs.put(alloc, "o/r@main", .{ .owner = "o", .repo = "r", .ref = "main" });
    var sets = RefSets{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };

    const shas = [_]disk_cache.ShaEntry{.{ .sha = "ff", .resolution = .has_tag }};
    const named = [_]disk_cache.NamedEntry{.{ .ref = "main", .is_tag = true, .is_branch = false }};
    const entry = disk_cache.CachedRepo{
        .cached_at = std.time.timestamp(),
        .archived = false,
        .shas = @constCast(&shas),
        .named = @constCast(&named),
    };

    const hits = applyCacheEntry(&sets, "o/r", "o", "r", entry, .{ .archived = true, .stale = false, .refconf = false, .impostor = false });
    try testing.expectEqual(@as(usize, 1), hits);
    try testing.expectEqual(@as(usize, 0), sets.repos.count());
    try testing.expectEqual(@as(usize, 1), sets.sha_refs.count());
    try testing.expectEqual(@as(usize, 1), sets.named_refs.count());
}

test "applyCacheEntry: impostor hydrates SC008 verdicts from disk" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var sets = RefSets{
        .repos = .{},
        .sha_refs = .{},
        .named_refs = .{},
    };
    defer sets.repos.deinit(alloc);
    defer sets.sha_refs.deinit(alloc);
    defer sets.named_refs.deinit(alloc);

    const sha_legit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const sha_imp = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const imp_entries = [_]disk_cache.ImpostorEntry{
        .{ .sha = sha_legit, .status = .legitimate },
        .{ .sha = sha_imp, .status = .impostor },
    };
    const entry: disk_cache.CachedRepo = .{
        .impostor = @constCast(&imp_entries),
    };

    _ = applyCacheEntry(&sets, "o/r", "o", "r", entry, .{ .archived = false, .stale = false, .refconf = false, .impostor = true });

    const legit = impostor.lookupCachedImpostorResult("o", "r", sha_legit) orelse
        return error.TestExpectedNonNull;
    try testing.expectEqual(impostor.ImpostorStatus.legitimate, legit.status);

    const imp = impostor.lookupCachedImpostorResult("o", "r", sha_imp) orelse
        return error.TestExpectedNonNull;
    try testing.expectEqual(impostor.ImpostorStatus.impostor, imp.status);
}

test "applyResults: missing entries are skipped (no rule init required)" {
    // All rule modules left uninitialized; setCached* is a no-op when their
    // arenas are null, so this primarily exercises the missing-guard branch.
    const results = [_]graphql.RepoResult{
        .{ .owner = "o", .repo = "r", .missing = true },
    };
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    applyResults(arena.allocator(), &results, .{ .archived = true, .stale = true, .refconf = true, .impostor = false }, null, null);
}

test "prefetchAllWithOptions: deadline-expired short-circuits" {
    // Route all network fetches to the deadline-exceeded path so the test
    // never touches the network, yet still exercises the orchestrator's
    // GraphQL-fallback + per-rule REST loops.
    archived.initArchived(testing.allocator, false);
    defer archived.deinitArchived();
    stale_refs.initStaleRefs(testing.allocator, false);
    defer stale_refs.deinitStaleRefs();
    refconfusion.initRefConfusion(testing.allocator, false);
    defer refconfusion.deinitRefConfusion();

    engine.network_deadline_ns = std.time.nanoTimestamp() - 1;
    defer engine.clearNetworkDeadline();

    const sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@" ++ sha) },
        .{ .uses = ActionRef.parse("actions/setup-node@v4") },
    };
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &jobs };
    const wfs = [_]Workflow{wf};

    try prefetchAllWithOptions(testing.allocator, &wfs, .{ .no_cache = true });
}

test "applyDiskCache: reads entries from XDG_CACHE_HOME and drops them from sets" {
    archived.initArchived(testing.allocator, false);
    defer archived.deinitArchived();
    stale_refs.initStaleRefs(testing.allocator, false);
    defer stale_refs.deinitStaleRefs();
    refconfusion.initRefConfusion(testing.allocator, false);
    defer refconfusion.deinitRefConfusion();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var env = try test_support.EnvGuard.setDir(testing.allocator, "XDG_CACHE_HOME", tmp.dir);
    defer env.deinit();

    // Stage a fresh entry at the real on-disk cache location so that
    // `disk_cache.load` (via XDG resolution) finds it.
    const now = std.time.timestamp();
    const fake_sha = "abc1230000000000000000000000000000000000";
    const shas = [_]disk_cache.ShaEntry{.{ .sha = fake_sha, .resolution = .no_tag }};
    const named = [_]disk_cache.NamedEntry{.{ .ref = "main", .is_tag = true, .is_branch = true }};
    try disk_cache.save(testing.allocator, "acme", "tool", .{
        .cached_at = now,
        .archived = false,
        .shas = @constCast(&shas),
        .named = @constCast(&named),
    });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const repo_key = "acme/tool";
    var repos: RepoSet = .{};
    try repos.put(alloc, repo_key, .{ .owner = "acme", .repo = "tool" });
    var sha_refs: ShaSet = .{};
    try sha_refs.put(alloc, "acme/tool@" ++ fake_sha, .{ .owner = "acme", .repo = "tool", .sha = fake_sha });
    var named_refs: NamedSet = .{};
    try named_refs.put(alloc, "acme/tool@main", .{ .owner = "acme", .repo = "tool", .ref = "main" });
    var sets = RefSets{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };

    const hits = applyDiskCache(alloc, &sets, .{ .archived = true, .stale = true, .refconf = true, .impostor = false });
    try testing.expectEqual(@as(usize, 3), hits);
    try testing.expectEqual(@as(usize, 0), sets.repos.count());
    try testing.expectEqual(@as(usize, 0), sets.sha_refs.count());
    try testing.expectEqual(@as(usize, 0), sets.named_refs.count());
}

test "applyResults: persists repo state to the provided cache dir" {
    archived.initArchived(testing.allocator, false);
    defer archived.deinitArchived();
    stale_refs.initStaleRefs(testing.allocator, false);
    defer stale_refs.deinitStaleRefs();
    refconfusion.initRefConfusion(testing.allocator, false);
    defer refconfusion.deinitRefConfusion();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var env = try test_support.EnvGuard.setDir(testing.allocator, "XDG_CACHE_HOME", tmp.dir);
    defer env.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const fake_sha = "abcd000000000000000000000000000000000000";
    const sha_res = [_]graphql.ShaTagResult{.{ .sha = fake_sha, .resolution = .has_tag }};
    const named_res = [_]graphql.NamedRefResult{.{ .ref = "main", .is_tag = true, .is_branch = true }};
    const results = [_]graphql.RepoResult{
        .{
            .owner = "o",
            .repo = "r",
            .archived = false,
            .sha_results = &sha_res,
            .named_results = &named_res,
        },
    };

    applyResults(alloc, &results, .{ .archived = true, .stale = true, .refconf = true, .impostor = false }, null, null);

    const loaded = disk_cache.load(testing.allocator, "o", "r") orelse
        return error.TestExpectedNonNull;
    defer {
        for (loaded.shas) |s| testing.allocator.free(s.sha);
        testing.allocator.free(loaded.shas);
        for (loaded.named) |n| testing.allocator.free(n.ref);
        testing.allocator.free(loaded.named);
    }
    try testing.expect(!loaded.archived.?);
    try testing.expectEqual(@as(usize, 1), loaded.shas.len);
    try testing.expectEqualStrings(fake_sha, loaded.shas[0].sha);
    try testing.expectEqual(graphql.ShaTagResolution.has_tag, loaded.shas[0].resolution);
    try testing.expectEqual(@as(usize, 1), loaded.named.len);
    try testing.expect(loaded.named[0].is_tag);
    try testing.expect(loaded.named[0].is_branch);
}

test "persistRepoResult: writes branches/default_branch/impostor (v2)" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var env = try test_support.EnvGuard.setDir(testing.allocator, "XDG_CACHE_HOME", tmp.dir);
    defer env.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const sha = "1111111111111111111111111111111111111111";
    const branch_head = "2222222222222222222222222222222222222222";

    impostor.setCachedImpostorResult("o", "r", sha, .{ .status = .impostor });

    const sha_res = [_]graphql.ShaTagResult{.{ .sha = sha, .resolution = .no_tag }};
    const branches = [_]graphql.NamedOid{.{ .name = "main", .oid = branch_head }};
    const tag_oids = [_]graphql.NamedOid{.{ .name = "v1", .oid = "3333333333333333333333333333333333333333" }};
    const default_branch: graphql.NamedOid = .{ .name = "main", .oid = branch_head };

    const res: graphql.RepoResult = .{
        .owner = "o",
        .repo = "r",
        .archived = false,
        .sha_results = &sha_res,
        .tag_oids = &tag_oids,
        .branch_oids = &branches,
        .default_branch = default_branch,
    };

    persistRepoResult(alloc, res, null);

    const loaded = disk_cache.load(testing.allocator, "o", "r") orelse
        return error.TestExpectedNonNull;
    defer {
        for (loaded.shas) |s| testing.allocator.free(s.sha);
        testing.allocator.free(loaded.shas);
        for (loaded.named) |n| testing.allocator.free(n.ref);
        testing.allocator.free(loaded.named);
        for (loaded.branches) |b| {
            testing.allocator.free(b.name);
            testing.allocator.free(b.oid);
        }
        testing.allocator.free(loaded.branches);
        if (loaded.default_branch) |db| {
            testing.allocator.free(db.name);
            testing.allocator.free(db.oid);
        }
        for (loaded.impostor) |im| testing.allocator.free(im.sha);
        testing.allocator.free(loaded.impostor);
    }

    try testing.expectEqual(@as(usize, 1), loaded.branches.len);
    try testing.expectEqualStrings("main", loaded.branches[0].name);
    try testing.expectEqualStrings(branch_head, loaded.branches[0].oid);
    try testing.expect(loaded.default_branch != null);
    try testing.expectEqualStrings("main", loaded.default_branch.?.name);
    try testing.expectEqual(@as(usize, 1), loaded.impostor.len);
    try testing.expectEqualStrings(sha, loaded.impostor[0].sha);
    try testing.expectEqual(disk_cache.ImpostorStatus.impostor, loaded.impostor[0].status);
}

test "buildRepoInputs: impostor sets needs_impostor only when SHAs exist" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var repos: RepoSet = .{};
    try repos.put(alloc, "o/has", .{ .owner = "o", .repo = "has" });
    try repos.put(alloc, "o/none", .{ .owner = "o", .repo = "none" });

    var sha_refs: ShaSet = .{};
    try sha_refs.put(alloc, "o/has@aa", .{ .owner = "o", .repo = "has", .sha = "aa" });

    const named_refs: NamedSet = .{};

    const sets = RefSets{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };
    const inputs = try buildRepoInputs(alloc, sets, .{ .archived = true, .stale = true, .refconf = false, .impostor = true });

    try testing.expectEqual(@as(usize, 2), inputs.len);
    var has_idx: usize = 0;
    var none_idx: usize = 0;
    for (inputs, 0..) |input, i| {
        if (std.mem.eql(u8, input.repo, "has")) has_idx = i;
        if (std.mem.eql(u8, input.repo, "none")) none_idx = i;
    }
    try testing.expect(inputs[has_idx].needs_impostor);
    try testing.expect(!inputs[none_idx].needs_impostor);
}

test "buildRepoInputs: impostor populates sha slice even when stale_refs is off" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var repos: RepoSet = .{};
    try repos.put(alloc, "o/r", .{ .owner = "o", .repo = "r" });

    var sha_refs: ShaSet = .{};
    try sha_refs.put(alloc, "o/r@aa", .{ .owner = "o", .repo = "r", .sha = "aa" });

    const named_refs: NamedSet = .{};

    const sets = RefSets{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };
    const inputs = try buildRepoInputs(alloc, sets, .{ .archived = true, .stale = false, .refconf = false, .impostor = true });

    try testing.expectEqual(@as(usize, 1), inputs.len);
    try testing.expectEqual(@as(usize, 1), inputs[0].sha_refs.len);
    try testing.expect(inputs[0].needs_impostor);
}
