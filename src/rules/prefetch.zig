//! Collects the unique `(owner, repo)`, `(owner, repo, sha)` and
//! `(owner, repo, ref)` triples across all workflows and fetches them up front
//! through the shared HTTP client, so the TLS handshake cost is paid once
//! even when many actions are referenced. The REST path stays available as a
//! fallback for unauthenticated users.

const std = @import("std");
const runtime = @import("../runtime.zig");
const workflow_types = @import("../workflow/types.zig");
const engine = @import("engine.zig");

const advisory = @import("advisory.zig");
const archived = @import("archived.zig");
const stale_refs = @import("stale_refs.zig");
const refconfusion = @import("refconfusion.zig");
const sha_pin = @import("sha_pin.zig");
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

/// The tag → commit oid answers this layer collected, re-exported so rules can
/// reach them through the prefetch API without depending on the orchestrator.
/// See `sha_pin.zig` for why a miss must never be read as "the tag is absent".
pub const lookupTagOid = sha_pin.lookupTagOid;
pub const setCachedTagOid = sha_pin.setCachedTagOid;
pub const initTagOids = sha_pin.initTagOids;
pub const deinitTagOids = sha_pin.deinitTagOids;

/// Threaded through the prefetch pipeline so every stage can skip the work
/// no rule asked for.
const ActiveRules = struct {
    archived: bool,
    stale: bool,
    refconf: bool,
    impostor: bool,
    /// SEC001 / SC006 want a tag's commit oid so `--fix` can pin to it. Unlike
    /// the others this is not a rule: it rides along on the named-ref lookups
    /// the batch already makes, and is off entirely without `--fix`.
    tag_pin: bool = false,

    fn detect() ActiveRules {
        return .{
            .archived = archived.isActive(),
            .stale = stale_refs.isActive(),
            .refconf = refconfusion.isActive(),
            .impostor = impostor.isActive(),
            .tag_pin = sha_pin.isActive(),
        };
    }

    fn any(self: ActiveRules) bool {
        return self.archived or self.stale or self.refconf or self.impostor or self.tag_pin;
    }

    /// Both consumers of the per-ref `tag_{d}` / `branch_{d}` aliases.
    fn needsNamedRefs(self: ActiveRules) bool {
        return self.refconf or self.tag_pin;
    }
};

pub fn prefetchAllWithOptions(
    allocator: Allocator,
    workflows: []const Workflow,
    opts: Options,
) !void {
    advisory.ensureLoaded();

    const active = ActiveRules.detect();
    if (!active.any()) return;

    var scratch_arena = std.heap.ArenaAllocator.init(allocator);
    defer scratch_arena.deinit();
    const scratch = scratch_arena.allocator();

    var ref_sets = try collectRefs(scratch, workflows);

    if (!opts.no_cache) {
        _ = applyDiskCache(scratch, &ref_sets, active);
    }
    pruneSatisfiedRepos(scratch, &ref_sets, active);

    // GraphQL first; falls back to REST on no-token, parse failure, or
    // rate-limit. SC008's REST compare phase rides on top of the same
    // GraphQL data so it shares whatever batches succeeded.
    var pending_compares = std.ArrayList(PendingCompare).empty;
    defer pending_compares.deinit(scratch);

    // Buffer GraphQL results so persistence runs after SC008's compare
    // phase has populated the impostor cache. Otherwise the disk_cache
    // entry would miss step3/4 verdicts on warm runs.
    var pending_persist = std.ArrayList(graphql.RepoResult).empty;
    defer pending_persist.deinit(scratch);

    const used_graphql = tryGraphQlBatch(
        scratch,
        &ref_sets,
        active,
        &pending_compares,
        &pending_persist,
    );

    if (!used_graphql) {
        if (active.archived) fetchRepos(scratch, ref_sets.repos);
        if (active.stale) fetchShaRefs(scratch, ref_sets.sha_refs);
        // The REST fallback answers ref existence only, never a target oid, so
        // SHA pinning has nothing to gain from it.
        if (active.refconf) fetchNamedRefs(scratch, ref_sets.named_refs);
    }

    if (active.impostor and pending_compares.items.len > 0) {
        impostor_compare.runImpostorCompares(scratch, pending_compares.items);
    }

    // Persisted only now that the impostor cache is fully populated.
    // Failures are non-fatal (best-effort warm-run hint).
    if (pending_persist.items.len > 0) {
        var cache_dir = disk_cache.getCacheDir(scratch);
        defer if (cache_dir) |*d| d.close(runtime.io());
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
            try collectStepRefs(allocator, job.steps, &repos, &sha_refs, &named_refs);
        }
    }

    return .{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };
}

fn collectStepRefs(
    allocator: Allocator,
    steps: []const workflow_types.Step,
    repos: *RepoSet,
    sha_refs: *ShaSet,
    named_refs: *NamedSet,
) !void {
    for (steps) |step| {
        if (step.uses) |action_ref| {
            if (!action_ref.is_local and !action_ref.is_docker) {
                if (action_ref.owner) |owner| {
                    if (action_ref.repo) |repo| {
                        if (engine.isValidGitHubComponent(owner) and engine.isValidGitHubComponent(repo)) {
                            const repo_key = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ owner, repo });
                            if (!repos.contains(repo_key)) {
                                try repos.put(allocator, repo_key, .{ .owner = owner, .repo = repo });
                            }

                            if (action_ref.ref) |ref| {
                                if (action_ref.is_pinned) {
                                    try putRefKey(allocator, sha_refs, owner, repo, ref, ShaKey{ .owner = owner, .repo = repo, .sha = ref });
                                } else if (engine.isValidGitRef(ref)) {
                                    try putRefKey(allocator, named_refs, owner, repo, ref, NamedKey{ .owner = owner, .repo = repo, .ref = ref });
                                }
                            }
                        }
                    }
                }
            }
        }
        try collectStepRefs(allocator, step.nestedSteps(), repos, sha_refs, named_refs);
    }
}

/// Satisfied refs are removed from `sets` so the GraphQL / REST phase only
/// fetches what the disk cache could not supply.
fn applyDiskCache(
    scratch: Allocator,
    sets: *RefSets,
    active: ActiveRules,
) usize {
    var hits: usize = 0;

    // Opened once for the whole sweep: `disk_cache.load` resolves and opens the
    // directory per call, on a path that never changes during a run.
    var cache_dir = disk_cache.getCacheDir(scratch) orelse return hits;
    defer cache_dir.close(runtime.io());

    // Iterate over a stable snapshot because `sets` is mutated while iterating.
    var repo_keys = std.ArrayList([]const u8).empty;
    defer repo_keys.deinit(scratch);
    var rk_it = sets.repos.keyIterator();
    while (rk_it.next()) |k| repo_keys.append(scratch, k.*) catch return hits;

    for (repo_keys.items) |repo_key| {
        const val_ptr = sets.repos.getPtr(repo_key) orelse continue;
        const owner = val_ptr.owner;
        const repo = val_ptr.repo;

        const entry = disk_cache.loadFromDir(cache_dir, scratch, owner, repo) orelse continue;
        hits += applyCacheEntry(sets, owner, repo, entry, active);
    }

    return hits;
}

/// Factored out of `applyDiskCache` so tests can drive the mutation logic
/// without staging files on disk.
fn applyCacheEntry(
    sets: *RefSets,
    owner: []const u8,
    repo: []const u8,
    entry: disk_cache.CachedRepo,
    active: ActiveRules,
) usize {
    var hits: usize = 0;

    // The repo itself is not dropped here: a repo whose `archived` flag is
    // cached may still own SHAs or named refs this run has to fetch, and
    // dropping it would keep those out of the GraphQL batch forever (#221).
    // `pruneSatisfiedRepos` removes a repo only once nothing is left to ask.
    if (active.archived) {
        if (entry.archived) |b| {
            archived.setCachedResult(owner, repo, b);
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
                // SC005 and SC008 share the (owner, repo, sha) tuple. A cache
                // file written by a run with SC008 off carries no impostor
                // verdict, so dropping the SHA here would keep it out of the
                // batch and silence SC008 for the rest of the TTL. It is not a
                // hit either: the ref still has to be fetched.
                if (active.impostor and !hasImpostorEntry(entry, s.sha)) continue;
                _ = sets.sha_refs.remove(key);
                hits += 1;
            }
        }
    }

    if (active.needsNamedRefs()) {
        for (entry.named) |n| {
            var key_buf: [max_ref_key_len]u8 = undefined;
            const key = std.fmt.bufPrint(&key_buf, "{s}/{s}@{s}", .{ owner, repo, n.ref }) catch continue;
            if (sets.named_refs.getPtr(key)) |_| {
                if (active.refconf) {
                    const status: refconfusion.RefStatus = if (n.is_tag and n.is_branch)
                        .ambiguous
                    else
                        .not_ambiguous;
                    refconfusion.setCachedRefResult(owner, repo, n.ref, status);
                }
                if (n.tag_oid) |oid| sha_pin.setCachedTagOid(owner, repo, n.ref, oid, n.is_branch);
                // A row written before the oid field existed, or by a run
                // without `--fix`, answers SC006 but not the pin. Keep the ref
                // in the batch so the oid can still be fetched; it is not a
                // hit either, since the request happens anyway.
                if (active.tag_pin and n.is_tag and n.tag_oid == null) continue;
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

fn hasImpostorEntry(entry: disk_cache.CachedRepo, sha: []const u8) bool {
    for (entry.impostor) |e| {
        if (std.mem.eql(u8, e.sha, sha)) return true;
    }
    return false;
}

/// Drops repositories that have nothing left to ask GitHub about: no
/// outstanding SHA or named ref, and either SC004 is off or its `archived`
/// verdict is already cached.
///
/// Without this, a run with SC004 disabled still sends every repository in an
/// otherwise empty GraphQL request and then overwrites the disk cache with
/// that empty answer, so warm and cold runs alternate forever (#221).
/// Conversely, a repository whose `archived` flag came from disk must stay
/// when a newly added pin still needs resolving.
fn pruneSatisfiedRepos(scratch: Allocator, sets: *RefSets, active: ActiveRules) void {
    // Bail out rather than prune on allocation failure: keeping a repository
    // costs one request, dropping one wrongly costs a missed diagnostic.
    var needed: std.StringHashMapUnmanaged(void) = .{};
    if (active.stale or active.impostor) {
        var it = sets.sha_refs.valueIterator();
        while (it.next()) |k| {
            const repo_key = std.fmt.allocPrint(scratch, "{s}/{s}", .{ k.owner, k.repo }) catch return;
            needed.put(scratch, repo_key, {}) catch return;
        }
    }
    if (active.needsNamedRefs()) {
        var it = sets.named_refs.valueIterator();
        while (it.next()) |k| {
            const repo_key = std.fmt.allocPrint(scratch, "{s}/{s}", .{ k.owner, k.repo }) catch return;
            needed.put(scratch, repo_key, {}) catch return;
        }
    }

    // Snapshot the keys: `sets.repos` is mutated below.
    var repo_keys = std.ArrayList([]const u8).empty;
    defer repo_keys.deinit(scratch);
    var rk_it = sets.repos.keyIterator();
    while (rk_it.next()) |k| repo_keys.append(scratch, k.*) catch return;

    for (repo_keys.items) |repo_key| {
        if (needed.contains(repo_key)) continue;
        if (active.archived) {
            const val = sets.repos.getPtr(repo_key) orelse continue;
            if (!archived.hasCachedResult(val.owner, val.repo)) continue;
        }
        _ = sets.repos.remove(repo_key);
    }
}

/// A repository accumulates SHAs across branches and runs, so the merged
/// arrays are capped to keep the cache file bounded. Fresh results are written
/// first, so the cap only ever discards the oldest entries.
const max_merged_entries = 256;

/// Fresh results win; entries the current run did not ask about are carried
/// over from disk. Without this the cache would only ever remember the last
/// run's delta, which is what breaks warm runs across branches (#221).
fn mergeEntries(
    comptime T: type,
    comptime key_field: []const u8,
    scratch: Allocator,
    old: []const T,
    fresh: []const T,
) []const T {
    if (old.len == 0) return fresh;
    if (fresh.len == 0) return if (old.len > max_merged_entries) old[0..max_merged_entries] else old;

    var list = std.ArrayList(T).empty;
    list.appendSlice(scratch, fresh) catch return fresh;
    outer: for (old) |o| {
        if (list.items.len >= max_merged_entries) break;
        for (fresh) |f| {
            if (std.mem.eql(u8, @field(o, key_field), @field(f, key_field))) continue :outer;
        }
        list.append(scratch, o) catch return fresh;
    }
    return list.toOwnedSlice(scratch) catch fresh;
}

/// Non-fatal: failures are ignored so that a missing cache dir or permission
/// error never blocks the lint run.
///
/// SC008 verdicts are read back out of the impostor module's cache, so
/// callers must run `runImpostorCompares` first if step3/4 results are
/// expected on disk.
/// `dir` lets a caller persisting several repos reuse one cache-directory
/// handle; `null` resolves and opens it for this single entry.
fn persistRepoResult(scratch: Allocator, res: graphql.RepoResult, dir: ?std.Io.Dir) void {
    if (res.missing) return;
    const entry: disk_cache.CachedRepo = .{
        .cached_at = std.Io.Clock.real.now(runtime.io()).toSeconds(),
        .archived = res.archived,
        .shas = res.sha_results,
        .named = res.named_results,
        .branches = res.branch_oids,
        .default_branch = res.default_branch,
        .impostor = blk: {
            if (!impostor.isActive() or res.sha_results.len == 0) break :blk &.{};
            var list = std.ArrayList(disk_cache.ImpostorEntry).empty;
            defer list.deinit(scratch);
            for (res.sha_results) |sr| {
                const cached = impostor.lookupCachedImpostorResult(res.owner, res.repo, sr.sha) orelse continue;
                list.append(scratch, .{ .sha = sr.sha, .status = cached.status }) catch break :blk &.{};
            }
            break :blk list.toOwnedSlice(scratch) catch &.{};
        },
    };
    const merged = mergeWithCached(scratch, res.owner, res.repo, entry, dir);

    if (dir) |d| {
        disk_cache.saveToDir(d, scratch, res.owner, res.repo, merged) catch return;
    } else {
        disk_cache.save(scratch, res.owner, res.repo, merged) catch return;
    }
}

/// Folds whatever the disk already holds for this repository into `entry`, so
/// a run that only queried the SHAs it missed does not erase the ones an
/// earlier run resolved.
fn mergeWithCached(
    scratch: Allocator,
    owner: []const u8,
    repo: []const u8,
    entry: disk_cache.CachedRepo,
    dir: ?std.Io.Dir,
) disk_cache.CachedRepo {
    const old = blk: {
        if (dir) |d| break :blk disk_cache.loadFromDir(d, scratch, owner, repo);
        break :blk disk_cache.load(scratch, owner, repo);
    } orelse return entry;

    var merged = entry;
    // The TTL is per file, so re-stamping it with `now` after carrying old
    // entries over would keep them alive for another day on every run: a
    // repository touched daily would never be re-checked. The file expires
    // when its oldest content does.
    merged.cached_at = @min(entry.cached_at, old.cached_at);
    merged.shas = mergeEntries(disk_cache.ShaEntry, "sha", scratch, old.shas, entry.shas);
    merged.named = mergeEntries(disk_cache.NamedEntry, "ref", scratch, old.named, entry.named);
    merged.branches = mergeEntries(disk_cache.BranchEntry, "name", scratch, old.branches, entry.branches);
    merged.impostor = mergeEntries(disk_cache.ImpostorEntry, "sha", scratch, old.impostor, entry.impostor);
    if (merged.archived == null) merged.archived = old.archived;
    if (merged.default_branch == null) merged.default_branch = old.default_branch;
    return merged;
}

/// `sets` is narrowed as batches land, so a REST fallback triggered by a later
/// batch only refetches what GraphQL could not resolve (#222).
fn tryGraphQlBatch(
    scratch: Allocator,
    sets: *RefSets,
    active: ActiveRules,
    pending: *std.ArrayList(PendingCompare),
    persist_buffer: ?*std.ArrayList(graphql.RepoResult),
) bool {
    if (sets.repos.count() == 0) return false;

    const inputs = buildRepoInputs(scratch, sets.*, active) catch return false;

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
            // RateLimited aborts the GraphQL phase, as `network-io.md` says:
            // REST talks to the same rate-limited API, so falling back would
            // only add requests to a budget that just ran out (#222).
            error.RateLimited => return true,
            // The transport is gone for the rest of the run; the REST
            // fallback would fail the same way before sending anything
            // (ADR 0016 D6).
            error.NetworkUnreachable => return true,
            else => return false,
        };

        applyResults(
            scratch,
            results,
            active,
            pending,
            persist_buffer,
        );
        markResolved(sets, results, active);
        idx = end;
    }

    return true;
}

const RefsByRepo = std.StringHashMapUnmanaged(std.ArrayList([]const u8));

fn appendByRepo(
    scratch: Allocator,
    map: *RefsByRepo,
    owner: []const u8,
    repo: []const u8,
    value: []const u8,
) !void {
    const repo_key = try std.fmt.allocPrint(scratch, "{s}/{s}", .{ owner, repo });
    const gop = try map.getOrPut(scratch, repo_key);
    if (!gop.found_existing) gop.value_ptr.* = .empty;
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
    if (active.needsNamedRefs()) {
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

/// Removes everything a landed batch answered from `sets`, so the REST
/// fallback a later batch may trigger neither refetches resolved refs nor
/// overwrites their values with `unknown` when the REST call fails (#222).
/// `.unknown` GraphQL verdicts stay in the set: REST may still do better.
fn markResolved(sets: *RefSets, results: []const graphql.RepoResult, active: ActiveRules) void {
    for (results) |res| {
        if (res.missing) continue;

        if (active.stale) {
            for (res.sha_results) |sr| {
                if (sr.resolution == .unknown) continue;
                removeRefKey(&sets.sha_refs, res.owner, res.repo, sr.sha);
            }
        }
        if (active.needsNamedRefs()) {
            for (res.named_results) |nr| {
                removeRefKey(&sets.named_refs, res.owner, res.repo, nr.ref);
            }
        }
        if (res.archived != null) {
            var key_buf: [max_ref_key_len]u8 = undefined;
            const key = std.fmt.bufPrint(&key_buf, "{s}/{s}", .{ res.owner, res.repo }) catch continue;
            _ = sets.repos.remove(key);
        }
    }
}

fn removeRefKey(set: anytype, owner: []const u8, repo: []const u8, ref: []const u8) void {
    var key_buf: [max_ref_key_len]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{s}/{s}@{s}", .{ owner, repo, ref }) catch return;
    _ = set.remove(key);
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
        if (active.needsNamedRefs()) {
            for (res.named_results) |nr| {
                if (active.refconf) {
                    const status: refconfusion.RefStatus = if (nr.is_tag and nr.is_branch)
                        .ambiguous
                    else
                        .not_ambiguous;
                    refconfusion.setCachedRefResult(res.owner, res.repo, nr.ref, status);
                }
                if (nr.tag_oid) |oid| sha_pin.setCachedTagOid(res.owner, res.repo, nr.ref, oid, nr.is_branch);
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
        if (engine.isNetworkDeadlineExceeded() or http_client.isNetworkUnreachable()) return;
        const is_archived = rest_fallback.fetchArchiveStatus(scratch, key.owner, key.repo) catch continue;
        archived.setCachedResult(key.owner, key.repo, is_archived);
    }
}

const ShaGroup = struct {
    owner: []const u8,
    repo: []const u8,
    shas: std.ArrayList([]const u8) = .empty,
};

/// The REST tag listing is per-repository, so grouping first turns "one
/// request per pinned SHA" into "one request per repository". Insertion order
/// is preserved so the deadline truncates the same prefix on every run.
fn groupShasByRepo(scratch: Allocator, set: ShaSet) std.array_hash_map.String(ShaGroup) {
    var by_repo: std.array_hash_map.String(ShaGroup) = .{};

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
        if (engine.isNetworkDeadlineExceeded() or http_client.isNetworkUnreachable()) return;
        const group = entry.value_ptr;
        const shas = group.shas.items;

        const out = scratch.alloc(rest_fallback.TagResolution, shas.len) catch continue;
        // A transport failure leaves every entry `.unknown`, as the per-SHA
        // path did.
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
        if (engine.isNetworkDeadlineExceeded() or http_client.isNetworkUnreachable()) return;
        const status = rest_fallback.queryRefStatus(scratch, key.owner, key.repo, key.ref);
        refconfusion.setCachedRefResult(key.owner, key.repo, key.ref, status);
    }
}

const test_support = @import("../test_support.zig");
const testing = std.testing;
const ActionRef = workflow_types.ActionRef;
const Step = workflow_types.Step;
const Job = workflow_types.Job;

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

test "applyCacheEntry: fresh hit drops shas/named from sets and counts hits" {
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
        .cached_at = std.Io.Clock.real.now(runtime.io()).toSeconds(),
        .archived = true,
        .shas = @constCast(&shas),
        .named = @constCast(&named),
    };

    const active = ActiveRules{ .archived = true, .stale = true, .refconf = true, .impostor = false };
    const hits = applyCacheEntry(&sets, "o", "r", entry, active);
    try testing.expectEqual(@as(usize, 3), hits);
    try testing.expectEqual(@as(usize, 0), sets.sha_refs.count());
    try testing.expectEqual(@as(usize, 0), sets.named_refs.count());

    // The repo survives `applyCacheEntry`; pruning is what drops it once
    // nothing is left to ask about.
    try testing.expectEqual(@as(usize, 1), sets.repos.count());
    pruneSatisfiedRepos(alloc, &sets, active);
    try testing.expectEqual(@as(usize, 0), sets.repos.count());
}

test "pruneSatisfiedRepos: keeps a cached-archived repo that still owns an unresolved SHA (#221)" {
    archived.initArchived(testing.allocator, false);
    defer archived.deinitArchived();
    stale_refs.initStaleRefs(testing.allocator, false);
    defer stale_refs.deinitStaleRefs();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var sets = RefSets{ .repos = .{}, .sha_refs = .{}, .named_refs = .{} };
    try sets.repos.put(alloc, "o/r", .{ .owner = "o", .repo = "r" });
    try sets.sha_refs.put(alloc, "o/r@new", .{ .owner = "o", .repo = "r", .sha = "new" });

    // Only the archived flag is cached; the freshly added pin is not.
    const entry = disk_cache.CachedRepo{ .cached_at = std.Io.Clock.real.now(runtime.io()).toSeconds(), .archived = true };
    const active = ActiveRules{ .archived = true, .stale = true, .refconf = false, .impostor = false };
    _ = applyCacheEntry(&sets, "o", "r", entry, active);
    pruneSatisfiedRepos(alloc, &sets, active);

    try testing.expectEqual(@as(usize, 1), sets.repos.count());
}

test "pruneSatisfiedRepos: drops every repo when no rule needs repo-level data (#221)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var sets = RefSets{ .repos = .{}, .sha_refs = .{}, .named_refs = .{} };
    try sets.repos.put(alloc, "o/r", .{ .owner = "o", .repo = "r" });

    // SC004 off and nothing outstanding: querying would send an empty GraphQL
    // request whose empty answer then overwrites the disk cache.
    pruneSatisfiedRepos(alloc, &sets, .{ .archived = false, .stale = true, .refconf = true, .impostor = false });
    try testing.expectEqual(@as(usize, 0), sets.repos.count());
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
        .cached_at = std.Io.Clock.real.now(runtime.io()).toSeconds(),
        .archived = false,
        .shas = @constCast(&shas),
        .named = @constCast(&named),
    };

    const active = ActiveRules{ .archived = true, .stale = false, .refconf = false, .impostor = false };
    const hits = applyCacheEntry(&sets, "o", "r", entry, active);
    try testing.expectEqual(@as(usize, 1), hits);
    try testing.expectEqual(@as(usize, 1), sets.sha_refs.count());
    try testing.expectEqual(@as(usize, 1), sets.named_refs.count());

    // Neither SC005 nor SC006 is active, so the untouched refs are not work
    // this run owes: the repo is fully satisfied.
    pruneSatisfiedRepos(alloc, &sets, active);
    try testing.expectEqual(@as(usize, 0), sets.repos.count());
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

    _ = applyCacheEntry(&sets, "o", "r", entry, .{ .archived = false, .stale = false, .refconf = false, .impostor = true });

    const legit = impostor.lookupCachedImpostorResult("o", "r", sha_legit) orelse
        return error.TestExpectedNonNull;
    try testing.expectEqual(impostor.ImpostorStatus.legitimate, legit.status);

    const imp = impostor.lookupCachedImpostorResult("o", "r", sha_imp) orelse
        return error.TestExpectedNonNull;
    try testing.expectEqual(impostor.ImpostorStatus.impostor, imp.status);
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

    engine.network_deadline_ns = std.Io.Clock.awake.now(runtime.io()).nanoseconds - 1;
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

test "tryGraphQlBatch: an unreachable network counts as handled so REST is skipped" {
    archived.initArchived(testing.allocator, false);
    defer archived.deinitArchived();
    stale_refs.initStaleRefs(testing.allocator, false);
    defer stale_refs.deinitStaleRefs();
    refconfusion.initRefConfusion(testing.allocator, false);
    defer refconfusion.deinitRefConfusion();

    var env = try test_support.EnvGuard.set(testing.allocator, "GITHUB_TOKEN", "ghp_test");
    defer env.deinit();
    engine.setNetworkDeadline(10 * std.time.ns_per_s);
    defer engine.clearNetworkDeadline();
    http_client.markNetworkUnreachable();
    defer http_client.resetNetworkState();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const steps = [_]Step{.{ .uses = ActionRef.parse("actions/checkout@v4") }};
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &jobs };
    var sets = try collectRefs(alloc, &[_]Workflow{wf});
    var pending = std.ArrayList(PendingCompare).empty;

    const active = ActiveRules{ .archived = true, .stale = true, .refconf = true, .impostor = false };
    try testing.expect(tryGraphQlBatch(alloc, &sets, active, &pending, null));
    // Nothing was resolved: the refs are still waiting, which the REST
    // fallback would otherwise pick up.
    try testing.expectEqual(@as(usize, 1), sets.named_refs.count());
}

test "prefetchAllWithOptions: an unreachable network short-circuits every stage" {
    archived.initArchived(testing.allocator, false);
    defer archived.deinitArchived();
    stale_refs.initStaleRefs(testing.allocator, false);
    defer stale_refs.deinitStaleRefs();
    refconfusion.initRefConfusion(testing.allocator, false);
    defer refconfusion.deinitRefConfusion();

    engine.setNetworkDeadline(10 * std.time.ns_per_s);
    defer engine.clearNetworkDeadline();
    http_client.markNetworkUnreachable();
    defer http_client.resetNetworkState();

    const sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@" ++ sha) },
        .{ .uses = ActionRef.parse("actions/setup-node@v4") },
    };
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &jobs };
    const wfs = [_]Workflow{wf};

    const t0 = std.Io.Clock.awake.now(runtime.io());
    try prefetchAllWithOptions(testing.allocator, &wfs, .{ .no_cache = true });
    const elapsed = std.Io.Clock.awake.now(runtime.io()).nanoseconds - t0.nanoseconds;
    try testing.expect(elapsed < std.time.ns_per_s);
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
    const now = std.Io.Clock.real.now(runtime.io()).toSeconds();
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

    const active = ActiveRules{ .archived = true, .stale = true, .refconf = true, .impostor = false };
    const hits = applyDiskCache(alloc, &sets, active);
    pruneSatisfiedRepos(alloc, &sets, active);
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

test "persistRepoResult: merges with the on-disk entry instead of overwriting it (#221)" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var env = try test_support.EnvGuard.setDir(testing.allocator, "XDG_CACHE_HOME", tmp.dir);
    defer env.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const sha_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const sha_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    // Run 1 resolves A1 and caches the archived flag.
    const first_shas = [_]graphql.ShaTagResult{.{ .sha = sha_a, .resolution = .has_tag }};
    persistRepoResult(alloc, .{
        .owner = "o",
        .repo = "r",
        .archived = false,
        .sha_results = &first_shas,
    }, null);

    // Run 2 only misses A2, so GraphQL is asked about A2 alone.
    const second_shas = [_]graphql.ShaTagResult{.{ .sha = sha_b, .resolution = .no_tag }};
    persistRepoResult(alloc, .{
        .owner = "o",
        .repo = "r",
        .sha_results = &second_shas,
    }, null);

    const loaded = disk_cache.load(testing.allocator, "o", "r") orelse
        return error.TestExpectedNonNull;
    defer {
        for (loaded.shas) |e| testing.allocator.free(e.sha);
        testing.allocator.free(loaded.shas);
        testing.allocator.free(loaded.named);
        testing.allocator.free(loaded.branches);
        testing.allocator.free(loaded.impostor);
    }

    try testing.expectEqual(@as(usize, 2), loaded.shas.len);
    var seen_a = false;
    var seen_b = false;
    for (loaded.shas) |e| {
        if (std.mem.eql(u8, e.sha, sha_a)) seen_a = true;
        if (std.mem.eql(u8, e.sha, sha_b)) seen_b = true;
    }
    try testing.expect(seen_a);
    try testing.expect(seen_b);
    // Run 2 never asked about `archived`, so run 1's answer survives.
    try testing.expect(loaded.archived != null);
    try testing.expect(!loaded.archived.?);
}

test "persistRepoResult: carrying old entries over does not renew the TTL (#221)" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var env = try test_support.EnvGuard.setDir(testing.allocator, "XDG_CACHE_HOME", tmp.dir);
    defer env.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const sha_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const sha_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    // An entry written some hours ago, still inside the TTL.
    const stamped = std.Io.Clock.real.now(runtime.io()).toSeconds() - 3600;
    const first_shas = [_]disk_cache.ShaEntry{.{ .sha = sha_a, .resolution = .has_tag }};
    var dir = disk_cache.getCacheDir(alloc) orelse return error.TestExpectedNonNull;
    defer dir.close(runtime.io());
    try disk_cache.saveToDir(dir, alloc, "o", "r", .{
        .cached_at = stamped,
        .archived = false,
        .shas = &first_shas,
    });

    const second_shas = [_]graphql.ShaTagResult{.{ .sha = sha_b, .resolution = .no_tag }};
    persistRepoResult(alloc, .{ .owner = "o", .repo = "r", .sha_results = &second_shas }, null);

    const loaded = disk_cache.load(testing.allocator, "o", "r") orelse
        return error.TestExpectedNonNull;
    defer {
        for (loaded.shas) |e| testing.allocator.free(e.sha);
        testing.allocator.free(loaded.shas);
        testing.allocator.free(loaded.named);
        testing.allocator.free(loaded.branches);
        testing.allocator.free(loaded.impostor);
    }

    try testing.expectEqual(@as(usize, 2), loaded.shas.len);
    // The carried-over answer keeps its age, so the file still expires on time.
    try testing.expectEqual(stamped, loaded.cached_at);
}

test "applyCacheEntry: keeps a SHA whose SC008 verdict the cache file lacks" {
    stale_refs.initStaleRefs(testing.allocator, false);
    defer stale_refs.deinitStaleRefs();
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const sha = "cccccccccccccccccccccccccccccccccccccccc";
    var sets = RefSets{ .repos = .{}, .sha_refs = .{}, .named_refs = .{} };
    try sets.repos.put(alloc, "o/r", .{ .owner = "o", .repo = "r" });
    try sets.sha_refs.put(alloc, "o/r@" ++ sha, .{ .owner = "o", .repo = "r", .sha = sha });

    // Written by a run with SC008 off: the tag resolution is there, the
    // impostor verdict is not.
    const shas = [_]disk_cache.ShaEntry{.{ .sha = sha, .resolution = .has_tag }};
    const entry = disk_cache.CachedRepo{ .cached_at = std.Io.Clock.real.now(runtime.io()).toSeconds(), .shas = &shas };
    const active = ActiveRules{ .archived = false, .stale = true, .refconf = false, .impostor = true };

    _ = applyCacheEntry(&sets, "o", "r", entry, active);
    pruneSatisfiedRepos(alloc, &sets, active);

    try testing.expectEqual(@as(usize, 1), sets.sha_refs.count());
    try testing.expectEqual(@as(usize, 1), sets.repos.count());

    // The same file with the verdict present must still satisfy the SHA,
    // otherwise the guard above would silently disable the whole SC005 cache.
    var sets2 = RefSets{ .repos = .{}, .sha_refs = .{}, .named_refs = .{} };
    try sets2.repos.put(alloc, "o/r", .{ .owner = "o", .repo = "r" });
    try sets2.sha_refs.put(alloc, "o/r@" ++ sha, .{ .owner = "o", .repo = "r", .sha = sha });

    const imp = [_]disk_cache.ImpostorEntry{.{ .sha = sha, .status = .legitimate }};
    const full = disk_cache.CachedRepo{ .cached_at = std.Io.Clock.real.now(runtime.io()).toSeconds(), .shas = &shas, .impostor = &imp };

    _ = applyCacheEntry(&sets2, "o", "r", full, active);
    pruneSatisfiedRepos(alloc, &sets2, active);

    try testing.expectEqual(@as(usize, 0), sets2.sha_refs.count());
    try testing.expectEqual(@as(usize, 0), sets2.repos.count());
}

test "mergeEntries: fresh results win over the cached ones for the same key" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const old = [_]disk_cache.ShaEntry{
        .{ .sha = "a", .resolution = .unknown },
        .{ .sha = "b", .resolution = .has_tag },
    };
    const fresh = [_]disk_cache.ShaEntry{.{ .sha = "a", .resolution = .no_tag }};

    const merged = mergeEntries(disk_cache.ShaEntry, "sha", alloc, &old, &fresh);
    try testing.expectEqual(@as(usize, 2), merged.len);
    try testing.expectEqualStrings("a", merged[0].sha);
    try testing.expectEqual(graphql.ShaTagResolution.no_tag, merged[0].resolution);
    try testing.expectEqualStrings("b", merged[1].sha);
}

test "markResolved: narrows the REST fallback to what GraphQL could not answer (#222)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var sets = RefSets{ .repos = .{}, .sha_refs = .{}, .named_refs = .{} };
    try sets.repos.put(alloc, "o/r", .{ .owner = "o", .repo = "r" });
    try sets.sha_refs.put(alloc, "o/r@a", .{ .owner = "o", .repo = "r", .sha = "a" });
    try sets.sha_refs.put(alloc, "o/r@b", .{ .owner = "o", .repo = "r", .sha = "b" });
    try sets.named_refs.put(alloc, "o/r@main", .{ .owner = "o", .repo = "r", .ref = "main" });

    const sha_res = [_]graphql.ShaTagResult{
        .{ .sha = "a", .resolution = .has_tag },
        // Unanswered by GraphQL: REST may still resolve it, so it stays.
        .{ .sha = "b", .resolution = .unknown },
    };
    const named_res = [_]graphql.NamedRefResult{.{ .ref = "main", .is_tag = true, .is_branch = false }};
    const results = [_]graphql.RepoResult{.{
        .owner = "o",
        .repo = "r",
        .archived = false,
        .sha_results = &sha_res,
        .named_results = &named_res,
    }};

    markResolved(&sets, &results, .{ .archived = true, .stale = true, .refconf = true, .impostor = false });

    try testing.expectEqual(@as(usize, 0), sets.repos.count());
    try testing.expectEqual(@as(usize, 0), sets.named_refs.count());
    try testing.expectEqual(@as(usize, 1), sets.sha_refs.count());
    try testing.expect(sets.sha_refs.contains("o/r@b"));
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

test "applyResults: seeds the SHA-pin store from the per-ref tag oids" {
    sha_pin.initTagOids(testing.allocator, false, true);
    defer sha_pin.deinitTagOids();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const oid = "a5ac7e51b41094c92402da3b24376905380afc29";
    const named_res = [_]graphql.NamedRefResult{
        .{ .ref = "v4", .is_tag = true, .is_branch = false, .tag_oid = oid },
        // A branch carries no tag oid, and must not gain one.
        .{ .ref = "main", .is_tag = false, .is_branch = true },
        // A name that is both keeps its oid, flagged so only SC006 may use it.
        .{ .ref = "edge", .is_tag = true, .is_branch = true, .tag_oid = oid },
    };
    const results = [_]graphql.RepoResult{.{
        .owner = "o",
        .repo = "r",
        .named_results = &named_res,
    }};

    applyResults(arena.allocator(), &results, .{
        .archived = false,
        .stale = false,
        .refconf = false,
        .impostor = false,
        .tag_pin = true,
    }, null, null);

    try testing.expectEqualStrings(oid, sha_pin.lookupTagOid("o", "r", "v4").?.oid);
    try testing.expect(!sha_pin.lookupTagOid("o", "r", "v4").?.also_branch);
    try testing.expect(sha_pin.lookupTagOid("o", "r", "main") == null);
    try testing.expect(sha_pin.lookupTagOid("o", "r", "edge").?.also_branch);
}

test "applyCacheEntry: a cached row without an oid keeps the ref in the batch" {
    sha_pin.initTagOids(testing.allocator, false, true);
    defer sha_pin.deinitTagOids();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var sets = RefSets{ .repos = .{}, .sha_refs = .{}, .named_refs = .{} };
    try sets.repos.put(alloc, "o/r", .{ .owner = "o", .repo = "r" });
    try sets.named_refs.put(alloc, "o/r@v4", .{ .owner = "o", .repo = "r", .ref = "v4" });
    try sets.named_refs.put(alloc, "o/r@v3", .{ .owner = "o", .repo = "r", .ref = "v3" });

    const oid = "a5ac7e51b41094c92402da3b24376905380afc29";
    const named = [_]disk_cache.NamedEntry{
        .{ .ref = "v4", .is_tag = true, .is_branch = false, .tag_oid = oid },
        .{ .ref = "v3", .is_tag = true, .is_branch = false },
    };
    const entry: disk_cache.CachedRepo = .{ .cached_at = 0, .named = @constCast(&named) };

    const active = ActiveRules{
        .archived = false,
        .stale = false,
        .refconf = false,
        .impostor = false,
        .tag_pin = true,
    };
    const hits = applyCacheEntry(&sets, "o", "r", entry, active);

    try testing.expectEqualStrings(oid, sha_pin.lookupTagOid("o", "r", "v4").?.oid);
    try testing.expectEqual(@as(usize, 1), hits);
    // v3's row predates the oid field, so it has to be asked about again.
    try testing.expect(!sets.named_refs.contains("o/r@v4"));
    try testing.expect(sets.named_refs.contains("o/r@v3"));
}

test "buildRepoInputs: SHA pinning alone pulls the named refs into the batch" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var sets = RefSets{ .repos = .{}, .sha_refs = .{}, .named_refs = .{} };
    try sets.repos.put(alloc, "o/r", .{ .owner = "o", .repo = "r" });
    try sets.named_refs.put(alloc, "o/r@v4", .{ .owner = "o", .repo = "r", .ref = "v4" });

    const inputs = try buildRepoInputs(alloc, sets, .{
        .archived = false,
        .stale = false,
        .refconf = false,
        .impostor = false,
        .tag_pin = true,
    });

    try testing.expectEqual(@as(usize, 1), inputs.len);
    try testing.expectEqual(@as(usize, 1), inputs[0].named_refs.len);
    try testing.expectEqualStrings("v4", inputs[0].named_refs[0]);
}
