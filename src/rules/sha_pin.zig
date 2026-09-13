//! Tag name → commit oid, populated by the prefetch layer, plus the `uses:`
//! rewrite the rules that want a SHA pin share (SEC001, SC006).
//!
//! It lives in its own module rather than in `prefetch.zig` so that a rule can
//! read it without importing the orchestrator that imports the rules.
//!
//! Only *positive* facts are stored: an entry means "this tag pointed at this
//! commit when we asked". A miss is never evidence that the tag does not
//! exist — the GraphQL tag listing is paginated (`tag_oids_complete`), the run
//! may be offline, or the repository may never have been queried — so callers
//! must degrade to "no fix" on a miss rather than concluding anything.

const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const engine = @import("engine.zig");

const Allocator = std.mem.Allocator;
const ActionRef = workflow_types.ActionRef;
const DiagnosticList = diagnostics.DiagnosticList;
const Edit = diagnostics.Edit;
const Fix = diagnostics.Fix;
const FixSafety = diagnostics.FixSafety;
const Step = workflow_types.Step;

/// The commit a tag pointed at, plus whether a branch of the same name also
/// exists. That flag is what keeps the `safe` pin honest: a name that is both
/// a tag and a branch is SC006's finding, and choosing the tag side is a guess
/// only the `unsafe` fix may make.
pub const TagOid = struct {
    oid: []const u8,
    also_branch: bool,
};

/// Unmanaged so the map does not have to hold on to an allocator whose arena
/// moves when the module state is swapped in tests.
const OidMap = std.StringHashMapUnmanaged(TagOid);

var oid_cache: OidMap = .{};
var oid_arena: ?std.heap.ArenaAllocator = null;

/// `wanted` is false for runs that could never use a SHA-pin rewrite (no
/// `--fix`), so those runs neither allocate the cache nor pull the extra ref
/// lookups into the prefetch batch.
pub fn initTagOids(backing_allocator: Allocator, offline: bool, wanted: bool) void {
    if (offline or !wanted) return;
    oid_arena = std.heap.ArenaAllocator.init(backing_allocator);
}

pub fn deinitTagOids() void {
    if (oid_arena) |*arena| {
        oid_cache = .{};
        arena.deinit();
        oid_arena = null;
    }
}

pub fn isActive() bool {
    return oid_arena != null;
}

/// Non-SHA oids are rejected here rather than at each call site: the value is
/// written verbatim into the user's workflow by `--fix`, and both the GraphQL
/// response and the on-disk cache are outside this process's control.
pub fn setCachedTagOid(
    owner: []const u8,
    repo: []const u8,
    tag: []const u8,
    oid: []const u8,
    also_branch: bool,
) void {
    const alloc = if (oid_arena) |*arena| arena.allocator() else return;
    if (!engine.isValidSha(oid)) return;
    if (!engine.isValidGitRef(tag)) return;

    const key = std.fmt.allocPrint(alloc, "{s}/{s}@{s}", .{ owner, repo, tag }) catch return;
    const value = alloc.dupe(u8, oid) catch return;
    oid_cache.put(alloc, key, .{ .oid = value, .also_branch = also_branch }) catch return;
}

/// The commit `tag` pointed at, or null when this run has no answer for it.
pub fn lookupTagOid(owner: []const u8, repo: []const u8, tag: []const u8) ?TagOid {
    if (oid_arena == null) return null;

    var key_buf: [max_key_len]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{s}/{s}@{s}", .{ owner, repo, tag }) catch return null;
    return oid_cache.get(key);
}

/// The tag whose stored oid is `oid`, or null when this run has no answer.
/// A miss is not evidence that the SHA is unknown upstream — the store is
/// only filled on `--fix` prefetch — so callers must not treat it as a
/// capability.
pub fn lookupTagForOid(owner: []const u8, repo: []const u8, oid: []const u8) ?[]const u8 {
    if (oid_arena == null) return null;

    var it = oid_cache.iterator();
    while (it.next()) |entry| {
        if (!std.ascii.eqlIgnoreCase(entry.value_ptr.oid, oid)) continue;
        const key = entry.key_ptr.*;
        const at = std.mem.lastIndexOfScalar(u8, key, '@') orelse continue;
        const slash = std.mem.findScalar(u8, key[0..at], '/') orelse continue;
        if (!std.ascii.eqlIgnoreCase(key[0..slash], owner)) continue;
        if (!std.ascii.eqlIgnoreCase(key[slash + 1 .. at], repo)) continue;
        return key[at + 1 ..];
    }
    return null;
}

/// `"{owner}/{repo}@{tag}"` — each component is bounded by
/// `engine.isValidGitRef` (255 bytes), plus the `/` and `@` separators.
const max_key_len = 255 * 3 + 2;

/// Rewrites `uses: owner/repo@v4` into `uses: owner/repo@<sha> # v4`.
///
/// Returns null — meaning "diagnose but offer no fix" — whenever the tag's
/// commit is unknown to this run (`--offline`, no token, a truncated tag
/// listing, a ref that is a branch rather than a tag) or the `uses:` value is
/// written in a style whose bytes we cannot address, such as a block scalar.
///
/// The trailing `# v4` is not decoration: it keeps the pinned version readable
/// for humans and is where Dependabot and Renovate read the version back from.
pub fn buildPinFix(
    list: *DiagnosticList,
    step: *const Step,
    action_ref: ActionRef,
    safety: FixSafety,
    description: []const u8,
) ?Fix {
    const owner = action_ref.owner orelse return null;
    const repo = action_ref.repo orelse return null;
    const ref = action_ref.ref orelse return null;
    const entry = lookupTagOid(owner, repo, ref) orelse return null;
    // A name that is both a tag and a branch is exactly SC006's finding:
    // pinning it decides which of the two the author meant, so only the
    // `unsafe` rewrite is allowed to make that call.
    if (safety == .safe and entry.also_branch) return null;
    // The trailing `# v4` comments out the rest of the line, so it may only be
    // appended where nothing follows the value — inside a flow collection it
    // would swallow the closing `}` or the next entry.
    if (!step.uses_value_ends_line) return null;

    const end_byte = step.uses_value_end_byte orelse return null;
    const style = step.uses_value_style orelse return null;
    const quote_offset: usize = switch (style) {
        .plain => 0,
        .single_quoted, .double_quoted => 1,
        .literal, .folded => return null,
    };
    if (end_byte < quote_offset + ref.len) return null;

    // The ref is the tail of the `uses:` value, so it ends where the value
    // does (inside the closing quote, when there is one).
    const ref_end = end_byte - quote_offset;
    const ref_start = ref_end - ref.len;

    const alloc = list.fixAllocator();
    const replacement = alloc.dupe(u8, entry.oid) catch return null;
    const comment = std.fmt.allocPrint(alloc, " # {s}", .{ref}) catch return null;

    const edits = alloc.alloc(Edit, 2) catch return null;
    edits[0] = .{ .start_byte = ref_start, .end_byte = ref_end, .replacement = replacement };
    // Anchored past the closing quote, so the comment lands outside the scalar.
    edits[1] = .{ .start_byte = end_byte, .end_byte = end_byte, .replacement = comment };

    return .{ .description = description, .safety = safety, .edits = edits };
}

const testing = std.testing;

const valid_oid = "a5ac7e51b41094c92402da3b24376905380afc29";

test "tag_oids: inactive lookup returns null" {
    deinitTagOids();
    setCachedTagOid("actions", "checkout", "v4", valid_oid, false);
    try testing.expect(lookupTagOid("actions", "checkout", "v4") == null);
    try testing.expect(!isActive());
}

test "tag_oids: offline init leaves the store inactive" {
    initTagOids(testing.allocator, true, true);
    defer deinitTagOids();
    try testing.expect(!isActive());
}

test "tag_oids: unwanted init leaves the store inactive" {
    initTagOids(testing.allocator, false, false);
    defer deinitTagOids();
    try testing.expect(!isActive());
}

test "tag_oids: round-trips a stored oid" {
    initTagOids(testing.allocator, false, true);
    defer deinitTagOids();

    setCachedTagOid("actions", "checkout", "v4", valid_oid, false);
    try testing.expectEqualStrings(valid_oid, lookupTagOid("actions", "checkout", "v4").?.oid);
}

test "tag_oids: lookupTagForOid reverses a stored oid" {
    initTagOids(testing.allocator, false, true);
    defer deinitTagOids();

    setCachedTagOid("actions", "setup-node", "v5", valid_oid, false);
    try testing.expectEqualStrings("v5", lookupTagForOid("actions", "setup-node", valid_oid).?);
    try testing.expect(lookupTagForOid("actions", "checkout", valid_oid) == null);
}

test "tag_oids: a miss is not an answer" {
    initTagOids(testing.allocator, false, true);
    defer deinitTagOids();

    setCachedTagOid("actions", "checkout", "v4", valid_oid, false);
    try testing.expect(lookupTagOid("actions", "checkout", "v3") == null);
    try testing.expect(lookupTagOid("actions", "setup-node", "v4") == null);
    try testing.expect(lookupTagForOid("actions", "checkout", valid_oid) != null);
    try testing.expect(lookupTagForOid("actions", "setup-node", valid_oid) == null);
}

test "tag_oids: lookupTagForOid is inactive without the store" {
    deinitTagOids();
    setCachedTagOid("actions", "setup-node", "v5", valid_oid, false);
    try testing.expect(lookupTagForOid("actions", "setup-node", valid_oid) == null);
}

test "tag_oids: rejects a non-SHA oid" {
    initTagOids(testing.allocator, false, true);
    defer deinitTagOids();

    setCachedTagOid("actions", "checkout", "v4", "not-a-sha", false);
    setCachedTagOid("actions", "checkout", "v3", "A5AC7E51B41094C92402DA3B24376905380AFC29", false);
    try testing.expect(lookupTagOid("actions", "checkout", "v4") == null);
    try testing.expect(lookupTagOid("actions", "checkout", "v3") == null);
}

test "tag_oids: rejects a malformed tag name" {
    initTagOids(testing.allocator, false, true);
    defer deinitTagOids();

    setCachedTagOid("actions", "checkout", "v4?evil", valid_oid, false);
    try testing.expect(lookupTagOid("actions", "checkout", "v4?evil") == null);
}

test "tag_oids: deinit clears the store" {
    initTagOids(testing.allocator, false, true);
    setCachedTagOid("actions", "checkout", "v4", valid_oid, false);
    deinitTagOids();
    try testing.expect(lookupTagOid("actions", "checkout", "v4") == null);
}
