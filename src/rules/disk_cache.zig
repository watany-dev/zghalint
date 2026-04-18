//! Per-repository disk cache for GraphQL/REST prefetch results.
//!
//! Stores results under `${XDG_CACHE_HOME:-${HOME}/.cache}/zghalint/repos/`
//! as one `<owner>_<repo>.json` file per repository, with a 24-hour TTL
//! measured from `cached_at`. Warm runs (re-lint without code changes) can
//! skip GraphQL entirely when every queried SHA / named ref is already
//! present in a fresh cache file.
//!
//! The on-disk format is a minimal JSON document:
//!
//! ```json
//! {
//!   "cached_at": 1713400000,
//!   "archived": true,
//!   "shas":  [["<sha>", "h"|"n"|"u"], ...],
//!   "named": [["<ref>", 0|1, 0|1], ...]
//! }
//! ```

const std = @import("std");
const graphql = @import("graphql.zig");

const Allocator = std.mem.Allocator;

pub const cache_ttl_s: i64 = 24 * 60 * 60;
const cache_subdir = "zghalint/repos";

// ============================================================
// Public types
// ============================================================

pub const ShaEntry = struct {
    sha: []const u8,
    resolution: graphql.ShaTagResolution,
};

pub const NamedEntry = struct {
    ref: []const u8,
    is_tag: bool,
    is_branch: bool,
};

pub const CachedRepo = struct {
    cached_at: i64 = 0,
    archived: ?bool = null,
    shas: []ShaEntry = &.{},
    named: []NamedEntry = &.{},
};

// ============================================================
// Cache directory resolution
// ============================================================

fn getCacheDir(allocator: Allocator) ?std.fs.Dir {
    if (std.process.getEnvVarOwned(allocator, "XDG_CACHE_HOME")) |xdg| {
        defer allocator.free(xdg);
        var dir = std.fs.openDirAbsolute(xdg, .{}) catch return null;
        const sub = dir.makeOpenPath(cache_subdir, .{}) catch {
            dir.close();
            return null;
        };
        dir.close();
        return sub;
    } else |_| {}

    if (std.process.getEnvVarOwned(allocator, "HOME")) |home| {
        defer allocator.free(home);
        var dir = std.fs.openDirAbsolute(home, .{}) catch return null;
        const sub = dir.makeOpenPath(".cache/" ++ cache_subdir, .{}) catch {
            dir.close();
            return null;
        };
        dir.close();
        return sub;
    } else |_| {}

    return null;
}

fn repoFilename(allocator: Allocator, owner: []const u8, repo: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s}_{s}.json", .{ owner, repo });
}

// ============================================================
// Freshness
// ============================================================

pub fn isFresh(cached_at: i64) bool {
    const now = std.time.timestamp();
    if (cached_at > now) return false;
    return (now - cached_at) < cache_ttl_s;
}

// ============================================================
// Load
// ============================================================

/// Load a fresh cache entry for the given repo, or return `null` if the file
/// is missing, stale, or malformed. All returned slices live on `allocator`.
pub fn load(
    allocator: Allocator,
    owner: []const u8,
    repo: []const u8,
) ?CachedRepo {
    var dir = getCacheDir(allocator) orelse return null;
    defer dir.close();
    return loadFromDir(dir, allocator, owner, repo);
}

/// Variant of `load` that takes an already-opened cache directory. Tests
/// use this to drive load/save against a `std.testing.tmpDir` instead of
/// the user's real XDG cache.
pub fn loadFromDir(
    dir: std.fs.Dir,
    allocator: Allocator,
    owner: []const u8,
    repo: []const u8,
) ?CachedRepo {
    const name = repoFilename(allocator, owner, repo) catch return null;
    defer allocator.free(name);

    const file = dir.openFile(name, .{}) catch return null;
    defer file.close();

    const body = file.readToEndAlloc(allocator, 1 * 1024 * 1024) catch return null;
    defer allocator.free(body);

    // Parse the JSON into an isolated arena so we don't leak the tree
    // when `allocator` is a GPA. Only the per-repo copies we dupe below
    // need to live on `allocator`.
    var parse_arena = std.heap.ArenaAllocator.init(allocator);
    defer parse_arena.deinit();
    const parse_alloc = parse_arena.allocator();

    const root = std.json.parseFromSliceLeaky(std.json.Value, parse_alloc, body, .{}) catch return null;
    const obj = switch (root) {
        .object => |o| o,
        else => return null,
    };

    const cached_at: i64 = blk: {
        const v = obj.get("cached_at") orelse break :blk 0;
        break :blk switch (v) {
            .integer => |i| @intCast(i),
            else => 0,
        };
    };
    if (!isFresh(cached_at)) return null;

    var result: CachedRepo = .{ .cached_at = cached_at };

    if (obj.get("archived")) |v| {
        result.archived = switch (v) {
            .bool => |b| b,
            else => null,
        };
    }

    if (obj.get("shas")) |v| {
        if (v == .array) {
            var list = std.ArrayList(ShaEntry){};
            defer list.deinit(allocator);
            for (v.array.items) |entry| {
                if (entry != .array) continue;
                const fields = entry.array.items;
                if (fields.len < 2) continue;
                if (fields[0] != .string or fields[1] != .string) continue;
                const res = parseResolutionCode(fields[1].string) orelse continue;
                const sha_copy = allocator.dupe(u8, fields[0].string) catch continue;
                list.append(allocator, .{ .sha = sha_copy, .resolution = res }) catch continue;
            }
            result.shas = list.toOwnedSlice(allocator) catch &.{};
        }
    }

    if (obj.get("named")) |v| {
        if (v == .array) {
            var list = std.ArrayList(NamedEntry){};
            defer list.deinit(allocator);
            for (v.array.items) |entry| {
                if (entry != .array) continue;
                const fields = entry.array.items;
                if (fields.len < 3) continue;
                if (fields[0] != .string) continue;
                const ref_copy = allocator.dupe(u8, fields[0].string) catch continue;
                const is_tag = intFieldAsBool(fields[1]);
                const is_branch = intFieldAsBool(fields[2]);
                list.append(allocator, .{ .ref = ref_copy, .is_tag = is_tag, .is_branch = is_branch }) catch continue;
            }
            result.named = list.toOwnedSlice(allocator) catch &.{};
        }
    }

    return result;
}

fn parseResolutionCode(code: []const u8) ?graphql.ShaTagResolution {
    if (code.len != 1) return null;
    return switch (code[0]) {
        'h' => .has_tag,
        'n' => .no_tag,
        'u' => .unknown,
        else => null,
    };
}

fn resolutionCode(res: graphql.ShaTagResolution) u8 {
    return switch (res) {
        .has_tag => 'h',
        .no_tag => 'n',
        .unknown => 'u',
    };
}

fn intFieldAsBool(v: std.json.Value) bool {
    return switch (v) {
        .bool => |b| b,
        .integer => |i| i != 0,
        else => false,
    };
}

// ============================================================
// Save
// ============================================================

pub fn save(
    allocator: Allocator,
    owner: []const u8,
    repo: []const u8,
    entry: CachedRepo,
) !void {
    var dir = getCacheDir(allocator) orelse return;
    defer dir.close();
    try saveToDir(dir, allocator, owner, repo, entry);
}

pub fn saveToDir(
    dir: std.fs.Dir,
    allocator: Allocator,
    owner: []const u8,
    repo: []const u8,
    entry: CachedRepo,
) !void {
    const name = try repoFilename(allocator, owner, repo);
    defer allocator.free(name);

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);

    try buf.writer(allocator).print("{{\"cached_at\":{d}", .{entry.cached_at});

    if (entry.archived) |b| {
        try buf.writer(allocator).print(",\"archived\":{s}", .{if (b) "true" else "false"});
    } else {
        try buf.appendSlice(allocator, ",\"archived\":null");
    }

    try buf.appendSlice(allocator, ",\"shas\":[");
    for (entry.shas, 0..) |s, i| {
        if (i != 0) try buf.append(allocator, ',');
        try buf.writer(allocator).print("[\"{s}\",\"{c}\"]", .{ s.sha, resolutionCode(s.resolution) });
    }

    try buf.appendSlice(allocator, "],\"named\":[");
    for (entry.named, 0..) |n, i| {
        if (i != 0) try buf.append(allocator, ',');
        try buf.writer(allocator).print("[\"{s}\",{d},{d}]", .{ n.ref, @intFromBool(n.is_tag), @intFromBool(n.is_branch) });
    }

    try buf.appendSlice(allocator, "]}");

    const file = dir.createFile(name, .{ .truncate = true }) catch return;
    defer file.close();
    file.writeAll(buf.items) catch return;
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;

test "isFresh: recent timestamp is fresh" {
    const now = std.time.timestamp();
    try testing.expect(isFresh(now - 60));
    try testing.expect(!isFresh(now - cache_ttl_s - 1));
    try testing.expect(!isFresh(now + 60)); // future -> not fresh
}

test "parseResolutionCode round-trips" {
    try testing.expectEqual(graphql.ShaTagResolution.has_tag, parseResolutionCode("h").?);
    try testing.expectEqual(graphql.ShaTagResolution.no_tag, parseResolutionCode("n").?);
    try testing.expectEqual(graphql.ShaTagResolution.unknown, parseResolutionCode("u").?);
    try testing.expect(parseResolutionCode("x") == null);
    try testing.expect(parseResolutionCode("") == null);
}

test "resolutionCode maps each enum variant" {
    try testing.expectEqual(@as(u8, 'h'), resolutionCode(.has_tag));
    try testing.expectEqual(@as(u8, 'n'), resolutionCode(.no_tag));
    try testing.expectEqual(@as(u8, 'u'), resolutionCode(.unknown));
}

test "intFieldAsBool decodes JSON variants" {
    try testing.expect(intFieldAsBool(.{ .bool = true }));
    try testing.expect(!intFieldAsBool(.{ .bool = false }));
    try testing.expect(intFieldAsBool(.{ .integer = 1 }));
    try testing.expect(!intFieldAsBool(.{ .integer = 0 }));
    try testing.expect(!intFieldAsBool(.{ .null = {} }));
}

test "saveToDir/loadFromDir round-trips all fields" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const shas = [_]ShaEntry{
        .{ .sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", .resolution = .has_tag },
        .{ .sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", .resolution = .no_tag },
    };
    const named = [_]NamedEntry{
        .{ .ref = "main", .is_tag = false, .is_branch = true },
        .{ .ref = "v4", .is_tag = true, .is_branch = false },
    };
    const now = std.time.timestamp();
    const entry: CachedRepo = .{
        .cached_at = now,
        .archived = true,
        .shas = @constCast(&shas),
        .named = @constCast(&named),
    };

    try saveToDir(tmp.dir, testing.allocator, "actions", "checkout", entry);
    const loaded = loadFromDir(tmp.dir, testing.allocator, "actions", "checkout") orelse
        return error.TestExpectedNonNull;
    defer {
        for (loaded.shas) |s| testing.allocator.free(s.sha);
        testing.allocator.free(loaded.shas);
        for (loaded.named) |n| testing.allocator.free(n.ref);
        testing.allocator.free(loaded.named);
    }

    try testing.expectEqual(now, loaded.cached_at);
    try testing.expect(loaded.archived.?);
    try testing.expectEqual(@as(usize, 2), loaded.shas.len);
    try testing.expectEqualStrings(shas[0].sha, loaded.shas[0].sha);
    try testing.expectEqual(graphql.ShaTagResolution.has_tag, loaded.shas[0].resolution);
    try testing.expectEqual(graphql.ShaTagResolution.no_tag, loaded.shas[1].resolution);
    try testing.expectEqual(@as(usize, 2), loaded.named.len);
    try testing.expectEqualStrings("main", loaded.named[0].ref);
    try testing.expect(!loaded.named[0].is_tag);
    try testing.expect(loaded.named[0].is_branch);
    try testing.expect(loaded.named[1].is_tag);
}

test "loadFromDir: missing file returns null" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try testing.expect(loadFromDir(tmp.dir, testing.allocator, "nobody", "nothing") == null);
}

test "loadFromDir: stale file (older than TTL) returns null" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const stale_time = std.time.timestamp() - cache_ttl_s - 10;
    try saveToDir(tmp.dir, testing.allocator, "o", "r", .{ .cached_at = stale_time, .archived = false });

    try testing.expect(loadFromDir(tmp.dir, testing.allocator, "o", "r") == null);
}

test "loadFromDir: malformed JSON returns null" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const name = try repoFilename(testing.allocator, "o", "r");
    defer testing.allocator.free(name);
    const file = try tmp.dir.createFile(name, .{});
    defer file.close();
    try file.writeAll("{ not valid json");

    try testing.expect(loadFromDir(tmp.dir, testing.allocator, "o", "r") == null);
}

test "saveToDir: archived null serializes as null literal" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const now = std.time.timestamp();
    try saveToDir(tmp.dir, testing.allocator, "o", "r", .{ .cached_at = now, .archived = null });

    const loaded = loadFromDir(tmp.dir, testing.allocator, "o", "r") orelse
        return error.TestExpectedNonNull;
    defer {
        testing.allocator.free(loaded.shas);
        testing.allocator.free(loaded.named);
    }
    try testing.expect(loaded.archived == null);
}

test "loadFromDir: non-object JSON root returns null" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const name = try repoFilename(testing.allocator, "o", "r");
    defer testing.allocator.free(name);
    const file = try tmp.dir.createFile(name, .{});
    defer file.close();
    try file.writeAll("[1,2,3]"); // array instead of object

    try testing.expect(loadFromDir(tmp.dir, testing.allocator, "o", "r") == null);
}

test "loadFromDir: tolerates malformed shas/named entries" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const name = try repoFilename(testing.allocator, "o", "r");
    defer testing.allocator.free(name);
    const file = try tmp.dir.createFile(name, .{});
    defer file.close();

    // Each shas entry is either non-array, too-short, wrong-type, or has an
    // unknown resolution code. All must be silently skipped.
    const now = std.time.timestamp();
    const body = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"cached_at\":{d},\"archived\":false,\"shas\":[42,[\"onlyone\"],[1,2],[\"sha\",\"X\"],[\"good\",\"h\"]],\"named\":[0,[\"x\"],[\"ref\",\"notnum\",1],[\"ok\",1,0]]}}",
        .{now},
    );
    defer testing.allocator.free(body);
    try file.writeAll(body);

    const loaded = loadFromDir(tmp.dir, testing.allocator, "o", "r") orelse
        return error.TestExpectedNonNull;
    defer {
        for (loaded.shas) |s| testing.allocator.free(s.sha);
        testing.allocator.free(loaded.shas);
        for (loaded.named) |n| testing.allocator.free(n.ref);
        testing.allocator.free(loaded.named);
    }
    // Only the "good" shas entry survives (others are dropped by length or
    // type checks). Named entries with a string-typed first field survive —
    // non-string bool/int fields fall through to intFieldAsBool's else branch.
    try testing.expectEqual(@as(usize, 1), loaded.shas.len);
    try testing.expectEqualStrings("good", loaded.shas[0].sha);
    try testing.expectEqual(graphql.ShaTagResolution.has_tag, loaded.shas[0].resolution);
    try testing.expectEqual(@as(usize, 2), loaded.named.len);
    try testing.expectEqualStrings("ref", loaded.named[0].ref);
    try testing.expect(!loaded.named[0].is_tag); // "notnum" -> false
    try testing.expect(loaded.named[0].is_branch); // 1 -> true
    try testing.expectEqualStrings("ok", loaded.named[1].ref);
}

test "load/save: round-trip via XDG_CACHE_HOME" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_path);
    const tmp_path_z = try testing.allocator.dupeZ(u8, tmp_path);
    defer testing.allocator.free(tmp_path_z);

    // Snapshot current env so we leave the process state untouched.
    const saved_xdg = std.process.getEnvVarOwned(testing.allocator, "XDG_CACHE_HOME") catch null;
    defer if (saved_xdg) |s| testing.allocator.free(s);
    const saved_xdg_z: ?[:0]u8 = if (saved_xdg) |s| (testing.allocator.dupeZ(u8, s) catch null) else null;
    defer if (saved_xdg_z) |z| testing.allocator.free(z);

    _ = libc_setenv("XDG_CACHE_HOME", tmp_path_z.ptr, 1);
    defer {
        if (saved_xdg_z) |z| {
            _ = libc_setenv("XDG_CACHE_HOME", z.ptr, 1);
        } else {
            _ = libc_unsetenv("XDG_CACHE_HOME");
        }
    }

    const now = std.time.timestamp();
    try save(testing.allocator, "xdg-o", "xdg-r", .{ .cached_at = now, .archived = true });

    const loaded = load(testing.allocator, "xdg-o", "xdg-r") orelse
        return error.TestExpectedNonNull;
    defer {
        testing.allocator.free(loaded.shas);
        testing.allocator.free(loaded.named);
    }
    try testing.expect(loaded.archived.?);
    try testing.expectEqual(now, loaded.cached_at);
}

const libc_setenv = @extern(*const fn ([*:0]const u8, [*:0]const u8, c_int) callconv(.c) c_int, .{ .name = "setenv" });
const libc_unsetenv = @extern(*const fn ([*:0]const u8) callconv(.c) c_int, .{ .name = "unsetenv" });
