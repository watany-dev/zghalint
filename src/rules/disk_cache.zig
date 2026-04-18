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

    const name = repoFilename(allocator, owner, repo) catch return null;
    defer allocator.free(name);

    const file = dir.openFile(name, .{}) catch return null;
    defer file.close();

    const body = file.readToEndAlloc(allocator, 1 * 1024 * 1024) catch return null;
    defer allocator.free(body);

    const root = std.json.parseFromSliceLeaky(std.json.Value, allocator, body, .{}) catch return null;
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
