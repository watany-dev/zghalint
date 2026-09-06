//! Per-repository disk cache for GraphQL/REST prefetch results, so warm runs
//! (re-lint without code changes) can skip GraphQL entirely when every
//! queried SHA / named ref is already present in a fresh cache file.
//!
//! v1 entries (no `cache_format` field, or `cache_format=1`) are loaded
//! with empty branches/impostor/default_branch. The next save promotes
//! them to v2.

const std = @import("std");
const json_util = @import("json_util.zig");
const graphql = @import("graphql.zig");
const impostor = @import("impostor.zig");
const engine = @import("engine.zig");

const Allocator = std.mem.Allocator;

pub const cache_ttl_s: i64 = 24 * 60 * 60;
const cache_subdir = "zghalint/repos";

/// Current on-disk schema version. Bumped when adding fields that older
/// readers would silently misinterpret. Older files (no field, or =1)
/// are tolerated and migrated on the next save.
pub const cache_format_current: u8 = 2;

// The cache stores exactly what the fetch layers produce, so the entry types
// are those layers' types rather than field-compatible copies. Sharing them
// keeps prefetch free of identity conversions in both directions.
pub const ShaEntry = graphql.ShaTagResult;
pub const NamedEntry = graphql.NamedRefResult;
pub const BranchEntry = graphql.NamedOid;
pub const ImpostorStatus = impostor.ImpostorStatus;

pub const ImpostorEntry = struct {
    sha: []const u8,
    status: ImpostorStatus,
};

pub const CachedRepo = struct {
    cached_at: i64 = 0,
    archived: ?bool = null,
    shas: []const ShaEntry = &.{},
    named: []const NamedEntry = &.{},
    branches: []const BranchEntry = &.{},
    default_branch: ?BranchEntry = null,
    impostor: []const ImpostorEntry = &.{},
};

/// Callers that touch more than one repo open the directory once and pass it
/// to `loadFromDir` / `saveToDir`, rather than paying an open per repo.
pub fn openCacheDir(allocator: Allocator) ?std.fs.Dir {
    return getCacheDir(allocator);
}

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

pub fn isFresh(cached_at: i64) bool {
    const now = std.time.timestamp();
    if (cached_at > now) return false;
    const floor = std.math.sub(i64, now, cache_ttl_s) catch return false;
    if (cached_at < floor) return false;
    return true;
}

pub fn load(
    allocator: Allocator,
    owner: []const u8,
    repo: []const u8,
) ?CachedRepo {
    var dir = getCacheDir(allocator) orelse return null;
    defer dir.close();
    return loadFromDir(dir, allocator, owner, repo);
}

/// Tests use this to drive load/save against a `std.testing.tmpDir` instead
/// of the user's real XDG cache.
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
    const obj = json_util.asObject(root) orelse return null;

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
        result.archived = json_util.asBool(v);
    }

    result.shas = parseEntryArray(ShaEntry, allocator, obj, "shas", parseShaEntry);
    result.named = parseEntryArray(NamedEntry, allocator, obj, "named", parseNamedEntry);
    result.branches = parseEntryArray(BranchEntry, allocator, obj, "branches", parseBranchEntry);
    result.impostor = parseEntryArray(ImpostorEntry, allocator, obj, "impostor", parseImpostorEntry);

    if (obj.get("default_branch")) |v| {
        if (v == .array) result.default_branch = parseBranchEntry(allocator, v.array.items);
    }

    return result;
}

/// A malformed or unvalidatable row is skipped: a partially corrupt cache
/// file degrades to a partial cache hit rather than a hard failure.
fn parseEntryArray(
    comptime T: type,
    allocator: Allocator,
    obj: std.json.ObjectMap,
    key: []const u8,
    comptime parseEntry: fn (Allocator, []const std.json.Value) ?T,
) []T {
    const v = obj.get(key) orelse return &.{};
    if (v != .array) return &.{};

    var list = std.ArrayList(T){};
    defer list.deinit(allocator);
    for (v.array.items) |entry| {
        if (entry != .array) continue;
        const parsed = parseEntry(allocator, entry.array.items) orelse continue;
        list.append(allocator, parsed) catch continue;
    }
    return list.toOwnedSlice(allocator) catch &.{};
}

fn stringField(fields: []const std.json.Value, idx: usize) ?[]const u8 {
    if (idx >= fields.len) return null;
    if (fields[idx] != .string) return null;
    return fields[idx].string;
}

fn parseShaEntry(allocator: Allocator, fields: []const std.json.Value) ?ShaEntry {
    const sha = stringField(fields, 0) orelse return null;
    const code = stringField(fields, 1) orelse return null;
    if (!engine.isValidSha(sha)) return null;
    const res = parseResolutionCode(code) orelse return null;
    return .{ .sha = allocator.dupe(u8, sha) catch return null, .resolution = res };
}

fn parseNamedEntry(allocator: Allocator, fields: []const std.json.Value) ?NamedEntry {
    if (fields.len < 3) return null;
    const ref = stringField(fields, 0) orelse return null;
    if (!engine.isValidGitRef(ref)) return null;
    return .{
        .ref = allocator.dupe(u8, ref) catch return null,
        .is_tag = intFieldAsBool(fields[1]),
        .is_branch = intFieldAsBool(fields[2]),
    };
}

fn parseBranchEntry(allocator: Allocator, fields: []const std.json.Value) ?BranchEntry {
    const name = stringField(fields, 0) orelse return null;
    const oid = stringField(fields, 1) orelse return null;
    if (!engine.isValidGitRef(name) or !engine.isValidSha(oid)) return null;
    const name_copy = allocator.dupe(u8, name) catch return null;
    const oid_copy = allocator.dupe(u8, oid) catch {
        allocator.free(name_copy);
        return null;
    };
    return .{ .name = name_copy, .oid = oid_copy };
}

fn parseImpostorEntry(allocator: Allocator, fields: []const std.json.Value) ?ImpostorEntry {
    const sha = stringField(fields, 0) orelse return null;
    const code = stringField(fields, 1) orelse return null;
    if (!engine.isValidSha(sha)) return null;
    const status = parseImpostorCode(code) orelse return null;
    return .{ .sha = allocator.dupe(u8, sha) catch return null, .status = status };
}

fn parseImpostorCode(code: []const u8) ?ImpostorStatus {
    if (code.len != 1) return null;
    return switch (code[0]) {
        'l' => .legitimate,
        'i' => .impostor,
        'u' => .unknown,
        else => null,
    };
}

fn impostorCode(status: ImpostorStatus) []const u8 {
    return switch (status) {
        .legitimate => "l",
        .impostor => "i",
        .unknown => "u",
    };
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

fn resolutionCode(res: graphql.ShaTagResolution) []const u8 {
    return switch (res) {
        .has_tag => "h",
        .no_tag => "n",
        .unknown => "u",
    };
}

fn intFieldAsBool(v: std.json.Value) bool {
    return switch (v) {
        .bool => |b| b,
        .integer => |i| i != 0,
        else => false,
    };
}

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

    var doc: std.Io.Writer.Allocating = .init(allocator);
    defer doc.deinit();
    var js: std.json.Stringify = .{ .writer = &doc.writer };

    try js.beginObject();
    try js.objectField("cache_format");
    try js.write(cache_format_current);
    try js.objectField("cached_at");
    try js.write(entry.cached_at);
    try js.objectField("archived");
    try js.write(entry.archived);

    try js.objectField("shas");
    try js.beginArray();
    for (entry.shas) |e| try js.write(.{ e.sha, resolutionCode(e.resolution) });
    try js.endArray();

    try js.objectField("named");
    try js.beginArray();
    for (entry.named) |e| try js.write(.{ e.ref, @intFromBool(e.is_tag), @intFromBool(e.is_branch) });
    try js.endArray();

    try js.objectField("branches");
    try js.beginArray();
    for (entry.branches) |e| try js.write(.{ e.name, e.oid });
    try js.endArray();

    try js.objectField("default_branch");
    if (entry.default_branch) |db| {
        try js.write(.{ db.name, db.oid });
    } else {
        try js.write(null);
    }

    try js.objectField("impostor");
    try js.beginArray();
    for (entry.impostor) |e| try js.write(.{ e.sha, impostorCode(e.status) });
    try js.endArray();

    try js.endObject();

    // Refuse to write through a symlink planted in the cache directory.
    // A same-user attacker could otherwise redirect the truncate+write to an
    // arbitrary file path.
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (dir.readLink(name, &link_buf)) |_| {
        return; // caller treats save() as best-effort
    } else |err| switch (err) {
        error.NotLink, error.FileNotFound => {},
        else => return,
    }

    // Atomically replace the cache file. atomicFile writes to a sibling
    // tmp file and renames over the destination, which swaps the directory
    // entry without following any existing symlink at the target path.
    var write_buf: [4096]u8 = undefined;
    var af = dir.atomicFile(name, .{ .write_buffer = &write_buf }) catch return;
    defer af.deinit();
    af.file_writer.interface.writeAll(doc.written()) catch return;
    af.finish() catch return;
}

const test_support = @import("../test_support.zig");
const testing = std.testing;

test "isFresh: recent timestamp is fresh" {
    const now = std.time.timestamp();
    try testing.expect(isFresh(now - 60));
    try testing.expect(!isFresh(now - cache_ttl_s - 1));
    try testing.expect(!isFresh(now + 60));
}

test "parseResolutionCode round-trips" {
    try testing.expectEqual(graphql.ShaTagResolution.has_tag, parseResolutionCode("h").?);
    try testing.expectEqual(graphql.ShaTagResolution.no_tag, parseResolutionCode("n").?);
    try testing.expectEqual(graphql.ShaTagResolution.unknown, parseResolutionCode("u").?);
    try testing.expect(parseResolutionCode("x") == null);
    try testing.expect(parseResolutionCode("") == null);
}

test "resolutionCode maps each enum variant" {
    try testing.expectEqualStrings("h", resolutionCode(.has_tag));
    try testing.expectEqualStrings("n", resolutionCode(.no_tag));
    try testing.expectEqualStrings("u", resolutionCode(.unknown));
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
    defer freeLoaded(loaded);

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
    try testing.expectEqual(@as(usize, 0), loaded.branches.len);
    try testing.expectEqual(@as(usize, 0), loaded.impostor.len);
    try testing.expect(loaded.default_branch == null);
}

fn freeLoaded(loaded: CachedRepo) void {
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
    try file.writeAll("[1,2,3]");

    try testing.expect(loadFromDir(tmp.dir, testing.allocator, "o", "r") == null);
}

test "loadFromDir: tolerates malformed shas/named entries" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const name = try repoFilename(testing.allocator, "o", "r");
    defer testing.allocator.free(name);
    const file = try tmp.dir.createFile(name, .{});
    defer file.close();

    const now = std.time.timestamp();
    const body = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"cached_at\":{d},\"archived\":false,\"shas\":[42,[\"onlyone\"],[1,2],[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"X\"],[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"h\"]],\"named\":[0,[\"x\"],[\"ref\",\"notnum\",1],[\"ok\",1,0]]}}",
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
    try testing.expectEqual(@as(usize, 1), loaded.shas.len);
    try testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", loaded.shas[0].sha);
    try testing.expectEqual(graphql.ShaTagResolution.has_tag, loaded.shas[0].resolution);
    try testing.expectEqual(@as(usize, 2), loaded.named.len);
    try testing.expectEqualStrings("ref", loaded.named[0].ref);
    try testing.expect(!loaded.named[0].is_tag);
    try testing.expect(loaded.named[0].is_branch);
    try testing.expectEqualStrings("ok", loaded.named[1].ref);
}

test "load/save: round-trip via XDG_CACHE_HOME" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_path);
    const tmp_path_z = try testing.allocator.dupeZ(u8, tmp_path);
    defer testing.allocator.free(tmp_path_z);

    var env = try test_support.EnvGuard.set(testing.allocator, "XDG_CACHE_HOME", tmp_path_z);
    defer env.deinit();

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

test "loadFromDir: invalid sha hex is dropped" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const name = try repoFilename(testing.allocator, "o", "r");
    defer testing.allocator.free(name);
    const file = try tmp.dir.createFile(name, .{});
    defer file.close();

    const now = std.time.timestamp();
    const body = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"cached_at\":{d},\"shas\":[[\"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\",\"h\"],[\"aaaa\",\"h\"],[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"h\"]],\"named\":[]}}",
        .{now},
    );
    defer testing.allocator.free(body);
    try file.writeAll(body);

    const loaded = loadFromDir(tmp.dir, testing.allocator, "o", "r") orelse
        return error.TestExpectedNonNull;
    defer {
        for (loaded.shas) |s| testing.allocator.free(s.sha);
        testing.allocator.free(loaded.shas);
        testing.allocator.free(loaded.named);
    }
    try testing.expectEqual(@as(usize, 1), loaded.shas.len);
    try testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", loaded.shas[0].sha);
}

test "loadFromDir: invalid git refs are dropped" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const name = try repoFilename(testing.allocator, "o", "r");
    defer testing.allocator.free(name);
    const file = try tmp.dir.createFile(name, .{});
    defer file.close();

    const now = std.time.timestamp();
    const body = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"cached_at\":{d},\"shas\":[],\"named\":[[\"../evil\",1,0],[\"with space\",1,0],[\"main\",0,1]]}}",
        .{now},
    );
    defer testing.allocator.free(body);
    try file.writeAll(body);

    const loaded = loadFromDir(tmp.dir, testing.allocator, "o", "r") orelse
        return error.TestExpectedNonNull;
    defer {
        testing.allocator.free(loaded.shas);
        for (loaded.named) |n| testing.allocator.free(n.ref);
        testing.allocator.free(loaded.named);
    }
    try testing.expectEqual(@as(usize, 1), loaded.named.len);
    try testing.expectEqualStrings("main", loaded.named[0].ref);
}

test "parseImpostorCode round-trips" {
    try testing.expectEqual(ImpostorStatus.legitimate, parseImpostorCode("l").?);
    try testing.expectEqual(ImpostorStatus.impostor, parseImpostorCode("i").?);
    try testing.expectEqual(ImpostorStatus.unknown, parseImpostorCode("u").?);
    try testing.expect(parseImpostorCode("L") == null);
    try testing.expect(parseImpostorCode("li") == null);
    try testing.expect(parseImpostorCode("") == null);
    try testing.expect(parseImpostorCode("x") == null);
}

test "impostorCode maps each enum variant" {
    try testing.expectEqualStrings("l", impostorCode(.legitimate));
    try testing.expectEqualStrings("i", impostorCode(.impostor));
    try testing.expectEqualStrings("u", impostorCode(.unknown));
}

test "saveToDir/loadFromDir: v2 round-trips branches/default_branch/impostor" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const branches = [_]BranchEntry{
        .{ .name = "main", .oid = "1111111111111111111111111111111111111111" },
        .{ .name = "release-1.x", .oid = "2222222222222222222222222222222222222222" },
    };
    const impostor_entries = [_]ImpostorEntry{
        .{ .sha = "3333333333333333333333333333333333333333", .status = .legitimate },
        .{ .sha = "4444444444444444444444444444444444444444", .status = .impostor },
        .{ .sha = "5555555555555555555555555555555555555555", .status = .unknown },
    };
    const default_branch: BranchEntry = .{
        .name = "main",
        .oid = "1111111111111111111111111111111111111111",
    };
    const now = std.time.timestamp();
    const entry: CachedRepo = .{
        .cached_at = now,
        .archived = false,
        .branches = @constCast(&branches),
        .default_branch = default_branch,
        .impostor = @constCast(&impostor_entries),
    };

    try saveToDir(tmp.dir, testing.allocator, "actions", "checkout", entry);
    const loaded = loadFromDir(tmp.dir, testing.allocator, "actions", "checkout") orelse
        return error.TestExpectedNonNull;
    defer freeLoaded(loaded);

    try testing.expectEqual(@as(usize, 2), loaded.branches.len);
    try testing.expectEqualStrings("main", loaded.branches[0].name);
    try testing.expectEqualStrings("1111111111111111111111111111111111111111", loaded.branches[0].oid);
    try testing.expectEqualStrings("release-1.x", loaded.branches[1].name);
    try testing.expectEqualStrings("2222222222222222222222222222222222222222", loaded.branches[1].oid);

    try testing.expect(loaded.default_branch != null);
    try testing.expectEqualStrings("main", loaded.default_branch.?.name);
    try testing.expectEqualStrings("1111111111111111111111111111111111111111", loaded.default_branch.?.oid);

    try testing.expectEqual(@as(usize, 3), loaded.impostor.len);
    try testing.expectEqualStrings("3333333333333333333333333333333333333333", loaded.impostor[0].sha);
    try testing.expectEqual(ImpostorStatus.legitimate, loaded.impostor[0].status);
    try testing.expectEqual(ImpostorStatus.impostor, loaded.impostor[1].status);
    try testing.expectEqual(ImpostorStatus.unknown, loaded.impostor[2].status);
}

test "loadFromDir: v1 legacy entry (no cache_format/branches/impostor) loads with empty SC008 fields" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const name = try repoFilename(testing.allocator, "o", "r");
    defer testing.allocator.free(name);
    const file = try tmp.dir.createFile(name, .{});
    defer file.close();

    const now = std.time.timestamp();
    const body = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"cached_at\":{d},\"archived\":false,\"shas\":[[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"h\"]],\"named\":[[\"main\",0,1]]}}",
        .{now},
    );
    defer testing.allocator.free(body);
    try file.writeAll(body);

    const loaded = loadFromDir(tmp.dir, testing.allocator, "o", "r") orelse
        return error.TestExpectedNonNull;
    defer freeLoaded(loaded);

    try testing.expectEqual(@as(usize, 1), loaded.shas.len);
    try testing.expectEqual(@as(usize, 1), loaded.named.len);
    try testing.expectEqual(@as(usize, 0), loaded.branches.len);
    try testing.expectEqual(@as(usize, 0), loaded.impostor.len);
    try testing.expect(loaded.default_branch == null);
}

test "loadFromDir: tolerates malformed branches/impostor/default_branch entries" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const name = try repoFilename(testing.allocator, "o", "r");
    defer testing.allocator.free(name);
    const file = try tmp.dir.createFile(name, .{});
    defer file.close();

    const now = std.time.timestamp();
    const body = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"cached_at\":{d},\"archived\":false," ++
            "\"shas\":[],\"named\":[]," ++
            "\"branches\":[42,[\"only\"],[\"../bad\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]," ++
            "[\"main\",\"zz\"],[\"main\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]]," ++
            "\"default_branch\":[\"../bad\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]," ++
            "\"impostor\":[5,[\"only\"],[\"zz\",\"l\"],[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"X\"]," ++
            "[\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"i\"]]}}",
        .{now},
    );
    defer testing.allocator.free(body);
    try file.writeAll(body);

    const loaded = loadFromDir(tmp.dir, testing.allocator, "o", "r") orelse
        return error.TestExpectedNonNull;
    defer freeLoaded(loaded);

    try testing.expectEqual(@as(usize, 1), loaded.branches.len);
    try testing.expectEqualStrings("main", loaded.branches[0].name);
    try testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", loaded.branches[0].oid);

    try testing.expect(loaded.default_branch == null);

    try testing.expectEqual(@as(usize, 1), loaded.impostor.len);
    try testing.expectEqualStrings("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", loaded.impostor[0].sha);
    try testing.expectEqual(ImpostorStatus.impostor, loaded.impostor[0].status);
}

test "saveToDir: refuses to write through a pre-existing symlink" {
    // On a same-user attack, a symlink planted in the cache dir pointing at
    // an arbitrary path would, prior to this hardening, be followed by a
    // truncating write. Verify saveToDir leaves the symlink target alone.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const victim = try tmp.dir.createFile("victim.txt", .{});
        defer victim.close();
        try victim.writeAll("SACRED");
    }

    const cache_name = try repoFilename(testing.allocator, "o", "r");
    defer testing.allocator.free(cache_name);

    tmp.dir.symLink("victim.txt", cache_name, .{}) catch |err| switch (err) {
        error.AccessDenied, error.Unexpected => return, // filesystem doesn't support symlinks
        else => return err,
    };

    const now = std.time.timestamp();
    try saveToDir(tmp.dir, testing.allocator, "o", "r", .{ .cached_at = now, .archived = false });

    const f = try tmp.dir.openFile("victim.txt", .{});
    defer f.close();
    var buf: [32]u8 = undefined;
    const n = try f.readAll(&buf);
    try testing.expectEqualStrings("SACRED", buf[0..n]);
}
