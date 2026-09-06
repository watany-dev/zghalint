//! Resolves the per-user cache root shared by the advisory cache and the
//! per-repository prefetch cache, and provides the symlink-safe atomic write
//! both of them use.

const std = @import("std");

const Allocator = std.mem.Allocator;

/// Opens `$XDG_CACHE_HOME/<sub_path>` or, failing that, `$HOME/.cache/<sub_path>`,
/// creating the subdirectory as needed. Returns null when neither base is a
/// usable absolute directory.
pub fn open(allocator: Allocator, comptime sub_path: []const u8) ?std.fs.Dir {
    if (openUnder(allocator, "XDG_CACHE_HOME", sub_path)) |dir| return dir;
    return openUnder(allocator, "HOME", ".cache/" ++ sub_path);
}

fn openUnder(allocator: Allocator, env_var: []const u8, comptime sub_path: []const u8) ?std.fs.Dir {
    const base = std.process.getEnvVarOwned(allocator, env_var) catch return null;
    defer allocator.free(base);
    // The XDG spec requires an absolute base and says a relative one must be
    // ignored; `openDirAbsolute` additionally asserts on it, so check first.
    if (!std.fs.path.isAbsolute(base)) return null;
    var dir = std.fs.openDirAbsolute(base, .{}) catch return null;
    defer dir.close();
    return dir.makeOpenPath(sub_path, .{}) catch null;
}

/// Refuses to write through a symlink planted in the cache directory: a
/// same-user attacker could otherwise redirect the write to an arbitrary
/// path. `atomicFile` writes a sibling temp file and renames it over the
/// destination, which swaps the directory entry without following a symlink
/// at the target path.
pub fn writeFileAtomic(dir: std.fs.Dir, name: []const u8, data: []const u8) !void {
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (dir.readLink(name, &link_buf)) |_| {
        return error.IsSymlink;
    } else |err| switch (err) {
        error.NotLink, error.FileNotFound => {},
        else => return err,
    }

    var write_buf: [4096]u8 = undefined;
    var af = try dir.atomicFile(name, .{ .write_buffer = &write_buf });
    defer af.deinit();
    try af.file_writer.interface.writeAll(data);
    try af.finish();
}

const test_support = @import("../test_support.zig");
const testing = std.testing;

test "open: relative XDG_CACHE_HOME is ignored, falls back to HOME" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var xdg = try test_support.EnvGuard.set(testing.allocator, "XDG_CACHE_HOME", "relative/cache");
    defer xdg.deinit();
    var home = try test_support.EnvGuard.setDir(testing.allocator, "HOME", tmp.dir);
    defer home.deinit();

    var dir = open(testing.allocator, "zghalint-test") orelse return error.TestExpectedNonNull;
    dir.close();
    try tmp.dir.access(".cache/zghalint-test", .{});
}

test "open: returns null when both bases are unusable" {
    var xdg = try test_support.EnvGuard.set(testing.allocator, "XDG_CACHE_HOME", "");
    defer xdg.deinit();
    var home = try test_support.EnvGuard.set(testing.allocator, "HOME", "not/absolute");
    defer home.deinit();

    try testing.expect(open(testing.allocator, "zghalint-test") == null);
}

test "writeFileAtomic: round-trips and replaces existing content" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeFileAtomic(tmp.dir, "f.txt", "first");
    try writeFileAtomic(tmp.dir, "f.txt", "second");

    var buf: [16]u8 = undefined;
    const n = try tmp.dir.readFile("f.txt", &buf);
    try testing.expectEqualStrings("second", n);
}

test "writeFileAtomic: refuses to write through a symlink" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "target.txt", .data = "keep" });
    tmp.dir.symLink("target.txt", "link.txt", .{}) catch return error.SkipZigTest;

    try testing.expectError(error.IsSymlink, writeFileAtomic(tmp.dir, "link.txt", "overwritten"));

    var buf: [16]u8 = undefined;
    const n = try tmp.dir.readFile("target.txt", &buf);
    try testing.expectEqualStrings("keep", n);
}
