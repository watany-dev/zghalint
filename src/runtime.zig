const std = @import("std");
const builtin = @import("builtin");

// Rule callbacks share process-scoped caches and cannot carry an Io argument.
// The embedding application must keep these resources alive until cache teardown.
pub var process_io: ?std.Io = null;
pub var environ: ?*std.process.Environ.Map = null;

pub fn init(process: std.process.Init) void {
    process_io = process.io;
    environ = process.environ_map;
}

pub fn io() std.Io {
    if (process_io) |value| return value;
    if (builtin.is_test) return std.testing.io;
    @panic("initialize zghalint.runtime before using I/O");
}

pub fn getEnv(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    if (environ) |map| {
        return allocator.dupe(u8, map.get(name) orelse return error.EnvironmentVariableNotFound);
    }
    if (builtin.is_test) return std.testing.environ.getAlloc(allocator, name);
    return error.EnvironmentVariableNotFound;
}
