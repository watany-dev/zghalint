//! Process-lifetime lookup cache shared by SC004 / SC005 / SC006.
//! Each rule instantiates `RefCache(V)` and keeps its own module-level slot.

const std = @import("std");

const Allocator = std.mem.Allocator;

pub fn RefCache(comptime V: type) type {
    return struct {
        const Self = @This();

        map: std.StringHashMap(V) = undefined,
        arena: ?std.heap.ArenaAllocator = null,

        pub fn init(self: *Self, backing: Allocator, offline: bool) void {
            if (offline) return;
            self.arena = std.heap.ArenaAllocator.init(backing);
            self.map = std.StringHashMap(V).init(self.arena.?.allocator());
        }

        pub fn deinit(self: *Self) void {
            if (self.arena) |*a| {
                a.deinit();
                self.arena = null;
            }
        }

        pub fn isActive(self: *const Self) bool {
            return self.arena != null;
        }

        pub fn allocator(self: *Self) ?Allocator {
            return if (self.arena) |*a| a.allocator() else null;
        }

        pub fn makeKey(self: *Self, comptime fmt: []const u8, args: anytype) ?[]const u8 {
            const alloc = self.allocator() orelse return null;
            return std.fmt.allocPrint(alloc, fmt, args) catch null;
        }

        pub fn get(self: *Self, key: []const u8) ?V {
            if (!self.isActive()) return null;
            return self.map.get(key);
        }

        pub fn contains(self: *Self, key: []const u8) bool {
            return self.isActive() and self.map.contains(key);
        }

        pub fn put(self: *Self, key: []const u8, value: V) void {
            if (!self.isActive()) return;
            self.map.put(key, value) catch return;
        }
    };
}
