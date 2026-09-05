//! Small accessors over `std.json.Value`.
//!
//! GitHub's REST and GraphQL payloads are read defensively: a key that is
//! missing and a key whose value has the wrong type are both "not usable
//! here". These helpers collapse the `get` + `switch` pair that every such
//! read would otherwise repeat into a single optional.

const std = @import("std");

const Value = std.json.Value;
const ObjectMap = std.json.ObjectMap;

/// The value as an object, or null when it is any other JSON type.
pub fn asObject(value: Value) ?ObjectMap {
    return switch (value) {
        .object => |o| o,
        else => null,
    };
}

/// The value as a string, or null when it is any other JSON type.
pub fn asString(value: Value) ?[]const u8 {
    return switch (value) {
        .string => |s| s,
        else => null,
    };
}

/// The value as an array's items, or null when it is any other JSON type.
pub fn asArray(value: Value) ?[]const Value {
    return switch (value) {
        .array => |a| a.items,
        else => null,
    };
}

/// The value as a bool, or null when it is any other JSON type.
pub fn asBool(value: Value) ?bool {
    return switch (value) {
        .bool => |b| b,
        else => null,
    };
}

pub fn objField(obj: ObjectMap, key: []const u8) ?ObjectMap {
    return asObject(obj.get(key) orelse return null);
}

pub fn stringField(obj: ObjectMap, key: []const u8) ?[]const u8 {
    return asString(obj.get(key) orelse return null);
}

pub fn arrayField(obj: ObjectMap, key: []const u8) ?[]const Value {
    return asArray(obj.get(key) orelse return null);
}

pub fn boolField(obj: ObjectMap, key: []const u8) ?bool {
    return asBool(obj.get(key) orelse return null);
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;

fn parse(arena: std.mem.Allocator, text: []const u8) Value {
    return std.json.parseFromSliceLeaky(Value, arena, text, .{}) catch unreachable;
}

test "field accessors return the value for a matching type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const root = asObject(parse(arena.allocator(),
        \\{"s": "x", "b": true, "a": [1], "o": {"k": "v"}}
    )).?;

    try testing.expectEqualStrings("x", stringField(root, "s").?);
    try testing.expectEqual(true, boolField(root, "b").?);
    try testing.expectEqual(@as(usize, 1), arrayField(root, "a").?.len);
    try testing.expectEqualStrings("v", stringField(objField(root, "o").?, "k").?);
}

test "field accessors return null for a missing key or a wrong type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const root = asObject(parse(arena.allocator(),
        \\{"s": "x"}
    )).?;

    try testing.expect(stringField(root, "absent") == null);
    try testing.expect(boolField(root, "s") == null);
    try testing.expect(arrayField(root, "s") == null);
    try testing.expect(objField(root, "s") == null);
}
