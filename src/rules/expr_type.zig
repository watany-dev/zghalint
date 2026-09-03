//! Static type representation for GitHub Actions expressions.
//!
//! See `docs/adr/0006-expr-static-typecheck.md` (D1) and
//! `docs/design/expr-static-typecheck-design.md` §2.
//!
//! Types are interned: every type is a comptime constant shared by pointer, so
//! identity comparison is type equality and nothing is allocated at runtime.

const std = @import("std");

pub const TypeKind = enum {
    any,
    null,
    number,
    bool,
    string,
    array,
    object,

    pub fn toString(self: TypeKind) []const u8 {
        return @tagName(self);
    }
};

/// How unknown keys of an object are treated.
pub const ObjectShape = enum {
    /// Unknown key is a type error (EXPR003). github / runner / job.
    strict,
    /// Unknown key is `any`. github.event, and contexts awaiting overlay.
    loose,
    /// Every key has the `elem` type. env / vars / secrets.
    map,
};

pub const Prop = struct {
    name: []const u8,
    ty: *const Type,
};

pub const Type = struct {
    kind: TypeKind,
    /// Element type of an array, or the value type of a map object.
    elem: ?*const Type = null,
    /// Known properties of an object, sorted by name (binary search).
    props: []const Prop = &.{},
    shape: ObjectShape = .loose,
    /// True when the array came from an object filter `.*` (actionlint ArrayType.Deref).
    deref: bool = false,
};

pub const TypeRef = *const Type;

// --- interned scalars (no runtime allocation) ---

pub const type_any: Type = .{ .kind = .any };
pub const type_null: Type = .{ .kind = .null };
pub const type_number: Type = .{ .kind = .number };
pub const type_bool: Type = .{ .kind = .bool };
pub const type_string: Type = .{ .kind = .string };
pub const type_array_any: Type = .{ .kind = .array, .elem = &type_any };
pub const type_array_string: Type = .{ .kind = .array, .elem = &type_string };
/// Empty loose object: every key is `any`.
pub const type_loose_object: Type = .{ .kind = .object, .shape = .loose };
/// `{string => string}` map object.
pub const type_map_string: Type = .{ .kind = .object, .shape = .map, .elem = &type_string };

/// Binary search over the sorted `props` of an object type.
pub fn findProp(ty: TypeRef, name: []const u8) ?TypeRef {
    var lo: usize = 0;
    var hi: usize = ty.props.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, ty.props[mid].name, name)) {
            .lt => lo = mid + 1,
            .gt => hi = mid,
            .eq => return ty.props[mid].ty,
        }
    }
    return null;
}

/// Merge two types. Conflicts collapse to `any` (ADR D5).
pub fn merge(a: TypeRef, b: TypeRef) TypeRef {
    if (a == b) return a;
    if (a.kind != b.kind or a.kind == .any) return &type_any;

    return switch (a.kind) {
        .array => if (merge(a.elem orelse &type_any, b.elem orelse &type_any) == (a.elem orelse &type_any))
            a
        else
            &type_array_any,
        // Property unions need an allocator; until overlays exist there is
        // nothing to union, so differing objects collapse to a loose object.
        .object => &type_loose_object,
        else => a,
    };
}

/// Render a type for diagnostic messages.
/// Strict objects become `{a: string; b: number}`, loose objects `object`,
/// map objects `{string => string}`. Falls back to the bare kind name when the
/// buffer is too small.
pub fn display(ty: TypeRef, buf: []u8) []const u8 {
    var len: usize = 0;
    write(ty, buf, &len, 0) catch return ty.kind.toString();
    return buf[0..len];
}

const WriteError = error{NoSpace};

fn writeStr(buf: []u8, len: *usize, s: []const u8) WriteError!void {
    if (len.* + s.len > buf.len) return WriteError.NoSpace;
    @memcpy(buf[len.* .. len.* + s.len], s);
    len.* += s.len;
}

fn write(ty: TypeRef, buf: []u8, len: *usize, depth: u8) WriteError!void {
    switch (ty.kind) {
        .array => {
            try writeStr(buf, len, "array<");
            if (depth >= 4) {
                try writeStr(buf, len, "...");
            } else {
                try write(ty.elem orelse &type_any, buf, len, depth + 1);
            }
            try writeStr(buf, len, ">");
        },
        .object => switch (ty.shape) {
            .map => {
                try writeStr(buf, len, "{string => ");
                if (depth >= 4) {
                    try writeStr(buf, len, "...");
                } else {
                    try write(ty.elem orelse &type_any, buf, len, depth + 1);
                }
                try writeStr(buf, len, "}");
            },
            .loose => try writeStr(buf, len, "object"),
            .strict => {
                if (depth >= 2) return writeStr(buf, len, "object");
                try writeStr(buf, len, "{");
                for (ty.props, 0..) |p, i| {
                    if (i > 0) try writeStr(buf, len, "; ");
                    try writeStr(buf, len, p.name);
                    try writeStr(buf, len, ": ");
                    try write(p.ty, buf, len, depth + 1);
                }
                try writeStr(buf, len, "}");
            },
        },
        else => try writeStr(buf, len, ty.kind.toString()),
    }
}

// ============================================================
// Tests
// ============================================================

test "merge: identical types are interned as one" {
    try std.testing.expectEqual(@as(TypeRef, &type_string), merge(&type_string, &type_string));
}

test "merge: conflicting kinds and any collapse to any" {
    try std.testing.expectEqual(TypeKind.any, merge(&type_number, &type_string).kind);
    try std.testing.expectEqual(TypeKind.any, merge(&type_any, &type_number).kind);
}

test "merge: differing objects collapse to a loose object" {
    const other: Type = .{ .kind = .object, .shape = .strict };
    const ty = merge(&type_loose_object, &other);
    try std.testing.expectEqual(TypeKind.object, ty.kind);
    try std.testing.expectEqual(ObjectShape.loose, ty.shape);
}

test "merge: arrays keep a shared element type" {
    try std.testing.expectEqual(@as(TypeRef, &type_array_string), merge(&type_array_string, &type_array_string));
    try std.testing.expectEqual(TypeKind.any, merge(&type_array_string, &type_array_any).elem.?.kind);
}

test "display: scalars and containers" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("string", display(&type_string, &buf));
    try std.testing.expectEqualStrings("array<any>", display(&type_array_any, &buf));
    try std.testing.expectEqualStrings("object", display(&type_loose_object, &buf));
    try std.testing.expectEqualStrings("{string => string}", display(&type_map_string, &buf));
}

test "display: strict object lists props" {
    const obj: Type = .{
        .kind = .object,
        .shape = .strict,
        .props = &.{
            .{ .name = "a", .ty = &type_string },
            .{ .name = "b", .ty = &type_number },
        },
    };
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("{a: string; b: number}", display(&obj, &buf));
}

test "display: falls back to kind name when the buffer is too small" {
    const obj: Type = .{
        .kind = .object,
        .shape = .strict,
        .props = &.{.{ .name = "verylongpropertyname", .ty = &type_string }},
    };
    var buf: [4]u8 = undefined;
    try std.testing.expectEqualStrings("object", display(&obj, &buf));
}

test "findProp: binary search hits and misses" {
    const obj: Type = .{
        .kind = .object,
        .shape = .strict,
        .props = &.{
            .{ .name = "alpha", .ty = &type_string },
            .{ .name = "beta", .ty = &type_number },
            .{ .name = "gamma", .ty = &type_bool },
        },
    };
    try std.testing.expectEqual(@as(?TypeRef, &type_number), findProp(&obj, "beta"));
    try std.testing.expectEqual(@as(?TypeRef, null), findProp(&obj, "delta"));
}
