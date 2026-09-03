//! Static type representation for GitHub Actions expressions.
//!
//! See `docs/adr/0006-expr-static-typecheck.md` (D1) and
//! `docs/design/expr-static-typecheck-design.md` §2.
//!
//! Types are interned: builtin catalog entries are comptime constants shared by
//! pointer, and only workflow-dependent overlays are allocated in a `TypeArena`.

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
        return switch (self) {
            .any => "any",
            .null => "null",
            .number => "number",
            .bool => "bool",
            .string => "string",
            .array => "array",
            .object => "object",
        };
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

/// Can a value of type `src` be used where `dst` is expected?
/// `any` is assignable in both directions. Mirrors actionlint `Assignable`.
pub fn assignable(dst: TypeRef, src: TypeRef) bool {
    if (dst.kind == .any or src.kind == .any) return true;
    return switch (dst.kind) {
        .any => true,
        // `if: ${{ steps.foo }}` is legal: anything is usable as a bool.
        .bool => true,
        .null => src.kind == .null,
        .number => src.kind == .number or src.kind == .bool,
        .string => switch (src.kind) {
            .string, .number, .bool, .null => true,
            else => false,
        },
        .array => src.kind == .array and
            assignable(dst.elem orelse &type_any, src.elem orelse &type_any),
        .object => src.kind == .object,
    };
}

/// Merge two types. Conflicts collapse to `any` (ADR D5).
/// `arena` is only needed to build a merged object/array; when it is null a
/// merge that would allocate falls back to `any`.
pub fn merge(arena: ?*TypeArena, a: TypeRef, b: TypeRef) TypeRef {
    if (a == b) return a;
    if (a.kind == .any or b.kind == .any) return &type_any;
    if (a.kind != b.kind) return &type_any;

    switch (a.kind) {
        .array => {
            const elem = merge(arena, a.elem orelse &type_any, b.elem orelse &type_any);
            const deref = a.deref and b.deref;
            if (elem == (a.elem orelse &type_any) and a.deref == deref) return a;
            if (elem.kind == .any and !deref) return &type_array_any;
            const ar = arena orelse return &type_any;
            return ar.internArray(elem, deref) catch &type_any;
        },
        .object => return mergeObject(arena, a, b),
        else => return a,
    }
}

fn mergeObject(arena: ?*TypeArena, a: TypeRef, b: TypeRef) TypeRef {
    const shape: ObjectShape = if (a.shape == .strict and b.shape == .strict) .strict else .loose;
    if (a.props.len == 0 and b.props.len == 0) {
        if (a.shape == .map and b.shape == .map) {
            const elem = merge(arena, a.elem orelse &type_any, b.elem orelse &type_any);
            if (elem == (a.elem orelse &type_any)) return a;
            const ar = arena orelse return &type_any;
            return ar.internMap(elem) catch &type_any;
        }
        if (shape == .loose) return &type_loose_object;
    }

    const ar = arena orelse return &type_any;

    // Exact-size allocation: counting first avoids pulling an ArrayList
    // instantiation into the binary (ADR D7 size budget).
    var count = a.props.len;
    for (b.props) |p| {
        if (findProp(a, p.name) == null) count += 1;
    }
    const slice = ar.allocator().alloc(Prop, count) catch return &type_any;

    var n: usize = 0;
    for (a.props) |p| {
        const merged = if (findProp(b, p.name)) |other| merge(arena, p.ty, other) else p.ty;
        slice[n] = .{ .name = p.name, .ty = merged };
        n += 1;
    }
    for (b.props) |p| {
        if (findProp(a, p.name) != null) continue;
        slice[n] = .{ .name = p.name, .ty = p.ty };
        n += 1;
    }
    sortProps(slice);
    return ar.internObject(shape, slice, null) catch &type_any;
}

/// Insertion sort: property lists are tiny and `std.mem.sort` would pull a
/// large block-sort instantiation into the binary (ADR D7 size budget).
fn sortProps(props: []Prop) void {
    var i: usize = 1;
    while (i < props.len) : (i += 1) {
        const item = props[i];
        var j = i;
        while (j > 0 and std.mem.order(u8, props[j - 1].name, item.name) == .gt) : (j -= 1) {
            props[j] = props[j - 1];
        }
        props[j] = item;
    }
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

/// Runtime intern table for workflow-dependent overlay types.
/// Lifetime: one workflow lint. Builtin types are never stored here.
pub const TypeArena = struct {
    arena: std.heap.ArenaAllocator,

    pub fn init(backing: std.mem.Allocator) TypeArena {
        return .{ .arena = std.heap.ArenaAllocator.init(backing) };
    }

    pub fn deinit(self: *TypeArena) void {
        self.arena.deinit();
    }

    pub fn allocator(self: *TypeArena) std.mem.Allocator {
        return self.arena.allocator();
    }

    pub fn internObject(
        self: *TypeArena,
        shape: ObjectShape,
        props: []const Prop,
        mapped: ?TypeRef,
    ) error{OutOfMemory}!TypeRef {
        const copy = try self.allocator().create(Type);
        copy.* = .{ .kind = .object, .elem = mapped, .props = props, .shape = shape };
        return copy;
    }

    pub fn internMap(self: *TypeArena, elem: TypeRef) error{OutOfMemory}!TypeRef {
        return self.internObject(.map, &.{}, elem);
    }

    pub fn internArray(self: *TypeArena, elem: TypeRef, deref: bool) error{OutOfMemory}!TypeRef {
        const copy = try self.allocator().create(Type);
        copy.* = .{ .kind = .array, .elem = elem, .deref = deref };
        return copy;
    }
};

// ============================================================
// Tests
// ============================================================

test "assignable: any is assignable in both directions" {
    try std.testing.expect(assignable(&type_string, &type_any));
    try std.testing.expect(assignable(&type_any, &type_object_fixture));
}

const type_object_fixture: Type = .{ .kind = .object, .shape = .loose };

test "assignable: bool accepts everything" {
    try std.testing.expect(assignable(&type_bool, &type_string));
    try std.testing.expect(assignable(&type_bool, &type_array_any));
}

test "assignable: string does not accept array or object" {
    try std.testing.expect(assignable(&type_string, &type_number));
    try std.testing.expect(!assignable(&type_string, &type_array_any));
    try std.testing.expect(!assignable(&type_string, &type_loose_object));
}

test "assignable: array compares element types" {
    try std.testing.expect(assignable(&type_array_string, &type_array_string));
    try std.testing.expect(assignable(&type_array_string, &type_array_any));
}

test "merge: identical types are interned as one" {
    try std.testing.expectEqual(@as(TypeRef, &type_string), merge(null, &type_string, &type_string));
}

test "merge: number with string is any" {
    const ty = merge(null, &type_number, &type_string);
    try std.testing.expectEqual(TypeKind.any, ty.kind);
}

test "merge: any wins" {
    try std.testing.expectEqual(TypeKind.any, merge(null, &type_any, &type_number).kind);
}

test "merge: loose objects merge without an arena" {
    const ty = merge(null, &type_loose_object, &type_object_fixture);
    try std.testing.expectEqual(TypeKind.object, ty.kind);
    try std.testing.expectEqual(ObjectShape.loose, ty.shape);
}

test "merge: strict objects need an arena and union their props" {
    var arena = TypeArena.init(std.testing.allocator);
    defer arena.deinit();

    const a: Type = .{
        .kind = .object,
        .shape = .strict,
        .props = &.{.{ .name = "a", .ty = &type_string }},
    };
    const b: Type = .{
        .kind = .object,
        .shape = .strict,
        .props = &.{.{ .name = "b", .ty = &type_number }},
    };
    const ty = merge(&arena, &a, &b);
    try std.testing.expectEqual(TypeKind.object, ty.kind);
    try std.testing.expectEqual(@as(usize, 2), ty.props.len);
    try std.testing.expectEqualStrings("a", ty.props[0].name);
    try std.testing.expectEqualStrings("b", ty.props[1].name);
}

test "merge: object without arena falls back to any" {
    const a: Type = .{
        .kind = .object,
        .shape = .strict,
        .props = &.{.{ .name = "a", .ty = &type_string }},
    };
    const b: Type = .{
        .kind = .object,
        .shape = .strict,
        .props = &.{.{ .name = "b", .ty = &type_number }},
    };
    try std.testing.expectEqual(TypeKind.any, merge(null, &a, &b).kind);
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

test "TypeArena: interned array and object" {
    var arena = TypeArena.init(std.testing.allocator);
    defer arena.deinit();
    const arr = try arena.internArray(&type_string, true);
    try std.testing.expectEqual(TypeKind.array, arr.kind);
    try std.testing.expect(arr.deref);
    const obj = try arena.internObject(.strict, &.{}, null);
    try std.testing.expectEqual(ObjectShape.strict, obj.shape);
}
