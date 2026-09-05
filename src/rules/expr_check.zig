//! Type inference and type checks over the expression AST.
//!
//! See `docs/design/expr-static-typecheck-design.md` §4-§6.
//! `typeOf` never fails: anything unknown collapses to `any` (ADR D5).

const std = @import("std");
const t = @import("expr_type.zig");
const catalog = @import("expr_catalog.zig");
const expressions = @import("expressions.zig");

const ExprNode = expressions.ExprNode;
const TypeRef = t.TypeRef;

const any = &t.type_any;

/// Context types for one workflow. Overlays (steps / matrix / needs / inputs /
/// secrets) are added in T4; until then every lookup goes to the builtin catalog.
pub const TypeEnv = struct {
    pub fn lookup(_: *const TypeEnv, name: []const u8) ?TypeRef {
        return catalog.lookupContext(name);
    }
};

/// The first type error found while walking a path. Only one is reported per
/// expression node; the result type collapses to `any` so errors do not cascade.
pub const Problem = union(enum) {
    /// Top-level context name is not known (EXPR002).
    unknown_context: []const u8,
    /// Known receiver object, unknown key (EXPR003).
    unknown_property: struct {
        /// Path up to and including the receiver, e.g. "github".
        receiver_path: []const u8,
        name: []const u8,
    },
    /// Property access on a non-object value (EXPR003).
    not_an_object: struct {
        receiver_path: []const u8,
        receiver: TypeRef,
        name: []const u8,
    },
};

pub const WalkResult = struct {
    ty: TypeRef,
    problem: ?Problem = null,
};

pub const Segment = union(enum) {
    ident: []const u8,
    star,
    index_string: []const u8,
};

/// Iterates the flat `context_access` path produced by the parser
/// (`github.event.pull_request`, `foo.*`, `secrets['A']`).
pub const SegmentIter = struct {
    path: []const u8,
    pos: usize = 0,
    /// Byte offset just past the previously returned segment.
    prev_end: usize = 0,

    pub fn next(self: *SegmentIter) ?Segment {
        if (self.pos >= self.path.len) return null;
        if (self.path[self.pos] == '.') self.pos += 1;

        if (self.pos < self.path.len and self.path[self.pos] == '[') {
            const close = std.mem.indexOfScalarPos(u8, self.path, self.pos, ']') orelse {
                self.pos = self.path.len;
                self.prev_end = self.path.len;
                return null;
            };
            const raw = self.path[self.pos + 1 .. close];
            self.pos = close + 1;
            self.prev_end = self.pos;
            return Segment{ .index_string = stripQuotes(raw) };
        }

        const start = self.pos;
        while (self.pos < self.path.len and self.path[self.pos] != '.' and self.path[self.pos] != '[') {
            self.pos += 1;
        }
        const text = self.path[start..self.pos];
        self.prev_end = self.pos;
        if (text.len == 0) return null;
        if (std.mem.eql(u8, text, "*")) return Segment.star;
        return Segment{ .ident = text };
    }
};

fn stripQuotes(s: []const u8) []const u8 {
    if (s.len >= 2 and (s[0] == '\'' or s[0] == '"') and s[s.len - 1] == s[0]) {
        return s[1 .. s.len - 1];
    }
    return s;
}

/// Walk a context path and infer its type, reporting the first type error.
pub fn walkPath(path: []const u8, env: *const TypeEnv) WalkResult {
    var iter = SegmentIter{ .path = path };
    const first = iter.next() orelse return .{ .ty = any };
    const root_name = switch (first) {
        .ident => |name| name,
        else => return .{ .ty = any },
    };

    var current = env.lookup(root_name) orelse
        return .{ .ty = any, .problem = .{ .unknown_context = root_name } };
    var receiver_end = iter.prev_end;

    while (iter.next()) |seg| {
        const receiver_path = path[0..receiver_end];
        const step = applySegment(current, seg, receiver_path);
        if (step.problem) |p| return .{ .ty = any, .problem = p };
        current = step.ty;
        receiver_end = iter.prev_end;
    }
    return .{ .ty = current };
}

fn applySegment(recv: TypeRef, seg: Segment, receiver_path: []const u8) WalkResult {
    if (recv.kind == .any) return .{ .ty = any };
    return switch (seg) {
        .ident => |name| derefProp(recv, name, receiver_path),
        .star => objectFilter(recv, receiver_path),
        .index_string => |key| indexString(recv, key, receiver_path),
    };
}

fn derefProp(recv: TypeRef, name: []const u8, receiver_path: []const u8) WalkResult {
    switch (recv.kind) {
        .object => {
            if (t.findProp(recv, name)) |ty| return .{ .ty = ty };
            return switch (recv.shape) {
                .map => .{ .ty = recv.elem orelse any },
                .loose => .{ .ty = any },
                .strict => .{ .ty = any, .problem = .{ .unknown_property = .{
                    .receiver_path = receiver_path,
                    .name = name,
                } } },
            };
        },
        else => return notAnObject(recv, name, receiver_path),
    }
}

fn notAnObject(recv: TypeRef, name: []const u8, receiver_path: []const u8) WalkResult {
    return .{ .ty = any, .problem = .{ .not_an_object = .{
        .receiver_path = receiver_path,
        .receiver = recv,
        .name = name,
    } } };
}

fn objectFilter(recv: TypeRef, receiver_path: []const u8) WalkResult {
    switch (recv.kind) {
        .any => return .{ .ty = any },
        .array => return .{ .ty = &t.type_array_any },
        .object => {
            // Element type is the merge of every value type; a heterogeneous
            // object collapses to array<any>, which is safe.
            var elem: ?TypeRef = if (recv.shape == .map) recv.elem else null;
            if (elem == null) {
                for (recv.props) |p| {
                    elem = if (elem) |e| t.merge(e, p.ty) else p.ty;
                }
            }
            const e = elem orelse any;
            if (e == &t.type_string) return .{ .ty = &t.type_array_string };
            return .{ .ty = &t.type_array_any };
        },
        else => return .{ .ty = any, .problem = .{ .not_an_object = .{
            .receiver_path = receiver_path,
            .receiver = recv,
            .name = "*",
        } } },
    }
}

fn indexString(recv: TypeRef, key: []const u8, receiver_path: []const u8) WalkResult {
    return switch (recv.kind) {
        .object => derefProp(recv, key, receiver_path),
        // String subscripts on arrays are not meaningful but are not worth a
        // false positive either.
        .array => .{ .ty = any },
        else => notAnObject(recv, key, receiver_path),
    };
}

// ============================================================
// typeOf
// ============================================================

pub fn typeOf(node: *const ExprNode, env: *const TypeEnv) TypeRef {
    return switch (node.kind) {
        .context_access => walkPath(node.value, env).ty,
        .function_call => functionReturnType(node),
        .binary_op => blk: {
            if (isCompareOp(node.value)) break :blk &t.type_bool;
            if (node.children.len == 2) {
                break :blk t.merge(
                    typeOf(&node.children[0], env),
                    typeOf(&node.children[1], env),
                );
            }
            break :blk any;
        },
        .unary_op => &t.type_bool,
        .string_literal => &t.type_string,
        .number_literal => &t.type_number,
        .boolean_literal => &t.type_bool,
        .null_literal => &t.type_null,
    };
}

fn functionReturnType(node: *const ExprNode) TypeRef {
    if (std.mem.eql(u8, node.value, "fromJSON")) return fromJsonType(node);
    const sig = catalog.lookupFunction(node.value) orelse return any;
    return sig.ret;
}

/// `fromJSON('<literal>')` infers a shallow type from the literal. Anything
/// else, including malformed JSON (EXPR009's job), is `any`.
fn fromJsonType(node: *const ExprNode) TypeRef {
    if (node.children.len != 1) return any;
    const arg = &node.children[0];
    if (arg.kind != .string_literal) return any;
    const text = std.mem.trim(u8, stripQuotes(arg.value), " \t\r\n");
    if (text.len == 0) return any;
    return switch (text[0]) {
        '[' => &t.type_array_any,
        '{' => &t.type_loose_object,
        '"' => &t.type_string,
        '-', '0'...'9' => &t.type_number,
        else => if (std.mem.eql(u8, text, "true") or std.mem.eql(u8, text, "false"))
            &t.type_bool
        else if (std.mem.eql(u8, text, "null"))
            &t.type_null
        else
            any,
    };
}

// ============================================================
// Comparison rules (EXPR017 / ADR D6)
// ============================================================

pub fn isCompareOp(op: []const u8) bool {
    return isEqualityOp(op) or isRelationalOp(op);
}

fn isEqualityOp(op: []const u8) bool {
    return std.mem.eql(u8, op, "==") or std.mem.eql(u8, op, "!=");
}

fn isRelationalOp(op: []const u8) bool {
    return std.mem.eql(u8, op, "<") or std.mem.eql(u8, op, ">") or
        std.mem.eql(u8, op, "<=") or std.mem.eql(u8, op, ">=");
}

fn isScalar(kind: t.TypeKind) bool {
    return kind == .number or kind == .bool or kind == .string;
}

/// Returns false only when the comparison can never be meaningful.
pub fn checkCompare(op: []const u8, lhs: TypeRef, rhs: TypeRef) bool {
    if (lhs.kind == .any or rhs.kind == .any) return true;

    if (isRelationalOp(op)) {
        return (lhs.kind == .number or lhs.kind == .string) and
            (rhs.kind == .number or rhs.kind == .string);
    }
    if (!isEqualityOp(op)) return true;

    if (lhs.kind == .null or rhs.kind == .null) return true;
    if (isScalar(lhs.kind) and isScalar(rhs.kind)) return true;
    if (lhs.kind == .object and rhs.kind == .object) return true;
    if (lhs.kind == .array and rhs.kind == .array) {
        return checkCompare(op, lhs.elem orelse any, rhs.elem orelse any);
    }
    return false;
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;
const empty_env = TypeEnv{};

fn walkTy(path: []const u8) TypeRef {
    return walkPath(path, &empty_env).ty;
}

test "walk: github.sha is string" {
    try testing.expectEqual(t.TypeKind.string, walkTy("github.sha").kind);
}

test "walk: github.ref_protected is bool" {
    try testing.expectEqual(t.TypeKind.bool, walkTy("github.ref_protected").kind);
}

test "walk: github.event.pull_request is any" {
    const r = walkPath("github.event.pull_request.head.sha", &empty_env);
    try testing.expectEqual(t.TypeKind.any, r.ty.kind);
    try testing.expectEqual(@as(?Problem, null), r.problem);
}

test "walk: unknown context is reported" {
    const r = walkPath("foo.bar", &empty_env);
    try testing.expect(r.problem != null);
    try testing.expectEqualStrings("foo", r.problem.?.unknown_context);
}

test "walk: unknown github property is reported" {
    const r = walkPath("github.reposiory", &empty_env);
    try testing.expect(r.problem != null);
    try testing.expectEqualStrings("reposiory", r.problem.?.unknown_property.name);
    try testing.expectEqualStrings("github", r.problem.?.unknown_property.receiver_path);
}

test "walk: property access on a string is reported" {
    const r = walkPath("github.repository.permissions", &empty_env);
    try testing.expect(r.problem != null);
    try testing.expectEqualStrings("permissions", r.problem.?.not_an_object.name);
    try testing.expectEqualStrings("github.repository", r.problem.?.not_an_object.receiver_path);
    try testing.expectEqual(t.TypeKind.any, r.ty.kind);
}

test "walk: unknown job property is reported" {
    const r = walkPath("job.unknown", &empty_env);
    try testing.expect(r.problem != null);
}

test "walk: nested job container property" {
    try testing.expectEqual(t.TypeKind.string, walkTy("job.container.id").kind);
    try testing.expectEqual(t.TypeKind.string, walkTy("job.services.redis.ports.6379").kind);
}

test "walk: contexts awaiting overlay stay silent" {
    for ([_][]const u8{
        "steps.setup.outputs.v",
        "matrix.os",
        "needs.build.outputs.x",
        "inputs.name",
        "jobs.build.outputs.x",
    }) |path| {
        const r = walkPath(path, &empty_env);
        try testing.expectEqual(@as(?Problem, null), r.problem);
        try testing.expectEqual(t.TypeKind.any, r.ty.kind);
    }
}

test "walk: map contexts yield string values" {
    try testing.expectEqual(t.TypeKind.string, walkTy("env.FOO").kind);
    try testing.expectEqual(t.TypeKind.string, walkTy("secrets.GITHUB_TOKEN").kind);
    try testing.expectEqual(t.TypeKind.string, walkTy("vars.ANY_NAME").kind);
}

test "walk: bracket access behaves like a property" {
    try testing.expectEqual(t.TypeKind.string, walkTy("github['sha']").kind);
    const r = walkPath("github['reposiory']", &empty_env);
    try testing.expect(r.problem != null);
}

test "walk: object filter produces an array" {
    const ty = walkTy("job.container.*");
    try testing.expectEqual(t.TypeKind.array, ty.kind);
    try testing.expectEqual(t.TypeKind.any, walkTy("steps.*.outputs.v").kind);
}

test "walk: strategy is loose but typed for known keys" {
    try testing.expectEqual(t.TypeKind.number, walkTy("strategy.job-index").kind);
    const r = walkPath("strategy.unknown", &empty_env);
    try testing.expectEqual(@as(?Problem, null), r.problem);
}

test "checkCompare: equality table" {
    try testing.expect(checkCompare("==", &t.type_string, &t.type_number));
    try testing.expect(checkCompare("==", &t.type_any, &t.type_loose_object));
    try testing.expect(checkCompare("==", &t.type_null, &t.type_loose_object));
    try testing.expect(checkCompare("==", &t.type_loose_object, &t.type_loose_object));
    try testing.expect(checkCompare("!=", &t.type_array_any, &t.type_array_string));
    try testing.expect(!checkCompare("==", &t.type_loose_object, &t.type_number));
    try testing.expect(!checkCompare("!=", &t.type_array_any, &t.type_string));
}

test "checkCompare: relational table" {
    try testing.expect(checkCompare("<", &t.type_number, &t.type_number));
    try testing.expect(checkCompare(">=", &t.type_string, &t.type_number));
    try testing.expect(checkCompare(">", &t.type_any, &t.type_loose_object));
    try testing.expect(!checkCompare(">", &t.type_bool, &t.type_number));
    try testing.expect(!checkCompare("<=", &t.type_null, &t.type_number));
    try testing.expect(!checkCompare(">", &t.type_loose_object, &t.type_number));
}

test "segments: dotted, star and bracket forms" {
    var iter = SegmentIter{ .path = "a.b.*['c']" };
    try testing.expectEqualStrings("a", iter.next().?.ident);
    try testing.expectEqualStrings("b", iter.next().?.ident);
    try testing.expectEqual(Segment.star, iter.next().?);
    try testing.expectEqualStrings("c", iter.next().?.index_string);
    try testing.expectEqual(@as(?Segment, null), iter.next());
}
