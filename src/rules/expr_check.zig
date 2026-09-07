//! See `docs/design/expr-static-typecheck-design.md` §4-§6.
//! `typeOf` never fails: anything unknown collapses to `any` (ADR D5).

const std = @import("std");
const t = @import("expr_type.zig");
const catalog = @import("expr_catalog.zig");
const expressions = @import("expressions.zig");

const ExprNode = expressions.ExprNode;
const TypeRef = t.TypeRef;

const any = &t.type_any;

/// Only one problem is reported per expression node and the result type
/// collapses to `any`, so a single error does not cascade.
pub const Problem = union(enum) {
    unknown_context: []const u8,
    unknown_property: struct {
        receiver_path: []const u8,
        name: []const u8,
    },
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

pub const SegmentIter = struct {
    path: []const u8,
    pos: usize = 0,
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

/// Per-workflow contextual overlays (T4, #129); see
/// `docs/design/expr-static-typecheck-design.md` §4. A null field leaves the
/// root resolving against the builtin catalog, where it is a loose object and
/// therefore silent.
pub const TypeEnv = struct {
    steps: ?TypeRef = null,
    matrix: ?TypeRef = null,
    needs: ?TypeRef = null,
    inputs: ?TypeRef = null,
    secrets: ?TypeRef = null,

    /// The overlay-free environment: what `check_step` and the unit tests use.
    pub const empty: TypeEnv = .{};

    /// Root names are matched exactly, like `catalog.lookupContext`: a
    /// miscased root is EXPR002's business, not the overlay's.
    pub fn lookup(self: *const TypeEnv, name: []const u8) ?TypeRef {
        const eql = std.mem.eql;
        if (eql(u8, name, "steps")) return self.steps;
        if (eql(u8, name, "matrix")) return self.matrix;
        if (eql(u8, name, "needs")) return self.needs;
        if (eql(u8, name, "inputs")) return self.inputs;
        if (eql(u8, name, "secrets")) return self.secrets;
        return null;
    }
};

/// Overlay roots are built strict so property types resolve, but a missing key
/// under one belongs to EXPR010-EXPR014: reporting it here too would double up
/// on the same span, so the walk stays silent and yields `any` (#129).
const Origin = enum { builtin, overlay };

/// Every root name resolves against `env` first, then the builtin catalog.
pub fn walkPath(path: []const u8, env: *const TypeEnv) WalkResult {
    var iter = SegmentIter{ .path = path };
    const first = iter.next() orelse return .{ .ty = any };
    const root_name = switch (first) {
        .ident => |name| name,
        else => return .{ .ty = any },
    };

    var origin: Origin = .overlay;
    var current = env.lookup(root_name) orelse blk: {
        origin = .builtin;
        break :blk catalog.lookupContext(root_name) orelse
            return .{ .ty = any, .problem = .{ .unknown_context = root_name } };
    };
    var receiver_end = iter.prev_end;
    // Nothing below `github.event` is diagnosed: the payload is not modelled
    // (ADR D3) and the curated overlay (D3-a) only exists to type comparisons,
    // so even a deref of a curated scalar collapses to `any` instead of
    // EXPR003.
    var in_payload = false;

    while (iter.next()) |seg| {
        const receiver_path = path[0..receiver_end];
        const step = applySegment(current, seg, receiver_path, origin);
        if (step.problem) |p| {
            if (origin == .overlay or in_payload) return .{ .ty = any };
            return .{ .ty = any, .problem = p };
        }
        current = step.ty;
        if (current == &catalog.github_event) in_payload = true;
        receiver_end = iter.prev_end;
    }
    return .{ .ty = current };
}

fn applySegment(recv: TypeRef, seg: Segment, receiver_path: []const u8, origin: Origin) WalkResult {
    if (recv.kind == .any) return .{ .ty = any };
    return switch (seg) {
        .ident => |name| derefProp(recv, name, receiver_path, origin),
        .star => objectFilter(recv, receiver_path),
        .index_string => |key| indexString(recv, key, receiver_path, origin),
    };
}

fn derefProp(recv: TypeRef, name: []const u8, receiver_path: []const u8, origin: Origin) WalkResult {
    switch (recv.kind) {
        .object => {
            const found = switch (origin) {
                .builtin => t.findProp(recv, name),
                .overlay => t.findPropIgnoreCase(recv, name),
            };
            if (found) |ty| return .{ .ty = ty };
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
            // A heterogeneous object collapses to array<any>, which is safe.
            // A loose object has keys outside `props`, so only a map or a
            // strict object can narrow the element type.
            var elem: ?TypeRef = if (recv.shape == .map) recv.elem else null;
            if (elem == null and recv.shape == .strict) {
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

fn indexString(recv: TypeRef, key: []const u8, receiver_path: []const u8, origin: Origin) WalkResult {
    return switch (recv.kind) {
        .object => derefProp(recv, key, receiver_path, origin),
        // String subscripts on arrays are not meaningful but are not worth a
        // false positive either.
        .array => .{ .ty = any },
        else => notAnObject(recv, key, receiver_path),
    };
}

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

/// Malformed JSON is EXPR009's job; anything but a string literal argument
/// is `any`.
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

/// Returns false only when the comparison can never be meaningful (ADR D6).
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

/// Returns false only when the value can never be what the parameter takes
/// (EXPR018, #162). `any` and the un-overlaid contexts short-circuit to true,
/// which is what keeps the check free of false positives (ADR D3).
pub fn acceptsArg(kind: catalog.ArgKind, ty: TypeRef) bool {
    if (ty.kind == .any) return true;
    if (catalog.isUnmodelledObject(ty)) return true;
    return switch (kind) {
        .any => true,
        .string => ty.kind != .object and ty.kind != .array,
        .string_or_array => ty.kind != .object,
    };
}

/// A value spliced into a string that GitHub cannot render usefully
/// (EXPR018, #162). Objects render as `Object`, arrays as `Array`, and null as
/// nothing at all; a scalar is always fine.
pub fn interpolationProblem(ty: TypeRef) ?t.TypeKind {
    if (catalog.isUnmodelledObject(ty)) return null;
    return switch (ty.kind) {
        .object, .array, .null => ty.kind,
        else => null,
    };
}

const testing = std.testing;
fn walkTy(path: []const u8) TypeRef {
    return walkPath(path, &TypeEnv.empty).ty;
}

test "walk: github.sha is string" {
    try testing.expectEqual(t.TypeKind.string, walkTy("github.sha").kind);
}

test "walk: github.ref_protected is bool" {
    try testing.expectEqual(t.TypeKind.bool, walkTy("github.ref_protected").kind);
}

test "walk: uncurated github.event payload stays any" {
    const r = walkPath("github.event.deployment.payload.env", &TypeEnv.empty);
    try testing.expectEqual(t.TypeKind.any, r.ty.kind);
    try testing.expectEqual(@as(?Problem, null), r.problem);
}

test "walk: curated github.event paths carry a type" {
    try testing.expectEqual(t.TypeKind.number, walkTy("github.event.issue.number").kind);
    try testing.expectEqual(t.TypeKind.string, walkTy("github.event.pull_request.head.sha").kind);
    try testing.expectEqual(t.TypeKind.bool, walkTy("github.event.pull_request.draft").kind);
    try testing.expectEqual(t.TypeKind.bool, walkTy("github.event.repository.private").kind);
    try testing.expectEqual(t.TypeKind.object, walkTy("github.event.issue").kind);
}

test "walk: nothing below github.event is ever diagnosed" {
    for ([_][]const u8{
        "github.event.issue.numer",
        "github.event.pull_request.hea.sha",
        "github.event.unknown_key.deep",
        "github.event.inputs.name",
        // Dereferencing a curated scalar: a real mistake, but the payload
        // stays silent (ADR D3).
        "github.event.issue.number.foo",
        "github.event.ref.name",
        "github.event.pull_request.head.sha[0]",
    }) |path| {
        const r = walkPath(path, &TypeEnv.empty);
        try testing.expectEqual(@as(?Problem, null), r.problem);
        try testing.expectEqual(t.TypeKind.any, r.ty.kind);
    }
}

test "checkCompare: curated overlay widens EXPR017 reach" {
    try testing.expect(!checkCompare("==", walkTy("github.event.issue"), &t.type_string));
    try testing.expect(!checkCompare(">", walkTy("github.event.pull_request.draft"), &t.type_number));
    // Scalar mixing stays silent: GitHub coerces number and string operands.
    try testing.expect(checkCompare("==", walkTy("github.event.issue.number"), &t.type_string));
}

test "walk: unknown context is reported" {
    const r = walkPath("foo.bar", &TypeEnv.empty);
    try testing.expect(r.problem != null);
    try testing.expectEqualStrings("foo", r.problem.?.unknown_context);
}

test "walk: unknown github property is reported" {
    const r = walkPath("github.reposiory", &TypeEnv.empty);
    try testing.expect(r.problem != null);
    try testing.expectEqualStrings("reposiory", r.problem.?.unknown_property.name);
    try testing.expectEqualStrings("github", r.problem.?.unknown_property.receiver_path);
}

test "walk: property access on a string is reported" {
    const r = walkPath("github.repository.permissions", &TypeEnv.empty);
    try testing.expect(r.problem != null);
    try testing.expectEqualStrings("permissions", r.problem.?.not_an_object.name);
    try testing.expectEqualStrings("github.repository", r.problem.?.not_an_object.receiver_path);
    try testing.expectEqual(t.TypeKind.any, r.ty.kind);
}

test "walk: unknown job property is reported" {
    const r = walkPath("job.unknown", &TypeEnv.empty);
    try testing.expect(r.problem != null);
}

test "walk: nested job container property" {
    try testing.expectEqual(t.TypeKind.string, walkTy("job.container.id").kind);
    try testing.expectEqual(t.TypeKind.string, walkTy("job.services.redis.ports.6379").kind);
}

test "walk: overlay-less contexts stay silent" {
    for ([_][]const u8{
        "steps.setup.outputs.v",
        "matrix.os",
        "needs.build.outputs.x",
        "inputs.name",
        "jobs.build.outputs.x",
    }) |path| {
        const r = walkPath(path, &TypeEnv.empty);
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
    const r = walkPath("github['reposiory']", &TypeEnv.empty);
    try testing.expect(r.problem != null);
}

test "walk: object filter produces an array" {
    const ty = walkTy("job.container.*");
    try testing.expectEqual(t.TypeKind.array, ty.kind);
    try testing.expectEqual(t.TypeKind.any, walkTy("steps.*.outputs.v").kind);
}

test "walk: an object filter over a loose object stays array<any>" {
    // `sender` delivers keys outside the curated set, so narrowing to
    // array<string> from its two string props would be wrong.
    const ty = walkTy("github.event.sender.*");
    try testing.expectEqual(t.TypeKind.array, ty.kind);
    try testing.expectEqual(t.TypeKind.any, ty.elem.?.kind);
}

test "walk: strategy is loose but typed for known keys" {
    try testing.expectEqual(t.TypeKind.number, walkTy("strategy.job-index").kind);
    const r = walkPath("strategy.unknown", &TypeEnv.empty);
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

test "acceptsArg: only containers are rejected" {
    const K = catalog.ArgKind;
    try testing.expect(acceptsArg(.string, &t.type_string));
    try testing.expect(acceptsArg(.string, &t.type_number));
    try testing.expect(acceptsArg(.string, &t.type_bool));
    // null coerces to an empty string, so it is not an argument error.
    try testing.expect(acceptsArg(.string, &t.type_null));
    try testing.expect(!acceptsArg(.string, &t.type_loose_object));
    try testing.expect(!acceptsArg(.string, &t.type_array_string));

    try testing.expect(acceptsArg(.string_or_array, &t.type_array_string));
    try testing.expect(!acceptsArg(.string_or_array, &t.type_loose_object));

    try testing.expect(acceptsArg(.any, &t.type_loose_object));
    try testing.expect(acceptsArg(K.string, &t.type_any));
    // An un-overlaid context carries no information to reject.
    try testing.expect(acceptsArg(.string, catalog.lookupContext("jobs").?));
}

test "interpolationProblem: containers and null only" {
    try testing.expectEqual(@as(?t.TypeKind, null), interpolationProblem(&t.type_string));
    try testing.expectEqual(@as(?t.TypeKind, null), interpolationProblem(&t.type_any));
    try testing.expectEqual(@as(?t.TypeKind, null), interpolationProblem(&t.type_bool));
    try testing.expectEqual(@as(?t.TypeKind, .object), interpolationProblem(&t.type_loose_object));
    try testing.expectEqual(@as(?t.TypeKind, .array), interpolationProblem(&t.type_array_any));
    try testing.expectEqual(@as(?t.TypeKind, .null), interpolationProblem(&t.type_null));
    try testing.expectEqual(@as(?t.TypeKind, null), interpolationProblem(catalog.lookupContext("steps").?));
}

test "segments: dotted, star and bracket forms" {
    var iter = SegmentIter{ .path = "a.b.*['c']" };
    try testing.expectEqualStrings("a", iter.next().?.ident);
    try testing.expectEqualStrings("b", iter.next().?.ident);
    try testing.expectEqual(Segment.star, iter.next().?);
    try testing.expectEqualStrings("c", iter.next().?.index_string);
    try testing.expectEqual(@as(?Segment, null), iter.next());
}
