//! Interned catalog of builtin contexts and function signatures.
//!
//! Single source of truth for EXPR002 (context names), EXPR003 (properties)
//! and EXPR004/EXPR005 (function names and arity).
//! See `docs/adr/0006-expr-static-typecheck.md` (D2, D3).

const std = @import("std");
const t = @import("expr_type.zig");

const Type = t.Type;
const TypeRef = t.TypeRef;
const Prop = t.Prop;

const any = &t.type_any;
const string = &t.type_string;
const number = &t.type_number;
const boolean = &t.type_bool;

// --- github ---

/// `github.event` is a loose object on purpose: no per-event payload schema
/// is shipped (ADR D3). Unknown keys resolve to `any` and never warn.
pub const github_event: Type = .{ .kind = .object, .shape = .loose };

/// Properties sorted by byte order; lookup is a binary search.
pub const github: Type = .{
    .kind = .object,
    .shape = .strict,
    .props = &.{
        .{ .name = "action", .ty = string },
        .{ .name = "action_path", .ty = string },
        .{ .name = "action_ref", .ty = string },
        .{ .name = "action_repository", .ty = string },
        .{ .name = "action_status", .ty = string },
        .{ .name = "actor", .ty = string },
        .{ .name = "actor_id", .ty = string },
        .{ .name = "api_url", .ty = string },
        .{ .name = "artifact_cache_size_limit", .ty = number },
        .{ .name = "base_ref", .ty = string },
        .{ .name = "env", .ty = string },
        .{ .name = "event", .ty = &github_event },
        .{ .name = "event_name", .ty = string },
        .{ .name = "event_path", .ty = string },
        .{ .name = "graphql_url", .ty = string },
        .{ .name = "head_ref", .ty = string },
        .{ .name = "job", .ty = string },
        .{ .name = "output", .ty = string },
        .{ .name = "path", .ty = string },
        .{ .name = "ref", .ty = string },
        .{ .name = "ref_name", .ty = string },
        .{ .name = "ref_protected", .ty = boolean },
        .{ .name = "ref_type", .ty = string },
        .{ .name = "repository", .ty = string },
        // Both spellings are kept so neither form produces a false positive.
        .{ .name = "repositoryUrl", .ty = string },
        .{ .name = "repository_id", .ty = string },
        .{ .name = "repository_owner", .ty = string },
        .{ .name = "repository_owner_id", .ty = string },
        .{ .name = "repository_visibility", .ty = string },
        .{ .name = "repositoryurl", .ty = string },
        .{ .name = "retention_days", .ty = number },
        .{ .name = "run_attempt", .ty = string },
        .{ .name = "run_id", .ty = string },
        .{ .name = "run_number", .ty = string },
        .{ .name = "secret_source", .ty = string },
        .{ .name = "server_url", .ty = string },
        .{ .name = "sha", .ty = string },
        .{ .name = "state", .ty = string },
        .{ .name = "step_summary", .ty = string },
        .{ .name = "token", .ty = string },
        .{ .name = "triggering_actor", .ty = string },
        .{ .name = "workflow", .ty = string },
        .{ .name = "workflow_ref", .ty = string },
        .{ .name = "workflow_sha", .ty = string },
        .{ .name = "workspace", .ty = string },
    },
};

// --- runner ---

pub const runner: Type = .{
    .kind = .object,
    .shape = .strict,
    .props = &.{
        .{ .name = "arch", .ty = string },
        .{ .name = "debug", .ty = string },
        .{ .name = "environment", .ty = string },
        .{ .name = "name", .ty = string },
        .{ .name = "os", .ty = string },
        .{ .name = "temp", .ty = string },
        .{ .name = "tool_cache", .ty = string },
    },
};

// --- job ---

const job_container: Type = .{
    .kind = .object,
    .shape = .strict,
    .props = &.{
        .{ .name = "id", .ty = string },
        .{ .name = "network", .ty = string },
    },
};

const job_service: Type = .{
    .kind = .object,
    .shape = .strict,
    .props = &.{
        .{ .name = "id", .ty = string },
        .{ .name = "network", .ty = string },
        .{ .name = "ports", .ty = &t.type_map_string },
    },
};

const job_services: Type = .{ .kind = .object, .shape = .map, .elem = &job_service };

pub const job: Type = .{
    .kind = .object,
    .shape = .strict,
    .props = &.{
        .{ .name = "check_run_id", .ty = number },
        .{ .name = "container", .ty = &job_container },
        .{ .name = "services", .ty = &job_services },
        .{ .name = "status", .ty = string },
    },
};

// --- strategy ---

/// Loose on purpose: actionlint keeps unknown strategy keys as `any`.
pub const strategy: Type = .{
    .kind = .object,
    .shape = .loose,
    .props = &.{
        .{ .name = "fail-fast", .ty = boolean },
        .{ .name = "job-index", .ty = number },
        .{ .name = "job-total", .ty = number },
        .{ .name = "max-parallel", .ty = number },
    },
};

// --- contexts awaiting a workflow overlay (T4) ---

/// `steps` / `matrix` / `needs` / `inputs` / `jobs` stay loose until the
/// contextual overlay is wired in; strictness before then would be a
/// false positive.
pub const loose_context: Type = .{ .kind = .object, .shape = .loose };

const ContextEntry = struct { name: []const u8, ty: TypeRef };

/// Sorted by name.
const contexts = [_]ContextEntry{
    .{ .name = "env", .ty = &t.type_map_string },
    .{ .name = "github", .ty = &github },
    .{ .name = "inputs", .ty = &loose_context },
    .{ .name = "job", .ty = &job },
    .{ .name = "jobs", .ty = &loose_context },
    .{ .name = "matrix", .ty = &loose_context },
    .{ .name = "needs", .ty = &loose_context },
    .{ .name = "runner", .ty = &runner },
    .{ .name = "secrets", .ty = &t.type_map_string },
    .{ .name = "steps", .ty = &loose_context },
    .{ .name = "strategy", .ty = &strategy },
    .{ .name = "vars", .ty = &t.type_map_string },
};

/// Returns null for an unknown context name (EXPR002).
pub fn lookupContext(name: []const u8) ?TypeRef {
    var lo: usize = 0;
    var hi: usize = contexts.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, contexts[mid].name, name)) {
            .lt => lo = mid + 1,
            .gt => hi = mid,
            .eq => return contexts[mid].ty,
        }
    }
    return null;
}

// ============================================================
// Function signatures
// ============================================================

pub const FuncSig = struct {
    min_args: u8,
    max_args: u8,
    /// Parameter types, checked from the front. Argument type mismatches are
    /// not diagnosed in V1 (ADR D4); the table exists for overload selection.
    params: []const TypeRef = &.{},
    ret: TypeRef,
    /// The last parameter type repeats for the remaining arguments.
    variadic: bool = false,
};

pub const FuncOverloads = struct {
    name: []const u8,
    sigs: []const FuncSig,
};

const no_args = [_]TypeRef{};

/// Sorted by name. Lookup is case-sensitive, matching the current EXPR004
/// behaviour (actionlint is case-insensitive; changing that is a separate
/// compatibility decision).
const functions = [_]FuncOverloads{
    .{ .name = "always", .sigs = &.{.{ .min_args = 0, .max_args = 0, .params = &no_args, .ret = boolean }} },
    .{ .name = "cancelled", .sigs = &.{.{ .min_args = 0, .max_args = 0, .params = &no_args, .ret = boolean }} },
    .{ .name = "case", .sigs = &.{.{
        .min_args = 3,
        .max_args = 255,
        .params = &.{ boolean, any, any },
        .ret = any,
        .variadic = true,
    }} },
    .{ .name = "contains", .sigs = &.{
        .{ .min_args = 2, .max_args = 2, .params = &.{ string, string }, .ret = boolean },
        .{ .min_args = 2, .max_args = 2, .params = &.{ &t.type_array_any, any }, .ret = boolean },
    } },
    .{ .name = "endsWith", .sigs = &.{.{ .min_args = 2, .max_args = 2, .params = &.{ string, string }, .ret = boolean }} },
    .{ .name = "failure", .sigs = &.{.{ .min_args = 0, .max_args = 0, .params = &no_args, .ret = boolean }} },
    .{ .name = "format", .sigs = &.{.{
        .min_args = 1,
        .max_args = 255,
        .params = &.{ string, any },
        .ret = string,
        .variadic = true,
    }} },
    .{ .name = "fromJSON", .sigs = &.{.{ .min_args = 1, .max_args = 1, .params = &.{string}, .ret = any }} },
    .{ .name = "hashFiles", .sigs = &.{.{
        .min_args = 1,
        .max_args = 255,
        .params = &.{string},
        .ret = string,
        .variadic = true,
    }} },
    .{ .name = "join", .sigs = &.{
        .{ .min_args = 1, .max_args = 1, .params = &.{&t.type_array_any}, .ret = string },
        .{ .min_args = 2, .max_args = 2, .params = &.{ &t.type_array_any, string }, .ret = string },
    } },
    .{ .name = "startsWith", .sigs = &.{.{ .min_args = 2, .max_args = 2, .params = &.{ string, string }, .ret = boolean }} },
    .{ .name = "success", .sigs = &.{.{ .min_args = 0, .max_args = 0, .params = &no_args, .ret = boolean }} },
    .{ .name = "toJSON", .sigs = &.{.{ .min_args = 1, .max_args = 1, .params = &.{any}, .ret = string }} },
};

/// Returns null for an unknown function name (EXPR004).
pub fn lookupFunction(name: []const u8) ?[]const FuncSig {
    var lo: usize = 0;
    var hi: usize = functions.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, functions[mid].name, name)) {
            .lt => lo = mid + 1,
            .gt => hi = mid,
            .eq => return functions[mid].sigs,
        }
    }
    return null;
}

/// Accepted argument count across every overload of `name`.
pub fn arityOf(sigs: []const FuncSig) struct { min: u8, max: u8 } {
    var min: u8 = 255;
    var max: u8 = 0;
    for (sigs) |sig| {
        if (sig.min_args < min) min = sig.min_args;
        if (sig.max_args > max) max = sig.max_args;
    }
    return .{ .min = min, .max = max };
}

// ============================================================
// Tests
// ============================================================

fn isSorted(comptime T: type, items: []const T) bool {
    var i: usize = 1;
    while (i < items.len) : (i += 1) {
        if (std.mem.order(u8, items[i - 1].name, items[i].name) != .lt) return false;
    }
    return true;
}

fn propsSorted(ty: TypeRef) bool {
    if (!isSorted(Prop, ty.props)) return false;
    for (ty.props) |p| {
        if (p.ty.kind == .object and !propsSorted(p.ty)) return false;
    }
    return true;
}

test "catalog: context table is sorted" {
    try std.testing.expect(isSorted(ContextEntry, &contexts));
}

test "catalog: function table is sorted" {
    try std.testing.expect(isSorted(FuncOverloads, &functions));
}

test "catalog: object props are sorted for binary search" {
    try std.testing.expect(propsSorted(&github));
    try std.testing.expect(propsSorted(&runner));
    try std.testing.expect(propsSorted(&job));
    try std.testing.expect(propsSorted(&strategy));
}

test "catalog: lookupContext finds every context" {
    for (contexts) |entry| {
        try std.testing.expect(lookupContext(entry.name) != null);
    }
    try std.testing.expectEqual(@as(?TypeRef, null), lookupContext("foo"));
    try std.testing.expectEqual(@as(?TypeRef, null), lookupContext("Github"));
}

test "catalog: github property types" {
    try std.testing.expectEqual(@as(?TypeRef, string), t.findProp(&github, "sha"));
    try std.testing.expectEqual(@as(?TypeRef, boolean), t.findProp(&github, "ref_protected"));
    try std.testing.expectEqual(@as(?TypeRef, number), t.findProp(&github, "retention_days"));
    try std.testing.expectEqual(@as(?TypeRef, &github_event), t.findProp(&github, "event"));
    try std.testing.expectEqual(@as(?TypeRef, null), t.findProp(&github, "reposiory"));
}

test "catalog: github.event is loose" {
    try std.testing.expectEqual(t.ObjectShape.loose, github_event.shape);
    try std.testing.expectEqual(@as(usize, 0), github_event.props.len);
}

test "catalog: lookupFunction is case-sensitive" {
    try std.testing.expect(lookupFunction("contains") != null);
    try std.testing.expectEqual(@as(?[]const FuncSig, null), lookupFunction("Contains"));
}

test "catalog: arity of overloaded join" {
    const sigs = lookupFunction("join").?;
    const arity = arityOf(sigs);
    try std.testing.expectEqual(@as(u8, 1), arity.min);
    try std.testing.expectEqual(@as(u8, 2), arity.max);
}

test "catalog: contexts awaiting overlay stay loose" {
    for ([_][]const u8{ "steps", "matrix", "needs", "inputs", "jobs" }) |name| {
        const ty = lookupContext(name).?;
        try std.testing.expectEqual(t.ObjectShape.loose, ty.shape);
    }
}

test "catalog: env vars secrets are string maps" {
    for ([_][]const u8{ "env", "vars", "secrets" }) |name| {
        const ty = lookupContext(name).?;
        try std.testing.expectEqual(t.ObjectShape.map, ty.shape);
        try std.testing.expectEqual(@as(?TypeRef, string), ty.elem);
    }
}
