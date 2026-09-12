//! Single source of truth for EXPR002 (context names), EXPR003 (properties)
//! and EXPR004/EXPR005 (function names and arity).
//! See `docs/adr/0009-expr-static-typecheck.md` (D2, D3).

const std = @import("std");
const t = @import("expr_type.zig");

const Type = t.Type;
const TypeRef = t.TypeRef;
const Prop = t.Prop;

const any = &t.type_any;
const string = &t.type_string;
const number = &t.type_number;
const boolean = &t.type_bool;

/// A curated scalar overlay for `github.event` (#124).
///
/// `github.event` stays a **loose** object (ADR D3): no per-event payload
/// schema is shipped, and every key outside this table — at any depth —
/// resolves to `any`. The overlay only widens what EXPR017 can see; nothing
/// below `github.event` ever produces an EXPR003, which `expr_check.walkPath`
/// enforces for the whole subtree rather than leaving it to this table.
///
/// A path is admitted only when all three hold, so the selection is
/// reproducible instead of a matter of taste (ADR D3, rejected alternative):
///
/// 1. it appears in the documented webhook payload of every event that
///    delivers its top-level key,
/// 2. its JSON type is the same across all of those events, and
/// 3. workflows in the wild compare it in `if:` conditions.
///
/// Anything whose type varies per event (`github.event.inputs`, the
/// `client_payload` of `repository_dispatch`, `deployment.payload`) is left
/// out and stays `any`.
const event_ref: Type = .{
    .kind = .object,
    .shape = .loose,
    .props = &.{
        .{ .name = "ref", .ty = string },
        .{ .name = "sha", .ty = string },
    },
};

const event_issue: Type = .{
    .kind = .object,
    .shape = .loose,
    .props = &.{
        .{ .name = "body", .ty = string },
        .{ .name = "number", .ty = number },
        .{ .name = "state", .ty = string },
        .{ .name = "title", .ty = string },
    },
};

const event_pull_request: Type = .{
    .kind = .object,
    .shape = .loose,
    .props = &.{
        .{ .name = "base", .ty = &event_ref },
        .{ .name = "body", .ty = string },
        .{ .name = "draft", .ty = boolean },
        .{ .name = "head", .ty = &event_ref },
        .{ .name = "number", .ty = number },
        .{ .name = "state", .ty = string },
        .{ .name = "title", .ty = string },
    },
};

const event_comment: Type = .{
    .kind = .object,
    .shape = .loose,
    .props = &.{
        .{ .name = "body", .ty = string },
        .{ .name = "id", .ty = number },
    },
};

const event_review: Type = .{
    .kind = .object,
    .shape = .loose,
    .props = &.{
        .{ .name = "body", .ty = string },
        .{ .name = "state", .ty = string },
    },
};

const event_repository: Type = .{
    .kind = .object,
    .shape = .loose,
    .props = &.{
        .{ .name = "default_branch", .ty = string },
        .{ .name = "full_name", .ty = string },
        .{ .name = "name", .ty = string },
        .{ .name = "private", .ty = boolean },
    },
};

const event_sender: Type = .{
    .kind = .object,
    .shape = .loose,
    .props = &.{
        .{ .name = "login", .ty = string },
        .{ .name = "type", .ty = string },
    },
};

const event_workflow_run: Type = .{
    .kind = .object,
    .shape = .loose,
    .props = &.{
        .{ .name = "conclusion", .ty = string },
        .{ .name = "event", .ty = string },
        .{ .name = "head_branch", .ty = string },
        .{ .name = "head_sha", .ty = string },
        .{ .name = "id", .ty = number },
    },
};

pub const github_event: Type = .{
    .kind = .object,
    .shape = .loose,
    .props = &.{
        .{ .name = "action", .ty = string },
        .{ .name = "after", .ty = string },
        .{ .name = "before", .ty = string },
        .{ .name = "comment", .ty = &event_comment },
        .{ .name = "issue", .ty = &event_issue },
        .{ .name = "number", .ty = number },
        .{ .name = "pull_request", .ty = &event_pull_request },
        .{ .name = "ref", .ty = string },
        .{ .name = "repository", .ty = &event_repository },
        .{ .name = "review", .ty = &event_review },
        .{ .name = "sender", .ty = &event_sender },
        .{ .name = "workflow_run", .ty = &event_workflow_run },
    },
};

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
        .{ .name = "workflow_file_path", .ty = string },
        .{ .name = "workflow_ref", .ty = string },
        .{ .name = "workflow_repository", .ty = string },
        .{ .name = "workflow_sha", .ty = string },
    },
};

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

/// The fallback for a context whose keys the workflow file decides. `steps` /
/// `matrix` / `needs` / `inputs` get a strict overlay from `expr_overlay` when
/// the workflow declares one, and land here when it does not; `jobs` (reusable
/// workflow outputs) has no overlay at all. Strictness here would be a false
/// positive.
pub const unknown_context: Type = .{ .kind = .object, .shape = .unknown };

const ContextEntry = struct { name: []const u8, ty: TypeRef };

/// Sorted by name.
const contexts = [_]ContextEntry{
    .{ .name = "env", .ty = &t.type_map_string },
    .{ .name = "github", .ty = &github },
    .{ .name = "inputs", .ty = &unknown_context },
    .{ .name = "job", .ty = &job },
    .{ .name = "jobs", .ty = &unknown_context },
    .{ .name = "matrix", .ty = &unknown_context },
    .{ .name = "needs", .ty = &unknown_context },
    .{ .name = "runner", .ty = &runner },
    .{ .name = "secrets", .ty = &t.type_map_string },
    .{ .name = "steps", .ty = &unknown_context },
    .{ .name = "strategy", .ty = &strategy },
    .{ .name = "vars", .ty = &t.type_map_string },
};

pub fn lookupContext(name: []const u8) ?TypeRef {
    const ctx = t.findByName(ContextEntry, &contexts, name) orelse return null;
    return ctx.ty;
}

/// The canonical spelling of a known context, whatever ASCII casing the
/// workflow wrote it in — context names are case-insensitive on GitHub.
/// Returns null for a name no context has (EXPR002's finding).
pub fn contextName(name: []const u8) ?[]const u8 {
    const ctx = t.findByNameAsciiCaseInsensitive(ContextEntry, &contexts, name) orelse return null;
    return ctx.name;
}

/// What a parameter accepts. Deliberately coarse: GitHub coerces scalars for
/// every builtin, so only the containers a parameter can never take are
/// modelled and EXPR018 stays free of false positives (ADR D3, #162).
pub const ArgKind = enum {
    any,
    /// Rejects object and array.
    string,
    /// `contains` / `join` first parameter: rejects object.
    string_or_array,

    pub fn display(self: ArgKind) []const u8 {
        return switch (self) {
            .any => "any value",
            .string => "a string",
            .string_or_array => "a string or an array",
        };
    }
};

/// How `min_args` / `max_args` are interpreted. `case()` is pairs plus a
/// fallback, so the count must be odd and at least 3.
const ArgCountShape = enum {
    range,
    odd_at_least,
    exact,
};

/// One entry per function: every overload of a GitHub Actions function shares
/// a return type, so only the accepted argument count varies.
pub const FuncSig = struct {
    name: []const u8,
    min_args: u8,
    max_args: u8,
    ret: TypeRef,
    shape: ArgCountShape = .range,
    /// Types of the leading parameters, positionally.
    args: []const ArgKind = &.{},
    /// Type of every argument past `args`, for the variadic tail.
    rest: ArgKind = .any,

    pub fn argKind(self: *const FuncSig, index: usize) ArgKind {
        if (index < self.args.len) return self.args[index];
        return self.rest;
    }

    pub fn acceptsArgCount(self: *const FuncSig, count: usize) bool {
        if (count < self.min_args or count > self.max_args) return false;
        return switch (self.shape) {
            .range, .exact => true,
            .odd_at_least => count % 2 == 1,
        };
    }
};

/// Sorted by name. Lookup is ASCII case-insensitive, matching GitHub Actions
/// and actionlint (#161).
const functions = [_]FuncSig{
    .{ .name = "always", .min_args = 0, .max_args = 0, .ret = boolean },
    .{ .name = "cancelled", .min_args = 0, .max_args = 0, .ret = boolean },
    .{ .name = "case", .min_args = 3, .max_args = 255, .shape = .odd_at_least, .ret = any },
    .{ .name = "contains", .min_args = 2, .max_args = 2, .ret = boolean, .args = &.{.string_or_array} },
    .{ .name = "endsWith", .min_args = 2, .max_args = 2, .ret = boolean, .args = &.{ .string, .string } },
    .{ .name = "failure", .min_args = 0, .max_args = 0, .ret = boolean },
    .{ .name = "format", .min_args = 1, .max_args = 255, .ret = string, .args = &.{.string} },
    .{ .name = "fromJSON", .min_args = 1, .max_args = 1, .ret = any, .args = &.{.string} },
    .{ .name = "hashFiles", .min_args = 1, .max_args = 255, .ret = string, .rest = .string },
    .{ .name = "join", .min_args = 1, .max_args = 2, .ret = string, .args = &.{ .string_or_array, .string } },
    .{ .name = "startsWith", .min_args = 2, .max_args = 2, .ret = boolean, .args = &.{ .string, .string } },
    .{ .name = "success", .min_args = 0, .max_args = 0, .ret = boolean },
    .{ .name = "toJSON", .min_args = 1, .max_args = 1, .ret = string },
};

pub fn lookupFunction(name: []const u8) ?*const FuncSig {
    return t.findByNameAsciiCaseInsensitive(FuncSig, &functions, name);
}

/// True for a context that fell back to `unknown_context` because the workflow
/// declared nothing to overlay. Its `object` kind says "unknown", not "this is
/// an object", so EXPR018 must stay silent on it (ADR D3, #162).
pub fn isUnmodelledObject(ty: TypeRef) bool {
    return ty.kind == .object and ty.shape == .unknown;
}

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
    try std.testing.expect(isSorted(FuncSig, &functions));
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
    try std.testing.expectEqual(@as(?TypeRef, string), t.findProp(&github, "workflow_ref"));
    try std.testing.expectEqual(@as(?TypeRef, null), t.findProp(&github, "workflow_repository"));
    try std.testing.expectEqual(@as(?TypeRef, string), t.findProp(&job, "workflow_ref"));
    try std.testing.expectEqual(@as(?TypeRef, string), t.findProp(&job, "workflow_repository"));
}

test "catalog: github.event and every curated node stay loose" {
    try std.testing.expectEqual(t.ObjectShape.loose, github_event.shape);
    try expectLooseRecursive(&github_event);
}

fn expectLooseRecursive(ty: TypeRef) !void {
    try std.testing.expectEqual(t.ObjectShape.loose, ty.shape);
    for (ty.props) |p| {
        if (p.ty.kind == .object) try expectLooseRecursive(p.ty);
    }
}

test "catalog: lookupFunction is case-insensitive" {
    try std.testing.expect(lookupFunction("contains") != null);
    try std.testing.expect(lookupFunction("Contains") != null);
    try std.testing.expect(lookupFunction("TOJSON") != null);
    try std.testing.expectEqual(@as(?*const FuncSig, null), lookupFunction("unknownFunc"));
}

test "catalog: arity of overloaded join" {
    const sig = lookupFunction("join").?;
    try std.testing.expectEqual(@as(u8, 1), sig.min_args);
    try std.testing.expectEqual(@as(u8, 2), sig.max_args);
}

test "catalog: case() accepts an odd count of at least 3" {
    const sig = lookupFunction("case").?;
    try std.testing.expectEqual(ArgCountShape.odd_at_least, sig.shape);
    try std.testing.expect(!sig.acceptsArgCount(2));
    try std.testing.expect(sig.acceptsArgCount(3));
    try std.testing.expect(!sig.acceptsArgCount(4));
    try std.testing.expect(sig.acceptsArgCount(5));
    try std.testing.expect(!sig.acceptsArgCount(6));
    try std.testing.expect(sig.acceptsArgCount(7));
}

test "catalog: argKind covers fixed and variadic parameters" {
    const fmt = lookupFunction("format").?;
    try std.testing.expectEqual(ArgKind.string, fmt.argKind(0));
    try std.testing.expectEqual(ArgKind.any, fmt.argKind(1));
    try std.testing.expectEqual(ArgKind.any, fmt.argKind(9));

    const hash = lookupFunction("hashFiles").?;
    try std.testing.expectEqual(ArgKind.string, hash.argKind(0));
    try std.testing.expectEqual(ArgKind.string, hash.argKind(3));

    const cont = lookupFunction("contains").?;
    try std.testing.expectEqual(ArgKind.string_or_array, cont.argKind(0));
    try std.testing.expectEqual(ArgKind.any, cont.argKind(1));

    // A function with no declared parameters takes anything.
    try std.testing.expectEqual(ArgKind.any, lookupFunction("toJSON").?.argKind(0));
}

test "catalog: isUnmodelledObject singles out the overlay fallback" {
    try std.testing.expect(isUnmodelledObject(lookupContext("jobs").?));
    try std.testing.expect(!isUnmodelledObject(&github_event));
    try std.testing.expect(!isUnmodelledObject(&t.type_loose_object));
}

test "catalog: workflow-defined contexts stay unknown without an overlay" {
    for ([_][]const u8{ "steps", "matrix", "needs", "inputs", "jobs" }) |name| {
        const ty = lookupContext(name).?;
        try std.testing.expectEqual(t.ObjectShape.unknown, ty.shape);
    }
}

test "catalog: env vars secrets are string maps" {
    for ([_][]const u8{ "env", "vars", "secrets" }) |name| {
        const ty = lookupContext(name).?;
        try std.testing.expectEqual(t.ObjectShape.map, ty.shape);
        try std.testing.expectEqual(@as(?TypeRef, string), ty.elem);
    }
}
