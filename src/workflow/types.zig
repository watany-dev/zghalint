const std = @import("std");
const yaml_types = @import("../yaml/types.zig");
const schema = @import("schema.zig");

pub const UnknownKey = schema.UnknownKey;

pub const EmptySection = struct {
    name: []const u8,
    span: yaml_types.Span,
};

pub const StringMap = std.StringArrayHashMap([]const u8);
pub const ScalarValueMetaMap = std.StringArrayHashMap(ScalarValueMeta);

/// A single key of an `env:` mapping, kept alongside `env` so that name
/// validation (SYN007) sees every key — including duplicates and keys whose
/// value is not a scalar, both of which `StringMap` drops — and can point the
/// diagnostic at the key token instead of its value.
pub const EnvKey = struct {
    name: []const u8,
    span: yaml_types.Span,
};

pub const ScalarValueMeta = struct {
    value_span: yaml_types.Span,
    style: yaml_types.ScalarStyle,
};

pub const PermissionLevel = enum {
    read,
    write,
    none,
};

pub const Permissions = struct {
    actions: ?PermissionLevel = null,
    artifact_metadata: ?PermissionLevel = null,
    attestations: ?PermissionLevel = null,
    checks: ?PermissionLevel = null,
    contents: ?PermissionLevel = null,
    deployments: ?PermissionLevel = null,
    discussions: ?PermissionLevel = null,
    id_token: ?PermissionLevel = null,
    issues: ?PermissionLevel = null,
    models: ?PermissionLevel = null,
    packages: ?PermissionLevel = null,
    pages: ?PermissionLevel = null,
    pull_requests: ?PermissionLevel = null,
    repository_projects: ?PermissionLevel = null,
    security_events: ?PermissionLevel = null,
    statuses: ?PermissionLevel = null,
    read_all: bool = false,
    write_all: bool = false,
    /// Span of the permissions value in the YAML source (for autofix)
    value_span: ?yaml_types.Span = null,
};

/// Per-field value spans for `Permissions` mapping entries. Populated only
/// when `permissions:` is given as a mapping (not `read-all`/`write-all`).
/// Used by PERM001 autofix to target the value of a specific scope key.
pub const PermissionsMeta = struct {
    actions: ?yaml_types.Span = null,
    artifact_metadata: ?yaml_types.Span = null,
    attestations: ?yaml_types.Span = null,
    checks: ?yaml_types.Span = null,
    contents: ?yaml_types.Span = null,
    deployments: ?yaml_types.Span = null,
    discussions: ?yaml_types.Span = null,
    id_token: ?yaml_types.Span = null,
    issues: ?yaml_types.Span = null,
    models: ?yaml_types.Span = null,
    packages: ?yaml_types.Span = null,
    pages: ?yaml_types.Span = null,
    pull_requests: ?yaml_types.Span = null,
    repository_projects: ?yaml_types.Span = null,
    security_events: ?yaml_types.Span = null,
    statuses: ?yaml_types.Span = null,
};

/// The `permissions:` scope keys, in schema order. `Permissions` and
/// `PermissionsMeta` declare exactly these, so `PermissionsMeta` doubles as the
/// key list for anything that walks the scopes.
pub const permission_scopes = std.meta.fieldNames(PermissionsMeta);

/// Field names use `_` where the YAML key uses `-`.
pub fn permissionScopeKey(comptime field_name: []const u8) []const u8 {
    comptime {
        var buf: [field_name.len]u8 = field_name[0..field_name.len].*;
        for (&buf) |*c| {
            if (c.* == '_') c.* = '-';
        }
        const key = buf;
        return &key;
    }
}

/// `permission_scopes` spelled as YAML keys, for the runtime lookups
/// `permissionScopeKey`'s comptime signature cannot serve (PERM003).
pub const permission_scope_keys: []const []const u8 = blk: {
    var keys: [permission_scopes.len][]const u8 = undefined;
    for (permission_scopes, 0..) |field, i| keys[i] = permissionScopeKey(field);
    const frozen = keys;
    break :blk &frozen;
};

pub const PermissionProblemKind = enum {
    unknown_scope,
    invalid_level,
    /// `permissions:` given as a scalar other than `read-all` / `write-all`.
    invalid_all,
};

/// A `permissions:` entry the parser could not map onto `Permissions` (PERM003).
/// `text` is the offending token as written: the key for `unknown_scope`, the
/// value for `invalid_level` and `invalid_all`, and empty when that value was
/// missing or not a scalar. `scope` names the key a bad value belongs to and is
/// empty for the other kinds.
pub const PermissionProblem = struct {
    kind: PermissionProblemKind,
    text: []const u8,
    scope: []const u8 = "",
    span: yaml_types.Span,
};

pub const Concurrency = struct {
    group: []const u8,
};

/// `defaults:` at workflow or job level. Only `run.shell` is modelled, since
/// that is all any rule needs so far; the whole struct is absent unless that
/// key is present with a scalar value.
pub const Defaults = struct {
    run_shell: []const u8,
    run_shell_span: yaml_types.Span = yaml_types.Span.point(0, 0, 0),
};

/// Key spans for the mutually exclusive `EventFilter` entries. A non-null
/// field means the key appeared in the source, which the value arrays alone
/// cannot express (`branches: []` yields an empty array but is still present).
pub const EventFilterSpans = struct {
    branches: ?yaml_types.Span = null,
    branches_ignore: ?yaml_types.Span = null,
    tags: ?yaml_types.Span = null,
    tags_ignore: ?yaml_types.Span = null,
    paths: ?yaml_types.Span = null,
    paths_ignore: ?yaml_types.Span = null,
};

pub const FilterPatternList = struct {
    values: []const []const u8 = &.{},
    spans: []const yaml_types.Span = &.{},
};

pub const EventFilter = struct {
    branches: FilterPatternList = .{},
    branches_ignore: FilterPatternList = .{},
    tags: FilterPatternList = .{},
    tags_ignore: FilterPatternList = .{},
    paths: FilterPatternList = .{},
    paths_ignore: FilterPatternList = .{},
    spans: EventFilterSpans = .{},
};

/// One key written under an event mapping, in source order. SYN011 checks the
/// names the `EventFilter` struct does not model, so it needs the raw list.
pub const EventConfigKey = struct {
    name: []const u8,
    span: yaml_types.Span,
};

pub const ScheduleEntry = struct {
    cron: []const u8,
    cron_span: yaml_types.Span,
};

pub const CallableInputType = enum {
    string,
    number,
    boolean,
};

pub const InputDef = struct {
    name: []const u8,
    name_span: yaml_types.Span,
    input_type: ?CallableInputType = null,
    type_span: ?yaml_types.Span = null,
    required: ?bool = null,
    default_value: ?[]const u8 = null,
    default_span: ?yaml_types.Span = null,
};

pub const WorkflowCallInputProblemKind = enum {
    missing_type,
    invalid_type,
    default_type_mismatch,
    required_with_default,
};

pub const WorkflowCallInputProblem = struct {
    kind: WorkflowCallInputProblemKind,
    input_name: []const u8,
    /// Invalid type name, or declared type name for `default_type_mismatch`.
    detail: []const u8,
    span: yaml_types.Span,
};

pub const EventType = enum {
    push,
    pull_request,
    pull_request_target,
    schedule,
    workflow_dispatch,
    workflow_call,
    release,
    issues,
    issue_comment,
    discussion,
    discussion_comment,
    create,
    delete,
    fork,
    watch,
    repository_dispatch,
    workflow_run,
    other,

    pub fn fromString(s: []const u8) EventType {
        const map = std.StaticStringMap(EventType).initComptime(.{
            .{ "push", .push },
            .{ "pull_request", .pull_request },
            .{ "pull_request_target", .pull_request_target },
            .{ "schedule", .schedule },
            .{ "workflow_dispatch", .workflow_dispatch },
            .{ "workflow_call", .workflow_call },
            .{ "release", .release },
            .{ "issues", .issues },
            .{ "issue_comment", .issue_comment },
            .{ "discussion", .discussion },
            .{ "discussion_comment", .discussion_comment },
            .{ "create", .create },
            .{ "delete", .delete },
            .{ "fork", .fork },
            .{ "watch", .watch },
            .{ "repository_dispatch", .repository_dispatch },
            .{ "workflow_run", .workflow_run },
        });
        return map.get(s) orelse .other;
    }
};

pub const EventConfig = struct {
    event: EventType,
    /// The trigger name as written, and the span of that token. `EventType`
    /// collapses every unrecognized name into `.other`, so SYN009 needs the
    /// source text to validate it and the span to point at it.
    name: []const u8 = "",
    name_span: yaml_types.Span = yaml_types.Span.point(0, 0, 0),
    filter: ?EventFilter = null,
    /// `types:` values as written, with a span each. SYN010 validates them
    /// against the event's entry in the trigger table.
    activity_types: FilterPatternList = .{},
    /// Span of the `types:` key itself, so SYN010 can point at it for an event
    /// that has no activity types at all.
    types_key_span: ?yaml_types.Span = null,
    config_keys: []const EventConfigKey = &.{},
    schedules: []const ScheduleEntry = &.{},
    workflow_call_inputs: []const InputDef = &.{},
    workflow_call_input_problems: []const WorkflowCallInputProblem = &.{},
};

pub const Trigger = struct {
    events: []const EventConfig,
};

pub const ActionRef = struct {
    raw: []const u8,
    owner: ?[]const u8 = null,
    repo: ?[]const u8 = null,
    path: ?[]const u8 = null,
    ref: ?[]const u8 = null,
    is_local: bool = false,
    is_docker: bool = false,
    is_pinned: bool = false,

    pub fn parse(raw: []const u8) ActionRef {
        if (raw.len >= 2 and raw[0] == '.' and (raw[1] == '/' or (raw.len >= 3 and raw[1] == '.' and raw[2] == '/'))) {
            return .{ .raw = raw, .is_local = true, .path = raw };
        }

        if (std.mem.startsWith(u8, raw, "docker://")) {
            return .{ .raw = raw, .is_docker = true };
        }

        var result = ActionRef{ .raw = raw };
        var remaining = raw;

        if (std.mem.indexOf(u8, remaining, "@")) |at_idx| {
            result.ref = remaining[at_idx + 1 ..];
            remaining = remaining[0..at_idx];

            if (result.ref) |ref| {
                result.is_pinned = isShaRef(ref);
            }
        }

        if (std.mem.indexOf(u8, remaining, "/")) |first_slash| {
            result.owner = remaining[0..first_slash];
            const after_owner = remaining[first_slash + 1 ..];

            if (std.mem.indexOf(u8, after_owner, "/")) |second_slash| {
                result.repo = after_owner[0..second_slash];
                result.path = after_owner[second_slash + 1 ..];
            } else {
                result.repo = after_owner;
            }
        }

        return result;
    }

    fn isShaRef(ref: []const u8) bool {
        if (ref.len != 40) return false;
        for (ref) |c| {
            if (!std.ascii.isHex(c)) return false;
        }
        return true;
    }
};

pub const Strategy = struct {
    fail_fast: bool = true,
    fail_fast_value_span: ?yaml_types.Span = null,
    fail_fast_entry_span: ?yaml_types.Span = null,
};

pub const Step = struct {
    id: ?[]const u8 = null,
    /// Span of the `id:` scalar value (for SYN005/SYN006 diagnostics).
    id_value_span: ?yaml_types.Span = null,
    name: ?[]const u8 = null,
    uses: ?ActionRef = null,
    run: ?[]const u8 = null,
    shell: ?[]const u8 = null,
    /// Span of the `shell:` scalar value (for BP004 diagnostics).
    shell_value_span: ?yaml_types.Span = null,
    with: ?StringMap = null,
    /// Value spans and styles of the `with:` entries (for diagnostics that
    /// scan a `with:` value, e.g. SEC003/SEC005/SEC011).
    with_meta: ?ScalarValueMetaMap = null,
    env: ?StringMap = null,
    env_meta: ?ScalarValueMetaMap = null,
    /// Keys of the `env:` mapping in source order (for SYN007).
    env_keys: []const EnvKey = &.{},
    empty_sections: []const EmptySection = &.{},
    if_condition: ?[]const u8 = null,
    /// Value span and scalar style of the `if:` scalar (for EXPR006 autofix).
    if_condition_meta: ?ScalarValueMeta = null,
    /// Span of the step mapping in source YAML (for autofix anchor).
    span: yaml_types.Span = yaml_types.Span.point(0, 0, 0),
    /// Column of the `uses:` key in source YAML (for autofix indentation).
    uses_key_col: ?u32 = null,
    /// Start byte of the `uses:` key token in source YAML (insertion point for `name:`).
    uses_key_start_byte: ?usize = null,
    /// End byte of the `uses:` value in source YAML (insertion point when no `with:` exists).
    uses_value_end_byte: ?usize = null,
    /// Scalar style of the `uses:` value (for autofix replacement quoting).
    uses_value_style: ?yaml_types.ScalarStyle = null,
    /// End byte of the last entry's value in the `with:` mapping (insertion point for new entries).
    with_last_entry_end_byte: ?usize = null,
    /// Span and style of the `run:` scalar. The style is needed to map an
    /// offset inside `run` back to a source line/column (block scalars start
    /// one line below their `|` / `>` indicator).
    run_meta: ?ScalarValueMeta = null,
    /// Span of the `uses:` scalar value (for SEC001 and the SC00x family).
    uses_value_span: ?yaml_types.Span = null,
    /// Byte position at the start of the next line after `run:` (insertion point for `shell:`).
    shell_insertion_byte: ?usize = null,
};

pub const SecretsConfig = union(enum) {
    inherit,
    map: StringMap,
};

pub const Credentials = struct {
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
};

pub const Container = struct {
    image: ?[]const u8 = null,
    credentials: ?Credentials = null,
    /// Keys of the `env:` mapping in source order (for SYN007).
    env_keys: []const EnvKey = &.{},
};

pub const Service = struct {
    name: []const u8,
    image: ?[]const u8 = null,
    credentials: ?Credentials = null,
    /// Keys of the `env:` mapping in source order (for SYN007).
    env_keys: []const EnvKey = &.{},
};

pub const Job = struct {
    id: []const u8,
    /// Span of the job key in the top-level `jobs:` mapping (for SYN005/SYN006 diagnostics).
    id_span: ?yaml_types.Span = null,
    span: yaml_types.Span = yaml_types.Span.point(0, 0, 0),
    name: ?[]const u8 = null,
    runs_on: ?[]const u8 = null,
    needs: []const []const u8 = &.{},
    /// Value spans of `needs` entries, parallel to `needs`. Empty when absent.
    needs_spans: []const yaml_types.Span = &.{},
    permissions: ?Permissions = null,
    permissions_meta: ?PermissionsMeta = null,
    /// `permissions:` entries rejected during parsing (PERM003).
    permission_problems: []const PermissionProblem = &.{},
    steps: []const Step = &.{},
    env: ?StringMap = null,
    env_meta: ?ScalarValueMetaMap = null,
    /// Keys of the `env:` mapping in source order (for SYN007).
    env_keys: []const EnvKey = &.{},
    if_condition: ?[]const u8 = null,
    /// Value span and scalar style of the `if:` scalar (for EXPR006 autofix).
    if_condition_meta: ?ScalarValueMeta = null,
    timeout_minutes: ?u32 = null,
    /// True when `timeout-minutes` is present in YAML, even if the value is invalid.
    timeout_minutes_specified: bool = false,
    strategy: ?Strategy = null,
    concurrency: ?Concurrency = null,
    defaults: ?Defaults = null,
    container: ?Container = null,
    services: []const Service = &.{},
    empty_sections: []const EmptySection = &.{},
    /// Reusable workflow reference (mutually exclusive with steps)
    uses: ?[]const u8 = null,
    /// Span of the job-level `uses:` scalar value (for DEP003).
    uses_value_span: ?yaml_types.Span = null,
    with: ?StringMap = null,
    secrets: ?SecretsConfig = null,
    /// Column (1-based) at which this job's child keys are indented.
    job_indent: u32 = 0,
    /// Byte position to insert a new `permissions:` entry (after `runs-on:` line).
    permissions_insertion_byte: ?usize = null,
    concurrency_insertion_byte: ?usize = null,
    /// Span of the `runs-on:` scalar value (for RUNNER001 autofix).
    /// Null when `runs-on` is absent or given as a sequence.
    runs_on_value_span: ?yaml_types.Span = null,
};

pub const Workflow = struct {
    name: ?[]const u8 = null,
    on: Trigger,
    permissions: ?Permissions = null,
    permissions_meta: ?PermissionsMeta = null,
    /// `permissions:` entries rejected during parsing (PERM003).
    permission_problems: []const PermissionProblem = &.{},
    env: ?StringMap = null,
    env_meta: ?ScalarValueMetaMap = null,
    /// Keys of the `env:` mapping in source order (for SYN007).
    env_keys: []const EnvKey = &.{},
    concurrency: ?Concurrency = null,
    defaults: ?Defaults = null,
    jobs: []const Job,
    empty_sections: []const EmptySection = &.{},
    unknown_keys: []const schema.UnknownKey = &.{},
    /// Mapping value type mismatches collected during parsing (SYN004).
    type_mismatches: []const type_validation.TypeMismatch = &.{},
    /// Top-level keys are always at column 1.
    top_level_indent: u32 = 0,
    /// Byte position to insert a new top-level `permissions:` entry (after `on:` line).
    permissions_insertion_byte: ?usize = null,
    /// Byte position to insert a new top-level `concurrency:` entry (after `on:` line).
    concurrency_insertion_byte: ?usize = null,
    /// Original YAML root. SYN002 walks this for case-insensitive duplicate keys.
    yaml_root: ?yaml_types.Node = null,

    /// Many rules only apply to a single trigger, so they gate on this before
    /// walking the jobs.
    pub fn hasEvent(self: *const Workflow, ev: EventType) bool {
        for (self.on.events) |event| {
            if (event.event == ev) return true;
        }
        return false;
    }
};

const type_validation = @import("type_validation.zig");

test "EventType.fromString known events" {
    try std.testing.expectEqual(EventType.push, EventType.fromString("push"));
    try std.testing.expectEqual(EventType.pull_request, EventType.fromString("pull_request"));
    try std.testing.expectEqual(EventType.schedule, EventType.fromString("schedule"));
    try std.testing.expectEqual(EventType.workflow_dispatch, EventType.fromString("workflow_dispatch"));
    try std.testing.expectEqual(EventType.workflow_call, EventType.fromString("workflow_call"));
    try std.testing.expectEqual(EventType.release, EventType.fromString("release"));
    try std.testing.expectEqual(EventType.discussion, EventType.fromString("discussion"));
    try std.testing.expectEqual(EventType.discussion_comment, EventType.fromString("discussion_comment"));
}

test "EventType.fromString unknown event" {
    try std.testing.expectEqual(EventType.other, EventType.fromString("custom_event"));
    try std.testing.expectEqual(EventType.other, EventType.fromString(""));
}

test "ActionRef.parse standard action" {
    const ref = ActionRef.parse("actions/checkout@v4");
    try std.testing.expectEqualStrings("actions", ref.owner.?);
    try std.testing.expectEqualStrings("checkout", ref.repo.?);
    try std.testing.expectEqualStrings("v4", ref.ref.?);
    try std.testing.expect(ref.path == null);
    try std.testing.expect(!ref.is_local);
    try std.testing.expect(!ref.is_docker);
    try std.testing.expect(!ref.is_pinned);
}

test "ActionRef.parse pinned action" {
    const ref = ActionRef.parse("actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675");
    try std.testing.expectEqualStrings("actions", ref.owner.?);
    try std.testing.expectEqualStrings("checkout", ref.repo.?);
    try std.testing.expect(ref.is_pinned);
}

test "ActionRef.parse action with path" {
    const ref = ActionRef.parse("github/codeql-action/analyze@v3");
    try std.testing.expectEqualStrings("github", ref.owner.?);
    try std.testing.expectEqualStrings("codeql-action", ref.repo.?);
    try std.testing.expectEqualStrings("analyze", ref.path.?);
    try std.testing.expectEqualStrings("v3", ref.ref.?);
}

test "ActionRef.parse local action" {
    const ref = ActionRef.parse("./my-action");
    try std.testing.expect(ref.is_local);
    try std.testing.expectEqualStrings("./my-action", ref.path.?);
}

test "ActionRef.parse relative parent action" {
    const ref = ActionRef.parse("../other-action");
    try std.testing.expect(ref.is_local);
    try std.testing.expectEqualStrings("../other-action", ref.path.?);
}

test "ActionRef.parse docker action" {
    const ref = ActionRef.parse("docker://alpine:3.8");
    try std.testing.expect(ref.is_docker);
    try std.testing.expect(!ref.is_local);
}

test "ActionRef unpinned ref" {
    const ref = ActionRef.parse("actions/checkout@main");
    try std.testing.expect(!ref.is_pinned);
}

test "ActionRef SHA-like but wrong length" {
    const ref = ActionRef.parse("actions/checkout@abcdef1234");
    try std.testing.expect(!ref.is_pinned);
}
