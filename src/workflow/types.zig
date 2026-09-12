const std = @import("std");
const yaml_types = @import("../yaml/types.zig");
const schema = @import("schema.zig");

pub const UnknownKey = schema.UnknownKey;

pub const EmptySection = struct {
    name: []const u8,
    span: yaml_types.Span,
};

/// A section that is present but empty is still written in the file, so the
/// rules that insert a missing section must stay quiet rather than add a
/// second key of the same name (#364).
pub fn hasEmptySection(sections: []const EmptySection, name: []const u8) bool {
    for (sections) |section| {
        if (std.mem.eql(u8, section.name, name)) return true;
    }
    return false;
}

pub const StringMap = std.array_hash_map.String([]const u8);
pub const ScalarValueMetaMap = std.array_hash_map.String(ScalarValueMeta);

/// A single key of an `env:` mapping, kept alongside `env` so that name
/// validation (SYN007) sees every key — including duplicates and keys whose
/// value is not a scalar, both of which `StringMap` drops — and can point the
/// diagnostic at the key token instead of its value.
pub const EnvKey = struct {
    name: []const u8,
    span: yaml_types.Span,
};

/// A single key of a job-level `outputs:` mapping, kept so that EXPR012 can
/// verify `needs.<job>.outputs.<name>` references and point the diagnostic at
/// the declaring key.
pub const OutputKey = struct {
    name: []const u8,
    span: yaml_types.Span,
    /// The scalar the output is bound to, when it is one. SEC002 reads it to
    /// carry taint across the job boundary: an output bound to a tainted
    /// `steps.<id>.outputs.*` makes `needs.<job>.outputs.<name>` untrusted.
    value: ?[]const u8 = null,
};

/// A single entry of a job-level `with:` / `secrets:` mapping on a reusable
/// workflow call. Kept alongside the value map so the RW rules see every entry —
/// including one whose value is not a scalar, which `StringMap` drops — and can
/// point a diagnostic at either token.
pub const CallArg = struct {
    name: []const u8,
    name_span: yaml_types.Span,
    /// Null when the value is not a scalar, which no RW rule can type-check.
    value: ?[]const u8 = null,
    value_span: ?yaml_types.Span = null,
};

pub const ScalarValueMeta = struct {
    value_span: yaml_types.Span,
    style: yaml_types.ScalarStyle,
    /// Span of the key this value hangs off, when the entry came from a
    /// mapping. Only set where a rule renames the key itself (DEP004/DEP005);
    /// a scalar with no mapping entry of its own leaves it null.
    key_span: ?yaml_types.Span = null,
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
    vulnerability_alerts: ?PermissionLevel = null,
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
    vulnerability_alerts: ?yaml_types.Span = null,
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

/// `vulnerability-alerts` accepts `read` / `none` only (2026-09-03).
pub fn isAllowedPermissionLevel(scope: []const u8, level: PermissionLevel) bool {
    if (std.mem.eql(u8, scope, "vulnerability-alerts")) return level != .write;
    return true;
}

/// `cache-mode:` at workflow or job level (2026-09-10). Job overrides workflow.
pub const cache_mode_values = [_][]const u8{ "none", "read", "write", "write-only" };

pub fn isCacheMode(value: []const u8) bool {
    return CacheCapability.fromMode(value) != null;
}

/// Restore/save abilities implied by `cache-mode`. This is a partial lattice,
/// not a linear scale: `read` restores, `write-only` saves, `write` does both,
/// `none` does neither.
pub const CacheCapability = struct {
    can_restore: bool,
    can_save: bool,

    pub const none: CacheCapability = .{ .can_restore = false, .can_save = false };
    pub const read: CacheCapability = .{ .can_restore = true, .can_save = false };
    pub const write: CacheCapability = .{ .can_restore = true, .can_save = true };
    pub const write_only: CacheCapability = .{ .can_restore = false, .can_save = true };
    pub const unrestricted: CacheCapability = write;

    pub fn fromMode(mode: []const u8) ?CacheCapability {
        if (std.mem.eql(u8, mode, "none")) return none;
        if (std.mem.eql(u8, mode, "read")) return read;
        if (std.mem.eql(u8, mode, "write")) return write;
        if (std.mem.eql(u8, mode, "write-only")) return write_only;
        return null;
    }

    pub fn allowsCache(self: CacheCapability) bool {
        return self.can_restore or self.can_save;
    }
};

/// Job `cache-mode` replaces the workflow value. Returns `null` for an
/// expression or unknown value so callers do not treat uncertainty as a
/// finding (ADR-0009). Omitted `cache-mode` is unrestricted by this key;
/// GitHub may still deny writes on low-trust events.
///
/// A reusable workflow cannot exceed the caller's grant at runtime; this
/// function only sees one file.
pub fn resolveCacheCapability(wf: *const Workflow, job: *const Job) ?CacheCapability {
    const raw = job.cache_mode orelse wf.cache_mode orelse return CacheCapability.unrestricted;
    return CacheCapability.fromMode(raw);
}

/// Unknown / expression modes stay permissive so SEC016 and PERF001 do not
/// guess a disable.
pub fn jobAllowsCache(wf: *const Workflow, job: *const Job) bool {
    const cap = resolveCacheCapability(wf, job) orelse return true;
    return cap.allowsCache();
}

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
    /// Value span and style of the `group` scalar, so an expression inside it
    /// can be reported where it appears (EXPR015/EXPR016).
    group_meta: ?ScalarValueMeta = null,
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
const EventFilterSpans = struct {
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
    /// Byte range that removes the whole entry, key line and value included
    /// (SYN011 autofix). Null when the parser cannot offer a stable range.
    full_span: ?yaml_types.Span = null,
};

pub const ScheduleEntry = struct {
    cron: []const u8,
    cron_span: yaml_types.Span,
    timezone: ?[]const u8 = null,
    timezone_span: ?yaml_types.Span = null,
};

pub const CallableInputType = enum {
    string,
    number,
    boolean,

    pub fn name(self: CallableInputType) []const u8 {
        return @tagName(self);
    }

    /// Whether a YAML scalar can carry a value of this type. Quoting is not
    /// consulted: `'3'` is accepted for `number`, the way the runner coerces
    /// the input rather than rejecting the call.
    pub fn matchesScalar(self: CallableInputType, value: []const u8) bool {
        return switch (self) {
            .string => true,
            .number => if (std.fmt.parseFloat(f64, value)) |_| true else |_| false,
            // YAML 1.2 core schema: only these six spellings resolve to a
            // bool. `yes` / `on` are YAML 1.1 and stay strings on GitHub.
            .boolean => for ([_][]const u8{ "true", "True", "TRUE", "false", "False", "FALSE" }) |lit| {
                if (std.mem.eql(u8, value, lit)) break true;
            } else false,
        };
    }

    /// The type a `default:` with no declared `type:` implies (RW001 autofix).
    /// Quoting decides here where `matchesScalar` ignores it: `default: true`
    /// is a boolean to the runner, `default: "true"` is the string `"true"`.
    pub fn inferFromScalar(value: []const u8, style: yaml_types.ScalarStyle) CallableInputType {
        switch (style) {
            .plain => {},
            else => return .string,
        }
        if (CallableInputType.boolean.matchesScalar(value)) return .boolean;
        if (value.len > 0 and CallableInputType.number.matchesScalar(value)) return .number;
        return .string;
    }
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

/// One entry of `on.workflow_call.secrets`. The declaration is what makes a
/// reusable workflow's secret set closed, which is what EXPR014 checks against.
pub const SecretDef = struct {
    name: []const u8,
    name_span: yaml_types.Span,
    required: ?bool = null,
};

/// One entry of `on.workflow_call.outputs`. RW005 checks the `value:`
/// expression against the jobs of the declaring workflow, and a caller's
/// `needs.<job>.outputs.<name>` against these names.
pub const CallOutputDef = struct {
    name: []const u8,
    name_span: yaml_types.Span,
    /// The `value:` scalar as written, null when `value:` is absent or is not
    /// a scalar — neither carries an expression to resolve.
    value: ?[]const u8 = null,
    /// Span and style of that scalar, so a diagnostic can point at the
    /// offending path inside the expression rather than at the whole entry.
    value_meta: ?ScalarValueMeta = null,
};

pub const WorkflowCallInputProblemKind = enum {
    missing_type,
    invalid_type,
    default_type_mismatch,
    required_with_default,
};

/// Where a `type:` entry goes for a `workflow_call` input declared without
/// one, and the type its `default:` implies (RW001 autofix). Null unless the
/// input has both a scalar `default:` to infer from and a key to anchor on.
pub const CallInputTypeInsertion = struct {
    /// Start byte of the input definition's first key, which the new entry is
    /// written in front of.
    anchor_byte: usize,
    /// Indentation of that key, i.e. its column minus one.
    indent: u32,
    /// `string`, `number` or `boolean`.
    type_name: []const u8,
};

pub const WorkflowCallInputProblem = struct {
    kind: WorkflowCallInputProblemKind,
    input_name: []const u8,
    /// Invalid type name, or declared type name for `default_type_mismatch`.
    detail: []const u8,
    span: yaml_types.Span,
    /// Only set for `missing_type`, and only when the type can be inferred.
    type_insertion: ?CallInputTypeInsertion = null,
};

/// The `type:` values `workflow_dispatch` accepts. `workflow_call` uses the
/// narrower `CallableInputType`: `choice` and `environment` are dispatch-only,
/// because only the manual run form can render a picker.
pub const DispatchInputType = enum {
    string,
    boolean,
    number,
    choice,
    environment,

    pub fn fromString(s: []const u8) ?DispatchInputType {
        const map = std.StaticStringMap(DispatchInputType).initComptime(.{
            .{ "string", .string },
            .{ "boolean", .boolean },
            .{ "number", .number },
            .{ "choice", .choice },
            .{ "environment", .environment },
        });
        return map.get(s);
    }
};

pub const DispatchInputDef = struct {
    name: []const u8,
    name_span: yaml_types.Span,
    /// Null when `type:` is absent (GitHub defaults to `string`) or invalid.
    input_type: ?DispatchInputType = null,
    type_span: ?yaml_types.Span = null,
    options: []const []const u8 = &.{},
    default_value: ?[]const u8 = null,
    default_span: ?yaml_types.Span = null,
};

const WorkflowDispatchInputProblemKind = enum {
    invalid_type,
    missing_options,
    empty_options,
    options_without_choice,
    default_not_in_options,
    default_type_mismatch,
};

pub const WorkflowDispatchInputProblem = struct {
    kind: WorkflowDispatchInputProblemKind,
    input_name: []const u8,
    /// Invalid type name, offending default value, or declared type name,
    /// depending on `kind`. Empty when the message needs no second value.
    detail: []const u8,
    span: yaml_types.Span,
};

pub const EventType = enum {
    push,
    pull_request,
    pull_request_target,
    pull_request_review,
    pull_request_review_comment,
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
            .{ "pull_request_review", .pull_request_review },
            .{ "pull_request_review_comment", .pull_request_review_comment },
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
    workflow_call_secrets: []const SecretDef = &.{},
    workflow_call_outputs: []const CallOutputDef = &.{},
    workflow_dispatch_inputs: []const DispatchInputDef = &.{},
    workflow_dispatch_input_problems: []const WorkflowDispatchInputProblem = &.{},
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

        // `$/{path}` names the repository the workflow came from, at the commit
        // the run started from. There is no `@ref` to pin and no remote
        // repository to look up, so it is local like `./{path}`.
        if (std.mem.startsWith(u8, raw, "$/")) {
            return .{ .raw = raw, .is_local = true, .path = raw };
        }

        if (std.mem.startsWith(u8, raw, "docker://")) {
            return .{ .raw = raw, .is_docker = true };
        }

        var result = ActionRef{ .raw = raw };
        var remaining = raw;

        if (std.mem.find(u8, remaining, "@")) |at_idx| {
            result.ref = remaining[at_idx + 1 ..];
            remaining = remaining[0..at_idx];

            if (result.ref) |ref| {
                result.is_pinned = isShaRef(ref);
            }
        }

        if (std.mem.find(u8, remaining, "/")) |first_slash| {
            result.owner = remaining[0..first_slash];
            const after_owner = remaining[first_slash + 1 ..];

            if (std.mem.find(u8, after_owner, "/")) |second_slash| {
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

/// One axis of `strategy.matrix`, i.e. one entry of the `matrix:` mapping.
/// `include` and `exclude` are axes too: they carry a sequence of values just
/// like a regular axis, and the rules that walk axes apply to them unchanged.
pub const MatrixAxis = struct {
    name: []const u8,
    /// Values of the axis, in source order. Empty when the axis value is not a
    /// sequence (e.g. `os: ${{ fromJSON(...) }}`).
    values: []const yaml_types.Node = &.{},
    /// How to remove each value, parallel to `values` (SYN018 autofix).
    /// Empty when the parser could offer no stable range.
    value_deletes: []const yaml_types.ItemDelete = &.{},
    /// The axis value is an expression scalar
    /// (`include: ${{ fromJSON(...) }}`), so its entries — and the keys an
    /// `include:` entry adds — exist only at run time (EXPR011).
    dynamic: bool = false,
};

pub const Matrix = struct {
    axes: []const MatrixAxis = &.{},
};

pub const Strategy = struct {
    fail_fast: bool = true,
    fail_fast_value_span: ?yaml_types.Span = null,
    fail_fast_entry_span: ?yaml_types.Span = null,
    /// The `strategy:` entry itself, and how many keys sit under it. Removing
    /// the only key of a section leaves a header with nothing beneath it, and
    /// whatever line follows becomes its value instead (PERF003 autofix, fuzz).
    entry_span: ?yaml_types.Span = null,
    entry_count: usize = 0,
    matrix: ?Matrix = null,
    /// True when a `matrix:` key is present, even if its value carries no
    /// inspectable axes (`matrix: ${{ fromJSON(...) }}` leaves `matrix` null).
    /// EXPR011 needs the distinction: a job with no `matrix:` at all has no
    /// `matrix` context, while a dynamic one has keys zghalint cannot know.
    matrix_key_present: bool = false,
};

/// Discriminator for a job step. `background: true` is a flag on `run` /
/// `action` steps, not a kind of its own.
pub const StepKind = enum {
    run,
    action,
    wait,
    wait_all,
    cancel,
    parallel,
};

/// A `wait:` / `cancel:` target, with the span of the YAML scalar so a
/// missing id can be reported on the token rather than the whole step.
pub const StepRef = struct {
    id: []const u8,
    span: yaml_types.Span,
};

/// Control-flow payload for `wait` / `wait-all` / `cancel` / `parallel`.
/// Ordinary `run:` / `uses:` steps leave this null.
pub const StepControl = union(enum) {
    wait: []const StepRef,
    wait_all,
    cancel: StepRef,
    parallel: []const Step,
};

pub const Step = struct {
    id: ?[]const u8 = null,
    /// Span of the `id:` scalar value (for SYN005/SYN006 diagnostics).
    id_value_span: ?yaml_types.Span = null,
    name: ?[]const u8 = null,
    /// Value span and style of the `name:` scalar, so an expression inside it
    /// can be reported where it appears (EXPR016).
    name_meta: ?ScalarValueMeta = null,
    uses: ?ActionRef = null,
    run: ?[]const u8 = null,
    shell: ?[]const u8 = null,
    /// Span of the `shell:` scalar value (for BP004 diagnostics).
    shell_value_span: ?yaml_types.Span = null,
    /// True when a `shell:` key is present, even with a value BP004 cannot
    /// read (`shell:` holding a mapping leaves `shell` null). Without the
    /// distinction `--fix` appended `shell: bash` again every round (fuzz).
    shell_key_present: bool = false,
    with: ?StringMap = null,
    /// True when a `with:` key is present, whatever it holds. An empty section
    /// and a mistyped one (`with: 4`) both leave `with` null while the key is
    /// still in source, so inserting a fresh `with:` block would give the step
    /// two of them (fuzz).
    with_key_present: bool = false,
    /// Value spans and styles of the `with:` entries (for diagnostics that
    /// scan a `with:` value, e.g. SEC003/SEC005/SEC011).
    with_meta: ?ScalarValueMetaMap = null,
    env: ?StringMap = null,
    /// True when an `env:` key is present, whatever it holds. See
    /// `with_key_present`.
    env_key_present: bool = false,
    env_meta: ?ScalarValueMetaMap = null,
    /// Keys of the `env:` mapping in source order (for SYN007).
    env_keys: []const EnvKey = &.{},
    empty_sections: []const EmptySection = &.{},
    if_condition: ?[]const u8 = null,
    /// Value span and scalar style of the `if:` scalar (for EXPR006 autofix).
    if_condition_meta: ?ScalarValueMeta = null,
    /// Span of the step mapping in source YAML (for autofix anchor).
    span: yaml_types.Span = yaml_types.Span.point(0, 0, 0),
    /// The step opens on a line of its own. `steps: - uses: x` puts it on the
    /// `steps:` line, where a block insertion aligned to the step's columns
    /// lands mid-line and outside the step, so the rule keeps re-adding it.
    own_line: bool = true,
    /// Column of the `uses:` key in source YAML (for autofix indentation).
    uses_key_col: ?u32 = null,
    /// End byte of the `uses:` value in source YAML (insertion point when no `with:` exists).
    uses_value_end_byte: ?usize = null,
    /// Scalar style of the `uses:` value (for autofix replacement quoting).
    uses_value_style: ?yaml_types.ScalarStyle = null,
    /// Nothing but blanks or a comment follows the `uses:` value on its line,
    /// so an autofix may append a trailing `# <tag>` after it.
    uses_value_ends_line: bool = false,
    /// End byte of the last entry's value in the `with:` mapping (insertion point for new entries).
    with_last_entry_end_byte: ?usize = null,
    /// Column of the first `with:` key, which appended entries align with. The
    /// step's `uses:` column is not a substitute: a `with:` body indented off
    /// the usual grid would take the appended key out of the mapping, and the
    /// rule would then re-add it on every run.
    with_key_col: ?u32 = null,
    /// Span and style of the `run:` scalar. The style is needed to map an
    /// offset inside `run` back to a source line/column (block scalars start
    /// one line below their `|` / `>` indicator).
    run_meta: ?ScalarValueMeta = null,
    /// Span of the `uses:` scalar value (for SEC001 and the SC00x family).
    uses_value_span: ?yaml_types.Span = null,
    /// Text of the comment trailing the `uses:` value, `#` stripped. A SHA
    /// pin hides the version it stands for, so SC003 reads the `# v1.2.3`
    /// convention that SEC001's autofix (and every pinning tool) writes.
    uses_line_comment: ?[]const u8 = null,
    /// Byte position at the start of the next line after `run:` (insertion point for `shell:`).
    shell_insertion_byte: ?usize = null,
    /// Start byte and column of the step mapping's first key. A new `env:`
    /// block is inserted here, taking over the first key's indentation (AF5).
    first_key_start_byte: ?usize = null,
    first_key_col: ?u32 = null,
    /// End byte of the last entry's value in the `env:` mapping (insertion
    /// point for new entries), under the same conditions as
    /// `with_last_entry_end_byte`.
    env_last_entry_end_byte: ?usize = null,
    /// Column of the first `env:` key, which appended entries align with.
    env_key_col: ?u32 = null,
    background: bool = false,
    control: ?StepControl = null,

    pub fn kind(self: *const Step) StepKind {
        if (self.control) |c| return switch (c) {
            .wait => .wait,
            .wait_all => .wait_all,
            .cancel => .cancel,
            .parallel => .parallel,
        };
        if (self.uses != null) return .action;
        return .run;
    }

    pub fn nestedSteps(self: *const Step) []const Step {
        return switch (self.control orelse return &.{}) {
            .parallel => |children| children,
            else => &.{},
        };
    }
};

/// Depth-first visit of `steps` and every nested `parallel:` child.
pub fn walkSteps(steps: []const Step, ctx: anytype) void {
    for (steps) |*step| {
        ctx.visit(step);
        walkSteps(step.nestedSteps(), ctx);
    }
}

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
    /// How many keys sit under the job id. Removing the only one leaves the job
    /// with no body, and the next line becomes its value (PERF003 autofix, fuzz).
    entry_count: usize = 0,
    /// Span of the job key in the top-level `jobs:` mapping (for SYN005/SYN006 diagnostics).
    id_span: ?yaml_types.Span = null,
    span: yaml_types.Span = yaml_types.Span.point(0, 0, 0),
    name: ?[]const u8 = null,
    runs_on: ?[]const u8 = null,
    needs: []const []const u8 = &.{},
    /// Value spans of `needs` entries, parallel to `needs`. Empty when absent.
    needs_spans: []const yaml_types.Span = &.{},
    /// How to remove each `needs` entry, parallel to `needs` (SYN008
    /// autofix). Empty when `needs` is a bare scalar, which has no entry to
    /// remove on its own.
    needs_deletes: []const yaml_types.ItemDelete = &.{},
    /// Keys of the job-level `outputs:` mapping in source order (for EXPR012).
    outputs: []const OutputKey = &.{},
    permissions: ?Permissions = null,
    permissions_meta: ?PermissionsMeta = null,
    /// `permissions:` entries rejected during parsing (PERM003).
    permission_problems: []const PermissionProblem = &.{},
    steps: []const Step = &.{},
    /// How to remove each step from the `steps:` sequence, the `- ` bullet
    /// included, parallel to `steps` (PERF002 autofix). Empty when the steps
    /// come from an alias expansion, whose text lives at the anchor.
    step_deletes: []const yaml_types.ItemDelete = &.{},
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
    /// Entries of the job-level `with:` mapping in source order (for RW002/RW003).
    with_args: []const CallArg = &.{},
    secrets: ?SecretsConfig = null,
    /// Entries of the job-level `secrets:` mapping in source order (for RW004).
    /// Empty for `secrets: inherit`, which names nothing.
    secrets_args: []const CallArg = &.{},
    /// Column (1-based) at which this job's child keys are indented.
    job_indent: u32 = 0,
    /// The job body starts on a line of its own rather than on the job id's
    /// line, which is what an insertion aligned to `job_indent` assumes.
    body_own_line: bool = true,
    /// Byte position to insert a new `permissions:` entry (after `runs-on:` line).
    permissions_insertion_byte: ?usize = null,
    concurrency_insertion_byte: ?usize = null,
    /// Span of the `runs-on:` scalar value (for RUNNER001 autofix).
    /// Null when `runs-on` is absent or given as a sequence.
    runs_on_value_span: ?yaml_types.Span = null,
    /// Scalar style of the `runs-on:` value, so a `${{ }}` inside it can be
    /// located within the token (EXPR011).
    runs_on_value_style: yaml_types.ScalarStyle = .plain,
    /// `runs-on` labels in source order, normalized from all three spellings:
    /// a scalar, a sequence, or the `labels:` list of a runner-group mapping.
    runs_on_labels: []const []const u8 = &.{},
    /// Value spans of `runs_on_labels`, parallel to it. Empty when absent.
    runs_on_label_spans: []const yaml_types.Span = &.{},
    /// `cache-mode:` scalar as written. Invalid values are kept so SYN023 can
    /// report them instead of dropping the key.
    cache_mode: ?[]const u8 = null,
    cache_mode_span: ?yaml_types.Span = null,
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
    /// Indentation (0-based) of the top-level keys. Normally 0, but a document
    /// whose root mapping is written indented needs the inserted entries to
    /// line up with it or the mapping ends at the insertion.
    top_level_indent: u32 = 0,
    /// Byte position to insert a new top-level `permissions:` entry (after `on:` line).
    permissions_insertion_byte: ?usize = null,
    /// Byte position to insert a new top-level `concurrency:` entry (after `on:` line).
    concurrency_insertion_byte: ?usize = null,
    /// Original YAML root. SYN002 walks this for case-insensitive duplicate keys.
    yaml_root: ?yaml_types.Node = null,
    /// `cache-mode:` scalar as written. Invalid values are kept so SYN023 can
    /// report them instead of dropping the key.
    cache_mode: ?[]const u8 = null,
    cache_mode_span: ?yaml_types.Span = null,

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

test "ActionRef.parse self-repository action" {
    const ref = ActionRef.parse("$/.github/actions/setup");
    try std.testing.expect(ref.is_local);
    try std.testing.expectEqualStrings("$/.github/actions/setup", ref.path.?);
    try std.testing.expect(ref.owner == null);
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

test "CallableInputType.inferFromScalar reads a plain default" {
    try std.testing.expectEqual(CallableInputType.boolean, CallableInputType.inferFromScalar("true", .plain));
    try std.testing.expectEqual(CallableInputType.boolean, CallableInputType.inferFromScalar("false", .plain));
    try std.testing.expectEqual(CallableInputType.number, CallableInputType.inferFromScalar("3", .plain));
    try std.testing.expectEqual(CallableInputType.number, CallableInputType.inferFromScalar("-1.5", .plain));
    try std.testing.expectEqual(CallableInputType.string, CallableInputType.inferFromScalar("main", .plain));
    try std.testing.expectEqual(CallableInputType.string, CallableInputType.inferFromScalar("", .plain));
}

test "CallableInputType.inferFromScalar treats a quoted default as a string" {
    try std.testing.expectEqual(CallableInputType.string, CallableInputType.inferFromScalar("true", .double_quoted));
    try std.testing.expectEqual(CallableInputType.string, CallableInputType.inferFromScalar("3", .single_quoted));
}

test "cache_mode_values matches the documented modes" {
    try std.testing.expect(isCacheMode("none"));
    try std.testing.expect(isCacheMode("read"));
    try std.testing.expect(isCacheMode("write"));
    try std.testing.expect(isCacheMode("write-only"));
    try std.testing.expect(!isCacheMode("read-write"));
    try std.testing.expect(!isCacheMode("writeonly"));
}

test "CacheCapability.fromMode is restore/save, not a linear scale" {
    try std.testing.expectEqual(CacheCapability.none, CacheCapability.fromMode("none").?);
    try std.testing.expectEqual(CacheCapability.read, CacheCapability.fromMode("read").?);
    try std.testing.expectEqual(CacheCapability.write, CacheCapability.fromMode("write").?);
    try std.testing.expectEqual(CacheCapability.write_only, CacheCapability.fromMode("write-only").?);
    try std.testing.expect(CacheCapability.fromMode("reed") == null);
    try std.testing.expect(CacheCapability.fromMode("${{ inputs.mode }}") == null);
    try std.testing.expect(CacheCapability.none.allowsCache() == false);
    try std.testing.expect(CacheCapability.read.allowsCache());
    try std.testing.expect(CacheCapability.write_only.allowsCache());
}

test "every cache_mode_values entry has a capability" {
    for (cache_mode_values) |mode| {
        try std.testing.expect(CacheCapability.fromMode(mode) != null);
        try std.testing.expect(isCacheMode(mode));
    }
}

test "resolveCacheCapability: job overrides workflow" {
    const jobs = [_]Job{
        .{ .id = "restricted", .cache_mode = "none" },
        .{ .id = "inherited", .cache_mode = null },
        .{ .id = "unknown", .cache_mode = "reed" },
    };
    const wf = Workflow{
        .on = .{ .events = &.{} },
        .jobs = &jobs,
        .cache_mode = "write",
    };
    try std.testing.expectEqual(CacheCapability.none, resolveCacheCapability(&wf, &jobs[0]).?);
    try std.testing.expectEqual(CacheCapability.write, resolveCacheCapability(&wf, &jobs[1]).?);
    try std.testing.expect(resolveCacheCapability(&wf, &jobs[2]) == null);
}

test "resolveCacheCapability: omitted cache-mode is unrestricted" {
    const jobs = [_]Job{.{ .id = "build" }};
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &jobs };
    try std.testing.expectEqual(CacheCapability.unrestricted, resolveCacheCapability(&wf, &jobs[0]).?);
    try std.testing.expect(jobAllowsCache(&wf, &jobs[0]));
}

test "jobAllowsCache: none is a disable, unknown is not" {
    const jobs = [_]Job{
        .{ .id = "off", .cache_mode = "none" },
        .{ .id = "unknown", .cache_mode = "reed" },
        .{ .id = "read", .cache_mode = "read" },
    };
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &jobs };
    try std.testing.expect(!jobAllowsCache(&wf, &jobs[0]));
    try std.testing.expect(jobAllowsCache(&wf, &jobs[1]));
    try std.testing.expect(jobAllowsCache(&wf, &jobs[2]));
}

test "vulnerability-alerts rejects write" {
    try std.testing.expect(!isAllowedPermissionLevel("vulnerability-alerts", .write));
    try std.testing.expect(isAllowedPermissionLevel("vulnerability-alerts", .read));
    try std.testing.expect(isAllowedPermissionLevel("vulnerability-alerts", .none));
    try std.testing.expect(isAllowedPermissionLevel("contents", .write));
}

test "hasEmptySection matches by name" {
    const sections = [_]EmptySection{.{ .name = "with", .span = yaml_types.Span.point(1, 1, 0) }};
    try std.testing.expect(hasEmptySection(&sections, "with"));
    try std.testing.expect(!hasEmptySection(&sections, "env"));
    try std.testing.expect(!hasEmptySection(&.{}, "with"));
}
