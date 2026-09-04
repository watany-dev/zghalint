const std = @import("std");
const yaml_types = @import("../yaml/types.zig");

/// A workflow section that was present in the source but empty.
pub const EmptySection = struct {
    name: []const u8,
    span: yaml_types.Span,
};

/// String map backed by an allocator
pub const StringMap = std.StringArrayHashMap([]const u8);
pub const ScalarValueMetaMap = std.StringArrayHashMap(ScalarValueMeta);

/// Source metadata for a scalar value preserved for autofix generation.
pub const ScalarValueMeta = struct {
    value_span: yaml_types.Span,
    style: yaml_types.ScalarStyle,
};

/// Permission level for a scope
pub const PermissionLevel = enum {
    read,
    write,
    none,
};

/// GitHub Actions permissions for GITHUB_TOKEN
pub const Permissions = struct {
    actions: ?PermissionLevel = null,
    attestations: ?PermissionLevel = null,
    checks: ?PermissionLevel = null,
    contents: ?PermissionLevel = null,
    deployments: ?PermissionLevel = null,
    discussions: ?PermissionLevel = null,
    id_token: ?PermissionLevel = null,
    issues: ?PermissionLevel = null,
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
    attestations: ?yaml_types.Span = null,
    checks: ?yaml_types.Span = null,
    contents: ?yaml_types.Span = null,
    deployments: ?yaml_types.Span = null,
    discussions: ?yaml_types.Span = null,
    id_token: ?yaml_types.Span = null,
    issues: ?yaml_types.Span = null,
    packages: ?yaml_types.Span = null,
    pages: ?yaml_types.Span = null,
    pull_requests: ?yaml_types.Span = null,
    repository_projects: ?yaml_types.Span = null,
    security_events: ?yaml_types.Span = null,
    statuses: ?yaml_types.Span = null,
};

/// Concurrency configuration
pub const Concurrency = struct {
    group: []const u8,
    cancel_in_progress: bool = false,
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

/// Event filter configuration for branches/tags/paths
pub const EventFilter = struct {
    branches: []const []const u8 = &.{},
    branches_ignore: []const []const u8 = &.{},
    tags: []const []const u8 = &.{},
    tags_ignore: []const []const u8 = &.{},
    paths: []const []const u8 = &.{},
    paths_ignore: []const []const u8 = &.{},
    types: []const []const u8 = &.{},
    spans: EventFilterSpans = .{},
};

/// Schedule entry (cron expression)
pub const ScheduleEntry = struct {
    cron: []const u8,
};

/// Input definition for workflow_dispatch / workflow_call
pub const InputDef = struct {
    description: ?[]const u8 = null,
    required: bool = false,
    default: ?[]const u8 = null,
    input_type: ?[]const u8 = null,
};

/// Output definition for workflow_call
pub const OutputDef = struct {
    description: ?[]const u8 = null,
    value: ?[]const u8 = null,
};

/// Secret definition for workflow_call
pub const SecretDef = struct {
    description: ?[]const u8 = null,
    required: bool = false,
};

/// Workflow dispatch trigger configuration
pub const WorkflowDispatch = struct {
    inputs: ?std.StringArrayHashMap(InputDef) = null,
};

/// Workflow call trigger configuration
pub const WorkflowCall = struct {
    inputs: ?std.StringArrayHashMap(InputDef) = null,
    outputs: ?std.StringArrayHashMap(OutputDef) = null,
    secrets: ?std.StringArrayHashMap(SecretDef) = null,
};

/// Known event types
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

/// A single event configuration within a trigger
pub const EventConfig = struct {
    event: EventType,
    name: []const u8,
    filter: ?EventFilter = null,
    schedule: []const ScheduleEntry = &.{},
    workflow_dispatch: ?WorkflowDispatch = null,
    workflow_call: ?WorkflowCall = null,
};

/// Trigger configuration (the `on:` field)
pub const Trigger = struct {
    events: []const EventConfig,
};

/// Action reference parsed from `uses:` field
pub const ActionRef = struct {
    raw: []const u8,
    owner: ?[]const u8 = null,
    repo: ?[]const u8 = null,
    path: ?[]const u8 = null,
    ref: ?[]const u8 = null,
    is_local: bool = false,
    is_docker: bool = false,
    is_pinned: bool = false,

    /// Parse a uses string like "actions/checkout@v4" or "./local-action"
    pub fn parse(raw: []const u8) ActionRef {
        // Local action
        if (raw.len >= 2 and raw[0] == '.' and (raw[1] == '/' or (raw.len >= 3 and raw[1] == '.' and raw[2] == '/'))) {
            return .{ .raw = raw, .is_local = true, .path = raw };
        }

        // Docker action
        if (std.mem.startsWith(u8, raw, "docker://")) {
            return .{ .raw = raw, .is_docker = true };
        }

        // owner/repo/path@ref or owner/repo@ref
        var result = ActionRef{ .raw = raw };
        var remaining = raw;

        // Split on @
        if (std.mem.indexOf(u8, remaining, "@")) |at_idx| {
            result.ref = remaining[at_idx + 1 ..];
            remaining = remaining[0..at_idx];

            // Check if pinned (40-char hex SHA)
            if (result.ref) |ref| {
                result.is_pinned = isShaRef(ref);
            }
        }

        // Split owner/repo[/path]
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

/// Matrix strategy configuration
pub const Strategy = struct {
    fail_fast: bool = true,
    /// Span of the `fail-fast` scalar value in the source YAML.
    fail_fast_value_span: ?yaml_types.Span = null,
    /// Span of the removable `fail-fast` entry in block-style YAML.
    fail_fast_entry_span: ?yaml_types.Span = null,
    max_parallel: ?u32 = null,
};

/// A single workflow step
pub const Step = struct {
    id: ?[]const u8 = null,
    /// Span of the `id:` scalar value (for SYN005 diagnostics).
    id_value_span: ?yaml_types.Span = null,
    name: ?[]const u8 = null,
    uses: ?ActionRef = null,
    run: ?[]const u8 = null,
    shell: ?[]const u8 = null,
    with: ?StringMap = null,
    env: ?StringMap = null,
    env_meta: ?ScalarValueMetaMap = null,
    empty_sections: []const EmptySection = &.{},
    if_condition: ?[]const u8 = null,
    /// Value span and scalar style of the `if:` scalar (for EXPR006 autofix).
    if_condition_meta: ?ScalarValueMeta = null,
    continue_on_error: bool = false,
    timeout_minutes: ?u32 = null,
    working_directory: ?[]const u8 = null,
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
    /// Value span of the `run:` scalar (for future SEC008 family).
    run_value_span: ?yaml_types.Span = null,
    /// Byte position at the start of the next line after `run:` (insertion point for `shell:`).
    shell_insertion_byte: ?usize = null,
    /// Byte position for appending an entry to the step mapping (end of last entry's line).
    env_insertion_byte: ?usize = null,
};

/// Secrets configuration for reusable workflow jobs
pub const SecretsConfig = union(enum) {
    inherit,
    map: StringMap,
};

/// Docker registry credentials for container/service images
pub const Credentials = struct {
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
};

/// Container configuration for a job
pub const Container = struct {
    image: ?[]const u8 = null,
    credentials: ?Credentials = null,
};

/// Service container configuration
pub const Service = struct {
    name: []const u8,
    image: ?[]const u8 = null,
    credentials: ?Credentials = null,
};

/// A workflow job
pub const Job = struct {
    id: []const u8,
    /// Span of the job key in the top-level `jobs:` mapping (for SYN005 diagnostics).
    id_span: ?yaml_types.Span = null,
    span: yaml_types.Span = yaml_types.Span.point(0, 0, 0),
    name: ?[]const u8 = null,
    runs_on: ?[]const u8 = null,
    needs: []const []const u8 = &.{},
    permissions: ?Permissions = null,
    permissions_meta: ?PermissionsMeta = null,
    steps: []const Step = &.{},
    env: ?StringMap = null,
    env_meta: ?ScalarValueMetaMap = null,
    if_condition: ?[]const u8 = null,
    /// Value span and scalar style of the `if:` scalar (for EXPR006 autofix).
    if_condition_meta: ?ScalarValueMeta = null,
    timeout_minutes: ?u32 = null,
    strategy: ?Strategy = null,
    concurrency: ?Concurrency = null,
    continue_on_error: bool = false,
    container: ?Container = null,
    services: []const Service = &.{},
    empty_sections: []const EmptySection = &.{},
    /// Reusable workflow reference (mutually exclusive with steps)
    uses: ?[]const u8 = null,
    with: ?StringMap = null,
    secrets: ?SecretsConfig = null,
    /// Column (1-based) at which this job's child keys are indented.
    job_indent: u32 = 0,
    /// Byte position to insert a new `permissions:` entry (after `runs-on:` line).
    permissions_insertion_byte: ?usize = null,
    /// Byte position to insert a new `concurrency:` entry at job level.
    concurrency_insertion_byte: ?usize = null,
    /// Span of the `runs-on:` scalar value (for RUNNER001 autofix).
    /// Null when `runs-on` is absent or given as a sequence.
    runs_on_value_span: ?yaml_types.Span = null,
};

/// Top-level workflow definition
pub const Workflow = struct {
    name: ?[]const u8 = null,
    on: Trigger,
    permissions: ?Permissions = null,
    permissions_meta: ?PermissionsMeta = null,
    env: ?StringMap = null,
    env_meta: ?ScalarValueMetaMap = null,
    concurrency: ?Concurrency = null,
    jobs: []const Job,
    empty_sections: []const EmptySection = &.{},
    /// Top-level keys are always at column 1.
    top_level_indent: u32 = 0,
    /// Byte position to insert a new top-level `permissions:` entry (after `on:` line).
    permissions_insertion_byte: ?usize = null,
    /// Byte position to insert a new top-level `concurrency:` entry (after `on:` line).
    concurrency_insertion_byte: ?usize = null,
};

// ============================================================
// Tests
// ============================================================

test "EventType.fromString known events" {
    try std.testing.expectEqual(EventType.push, EventType.fromString("push"));
    try std.testing.expectEqual(EventType.pull_request, EventType.fromString("pull_request"));
    try std.testing.expectEqual(EventType.schedule, EventType.fromString("schedule"));
    try std.testing.expectEqual(EventType.workflow_dispatch, EventType.fromString("workflow_dispatch"));
    try std.testing.expectEqual(EventType.workflow_call, EventType.fromString("workflow_call"));
    try std.testing.expectEqual(EventType.release, EventType.fromString("release"));
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

test "PermissionLevel values" {
    try std.testing.expect(@intFromEnum(PermissionLevel.read) != @intFromEnum(PermissionLevel.write));
    try std.testing.expect(@intFromEnum(PermissionLevel.none) != @intFromEnum(PermissionLevel.read));
}

test "Permissions default all null" {
    const p = Permissions{};
    try std.testing.expect(p.actions == null);
    try std.testing.expect(p.contents == null);
    try std.testing.expect(!p.read_all);
    try std.testing.expect(!p.write_all);
}

test "Concurrency fields" {
    const c = Concurrency{ .group = "ci-${{ github.ref }}" };
    try std.testing.expectEqualStrings("ci-${{ github.ref }}", c.group);
    try std.testing.expect(!c.cancel_in_progress);
}

test "Step default fields" {
    const step = Step{};
    try std.testing.expect(step.id == null);
    try std.testing.expect(step.uses == null);
    try std.testing.expect(step.run == null);
    try std.testing.expect(!step.continue_on_error);
}

test "Job default fields" {
    const job = Job{ .id = "build" };
    try std.testing.expectEqualStrings("build", job.id);
    try std.testing.expect(job.runs_on == null);
    try std.testing.expect(job.steps.len == 0);
    try std.testing.expect(job.needs.len == 0);
    try std.testing.expect(job.uses == null);
}

test "SecretsConfig inherit" {
    const s = SecretsConfig{ .inherit = {} };
    switch (s) {
        .inherit => {},
        .map => unreachable,
    }
}

test "Workflow construction" {
    var events = [_]EventConfig{
        .{ .event = .push, .name = "push" },
    };
    var jobs = [_]Job{
        .{ .id = "build" },
    };
    const wf = Workflow{
        .name = "CI",
        .on = .{ .events = &events },
        .jobs = &jobs,
    };
    try std.testing.expectEqualStrings("CI", wf.name.?);
    try std.testing.expectEqual(@as(usize, 1), wf.on.events.len);
    try std.testing.expectEqual(@as(usize, 1), wf.jobs.len);
}

test "EventFilter defaults empty" {
    const f = EventFilter{};
    try std.testing.expectEqual(@as(usize, 0), f.branches.len);
    try std.testing.expectEqual(@as(usize, 0), f.tags.len);
    try std.testing.expectEqual(@as(usize, 0), f.paths.len);
    try std.testing.expectEqual(@as(usize, 0), f.types.len);
}

test "Strategy defaults" {
    const s = Strategy{};
    try std.testing.expect(s.fail_fast);
    try std.testing.expect(s.max_parallel == null);
}
