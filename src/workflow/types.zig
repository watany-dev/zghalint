pub const StringMap = struct {
    keys: []const []const u8,
    values: []const []const u8,

    pub fn get(self: StringMap, key: []const u8) ?[]const u8 {
        for (self.keys, self.values) |k, v| {
            if (std.mem.eql(u8, k, key)) return v;
        }
        return null;
    }

    pub const empty: StringMap = .{ .keys = &.{}, .values = &.{} };
};

pub const Permissions = struct {
    scope: ?[]const u8 = null,
    individual: ?StringMap = null,

    pub fn getIndividualPermission(self: Permissions, key: []const u8) ?[]const u8 {
        if (self.individual) |ind| {
            return ind.get(key);
        }
        return null;
    }
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
        if (raw.len == 0) return .{ .raw = raw };

        if (raw[0] == '.') return .{ .raw = raw, .is_local = true };
        if (std.mem.startsWith(u8, raw, "docker://")) return .{ .raw = raw, .is_docker = true };

        var result = ActionRef{ .raw = raw };

        var rest = raw;
        if (std.mem.indexOf(u8, rest, "@")) |at_pos| {
            result.ref = rest[at_pos + 1 ..];
            rest = rest[0..at_pos];

            if (result.ref) |ref| {
                result.is_pinned = ref.len == 40 and isAllHex(ref);
            }
        }

        if (std.mem.indexOf(u8, rest, "/")) |slash_pos| {
            result.owner = rest[0..slash_pos];
            const after_owner = rest[slash_pos + 1 ..];
            if (std.mem.indexOf(u8, after_owner, "/")) |second_slash| {
                result.repo = after_owner[0..second_slash];
                result.path = after_owner[second_slash + 1 ..];
            } else {
                result.repo = after_owner;
            }
        }

        return result;
    }

    pub fn getFullName(self: ActionRef) ?[]const u8 {
        // Return "owner/repo" portion
        if (self.owner == null or self.repo == null) return null;
        // We need to reconstruct, but since raw contains it, extract from raw
        const raw = self.raw;
        if (std.mem.indexOf(u8, raw, "@")) |at_pos| {
            const before_at = raw[0..at_pos];
            // Remove path portion if present
            if (self.owner) |owner| {
                if (self.repo) |repo| {
                    _ = owner;
                    _ = repo;
                    return before_at;
                }
            }
        }
        return null;
    }

    fn isAllHex(s: []const u8) bool {
        for (s) |c| {
            if (!std.ascii.isHex(c)) return false;
        }
        return true;
    }
};

pub const Step = struct {
    id: ?[]const u8 = null,
    name: ?[]const u8 = null,
    uses: ?ActionRef = null,
    run: ?[]const u8 = null,
    shell: ?[]const u8 = null,
    with: ?StringMap = null,
    env: ?StringMap = null,
    if_condition: ?[]const u8 = null,
    continue_on_error: bool = false,
    timeout_minutes: ?u32 = null,
    working_directory: ?[]const u8 = null,
};

pub const MatrixEntry = struct {
    key: []const u8,
    values: []const []const u8,
};

pub const Strategy = struct {
    matrix: ?[]const MatrixEntry = null,
    fail_fast: ?bool = null,
    max_parallel: ?u32 = null,

    pub fn totalCombinations(self: Strategy) usize {
        const entries = self.matrix orelse return 0;
        if (entries.len == 0) return 0;
        var total: usize = 1;
        for (entries) |entry| {
            if (entry.values.len > 0) total *= entry.values.len;
        }
        return total;
    }
};

pub const EventType = enum {
    push,
    pull_request,
    pull_request_target,
    workflow_dispatch,
    workflow_call,
    schedule,
    release,
    issues,
    issue_comment,
    create,
    delete_event,
    fork,
    watch,
    repository_dispatch,
    check_run,
    check_suite,
    deployment,
    deployment_status,
    page_build,
    status,
    other,
};

pub const EventConfig = struct {
    event: EventType,
    name: []const u8,
};

pub const Trigger = struct {
    events: []const EventConfig,
};

pub const Concurrency = struct {
    group: []const u8,
    cancel_in_progress: bool = false,
};

pub const Job = struct {
    id: []const u8,
    name: ?[]const u8 = null,
    runs_on: ?[]const u8 = null,
    needs: []const []const u8 = &.{},
    permissions: ?Permissions = null,
    steps: []const Step = &.{},
    env: ?StringMap = null,
    if_condition: ?[]const u8 = null,
    timeout_minutes: ?u32 = null,
    strategy: ?Strategy = null,
    concurrency: ?Concurrency = null,
    continue_on_error: bool = false,
    uses: ?[]const u8 = null,
    with: ?StringMap = null,
    secrets: ?StringMap = null,
};

pub const Workflow = struct {
    name: ?[]const u8 = null,
    on: Trigger,
    permissions: ?Permissions = null,
    env: ?StringMap = null,
    concurrency: ?Concurrency = null,
    jobs: []const Job = &.{},
};

const std = @import("std");
