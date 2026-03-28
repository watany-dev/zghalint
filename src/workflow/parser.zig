const std = @import("std");
const types = @import("types.zig");
const yaml = @import("../yaml/types.zig");

const Node = yaml.Node;
const Mapping = yaml.Mapping;

pub const ParseError = error{
    MissingField,
    InvalidValue,
    OutOfMemory,
};

/// Parse a YAML AST Node into a Workflow struct
pub fn parseWorkflow(allocator: std.mem.Allocator, node: Node) ParseError!types.Workflow {
    const root = switch (node) {
        .mapping => |m| m,
        else => return error.InvalidValue,
    };

    const trigger = if (root.get("on")) |on_node|
        try parseTrigger(allocator, on_node)
    else if (root.get("true")) |on_node|
        // YAML parses bare `on:` as boolean `true` key in some cases
        try parseTrigger(allocator, on_node)
    else
        return error.MissingField;

    const jobs = if (root.get("jobs")) |jobs_node|
        try parseJobs(allocator, jobs_node)
    else
        return error.MissingField;

    return types.Workflow{
        .name = root.getScalar("name"),
        .on = trigger,
        .permissions = if (root.get("permissions")) |n| try parsePermissions(n) else null,
        .env = if (root.get("env")) |n| try parseStringMap(allocator, n) else null,
        .concurrency = if (root.get("concurrency")) |n| try parseConcurrency(n) else null,
        .jobs = jobs,
    };
}

/// Parse the `on:` trigger field
fn parseTrigger(allocator: std.mem.Allocator, node: Node) ParseError!types.Trigger {
    switch (node) {
        .scalar => |s| {
            // on: push
            const events = try allocator.alloc(types.EventConfig, 1);
            events[0] = .{
                .event = types.EventType.fromString(s.value),
                .name = s.value,
            };
            return .{ .events = events };
        },
        .sequence => |seq| {
            // on: [push, pull_request]
            const events = try allocator.alloc(types.EventConfig, seq.items.len);
            for (seq.items, 0..) |item, i| {
                switch (item) {
                    .scalar => |s| {
                        events[i] = .{
                            .event = types.EventType.fromString(s.value),
                            .name = s.value,
                        };
                    },
                    else => return error.InvalidValue,
                }
            }
            return .{ .events = events };
        },
        .mapping => |m| {
            // on: { push: { branches: [main] }, pull_request: ... }
            const events = try allocator.alloc(types.EventConfig, m.entries.len);
            for (m.entries, 0..) |entry, i| {
                events[i] = try parseEventConfig(allocator, entry.key.value, entry.value);
            }
            return .{ .events = events };
        },
        .null_value => return error.InvalidValue,
    }
}

fn parseEventConfig(allocator: std.mem.Allocator, name: []const u8, node: Node) ParseError!types.EventConfig {
    const event_type = types.EventType.fromString(name);
    var config = types.EventConfig{
        .event = event_type,
        .name = name,
    };

    switch (node) {
        .null_value => {
            // on: { push: } — no config
            return config;
        },
        .mapping => |m| {
            switch (event_type) {
                .schedule => {
                    // schedule is handled via the parent — schedule entries come as a sequence
                },
                .workflow_dispatch => {
                    var wd = types.WorkflowDispatch{};
                    if (m.get("inputs")) |inputs_node| {
                        wd.inputs = try parseInputDefs(allocator, inputs_node);
                    }
                    config.workflow_dispatch = wd;
                },
                .workflow_call => {
                    var wc = types.WorkflowCall{};
                    if (m.get("inputs")) |n| {
                        wc.inputs = try parseInputDefs(allocator, n);
                    }
                    if (m.get("outputs")) |n| {
                        wc.outputs = try parseOutputDefs(allocator, n);
                    }
                    if (m.get("secrets")) |n| {
                        wc.secrets = try parseSecretDefs(allocator, n);
                    }
                    config.workflow_call = wc;
                },
                else => {
                    config.filter = try parseEventFilter(allocator, m);
                },
            }
        },
        .sequence => |seq| {
            if (event_type == .schedule) {
                config.schedule = try parseScheduleEntries(allocator, seq);
            }
        },
        .scalar => {},
    }

    return config;
}

fn parseEventFilter(allocator: std.mem.Allocator, m: Mapping) ParseError!types.EventFilter {
    return .{
        .branches = if (m.get("branches")) |n| try parseStringArray(allocator, n) else &.{},
        .branches_ignore = if (m.get("branches-ignore")) |n| try parseStringArray(allocator, n) else &.{},
        .tags = if (m.get("tags")) |n| try parseStringArray(allocator, n) else &.{},
        .tags_ignore = if (m.get("tags-ignore")) |n| try parseStringArray(allocator, n) else &.{},
        .paths = if (m.get("paths")) |n| try parseStringArray(allocator, n) else &.{},
        .paths_ignore = if (m.get("paths-ignore")) |n| try parseStringArray(allocator, n) else &.{},
        .types = if (m.get("types")) |n| try parseStringArray(allocator, n) else &.{},
    };
}

fn parseScheduleEntries(allocator: std.mem.Allocator, seq: yaml.Sequence) ParseError![]const types.ScheduleEntry {
    const entries = try allocator.alloc(types.ScheduleEntry, seq.items.len);
    for (seq.items, 0..) |item, i| {
        switch (item) {
            .mapping => |m| {
                entries[i] = .{
                    .cron = m.getScalar("cron") orelse return error.InvalidValue,
                };
            },
            else => return error.InvalidValue,
        }
    }
    return entries;
}

fn parseInputDefs(allocator: std.mem.Allocator, node: Node) ParseError!std.StringArrayHashMap(types.InputDef) {
    var map = std.StringArrayHashMap(types.InputDef).init(allocator);
    switch (node) {
        .mapping => |m| {
            for (m.entries) |entry| {
                var def = types.InputDef{};
                switch (entry.value) {
                    .mapping => |vm| {
                        def.description = vm.getScalar("description");
                        def.default = vm.getScalar("default");
                        def.input_type = vm.getScalar("type");
                        if (vm.getScalar("required")) |r| {
                            def.required = std.mem.eql(u8, r, "true");
                        }
                    },
                    else => {},
                }
                try map.put(entry.key.value, def);
            }
        },
        else => return error.InvalidValue,
    }
    return map;
}

fn parseOutputDefs(allocator: std.mem.Allocator, node: Node) ParseError!std.StringArrayHashMap(types.OutputDef) {
    var map = std.StringArrayHashMap(types.OutputDef).init(allocator);
    switch (node) {
        .mapping => |m| {
            for (m.entries) |entry| {
                var def = types.OutputDef{};
                switch (entry.value) {
                    .mapping => |vm| {
                        def.description = vm.getScalar("description");
                        def.value = vm.getScalar("value");
                    },
                    else => {},
                }
                try map.put(entry.key.value, def);
            }
        },
        else => return error.InvalidValue,
    }
    return map;
}

fn parseSecretDefs(allocator: std.mem.Allocator, node: Node) ParseError!std.StringArrayHashMap(types.SecretDef) {
    var map = std.StringArrayHashMap(types.SecretDef).init(allocator);
    switch (node) {
        .mapping => |m| {
            for (m.entries) |entry| {
                var def = types.SecretDef{};
                switch (entry.value) {
                    .mapping => |vm| {
                        def.description = vm.getScalar("description");
                        if (vm.getScalar("required")) |r| {
                            def.required = std.mem.eql(u8, r, "true");
                        }
                    },
                    else => {},
                }
                try map.put(entry.key.value, def);
            }
        },
        else => return error.InvalidValue,
    }
    return map;
}

fn parseJobs(allocator: std.mem.Allocator, node: Node) ParseError![]const types.Job {
    const m = switch (node) {
        .mapping => |m| m,
        else => return error.InvalidValue,
    };

    const jobs = try allocator.alloc(types.Job, m.entries.len);
    for (m.entries, 0..) |entry, i| {
        jobs[i] = try parseJob(allocator, entry.key.value, entry.value);
    }
    return jobs;
}

fn parseJob(allocator: std.mem.Allocator, id: []const u8, node: Node) ParseError!types.Job {
    const m = switch (node) {
        .mapping => |m| m,
        else => return error.InvalidValue,
    };

    var job = types.Job{ .id = id };
    job.name = m.getScalar("name");
    job.runs_on = m.getScalar("runs-on");
    job.if_condition = m.getScalar("if");
    job.uses = m.getScalar("uses");

    if (m.getScalar("timeout-minutes")) |t| {
        job.timeout_minutes = std.fmt.parseInt(u32, t, 10) catch null;
    }
    if (m.getScalar("continue-on-error")) |v| {
        job.continue_on_error = std.mem.eql(u8, v, "true");
    }

    if (m.get("needs")) |needs_node| {
        job.needs = try parseStringArrayOrSingle(allocator, needs_node);
    }

    if (m.get("steps")) |steps_node| {
        job.steps = try parseSteps(allocator, steps_node);
    }

    if (m.get("permissions")) |n| {
        job.permissions = try parsePermissions(n);
    }
    if (m.get("env")) |n| {
        job.env = try parseStringMap(allocator, n);
    }
    if (m.get("concurrency")) |n| {
        job.concurrency = try parseConcurrency(n);
    }
    if (m.get("strategy")) |n| {
        job.strategy = try parseStrategy(n);
    }
    if (m.get("with")) |n| {
        job.with = try parseStringMap(allocator, n);
    }
    if (m.get("secrets")) |n| {
        job.secrets = try parseSecretsConfig(allocator, n);
    }
    if (m.get("container")) |n| {
        job.container = try parseContainer(n);
    }
    if (m.get("services")) |n| {
        job.services = try parseServices(allocator, n);
    }

    return job;
}

fn parseSteps(allocator: std.mem.Allocator, node: Node) ParseError![]const types.Step {
    const seq = switch (node) {
        .sequence => |s| s,
        else => return error.InvalidValue,
    };

    const steps = try allocator.alloc(types.Step, seq.items.len);
    for (seq.items, 0..) |item, i| {
        steps[i] = try parseStep(allocator, item);
    }
    return steps;
}

fn parseStep(allocator: std.mem.Allocator, node: Node) ParseError!types.Step {
    const m = switch (node) {
        .mapping => |mp| mp,
        else => return error.InvalidValue,
    };

    var step = types.Step{};
    step.id = m.getScalar("id");
    step.name = m.getScalar("name");
    step.run = m.getScalar("run");
    step.shell = m.getScalar("shell");
    step.if_condition = m.getScalar("if");
    step.working_directory = m.getScalar("working-directory");

    if (m.getScalar("uses")) |uses_str| {
        step.uses = types.ActionRef.parse(uses_str);
    }
    if (m.getScalar("timeout-minutes")) |t| {
        step.timeout_minutes = std.fmt.parseInt(u32, t, 10) catch null;
    }
    if (m.getScalar("continue-on-error")) |v| {
        step.continue_on_error = std.mem.eql(u8, v, "true");
    }
    if (m.get("with")) |n| {
        step.with = try parseStringMap(allocator, n);
    }
    if (m.get("env")) |n| {
        step.env = try parseStringMap(allocator, n);
    }

    return step;
}

fn parsePermissions(node: Node) ParseError!types.Permissions {
    switch (node) {
        .scalar => |s| {
            var perms = types.Permissions{};
            if (std.mem.eql(u8, s.value, "read-all")) {
                perms.read_all = true;
            } else if (std.mem.eql(u8, s.value, "write-all")) {
                perms.write_all = true;
            }
            return perms;
        },
        .mapping => |m| {
            var perms = types.Permissions{};
            for (m.entries) |entry| {
                const level = parsePermissionLevel(entry.value) orelse continue;
                setPermissionField(&perms, entry.key.value, level);
            }
            return perms;
        },
        else => return error.InvalidValue,
    }
}

fn parsePermissionLevel(node: Node) ?types.PermissionLevel {
    switch (node) {
        .scalar => |s| {
            if (std.mem.eql(u8, s.value, "read")) return .read;
            if (std.mem.eql(u8, s.value, "write")) return .write;
            if (std.mem.eql(u8, s.value, "none")) return .none;
            return null;
        },
        else => return null,
    }
}

fn setPermissionField(perms: *types.Permissions, key: []const u8, level: types.PermissionLevel) void {
    const fields = .{
        .{ "actions", &perms.actions },
        .{ "attestations", &perms.attestations },
        .{ "checks", &perms.checks },
        .{ "contents", &perms.contents },
        .{ "deployments", &perms.deployments },
        .{ "discussions", &perms.discussions },
        .{ "id-token", &perms.id_token },
        .{ "issues", &perms.issues },
        .{ "packages", &perms.packages },
        .{ "pages", &perms.pages },
        .{ "pull-requests", &perms.pull_requests },
        .{ "repository-projects", &perms.repository_projects },
        .{ "security-events", &perms.security_events },
        .{ "statuses", &perms.statuses },
    };
    inline for (fields) |f| {
        if (std.mem.eql(u8, key, f[0])) {
            f[1].* = level;
            return;
        }
    }
}

fn parseConcurrency(node: Node) ParseError!types.Concurrency {
    switch (node) {
        .scalar => |s| {
            return .{ .group = s.value };
        },
        .mapping => |m| {
            return .{
                .group = m.getScalar("group") orelse return error.MissingField,
                .cancel_in_progress = if (m.getScalar("cancel-in-progress")) |v|
                    std.mem.eql(u8, v, "true")
                else
                    false,
            };
        },
        else => return error.InvalidValue,
    }
}

fn parseStrategy(node: Node) ParseError!types.Strategy {
    const m = switch (node) {
        .mapping => |m| m,
        else => return error.InvalidValue,
    };

    var strategy = types.Strategy{};
    if (m.getScalar("fail-fast")) |v| {
        strategy.fail_fast = !std.mem.eql(u8, v, "false");
    }
    if (m.getScalar("max-parallel")) |v| {
        strategy.max_parallel = std.fmt.parseInt(u32, v, 10) catch null;
    }
    return strategy;
}

fn parseSecretsConfig(allocator: std.mem.Allocator, node: Node) ParseError!types.SecretsConfig {
    switch (node) {
        .scalar => |s| {
            if (std.mem.eql(u8, s.value, "inherit")) {
                return .{ .inherit = {} };
            }
            return error.InvalidValue;
        },
        .mapping => |m| {
            var map = types.StringMap.init(allocator);
            for (m.entries) |entry| {
                switch (entry.value) {
                    .scalar => |sv| try map.put(entry.key.value, sv.value),
                    else => {},
                }
            }
            return .{ .map = map };
        },
        else => return error.InvalidValue,
    }
}

fn parseCredentials(node: Node) ParseError!types.Credentials {
    const m = switch (node) {
        .mapping => |m| m,
        else => return error.InvalidValue,
    };
    return .{
        .username = m.getScalar("username"),
        .password = m.getScalar("password"),
    };
}

fn parseContainer(node: Node) ParseError!types.Container {
    switch (node) {
        .scalar => |s| {
            return .{ .image = s.value };
        },
        .mapping => |m| {
            return .{
                .image = m.getScalar("image"),
                .credentials = if (m.get("credentials")) |n| try parseCredentials(n) else null,
            };
        },
        else => return error.InvalidValue,
    }
}

fn parseServices(allocator: std.mem.Allocator, node: Node) ParseError![]const types.Service {
    const m = switch (node) {
        .mapping => |m| m,
        else => return error.InvalidValue,
    };

    const services = try allocator.alloc(types.Service, m.entries.len);
    for (m.entries, 0..) |entry, i| {
        switch (entry.value) {
            .mapping => |vm| {
                services[i] = .{
                    .name = entry.key.value,
                    .image = vm.getScalar("image"),
                    .credentials = if (vm.get("credentials")) |n| try parseCredentials(n) else null,
                };
            },
            .scalar => |s| {
                services[i] = .{
                    .name = entry.key.value,
                    .image = s.value,
                };
            },
            else => return error.InvalidValue,
        }
    }
    return services;
}

fn parseStringMap(allocator: std.mem.Allocator, node: Node) ParseError!types.StringMap {
    const m = switch (node) {
        .mapping => |m| m,
        else => return error.InvalidValue,
    };

    var map = types.StringMap.init(allocator);
    for (m.entries) |entry| {
        switch (entry.value) {
            .scalar => |s| try map.put(entry.key.value, s.value),
            else => {},
        }
    }
    return map;
}

fn parseStringArray(allocator: std.mem.Allocator, node: Node) ParseError![]const []const u8 {
    switch (node) {
        .sequence => |seq| {
            const result = try allocator.alloc([]const u8, seq.items.len);
            for (seq.items, 0..) |item, i| {
                switch (item) {
                    .scalar => |s| result[i] = s.value,
                    else => return error.InvalidValue,
                }
            }
            return result;
        },
        .scalar => |s| {
            const result = try allocator.alloc([]const u8, 1);
            result[0] = s.value;
            return result;
        },
        else => return error.InvalidValue,
    }
}

fn parseStringArrayOrSingle(allocator: std.mem.Allocator, node: Node) ParseError![]const []const u8 {
    return parseStringArray(allocator, node);
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;

fn mkSpan() yaml.Span {
    return yaml.Span.point(1, 1, 0);
}

fn mkScalar(value: []const u8) Node {
    return .{ .scalar = .{ .value = value, .style = .plain, .span = mkSpan() } };
}

fn mkScalarS(value: []const u8) yaml.Scalar {
    return .{ .value = value, .style = .plain, .span = mkSpan() };
}

fn mkMapping(entries: []yaml.MappingEntry) Node {
    return .{ .mapping = .{ .entries = entries, .span = mkSpan() } };
}

fn mkSequence(items: []Node) Node {
    return .{ .sequence = .{ .items = items, .span = mkSpan() } };
}

test "parseWorkflow minimal" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Build: { name: CI, on: push, jobs: { build: { runs-on: ubuntu-latest, steps: [{ run: echo hi }] } } }
    var step_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("run"), .value = mkScalar("echo hi"), .span = mkSpan() },
    };
    var step_items = [_]Node{mkMapping(&step_entries)};

    var job_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("runs-on"), .value = mkScalar("ubuntu-latest"), .span = mkSpan() },
        .{ .key = mkScalarS("steps"), .value = mkSequence(&step_items), .span = mkSpan() },
    };

    var jobs_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("build"), .value = mkMapping(&job_entries), .span = mkSpan() },
    };

    var root_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("name"), .value = mkScalar("CI"), .span = mkSpan() },
        .{ .key = mkScalarS("on"), .value = mkScalar("push"), .span = mkSpan() },
        .{ .key = mkScalarS("jobs"), .value = mkMapping(&jobs_entries), .span = mkSpan() },
    };

    const root = mkMapping(&root_entries);
    const wf = try parseWorkflow(alloc, root);

    try testing.expectEqualStrings("CI", wf.name.?);
    try testing.expectEqual(@as(usize, 1), wf.on.events.len);
    try testing.expectEqual(types.EventType.push, wf.on.events[0].event);
    try testing.expectEqual(@as(usize, 1), wf.jobs.len);
    try testing.expectEqualStrings("build", wf.jobs[0].id);
    try testing.expectEqualStrings("ubuntu-latest", wf.jobs[0].runs_on.?);
    try testing.expectEqual(@as(usize, 1), wf.jobs[0].steps.len);
    try testing.expectEqualStrings("echo hi", wf.jobs[0].steps[0].run.?);
}

test "parseWorkflow missing on" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var jobs_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("build"), .value = mkScalar("x"), .span = mkSpan() },
    };
    var root_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("jobs"), .value = mkMapping(&jobs_entries), .span = mkSpan() },
    };

    const root = mkMapping(&root_entries);
    try testing.expectError(error.MissingField, parseWorkflow(arena.allocator(), root));
}

test "parseWorkflow missing jobs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var root_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("on"), .value = mkScalar("push"), .span = mkSpan() },
    };

    const root = mkMapping(&root_entries);
    try testing.expectError(error.MissingField, parseWorkflow(arena.allocator(), root));
}

test "parseWorkflow not a mapping" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const root = mkScalar("not a workflow");
    try testing.expectError(error.InvalidValue, parseWorkflow(arena.allocator(), root));
}

test "parseTrigger scalar" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const trigger = try parseTrigger(arena.allocator(), mkScalar("push"));
    try testing.expectEqual(@as(usize, 1), trigger.events.len);
    try testing.expectEqual(types.EventType.push, trigger.events[0].event);
}

test "parseTrigger sequence" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var items = [_]Node{ mkScalar("push"), mkScalar("pull_request") };
    const trigger = try parseTrigger(arena.allocator(), mkSequence(&items));
    try testing.expectEqual(@as(usize, 2), trigger.events.len);
    try testing.expectEqual(types.EventType.push, trigger.events[0].event);
    try testing.expectEqual(types.EventType.pull_request, trigger.events[1].event);
}

test "parseTrigger mapping with filter" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var branch_items = [_]Node{mkScalar("main")};
    var push_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("branches"), .value = mkSequence(&branch_items), .span = mkSpan() },
    };
    var trigger_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("push"), .value = mkMapping(&push_entries), .span = mkSpan() },
    };

    const trigger = try parseTrigger(arena.allocator(), mkMapping(&trigger_entries));
    try testing.expectEqual(@as(usize, 1), trigger.events.len);
    try testing.expectEqual(types.EventType.push, trigger.events[0].event);
    try testing.expectEqual(@as(usize, 1), trigger.events[0].filter.?.branches.len);
    try testing.expectEqualStrings("main", trigger.events[0].filter.?.branches[0]);
}

test "parseTrigger schedule" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var cron_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("cron"), .value = mkScalar("0 0 * * *"), .span = mkSpan() },
    };
    var sched_items = [_]Node{mkMapping(&cron_entries)};
    var trigger_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("schedule"), .value = mkSequence(&sched_items), .span = mkSpan() },
    };

    const trigger = try parseTrigger(arena.allocator(), mkMapping(&trigger_entries));
    try testing.expectEqual(@as(usize, 1), trigger.events.len);
    try testing.expectEqual(@as(usize, 1), trigger.events[0].schedule.len);
    try testing.expectEqualStrings("0 0 * * *", trigger.events[0].schedule[0].cron);
}

test "parsePermissions read-all" {
    const perms = try parsePermissions(mkScalar("read-all"));
    try testing.expect(perms.read_all);
    try testing.expect(!perms.write_all);
}

test "parsePermissions write-all" {
    const perms = try parsePermissions(mkScalar("write-all"));
    try testing.expect(perms.write_all);
    try testing.expect(!perms.read_all);
}

test "parsePermissions individual scopes" {
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("contents"), .value = mkScalar("read"), .span = mkSpan() },
        .{ .key = mkScalarS("pull-requests"), .value = mkScalar("write"), .span = mkSpan() },
        .{ .key = mkScalarS("issues"), .value = mkScalar("none"), .span = mkSpan() },
    };

    const perms = try parsePermissions(mkMapping(&entries));
    try testing.expectEqual(types.PermissionLevel.read, perms.contents.?);
    try testing.expectEqual(types.PermissionLevel.write, perms.pull_requests.?);
    try testing.expectEqual(types.PermissionLevel.none, perms.issues.?);
    try testing.expect(perms.actions == null);
}

test "parseConcurrency scalar" {
    const c = try parseConcurrency(mkScalar("ci-group"));
    try testing.expectEqualStrings("ci-group", c.group);
    try testing.expect(!c.cancel_in_progress);
}

test "parseConcurrency mapping" {
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("group"), .value = mkScalar("ci"), .span = mkSpan() },
        .{ .key = mkScalarS("cancel-in-progress"), .value = mkScalar("true"), .span = mkSpan() },
    };

    const c = try parseConcurrency(mkMapping(&entries));
    try testing.expectEqualStrings("ci", c.group);
    try testing.expect(c.cancel_in_progress);
}

test "parseStep with uses" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("name"), .value = mkScalar("Checkout"), .span = mkSpan() },
        .{ .key = mkScalarS("uses"), .value = mkScalar("actions/checkout@v4"), .span = mkSpan() },
    };

    const step = try parseStep(arena.allocator(), mkMapping(&entries));
    try testing.expectEqualStrings("Checkout", step.name.?);
    try testing.expectEqualStrings("actions", step.uses.?.owner.?);
    try testing.expectEqualStrings("checkout", step.uses.?.repo.?);
}

test "parseStep with run" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("name"), .value = mkScalar("Build"), .span = mkSpan() },
        .{ .key = mkScalarS("run"), .value = mkScalar("make build"), .span = mkSpan() },
        .{ .key = mkScalarS("shell"), .value = mkScalar("bash"), .span = mkSpan() },
    };

    const step = try parseStep(arena.allocator(), mkMapping(&entries));
    try testing.expectEqualStrings("make build", step.run.?);
    try testing.expectEqualStrings("bash", step.shell.?);
}

test "parseJob with needs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var step_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("run"), .value = mkScalar("echo"), .span = mkSpan() },
    };
    var step_items = [_]Node{mkMapping(&step_entries)};

    var needs_items = [_]Node{ mkScalar("build"), mkScalar("lint") };

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("runs-on"), .value = mkScalar("ubuntu-latest"), .span = mkSpan() },
        .{ .key = mkScalarS("needs"), .value = mkSequence(&needs_items), .span = mkSpan() },
        .{ .key = mkScalarS("steps"), .value = mkSequence(&step_items), .span = mkSpan() },
    };

    const job = try parseJob(arena.allocator(), "deploy", mkMapping(&entries));
    try testing.expectEqualStrings("deploy", job.id);
    try testing.expectEqual(@as(usize, 2), job.needs.len);
    try testing.expectEqualStrings("build", job.needs[0]);
    try testing.expectEqualStrings("lint", job.needs[1]);
}

test "parseJob reusable workflow" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("uses"), .value = mkScalar("octo-org/this-repo/.github/workflows/workflow-1.yml@v1"), .span = mkSpan() },
        .{ .key = mkScalarS("secrets"), .value = mkScalar("inherit"), .span = mkSpan() },
    };

    const job = try parseJob(arena.allocator(), "call-workflow", mkMapping(&entries));
    try testing.expectEqualStrings("octo-org/this-repo/.github/workflows/workflow-1.yml@v1", job.uses.?);
    switch (job.secrets.?) {
        .inherit => {},
        .map => unreachable,
    }
}

test "parseStringMap" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("FOO"), .value = mkScalar("bar"), .span = mkSpan() },
        .{ .key = mkScalarS("BAZ"), .value = mkScalar("qux"), .span = mkSpan() },
    };

    const map = try parseStringMap(arena.allocator(), mkMapping(&entries));
    try testing.expectEqualStrings("bar", map.get("FOO").?);
    try testing.expectEqualStrings("qux", map.get("BAZ").?);
}

test "parseWorkflow with env and concurrency" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var step_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("run"), .value = mkScalar("echo"), .span = mkSpan() },
    };
    var step_items = [_]Node{mkMapping(&step_entries)};

    var job_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("runs-on"), .value = mkScalar("ubuntu-latest"), .span = mkSpan() },
        .{ .key = mkScalarS("steps"), .value = mkSequence(&step_items), .span = mkSpan() },
    };
    var jobs_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("build"), .value = mkMapping(&job_entries), .span = mkSpan() },
    };

    var env_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("CI"), .value = mkScalar("true"), .span = mkSpan() },
    };

    var root_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("on"), .value = mkScalar("push"), .span = mkSpan() },
        .{ .key = mkScalarS("jobs"), .value = mkMapping(&jobs_entries), .span = mkSpan() },
        .{ .key = mkScalarS("env"), .value = mkMapping(&env_entries), .span = mkSpan() },
        .{ .key = mkScalarS("concurrency"), .value = mkScalar("my-group"), .span = mkSpan() },
    };

    const wf = try parseWorkflow(arena.allocator(), mkMapping(&root_entries));
    try testing.expectEqualStrings("true", wf.env.?.get("CI").?);
    try testing.expectEqualStrings("my-group", wf.concurrency.?.group);
}

test "parseJob with container as scalar" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var step_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("run"), .value = mkScalar("echo"), .span = mkSpan() },
    };
    var step_items = [_]Node{mkMapping(&step_entries)};

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("runs-on"), .value = mkScalar("ubuntu-latest"), .span = mkSpan() },
        .{ .key = mkScalarS("steps"), .value = mkSequence(&step_items), .span = mkSpan() },
        .{ .key = mkScalarS("container"), .value = mkScalar("node:14"), .span = mkSpan() },
    };

    const job = try parseJob(arena.allocator(), "build", mkMapping(&entries));
    try testing.expectEqualStrings("node:14", job.container.?.image.?);
    try testing.expect(job.container.?.credentials == null);
}

test "parseJob with container credentials" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var step_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("run"), .value = mkScalar("echo"), .span = mkSpan() },
    };
    var step_items = [_]Node{mkMapping(&step_entries)};

    var cred_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("username"), .value = mkScalar("myuser"), .span = mkSpan() },
        .{ .key = mkScalarS("password"), .value = mkScalar("mypassword"), .span = mkSpan() },
    };
    var container_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("image"), .value = mkScalar("node:14"), .span = mkSpan() },
        .{ .key = mkScalarS("credentials"), .value = mkMapping(&cred_entries), .span = mkSpan() },
    };

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("runs-on"), .value = mkScalar("ubuntu-latest"), .span = mkSpan() },
        .{ .key = mkScalarS("steps"), .value = mkSequence(&step_items), .span = mkSpan() },
        .{ .key = mkScalarS("container"), .value = mkMapping(&container_entries), .span = mkSpan() },
    };

    const job = try parseJob(arena.allocator(), "build", mkMapping(&entries));
    try testing.expectEqualStrings("node:14", job.container.?.image.?);
    try testing.expectEqualStrings("myuser", job.container.?.credentials.?.username.?);
    try testing.expectEqualStrings("mypassword", job.container.?.credentials.?.password.?);
}

test "parseJob with service credentials" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var step_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("run"), .value = mkScalar("echo"), .span = mkSpan() },
    };
    var step_items = [_]Node{mkMapping(&step_entries)};

    var cred_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("username"), .value = mkScalar("${{ secrets.REDIS_USER }}"), .span = mkSpan() },
        .{ .key = mkScalarS("password"), .value = mkScalar("${{ secrets.REDIS_PASS }}"), .span = mkSpan() },
    };
    var svc_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("image"), .value = mkScalar("redis"), .span = mkSpan() },
        .{ .key = mkScalarS("credentials"), .value = mkMapping(&cred_entries), .span = mkSpan() },
    };
    var services_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("redis"), .value = mkMapping(&svc_entries), .span = mkSpan() },
    };

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("runs-on"), .value = mkScalar("ubuntu-latest"), .span = mkSpan() },
        .{ .key = mkScalarS("steps"), .value = mkSequence(&step_items), .span = mkSpan() },
        .{ .key = mkScalarS("services"), .value = mkMapping(&services_entries), .span = mkSpan() },
    };

    const job = try parseJob(arena.allocator(), "build", mkMapping(&entries));
    try testing.expectEqual(@as(usize, 1), job.services.len);
    try testing.expectEqualStrings("redis", job.services[0].name);
    try testing.expectEqualStrings("redis", job.services[0].image.?);
    try testing.expectEqualStrings("${{ secrets.REDIS_USER }}", job.services[0].credentials.?.username.?);
    try testing.expectEqualStrings("${{ secrets.REDIS_PASS }}", job.services[0].credentials.?.password.?);
}
