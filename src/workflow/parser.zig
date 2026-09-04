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

const ParsedStringMap = struct {
    values: types.StringMap,
    meta: types.ScalarValueMetaMap,
};

const ParsedPermissions = struct {
    permissions: types.Permissions,
    meta: ?types.PermissionsMeta,
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

    var workflow = types.Workflow{
        .name = root.getScalar("name"),
        .on = trigger,
        .concurrency = if (root.get("concurrency")) |n| try parseConcurrency(n) else null,
        .jobs = jobs,
        .yaml_root = node,
    };

    if (root.get("permissions")) |n| {
        const parsed = try parsePermissions(n);
        workflow.permissions = parsed.permissions;
        workflow.permissions_meta = parsed.meta;
    }

    if (root.get("env")) |n| {
        const parsed = try parseStringMapWithMeta(allocator, n);
        workflow.env = parsed.values;
        workflow.env_meta = parsed.meta;
    }

    // Compute insertion anchors for top-level `permissions:` / `concurrency:`
    // directly after the `on:` entry line.
    for (root.entries) |entry| {
        const name = entry.key.value;
        if (std.mem.eql(u8, name, "on") or std.mem.eql(u8, name, "true")) {
            if (entry.full_span) |fs| {
                workflow.permissions_insertion_byte = fs.end_byte;
                workflow.concurrency_insertion_byte = fs.end_byte;
            }
            break;
        }
    }

    return workflow;
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
        .spans = .{
            .branches = m.getKeySpan("branches"),
            .branches_ignore = m.getKeySpan("branches-ignore"),
            .tags = m.getKeySpan("tags"),
            .tags_ignore = m.getKeySpan("tags-ignore"),
            .paths = m.getKeySpan("paths"),
            .paths_ignore = m.getKeySpan("paths-ignore"),
        },
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
    job.span = m.span;
    job.job_indent = m.span.start_col;
    job.name = m.getScalar("name");
    job.runs_on = m.getScalar("runs-on");
    if (m.get("runs-on")) |n| {
        switch (n) {
            .scalar => |s| job.runs_on_value_span = s.span,
            else => {},
        }
    }
    job.if_condition = m.getScalar("if");
    if (m.get("if")) |n| {
        switch (n) {
            .scalar => |s| job.if_condition_meta = .{ .value_span = s.span, .style = s.style },
            else => {},
        }
    }
    job.uses = m.getScalar("uses");

    // Insertion anchor for job-level `permissions:` / `concurrency:` lands after
    // the `runs-on:` line; `uses:` (reusable workflow) works as a fallback.
    for (m.entries) |entry| {
        const name = entry.key.value;
        if (std.mem.eql(u8, name, "runs-on") or std.mem.eql(u8, name, "uses")) {
            if (entry.full_span) |fs| {
                if (job.permissions_insertion_byte == null) {
                    job.permissions_insertion_byte = fs.end_byte;
                }
                if (job.concurrency_insertion_byte == null) {
                    job.concurrency_insertion_byte = fs.end_byte;
                }
            }
        }
    }

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
        const parsed = try parsePermissions(n);
        job.permissions = parsed.permissions;
        job.permissions_meta = parsed.meta;
    }
    if (m.get("env")) |n| {
        const parsed = try parseStringMapWithMeta(allocator, n);
        job.env = parsed.values;
        job.env_meta = parsed.meta;
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
    step.span = m.span;
    step.id = m.getScalar("id");
    step.name = m.getScalar("name");
    step.run = m.getScalar("run");
    step.shell = m.getScalar("shell");
    step.if_condition = m.getScalar("if");
    if (m.get("if")) |n| {
        switch (n) {
            .scalar => |s| step.if_condition_meta = .{ .value_span = s.span, .style = s.style },
            else => {},
        }
    }
    step.working_directory = m.getScalar("working-directory");

    // Capture `run:` value span and the insertion anchor for a sibling `shell:`.
    for (m.entries) |entry| {
        if (!std.mem.eql(u8, entry.key.value, "run")) continue;
        switch (entry.value) {
            .scalar => |s| step.run_value_span = s.span,
            else => {},
        }
        if (entry.full_span) |fs| {
            step.shell_insertion_byte = fs.end_byte;
        }
        break;
    }

    // Insertion anchor for a new entry at the end of the step mapping.
    if (m.entries.len > 0) {
        const last = m.entries[m.entries.len - 1];
        if (last.full_span) |fs| {
            step.env_insertion_byte = fs.end_byte;
        }
    }

    // Parse uses: and capture span info for autofix
    if (m.get("uses")) |uses_node| {
        switch (uses_node) {
            .scalar => |s| {
                step.uses = types.ActionRef.parse(s.value);
                step.uses_value_end_byte = s.span.end_byte;
                step.uses_value_style = s.style;
            },
            else => {},
        }
        for (m.entries, 0..) |entry, idx| {
            if (std.mem.eql(u8, entry.key.value, "uses")) {
                step.uses_key_col = entry.key.span.start_col;
                // Only capture insertion anchor when `uses` is the first key in the
                // step mapping; BP002 autofix inserts `name:` before this anchor and
                // must land at the step head.
                if (idx == 0) {
                    step.uses_key_start_byte = entry.key.span.start_byte;
                }
                break;
            }
        }
    }
    if (m.getScalar("timeout-minutes")) |t| {
        step.timeout_minutes = std.fmt.parseInt(u32, t, 10) catch null;
    }
    if (m.getScalar("continue-on-error")) |v| {
        step.continue_on_error = std.mem.eql(u8, v, "true");
    }
    // Parse with: and capture last entry's value end byte for autofix
    if (m.get("with")) |with_node| {
        step.with = try parseStringMap(allocator, with_node);
        switch (with_node) {
            .mapping => |with_mapping| {
                if (with_mapping.entries.len > 0) {
                    const last = with_mapping.entries[with_mapping.entries.len - 1];
                    step.with_last_entry_end_byte = last.value.getSpan().end_byte;
                }
            },
            else => {},
        }
    }
    if (m.get("env")) |n| {
        const parsed = try parseStringMapWithMeta(allocator, n);
        step.env = parsed.values;
        step.env_meta = parsed.meta;
    }

    return step;
}

fn parsePermissions(node: Node) ParseError!ParsedPermissions {
    switch (node) {
        .scalar => |s| {
            var perms = types.Permissions{ .value_span = s.span };
            if (std.mem.eql(u8, s.value, "read-all")) {
                perms.read_all = true;
            } else if (std.mem.eql(u8, s.value, "write-all")) {
                perms.write_all = true;
            }
            return .{ .permissions = perms, .meta = null };
        },
        .mapping => |m| {
            var perms = types.Permissions{ .value_span = m.span };
            var meta = types.PermissionsMeta{};
            for (m.entries) |entry| {
                const level = parsePermissionLevel(entry.value) orelse continue;
                setPermissionField(&perms, entry.key.value, level);
                setPermissionMetaField(&meta, entry.key.value, entry.value);
            }
            return .{ .permissions = perms, .meta = meta };
        },
        else => return error.InvalidValue,
    }
}

fn setPermissionMetaField(meta: *types.PermissionsMeta, key: []const u8, value: Node) void {
    const scalar_span: yaml.Span = switch (value) {
        .scalar => |s| s.span,
        else => return,
    };
    const fields = .{
        .{ "actions", &meta.actions },
        .{ "attestations", &meta.attestations },
        .{ "checks", &meta.checks },
        .{ "contents", &meta.contents },
        .{ "deployments", &meta.deployments },
        .{ "discussions", &meta.discussions },
        .{ "id-token", &meta.id_token },
        .{ "issues", &meta.issues },
        .{ "packages", &meta.packages },
        .{ "pages", &meta.pages },
        .{ "pull-requests", &meta.pull_requests },
        .{ "repository-projects", &meta.repository_projects },
        .{ "security-events", &meta.security_events },
        .{ "statuses", &meta.statuses },
    };
    inline for (fields) |f| {
        if (std.mem.eql(u8, key, f[0])) {
            f[1].* = scalar_span;
            return;
        }
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
    for (m.entries) |entry| {
        if (std.mem.eql(u8, entry.key.value, "fail-fast")) {
            switch (entry.value) {
                .scalar => |s| {
                    strategy.fail_fast = !std.mem.eql(u8, s.value, "false");
                    strategy.fail_fast_value_span = s.span;
                    strategy.fail_fast_entry_span = entry.full_span;
                },
                else => {},
            }
        } else if (std.mem.eql(u8, entry.key.value, "max-parallel")) {
            switch (entry.value) {
                .scalar => |s| {
                    strategy.max_parallel = std.fmt.parseInt(u32, s.value, 10) catch null;
                },
                else => {},
            }
        }
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

fn parseStringMapWithMeta(allocator: std.mem.Allocator, node: Node) ParseError!ParsedStringMap {
    const m = switch (node) {
        .mapping => |m| m,
        else => return error.InvalidValue,
    };

    var values = types.StringMap.init(allocator);
    var meta = types.ScalarValueMetaMap.init(allocator);
    for (m.entries) |entry| {
        switch (entry.value) {
            .scalar => |s| {
                try values.put(entry.key.value, s.value);
                try meta.put(entry.key.value, .{
                    .value_span = s.span,
                    .style = s.style,
                });
            },
            else => {},
        }
    }
    return .{ .values = values, .meta = meta };
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

fn mkSpanBytes(start_byte: usize, end_byte: usize) yaml.Span {
    return .{
        .start_line = 1,
        .start_col = 1,
        .end_line = 1,
        .end_col = 1,
        .start_byte = start_byte,
        .end_byte = end_byte,
    };
}

fn mkScalar(value: []const u8) Node {
    return .{ .scalar = .{ .value = value, .style = .plain, .span = mkSpan() } };
}

fn mkScalarStyled(value: []const u8, style: yaml.ScalarStyle, span: yaml.Span) Node {
    return .{ .scalar = .{ .value = value, .style = style, .span = span } };
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
    try testing.expect(trigger.events[0].filter.?.spans.branches != null);
    try testing.expect(trigger.events[0].filter.?.spans.branches_ignore == null);
}

test "parseTrigger records key spans for empty filter values" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // `paths-ignore:` with no items still counts as present.
    var empty_items = [_]Node{};
    var push_entries = [_]yaml.MappingEntry{
        .{ .key = .{ .value = "paths-ignore", .style = .plain, .span = mkSpanBytes(20, 32) }, .value = mkSequence(&empty_items), .span = mkSpan() },
    };
    var trigger_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("push"), .value = mkMapping(&push_entries), .span = mkSpan() },
    };

    const trigger = try parseTrigger(arena.allocator(), mkMapping(&trigger_entries));
    const spans = trigger.events[0].filter.?.spans;
    try testing.expectEqual(@as(usize, 0), trigger.events[0].filter.?.paths_ignore.len);
    try testing.expectEqual(@as(usize, 20), (spans.paths_ignore orelse return error.TestUnexpectedResult).start_byte);
    try testing.expect(spans.paths == null);
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
    const parsed = try parsePermissions(mkScalar("read-all"));
    try testing.expect(parsed.permissions.read_all);
    try testing.expect(!parsed.permissions.write_all);
    try testing.expect(parsed.meta == null);
}

test "parsePermissions write-all" {
    const parsed = try parsePermissions(mkScalar("write-all"));
    try testing.expect(parsed.permissions.write_all);
    try testing.expect(!parsed.permissions.read_all);
    try testing.expect(parsed.meta == null);
}

test "parsePermissions individual scopes" {
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("contents"), .value = mkScalar("read"), .span = mkSpan() },
        .{ .key = mkScalarS("pull-requests"), .value = mkScalar("write"), .span = mkSpan() },
        .{ .key = mkScalarS("issues"), .value = mkScalar("none"), .span = mkSpan() },
    };

    const parsed = try parsePermissions(mkMapping(&entries));
    try testing.expectEqual(types.PermissionLevel.read, parsed.permissions.contents.?);
    try testing.expectEqual(types.PermissionLevel.write, parsed.permissions.pull_requests.?);
    try testing.expectEqual(types.PermissionLevel.none, parsed.permissions.issues.?);
    try testing.expect(parsed.permissions.actions == null);
    const meta = parsed.meta orelse return error.TestExpectedNonNull;
    try testing.expect(meta.contents != null);
    try testing.expect(meta.pull_requests != null);
    try testing.expect(meta.issues != null);
    try testing.expect(meta.actions == null);
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

test "parseStringMapWithMeta" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var entries = [_]yaml.MappingEntry{
        .{
            .key = mkScalarS("PLAIN"),
            .value = mkScalarStyled("true", .plain, mkSpanBytes(10, 14)),
            .span = mkSpan(),
        },
        .{
            .key = mkScalarS("QUOTED"),
            .value = mkScalarStyled("true", .double_quoted, mkSpanBytes(20, 26)),
            .span = mkSpan(),
        },
    };

    const parsed = try parseStringMapWithMeta(arena.allocator(), mkMapping(&entries));
    try testing.expectEqualStrings("true", parsed.values.get("PLAIN").?);
    try testing.expectEqualStrings("true", parsed.values.get("QUOTED").?);
    try testing.expectEqual(yaml.ScalarStyle.plain, parsed.meta.get("PLAIN").?.style);
    try testing.expectEqual(yaml.ScalarStyle.double_quoted, parsed.meta.get("QUOTED").?.style);
    try testing.expectEqual(@as(usize, 10), parsed.meta.get("PLAIN").?.value_span.start_byte);
    try testing.expectEqual(@as(usize, 26), parsed.meta.get("QUOTED").?.value_span.end_byte);
}

test "parseStrategy with fail-fast and max-parallel" {
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("fail-fast"), .value = mkScalar("false"), .span = mkSpan() },
        .{ .key = mkScalarS("max-parallel"), .value = mkScalar("2"), .span = mkSpan() },
    };

    const strategy = try parseStrategy(mkMapping(&entries));
    try testing.expect(!strategy.fail_fast);
    try testing.expectEqual(@as(?u32, 2), strategy.max_parallel);
}

test "parseWorkflow captures removable span for fail-fast entry" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      fail-fast: "false" # keep running
        \\      max-parallel: 2
        \\    steps:
        \\      - run: echo test
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try parseWorkflow(alloc, yaml_node);

    const strategy = wf.jobs[0].strategy.?;
    const value_span = strategy.fail_fast_value_span.?;
    const entry_span = strategy.fail_fast_entry_span.?;

    try testing.expect(!strategy.fail_fast);
    try testing.expectEqualStrings("\"false\"", source[value_span.start_byte..value_span.end_byte]);
    try testing.expectEqualStrings(
        "      fail-fast: \"false\" # keep running\n",
        source[entry_span.start_byte..entry_span.end_byte],
    );
}

test "parseJob captures runs_on_value_span for scalar runs-on" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-20.04
        \\    steps:
        \\      - run: echo hi
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try parseWorkflow(alloc, yaml_node);

    const span = wf.jobs[0].runs_on_value_span.?;
    try testing.expectEqualStrings("ubuntu-20.04", source[span.start_byte..span.end_byte]);
}

test "parseJob leaves runs_on_value_span null for missing runs-on" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: workflow_call
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try parseWorkflow(alloc, yaml_node);

    try testing.expect(wf.jobs[0].runs_on_value_span == null);
}

test "parseStep with timeout and continue-on-error" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var with_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("key"), .value = mkScalar("value"), .span = mkSpan() },
    };
    var env_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("FOO"), .value = mkScalar("bar"), .span = mkSpan() },
    };

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("run"), .value = mkScalar("echo test"), .span = mkSpan() },
        .{ .key = mkScalarS("timeout-minutes"), .value = mkScalar("10"), .span = mkSpan() },
        .{ .key = mkScalarS("continue-on-error"), .value = mkScalar("true"), .span = mkSpan() },
        .{ .key = mkScalarS("if"), .value = mkScalar("always()"), .span = mkSpan() },
        .{ .key = mkScalarS("id"), .value = mkScalar("step1"), .span = mkSpan() },
        .{ .key = mkScalarS("working-directory"), .value = mkScalar("./src"), .span = mkSpan() },
        .{ .key = mkScalarS("with"), .value = mkMapping(&with_entries), .span = mkSpan() },
        .{ .key = mkScalarS("env"), .value = mkMapping(&env_entries), .span = mkSpan() },
    };

    const step = try parseStep(arena.allocator(), mkMapping(&entries));
    try testing.expectEqual(@as(?u32, 10), step.timeout_minutes);
    try testing.expect(step.continue_on_error);
    try testing.expectEqualStrings("always()", step.if_condition.?);
    try testing.expectEqualStrings("step1", step.id.?);
    try testing.expectEqualStrings("./src", step.working_directory.?);
    try testing.expectEqualStrings("value", step.with.?.get("key").?);
    try testing.expectEqualStrings("bar", step.env.?.get("FOO").?);
    try testing.expect(step.env_meta != null);
    try testing.expectEqual(yaml.ScalarStyle.plain, step.env_meta.?.get("FOO").?.style);
}

test "parseJob with timeout and strategy" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var step_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("run"), .value = mkScalar("echo"), .span = mkSpan() },
    };
    var step_items = [_]Node{mkMapping(&step_entries)};

    var strategy_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("fail-fast"), .value = mkScalar("true"), .span = mkSpan() },
    };

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("runs-on"), .value = mkScalar("ubuntu-latest"), .span = mkSpan() },
        .{ .key = mkScalarS("steps"), .value = mkSequence(&step_items), .span = mkSpan() },
        .{ .key = mkScalarS("timeout-minutes"), .value = mkScalar("30"), .span = mkSpan() },
        .{ .key = mkScalarS("continue-on-error"), .value = mkScalar("true"), .span = mkSpan() },
        .{ .key = mkScalarS("if"), .value = mkScalar("success()"), .span = mkSpan() },
        .{ .key = mkScalarS("strategy"), .value = mkMapping(&strategy_entries), .span = mkSpan() },
    };

    const job = try parseJob(arena.allocator(), "test", mkMapping(&entries));
    try testing.expectEqual(@as(?u32, 30), job.timeout_minutes);
    try testing.expect(job.continue_on_error);
    try testing.expectEqualStrings("success()", job.if_condition.?);
    try testing.expect(job.strategy.?.fail_fast);
}

test "parseStep captures if_condition_meta" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // Simulate `if: contains(github.ref, 'main')` where the value starts at byte 4.
    const if_value_span = mkSpanBytes(4, 32);
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("run"), .value = mkScalar("echo"), .span = mkSpan() },
        .{
            .key = mkScalarS("if"),
            .value = mkScalarStyled("contains(github.ref, 'main')", .plain, if_value_span),
            .span = mkSpan(),
        },
    };

    const step = try parseStep(arena.allocator(), mkMapping(&entries));
    try testing.expect(step.if_condition_meta != null);
    try testing.expectEqual(@as(usize, 4), step.if_condition_meta.?.value_span.start_byte);
    try testing.expectEqual(@as(usize, 32), step.if_condition_meta.?.value_span.end_byte);
    try testing.expectEqual(yaml.ScalarStyle.plain, step.if_condition_meta.?.style);
}

test "parseJob captures if_condition_meta with double-quoted style" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var step_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("run"), .value = mkScalar("echo"), .span = mkSpan() },
    };
    var step_items = [_]Node{mkMapping(&step_entries)};

    const if_value_span = mkSpanBytes(10, 50);
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("runs-on"), .value = mkScalar("ubuntu-latest"), .span = mkSpan() },
        .{ .key = mkScalarS("steps"), .value = mkSequence(&step_items), .span = mkSpan() },
        .{
            .key = mkScalarS("if"),
            .value = mkScalarStyled("${{ contains(github.ref, 'main') }}", .double_quoted, if_value_span),
            .span = mkSpan(),
        },
    };

    const job = try parseJob(arena.allocator(), "test", mkMapping(&entries));
    try testing.expect(job.if_condition_meta != null);
    try testing.expectEqual(@as(usize, 10), job.if_condition_meta.?.value_span.start_byte);
    try testing.expectEqual(yaml.ScalarStyle.double_quoted, job.if_condition_meta.?.style);
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
    try testing.expect(wf.env_meta != null);
    try testing.expectEqual(yaml.ScalarStyle.plain, wf.env_meta.?.get("CI").?.style);
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

test "parseEventConfig with workflow_dispatch inputs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var input_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("description"), .value = mkScalar("The name"), .span = mkSpan() },
        .{ .key = mkScalarS("required"), .value = mkScalar("true"), .span = mkSpan() },
        .{ .key = mkScalarS("default"), .value = mkScalar("hello"), .span = mkSpan() },
        .{ .key = mkScalarS("type"), .value = mkScalar("string"), .span = mkSpan() },
    };
    var inputs_map_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("name"), .value = mkMapping(&input_entries), .span = mkSpan() },
    };
    var wd_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("inputs"), .value = mkMapping(&inputs_map_entries), .span = mkSpan() },
    };

    const config = try parseEventConfig(alloc, "workflow_dispatch", mkMapping(&wd_entries));
    try testing.expectEqual(types.EventType.workflow_dispatch, config.event);
    try testing.expect(config.workflow_dispatch != null);
    try testing.expectEqual(@as(usize, 1), config.workflow_dispatch.?.inputs.?.count());
    const input_def = config.workflow_dispatch.?.inputs.?.get("name").?;
    try testing.expect(input_def.required);
    try testing.expectEqualStrings("The name", input_def.description.?);
    try testing.expectEqualStrings("hello", input_def.default.?);
    try testing.expectEqualStrings("string", input_def.input_type.?);
}

test "parseEventConfig with workflow_call" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var input_def_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("description"), .value = mkScalar("An input"), .span = mkSpan() },
    };
    var inputs_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("my-input"), .value = mkMapping(&input_def_entries), .span = mkSpan() },
    };
    var output_def_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("description"), .value = mkScalar("An output"), .span = mkSpan() },
        .{ .key = mkScalarS("value"), .value = mkScalar("${{ jobs.build.outputs.result }}"), .span = mkSpan() },
    };
    var outputs_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("my-output"), .value = mkMapping(&output_def_entries), .span = mkSpan() },
    };
    var secret_def_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("description"), .value = mkScalar("A secret"), .span = mkSpan() },
        .{ .key = mkScalarS("required"), .value = mkScalar("true"), .span = mkSpan() },
    };
    var secrets_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("my-secret"), .value = mkMapping(&secret_def_entries), .span = mkSpan() },
    };
    var wc_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("inputs"), .value = mkMapping(&inputs_entries), .span = mkSpan() },
        .{ .key = mkScalarS("outputs"), .value = mkMapping(&outputs_entries), .span = mkSpan() },
        .{ .key = mkScalarS("secrets"), .value = mkMapping(&secrets_entries), .span = mkSpan() },
    };

    const config = try parseEventConfig(alloc, "workflow_call", mkMapping(&wc_entries));
    try testing.expect(config.workflow_call != null);
    const wc = config.workflow_call.?;
    try testing.expectEqual(@as(usize, 1), wc.inputs.?.count());
    try testing.expectEqual(@as(usize, 1), wc.outputs.?.count());
    try testing.expectEqual(@as(usize, 1), wc.secrets.?.count());
    try testing.expectEqualStrings("An output", wc.outputs.?.get("my-output").?.description.?);
    try testing.expect(wc.secrets.?.get("my-secret").?.required);
}

test "parseEventConfig with null value (empty event)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const config = try parseEventConfig(arena.allocator(), "push", .{ .null_value = mkSpan() });
    try testing.expectEqual(types.EventType.push, config.event);
    try testing.expectEqualStrings("push", config.name);
}

test "parseSecretsConfig with mapping" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("TOKEN"), .value = mkScalar("${{ secrets.MY_TOKEN }}"), .span = mkSpan() },
    };

    const config = try parseSecretsConfig(arena.allocator(), mkMapping(&entries));
    switch (config) {
        .map => |m| try testing.expectEqualStrings("${{ secrets.MY_TOKEN }}", m.get("TOKEN").?),
        .inherit => unreachable,
    }
}

test "parseWorkflow with permissions" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

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
        .{ .key = mkScalarS("on"), .value = mkScalar("push"), .span = mkSpan() },
        .{ .key = mkScalarS("jobs"), .value = mkMapping(&jobs_entries), .span = mkSpan() },
        .{ .key = mkScalarS("permissions"), .value = mkScalar("read-all"), .span = mkSpan() },
    };

    const wf = try parseWorkflow(arena.allocator(), mkMapping(&root_entries));
    try testing.expect(wf.permissions != null);
    try testing.expect(wf.permissions.?.read_all);
}

test "ActionRef.parse without ref (no @)" {
    const ref = types.ActionRef.parse("actions/checkout");
    try testing.expectEqualStrings("actions", ref.owner.?);
    try testing.expectEqualStrings("checkout", ref.repo.?);
    try testing.expect(ref.ref == null);
    try testing.expect(!ref.is_pinned);
}

test "ActionRef.parse bare name (no slash)" {
    const ref = types.ActionRef.parse("checkout");
    try testing.expect(ref.owner == null);
    try testing.expect(ref.repo == null);
    try testing.expect(ref.ref == null);
}

test "parseJob with env and concurrency and with" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var step_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("run"), .value = mkScalar("echo"), .span = mkSpan() },
    };
    var step_items = [_]Node{mkMapping(&step_entries)};
    var env_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("CI"), .value = mkScalar("true"), .span = mkSpan() },
    };
    var with_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("key"), .value = mkScalar("val"), .span = mkSpan() },
    };
    var perm_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("contents"), .value = mkScalar("read"), .span = mkSpan() },
    };

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("runs-on"), .value = mkScalar("ubuntu-latest"), .span = mkSpan() },
        .{ .key = mkScalarS("steps"), .value = mkSequence(&step_items), .span = mkSpan() },
        .{ .key = mkScalarS("env"), .value = mkMapping(&env_entries), .span = mkSpan() },
        .{ .key = mkScalarS("with"), .value = mkMapping(&with_entries), .span = mkSpan() },
        .{ .key = mkScalarS("concurrency"), .value = mkScalar("my-group"), .span = mkSpan() },
        .{ .key = mkScalarS("permissions"), .value = mkMapping(&perm_entries), .span = mkSpan() },
    };

    const job = try parseJob(arena.allocator(), "test", mkMapping(&entries));
    try testing.expectEqualStrings("true", job.env.?.get("CI").?);
    try testing.expect(job.env_meta != null);
    try testing.expectEqual(yaml.ScalarStyle.plain, job.env_meta.?.get("CI").?.style);
    try testing.expectEqualStrings("val", job.with.?.get("key").?);
    try testing.expectEqualStrings("my-group", job.concurrency.?.group);
    try testing.expect(job.permissions != null);
    try testing.expectEqual(types.PermissionLevel.read, job.permissions.?.contents.?);
}

test "parsePermissions ignores invalid permission level" {
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("contents"), .value = mkScalar("execute"), .span = mkSpan() },
        .{ .key = mkScalarS("issues"), .value = mkScalar("admin"), .span = mkSpan() },
        .{ .key = mkScalarS("pull-requests"), .value = mkScalar("read"), .span = mkSpan() },
    };

    const parsed = try parsePermissions(mkMapping(&entries));
    // Invalid levels should be skipped (orelse continue)
    try testing.expect(parsed.permissions.contents == null);
    try testing.expect(parsed.permissions.issues == null);
    // Valid level should be set
    try testing.expectEqual(types.PermissionLevel.read, parsed.permissions.pull_requests.?);
}

test "parsePermissions with empty mapping" {
    var entries = [_]yaml.MappingEntry{};
    const parsed = try parsePermissions(mkMapping(&entries));
    try testing.expect(!parsed.permissions.read_all);
    try testing.expect(!parsed.permissions.write_all);
    try testing.expect(parsed.permissions.contents == null);
}

test "parseTrigger null value" {
    try testing.expectError(error.InvalidValue, parseTrigger(testing.allocator, .{ .null_value = mkSpan() }));
}

test "parseEventConfig with scalar (unknown event)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // A scalar value for an event config (e.g. `push: true`) is valid but does nothing
    const config = try parseEventConfig(arena.allocator(), "push", mkScalar("true"));
    try testing.expectEqual(types.EventType.push, config.event);
}

test "parseServices with scalar image" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("redis"), .value = mkScalar("redis:6"), .span = mkSpan() },
    };

    const services = try parseServices(arena.allocator(), mkMapping(&entries));
    try testing.expectEqual(@as(usize, 1), services.len);
    try testing.expectEqualStrings("redis", services[0].name);
    try testing.expectEqualStrings("redis:6", services[0].image.?);
    try testing.expect(services[0].credentials == null);
}
