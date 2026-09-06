const std = @import("std");
const types = @import("types.zig");
const schema = @import("schema.zig");
const yaml = @import("../yaml/types.zig");
const type_validation = @import("type_validation.zig");

const Node = yaml.Node;
const Mapping = yaml.Mapping;

pub const ParseError = error{
    MissingField,
    InvalidValue,
    OutOfMemory,
};

const ParseContext = struct {
    allocator: std.mem.Allocator,
    type_mismatches: ?*std.ArrayList(type_validation.TypeMismatch),
    unknown_collector: ?*schema.UnknownKeyCollector,
};

const ParsedStringMap = struct {
    values: types.StringMap,
    meta: types.ScalarValueMetaMap,
};

const ParsedPermissions = struct {
    permissions: types.Permissions,
    meta: ?types.PermissionsMeta,
    problems: []const types.PermissionProblem,
};

fn isInlineScalar(node: Node) bool {
    return switch (node) {
        .scalar => |sc| sc.style != .literal and sc.style != .folded,
        else => false,
    };
}

fn isEmptyContainer(node: Node) bool {
    return switch (node) {
        .mapping => |m| m.entries.len == 0,
        .sequence => |s| s.items.len == 0,
        .null_value => true,
        else => false,
    };
}

fn recordEmpty(list: *std.ArrayList(types.EmptySection), allocator: std.mem.Allocator, name: []const u8, node: Node) !void {
    if (!isEmptyContainer(node)) return;
    try list.append(allocator, .{ .name = name, .span = node.getSpan() });
}

fn recordTriggerNestedEmpty(list: *std.ArrayList(types.EmptySection), allocator: std.mem.Allocator, node: Node) !void {
    const mapping = switch (node) {
        .mapping => |m| m,
        else => return,
    };
    for (mapping.entries) |entry| {
        const inner = switch (entry.value) {
            .mapping => |im| im,
            else => continue,
        };
        switch (types.EventType.fromString(entry.key.value)) {
            .workflow_dispatch => {
                if (inner.get("inputs")) |n| try recordEmpty(list, allocator, "inputs", n);
            },
            .workflow_call => {
                if (inner.get("inputs")) |n| try recordEmpty(list, allocator, "inputs", n);
                if (inner.get("outputs")) |n| try recordEmpty(list, allocator, "outputs", n);
                if (inner.get("secrets")) |n| try recordEmpty(list, allocator, "secrets", n);
            },
            else => {},
        }
    }
}

pub fn parseWorkflow(allocator: std.mem.Allocator, node: Node) ParseError!types.Workflow {
    var type_mismatches = std.ArrayList(type_validation.TypeMismatch){};
    errdefer type_mismatches.deinit(allocator);

    var unknown_collector = schema.UnknownKeyCollector.init(allocator);
    errdefer unknown_collector.deinit();

    var ctx = ParseContext{
        .allocator = allocator,
        .type_mismatches = &type_mismatches,
        .unknown_collector = &unknown_collector,
    };

    const root = switch (node) {
        .mapping => |m| m,
        else => return error.InvalidValue,
    };

    var empty = std.ArrayList(types.EmptySection){};
    defer empty.deinit(allocator);

    const on_node = root.get("on") orelse root.get("true") orelse return error.MissingField;
    try recordEmpty(&empty, allocator, "on", on_node);
    try recordTriggerNestedEmpty(&empty, allocator, on_node);
    const trigger = if (isEmptyContainer(on_node))
        types.Trigger{ .events = &.{} }
    else
        try parseTrigger(allocator, on_node);

    const jobs_node = root.get("jobs") orelse return error.MissingField;
    try recordEmpty(&empty, allocator, "jobs", jobs_node);
    const jobs = if (isEmptyContainer(jobs_node))
        try allocator.alloc(types.Job, 0)
    else
        try parseJobs(&ctx, jobs_node);

    var workflow = types.Workflow{
        .name = root.getScalar("name"),
        .on = trigger,
        .concurrency = if (root.get("concurrency")) |n| try parseConcurrency(&ctx, n) else null,
        .jobs = jobs,
        .type_mismatches = try type_mismatches.toOwnedSlice(allocator),
        .yaml_root = node,
    };

    if (root.get("permissions")) |n| {
        const parsed = try parsePermissions(allocator, n);
        workflow.permissions = parsed.permissions;
        workflow.permissions_meta = parsed.meta;
        workflow.permission_problems = parsed.problems;
    }

    if (root.get("env")) |n| {
        try recordEmpty(&empty, allocator, "env", n);
        if (!isEmptyContainer(n)) {
            const parsed = try parseStringMapWithMeta(allocator, n);
            workflow.env = parsed.values;
            workflow.env_meta = parsed.meta;
            workflow.env_keys = try parseEnvKeys(allocator, n);
        }
    }

    if (root.get("defaults")) |n| {
        try recordEmpty(&empty, allocator, "defaults", n);
        workflow.defaults = parseDefaults(n);
    }

    try unknown_collector.checkMapping(root, "workflow", &schema.workflow_keys, &.{schema.workflow_on_key_alias});
    if (root.get("defaults")) |n| try unknown_collector.checkDefaults(n);

    workflow.unknown_keys = try unknown_collector.toOwnedSlice();
    workflow.empty_sections = try empty.toOwnedSlice(allocator);

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

fn parseTrigger(allocator: std.mem.Allocator, node: Node) ParseError!types.Trigger {
    switch (node) {
        .scalar => |s| {
            const events = try allocator.alloc(types.EventConfig, 1);
            events[0] = .{
                .event = types.EventType.fromString(s.value),
                .name = s.value,
                .name_span = s.span,
            };
            return .{ .events = events };
        },
        .sequence => |seq| {
            const events = try allocator.alloc(types.EventConfig, seq.items.len);
            for (seq.items, 0..) |item, i| {
                switch (item) {
                    .scalar => |s| {
                        events[i] = .{
                            .event = types.EventType.fromString(s.value),
                            .name = s.value,
                            .name_span = s.span,
                        };
                    },
                    else => return error.InvalidValue,
                }
            }
            return .{ .events = events };
        },
        .mapping => |m| {
            const events = try allocator.alloc(types.EventConfig, m.entries.len);
            for (m.entries, 0..) |entry, i| {
                events[i] = try parseEventConfig(allocator, entry.key.value, entry.value);
                events[i].name_span = entry.key.span;
            }
            return .{ .events = events };
        },
        .null_value => return error.InvalidValue,
    }
}

fn parseEventConfig(allocator: std.mem.Allocator, name: []const u8, node: Node) ParseError!types.EventConfig {
    const event_type = types.EventType.fromString(name);
    var config = types.EventConfig{ .event = event_type, .name = name };

    switch (node) {
        .null_value => {
            return config;
        },
        .mapping => |m| {
            switch (event_type) {
                .workflow_call => {
                    if (m.get("inputs")) |inputs_node| {
                        const parsed = try parseWorkflowCallInputs(allocator, inputs_node);
                        config.workflow_call_inputs = parsed.inputs;
                        config.workflow_call_input_problems = parsed.problems;
                    }
                },
                .workflow_dispatch => {
                    if (m.get("inputs")) |inputs_node| {
                        const parsed = try parseWorkflowDispatchInputs(allocator, inputs_node);
                        config.workflow_dispatch_inputs = parsed.inputs;
                        config.workflow_dispatch_input_problems = parsed.problems;
                    }
                },
                else => {
                    config.filter = try parseEventFilter(allocator, m);
                },
            }
        },
        .sequence => |seq| {
            if (event_type == .schedule) {
                config.schedules = try parseScheduleEntries(allocator, seq);
            }
        },
        .scalar => {},
    }

    return config;
}

fn parseScheduleEntries(allocator: std.mem.Allocator, seq: yaml.Sequence) ParseError![]const types.ScheduleEntry {
    var entries = std.ArrayList(types.ScheduleEntry){};
    errdefer entries.deinit(allocator);

    for (seq.items) |item| {
        const mapping = switch (item) {
            .mapping => |m| m,
            else => continue,
        };
        const cron_node = mapping.get("cron") orelse continue;
        const cron_scalar = switch (cron_node) {
            .scalar => |s| s,
            else => continue,
        };
        if (cron_scalar.value.len == 0) continue;
        var entry = types.ScheduleEntry{
            .cron = cron_scalar.value,
            .cron_span = cron_scalar.span,
        };
        if (mapping.get("timezone")) |tz_node| {
            switch (tz_node) {
                .scalar => |s| {
                    entry.timezone = s.value;
                    entry.timezone_span = s.span;
                },
                else => {},
            }
        }
        try entries.append(allocator, entry);
    }

    return try entries.toOwnedSlice(allocator);
}

const ParsedWorkflowCallInputs = struct {
    inputs: []const types.InputDef,
    problems: []const types.WorkflowCallInputProblem,
};

fn parseCallableInputType(type_name: []const u8) ?types.CallableInputType {
    if (std.mem.eql(u8, type_name, "string")) return .string;
    if (std.mem.eql(u8, type_name, "number")) return .number;
    if (std.mem.eql(u8, type_name, "boolean")) return .boolean;
    return null;
}

fn callableInputTypeName(input_type: types.CallableInputType) []const u8 {
    return switch (input_type) {
        .string => "string",
        .number => "number",
        .boolean => "boolean",
    };
}

fn parseYamlBool(node: Node) ?bool {
    return switch (node) {
        .scalar => |s| blk: {
            // YAML 1.2 core schema: only these six spellings resolve to a
            // bool. `yes` / `on` are YAML 1.1 and stay strings on GitHub.
            if (std.mem.eql(u8, s.value, "true") or std.mem.eql(u8, s.value, "True") or std.mem.eql(u8, s.value, "TRUE")) break :blk true;
            if (std.mem.eql(u8, s.value, "false") or std.mem.eql(u8, s.value, "False") or std.mem.eql(u8, s.value, "FALSE")) break :blk false;
            break :blk null;
        },
        else => null,
    };
}

fn isYamlNumber(node: Node) bool {
    return switch (node) {
        .scalar => |s| if (std.fmt.parseFloat(f64, s.value)) |_| true else |_| false,
        else => false,
    };
}

fn defaultMatchesCallableInputType(input_type: types.CallableInputType, node: Node) bool {
    return switch (input_type) {
        .boolean => parseYamlBool(node) != null,
        .number => isYamlNumber(node),
        .string => node == .scalar,
    };
}

fn parseWorkflowCallInputs(allocator: std.mem.Allocator, node: Node) ParseError!ParsedWorkflowCallInputs {
    const inputs_mapping = switch (node) {
        .mapping => |m| m,
        else => return .{ .inputs = &.{}, .problems = &.{} },
    };

    var inputs = std.ArrayList(types.InputDef){};
    errdefer inputs.deinit(allocator);
    var problems = std.ArrayList(types.WorkflowCallInputProblem){};
    errdefer problems.deinit(allocator);

    for (inputs_mapping.entries) |entry| {
        const input_name = entry.key.value;
        const input_mapping = switch (entry.value) {
            .mapping => |m| m,
            else => continue,
        };

        var def = types.InputDef{
            .name = input_name,
            .name_span = entry.key.span,
        };

        const type_node = input_mapping.get("type");
        if (type_node) |tn| {
            switch (tn) {
                .scalar => |s| {
                    def.type_span = s.span;
                    if (parseCallableInputType(s.value)) |parsed_type| {
                        def.input_type = parsed_type;
                    } else {
                        try problems.append(allocator, .{
                            .kind = .invalid_type,
                            .input_name = input_name,
                            .detail = s.value,
                            .span = s.span,
                        });
                    }
                },
                else => {
                    try problems.append(allocator, .{
                        .kind = .invalid_type,
                        .input_name = input_name,
                        .detail = "",
                        .span = tn.getSpan(),
                    });
                },
            }
        } else {
            try problems.append(allocator, .{
                .kind = .missing_type,
                .input_name = input_name,
                .detail = "",
                .span = entry.value.getSpan(),
            });
        }

        if (input_mapping.get("required")) |required_node| {
            def.required = parseYamlBool(required_node);
        }

        if (input_mapping.get("default")) |default_node| {
            switch (default_node) {
                .scalar => |s| {
                    def.default_value = s.value;
                    def.default_span = s.span;
                },
                else => {},
            }
        }

        if (def.required == true and def.default_value != null) {
            try problems.append(allocator, .{
                .kind = .required_with_default,
                .input_name = input_name,
                .detail = "",
                .span = def.default_span orelse entry.value.getSpan(),
            });
        }

        if (def.input_type) |input_type| {
            if (input_mapping.get("default")) |default_node| {
                if (!defaultMatchesCallableInputType(input_type, default_node)) {
                    try problems.append(allocator, .{
                        .kind = .default_type_mismatch,
                        .input_name = input_name,
                        .detail = callableInputTypeName(input_type),
                        .span = default_node.getSpan(),
                    });
                }
            }
        }

        try inputs.append(allocator, def);
    }

    return .{
        .inputs = try inputs.toOwnedSlice(allocator),
        .problems = try problems.toOwnedSlice(allocator),
    };
}

const ParsedWorkflowDispatchInputs = struct {
    inputs: []const types.DispatchInputDef,
    problems: []const types.WorkflowDispatchInputProblem,
};

fn defaultMatchesDispatchInputType(input_type: types.DispatchInputType, node: Node) bool {
    return switch (input_type) {
        .boolean => parseYamlBool(node) != null,
        .number => isYamlNumber(node),
        .string, .choice, .environment => node == .scalar,
    };
}

/// GitHub accepts only a sequence of scalars here. Anything else yields no
/// values rather than a parse error, so a malformed `options:` surfaces as an
/// empty option list instead of aborting the whole file.
fn collectOptionValues(allocator: std.mem.Allocator, node: Node) ParseError![]const []const u8 {
    var values = std.ArrayList([]const u8){};
    errdefer values.deinit(allocator);
    if (node == .sequence) {
        for (node.sequence.items) |item| {
            switch (item) {
                .scalar => |sc| try values.append(allocator, sc.value),
                else => {},
            }
        }
    }
    return values.toOwnedSlice(allocator);
}

fn parseWorkflowDispatchInputs(allocator: std.mem.Allocator, node: Node) ParseError!ParsedWorkflowDispatchInputs {
    const inputs_mapping = switch (node) {
        .mapping => |m| m,
        else => return .{ .inputs = &.{}, .problems = &.{} },
    };

    var inputs = std.ArrayList(types.DispatchInputDef){};
    errdefer inputs.deinit(allocator);
    var problems = std.ArrayList(types.WorkflowDispatchInputProblem){};
    errdefer problems.deinit(allocator);

    for (inputs_mapping.entries) |entry| {
        const input_name = entry.key.value;
        const input_mapping = switch (entry.value) {
            .mapping => |m| m,
            else => continue,
        };

        var def = types.DispatchInputDef{
            .name = input_name,
            .name_span = entry.key.span,
        };

        var type_invalid = false;
        if (input_mapping.get("type")) |type_node| {
            def.type_span = type_node.getSpan();
            const type_name = switch (type_node) {
                .scalar => |sc| sc.value,
                else => "",
            };
            if (types.DispatchInputType.fromString(type_name)) |parsed_type| {
                def.input_type = parsed_type;
            } else {
                type_invalid = true;
                try problems.append(allocator, .{
                    .kind = .invalid_type,
                    .input_name = input_name,
                    .detail = type_name,
                    .span = type_node.getSpan(),
                });
            }
        }

        const options_node = input_mapping.get("options");
        if (options_node) |on| def.options = try collectOptionValues(allocator, on);

        const default_node = input_mapping.get("default");
        if (default_node) |dn| {
            switch (dn) {
                .scalar => |sc| {
                    def.default_value = sc.value;
                    def.default_span = sc.span;
                },
                else => {},
            }
        }

        // An invalid `type:` already has its own diagnostic; the checks below
        // would only restate it against a type GitHub never resolved. An
        // absent `type:` is not that case — GitHub defaults it to `string`.
        if (!type_invalid) {
            try appendDispatchInputProblems(
                allocator,
                &problems,
                def,
                def.input_type orelse .string,
                options_node,
                default_node,
                entry.value.getSpan(),
            );
        }

        try inputs.append(allocator, def);
    }

    return .{
        .inputs = try inputs.toOwnedSlice(allocator),
        .problems = try problems.toOwnedSlice(allocator),
    };
}

fn appendDispatchInputProblems(
    allocator: std.mem.Allocator,
    problems: *std.ArrayList(types.WorkflowDispatchInputProblem),
    def: types.DispatchInputDef,
    input_type: types.DispatchInputType,
    options_node: ?Node,
    default_node: ?Node,
    input_span: yaml.Span,
) ParseError!void {
    if (input_type == .choice) {
        if (options_node) |on| {
            if (def.options.len == 0) {
                try problems.append(allocator, .{
                    .kind = .empty_options,
                    .input_name = def.name,
                    .detail = "",
                    .span = on.getSpan(),
                });
            }
        } else {
            try problems.append(allocator, .{
                .kind = .missing_options,
                .input_name = def.name,
                .detail = "",
                .span = def.type_span orelse input_span,
            });
        }
    } else if (options_node) |on| {
        try problems.append(allocator, .{
            .kind = .options_without_choice,
            .input_name = def.name,
            .detail = @tagName(input_type),
            .span = on.getSpan(),
        });
    }

    const default = default_node orelse return;

    if (!defaultMatchesDispatchInputType(input_type, default)) {
        try problems.append(allocator, .{
            .kind = .default_type_mismatch,
            .input_name = def.name,
            .detail = @tagName(input_type),
            .span = default.getSpan(),
        });
        return;
    }

    if (input_type != .choice or def.options.len == 0) return;
    const default_value = def.default_value orelse return;
    for (def.options) |option| {
        if (std.mem.eql(u8, option, default_value)) return;
    }
    try problems.append(allocator, .{
        .kind = .default_not_in_options,
        .input_name = def.name,
        .detail = default_value,
        .span = def.default_span orelse default.getSpan(),
    });
}

fn parseFilterPatternList(allocator: std.mem.Allocator, node: ?Node) ParseError!types.FilterPatternList {
    if (node) |n| {
        const parsed = try parseStringArrayWithSpans(allocator, n);
        return .{ .values = parsed.values, .spans = parsed.spans };
    }
    return .{};
}

fn parseEventFilter(allocator: std.mem.Allocator, m: Mapping) ParseError!types.EventFilter {
    return .{
        .branches = try parseFilterPatternList(allocator, m.get("branches")),
        .branches_ignore = try parseFilterPatternList(allocator, m.get("branches-ignore")),
        .tags = try parseFilterPatternList(allocator, m.get("tags")),
        .tags_ignore = try parseFilterPatternList(allocator, m.get("tags-ignore")),
        .paths = try parseFilterPatternList(allocator, m.get("paths")),
        .paths_ignore = try parseFilterPatternList(allocator, m.get("paths-ignore")),
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

fn parseJobs(ctx: *ParseContext, node: Node) ParseError![]const types.Job {
    const m = switch (node) {
        .mapping => |m| m,
        else => return error.InvalidValue,
    };

    const jobs = try ctx.allocator.alloc(types.Job, m.entries.len);
    for (m.entries, 0..) |entry, i| {
        jobs[i] = try parseJob(ctx, entry.key.value, entry.key.span, entry.value);
    }
    return jobs;
}

fn parseJob(ctx: *ParseContext, id: []const u8, id_span: yaml.Span, node: Node) ParseError!types.Job {
    const m = switch (node) {
        .mapping => |m| m,
        else => return error.InvalidValue,
    };

    var job = types.Job{ .id = id, .id_span = id_span };
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
    if (m.get("uses")) |n| {
        switch (n) {
            .scalar => |s| job.uses_value_span = s.span,
            else => {},
        }
    }

    var empty = std.ArrayList(types.EmptySection){};
    defer empty.deinit(ctx.allocator);

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

    if (m.get("timeout-minutes")) |n| {
        job.timeout_minutes_specified = true;
        job.timeout_minutes = type_validation.checkNumber(
            n,
            "timeout-minutes",
            ctx.type_mismatches,
            ctx.allocator,
        );
    }
    if (m.get("continue-on-error")) |n| {
        _ = type_validation.checkBool(
            n,
            "continue-on-error",
            ctx.type_mismatches,
            ctx.allocator,
        ) orelse false;
    }

    if (m.get("needs")) |needs_node| {
        const parsed = try parseStringArrayWithSpans(ctx.allocator, needs_node);
        job.needs = parsed.values;
        job.needs_spans = parsed.spans;
    }

    if (m.get("steps")) |n| {
        try recordEmpty(&empty, ctx.allocator, "steps", n);
        if (!isEmptyContainer(n)) {
            job.steps = try parseSteps(ctx, n);
        }
    }

    if (m.get("permissions")) |n| {
        const parsed = try parsePermissions(ctx.allocator, n);
        job.permissions = parsed.permissions;
        job.permissions_meta = parsed.meta;
        job.permission_problems = parsed.problems;
    }
    if (m.get("env")) |n| {
        try recordEmpty(&empty, ctx.allocator, "env", n);
        if (!isEmptyContainer(n)) {
            const parsed = try parseStringMapWithMeta(ctx.allocator, n);
            job.env = parsed.values;
            job.env_meta = parsed.meta;
            job.env_keys = try parseEnvKeys(ctx.allocator, n);
        }
    }
    if (m.get("concurrency")) |n| {
        job.concurrency = try parseConcurrency(ctx, n);
    }
    if (m.get("strategy")) |n| {
        try recordEmpty(&empty, ctx.allocator, "strategy", n);
        if (!isEmptyContainer(n)) {
            job.strategy = try parseStrategy(ctx, n);
            switch (n) {
                .mapping => |sm| {
                    if (sm.get("matrix")) |matrix_node| {
                        try recordEmpty(&empty, ctx.allocator, "matrix", matrix_node);
                    }
                },
                else => {},
            }
        }
    }
    if (m.get("with")) |n| {
        try recordEmpty(&empty, ctx.allocator, "with", n);
        if (!isEmptyContainer(n)) {
            job.with = try parseStringMap(ctx.allocator, n);
        }
    }
    if (m.get("secrets")) |n| {
        try recordEmpty(&empty, ctx.allocator, "secrets", n);
        if (!isEmptyContainer(n)) {
            job.secrets = try parseSecretsConfig(ctx.allocator, n);
        }
    }
    if (m.get("container")) |n| {
        try recordEmpty(&empty, ctx.allocator, "container", n);
        if (!isEmptyContainer(n)) {
            job.container = try parseContainer(ctx.allocator, n);
        }
    }
    if (m.get("services")) |n| {
        try recordEmpty(&empty, ctx.allocator, "services", n);
        if (!isEmptyContainer(n)) {
            job.services = try parseServices(ctx.allocator, n);
        }
    }
    if (m.get("outputs")) |n| try recordEmpty(&empty, ctx.allocator, "outputs", n);
    if (m.get("defaults")) |n| {
        try recordEmpty(&empty, ctx.allocator, "defaults", n);
        job.defaults = parseDefaults(n);
    }

    if (ctx.unknown_collector) |c| {
        try c.checkMapping(m, "job", &schema.job_keys, &.{});
        if (m.get("defaults")) |n| try c.checkDefaults(n);
        if (m.get("strategy")) |n| {
            if (n == .mapping) try c.checkMapping(n.mapping, "strategy", &schema.strategy_keys, &.{});
        }
        if (m.get("container")) |n| try c.checkContainer(n, "container");
        if (m.get("services")) |n| {
            if (n == .mapping) {
                for (n.mapping.entries) |entry| {
                    try c.checkContainer(entry.value, "services");
                }
            }
        }
    }

    job.empty_sections = try empty.toOwnedSlice(ctx.allocator);
    return job;
}

fn parseDefaults(node: Node) ?types.Defaults {
    const m = switch (node) {
        .mapping => |mp| mp,
        else => return null,
    };
    const run_node = m.get("run") orelse return null;
    const run_mapping = switch (run_node) {
        .mapping => |mp| mp,
        else => return null,
    };
    const shell_node = run_mapping.get("shell") orelse return null;
    return switch (shell_node) {
        .scalar => |s| .{ .run_shell = s.value, .run_shell_span = s.span },
        else => null,
    };
}

fn parseSteps(ctx: *ParseContext, node: Node) ParseError![]const types.Step {
    const seq = switch (node) {
        .sequence => |s| s,
        else => return error.InvalidValue,
    };

    const steps = try ctx.allocator.alloc(types.Step, seq.items.len);
    for (seq.items, 0..) |item, i| {
        steps[i] = try parseStep(ctx, item);
    }
    return steps;
}

fn parseStep(ctx: *ParseContext, node: Node) ParseError!types.Step {
    const m = switch (node) {
        .mapping => |mp| mp,
        else => return error.InvalidValue,
    };

    var step = types.Step{};
    step.span = m.span;
    if (m.get("id")) |id_node| {
        switch (id_node) {
            .scalar => |s| {
                step.id = s.value;
                step.id_value_span = s.span;
            },
            else => {},
        }
    }
    step.name = m.getScalar("name");
    step.run = m.getScalar("run");
    if (m.get("shell")) |n| {
        switch (n) {
            .scalar => |s| {
                step.shell = s.value;
                step.shell_value_span = s.span;
            },
            else => {},
        }
    }
    step.if_condition = m.getScalar("if");
    if (m.get("if")) |n| {
        switch (n) {
            .scalar => |s| step.if_condition_meta = .{ .value_span = s.span, .style = s.style },
            else => {},
        }
    }
    for (m.entries) |entry| {
        if (!std.mem.eql(u8, entry.key.value, "run")) continue;
        switch (entry.value) {
            .scalar => |s| {
                step.run_meta = .{ .value_span = s.span, .style = s.style };
            },
            else => {},
        }
        if (entry.full_span) |fs| {
            step.shell_insertion_byte = fs.end_byte;
        }
        break;
    }

    if (m.get("uses")) |uses_node| {
        switch (uses_node) {
            .scalar => |s| {
                step.uses = types.ActionRef.parse(s.value);
                step.uses_value_span = s.span;
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
    if (m.get("timeout-minutes")) |n| {
        _ = type_validation.checkNumber(
            n,
            "timeout-minutes",
            ctx.type_mismatches,
            ctx.allocator,
        );
    }
    if (m.get("continue-on-error")) |n| {
        _ = type_validation.checkBool(
            n,
            "continue-on-error",
            ctx.type_mismatches,
            ctx.allocator,
        );
    }
    var empty = std.ArrayList(types.EmptySection){};
    defer empty.deinit(ctx.allocator);
    if (m.get("with")) |with_node| {
        try recordEmpty(&empty, ctx.allocator, "with", with_node);
        if (!isEmptyContainer(with_node)) {
            const parsed_with = try parseStringMapWithMeta(ctx.allocator, with_node);
            step.with = parsed_with.values;
            step.with_meta = parsed_with.meta;
            switch (with_node) {
                .mapping => |with_mapping| {
                    if (with_mapping.entries.len > 0) {
                        const last = with_mapping.entries[with_mapping.entries.len - 1];
                        // Appending after the last entry is only safe when `with:`
                        // is a block mapping (a flow entry has no full_span) and the
                        // last value ends where its span says: a flow collection's
                        // span covers only its opening bracket, and a block scalar
                        // ends at the start of the next line (#171).
                        if (last.full_span != null and isInlineScalar(last.value)) {
                            step.with_last_entry_end_byte = last.value.getSpan().end_byte;
                        }
                    }
                },
                else => {},
            }
        }
    }
    if (m.get("env")) |n| {
        try recordEmpty(&empty, ctx.allocator, "env", n);
        if (!isEmptyContainer(n)) {
            const parsed = try parseStringMapWithMeta(ctx.allocator, n);
            step.env = parsed.values;
            step.env_meta = parsed.meta;
            step.env_keys = try parseEnvKeys(ctx.allocator, n);
        }
    }
    step.empty_sections = try empty.toOwnedSlice(ctx.allocator);

    if (ctx.unknown_collector) |c| try c.checkMapping(m, "step", schema.stepExpectedKeys(m), &.{});

    return step;
}

fn parsePermissions(allocator: std.mem.Allocator, node: Node) ParseError!ParsedPermissions {
    var problems = std.ArrayList(types.PermissionProblem){};
    errdefer problems.deinit(allocator);

    switch (node) {
        .scalar => |s| {
            var perms = types.Permissions{ .value_span = s.span };
            if (std.mem.eql(u8, s.value, "read-all")) {
                perms.read_all = true;
            } else if (std.mem.eql(u8, s.value, "write-all")) {
                perms.write_all = true;
            } else {
                try problems.append(allocator, .{
                    .kind = .invalid_all,
                    .text = s.value,
                    .span = s.span,
                });
            }
            return .{
                .permissions = perms,
                .meta = null,
                .problems = try problems.toOwnedSlice(allocator),
            };
        },
        .mapping => |m| {
            var perms = types.Permissions{ .value_span = m.span };
            var meta = types.PermissionsMeta{};
            for (m.entries) |entry| {
                const level = parsePermissionLevel(entry.value);
                var known_scope = false;
                inline for (types.permission_scopes) |field| {
                    if (std.mem.eql(u8, entry.key.value, comptime types.permissionScopeKey(field))) {
                        known_scope = true;
                        // parsePermissionLevel only accepts scalars, so the
                        // value span for `meta` is always available alongside
                        // the level.
                        if (level) |lvl| {
                            @field(perms, field) = lvl;
                            @field(meta, field) = entry.value.scalar.span;
                        }
                        break;
                    }
                }
                if (!known_scope) {
                    try problems.append(allocator, .{
                        .kind = .unknown_scope,
                        .text = entry.key.value,
                        .span = entry.key.span,
                    });
                } else if (level == null) {
                    // A null value's span is the *next* token, so a non-scalar
                    // value is reported on the key instead.
                    const text: []const u8, const span: yaml.Span = switch (entry.value) {
                        .scalar => |s| .{ s.value, s.span },
                        else => .{ "", entry.key.span },
                    };
                    try problems.append(allocator, .{
                        .kind = .invalid_level,
                        .text = text,
                        .scope = entry.key.value,
                        .span = span,
                    });
                }
            }
            return .{
                .permissions = perms,
                .meta = meta,
                .problems = try problems.toOwnedSlice(allocator),
            };
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

fn parseConcurrency(ctx: *ParseContext, node: Node) ParseError!types.Concurrency {
    switch (node) {
        .scalar => |s| {
            return .{ .group = s.value };
        },
        .mapping => |m| {
            const concurrency = types.Concurrency{
                .group = m.getScalar("group") orelse return error.MissingField,
            };
            if (m.get("cancel-in-progress")) |n| {
                _ = type_validation.checkBool(
                    n,
                    "cancel-in-progress",
                    ctx.type_mismatches,
                    ctx.allocator,
                );
            }
            return concurrency;
        },
        else => return error.InvalidValue,
    }
}

fn parseStrategy(ctx: *ParseContext, node: Node) ParseError!types.Strategy {
    const m = switch (node) {
        .mapping => |m| m,
        else => return error.InvalidValue,
    };

    var strategy = types.Strategy{};
    for (m.entries) |entry| {
        if (std.mem.eql(u8, entry.key.value, "fail-fast")) {
            if (type_validation.checkBool(
                entry.value,
                "fail-fast",
                ctx.type_mismatches,
                ctx.allocator,
            )) |value| {
                strategy.fail_fast = value;
                if (entry.value == .scalar) {
                    strategy.fail_fast_value_span = entry.value.scalar.span;
                }
                strategy.fail_fast_entry_span = entry.full_span;
            }
        } else if (std.mem.eql(u8, entry.key.value, "max-parallel")) {
            _ = type_validation.checkNumber(
                entry.value,
                "max-parallel",
                ctx.type_mismatches,
                ctx.allocator,
            );
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

fn parseContainer(allocator: std.mem.Allocator, node: Node) ParseError!types.Container {
    switch (node) {
        .scalar => |s| {
            return .{ .image = s.value };
        },
        .mapping => |m| {
            return .{
                .image = m.getScalar("image"),
                .credentials = if (m.get("credentials")) |n| try parseCredentials(n) else null,
                .env_keys = if (m.get("env")) |n| try parseEnvKeys(allocator, n) else &.{},
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
                    .env_keys = if (vm.get("env")) |n| try parseEnvKeys(allocator, n) else &.{},
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
    return (try parseStringMapWithMeta(allocator, node)).values;
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

/// Unlike `parseStringMapWithMeta`, no entry is dropped: SYN007 must see keys
/// whose value is not a scalar, and duplicated keys, to validate their names.
fn parseEnvKeys(allocator: std.mem.Allocator, node: Node) ParseError![]const types.EnvKey {
    const m = switch (node) {
        .mapping => |m| m,
        else => return &.{},
    };

    const keys = try allocator.alloc(types.EnvKey, m.entries.len);
    for (m.entries, keys) |entry, *key| {
        key.* = .{ .name = entry.key.value, .span = entry.key.span };
    }
    return keys;
}

const ParsedStringArray = struct {
    values: []const []const u8,
    spans: []const yaml.Span,
};

fn parseStringArrayWithSpans(allocator: std.mem.Allocator, node: Node) ParseError!ParsedStringArray {
    switch (node) {
        .sequence => |seq| {
            const values = try allocator.alloc([]const u8, seq.items.len);
            const spans = try allocator.alloc(yaml.Span, seq.items.len);
            for (seq.items, 0..) |item, i| {
                switch (item) {
                    .scalar => |s| {
                        values[i] = s.value;
                        spans[i] = s.span;
                    },
                    else => return error.InvalidValue,
                }
            }
            return .{ .values = values, .spans = spans };
        },
        .scalar => |s| {
            const values = try allocator.alloc([]const u8, 1);
            values[0] = s.value;
            const spans = try allocator.alloc(yaml.Span, 1);
            spans[0] = s.span;
            return .{ .values = values, .spans = spans };
        },
        else => return error.InvalidValue,
    }
}

fn parseStringArray(allocator: std.mem.Allocator, node: Node) ParseError![]const []const u8 {
    return (try parseStringArrayWithSpans(allocator, node)).values;
}

const testing = std.testing;
const test_support = @import("../test_support.zig");

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

const mkScalar = test_support.mkScalar;

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

fn testCtx(allocator: std.mem.Allocator) ParseContext {
    return .{ .allocator = allocator, .type_mismatches = null, .unknown_collector = null };
}

test "parseWorkflow minimal" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var step_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("run"), .value = mkScalar("echo hi"), .span = mkSpan() },
    };
    var step_items = [_]Node{mkMapping(&step_entries)};

    var job_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("runs-on"), .value = mkScalar("ubuntu-latest"), .span = mkSpan() },
        .{ .key = mkScalarS("steps"), .value = mkSequence(&step_items), .span = mkSpan() },
    };

    var jobs_entries = [_]yaml.MappingEntry{
        .{ .key = .{ .value = "build", .style = .plain, .span = mkSpanBytes(20, 25) }, .value = mkMapping(&job_entries), .span = mkSpan() },
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
    try testing.expectEqual(@as(usize, 20), wf.jobs[0].id_span.?.start_byte);
    try testing.expectEqual(@as(usize, 25), wf.jobs[0].id_span.?.end_byte);
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
    try testing.expectEqual(@as(usize, 1), trigger.events[0].filter.?.branches.values.len);
    try testing.expectEqualStrings("main", trigger.events[0].filter.?.branches.values[0]);
    try testing.expect(trigger.events[0].filter.?.spans.branches != null);
    try testing.expect(trigger.events[0].filter.?.spans.branches_ignore == null);
}

test "parseTrigger schedule entries capture cron spans" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var cron_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("cron"), .value = mkScalarStyled("0 0 * * *", .single_quoted, mkSpanBytes(40, 51)), .span = mkSpan() },
    };
    var schedule_items = [_]Node{mkMapping(&cron_entries)};
    var trigger_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("schedule"), .value = mkSequence(&schedule_items), .span = mkSpan() },
    };

    const trigger = try parseTrigger(arena.allocator(), mkMapping(&trigger_entries));
    try testing.expectEqual(@as(usize, 1), trigger.events.len);
    try testing.expectEqual(types.EventType.schedule, trigger.events[0].event);
    try testing.expectEqual(@as(usize, 1), trigger.events[0].schedules.len);
    try testing.expectEqualStrings("0 0 * * *", trigger.events[0].schedules[0].cron);
    try testing.expectEqual(@as(usize, 40), trigger.events[0].schedules[0].cron_span.start_byte);
    try testing.expect(trigger.events[0].schedules[0].timezone == null);
}

test "parseTrigger schedule entries capture the timezone and its span" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var cron_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("cron"), .value = mkScalarStyled("0 0 * * *", .single_quoted, mkSpanBytes(40, 51)), .span = mkSpan() },
        .{ .key = mkScalarS("timezone"), .value = mkScalarStyled("Asia/Tokyo", .single_quoted, mkSpanBytes(70, 82)), .span = mkSpan() },
    };
    var schedule_items = [_]Node{mkMapping(&cron_entries)};
    var trigger_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("schedule"), .value = mkSequence(&schedule_items), .span = mkSpan() },
    };

    const trigger = try parseTrigger(arena.allocator(), mkMapping(&trigger_entries));
    const entry = trigger.events[0].schedules[0];
    try testing.expectEqualStrings("Asia/Tokyo", entry.timezone.?);
    try testing.expectEqual(@as(usize, 70), entry.timezone_span.?.start_byte);
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
    try testing.expectEqual(@as(usize, 0), trigger.events[0].filter.?.paths_ignore.values.len);
    try testing.expectEqual(@as(usize, 20), (spans.paths_ignore orelse return error.TestUnexpectedResult).start_byte);
    try testing.expect(spans.paths == null);
}

test "parsePermissions read-all" {
    const parsed = try parsePermissions(testing.allocator, mkScalar("read-all"));
    defer testing.allocator.free(parsed.problems);
    try testing.expect(parsed.permissions.read_all);
    try testing.expect(!parsed.permissions.write_all);
    try testing.expect(parsed.meta == null);
    try testing.expectEqual(@as(usize, 0), parsed.problems.len);
}

test "parsePermissions write-all" {
    const parsed = try parsePermissions(testing.allocator, mkScalar("write-all"));
    defer testing.allocator.free(parsed.problems);
    try testing.expect(parsed.permissions.write_all);
    try testing.expect(!parsed.permissions.read_all);
    try testing.expect(parsed.meta == null);
    try testing.expectEqual(@as(usize, 0), parsed.problems.len);
}

test "parsePermissions reports an invalid all-scopes value" {
    const parsed = try parsePermissions(testing.allocator, mkScalar("read"));
    defer testing.allocator.free(parsed.problems);
    try testing.expect(!parsed.permissions.read_all);
    try testing.expect(!parsed.permissions.write_all);
    try testing.expectEqual(@as(usize, 1), parsed.problems.len);
    try testing.expectEqual(types.PermissionProblemKind.invalid_all, parsed.problems[0].kind);
    try testing.expectEqualStrings("read", parsed.problems[0].text);
}

test "parsePermissions individual scopes" {
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("contents"), .value = mkScalar("read"), .span = mkSpan() },
        .{ .key = mkScalarS("pull-requests"), .value = mkScalar("write"), .span = mkSpan() },
        .{ .key = mkScalarS("issues"), .value = mkScalar("none"), .span = mkSpan() },
    };

    const parsed = try parsePermissions(testing.allocator, mkMapping(&entries));
    defer testing.allocator.free(parsed.problems);
    try testing.expectEqual(@as(usize, 0), parsed.problems.len);
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
    var ctx = testCtx(testing.allocator);
    const c = try parseConcurrency(&ctx, mkScalar("ci-group"));
    try testing.expectEqualStrings("ci-group", c.group);
}

test "parseConcurrency mapping" {
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("group"), .value = mkScalar("ci"), .span = mkSpan() },
        .{ .key = mkScalarS("cancel-in-progress"), .value = mkScalar("true"), .span = mkSpan() },
    };

    var ctx = testCtx(testing.allocator);
    const c = try parseConcurrency(&ctx, mkMapping(&entries));
    try testing.expectEqualStrings("ci", c.group);
}

test "parseStep with uses" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("name"), .value = mkScalar("Checkout"), .span = mkSpan() },
        .{ .key = mkScalarS("uses"), .value = mkScalar("actions/checkout@v4"), .span = mkSpan() },
    };

    var ctx = testCtx(arena.allocator());
    const step = try parseStep(&ctx, mkMapping(&entries));
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

    var ctx = testCtx(arena.allocator());
    const step = try parseStep(&ctx, mkMapping(&entries));
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

    var needs_items = [_]Node{
        mkScalarStyled("build", .plain, mkSpanBytes(100, 105)),
        mkScalarStyled("lint", .plain, mkSpanBytes(110, 114)),
    };

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("runs-on"), .value = mkScalar("ubuntu-latest"), .span = mkSpan() },
        .{ .key = mkScalarS("needs"), .value = mkSequence(&needs_items), .span = mkSpan() },
        .{ .key = mkScalarS("steps"), .value = mkSequence(&step_items), .span = mkSpan() },
    };

    var ctx = testCtx(arena.allocator());
    const job = try parseJob(&ctx, "deploy", mkSpan(), mkMapping(&entries));
    try testing.expectEqualStrings("deploy", job.id);
    try testing.expectEqual(@as(usize, 2), job.needs.len);
    try testing.expectEqualStrings("build", job.needs[0]);
    try testing.expectEqualStrings("lint", job.needs[1]);
    try testing.expectEqual(@as(usize, 2), job.needs_spans.len);
    try testing.expectEqual(@as(usize, 100), job.needs_spans[0].start_byte);
    try testing.expectEqual(@as(usize, 105), job.needs_spans[0].end_byte);
    try testing.expectEqual(@as(usize, 110), job.needs_spans[1].start_byte);
    try testing.expectEqual(@as(usize, 114), job.needs_spans[1].end_byte);
}

test "parseJob reusable workflow" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("uses"), .value = mkScalar("octo-org/this-repo/.github/workflows/workflow-1.yml@v1"), .span = mkSpan() },
        .{ .key = mkScalarS("secrets"), .value = mkScalar("inherit"), .span = mkSpan() },
    };

    var ctx = testCtx(arena.allocator());
    const job = try parseJob(&ctx, "call-workflow", mkSpan(), mkMapping(&entries));
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

    var ctx = testCtx(testing.allocator);
    const strategy = try parseStrategy(&ctx, mkMapping(&entries));
    try testing.expect(!strategy.fail_fast);
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
    const yaml_node = try yp.parse();
    const wf = try parseWorkflow(alloc, yaml_node);

    const span = wf.jobs[0].runs_on_value_span.?;
    try testing.expectEqualStrings("ubuntu-20.04", source[span.start_byte..span.end_byte]);
}

test "parseDefaults captures defaults.run.shell at workflow and job level" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: push
        \\defaults:
        \\  run:
        \\    shell: bash
        \\jobs:
        \\  build:
        \\    runs-on: windows-latest
        \\    defaults:
        \\      run:
        \\        shell: pwsh
        \\    steps:
        \\      - run: echo hi
        \\        shell: cmd
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const yaml_node = try yp.parse();
    const wf = try parseWorkflow(alloc, yaml_node);

    try testing.expectEqualStrings("bash", wf.defaults.?.run_shell);
    const wf_span = wf.defaults.?.run_shell_span;
    try testing.expectEqualStrings("bash", source[wf_span.start_byte..wf_span.end_byte]);

    try testing.expectEqualStrings("pwsh", wf.jobs[0].defaults.?.run_shell);

    const step_span = wf.jobs[0].steps[0].shell_value_span.?;
    try testing.expectEqualStrings("cmd", source[step_span.start_byte..step_span.end_byte]);
}

test "parseDefaults leaves defaults null when run.shell is absent" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: push
        \\defaults:
        \\  run:
        \\    working-directory: ./src
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const yaml_node = try yp.parse();
    const wf = try parseWorkflow(alloc, yaml_node);

    try testing.expect(wf.defaults == null);
    try testing.expect(wf.jobs[0].defaults == null);
    try testing.expect(wf.jobs[0].steps[0].shell_value_span == null);
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
        .{ .key = mkScalarS("id"), .value = mkScalarStyled("step1", .plain, mkSpanBytes(50, 55)), .span = mkSpan() },
        .{ .key = mkScalarS("working-directory"), .value = mkScalar("./src"), .span = mkSpan() },
        .{ .key = mkScalarS("with"), .value = mkMapping(&with_entries), .span = mkSpan() },
        .{ .key = mkScalarS("env"), .value = mkMapping(&env_entries), .span = mkSpan() },
    };

    var ctx = testCtx(arena.allocator());
    const step = try parseStep(&ctx, mkMapping(&entries));
    try testing.expectEqualStrings("always()", step.if_condition.?);
    try testing.expectEqualStrings("step1", step.id.?);
    try testing.expectEqual(@as(usize, 50), step.id_value_span.?.start_byte);
    try testing.expectEqual(@as(usize, 55), step.id_value_span.?.end_byte);
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

    var ctx = testCtx(arena.allocator());
    const job = try parseJob(&ctx, "test", mkSpan(), mkMapping(&entries));
    try testing.expectEqual(@as(?u32, 30), job.timeout_minutes);
    try testing.expectEqualStrings("success()", job.if_condition.?);
    try testing.expect(job.strategy.?.fail_fast);
}

test "parseStep captures if_condition_meta" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const if_value_span = mkSpanBytes(4, 32);
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("run"), .value = mkScalar("echo"), .span = mkSpan() },
        .{
            .key = mkScalarS("if"),
            .value = mkScalarStyled("contains(github.ref, 'main')", .plain, if_value_span),
            .span = mkSpan(),
        },
    };

    var ctx = testCtx(arena.allocator());
    const step = try parseStep(&ctx, mkMapping(&entries));
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

    var ctx = testCtx(arena.allocator());
    const job = try parseJob(&ctx, "test", mkSpan(), mkMapping(&entries));
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

    var ctx = testCtx(arena.allocator());
    const job = try parseJob(&ctx, "build", mkSpan(), mkMapping(&entries));
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

    var ctx = testCtx(arena.allocator());
    const job = try parseJob(&ctx, "build", mkSpan(), mkMapping(&entries));
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

    var ctx = testCtx(arena.allocator());
    const job = try parseJob(&ctx, "build", mkSpan(), mkMapping(&entries));
    try testing.expectEqual(@as(usize, 1), job.services.len);
    try testing.expectEqualStrings("redis", job.services[0].name);
    try testing.expectEqualStrings("redis", job.services[0].image.?);
    try testing.expectEqualStrings("${{ secrets.REDIS_USER }}", job.services[0].credentials.?.username.?);
    try testing.expectEqualStrings("${{ secrets.REDIS_PASS }}", job.services[0].credentials.?.password.?);
}

test "parseEventConfig with null value (empty event)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const config = try parseEventConfig(arena.allocator(), "push", .{ .null_value = mkSpan() });
    try testing.expectEqual(types.EventType.push, config.event);
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

    var ctx = testCtx(arena.allocator());
    const job = try parseJob(&ctx, "test", mkSpan(), mkMapping(&entries));
    try testing.expectEqualStrings("true", job.env.?.get("CI").?);
    try testing.expect(job.env_meta != null);
    try testing.expectEqual(yaml.ScalarStyle.plain, job.env_meta.?.get("CI").?.style);
    try testing.expectEqualStrings("val", job.with.?.get("key").?);
    try testing.expectEqualStrings("my-group", job.concurrency.?.group);
    try testing.expect(job.permissions != null);
    try testing.expectEqual(types.PermissionLevel.read, job.permissions.?.contents.?);
}

test "parsePermissions reports invalid permission levels" {
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("contents"), .value = mkScalar("execute"), .span = mkSpan() },
        .{ .key = mkScalarS("issues"), .value = mkScalar("admin"), .span = mkSpan() },
        .{ .key = mkScalarS("pull-requests"), .value = mkScalar("read"), .span = mkSpan() },
    };

    const parsed = try parsePermissions(testing.allocator, mkMapping(&entries));
    defer testing.allocator.free(parsed.problems);
    try testing.expect(parsed.permissions.contents == null);
    try testing.expect(parsed.permissions.issues == null);
    try testing.expectEqual(types.PermissionLevel.read, parsed.permissions.pull_requests.?);

    try testing.expectEqual(@as(usize, 2), parsed.problems.len);
    try testing.expectEqual(types.PermissionProblemKind.invalid_level, parsed.problems[0].kind);
    try testing.expectEqualStrings("execute", parsed.problems[0].text);
    try testing.expectEqualStrings("contents", parsed.problems[0].scope);
    try testing.expectEqualStrings("admin", parsed.problems[1].text);
    try testing.expectEqualStrings("issues", parsed.problems[1].scope);
}

test "parsePermissions reports an unknown scope" {
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("content"), .value = mkScalar("read"), .span = mkSpan() },
    };

    const parsed = try parsePermissions(testing.allocator, mkMapping(&entries));
    defer testing.allocator.free(parsed.problems);
    try testing.expectEqual(@as(usize, 1), parsed.problems.len);
    try testing.expectEqual(types.PermissionProblemKind.unknown_scope, parsed.problems[0].kind);
    try testing.expectEqualStrings("content", parsed.problems[0].text);
}

test "parsePermissions accepts artifact-metadata and models" {
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("artifact-metadata"), .value = mkScalar("read"), .span = mkSpan() },
        .{ .key = mkScalarS("models"), .value = mkScalar("read"), .span = mkSpan() },
    };

    const parsed = try parsePermissions(testing.allocator, mkMapping(&entries));
    defer testing.allocator.free(parsed.problems);
    try testing.expectEqual(@as(usize, 0), parsed.problems.len);
    try testing.expectEqual(types.PermissionLevel.read, parsed.permissions.artifact_metadata.?);
    try testing.expectEqual(types.PermissionLevel.read, parsed.permissions.models.?);
}

test "parsePermissions with empty mapping" {
    var entries = [_]yaml.MappingEntry{};
    const parsed = try parsePermissions(testing.allocator, mkMapping(&entries));
    defer testing.allocator.free(parsed.problems);
    try testing.expect(!parsed.permissions.read_all);
    try testing.expect(!parsed.permissions.write_all);
    try testing.expect(parsed.permissions.contents == null);
    try testing.expectEqual(@as(usize, 0), parsed.problems.len);
}

test "parseWorkflow records empty sections for SYN003" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy: {}
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\        with: {}
    ;

    var parser = yaml_parser_mod.Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const wf = try parseWorkflow(arena.allocator(), node);

    try testing.expectEqual(@as(usize, 1), wf.jobs[0].empty_sections.len);
    try testing.expectEqualStrings("strategy", wf.jobs[0].empty_sections[0].name);
    try testing.expectEqual(@as(usize, 1), wf.jobs[0].steps[0].empty_sections.len);
    try testing.expectEqualStrings("with", wf.jobs[0].steps[0].empty_sections[0].name);
}

test "parseWorkflow does not record empty permissions" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on: push
        \\permissions: {}
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    permissions: {}
        \\    steps:
        \\      - run: echo
    ;

    var parser = yaml_parser_mod.Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const wf = try parseWorkflow(arena.allocator(), node);

    try testing.expectEqual(@as(usize, 0), wf.empty_sections.len);
    try testing.expectEqual(@as(usize, 0), wf.jobs[0].empty_sections.len);
}

test "parseWorkflow records implicit-null empty sections" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on: push
        \\jobs:
    ;

    var parser = yaml_parser_mod.Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const wf = try parseWorkflow(arena.allocator(), node);

    try testing.expectEqual(@as(usize, 0), wf.jobs.len);
    try testing.expectEqual(@as(usize, 1), wf.empty_sections.len);
    try testing.expectEqualStrings("jobs", wf.empty_sections[0].name);
}

test "parseWorkflow records implicit-null strategy and with" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\        with:
    ;

    var parser = yaml_parser_mod.Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const wf = try parseWorkflow(arena.allocator(), node);

    try testing.expectEqualStrings("strategy", wf.jobs[0].empty_sections[0].name);
    try testing.expectEqualStrings("with", wf.jobs[0].steps[0].empty_sections[0].name);
}

test "parseWorkflow records empty workflow_dispatch inputs" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on:
        \\  workflow_dispatch:
        \\    inputs: {}
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var parser = yaml_parser_mod.Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const wf = try parseWorkflow(arena.allocator(), node);

    try testing.expectEqual(@as(usize, 1), wf.empty_sections.len);
    try testing.expectEqualStrings("inputs", wf.empty_sections[0].name);
}

test "parseWorkflowCallInputs collects workflow_call input problems" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      env:
        \\        type: choice
        \\      version:
        \\        description: Version
        \\      verbose:
        \\        type: boolean
        \\        default: 'yes'
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var parser = yaml_parser_mod.Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const wf = try parseWorkflow(arena.allocator(), node);

    try testing.expectEqual(@as(usize, 1), wf.on.events.len);
    const event = wf.on.events[0];
    try testing.expectEqual(types.EventType.workflow_call, event.event);
    try testing.expectEqual(@as(usize, 3), event.workflow_call_inputs.len);
    try testing.expectEqual(@as(usize, 3), event.workflow_call_input_problems.len);
    try testing.expectEqual(types.WorkflowCallInputProblemKind.invalid_type, event.workflow_call_input_problems[0].kind);
    try testing.expectEqual(types.WorkflowCallInputProblemKind.missing_type, event.workflow_call_input_problems[1].kind);
    try testing.expectEqual(types.WorkflowCallInputProblemKind.default_type_mismatch, event.workflow_call_input_problems[2].kind);
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

test "parseStep captures run/uses/with source metadata" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\        with:
        \\          ref: main
        \\      - run: |
        \\          echo hello
        \\
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());

    const checkout = wf.jobs[0].steps[0];
    const uses_span = checkout.uses_value_span.?;
    try testing.expectEqual(@as(u32, 7), uses_span.start_line);
    try testing.expectEqualStrings(
        "actions/checkout@v4",
        source[uses_span.start_byte..uses_span.end_byte],
    );
    try testing.expectEqual(yaml.ScalarStyle.plain, checkout.with_meta.?.get("ref").?.style);
    try testing.expectEqual(@as(u32, 9), checkout.with_meta.?.get("ref").?.value_span.start_line);

    const run_step = wf.jobs[0].steps[1];
    try testing.expectEqual(yaml.ScalarStyle.literal, run_step.run_meta.?.style);
    // The `run:` span starts at the `|` indicator, one line above the content.
    try testing.expectEqual(@as(u32, 10), run_step.run_meta.?.value_span.start_line);
}

test "top-level permissions anchor clears an on: block scalar (#172)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on:
        \\  workflow_dispatch:
        \\    inputs:
        \\      x:
        \\        description: |
        \\          a long description
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());

    const anchor = wf.permissions_insertion_byte.?;
    try testing.expectEqualStrings("jobs:\n", source[anchor .. anchor + "jobs:\n".len]);
}

test "with_last_entry_end_byte is set only for an inline scalar in a block with: (#171)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    const Case = struct { name: []const u8, with_block: []const u8, anchored_after: ?[]const u8 };
    const cases = [_]Case{
        .{ .name = "flow with", .with_block = "        with: {x: y}\n", .anchored_after = null },
        .{ .name = "flow mapping value", .with_block = "        with:\n          x: {a: b}\n", .anchored_after = null },
        .{ .name = "flow sequence value", .with_block = "        with:\n          x: [a, b]\n", .anchored_after = null },
        .{ .name = "block scalar value", .with_block = "        with:\n          x: |\n            a\n", .anchored_after = null },
        .{ .name = "plain scalar value", .with_block = "        with:\n          x: y\n", .anchored_after = "x: y" },
        .{ .name = "quoted multi-line value", .with_block = "        with:\n          x: \"a\n            b\"\n", .anchored_after = "b\"" },
    };

    for (cases) |case| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const source = try std.fmt.allocPrint(alloc,
            \\name: CI
            \\on: push
            \\jobs:
            \\  build:
            \\    runs-on: ubuntu-latest
            \\    steps:
            \\      - uses: actions/checkout@v4
            \\{s}
        , .{case.with_block});

        var yp = yaml_parser_mod.Parser.init(alloc, source);
        const wf = try parseWorkflow(alloc, try yp.parse());
        const anchor = wf.jobs[0].steps[0].with_last_entry_end_byte;

        const expected: ?usize = if (case.anchored_after) |tail|
            std.mem.indexOf(u8, source, tail).? + tail.len
        else
            null;
        testing.expectEqual(expected, anchor) catch |err| {
            std.debug.print("case '{s}'\n", .{case.name});
            return err;
        };
    }
}
