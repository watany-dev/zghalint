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

/// Where a workflow parse gave up. Zig errors carry no payload, so callers
/// that want to print `file:line:col` read it from the out-parameter that
/// `parseWorkflowTracked` fills in.
pub const Failure = struct {
    /// Dotted path to the offending part of the workflow, e.g. `on` or
    /// `jobs.build.steps[1]`.
    path: []const u8,
    /// Null when the field is missing outright: there is no node to point at.
    span: ?yaml.Span,
};

const ParseContext = struct {
    allocator: std.mem.Allocator,
    type_mismatches: ?*std.ArrayList(type_validation.TypeMismatch),
    unknown_collector: ?*schema.UnknownKeyCollector,
    /// Absent for the entry points that parse a fragment (a standalone step)
    /// and have no whole-file error to report.
    failure: ?*?Failure = null,

    /// Records where the parse gave up. The innermost frame notes its own
    /// segment and each enclosing frame prepends its own as the error
    /// unwinds, so the reported path reads `jobs.build.steps[1]`. `span` is
    /// taken from the innermost note; the outer ones only extend the path.
    fn note(self: *const ParseContext, segment: []const u8, span: ?yaml.Span) void {
        const slot = self.failure orelse return;
        const inner = slot.* orelse {
            slot.* = .{ .path = segment, .span = span };
            return;
        };
        const path = std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ segment, inner.path }) catch segment;
        slot.* = .{ .path = path, .span = inner.span };
    }

    /// `note` with the segment built from `fmt`. Falls back to `fallback` when
    /// the formatting allocation fails: a parse error is already in flight and
    /// must not be replaced by an allocation error.
    fn noteFmt(
        self: *const ParseContext,
        comptime fmt: []const u8,
        args: anytype,
        fallback: []const u8,
        span: ?yaml.Span,
    ) void {
        if (self.failure == null) return;
        self.note(std.fmt.allocPrint(self.allocator, fmt, args) catch fallback, span);
    }
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

/// `with: fetch-depth: 0` parses to a mapping here too, but its entries sit on
/// the key's line: a fix that appends an entry below is not read back as part
/// of the mapping, so the same fix fires again on every `--fix` round (#370).
/// Such a mapping offers no append point at all.
fn isOwnLineBlockMapping(parent: Mapping, key: []const u8, body: Mapping) bool {
    if (body.entries.len == 0) return false;
    const key_span = parent.getKeySpan(key) orelse return false;
    return body.entries[0].key.span.start_line > key_span.start_line;
}

/// True when the entry's value is a mapping that opens on the key's own line
/// (`on: push:`, or a flow mapping). `full_span` covers the key's line only, so
/// an insertion anchored at its end byte lands inside the value.
fn startsInlineMapping(entry: yaml.MappingEntry) bool {
    const body = switch (entry.value) {
        .mapping => |m| m,
        else => return false,
    };
    if (body.entries.len == 0) return false;
    return body.entries[0].key.span.start_line == entry.key.span.start_line;
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

/// `permissions: {}` is the deny-all form and carries meaning, so only a
/// value-less `permissions:` counts as an empty section.
fn recordNullSection(list: *std.ArrayList(types.EmptySection), allocator: std.mem.Allocator, name: []const u8, node: Node) !void {
    if (node != .null_value) return;
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
    var failure: ?Failure = null;
    return parseWorkflowTracked(allocator, node, &failure);
}

/// `parseWorkflow` plus the location of the failure, for callers that report
/// the error to the user rather than skipping the file silently.
pub fn parseWorkflowTracked(
    allocator: std.mem.Allocator,
    node: Node,
    failure: *?Failure,
) ParseError!types.Workflow {
    var type_mismatches = std.ArrayList(type_validation.TypeMismatch).empty;
    errdefer type_mismatches.deinit(allocator);

    var unknown_collector = schema.UnknownKeyCollector.init(allocator);
    errdefer unknown_collector.deinit();

    var ctx = ParseContext{
        .allocator = allocator,
        .type_mismatches = &type_mismatches,
        .unknown_collector = &unknown_collector,
        .failure = failure,
    };

    const root = switch (node) {
        .mapping => |m| m,
        else => {
            ctx.note("workflow", node.getSpan());
            return error.InvalidValue;
        },
    };

    var empty = std.ArrayList(types.EmptySection).empty;
    defer empty.deinit(allocator);

    const on_node = root.get("on") orelse root.get("true") orelse {
        ctx.note("on", null);
        return error.MissingField;
    };
    try recordEmpty(&empty, allocator, "on", on_node);
    try recordTriggerNestedEmpty(&empty, allocator, on_node);
    const trigger = if (isEmptyContainer(on_node))
        types.Trigger{ .events = &.{} }
    else
        parseTrigger(allocator, on_node) catch |err| {
            ctx.note("on", on_node.getSpan());
            return err;
        };

    const jobs_node = root.get("jobs") orelse {
        ctx.note("jobs", null);
        return error.MissingField;
    };
    try recordEmpty(&empty, allocator, "jobs", jobs_node);
    const jobs = if (isEmptyContainer(jobs_node))
        try allocator.alloc(types.Job, 0)
    else
        try parseJobs(&ctx, jobs_node);

    var concurrency: ?types.Concurrency = null;
    if (root.get("concurrency")) |n| {
        try recordEmpty(&empty, allocator, "concurrency", n);
        if (!isEmptyContainer(n)) {
            concurrency = parseConcurrency(&ctx, n) catch |err| {
                ctx.note("concurrency", n.getSpan());
                return err;
            };
        }
    }

    var cache_mode: ?[]const u8 = null;
    var cache_mode_span: ?yaml.Span = null;
    if (root.get("cache-mode")) |n| {
        applyCacheMode(&ctx, n, &cache_mode, &cache_mode_span);
    }

    var workflow = types.Workflow{
        .name = root.getScalar("name"),
        .on = trigger,
        .concurrency = concurrency,
        .jobs = jobs,
        .cache_mode = cache_mode,
        .cache_mode_span = cache_mode_span,
        .type_mismatches = try type_mismatches.toOwnedSlice(allocator),
        .yaml_root = node,
    };

    if (root.get("permissions")) |n| {
        try recordNullSection(&empty, allocator, "permissions", n);
        if (n != .null_value) {
            const parsed = parsePermissions(allocator, n) catch |err| {
                ctx.note("permissions", n.getSpan());
                return err;
            };
            workflow.permissions = parsed.permissions;
            workflow.permissions_meta = parsed.meta;
            workflow.permission_problems = parsed.problems;
        }
    }

    if (root.get("env")) |n| {
        try recordEmpty(&empty, allocator, "env", n);
        if (!isEmptyContainer(n)) {
            const parsed = parseStringMapWithMeta(allocator, n) catch |err| {
                ctx.note("env", n.getSpan());
                return err;
            };
            workflow.env = parsed.values;
            workflow.env_meta = parsed.meta;
            workflow.env_keys = parseEnvKeys(allocator, n) catch |err| {
                ctx.note("env", n.getSpan());
                return err;
            };
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
            if (entry.key.span.start_col >= 1) {
                workflow.top_level_indent = entry.key.span.start_col - 1;
            }
            // A mapping that opens on the key's own line (`on: push:`) leaves
            // its children outside `full_span`, so an insertion at that anchor
            // lands inside the trigger rather than after it.
            // Lines the parser dropped under `on:` sit past its `full_span` but
            // inside its extent. A `>` there swallowed the rest of the file,
            // and the inserted `permissions:` line ended the scalar early --
            // the `<: *b` it had been holding became an undefined alias (fuzz).
            if (entry.full_span) |fs| {
                if (!startsInlineMapping(entry) and !entry.has_indented_tail) {
                    workflow.permissions_insertion_byte = fs.end_byte;
                    workflow.concurrency_insertion_byte = fs.end_byte;
                }
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
                events[i] = try parseEventConfig(allocator, entry.key.value, entry.value, entry.has_indented_tail);
                events[i].name_span = entry.key.span;
            }
            return .{ .events = events };
        },
        .null_value => return error.InvalidValue,
    }
}

/// `has_tail` says the parser dropped lines under this event's key. They sit
/// inside the event's extent but hold no node, so emptying the mapping lets the
/// next parse read one as the event's value (fuzz).
fn parseEventConfig(allocator: std.mem.Allocator, name: []const u8, node: Node, has_tail: bool) ParseError!types.EventConfig {
    const event_type = types.EventType.fromString(name);
    var config = types.EventConfig{ .event = event_type, .name = name };

    switch (node) {
        .null_value => {
            return config;
        },
        .mapping => |m| {
            config.config_keys = try collectEventConfigKeys(allocator, m, has_tail);
            config.types_key_span = m.getKeySpan("types");
            config.activity_types = try parseActivityTypes(allocator, m.get("types"));

            switch (event_type) {
                .workflow_call => {
                    if (m.get("inputs")) |inputs_node| {
                        const parsed = try parseWorkflowCallInputs(allocator, inputs_node);
                        config.workflow_call_inputs = parsed.inputs;
                        config.workflow_call_input_problems = parsed.problems;
                    }
                    if (m.get("secrets")) |secrets_node| {
                        config.workflow_call_secrets = try parseWorkflowCallSecrets(allocator, secrets_node);
                    }
                    if (m.get("outputs")) |outputs_node| {
                        config.workflow_call_outputs = try parseWorkflowCallOutputs(allocator, outputs_node);
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
    var entries = std.ArrayList(types.ScheduleEntry).empty;
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
    const scalar = switch (node) {
        .scalar => |s| s,
        else => return false,
    };
    return input_type.matchesScalar(scalar.value);
}

/// `secrets:` is a mapping of secret name to an optional
/// `{required:, description:}` mapping. A `secrets:` whose value is not a
/// mapping declares nothing, so it yields an empty list — same as an absent
/// key, which is what EXPR014 needs to stay quiet on.
fn parseWorkflowCallSecrets(allocator: std.mem.Allocator, node: Node) ParseError![]const types.SecretDef {
    const m = switch (node) {
        .mapping => |m| m,
        else => return &.{},
    };

    var secrets = try std.ArrayList(types.SecretDef).initCapacity(allocator, m.entries.len);
    for (m.entries) |entry| {
        var def = types.SecretDef{ .name = entry.key.value, .name_span = entry.key.span };
        switch (entry.value) {
            .mapping => |sm| {
                if (sm.get("required")) |required_node| {
                    def.required = parseYamlBool(required_node);
                }
            },
            else => {},
        }
        secrets.appendAssumeCapacity(def);
    }
    return secrets.toOwnedSlice(allocator);
}

/// `outputs:` is a mapping of output name to a `{value:, description:}`
/// mapping. An entry whose value is not a mapping still declares the name, so
/// it is kept with no `value` rather than dropped.
fn parseWorkflowCallOutputs(allocator: std.mem.Allocator, node: Node) ParseError![]const types.CallOutputDef {
    const m = switch (node) {
        .mapping => |m| m,
        else => return &.{},
    };

    const outputs = try allocator.alloc(types.CallOutputDef, m.entries.len);
    for (m.entries, outputs) |entry, *def| {
        def.* = .{ .name = entry.key.value, .name_span = entry.key.span };
        const om = switch (entry.value) {
            .mapping => |om| om,
            else => continue,
        };
        switch (om.get("value") orelse continue) {
            .scalar => |s| {
                def.value = s.value;
                def.value_meta = .{ .value_span = s.span, .style = s.style };
            },
            else => {},
        }
    }
    return outputs;
}

/// Where RW001's autofix writes the `type:` it inferred: in front of the
/// definition's first key, so the new entry lands inside the input's own
/// mapping whatever order the author wrote the other keys in. Returns null
/// when there is no `default:` to infer from, or no key to anchor on (a flow
/// mapping `{}`, or one whose key the parser gave no column for).
fn callInputTypeInsertion(
    input_mapping: Mapping,
    default_value: ?[]const u8,
    default_style: ?yaml.ScalarStyle,
) ?types.CallInputTypeInsertion {
    const value = default_value orelse return null;
    const style = default_style orelse return null;
    if (input_mapping.entries.len == 0) return null;

    const first = input_mapping.entries[0].key.span;
    if (first.start_col == 0) return null;

    return .{
        .anchor_byte = first.start_byte,
        .indent = first.start_col - 1,
        .type_name = types.CallableInputType.inferFromScalar(value, style).name(),
    };
}

fn parseWorkflowCallInputs(allocator: std.mem.Allocator, node: Node) ParseError!ParsedWorkflowCallInputs {
    const inputs_mapping = switch (node) {
        .mapping => |m| m,
        else => return .{ .inputs = &.{}, .problems = &.{} },
    };

    var inputs = std.ArrayList(types.InputDef).empty;
    errdefer inputs.deinit(allocator);
    var problems = std.ArrayList(types.WorkflowCallInputProblem).empty;
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

        // Read `default:` before `type:` so a missing `type:` can name the
        // type its default implies (RW001 autofix).
        var default_style: ?yaml.ScalarStyle = null;
        if (input_mapping.get("default")) |default_node| {
            switch (default_node) {
                .scalar => |s| {
                    def.default_value = s.value;
                    def.default_span = s.span;
                    default_style = s.style;
                },
                else => {},
            }
        }

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
                .type_insertion = callInputTypeInsertion(input_mapping, def.default_value, default_style),
            });
        }

        if (input_mapping.get("required")) |required_node| {
            def.required = parseYamlBool(required_node);
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
                        .detail = input_type.name(),
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

fn collectEventConfigKeys(allocator: std.mem.Allocator, m: Mapping, has_tail: bool) ParseError![]const types.EventConfigKey {
    const keys = try allocator.alloc(types.EventConfigKey, m.entries.len);
    // Removing the last key leaves the event without a value, and a dropped
    // line below becomes one: `*r` under an emptied `workflow_call:` turned
    // into an undefined alias and the whole file stopped parsing (fuzz).
    const empties = has_tail and m.entries.len == 1;
    for (m.entries, 0..) |entry, i| {
        keys[i] = .{
            .name = entry.key.value,
            .span = entry.key.span,
            .full_span = if (empties) null else eventKeyFullSpan(m, i),
        };
    }
    return keys;
}

fn eventKeyFullSpan(mapping: Mapping, index: usize) ?yaml.Span {
    const entry = mapping.entries[index];
    if (entry.full_span) |span| return span;
    if (!mapping.flow or mapping.entries.len < 2) return null;
    const close = mapping.close_byte orelse return null;
    var span = entry.key.span;
    const value_span = entry.value.getSpan();
    // A wider gap can contain an anchor definition that deletion would remove.
    if (value_span.start_byte <= span.end_byte or value_span.start_byte - span.end_byte > 2) return null;
    _ = eventFilterValueEnd(entry.value) orelse return null;
    if (span.start_byte <= mapping.span.start_byte or span.end_byte >= close) return null;
    if (index + 1 < mapping.entries.len) {
        const next = mapping.entries[index + 1].key.span;
        if (next.start_byte <= span.end_byte or next.start_byte >= close) return null;
        span.end_byte = next.start_byte;
        span.end_line = next.start_line;
        span.end_col = next.start_col;
    } else {
        const previous = mapping.entries[index - 1];
        const start = eventFilterValueEnd(previous.value) orelse return null;
        const end = eventFilterValueEnd(entry.value) orelse return null;
        if (start <= previous.key.span.end_byte or start >= span.start_byte or end <= span.end_byte or end >= close) return null;
        span.start_byte = start;
        span.end_byte = end;
    }
    return span;
}

fn eventFilterValueEnd(node: Node) ?usize {
    return switch (node) {
        .scalar => |s| if (s.unterminated) null else s.span.end_byte,
        .sequence => |s| if (s.item_deletes.len == s.items.len) s.close_byte else null,
        else => null,
    };
}

/// `types:` is read for every event, not just the ones with a filter, so an
/// empty or malformed value must not fail the whole parse: SYN010 reports on
/// what is there and stays quiet about what is not.
fn parseActivityTypes(allocator: std.mem.Allocator, node: ?Node) ParseError!types.FilterPatternList {
    const n = node orelse return .{};
    const parsed = parseStringArrayWithSpans(allocator, n) catch |err| switch (err) {
        error.InvalidValue => return .{},
        else => return err,
    };
    return .{ .values = parsed.values, .spans = parsed.spans };
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
    var values = std.ArrayList([]const u8).empty;
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

    var inputs = std.ArrayList(types.DispatchInputDef).empty;
    errdefer inputs.deinit(allocator);
    var problems = std.ArrayList(types.WorkflowDispatchInputProblem).empty;
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
    // A `jobs:` holding a scalar is a type error SYN004 reports. Failing the
    // parse over it threw away every other diagnostic in the file, and an
    // inserted `permissions:` line was enough to turn a linted file into an
    // unlintable one (fuzz).
    if (!type_validation.checkMapping(node, "jobs", ctx.type_mismatches, ctx.allocator)) {
        return &.{};
    }
    const m = node.mapping;

    const jobs = try ctx.allocator.alloc(types.Job, m.entries.len);
    for (m.entries, 0..) |entry, i| {
        jobs[i] = parseJob(ctx, entry.key.value, entry.key.span, entry.value) catch |err| {
            ctx.noteFmt("jobs.{s}", .{entry.key.value}, "jobs", entry.key.span);
            return err;
        };
    }
    return jobs;
}

fn parseJob(ctx: *ParseContext, id: []const u8, id_span: yaml.Span, node: Node) ParseError!types.Job {
    // A job id with nothing under it is an unfinished workflow, and one holding
    // a scalar is a type error SYN004 reports. Failing the parse over either
    // made every other diagnostic in the file disappear (fuzz).
    // The id is the only span such a job has, and a rule reporting it needs a
    // real line: a default span put BP001 at line 0 (fuzz).
    if (node == .null_value or !type_validation.checkMapping(node, "job", ctx.type_mismatches, ctx.allocator)) {
        // No body means no block to insert an entry into: anchoring on the id
        // put `timeout-minutes: 30` on the `jobs:` line, and every pass added
        // another one (fuzz).
        return types.Job{ .id = id, .id_span = id_span, .span = id_span, .body_own_line = false };
    }
    const m = node.mapping;

    var job = types.Job{ .id = id, .id_span = id_span };
    job.span = m.span;
    job.entry_count = m.entries.len;
    // `j: runs-on: x` puts the body on the job id's line, where an insertion
    // aligned to the body's column would land mid-line. A body that is not
    // indented past the id is no better: `e{up: :` followed by `d:` at the id's
    // own column parses as a body here, but an insertion aligned to it reads
    // back as another job (fuzz).
    job.body_own_line = m.entries.len > 0 and
        m.entries[0].key.span.start_line > id_span.start_line and
        m.entries[0].key.span.start_col > id_span.start_col;
    job.job_indent = m.span.start_col;
    job.name = m.getScalar("name");
    job.runs_on = m.getScalar("runs-on");
    if (m.get("runs-on")) |n| {
        switch (n) {
            .scalar => |s| {
                job.runs_on_value_span = s.span;
                job.runs_on_value_style = s.style;
            },
            else => {},
        }
        // A runner group (`runs-on: {group:, labels:}`) keeps its labels one
        // level down; every other form is the label list itself.
        const labels_node: ?Node = switch (n) {
            .mapping => |rm| rm.get("labels"),
            .scalar, .sequence => n,
            else => null,
        };
        if (labels_node) |ln| {
            const parsed = parseStringArrayWithSpans(ctx.allocator, ln) catch |err| switch (err) {
                // A non-scalar entry is not a label zghalint can read; the
                // rest of the job still parses.
                error.InvalidValue, error.MissingField => null,
                else => return err,
            };
            if (parsed) |p| {
                job.runs_on_labels = p.values;
                job.runs_on_label_spans = p.spans;
            }
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

    var empty = std.ArrayList(types.EmptySection).empty;
    defer empty.deinit(ctx.allocator);

    // Insertion anchor for job-level `permissions:` / `concurrency:` lands after
    // the `runs-on:` line; `uses:` (reusable workflow) works as a fallback.
    for (m.entries) |entry| {
        const name = entry.key.value;
        if (std.mem.eql(u8, name, "runs-on") or std.mem.eql(u8, name, "uses")) {
            if (startsInlineMapping(entry)) continue;
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
        job.needs_deletes = switch (needs_node) {
            .sequence => |seq| seq.item_deletes,
            else => &.{},
        };
    }

    if (m.get("steps")) |n| {
        try recordEmpty(&empty, ctx.allocator, "steps", n);
        if (!isEmptyContainer(n)) {
            job.steps = try parseSteps(ctx, n, keyLine(m, "steps"));
            job.step_deletes = switch (n) {
                .sequence => |seq| seq.item_deletes,
                else => &.{},
            };
        }
    }

    if (m.get("permissions")) |n| {
        try recordNullSection(&empty, ctx.allocator, "permissions", n);
        if (n != .null_value) {
            const parsed = try parsePermissions(ctx.allocator, n);
            job.permissions = parsed.permissions;
            job.permissions_meta = parsed.meta;
            job.permission_problems = parsed.problems;
        }
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
        try recordEmpty(&empty, ctx.allocator, "concurrency", n);
        if (!isEmptyContainer(n)) {
            job.concurrency = try parseConcurrency(ctx, n);
        }
    }
    if (m.get("strategy")) |n| {
        try recordEmpty(&empty, ctx.allocator, "strategy", n);
        if (!isEmptyContainer(n)) {
            job.strategy = try parseStrategy(ctx, n);
            job.strategy.?.entry_span = m.getFullSpan("strategy");
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
            job.with_args = try parseCallArgs(ctx.allocator, n);
        }
    }
    if (m.get("secrets")) |n| {
        try recordEmpty(&empty, ctx.allocator, "secrets", n);
        if (!isEmptyContainer(n)) {
            job.secrets = try parseSecretsConfig(ctx.allocator, n);
            job.secrets_args = try parseCallArgs(ctx.allocator, n);
            // A flow `{secrets: inherit}` cannot take a block mapping, and a
            // quoted `'inherit'` would leave the quotes around the rewrite.
            if (job.secrets) |secrets| {
                if (secrets == .inherit and !m.flow) {
                    switch (n) {
                        .scalar => |s| {
                            if (s.style == .plain) job.secrets_inherit_span = s.span;
                        },
                        else => {},
                    }
                }
            }
        }
    }
    if (m.get("container")) |n| {
        try recordEmpty(&empty, ctx.allocator, "container", n);
        if (!isEmptyContainer(n)) {
            job.container = try parseContainer(ctx.allocator, n, ctx.type_mismatches);
        }
    }
    if (m.get("services")) |n| {
        try recordEmpty(&empty, ctx.allocator, "services", n);
        if (!isEmptyContainer(n)) {
            job.services = try parseServices(ctx.allocator, n, ctx.type_mismatches);
        }
    }
    if (m.get("outputs")) |n| {
        try recordEmpty(&empty, ctx.allocator, "outputs", n);
        job.outputs = try parseOutputKeys(ctx.allocator, n);
    }
    if (m.get("defaults")) |n| {
        try recordEmpty(&empty, ctx.allocator, "defaults", n);
        job.defaults = parseDefaults(n);
    }
    if (m.get("cache-mode")) |n| {
        applyCacheMode(ctx, n, &job.cache_mode, &job.cache_mode_span);
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

/// A composite action's `runs.steps` never reach `parseWorkflow`, so the step
/// rules get at them through this wrapper (#254). Type mismatches and unknown
/// keys are reported through channels the action metadata linter does not own,
/// so both collectors stay off here.
pub fn parseStandaloneStep(allocator: std.mem.Allocator, node: Node) ParseError!types.Step {
    var ctx = ParseContext{
        .allocator = allocator,
        .type_mismatches = null,
        .unknown_collector = null,
    };
    return parseStep(&ctx, node);
}

/// Line the mapping's `name` key sits on, or 0 when it has none: a step whose
/// span starts on that line shares it with the key that introduces it.
fn keyLine(m: Mapping, name: []const u8) u32 {
    for (m.entries) |entry| {
        if (std.mem.eql(u8, entry.key.value, name)) return entry.key.span.start_line;
    }
    return 0;
}

fn parseSteps(ctx: *ParseContext, node: Node, steps_key_line: u32) ParseError![]const types.Step {
    const seq = switch (node) {
        .sequence => |s| s,
        // A `steps:` holding something else is a type error, not a reason to
        // drop every other diagnostic in the file. A merge key folded a mapping
        // into it and SEC010's rewrite made the whole parse fail (fuzz).
        else => {
            _ = type_validation.checkSequence(node, "steps", ctx.type_mismatches, ctx.allocator);
            return &.{};
        },
    };

    const steps = try ctx.allocator.alloc(types.Step, seq.items.len);
    for (seq.items, 0..) |item, i| {
        steps[i] = parseStep(ctx, item) catch |err| {
            ctx.noteFmt("steps[{d}]", .{i}, "steps", item.getSpan());
            return err;
        };
        // A step written as `{uses: x}` has no block line to insert into: an
        // insertion anchored inside the braces is flow text, not a `with:`
        // block, and it left the step holding a scalar where a mapping belonged
        // (fuzz).
        steps[i].own_line = item.getSpan().start_line > steps_key_line and
            !(item == .mapping and item.mapping.flow);
    }
    return steps;
}

/// True when a block scalar would claim a sibling key written below it. YAML
/// takes the content indentation from the first non-empty line, so a scalar with
/// none is still open and swallows whatever comes next. A scalar whose content
/// sits no further right than its own key is under-indented and swallows a
/// sibling too. `key_column` is 1-based, as spans are.
fn blockScalarIndentationOpen(value: []const u8, key_column: u32) bool {
    if (std.mem.indexOfScalar(u8, value, '\n') == null) return true;
    var lines = std.mem.splitScalar(u8, value, '\n');
    while (lines.next()) |line| {
        const indent = std.mem.indexOfNone(u8, line, " \t") orelse continue;
        return indent < key_column;
    }
    return true;
}

fn parseStepControl(ctx: *ParseContext, m: Mapping, step: *types.Step) ParseError!void {
    if (m.get("wait")) |n| {
        const parsed = try parseStringArrayWithSpans(ctx.allocator, n);
        const refs = try ctx.allocator.alloc(types.StepRef, parsed.values.len);
        for (parsed.values, parsed.spans, refs) |id, span, *ref| {
            ref.* = .{ .id = id, .span = span };
        }
        step.control = .{ .wait = refs };
        return;
    }
    if (m.get("wait-all") != null) {
        step.control = .wait_all;
        return;
    }
    if (m.get("cancel")) |n| {
        switch (n) {
            .scalar => |s| {
                step.control = .{ .cancel = .{ .id = s.value, .span = s.span } };
            },
            else => {
                if (ctx.type_mismatches) |list| {
                    list.append(ctx.allocator, .{
                        .field = "cancel",
                        .expected = "string",
                        .actual = switch (n) {
                            .mapping => "mapping",
                            .sequence => "sequence",
                            .null_value => "null",
                            .scalar => "string",
                        },
                        .span = n.getSpan(),
                    }) catch {};
                }
                step.control = .{ .cancel = .{ .id = "", .span = n.getSpan() } };
            },
        }
        return;
    }
    if (m.get("parallel")) |n| {
        if (!type_validation.checkSequence(n, "parallel", ctx.type_mismatches, ctx.allocator)) {
            step.control = .{ .parallel = &.{} };
            return;
        }
        step.control = .{ .parallel = try parseSteps(ctx, n, keyLine(m, "parallel")) };
    }
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
    if (m.get("name")) |n| {
        switch (n) {
            .scalar => |s| step.name_meta = scalarMeta(s),
            else => {},
        }
    }
    step.run = m.getScalar("run");
    if (m.get("shell")) |n| {
        step.shell_key_present = true;
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
        // A block scalar whose indentation is still open swallows the line
        // below it as content, so a key inserted there is not a key at all
        // and --fix appends it again every round (fuzz).
        var indentation_open = false;
        switch (entry.value) {
            .scalar => |s| {
                step.run_meta = .{ .value_span = s.span, .style = s.style };
                indentation_open = (s.style == .literal or s.style == .folded) and
                    blockScalarIndentationOpen(s.value, entry.key.span.start_col);
            },
            else => {},
        }
        if (entry.full_span) |fs| {
            if (!indentation_open) step.shell_insertion_byte = fs.end_byte;
        }
        break;
    }

    if (m.get("uses")) |uses_node| {
        switch (uses_node) {
            .scalar => |s| {
                step.uses = types.ActionRef.parse(s.value);
                step.uses_value_span = s.span;
                // A quoted `uses:` that never closes swallows everything below
                // it, so a `with:` block written after it becomes more quoted
                // text and `--fix` writes it again every round (fuzz).
                // Lines the parser dropped under `uses:` sit below the value
                // but inside the entry, so a `with:` block written at the
                // value's end adopts them: a stray `<: *g` became a real merge
                // key and the alias had no anchor to resolve (fuzz).
                step.uses_value_end_byte = if (s.unterminated or m.hasIndentedTail("uses"))
                    null
                else
                    s.span.end_byte;
                step.uses_value_style = s.style;
                step.uses_value_ends_line = s.ends_line;
                step.uses_line_comment = s.line_comment;
            },
            else => {},
        }
        for (m.entries) |entry| {
            if (std.mem.eql(u8, entry.key.value, "uses")) {
                step.uses_key_col = entry.key.span.start_col;
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
    if (m.get("background")) |n| {
        if (type_validation.checkBool(
            n,
            "background",
            ctx.type_mismatches,
            ctx.allocator,
        )) |value| {
            step.background = value;
        }
    }
    try parseStepControl(ctx, m, &step);
    var empty = std.ArrayList(types.EmptySection).empty;
    defer empty.deinit(ctx.allocator);
    if (m.get("with")) |with_node| {
        step.with_key_present = true;
        try recordEmpty(&empty, ctx.allocator, "with", with_node);
        // `with: 4` is a type error SYN004 reports, not a reason to give up on
        // the whole file (fuzz).
        if (!isEmptyContainer(with_node) and
            type_validation.checkMapping(with_node, "with", ctx.type_mismatches, ctx.allocator))
        {
            const parsed_with = try parseStringMapWithMeta(ctx.allocator, with_node);
            step.with = parsed_with.values;
            step.with_meta = parsed_with.meta;
            switch (with_node) {
                .mapping => |with_mapping| {
                    if (with_mapping.entries.len > 0) {
                        step.with_key_col = with_mapping.entries[0].key.span.start_col;
                        const last = with_mapping.entries[with_mapping.entries.len - 1];
                        // Appending after the last entry is only safe when `with:`
                        // is a block mapping (a flow entry has no full_span) and the
                        // last value ends where its span says: a flow collection's
                        // span covers only its opening bracket, and a block scalar
                        // ends at the start of the next line (#171).
                        if (last.full_span != null and isInlineScalar(last.value) and
                            isOwnLineBlockMapping(m, "with", with_mapping))
                        {
                            step.with_last_entry_end_byte = last.value.getSpan().end_byte;
                        }
                    }
                },
                else => {},
            }
        }
    }
    if (m.get("env")) |n| {
        step.env_key_present = true;
        try recordEmpty(&empty, ctx.allocator, "env", n);
        if (!isEmptyContainer(n) and
            type_validation.checkMapping(n, "env", ctx.type_mismatches, ctx.allocator))
        {
            const parsed = try parseStringMapWithMeta(ctx.allocator, n);
            step.env = parsed.values;
            step.env_meta = parsed.meta;
            step.env_keys = try parseEnvKeys(ctx.allocator, n);
            switch (n) {
                .mapping => |env_mapping| {
                    if (env_mapping.entries.len > 0) {
                        step.env_key_col = env_mapping.entries[0].key.span.start_col;
                        const last = env_mapping.entries[env_mapping.entries.len - 1];
                        // Same conditions as `with_last_entry_end_byte`: only a
                        // block mapping whose last value is an inline scalar
                        // ends where its span says it does (#171).
                        if (last.full_span != null and isInlineScalar(last.value) and
                            isOwnLineBlockMapping(m, "env", env_mapping))
                        {
                            step.env_last_entry_end_byte = last.value.getSpan().end_byte;
                        }
                    }
                },
                else => {},
            }
        }
    }
    if (m.entries.len > 0) {
        step.first_key_start_byte = m.entries[0].key.span.start_byte;
        step.first_key_col = m.entries[0].key.span.start_col;
    }
    step.empty_sections = try empty.toOwnedSlice(ctx.allocator);

    if (ctx.unknown_collector) |c| try c.checkMapping(m, "step", schema.stepExpectedKeys(m), &.{});

    return step;
}

fn parsePermissions(allocator: std.mem.Allocator, node: Node) ParseError!ParsedPermissions {
    var problems = std.ArrayList(types.PermissionProblem).empty;
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
                            if (types.isAllowedPermissionLevel(comptime types.permissionScopeKey(field), lvl)) {
                                @field(perms, field) = lvl;
                                @field(meta, field) = entry.value.scalar.span;
                            } else {
                                try problems.append(allocator, .{
                                    .kind = .invalid_level,
                                    .text = entry.value.scalar.value,
                                    .scope = entry.key.value,
                                    .span = entry.value.scalar.span,
                                });
                            }
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

fn applyCacheMode(
    ctx: *ParseContext,
    node: Node,
    value: *?[]const u8,
    span: *?yaml.Span,
) void {
    switch (node) {
        .scalar => |s| {
            value.* = s.value;
            span.* = s.span;
        },
        else => {
            const mismatches = ctx.type_mismatches orelse return;
            mismatches.append(ctx.allocator, .{
                .field = "cache-mode",
                .expected = "string",
                .actual = switch (node) {
                    .mapping => "mapping",
                    .sequence => "sequence",
                    .null_value => "null",
                    .scalar => unreachable,
                },
                .span = node.getSpan(),
            }) catch {};
        },
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

fn scalarMeta(s: yaml.Scalar) types.ScalarValueMeta {
    return .{ .value_span = s.span, .style = s.style };
}

fn parseConcurrency(ctx: *ParseContext, node: Node) ParseError!types.Concurrency {
    switch (node) {
        .scalar => |s| {
            return .{ .group = s.value, .group_meta = scalarMeta(s) };
        },
        .mapping => |m| {
            const group = switch (m.get("group") orelse return error.MissingField) {
                .scalar => |s| s,
                else => return error.MissingField,
            };
            const concurrency = types.Concurrency{
                .group = group.value,
                .group_meta = scalarMeta(group),
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
    // A `strategy:` holding a scalar is a type error SYN004 reports, not a reason
    // to fail the whole workflow parse: removing `fail-fast` left the junk line
    // below it as the section's value, so a file that linted a moment before
    // stopped parsing (fuzz).
    if (!type_validation.checkMapping(node, "strategy", ctx.type_mismatches, ctx.allocator)) {
        return types.Strategy{};
    }
    const m = node.mapping;

    var strategy = types.Strategy{ .entry_count = m.entries.len };
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
        } else if (std.mem.eql(u8, entry.key.value, "matrix")) {
            strategy.matrix_key_present = true;
            strategy.matrix = try parseMatrix(ctx.allocator, entry.value);
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

/// `matrix:` is a mapping of axis name to a sequence of values. A non-mapping
/// (`matrix: ${{ fromJSON(...) }}`) carries no axes to inspect.
fn parseMatrix(allocator: std.mem.Allocator, node: Node) ParseError!?types.Matrix {
    const m = switch (node) {
        .mapping => |m| m,
        else => return null,
    };

    var axes = try std.ArrayList(types.MatrixAxis).initCapacity(allocator, m.entries.len);
    for (m.entries) |entry| {
        axes.appendAssumeCapacity(switch (entry.value) {
            .sequence => |s| .{
                .name = entry.key.value,
                .values = s.items,
                .value_deletes = s.item_deletes,
            },
            .scalar => |scalar| .{
                .name = entry.key.value,
                .dynamic = type_validation.containsExpression(scalar.value),
            },
            else => .{ .name = entry.key.value },
        });
    }

    return .{ .axes = try axes.toOwnedSlice(allocator) };
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
            var map: types.StringMap = .empty;
            for (m.entries) |entry| {
                switch (entry.value) {
                    .scalar => |sv| try map.put(allocator, entry.key.value, sv.value),
                    else => {},
                }
            }
            return .{ .map = map };
        },
        else => return error.InvalidValue,
    }
}

fn parseCredentials(
    allocator: std.mem.Allocator,
    node: Node,
    mismatches: ?*std.ArrayList(type_validation.TypeMismatch),
) ParseError!?types.Credentials {
    // A `credentials:` written with nothing under it carries no username and no
    // password, and one holding a scalar is a type error SYN004 reports.
    // Rejecting either failed the whole workflow parse over one section, so
    // every other rule went unreported (fuzz).
    if (node == .null_value) return null;
    if (!type_validation.checkMapping(node, "credentials", mismatches, allocator)) return null;
    const m = node.mapping;
    return .{
        .username = m.getScalar("username"),
        .password = m.getScalar("password"),
    };
}

fn parseContainer(
    allocator: std.mem.Allocator,
    node: Node,
    mismatches: ?*std.ArrayList(type_validation.TypeMismatch),
) ParseError!types.Container {
    switch (node) {
        .scalar => |s| {
            return .{ .image = s.value };
        },
        .mapping => |m| {
            return .{
                .image = m.getScalar("image"),
                .credentials = if (m.get("credentials")) |n|
                    try parseCredentials(allocator, n, mismatches)
                else
                    null,
                .env_keys = if (m.get("env")) |n| try parseEnvKeys(allocator, n) else &.{},
            };
        },
        else => return error.InvalidValue,
    }
}

fn parseServices(
    allocator: std.mem.Allocator,
    node: Node,
    mismatches: ?*std.ArrayList(type_validation.TypeMismatch),
) ParseError![]const types.Service {
    // A `services:` holding anything but a mapping is a type error SYN004
    // reports. Failing the whole workflow parse over it dropped every other
    // diagnostic in the file (fuzz).
    if (!type_validation.checkMapping(node, "services", mismatches, allocator)) return &.{};
    const m = node.mapping;

    const services = try allocator.alloc(types.Service, m.entries.len);
    for (m.entries, 0..) |entry, i| {
        switch (entry.value) {
            .mapping => |vm| {
                services[i] = .{
                    .name = entry.key.value,
                    .image = vm.getScalar("image"),
                    .credentials = if (vm.get("credentials")) |n|
                        try parseCredentials(allocator, n, mismatches)
                    else
                        null,
                    .env_keys = if (vm.get("env")) |n| try parseEnvKeys(allocator, n) else &.{},
                };
            },
            .scalar => |s| {
                services[i] = .{
                    .name = entry.key.value,
                    .image = s.value,
                };
            },
            // A service written with nothing under it names no image. It is
            // reported as an empty section; failing the whole workflow parse
            // over it dropped every other diagnostic too (fuzz).
            .null_value => services[i] = .{ .name = entry.key.value },
            // A service holding a sequence names no image either. SYN001's
            // rename reaches this: `erices:` became `services:` without
            // changing what was written under it (fuzz).
            else => {
                _ = type_validation.checkMapping(entry.value, "services", mismatches, allocator);
                services[i] = .{ .name = entry.key.value };
            },
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

    var values: types.StringMap = .empty;
    var meta: types.ScalarValueMetaMap = .empty;
    for (m.entries) |entry| {
        switch (entry.value) {
            .scalar => |s| {
                try values.put(allocator, entry.key.value, s.value);
                var entry_meta = scalarMeta(s);
                entry_meta.key_span = entry.key.span;
                try meta.put(allocator, entry.key.value, entry_meta);
            },
            // A key whose value is a sequence, a mapping, or nothing at all is
            // still a key the workflow wrote. Dropping it made DEP004/DEP005
            // report the input as not provided; it is recorded with an empty
            // value instead, and without meta, because there is no scalar span
            // to point a diagnostic at.
            else => try values.put(allocator, entry.key.value, ""),
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

/// Like `parseEnvKeys`, but for the `with:` / `secrets:` mapping of a
/// reusable workflow call: the RW rules validate key names, so no entry may be
/// dropped for having a non-scalar value.
fn parseCallArgs(allocator: std.mem.Allocator, node: Node) ParseError![]const types.CallArg {
    const m = switch (node) {
        .mapping => |m| m,
        else => return &.{},
    };

    const args = try allocator.alloc(types.CallArg, m.entries.len);
    for (m.entries, args) |entry, *arg| {
        arg.* = .{ .name = entry.key.value, .name_span = entry.key.span };
        switch (entry.value) {
            .scalar => |s| {
                arg.value = s.value;
                arg.value_span = s.span;
            },
            else => {},
        }
    }
    return args;
}

fn parseOutputKeys(allocator: std.mem.Allocator, node: Node) ParseError![]const types.OutputKey {
    const m = switch (node) {
        .mapping => |m| m,
        else => return &.{},
    };

    const keys = try allocator.alloc(types.OutputKey, m.entries.len);
    for (m.entries, keys) |entry, *key| {
        key.* = .{
            .name = entry.key.value,
            .span = entry.key.span,
            .value = switch (entry.value) {
                .scalar => |scalar| scalar.value,
                else => null,
            },
        };
    }
    return keys;
}

const ParsedStringArray = struct {
    values: []const []const u8,
    spans: []const yaml.Span,
};

fn parseStringArrayWithSpans(allocator: std.mem.Allocator, node: Node) ParseError!ParsedStringArray {
    switch (node) {
        // An entry that is not a scalar is not a string zghalint can read, but
        // the list around it still is: `needs: [\n` parses as a sequence
        // holding one empty item, and rejecting it used to make the whole file
        // unlintable (fuzz).
        .sequence => |seq| {
            const values = try allocator.alloc([]const u8, seq.items.len);
            const spans = try allocator.alloc(yaml.Span, seq.items.len);
            var len: usize = 0;
            for (seq.items) |item| {
                switch (item) {
                    .scalar => |s| {
                        values[len] = s.value;
                        spans[len] = s.span;
                        len += 1;
                    },
                    else => {},
                }
            }
            return .{ .values = values[0..len], .spans = spans[0..len] };
        },
        .scalar => |s| {
            const values = try allocator.alloc([]const u8, 1);
            values[0] = s.value;
            const spans = try allocator.alloc(yaml.Span, 1);
            spans[0] = s.span;
            return .{ .values = values, .spans = spans };
        },
        // `needs:` left empty is a list of nothing, not a broken workflow.
        // Rejecting it used to make the whole file unlintable (fuzz).
        .null_value => return .{ .values = &.{}, .spans = &.{} },
        // A mapping holds no strings either. `branches: l:` puts two keys on
        // one line, and rejecting it failed the whole workflow parse, so every
        // other diagnostic on the file went unreported (fuzz).
        .mapping => return .{ .values = &.{}, .spans = &.{} },
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

test "parseStep accepts background wait wait-all cancel and parallel" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const yaml_parser_mod = @import("../yaml/parser.zig");

    const source =
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: producer
        \\        background: true
        \\        run: echo value=ready >> "$GITHUB_OUTPUT"
        \\      - name: Wait for producer
        \\        wait: producer
        \\      - wait-all:
        \\      - cancel: producer
        \\      - parallel:
        \\          - run: echo frontend
        \\          - run: echo backend
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());
    try testing.expectEqual(@as(usize, 5), wf.jobs[0].steps.len);

    const producer = wf.jobs[0].steps[0];
    try testing.expect(producer.background);
    try testing.expectEqual(types.StepKind.run, producer.kind());

    const wait_step = wf.jobs[0].steps[1];
    try testing.expectEqual(types.StepKind.wait, wait_step.kind());
    const wait_refs = wait_step.control.?.wait;
    try testing.expectEqual(@as(usize, 1), wait_refs.len);
    try testing.expectEqualStrings("producer", wait_refs[0].id);

    try testing.expectEqual(types.StepKind.wait_all, wf.jobs[0].steps[2].kind());
    try testing.expectEqual(types.StepKind.cancel, wf.jobs[0].steps[3].kind());
    try testing.expectEqualStrings("producer", wf.jobs[0].steps[3].control.?.cancel.id);

    const parallel = wf.jobs[0].steps[4];
    try testing.expectEqual(types.StepKind.parallel, parallel.kind());
    try testing.expectEqual(@as(usize, 2), parallel.nestedSteps().len);
    try testing.expectEqualStrings("echo frontend", parallel.nestedSteps()[0].run.?);
    try testing.expectEqualStrings("echo backend", parallel.nestedSteps()[1].run.?);
    try testing.expectEqual(@as(usize, 0), wf.unknown_keys.len);
}

test "parseStep records a type mismatch for a non-scalar cancel" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const yaml_parser_mod = @import("../yaml/parser.zig");

    const source =
        \\on: push
        \\jobs:
        \\  verify:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - cancel: [producer]
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    var failure: ?Failure = null;
    const wf = try parseWorkflowTracked(alloc, try yp.parse(), &failure);
    try testing.expectEqual(types.StepKind.cancel, wf.jobs[0].steps[0].kind());
    try testing.expectEqualStrings("", wf.jobs[0].steps[0].control.?.cancel.id);
    try testing.expectEqual(@as(usize, 1), wf.type_mismatches.len);
    try testing.expectEqualStrings("cancel", wf.type_mismatches[0].field);
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

test "parseJob records secrets_inherit_span for a block-style plain inherit" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const yaml_parser_mod = @import("../yaml/parser.zig");
    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\    secrets: inherit
        \\
    ;
    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());
    const job = wf.jobs[0];
    try testing.expect(job.secrets.? == .inherit);
    const span = job.secrets_inherit_span orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("inherit", source[span.start_byte..span.end_byte]);
}

test "parseJob leaves secrets_inherit_span null for quoted and flow inherit" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const yaml_parser_mod = @import("../yaml/parser.zig");

    {
        const source =
            \\on: push
            \\jobs:
            \\  call:
            \\    uses: ./.github/workflows/reusable.yml
            \\    secrets: "inherit"
            \\
        ;
        var yp = yaml_parser_mod.Parser.init(alloc, source);
        const wf = try parseWorkflow(alloc, try yp.parse());
        try testing.expect(wf.jobs[0].secrets.? == .inherit);
        try testing.expect(wf.jobs[0].secrets_inherit_span == null);
    }
    {
        const source =
            \\on: push
            \\jobs:
            \\  call: { uses: ./.github/workflows/reusable.yml, secrets: inherit }
            \\
        ;
        var yp = yaml_parser_mod.Parser.init(alloc, source);
        const wf = try parseWorkflow(alloc, try yp.parse());
        try testing.expect(wf.jobs[0].secrets.? == .inherit);
        try testing.expect(wf.jobs[0].secrets_inherit_span == null);
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

test "parseStringMapWithMeta keeps a key whose value is not a scalar" {
    // DEP004 / DEP005 read the key set to decide whether a required input was
    // provided, so a `path:` written as a sequence must not look absent.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var items = [_]Node{mkScalar("~/.cache")};
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("path"), .value = mkSequence(&items), .span = mkSpan() },
    };

    const parsed = try parseStringMapWithMeta(arena.allocator(), mkMapping(&entries));
    try testing.expectEqualStrings("", parsed.values.get("path").?);
    try testing.expect(parsed.meta.get("path") == null);
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

test "parseWorkflow captures matrix axes and their values" {
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
        \\      matrix:
        \\        os: [ubuntu-latest, macos-latest]
        \\        include:
        \\          - os: ubuntu-latest
        \\            node: 18
        \\    steps:
        \\      - run: echo test
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());

    const matrix = wf.jobs[0].strategy.?.matrix.?;
    try testing.expectEqual(@as(usize, 2), matrix.axes.len);
    try testing.expectEqualStrings("os", matrix.axes[0].name);
    try testing.expectEqual(@as(usize, 2), matrix.axes[0].values.len);
    try testing.expectEqualStrings("macos-latest", matrix.axes[0].values[1].scalar.value);
    try testing.expectEqualStrings("include", matrix.axes[1].name);
    try testing.expectEqual(@as(usize, 1), matrix.axes[1].values.len);
    try testing.expect(matrix.axes[1].values[0] == .mapping);
}

test "parseWorkflow leaves matrix null when it is an expression" {
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
        \\      matrix: ${{ fromJSON(needs.setup.outputs.matrix) }}
        \\    steps:
        \\      - run: echo test
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());

    try testing.expect(wf.jobs[0].strategy.?.matrix == null);
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

test "parseJob collects runs_on_labels for a scalar runs-on" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());

    const labels = wf.jobs[0].runs_on_labels;
    try testing.expectEqual(@as(usize, 1), labels.len);
    try testing.expectEqualStrings("ubuntu-latest", labels[0]);
    const span = wf.jobs[0].runs_on_label_spans[0];
    try testing.expectEqualStrings("ubuntu-latest", source[span.start_byte..span.end_byte]);
}

test "parseJob collects runs_on_labels for a sequence runs-on" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: [self-hosted, linux, x64]
        \\    steps:
        \\      - run: echo hi
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());

    const job = wf.jobs[0];
    try testing.expect(job.runs_on == null);
    try testing.expect(job.runs_on_value_span == null);
    try testing.expectEqual(@as(usize, 3), job.runs_on_labels.len);
    try testing.expectEqualStrings("self-hosted", job.runs_on_labels[0]);
    try testing.expectEqualStrings("linux", job.runs_on_labels[1]);
    try testing.expectEqualStrings("x64", job.runs_on_labels[2]);
    try testing.expectEqual(@as(usize, 3), job.runs_on_label_spans.len);
    const span = job.runs_on_label_spans[1];
    try testing.expectEqualStrings("linux", source[span.start_byte..span.end_byte]);
}

test "parseJob collects runs_on_labels from a runner group mapping" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on:
        \\      group: ubuntu-runners
        \\      labels: [ubuntu-latest, x64]
        \\    steps:
        \\      - run: echo hi
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());

    const labels = wf.jobs[0].runs_on_labels;
    try testing.expectEqual(@as(usize, 2), labels.len);
    try testing.expectEqualStrings("ubuntu-latest", labels[0]);
    try testing.expectEqualStrings("x64", labels[1]);
}

test "parseJob leaves runs_on_labels empty for a group without labels" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on:
        \\      group: ubuntu-runners
        \\    steps:
        \\      - run: echo hi
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());

    try testing.expectEqual(@as(usize, 0), wf.jobs[0].runs_on_labels.len);
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

test "an empty container credentials: does not fail the parse (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var parser = yaml_parser_mod.Parser.init(
        alloc,
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    container:\n      image: node:20\n      credentials:\n",
    );
    const wf = try parseWorkflow(alloc, try parser.parse());
    try testing.expectEqualStrings("node:20", wf.jobs[0].container.?.image.?);
    try testing.expect(wf.jobs[0].container.?.credentials == null);
}

test "a uses: with dropped lines under it offers no insertion anchor (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // The `<: *g` line holds no node, but a `with:` block written at the value's
    // end adopts it, and the merge key's alias has no anchor to resolve.
    var parser = yaml_parser_mod.Parser.init(
        alloc,
        "on: push\njobs:\n d:\n  steps:\n   - uses: actions/checkout@v4\n       <: *g\n",
    );
    const wf = try parseWorkflow(alloc, try parser.parse());
    try testing.expect(wf.jobs[0].steps[0].uses_value_end_byte == null);

    // Nothing under the value, so the anchor stands.
    var plain = yaml_parser_mod.Parser.init(
        alloc,
        "on: push\njobs:\n d:\n  steps:\n   - uses: actions/checkout@v4\n",
    );
    const plain_wf = try parseWorkflow(alloc, try plain.parse());
    try testing.expect(plain_wf.jobs[0].steps[0].uses_value_end_byte != null);
}

test "a service holding a sequence is a type error, not a parse failure (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // SYN001's rename reaches this: `erices:` became `services:` without
    // changing what was written under it, and the whole workflow stopped
    // parsing where it had linted a moment before.
    var parser = yaml_parser_mod.Parser.init(alloc, "on: push\njobs:\n b: services:\n     b: -\n");
    const wf = try parseWorkflow(alloc, try parser.parse());
    try testing.expectEqual(@as(usize, 1), wf.jobs[0].services.len);
    try testing.expectEqualStrings("b", wf.jobs[0].services[0].name);

    // A `services:` that is not a mapping at all is the same kind of error.
    var scalar = yaml_parser_mod.Parser.init(alloc, "on: push\njobs:\n b:\n  services: x\n");
    const scalar_wf = try parseWorkflow(alloc, try scalar.parse());
    try testing.expectEqual(@as(usize, 0), scalar_wf.jobs[0].services.len);
}

test "steps holding a mapping is a type mismatch, not a parse failure (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var parser = yaml_parser_mod.Parser.init(alloc, "on: push\njobs:\n  j:\n    steps:\n      a: b\n");
    const wf = try parseWorkflow(alloc, try parser.parse());
    try testing.expectEqual(@as(usize, 0), wf.jobs[0].steps.len);

    var found = false;
    for (wf.type_mismatches) |tm| {
        if (std.mem.eql(u8, tm.field, "steps")) found = true;
    }
    try testing.expect(found);
}

test "a dropped line under on: offers no insertion anchor (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // The `>` holds the rest of the file, so a `permissions:` line inserted at
    // the end of the `on:` block ends the scalar early and the `<: *b` it had
    // been holding becomes an undefined alias.
    var parser = yaml_parser_mod.Parser.init(alloc, "on: &c\n  l:\n  >\n   \n<: *b\njobs:");
    const wf = try parseWorkflow(alloc, try parser.parse());
    try testing.expect(wf.permissions_insertion_byte == null);
    try testing.expect(wf.concurrency_insertion_byte == null);

    var plain = yaml_parser_mod.Parser.init(alloc, "on:\n  push:\njobs:\n");
    const plain_wf = try parseWorkflow(alloc, try plain.parse());
    try testing.expect(plain_wf.permissions_insertion_byte != null);
}

test "an event whose only key sits above a dropped line offers no removal range (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // `*r` holds no node, but removing `x:` empties the event and the next parse
    // reads the alias as its value, where it has no anchor to resolve.
    var parser = yaml_parser_mod.Parser.init(alloc, "on:\n workflow_call:\n    x:\n  *r \njobs:\n");
    const wf = try parseWorkflow(alloc, try parser.parse());
    try testing.expect(wf.on.events[0].config_keys[0].full_span == null);

    // Nothing dropped under the key, so the range stands.
    var plain = yaml_parser_mod.Parser.init(alloc, "on:\n workflow_call:\n    x:\njobs:\n");
    const plain_wf = try parseWorkflow(alloc, try plain.parse());
    try testing.expect(plain_wf.on.events[0].config_keys[0].full_span != null);
}

test "an unterminated quoted uses: offers no insertion anchor (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // The scalar swallows everything below it, so a `with:` block written after
    // it becomes more quoted text rather than a key.
    var parser = yaml_parser_mod.Parser.init(
        alloc,
        "on: push\njobs:\n d:\n  steps:\n   - uses: \"actions/checkout@v4\n",
    );
    const wf = try parseWorkflow(alloc, try parser.parse());
    try testing.expect(wf.jobs[0].steps[0].uses_value_end_byte == null);

    // The same step, closed, keeps its anchor.
    var closed = yaml_parser_mod.Parser.init(
        alloc,
        "on: push\njobs:\n d:\n  steps:\n   - uses: \"actions/checkout@v4\"\n",
    );
    const closed_wf = try parseWorkflow(alloc, try closed.parse());
    try testing.expect(closed_wf.jobs[0].steps[0].uses_value_end_byte != null);
}

test "a mapping where a string list belongs does not fail the parse (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // `branches: l:` puts two keys on one line, so `branches` holds a mapping.
    var parser = yaml_parser_mod.Parser.init(alloc, "on:\n push:\n  branches: l:\njobs:\n");
    const wf = try parseWorkflow(alloc, try parser.parse());
    try testing.expectEqual(@as(usize, 0), wf.on.events[0].filter.?.branches.values.len);
}

test "a mistyped with:/env: still counts as a key in source (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // `with: 4` is a type mismatch, not a mapping, so `with` stays null. A fix
    // reading that as "no `with:` in source" would insert a second one.
    var parser = yaml_parser_mod.Parser.init(
        alloc,
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: a/b@v1\n        with: 4\n        env: 4\n",
    );
    const wf = try parseWorkflow(alloc, try parser.parse());
    const step = wf.jobs[0].steps[0];
    try testing.expect(step.with == null);
    try testing.expect(step.with_key_present);
    try testing.expect(step.env == null);
    try testing.expect(step.env_key_present);
}

test "a service with nothing under it does not fail the parse (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var parser = yaml_parser_mod.Parser.init(
        alloc,
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    services:\n      redis:\n",
    );
    const wf = try parseWorkflow(alloc, try parser.parse());
    try testing.expectEqualStrings("redis", wf.jobs[0].services[0].name);
    try testing.expect(wf.jobs[0].services[0].image == null);
}

test "a credentials: holding a scalar does not fail the parse (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // `--fix` can rename a typo into `credentials:` while the value below it is
    // still a scalar. Failing the parse dropped every other diagnostic in the
    // file, so the round-trip never converged.
    var parser = yaml_parser_mod.Parser.init(
        alloc,
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    container:\n      image: node:20\n      credentials: u\n    steps:\n      - run: echo\n",
    );
    const wf = try parseWorkflow(alloc, try parser.parse());
    try testing.expect(wf.jobs[0].container.?.credentials == null);
    try testing.expectEqual(@as(usize, 1), wf.type_mismatches.len);
    try testing.expectEqualStrings("credentials", wf.type_mismatches[0].field);
}

test "a jobs: holding a scalar does not fail the parse (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Inserting a `permissions:` line above it changed which `jobs:` the parse
    // reached, and the one it landed on carried a scalar. Failing there made a
    // file that had linted a pass earlier unlintable.
    var parser = yaml_parser_mod.Parser.init(alloc, "on:\n  x:\njobs: }\n");
    const wf = try parseWorkflow(alloc, try parser.parse());
    try testing.expectEqual(@as(usize, 0), wf.jobs.len);
    try testing.expectEqual(@as(usize, 1), wf.type_mismatches.len);
    try testing.expectEqualStrings("jobs", wf.type_mismatches[0].field);
}

test "a strategy: holding a scalar does not fail the parse (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Removing `fail-fast` under `--fix-unsafe` left the junk line below it as
    // the section's value. Failing the parse there made the file unlintable
    // after a pass that had linted it fine.
    var parser = yaml_parser_mod.Parser.init(
        alloc,
        "on: push\njobs:\n b:\n  strategy: 2\n  x:\n",
    );
    const wf = try parseWorkflow(alloc, try parser.parse());
    try testing.expect(wf.jobs[0].strategy == null or wf.jobs[0].strategy.?.entry_count == 0);
    try testing.expectEqual(@as(usize, 1), wf.type_mismatches.len);
    try testing.expectEqualStrings("strategy", wf.type_mismatches[0].field);
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

    const config = try parseEventConfig(arena.allocator(), "push", .{ .null_value = mkSpan() }, false);
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

test "parsePermissions accepts vulnerability-alerts read and none" {
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("vulnerability-alerts"), .value = mkScalar("read"), .span = mkSpan() },
    };
    const parsed = try parsePermissions(testing.allocator, mkMapping(&entries));
    defer testing.allocator.free(parsed.problems);
    try testing.expectEqual(@as(usize, 0), parsed.problems.len);
    try testing.expectEqual(types.PermissionLevel.read, parsed.permissions.vulnerability_alerts.?);

    var none_entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("vulnerability-alerts"), .value = mkScalar("none"), .span = mkSpan() },
    };
    const none_parsed = try parsePermissions(testing.allocator, mkMapping(&none_entries));
    defer testing.allocator.free(none_parsed.problems);
    try testing.expectEqual(types.PermissionLevel.none, none_parsed.permissions.vulnerability_alerts.?);
}

test "parsePermissions rejects vulnerability-alerts write" {
    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("vulnerability-alerts"), .value = mkScalar("write"), .span = mkSpan() },
    };
    const parsed = try parsePermissions(testing.allocator, mkMapping(&entries));
    defer testing.allocator.free(parsed.problems);
    try testing.expect(parsed.permissions.vulnerability_alerts == null);
    try testing.expectEqual(@as(usize, 1), parsed.problems.len);
    try testing.expectEqual(types.PermissionProblemKind.invalid_level, parsed.problems[0].kind);
    try testing.expectEqualStrings("write", parsed.problems[0].text);
    try testing.expectEqualStrings("vulnerability-alerts", parsed.problems[0].scope);
}

test "parseWorkflow captures cache-mode on workflow and job" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: push
        \\cache-mode: write
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    cache-mode: read
        \\    steps:
        \\      - run: echo hi
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());
    try testing.expectEqualStrings("write", wf.cache_mode.?);
    try testing.expectEqualStrings("read", wf.jobs[0].cache_mode.?);
    try testing.expectEqual(@as(usize, 0), wf.unknown_keys.len);
}

test "parseWorkflow keeps an unknown cache-mode value" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: push
        \\cache-mode: reed
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());
    try testing.expectEqualStrings("reed", wf.cache_mode.?);
    try testing.expect(wf.cache_mode_span != null);
}

test "parseWorkflow reports a non-scalar cache-mode as a type mismatch" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: push
        \\cache-mode:
        \\  foo: bar
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());
    try testing.expect(wf.cache_mode == null);
    try testing.expectEqual(@as(usize, 1), wf.type_mismatches.len);
    try testing.expectEqualStrings("cache-mode", wf.type_mismatches[0].field);
    try testing.expectEqualStrings("mapping", wf.type_mismatches[0].actual);
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
    const config = try parseEventConfig(arena.allocator(), "push", mkScalar("true"), false);
    try testing.expectEqual(types.EventType.push, config.event);
}

test "parseServices with scalar image" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var entries = [_]yaml.MappingEntry{
        .{ .key = mkScalarS("redis"), .value = mkScalar("redis:6"), .span = mkSpan() },
    };

    const services = try parseServices(arena.allocator(), mkMapping(&entries), null);
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
        // `with: x: y` parses to a mapping here, but its entry sits on the
        // key's line: nothing appended below is read back as part of it, so
        // the fix that used this anchor never converged (#370).
        .{ .name = "entry on the with: line", .with_block = "        with: x: y\n", .anchored_after = null },
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
            std.mem.find(u8, source, tail).? + tail.len
        else
            null;
        testing.expectEqual(expected, anchor) catch |err| {
            std.debug.print("case '{s}'\n", .{case.name});
            return err;
        };
    }
}

test "a CRLF workflow parses like its LF twin" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // A Windows checkout hands the linter CRLF; before the tokenizer treated
    // `\r\n` as a break, every such file failed with MissingField.
    const source = "name: ci\r\non:\r\n  push:\r\njobs:\r\n  build:\r\n    runs-on: ubuntu-latest\r\n    steps:\r\n      - uses: actions/checkout@v4\r\n";
    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());

    try testing.expectEqualStrings("ci", wf.name.?);
    try testing.expectEqual(@as(usize, 1), wf.jobs.len);
    try testing.expectEqualStrings("build", wf.jobs[0].id);
    try testing.expectEqualStrings("ubuntu-latest", wf.jobs[0].runs_on.?);
    try testing.expectEqualStrings("actions/checkout@v4", wf.jobs[0].steps[0].uses.?.raw);
}

test "an empty needs: leaves the workflow parseable (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var yp = yaml_parser_mod.Parser.init(alloc, "on: push\njobs:\n  d:\n    needs:\n    runs-on: ubuntu-latest\n    steps: []\n");
    const wf = try parseWorkflow(alloc, try yp.parse());

    try testing.expectEqual(@as(usize, 1), wf.jobs.len);
    try testing.expectEqual(@as(usize, 0), wf.jobs[0].needs.len);
}

test "an empty run: block scalar offers no shell insertion point (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const head = "on: push\njobs:\n  d:\n    runs-on: windows-latest\n    steps:\n      - run: |";

    var empty = yaml_parser_mod.Parser.init(alloc, head ++ "\n");
    const wf_empty = try parseWorkflow(alloc, try empty.parse());
    try testing.expect(wf_empty.jobs[0].steps[0].shell_insertion_byte == null);

    // Blank lines do not fix the indentation either: the first non-empty line
    // does, and this scalar still has none.
    var blank = yaml_parser_mod.Parser.init(alloc, head ++ "\n\n");
    const wf_blank = try parseWorkflow(alloc, try blank.parse());
    try testing.expect(wf_blank.jobs[0].steps[0].shell_insertion_byte == null);

    // Content no further right than the `run` key is under-indented, so a
    // sibling key written below it lands inside the scalar too.
    var shallow = yaml_parser_mod.Parser.init(alloc, head ++ "\n  echo hi\n");
    const wf_shallow = try parseWorkflow(alloc, try shallow.parse());
    try testing.expect(wf_shallow.jobs[0].steps[0].shell_insertion_byte == null);

    var filled = yaml_parser_mod.Parser.init(alloc, head ++ "\n          echo hi\n");
    const wf_filled = try parseWorkflow(alloc, try filled.parse());
    try testing.expect(wf_filled.jobs[0].steps[0].shell_insertion_byte != null);
}

test "a step with: that is not a mapping is a type mismatch, not a parse failure (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var yp = yaml_parser_mod.Parser.init(alloc, "on: push\njobs:\n  d:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with: 4\n");
    const wf = try parseWorkflow(alloc, try yp.parse());

    try testing.expectEqual(@as(usize, 1), wf.jobs[0].steps.len);
    try testing.expectEqual(@as(usize, 1), wf.type_mismatches.len);
    try testing.expectEqualStrings("with", wf.type_mismatches[0].field);
    try testing.expectEqualStrings("mapping", wf.type_mismatches[0].expected);
}

test "a needs: list with an unreadable entry keeps the readable ones (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // An unterminated flow sequence holds one empty item; `build` is still a
    // dependency, and the rest of the workflow is still lintable.
    var yp = yaml_parser_mod.Parser.init(alloc, "on: push\njobs:\n  d:\n    needs:\n      - build\n      -\n    runs-on: ubuntu-latest\n    steps: []\n");
    const wf = try parseWorkflow(alloc, try yp.parse());

    try testing.expectEqual(@as(usize, 1), wf.jobs.len);
    try testing.expectEqual(@as(usize, 1), wf.jobs[0].needs.len);
    try testing.expectEqualStrings("build", wf.jobs[0].needs[0]);
}

test "a job body flush with its id does not count as own-line (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // `e{up: runs-on: x` puts the body on the job id's line, where an insertion
    // aligned to the body's column would land mid-line.
    var yp = yaml_parser_mod.Parser.init(alloc, "on:\njobs:\n  e{up: runs-on: x\n");
    const wf = try parseWorkflow(alloc, try yp.parse());

    try testing.expectEqual(@as(usize, 1), wf.jobs.len);
    try testing.expect(!wf.jobs[0].body_own_line);
}

test "a step written as a flow mapping does not count as own-line (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // SEC001's fix inserted a block `with:` inside the braces, which the next
    // parse read as the step's scalar value and broke the workflow parse.
    var yp = yaml_parser_mod.Parser.init(alloc, "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - {uses: actions/checkout@v4}\n");
    const wf = try parseWorkflow(alloc, try yp.parse());

    try testing.expectEqual(@as(usize, 1), wf.jobs[0].steps.len);
    try testing.expect(!wf.jobs[0].steps[0].own_line);

    // A block step on its own line still takes one.
    var block = yaml_parser_mod.Parser.init(alloc, "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n");
    const block_wf = try parseWorkflow(alloc, try block.parse());
    try testing.expect(block_wf.jobs[0].steps[0].own_line);
}

test "a job body indented past its id counts as own-line" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var yp = yaml_parser_mod.Parser.init(alloc, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n");
    const wf = try parseWorkflow(alloc, try yp.parse());

    try testing.expectEqual(@as(usize, 1), wf.jobs.len);
    try testing.expect(wf.jobs[0].body_own_line);
}

/// #293: a parse error used to be reported as a bare error name, leaving the
/// user to find the offending field in a workflow of any size.
fn parseFailure(allocator: std.mem.Allocator, source: []const u8) !Failure {
    const yaml_parser = @import("../yaml/parser.zig");
    var yp = yaml_parser.Parser.init(allocator, source);
    const root = try yp.parse();

    var failure: ?Failure = null;
    _ = parseWorkflowTracked(allocator, root, &failure) catch {
        return failure orelse error.NoFailureRecorded;
    };
    return error.ParseUnexpectedlySucceeded;
}

test "parseWorkflowTracked reports the line of an invalid step" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const failure = try parseFailure(arena.allocator(),
        \\name: t
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\      - 42
        \\
    );

    try testing.expectEqualStrings("jobs.build.steps[1]", failure.path);
    try testing.expectEqual(@as(u32, 8), failure.span.?.start_line);
}

test "a job holding a scalar is a type mismatch, not a parse failure (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var yp = yaml_parser_mod.Parser.init(alloc, "name: t\non: push\njobs:\n  build: oops\n");
    const wf = try parseWorkflow(alloc, try yp.parse());

    try testing.expectEqual(@as(usize, 1), wf.jobs.len);
    try testing.expectEqualStrings("build", wf.jobs[0].id);
    try testing.expectEqual(@as(usize, 1), wf.type_mismatches.len);
    try testing.expectEqualStrings("job", wf.type_mismatches[0].field);
}

test "a job id with nothing under it does not fail the parse (fuzz)" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var yp = yaml_parser_mod.Parser.init(alloc, "on: push\njobs:\n  a:\n");
    const wf = try parseWorkflow(alloc, try yp.parse());

    try testing.expectEqual(@as(usize, 1), wf.jobs.len);
    try testing.expectEqual(@as(usize, 0), wf.jobs[0].steps.len);
    try testing.expectEqual(@as(usize, 0), wf.type_mismatches.len);
    // Rules report the job at this span, and line 0 is not a place in a file.
    try testing.expectEqual(@as(u32, 3), wf.jobs[0].span.start_line);
    // There is no body to insert an entry into.
    try testing.expect(!wf.jobs[0].body_own_line);
}

test "parseWorkflowTracked reports the line of an invalid trigger" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const failure = try parseFailure(arena.allocator(), "name: t\non:\n  - push\n  - [nested]\njobs: {}\n");

    try testing.expectEqualStrings("on", failure.path);
    // A block sequence's span starts at its first item, so the position points
    // at the list rather than at the `on:` key line.
    try testing.expectEqual(@as(u32, 3), failure.span.?.start_line);
}

// A field that is absent has no node to point at, so the path alone is the
// whole answer and the caller prints the error without a position.
test "parseWorkflowTracked names a missing required field without a span" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const on = try parseFailure(arena.allocator(), "name: t\njobs: {}\n");
    try testing.expectEqualStrings("on", on.path);
    try testing.expect(on.span == null);

    const jobs = try parseFailure(arena.allocator(), "name: t\non: push\n");
    try testing.expectEqualStrings("jobs", jobs.path);
    try testing.expect(jobs.span == null);
}

test "parseWorkflow still works without a failure sink" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expectError(error.MissingField, parseWorkflow(arena.allocator(), mkMapping(&.{})));
}

test "step: first key and env: insertion anchors are captured" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: t
        \\on: push
        \\jobs:
        \\  a:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - name: one
        \\        env:
        \\          FOO: bar
        \\        run: echo hi
        \\
    ;
    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());
    const step = wf.jobs[0].steps[0];

    // `name` is the first key of the step mapping, at column 9.
    try testing.expectEqual(@as(u32, 9), step.first_key_col.?);
    try testing.expectEqual(std.mem.find(u8, source, "name: one").?, step.first_key_start_byte.?);
    try testing.expectEqual(@as(u32, 11), step.env_key_col.?);
    try testing.expectEqual(
        std.mem.find(u8, source, "FOO: bar").? + "FOO: bar".len,
        step.env_last_entry_end_byte.?,
    );
}

test "step: no env: leaves the append anchors unset" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: t
        \\on: push
        \\jobs:
        \\  a:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;
    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());
    const step = wf.jobs[0].steps[0];

    try testing.expect(step.env_key_col == null);
    try testing.expect(step.env_last_entry_end_byte == null);
    try testing.expectEqual(@as(u32, 9), step.first_key_col.?);
}

test "parseWorkflow carries the pin comment on a step's uses" {
    const yaml_parser_mod = @import("../yaml/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@11bd719 # v4.2.2
        \\      - uses: actions/setup-node@8f4b7f8
    ;

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    const wf = try parseWorkflow(alloc, try yp.parse());

    const steps = wf.jobs[0].steps;
    try testing.expectEqualStrings("v4.2.2", steps[0].uses_line_comment.?);
    try testing.expect(steps[1].uses_line_comment == null);
}
