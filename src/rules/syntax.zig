const std = @import("std");
const engine = @import("engine.zig");
const glob = @import("glob.zig");
const workflow_types = @import("../workflow/types.zig");
const workflow_events = @import("../workflow/events.zig");
const workflow_parser = @import("../workflow/parser.zig");
const yaml_types = @import("../yaml/types.zig");
const util = @import("../util.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const Job = engine.Job;
const Step = engine.Step;
const DiagnosticList = engine.DiagnosticList;
const Span = yaml_types.Span;
const Node = yaml_types.Node;
const Mapping = yaml_types.Mapping;
const UnknownKey = workflow_types.UnknownKey;

/// The 13 section names all produce the same sentence, so format it instead of
/// keeping a lookup table of identical strings.
fn emptySectionMessage(list: *DiagnosticList, section: []const u8) []const u8 {
    const generic = "section should not be empty";
    if (section.len == 0) return generic;
    return std.fmt.allocPrint(
        list.fixAllocator(),
        "\"{s}\" " ++ generic,
        .{section},
    ) catch generic;
}

fn checkEmptySections(sections: []const workflow_types.EmptySection, list: *DiagnosticList) void {
    for (sections) |section| {
        list.append(.{
            .rule_id = "SYN003",
            .severity = .@"error",
            .message = emptySectionMessage(list, section.name),
            .span = section.span,
            .fix_hint = "remove this section if it is unnecessary",
        }) catch return;
    }
}

fn checkWorkflowEmptySections(wf: *const Workflow, list: *DiagnosticList) void {
    checkEmptySections(wf.empty_sections, list);
}

fn checkJobEmptySections(job: *const Job, list: *DiagnosticList) void {
    checkEmptySections(job.empty_sections, list);
}

fn checkStepEmptySections(step: *const Step, list: *DiagnosticList) void {
    checkEmptySections(step.empty_sections, list);
}

fn checkDuplicateKeys(wf: *const Workflow, list: *DiagnosticList) void {
    const root = wf.yaml_root orelse return;
    walkDuplicateKeys(root, "workflow", null, workflowJobsEntries(root), list);
}

/// Job ID uniqueness belongs to SYN005, which reports the same duplicate at the
/// same position and additionally validates `needs` references (issue #136).
/// SYN002 therefore descends into the workflow's `jobs:` mapping without
/// reporting its own keys. Identity decides, not the section name: a mapping
/// that merely happens to be named `jobs` (under `with:`, say) is still checked,
/// and so is a second root-level `jobs:` key, which the parser never reads.
fn workflowJobsEntries(root: Node) ?[]const yaml_types.MappingEntry {
    const mapping = switch (root) {
        .mapping => |m| m,
        else => return null,
    };
    for (mapping.entries) |entry| {
        if (!std.mem.eql(u8, entry.key.value, "jobs")) continue;
        return switch (entry.value) {
            .mapping => |jobs| jobs.entries,
            else => null,
        };
    }
    return null;
}

fn isSameEntries(entries: []const yaml_types.MappingEntry, other: ?[]const yaml_types.MappingEntry) bool {
    const skip = other orelse return false;
    return entries.ptr == skip.ptr and entries.len == skip.len;
}

fn sectionForMappingChild(parent_section: []const u8, key: []const u8, value: Node) []const u8 {
    // Job IDs are arbitrary. A job named `env` is still a job, not an env map.
    if (std.mem.eql(u8, parent_section, "jobs")) return "job";
    return switch (value) {
        .mapping => key,
        else => parent_section,
    };
}

fn walkDuplicateKeys(
    node: Node,
    section: []const u8,
    parent_key: ?[]const u8,
    skip: ?[]const yaml_types.MappingEntry,
    list: *DiagnosticList,
) void {
    switch (node) {
        .mapping => |m| checkMapping(m, section, skip, list),
        .sequence => |s| {
            const item_section = if (parent_key) |pk|
                (if (std.ascii.eqlIgnoreCase(pk, "steps")) "step" else section)
            else
                section;
            for (s.items) |item| {
                walkDuplicateKeys(item, item_section, parent_key, skip, list);
            }
        },
        else => {},
    }
}

fn reportDuplicateKey(
    earlier_entries: []const yaml_types.MappingEntry,
    entry: yaml_types.MappingEntry,
    section: []const u8,
    list: *DiagnosticList,
) void {
    for (earlier_entries) |earlier| {
        if (!std.ascii.eqlIgnoreCase(earlier.key.value, entry.key.value)) continue;
        const message = std.fmt.allocPrint(
            list.fixAllocator(),
            "key \"{s}\" is duplicated in \"{s}\" section. previously defined at line:{d},col:{d}. note that this key is case insensitive",
            .{ entry.key.value, section, earlier.key.span.start_line, earlier.key.span.start_col },
        ) catch return;

        list.append(.{
            .rule_id = "SYN002",
            .severity = .@"error",
            .message = message,
            .span = entry.key.span,
            .fix_hint = "remove the duplicate key or rename it so keys are unique within the section",
        }) catch return;
        return;
    }
}

fn checkMapping(
    mapping: Mapping,
    section: []const u8,
    skip: ?[]const yaml_types.MappingEntry,
    list: *DiagnosticList,
) void {
    const report = !isSameEntries(mapping.entries, skip);
    for (mapping.entries, 0..) |entry, i| {
        if (report) reportDuplicateKey(mapping.entries[0..i], entry, section, list);

        const child_section = sectionForMappingChild(section, entry.key.value, entry.value);
        walkDuplicateKeys(entry.value, child_section, entry.key.value, skip, list);
    }
}

fn formatUnexpectedKeyMessage(
    alloc: std.mem.Allocator,
    uk: UnknownKey,
    suggestion: ?[]const u8,
) ![]const u8 {
    var message = std.ArrayList(u8){};
    defer message.deinit(alloc);
    const writer = message.writer(alloc);
    try writer.print(
        "unexpected key \"{s}\" for \"{s}\" section. expected one of ",
        .{ uk.key, uk.section },
    );
    for (uk.expected, 0..) |key, i| {
        if (i > 0) try writer.writeAll(", ");
        try writer.print("\"{s}\"", .{key});
    }
    if (suggestion) |s| {
        try writer.print("; did you mean \"{s}\"?", .{s});
    }
    return try message.toOwnedSlice(alloc);
}

fn checkUnknownKeys(wf: *const Workflow, list: *DiagnosticList) void {
    const alloc = list.fixAllocator();
    for (wf.unknown_keys) |uk| {
        const suggestion = util.didYouMean(uk.key, uk.expected);
        const message = formatUnexpectedKeyMessage(alloc, uk, suggestion) catch continue;
        list.append(.{
            .rule_id = "SYN001",
            .severity = .@"error",
            .message = message,
            .span = uk.span,
        }) catch continue;
    }
}

fn checkMappingValueTypes(wf: *const Workflow, list: *DiagnosticList) void {
    const alloc = list.fixAllocator();
    for (wf.type_mismatches) |mismatch| {
        const msg = std.fmt.allocPrint(
            alloc,
            "expected {s} for \"{s}\", but found {s}",
            .{ mismatch.expected, mismatch.field, mismatch.actual },
        ) catch continue;
        list.append(.{
            .rule_id = "SYN004",
            .severity = .@"error",
            .message = msg,
            .span = mismatch.span,
            .fix_hint = "use a value of the expected type for this field",
        }) catch return;
    }
}

fn isValidId(id: []const u8) bool {
    if (id.len == 0) return true;
    const first = id[0];
    if (first != '_' and !std.ascii.isAlphabetic(first)) return false;
    for (id[1..]) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return false;
    }
    return true;
}

fn reportInvalidId(list: *DiagnosticList, what: []const u8, id: []const u8, span: Span) void {
    if (std.mem.indexOf(u8, id, "${{") != null) return;
    if (isValidId(id)) return;

    const alloc = list.fixAllocator();
    const message = std.fmt.allocPrint(
        alloc,
        "invalid {s} ID \"{s}\". {s} ID must start with a letter or _ and contain only alphanumeric characters, -, or _",
        .{ what, id, what },
    ) catch return;

    list.append(.{
        .rule_id = "SYN006",
        .severity = .@"error",
        .message = message,
        .span = span,
        .fix_hint = "rename the ID to start with a letter or _ and use only letters, digits, hyphens, and underscores",
    }) catch return;
}

fn checkInvalidJobId(job: *const Job, diag_list: *DiagnosticList) void {
    reportInvalidId(diag_list, "job", job.id, (job.id_span orelse job.span));
    for (job.needs, 0..) |need, i| {
        reportInvalidId(diag_list, "job", need, if (i < job.needs_spans.len) job.needs_spans[i] else job.span);
    }
}

fn checkInvalidStepId(step: *const Step, diag_list: *DiagnosticList) void {
    const id = step.id orelse return;
    reportInvalidId(diag_list, "step", id, (step.id_value_span orelse step.span));
}

fn reportDuplicateId(
    list: *DiagnosticList,
    id: []const u8,
    prior_line: u32,
    span: Span,
    comptime message_fmt: []const u8,
    fix_hint: []const u8,
) void {
    const alloc = list.fixAllocator();
    const message = std.fmt.allocPrint(alloc, message_fmt, .{ id, prior_line }) catch return;
    list.append(.{
        .rule_id = "SYN005",
        .severity = .@"error",
        .message = message,
        .span = span,
        .fix_hint = fix_hint,
    }) catch return;
}

const job_id_dup_fmt =
    "job ID \"{s}\" duplicates. previously defined at line {d}. note that job ID is case insensitive";
const step_id_dup_fmt =
    "step ID \"{s}\" duplicates. previously defined at line {d}. step ID must be unique within a job. note that step ID is case insensitive";

fn checkDuplicateJobIds(wf: *const Workflow, list: *DiagnosticList) void {
    for (wf.jobs, 0..) |*job, i| {
        for (wf.jobs[0..i]) |*prior| {
            if (!std.ascii.eqlIgnoreCase(prior.id, job.id)) continue;
            reportDuplicateId(
                list,
                job.id,
                (prior.id_span orelse prior.span).start_line,
                (job.id_span orelse job.span),
                job_id_dup_fmt,
                "use a unique job ID within the workflow",
            );
            break;
        }
    }
}

fn checkDuplicateStepIds(job: *const Job, list: *DiagnosticList) void {
    for (job.steps, 0..) |*step, i| {
        const step_id = step.id orelse continue;
        for (job.steps[0..i]) |*prior_step| {
            const prior_id = prior_step.id orelse continue;
            if (!std.ascii.eqlIgnoreCase(prior_id, step_id)) continue;
            reportDuplicateId(
                list,
                step_id,
                (prior_step.id_value_span orelse prior_step.span).start_line,
                (step.id_value_span orelse step.span),
                step_id_dup_fmt,
                "use a unique step ID within the job",
            );
            break;
        }
    }
}

fn checkEnvNames(env_keys: []const workflow_types.EnvKey, list: *DiagnosticList) void {
    for (env_keys) |key| {
        if (key.name.len == 0) {
            list.append(.{
                .rule_id = "SYN007",
                .severity = .@"error",
                .message = "environment variable name must not be empty",
                .span = key.span,
                .fix_hint = "give the environment variable a name, or remove the entry",
            }) catch return;
            continue;
        }

        // An expression is substituted before the runner ever sees the name,
        // so the literal text here says nothing about the final name.
        if (std.mem.indexOf(u8, key.name, "${{") != null) continue;

        // `=` and `&` break the `NAME=value` form written to the environment
        // file, and a space cannot appear in a shell variable name.
        if (std.mem.indexOfAny(u8, key.name, "&= ") == null) continue;

        const message = std.fmt.allocPrint(
            list.fixAllocator(),
            "environment variable name \"{s}\" is invalid. '&', '=' and spaces must not be contained",
            .{key.name},
        ) catch return;

        list.append(.{
            .rule_id = "SYN007",
            .severity = .@"error",
            .message = message,
            .span = key.span,
            .fix_hint = "rename the environment variable so it contains no '&', '=', or space",
        }) catch return;
    }
}

fn checkWorkflowEnvNames(wf: *const Workflow, list: *DiagnosticList) void {
    checkEnvNames(wf.env_keys, list);
}

fn checkJobEnvNames(job: *const Job, list: *DiagnosticList) void {
    checkEnvNames(job.env_keys, list);
    if (job.container) |container| checkEnvNames(container.env_keys, list);
    for (job.services) |service| checkEnvNames(service.env_keys, list);
}

fn checkStepEnvNames(step: *const Step, list: *DiagnosticList) void {
    checkEnvNames(step.env_keys, list);
}

fn checkDuplicateNeeds(job: *const Job, diag_list: *DiagnosticList) void {
    for (job.needs, 0..) |dep, i| {
        // Job IDs are case-insensitive in GitHub Actions. Report on the second
        // occurrence only, so an ID repeated three or more times still yields
        // a single diagnostic.
        var prior: usize = 0;
        for (job.needs[0..i]) |earlier| {
            if (std.ascii.eqlIgnoreCase(earlier, dep)) prior += 1;
        }
        if (prior != 1) continue;

        diag_list.append(.{
            .rule_id = "SYN008",
            .severity = .warning,
            .message = "job ID is duplicated in 'needs'",
            .span = if (i < job.needs_spans.len) job.needs_spans[i] else job.span,
            .fix_hint = "remove the repeated job ID from 'needs'",
        }) catch return;
    }
}

fn checkUnknownEvents(wf: *const Workflow, list: *DiagnosticList) void {
    const alloc = list.fixAllocator();
    for (wf.on.events) |event| {
        // A name built from an expression is not a literal event name at all.
        // An empty name is not exempt: `on: ""` triggers nothing either.
        if (std.mem.indexOf(u8, event.name, "${{") != null) continue;
        if (workflow_events.isKnown(event.name)) continue;

        var suffix_buf: [64]u8 = undefined;
        const suffix = if (util.didYouMean(event.name, &workflow_events.trigger_names)) |s|
            std.fmt.bufPrint(&suffix_buf, ". did you mean \"{s}\"?", .{s}) catch ""
        else
            "";

        list.append(.{
            .rule_id = "SYN009",
            .severity = .@"error",
            .message = std.fmt.allocPrint(
                alloc,
                "unknown Webhook event \"{s}\"{s}",
                .{ event.name, suffix },
            ) catch "unknown Webhook event",
            .span = event.name_span,
            .fix_hint = "use one of the event names GitHub Actions supports under 'on'",
        }) catch return;
    }
}

/// GitHub Actions rejects a workflow that specifies both halves of a pair.
const ExclusivePair = struct {
    include: ?Span,
    exclude: ?Span,
    message: []const u8,
    fix_hint: []const u8,
};

fn checkExclusiveFilters(wf: *const Workflow, list: *DiagnosticList) void {
    for (wf.on.events) |event| {
        const s = (event.filter orelse continue).spans;
        const pairs = [_]ExclusivePair{
            .{
                .include = s.branches,
                .exclude = s.branches_ignore,
                .message = "both \"branches\" and \"branches-ignore\" filters cannot be used for the same event",
                .fix_hint = "keep only one of 'branches' or 'branches-ignore'; a negated pattern such as '!wip/**' can be listed under 'branches'",
            },
            .{
                .include = s.tags,
                .exclude = s.tags_ignore,
                .message = "both \"tags\" and \"tags-ignore\" filters cannot be used for the same event",
                .fix_hint = "keep only one of 'tags' or 'tags-ignore'; a negated pattern such as '!v0.*' can be listed under 'tags'",
            },
            .{
                .include = s.paths,
                .exclude = s.paths_ignore,
                .message = "both \"paths\" and \"paths-ignore\" filters cannot be used for the same event",
                .fix_hint = "keep only one of 'paths' or 'paths-ignore'; a negated pattern such as '!docs/**' can be listed under 'paths'",
            },
        };

        for (pairs) |pair| {
            const include = pair.include orelse continue;
            const exclude = pair.exclude orelse continue;

            // Report on whichever key comes second in the source so the
            // diagnostic points at the offending addition, not the first
            // filter the author wrote.
            const span = if (exclude.start_byte >= include.start_byte) exclude else include;

            list.append(.{
                .rule_id = "SYN012",
                .severity = .@"error",
                .message = pair.message,
                .span = span,
                .fix_hint = pair.fix_hint,
            }) catch return;
        }
    }
}

fn globPatternSpan(value_span: Span, pat: []const u8, err_col: usize) Span {
    if (err_col == 0) return value_span;
    // Quoted YAML scalars include delimiters in the span but not in the value.
    const quoted: u32 = if (value_span.end_byte - value_span.start_byte == pat.len + 2) 1 else 0;
    const off = quoted + @as(u32, @intCast(err_col - 1));
    const byte_off = quoted + err_col - 1;
    return .{
        .start_line = value_span.start_line,
        .start_col = value_span.start_col + off,
        .end_line = value_span.start_line,
        .end_col = value_span.start_col + off + 1,
        .start_byte = value_span.start_byte + byte_off,
        .end_byte = value_span.start_byte + byte_off + 1,
    };
}

fn reportGlobErrors(
    list: *DiagnosticList,
    patterns: workflow_types.FilterPatternList,
    validate: *const fn (std.mem.Allocator, []const u8) []const glob.InvalidGlobPattern,
) void {
    const alloc = list.fixAllocator();
    for (patterns.values, 0..) |pat, i| {
        if (pat.len == 0) continue;
        const value_span = if (i < patterns.spans.len) patterns.spans[i] else Span.point(1, 1, 0);
        const errs = validate(alloc, pat);
        for (errs) |err| {
            list.append(.{
                .rule_id = "SYN013",
                .severity = .@"error",
                .message = err.message,
                .span = globPatternSpan(value_span, pat, err.column),
            }) catch return;
        }
    }
}

const cron = @import("../workflow/cron.zig");
const timezones = @import("../workflow/timezones.zig");

fn checkScheduleCronSyntax(wf: *const Workflow, list: *DiagnosticList) void {
    for (wf.on.events) |event| {
        if (event.event != .schedule) continue;
        for (event.schedules) |entry| {
            _ = cron.Schedule.parse(entry.cron) catch |err| {
                const detail = cron.Schedule.errorMessage(err);
                list.append(.{
                    .rule_id = "SYN014",
                    .severity = .@"error",
                    .message = std.fmt.allocPrint(
                        list.fixAllocator(),
                        "invalid CRON format \"{s}\" in schedule event: {s}",
                        .{ entry.cron, detail },
                    ) catch "invalid CRON format in schedule event",
                    .span = entry.cron_span,
                    .fix_hint = "use a 5-field POSIX cron expression (minute hour day month weekday)",
                }) catch return;
            };
        }
    }
}

fn checkScheduleCronFrequency(wf: *const Workflow, list: *DiagnosticList) void {
    for (wf.on.events) |event| {
        if (event.event != .schedule) continue;
        for (event.schedules) |entry| {
            const sched = cron.Schedule.parse(entry.cron) catch continue;
            const interval = sched.minIntervalSeconds() orelse continue;
            if (interval >= 60 * 5) continue;

            list.append(.{
                .rule_id = "SYN015",
                .severity = .@"error",
                .message = std.fmt.allocPrint(
                    list.fixAllocator(),
                    "scheduled job runs too frequently. it runs once per {d} seconds. the shortest interval is once every 5 minutes",
                    .{interval},
                ) catch "scheduled job runs too frequently. the shortest interval is once every 5 minutes",
                .span = entry.cron_span,
                .fix_hint = "set the minute field so scheduled runs are at least 5 minutes apart",
            }) catch return;
        }
    }
}

fn checkScheduleTimezone(wf: *const Workflow, list: *DiagnosticList) void {
    const alloc = list.fixAllocator();
    for (wf.on.events) |event| {
        if (event.event != .schedule) continue;
        for (event.schedules) |entry| {
            const tz = entry.timezone orelse continue;
            // A name built from an expression is not a literal zone name at all.
            if (std.mem.indexOf(u8, tz, "${{") != null) continue;
            if (timezones.isKnown(tz)) continue;

            var suffix_buf: [96]u8 = undefined;
            const suffix = if (util.didYouMean(tz, &timezones.timezone_names)) |s|
                std.fmt.bufPrint(&suffix_buf, ". did you mean \"{s}\"?", .{s}) catch ""
            else
                "";

            list.append(.{
                .rule_id = "SYN016",
                .severity = .@"error",
                .message = std.fmt.allocPrint(
                    alloc,
                    "invalid timezone \"{s}\" in schedule event{s}",
                    .{ tz, suffix },
                ) catch "invalid timezone in schedule event",
                .span = entry.timezone_span orelse entry.cron_span,
                .fix_hint = "use a name from the IANA time zone database, such as \"Asia/Tokyo\" or \"UTC\"",
            }) catch return;
        }
    }
}

fn workflowDispatchInputMessage(
    alloc: std.mem.Allocator,
    problem: workflow_types.WorkflowDispatchInputProblem,
) ?[]const u8 {
    return switch (problem.kind) {
        .invalid_type => std.fmt.allocPrint(
            alloc,
            "invalid input type \"{s}\" for workflow_dispatch input \"{s}\". available types are \"string\", \"boolean\", \"number\", \"choice\" and \"environment\"",
            .{ problem.detail, problem.input_name },
        ) catch null,
        .missing_options => std.fmt.allocPrint(
            alloc,
            "\"options\" is required for workflow_dispatch input \"{s}\" of type \"choice\"",
            .{problem.input_name},
        ) catch null,
        .empty_options => std.fmt.allocPrint(
            alloc,
            "\"options\" of workflow_dispatch input \"{s}\" is empty",
            .{problem.input_name},
        ) catch null,
        .options_without_choice => std.fmt.allocPrint(
            alloc,
            "\"options\" is only available for type \"choice\", but workflow_dispatch input \"{s}\" has type \"{s}\"",
            .{ problem.input_name, problem.detail },
        ) catch null,
        .default_not_in_options => std.fmt.allocPrint(
            alloc,
            "default \"{s}\" of workflow_dispatch input \"{s}\" is not included in its \"options\"",
            .{ problem.detail, problem.input_name },
        ) catch null,
        .default_type_mismatch => std.fmt.allocPrint(
            alloc,
            "default of workflow_dispatch input \"{s}\" is not a valid \"{s}\" value",
            .{ problem.input_name, problem.detail },
        ) catch null,
    };
}

fn checkWorkflowDispatchInputs(wf: *const Workflow, list: *DiagnosticList) void {
    const alloc = list.fixAllocator();
    for (wf.on.events) |event| {
        if (event.event != .workflow_dispatch) continue;
        for (event.workflow_dispatch_input_problems) |problem| {
            const message = workflowDispatchInputMessage(alloc, problem) orelse continue;
            list.append(.{
                .rule_id = "SYN017",
                .severity = .@"error",
                .message = message,
                .span = problem.span,
                .fix_hint = switch (problem.kind) {
                    .invalid_type => "use `string`, `boolean`, `number`, `choice`, or `environment`",
                    .missing_options => "add an `options:` list, or drop `type: choice`",
                    .empty_options => "list at least one value under `options:`",
                    .options_without_choice => "remove `options:`, or set `type: choice`",
                    .default_not_in_options => "use one of the listed options as the default, or add it to `options:`",
                    .default_type_mismatch => "write the default as a value of the declared type",
                },
            }) catch return;
        }
    }
}

fn checkGlobFilters(wf: *const Workflow, list: *DiagnosticList) void {
    for (wf.on.events) |event| {
        const filter = event.filter orelse continue;
        reportGlobErrors(list, filter.branches, glob.validateRefGlob);
        reportGlobErrors(list, filter.branches_ignore, glob.validateRefGlob);
        reportGlobErrors(list, filter.tags, glob.validateRefGlob);
        reportGlobErrors(list, filter.tags_ignore, glob.validateRefGlob);
        reportGlobErrors(list, filter.paths, glob.validatePathGlob);
        reportGlobErrors(list, filter.paths_ignore, glob.validatePathGlob);
    }
}

pub const rules = [_]Rule{
    .{
        .id = "SYN001",
        .name = "unknown-key",
        .description = "mapping contains a key that is not defined in the GitHub Actions workflow schema",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkUnknownKeys,
    },
    .{
        .id = "SYN002",
        .name = "duplicate-key",
        .description = "the same mapping key appears more than once (case-insensitive)",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkDuplicateKeys,
    },
    .{
        .id = "SYN003",
        .name = "empty-section",
        .description = "Required workflow sections must not be empty mappings or sequences",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkWorkflowEmptySections,
        .check_job = &checkJobEmptySections,
        .check_step = &checkStepEmptySections,
    },
    .{
        .id = "SYN004",
        .name = "mapping-value-type",
        .description = "mapping value does not match the expected type for its key",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkMappingValueTypes,
    },
    .{
        .id = "SYN005",
        .name = "duplicate-id",
        .description = "job IDs and step IDs must be unique within a workflow or job (case-insensitive)",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkDuplicateJobIds,
        .check_job = &checkDuplicateStepIds,
    },
    .{
        .id = "SYN006",
        .name = "invalid-id-naming",
        .description = "job ID and step ID must start with a letter or _ and contain only alphanumeric characters, -, or _",
        .severity = .@"error",
        .category = .syntax,
        .check_job = &checkInvalidJobId,
        .check_step = &checkInvalidStepId,
    },
    .{
        .id = "SYN007",
        .name = "invalid-env-var-name",
        .description = "environment variable name must not be empty or contain '&', '=', or spaces",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkWorkflowEnvNames,
        .check_job = &checkJobEnvNames,
        .check_step = &checkStepEnvNames,
    },
    .{
        .id = "SYN008",
        .name = "duplicate-needs",
        .description = "the same job ID is listed more than once in 'needs'",
        .severity = .warning,
        .category = .syntax,
        .check_job = &checkDuplicateNeeds,
    },
    .{
        .id = "SYN009",
        .name = "unknown-event",
        .description = "'on' names an event GitHub Actions does not support, so the workflow never triggers",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkUnknownEvents,
    },
    .{
        .id = "SYN012",
        .name = "exclusive-event-filters",
        .description = "Mutually exclusive event filters (branches/tags/paths and their -ignore forms) are specified together",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkExclusiveFilters,
    },
    .{
        .id = "SYN013",
        .name = "invalid-filter-glob",
        .description = "Event filter pattern uses invalid GitHub Actions glob syntax",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkGlobFilters,
    },
    .{
        .id = "SYN014",
        .name = "invalid-cron",
        .description = "schedule cron expression is not valid POSIX 5-field cron syntax",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkScheduleCronSyntax,
    },
    .{
        .id = "SYN015",
        .name = "cron-too-frequent",
        .description = "scheduled workflow runs more often than GitHub Actions allows (once every 5 minutes)",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkScheduleCronFrequency,
    },
    .{
        .id = "SYN016",
        .name = "invalid-timezone",
        .description = "schedule timezone is not a name in the IANA time zone database",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkScheduleTimezone,
    },
    .{
        .id = "SYN017",
        .name = "workflow-dispatch-inputs",
        .description = "workflow_dispatch input declares an invalid type, options, or default",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkWorkflowDispatchInputs,
    },
};

const testing = std.testing;
const test_support = @import("../test_support.zig");
const yaml_parser = @import("../yaml/parser.zig");
const EventConfig = workflow_types.EventConfig;

fn runSyn001(source: []const u8, list: *DiagnosticList) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const wf = try test_support.parseWorkflowSource(alloc, source);
    checkUnknownKeys(&wf, list);
}

test "SYN001: unknown job key is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    timeout-minute: 10
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn001(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("SYN001", diag.rule_id);
    try testing.expect(diag.severity == .@"error");
    try testing.expect(std.mem.indexOf(u8, diag.message, "timeout-minute") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"job\"") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean \"timeout-minutes\"") != null);
}

test "SYN001: unknown step key is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - runs: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn001(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "runs") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"step\"") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean \"run\"") != null);
}

test "SYN001: valid workflow produces no diagnostic" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    timeout-minutes: 10
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn001(source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN001: matrix keys are not validated" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\        custom-key: [value]
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn001(source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN001: with and env keys are not validated" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\        with:
        \\          fetch-depth: 1
        \\        env:
        \\          CUSTOM: value
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn001(source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN001: unknown workflow key is reported" {
    const source =
        \\on: push
        \\default:
        \\  run:
        \\    shell: bash
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn001(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "default") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"workflow\"") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean \"defaults\"") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"true\"") == null);
}

test "SYN001: expected keys are sorted" {
    const source =
        \\on: push
        \\foo: bar
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn001(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "\"concurrency\", \"defaults\", \"env\", \"jobs\"") != null);
}

test "SYN001: unknown strategy key is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      fail_fast: false
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn001(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "fail_fast") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"strategy\"") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean \"fail-fast\"") != null);
}

test "SYN001: unknown container key is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    container:
        \\      image: node:20
        \\      imagen: node:20
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn001(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "imagen") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"container\"") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean \"image\"") != null);
}

test "SYN001: unknown services key is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    services:
        \\      redis:
        \\        image: redis
        \\        imagen: redis
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn001(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "imagen") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"services\"") != null);
}

test "SYN001: unknown defaults.run key is reported" {
    const source =
        \\on: push
        \\defaults:
        \\  run:
        \\    shel: bash
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn001(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "shel") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"run\"") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean \"shell\"") != null);
}

test "SYN001: step keys are case-sensitive" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\        Shell: bash
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn001(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "Shell") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean \"shell\"") != null);
}

test "SYN001: action step rejects shell" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\        shell: bash
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn001(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "shell") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"step\"") != null);
}

test "SYN001: distant key has no did-you-mean" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    totally-unrelated: 1
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn001(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "totally-unrelated") != null);
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "did you mean") == null);
}

test "SYN001: message survives appendOwning after source list deinit" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    timeout-minute: 10
        \\    steps:
        \\      - run: echo hi
    ;

    var dst = DiagnosticList.init(testing.allocator);
    defer dst.deinit();

    {
        var src = DiagnosticList.init(testing.allocator);
        defer src.deinit();
        try runSyn001(source, &src);
        try testing.expectEqual(@as(usize, 1), src.len());
        try dst.appendOwning(src.get(0));
    }

    try testing.expectEqualStrings("SYN001", dst.get(0).rule_id);
    try testing.expect(std.mem.indexOf(u8, dst.get(0).message, "timeout-minute") != null);
}

fn lintYaml(source: []const u8, diags: *DiagnosticList) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const wf = try test_support.parseWorkflowSource(alloc, source);

    const rule_engine = engine.Engine.init(&rules);
    var list = rule_engine.run(testing.allocator, &wf);
    defer list.deinit();
    for (list.items.items) |diag| {
        // `appendOwning`, not `append`: allocPrint-ed messages live in
        // `list`'s arena, which dies with this function.
        diags.appendOwning(diag) catch return;
    }
}

fn expectSyn003(diags: DiagnosticList, expected: []const []const u8) !void {
    var found: usize = 0;
    for (0..diags.len()) |i| {
        const d = diags.get(i);
        if (!std.mem.eql(u8, d.rule_id, "SYN003")) continue;
        found += 1;
        var matched = false;
        for (expected) |msg| {
            if (std.mem.eql(u8, d.message, msg)) {
                matched = true;
                break;
            }
        }
        try testing.expect(matched);
        try testing.expect(d.severity == .@"error");
    }
    try testing.expectEqual(expected.len, found);
}

fn sectionMsg(comptime name: []const u8) []const u8 {
    return "\"" ++ name ++ "\" section should not be empty";
}

test "SYN003: empty strategy and with are reported" {
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

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    try expectSyn003(diags, &.{
        sectionMsg("strategy"),
        sectionMsg("with"),
    });
}

test "SYN003: valid workflow without empty sections is clean" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN003: permissions mapping is allowed to be empty" {
    const source =
        \\on: push
        \\permissions: {}
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    permissions: {}
        \\    steps:
        \\      - run: echo ok
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    for (0..diags.len()) |i| {
        try testing.expect(!std.mem.eql(u8, diags.get(i).rule_id, "SYN003"));
    }
}

test "SYN003: empty jobs mapping is reported" {
    const source =
        \\on: push
        \\jobs: {}
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    try expectSyn003(diags, &.{sectionMsg("jobs")});
}

test "SYN003: empty steps sequence is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps: []
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    try expectSyn003(diags, &.{sectionMsg("steps")});
}

test "SYN003: implicit-null jobs is reported" {
    const source =
        \\on: push
        \\jobs:
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    try expectSyn003(diags, &.{sectionMsg("jobs")});
}

test "SYN003: implicit-null strategy and with are reported" {
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

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    try expectSyn003(diags, &.{
        sectionMsg("strategy"),
        sectionMsg("with"),
    });
}

test "SYN003: empty on mapping is reported" {
    const source =
        \\on: {}
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    try expectSyn003(diags, &.{sectionMsg("on")});
}

test "SYN003: empty env at workflow job and step is reported" {
    const source =
        \\on: push
        \\env: {}
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    env: {}
        \\    steps:
        \\      - run: echo
        \\        env: {}
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    try expectSyn003(diags, &.{
        sectionMsg("env"),
        sectionMsg("env"),
        sectionMsg("env"),
    });
}

test "SYN003: empty matrix defaults container services outputs secrets" {
    const source =
        \\on: push
        \\defaults: {}
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix: {}
        \\    container: {}
        \\    services: {}
        \\    outputs: {}
        \\    defaults: {}
        \\    steps:
        \\      - run: echo
        \\  call:
        \\    uses: org/repo/.github/workflows/x.yml@v1
        \\    secrets: {}
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    try expectSyn003(diags, &.{
        sectionMsg("defaults"),
        sectionMsg("matrix"),
        sectionMsg("container"),
        sectionMsg("services"),
        sectionMsg("outputs"),
        sectionMsg("defaults"),
        sectionMsg("secrets"),
    });
}

test "SYN003: empty workflow_dispatch inputs is reported" {
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

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    try expectSyn003(diags, &.{sectionMsg("inputs")});
}

test "SYN003: secrets inherit and scalar container are not empty sections" {
    const source =
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: org/repo/.github/workflows/x.yml@v1
        \\    secrets: inherit
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    container: ubuntu
        \\    steps:
        \\      - run: echo
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    try expectSyn003(diags, &.{});
}

/// The workflow lives in an arena released before returning; the diagnostics
/// only borrow string literals.
fn runSyn004(source: []const u8, list: *DiagnosticList) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);
    checkMappingValueTypes(&wf, list);
}

const dummySpan = test_support.dummySpan;

test "SYN006: job ID starting with a digit is reported" {
    const job = Job{
        .id = "1-build",
        .id_span = dummySpan(10, 17),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkInvalidJobId(&job, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("SYN006", diag.rule_id);
    try testing.expect(diag.severity == .@"error");
    try testing.expect(std.mem.startsWith(u8, diag.message, "invalid job ID \"1-build\""));
    try testing.expectEqual(@as(usize, 10), diag.span.start_byte);
}

test "SYN006: job ID with a space is reported" {
    const job = Job{
        .id = "build job",
        .id_span = dummySpan(20, 29),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkInvalidJobId(&job, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.startsWith(u8, diags.get(0).message, "invalid job ID \"build job\""));
}

test "SYN006: invalid needs entry is reported at the needs value span" {
    const job = Job{
        .id = "deploy",
        .needs = &.{"1-build"},
        .needs_spans = &.{dummySpan(90, 97)},
        .span = dummySpan(40, 80),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkInvalidJobId(&job, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.startsWith(u8, diags.get(0).message, "invalid job ID \"1-build\""));
    try testing.expectEqual(@as(usize, 90), diags.get(0).span.start_byte);
}

test "SYN006: step ID with a dot is reported" {
    const step = Step{
        .id = "my.step",
        .id_value_span = dummySpan(50, 57),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkInvalidStepId(&step, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("SYN006", diag.rule_id);
    try testing.expect(std.mem.startsWith(u8, diag.message, "invalid step ID \"my.step\""));
    try testing.expectEqual(@as(usize, 50), diag.span.start_byte);
}

test "SYN006: valid job and step IDs produce no diagnostic" {
    const job = Job{
        .id = "build-and-test",
        .id_span = dummySpan(1, 14),
    };
    var job_diags = DiagnosticList.init(testing.allocator);
    defer job_diags.deinit();
    checkInvalidJobId(&job, &job_diags);
    try testing.expectEqual(@as(usize, 0), job_diags.len());

    const step = Step{
        .id = "_setup_node",
        .id_value_span = dummySpan(30, 41),
    };
    var step_diags = DiagnosticList.init(testing.allocator);
    defer step_diags.deinit();
    checkInvalidStepId(&step, &step_diags);
    try testing.expectEqual(@as(usize, 0), step_diags.len());
}

test "SYN006: step ID with expression is skipped" {
    const step = Step{
        .id = "${{ github.run_id }}",
        .id_value_span = dummySpan(60, 80),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkInvalidStepId(&step, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN006: job ID with expression is skipped" {
    const job = Job{
        .id = "${{ matrix.name }}",
        .id_span = dummySpan(1, 18),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkInvalidJobId(&job, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN006: empty ID is skipped" {
    var job_diags = DiagnosticList.init(testing.allocator);
    defer job_diags.deinit();
    checkInvalidJobId(&Job{ .id = "" }, &job_diags);
    try testing.expectEqual(@as(usize, 0), job_diags.len());

    var step_diags = DiagnosticList.init(testing.allocator);
    defer step_diags.deinit();
    checkInvalidStepId(&Step{ .id = "" }, &step_diags);
    try testing.expectEqual(@as(usize, 0), step_diags.len());
}

test "SYN006: invalid ID character classes are reported" {
    const cases = [_][]const u8{ "-foo", "v1.2.3", "hello!", "じょぶ", "12345" };
    for (cases) |id| {
        var diags = DiagnosticList.init(testing.allocator);
        defer diags.deinit();
        const job = Job{ .id = id, .id_span = dummySpan(0, id.len) };
        checkInvalidJobId(&job, &diags);
        try testing.expectEqual(@as(usize, 1), diags.len());
        try testing.expectEqualStrings("SYN006", diags.get(0).rule_id);
    }
}

test "SYN006: valid ID character classes produce no diagnostic" {
    const cases = [_][]const u8{
        "foo-bar",
        "foo_bar",
        "foo--bar",
        "foo__bar",
        "_FOO123-",
        "_____",
        "_-_-",
        "a",
        "_",
    };
    for (cases) |id| {
        var diags = DiagnosticList.init(testing.allocator);
        defer diags.deinit();
        const job = Job{ .id = id, .id_span = dummySpan(0, id.len) };
        checkInvalidJobId(&job, &diags);
        try testing.expectEqual(@as(usize, 0), diags.len());
    }
}

test "SYN006: parse-then-check points at the job key, step id, and needs value" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: push
        \\jobs:
        \\  1-build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: my.step
        \\        run: echo hi
        \\  deploy:
        \\    needs: 1-build
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    for (wf.jobs) |*job| {
        checkInvalidJobId(job, &diags);
        for (job.steps) |*step| {
            checkInvalidStepId(step, &diags);
        }
    }

    try testing.expectEqual(@as(usize, 3), diags.len());
    try testing.expectEqual(@as(u32, 3), diags.get(0).span.start_line);
    try testing.expect(std.mem.startsWith(u8, diags.get(0).message, "invalid job ID \"1-build\""));
    try testing.expectEqual(@as(u32, 6), diags.get(1).span.start_line);
    try testing.expect(std.mem.startsWith(u8, diags.get(1).message, "invalid step ID \"my.step\""));
    try testing.expectEqual(@as(u32, 9), diags.get(2).span.start_line);
    try testing.expect(std.mem.startsWith(u8, diags.get(2).message, "invalid job ID \"1-build\""));
}

fn runOn(events: []const EventConfig) DiagnosticList {
    const wf = Workflow{ .on = .{ .events = events }, .jobs = &.{} };
    var list = DiagnosticList.init(testing.allocator);
    checkExclusiveFilters(&wf, &list);
    return list;
}

fn runOnNeeds(needs: []const []const u8) DiagnosticList {
    const job = Job{ .id = "test", .runs_on = "ubuntu-latest", .needs = needs };
    var diags = DiagnosticList.init(testing.allocator);
    checkDuplicateNeeds(&job, &diags);
    return diags;
}

fn collectDuplicateKeyDiagnostics(source: []const u8, diags: *DiagnosticList) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var parser = yaml_parser.Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    walkDuplicateKeys(node, "workflow", null, workflowJobsEntries(node), diags);
}

test "SYN002: duplicated steps key is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo first
        \\    STEPS:
        \\      - run: echo second
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("SYN002", diag.rule_id);
    try testing.expect(diag.severity == .@"error");
    try testing.expect(std.mem.indexOf(u8, diag.message, "STEPS") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "job") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "previously defined at line:5,col:5") != null);
    try testing.expectEqual(@as(u32, 7), diag.span.start_line);
    try testing.expectEqual(@as(u32, 5), diag.span.start_col);
}

test "SYN002: duplicate detection is case-insensitive in matrix" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        version_name: [v1, v2]
        \\        VERSION_NAME: [V1, V2]
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "matrix") != null);
}

test "SYN002: distinct env keys are not reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    env:
        \\      FOO: 1
        \\      foo_bar: 2
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN002: a key repeated three times reports each extra occurrence" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    env:
        \\      FOO: 1
        \\      foo: 2
        \\      Foo: 3
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "foo") != null);
    try testing.expect(std.mem.indexOf(u8, diags.get(1).message, "Foo") != null);
}

test "SYN002: with mapping duplicates are reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\        with:
        \\          fetch-depth: 1
        \\          FETCH-DEPTH: 0
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "with") != null);
}

test "SYN002: flow mapping duplicates are reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    env: {FOO: 1, foo: 2}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "env") != null);
}

test "SYN002: duplicate job IDs are left to SYN005" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo a
        \\  BUILD:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo b
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN002: a mapping named jobs outside the workflow root is still checked" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: ./.github/actions/run
        \\        with:
        \\          jobs:
        \\            build: a
        \\            BUILD: b
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "\"BUILD\"") != null);
}

test "SYN002: a jobs mapping nested in a root sequence is still checked" {
    const source =
        \\on: push
        \\x:
        \\  - jobs:
        \\      a: 1
        \\      A: 2
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "\"A\"") != null);
}

test "SYN002: a second root-level jobs mapping is still checked" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\jobs:
        \\  other:
        \\    runs-on: ubuntu-latest
        \\  OTHER:
        \\    runs-on: ubuntu-latest
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    // The duplicate `jobs:` key itself, plus the job IDs SYN005 cannot reach
    // because the parser only reads the first `jobs:` mapping.
    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "\"jobs\"") != null);
    try testing.expect(std.mem.indexOf(u8, diags.get(1).message, "\"OTHER\"") != null);
}

test "SYN002: a job named env is still a job section" {
    const source =
        \\on: push
        \\jobs:
        \\  env:
        \\    runs-on: ubuntu-latest
        \\    RUNS-ON: windows-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "job") != null);
}

test "SYN002: engine.run emits via yaml_root" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo first
        \\    STEPS:
        \\      - run: echo second
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);

    const engine_inst = engine.Engine.init(&rules);
    var diags = engine_inst.run(testing.allocator, &wf);
    defer diags.deinit();

    var found = false;
    for (0..diags.len()) |i| {
        if (std.mem.eql(u8, diags.get(i).rule_id, "SYN002")) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

const Syn004Case = struct {
    name: []const u8,
    source: []const u8,
    want: usize,
    message_contains: ?[]const u8 = null,
};

test "SYN004: mapping value type validation" {
    const cases = [_]Syn004Case{
        .{
            .name = "invalid job fields",
            .source =
            \\on: push
            \\jobs:
            \\  build:
            \\    runs-on: ubuntu-latest
            \\    timeout-minutes: "ten"
            \\    continue-on-error: maybe
            \\    strategy:
            \\      max-parallel: high
            \\    steps:
            \\      - run: echo hi
            ,
            .want = 3,
            .message_contains = "timeout-minutes",
        },
        .{
            .name = "invalid fail-fast and cancel-in-progress",
            .source =
            \\on: push
            \\concurrency:
            \\  group: ci
            \\  cancel-in-progress: yes
            \\jobs:
            \\  build:
            \\    runs-on: ubuntu-latest
            \\    strategy:
            \\      fail-fast: maybe
            \\    steps:
            \\      - run: echo hi
            ,
            .want = 2,
        },
        .{
            .name = "wrong node kinds",
            .source =
            \\on: push
            \\jobs:
            \\  build:
            \\    runs-on: ubuntu-latest
            \\    timeout-minutes: [10]
            \\    continue-on-error: {}
            \\    steps:
            \\      - run: echo hi
            ,
            .want = 2,
        },
        .{
            .name = "dollar-prefixed non-expression",
            .source =
            \\on: push
            \\jobs:
            \\  build:
            \\    runs-on: ubuntu-latest
            \\    continue-on-error: $maybe
            \\    steps:
            \\      - run: echo hi
            ,
            .want = 1,
        },
        .{
            .name = "valid values",
            .source =
            \\on: push
            \\jobs:
            \\  build:
            \\    runs-on: ubuntu-latest
            \\    timeout-minutes: 10
            \\    continue-on-error: true
            \\    steps:
            \\      - run: echo hi
            ,
            .want = 0,
        },
        .{
            .name = "expression values",
            .source =
            \\on: push
            \\jobs:
            \\  build:
            \\    runs-on: ubuntu-latest
            \\    continue-on-error: ${{ github.event_name == 'push' }}
            \\    timeout-minutes: ${{ matrix.timeout }}
            \\    steps:
            \\      - run: echo hi
            ,
            .want = 0,
        },
        .{
            .name = "step-level invalid fields",
            .source =
            \\on: push
            \\jobs:
            \\  build:
            \\    runs-on: ubuntu-latest
            \\    steps:
            \\      - run: echo hi
            \\        timeout-minutes: bad
            \\        continue-on-error: yes
            ,
            .want = 2,
        },
    };

    for (cases) |case| {
        var diags = DiagnosticList.init(testing.allocator);
        defer diags.deinit();

        try runSyn004(case.source, &diags);
        try testing.expectEqual(case.want, diags.len());

        if (case.message_contains) |needle| {
            try testing.expect(std.mem.indexOf(u8, diags.get(0).message, needle) != null);
        }

        for (diags.items.items) |diag| {
            try testing.expectEqualStrings("SYN004", diag.rule_id);
            try testing.expect(diag.severity == .@"error");
        }
    }
}

fn runOnDuplicateJobIds(jobs: []const Job) DiagnosticList {
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = jobs };
    var diags = DiagnosticList.init(testing.allocator);
    checkDuplicateJobIds(&wf, &diags);
    return diags;
}

fn runOnDuplicateStepIds(steps: []const Step) DiagnosticList {
    const job = Job{ .id = "build", .runs_on = "ubuntu-latest", .steps = steps };
    var diags = DiagnosticList.init(testing.allocator);
    checkDuplicateStepIds(&job, &diags);
    return diags;
}

test "SYN005: duplicate job IDs" {
    const cases = [_]struct {
        jobs: [2]Job,
        message: []const u8,
        span_line: u32,
    }{
        .{
            .jobs = .{
                .{ .id = "build", .id_span = Span.point(3, 3, 20), .runs_on = "ubuntu-latest" },
                .{ .id = "build", .id_span = Span.point(6, 3, 50), .runs_on = "ubuntu-latest" },
            },
            .message = "job ID \"build\" duplicates. previously defined at line 3. note that job ID is case insensitive",
            .span_line = 6,
        },
        .{
            .jobs = .{
                .{ .id = "build", .id_span = Span.point(5, 3, 40), .runs_on = "ubuntu-latest" },
                .{ .id = "Build", .id_span = Span.point(8, 3, 80), .runs_on = "ubuntu-latest" },
            },
            .message = "job ID \"Build\" duplicates. previously defined at line 5. note that job ID is case insensitive",
            .span_line = 8,
        },
    };

    for (cases) |c| {
        var diags = runOnDuplicateJobIds(&c.jobs);
        defer diags.deinit();

        try testing.expectEqual(@as(usize, 1), diags.len());
        const diag = diags.get(0);
        try testing.expectEqualStrings("SYN005", diag.rule_id);
        try testing.expect(diag.severity == .@"error");
        try testing.expectEqualStrings(c.message, diag.message);
        try testing.expectEqual(c.span_line, diag.span.start_line);
    }
}

test "SYN005: job ID repeated three times reports on each subsequent occurrence" {
    const jobs = [_]Job{
        .{ .id = "build", .id_span = Span.point(3, 3, 20) },
        .{ .id = "Build", .id_span = Span.point(6, 3, 50) },
        .{ .id = "BUILD", .id_span = Span.point(9, 3, 80) },
    };
    var diags = runOnDuplicateJobIds(&jobs);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expectEqualStrings(
        "job ID \"Build\" duplicates. previously defined at line 3. note that job ID is case insensitive",
        diags.get(0).message,
    );
    try testing.expectEqualStrings(
        "job ID \"BUILD\" duplicates. previously defined at line 3. note that job ID is case insensitive",
        diags.get(1).message,
    );
}

test "SYN005: distinct job IDs produce no diagnostic" {
    const jobs = [_]Job{
        .{ .id = "build", .id_span = Span.point(3, 3, 20) },
        .{ .id = "test", .id_span = Span.point(6, 3, 50) },
    };
    var diags = runOnDuplicateJobIds(&jobs);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN005: duplicate step IDs within a job" {
    const cases = [_]struct {
        steps: [2]Step,
        message: []const u8,
        span_line: u32,
    }{
        .{
            .steps = .{
                .{ .id = "setup", .id_value_span = Span.point(7, 11, 100), .run = "echo hi" },
                .{ .id = "setup", .id_value_span = Span.point(9, 11, 140), .run = "echo hi" },
            },
            .message = "step ID \"setup\" duplicates. previously defined at line 7. step ID must be unique within a job. note that step ID is case insensitive",
            .span_line = 9,
        },
        .{
            .steps = .{
                .{ .id = "setup", .id_value_span = Span.point(7, 11, 100), .run = "echo hi" },
                .{ .id = "SETUP", .id_value_span = Span.point(9, 11, 140), .run = "echo hi" },
            },
            .message = "step ID \"SETUP\" duplicates. previously defined at line 7. step ID must be unique within a job. note that step ID is case insensitive",
            .span_line = 9,
        },
    };

    for (cases) |c| {
        var diags = runOnDuplicateStepIds(&c.steps);
        defer diags.deinit();

        try testing.expectEqual(@as(usize, 1), diags.len());
        const diag = diags.get(0);
        try testing.expectEqualStrings("SYN005", diag.rule_id);
        try testing.expect(diag.severity == .@"error");
        try testing.expectEqualStrings(c.message, diag.message);
        try testing.expectEqual(c.span_line, diag.span.start_line);
    }
}

test "SYN005: step ID repeated three times reports on each subsequent occurrence" {
    const steps = [_]Step{
        .{ .id = "setup", .id_value_span = Span.point(7, 11, 100), .run = "echo hi" },
        .{ .id = "Setup", .id_value_span = Span.point(9, 11, 140), .run = "echo hi" },
        .{ .id = "SETUP", .id_value_span = Span.point(11, 11, 180), .run = "echo hi" },
    };
    var diags = runOnDuplicateStepIds(&steps);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expectEqualStrings(
        "step ID \"Setup\" duplicates. previously defined at line 7. step ID must be unique within a job. note that step ID is case insensitive",
        diags.get(0).message,
    );
    try testing.expectEqualStrings(
        "step ID \"SETUP\" duplicates. previously defined at line 7. step ID must be unique within a job. note that step ID is case insensitive",
        diags.get(1).message,
    );
}

test "SYN005: same step ID in different jobs is allowed" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    const steps_a = [_]Step{
        .{ .id = "setup", .id_value_span = Span.point(7, 11, 100), .run = "echo hi" },
    };
    const steps_b = [_]Step{
        .{ .id = "setup", .id_value_span = Span.point(12, 11, 200), .run = "echo hi" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .runs_on = "ubuntu-latest", .steps = &steps_a },
        .{ .id = "test", .runs_on = "ubuntu-latest", .steps = &steps_b },
    };

    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &jobs };
    const eng = engine.Engine.init(&rules);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SYN005: steps without id are ignored" {
    const steps = [_]Step{
        .{ .run = "echo hi" },
        .{ .run = "echo bye" },
    };
    var diags = runOnDuplicateStepIds(&steps);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN005: end-to-end duplicate job and step IDs from YAML source" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: setup
        \\        run: echo hi
        \\      - id: setup
        \\        run: echo hi
        \\      - id: SETUP
        \\        run: echo hi
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\  Build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const wf = try test_support.parseWorkflowSource(alloc, source);

    const eng = engine.Engine.init(&rules);
    var diags = eng.run(alloc, &wf);
    defer diags.deinit();

    // Job ID duplicates belong to SYN005 alone, so the whole diagnostic list is
    // exactly the four expected duplicates (see issue #136).
    try testing.expectEqual(@as(usize, 4), diags.len());

    var step_exact = false;
    var step_case = false;
    var job_exact = false;
    var job_case = false;
    for (diags.items.items) |d| {
        try testing.expectEqualStrings("SYN005", d.rule_id);
        if (std.mem.eql(u8, d.message, "step ID \"setup\" duplicates. previously defined at line 6. step ID must be unique within a job. note that step ID is case insensitive")) {
            step_exact = true;
            try testing.expectEqual(@as(u32, 8), d.span.start_line);
        }
        if (std.mem.eql(u8, d.message, "step ID \"SETUP\" duplicates. previously defined at line 6. step ID must be unique within a job. note that step ID is case insensitive")) {
            step_case = true;
            try testing.expectEqual(@as(u32, 10), d.span.start_line);
        }
        if (std.mem.eql(u8, d.message, "job ID \"build\" duplicates. previously defined at line 3. note that job ID is case insensitive")) {
            job_exact = true;
            try testing.expectEqual(@as(u32, 12), d.span.start_line);
        }
        if (std.mem.eql(u8, d.message, "job ID \"Build\" duplicates. previously defined at line 3. note that job ID is case insensitive")) {
            job_case = true;
            try testing.expectEqual(@as(u32, 16), d.span.start_line);
        }
    }
    try testing.expect(step_exact);
    try testing.expect(step_case);
    try testing.expect(job_exact);
    try testing.expect(job_case);
}

fn runSyn007(source: []const u8, alloc: std.mem.Allocator, list: *DiagnosticList) !void {
    const wf = try test_support.parseWorkflowSource(alloc, source);

    checkWorkflowEnvNames(&wf, list);
    for (wf.jobs) |*job| {
        checkJobEnvNames(job, list);
        for (job.steps) |*step| checkStepEnvNames(step, list);
    }
}

test "SYN007: invalid env var names are reported at every level" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on: push
        \\env:
        \\  "TOP LEVEL": 1
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    env:
        \\      FOO=BAR: 1
        \\      FOO&BAR: 3
        \\    steps:
        \\      - run: echo hi
        \\        env:
        \\          "A B": 2
        \\
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn007(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 4), diags.len());
    for (diags.items.items) |d| {
        try testing.expectEqualStrings("SYN007", d.rule_id);
        try testing.expect(d.severity == .@"error");
    }
    try testing.expectEqualStrings(
        "environment variable name \"TOP LEVEL\" is invalid. '&', '=' and spaces must not be contained",
        diags.get(0).message,
    );
    try testing.expectEqual(@as(u32, 3), diags.get(0).span.start_line);
    try testing.expect(std.mem.indexOf(u8, diags.get(1).message, "\"FOO=BAR\"") != null);
    try testing.expectEqual(@as(u32, 8), diags.get(1).span.start_line);
    try testing.expect(std.mem.indexOf(u8, diags.get(2).message, "\"FOO&BAR\"") != null);
    try testing.expectEqual(@as(u32, 9), diags.get(2).span.start_line);
    try testing.expect(std.mem.indexOf(u8, diags.get(3).message, "\"A B\"") != null);
    try testing.expectEqual(@as(u32, 13), diags.get(3).span.start_line);
}

test "SYN007: valid env var names produce no diagnostic" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on: push
        \\env:
        \\  MY_VAR: 1
        \\  PATH_2: 2
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    env:
        \\      lower-case.dotted: ok
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn007(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN007: empty env var name is reported" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    const keys = [_]workflow_types.EnvKey{
        .{ .name = "", .span = dummySpan(0, 0) },
    };
    checkEnvNames(&keys, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings("SYN007", diags.get(0).rule_id);
    try testing.expectEqualStrings(
        "environment variable name must not be empty",
        diags.get(0).message,
    );
}

test "SYN007: container and service env keys are validated" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    container:
        \\      image: node:20
        \\      env:
        \\        "BAD KEY": 1
        \\        GOOD_KEY: 2
        \\    services:
        \\      redis:
        \\        image: redis
        \\        env:
        \\          X=Y: 1
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn007(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "\"BAD KEY\"") != null);
    try testing.expectEqual(@as(u32, 8), diags.get(0).span.start_line);
    try testing.expect(std.mem.indexOf(u8, diags.get(1).message, "\"X=Y\"") != null);
    try testing.expectEqual(@as(u32, 14), diags.get(1).span.start_line);
}

test "SYN007: an env key containing an expression is skipped" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    env:
        \\      "${{ matrix.env_name }}": 1
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn007(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN007: a non-scalar env value still has its key validated" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on: push
        \\env:
        \\  "A B":
        \\    - 1
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn007(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "\"A B\"") != null);
}

test "SYN008: duplicated job ID is reported" {
    var diags = runOnNeeds(&.{ "build", "build" });
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("SYN008", diag.rule_id);
    try testing.expect(diag.severity == .warning);
}

test "SYN008: duplicate detection is case-insensitive" {
    var diags = runOnNeeds(&.{ "Build", "bUILD" });
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
}

test "SYN008: a job ID repeated three times reports once" {
    var diags = runOnNeeds(&.{ "build", "build", "build" });
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
}

test "SYN008: distinct job IDs produce no diagnostic" {
    var diags = runOnNeeds(&.{ "build", "lint" });
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

fn runSyn009(source: []const u8, alloc: std.mem.Allocator, list: *DiagnosticList) !void {
    const wf = try test_support.parseWorkflowSource(alloc, source);
    checkUnknownEvents(&wf, list);
}

test "SYN009: a misspelled event is reported with a suggestion" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on:
        \\  pull_reqeust:
        \\    types: [opened]
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn009(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("SYN009", diag.rule_id);
    try testing.expect(diag.severity == .@"error");
    try testing.expectEqualStrings(
        "unknown Webhook event \"pull_reqeust\". did you mean \"pull_request\"?",
        diag.message,
    );
    // The diagnostic points at the event key, not at the `on:` line.
    try testing.expectEqual(@as(u32, 2), diag.span.start_line);
    try testing.expectEqual(@as(u32, 3), diag.span.start_col);
}

test "SYN009: an event with no near match is reported without a suggestion" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on:
        \\  push_tag:
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn009(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings("unknown Webhook event \"push_tag\"", diags.get(0).message);
}

test "SYN009: known events are clean in every `on` form" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const sources = [_][]const u8{
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
        ,
        \\on: [push, merge_group, workflow_dispatch]
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
        ,
        \\on:
        \\  discussion_comment:
        \\    types: [created]
        \\  schedule:
        \\    - cron: '0 0 * * *'
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
        ,
    };

    for (sources) |source| {
        var diags = DiagnosticList.init(testing.allocator);
        defer diags.deinit();
        try runSyn009(source, arena.allocator(), &diags);
        try testing.expectEqual(@as(usize, 0), diags.len());
    }
}

test "SYN009: an unknown event in a sequence is reported at its own item" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on: [push, puhs]
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn009(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings(
        "unknown Webhook event \"puhs\". did you mean \"push\"?",
        diags.get(0).message,
    );
    try testing.expectEqual(@as(u32, 1), diags.get(0).span.start_line);
    try testing.expectEqual(@as(u32, 12), diags.get(0).span.start_col);
}

test "SYN009: an event name built from an expression is skipped" {
    const on_events = [_]EventConfig{.{ .event = .other, .name = "${{ inputs.event }}" }};
    const wf = Workflow{ .on = .{ .events = &on_events }, .jobs = &.{} };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    checkUnknownEvents(&wf, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN009: an empty event name is reported" {
    const on_events = [_]EventConfig{.{ .event = .other, .name = "" }};
    const wf = Workflow{ .on = .{ .events = &on_events }, .jobs = &.{} };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    checkUnknownEvents(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings("unknown Webhook event \"\"", diags.get(0).message);
}

test "SYN012: branches with branches-ignore is an error" {
    const events = [_]EventConfig{.{
        .event = .push,
        .filter = .{ .spans = .{ .branches = Span.point(1, 1, 10), .branches_ignore = Span.point(1, 1, 30) } },
    }};
    var diags = runOn(&events);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("SYN012", diag.rule_id);
    try testing.expect(diag.severity == .@"error");
    try testing.expectEqualStrings(
        "both \"branches\" and \"branches-ignore\" filters cannot be used for the same event",
        diag.message,
    );
    try testing.expectEqual(@as(usize, 30), diag.span.start_byte);
}

test "SYN012: tags with tags-ignore is an error" {
    const events = [_]EventConfig{.{
        .event = .push,
        .filter = .{ .spans = .{ .tags = Span.point(1, 1, 10), .tags_ignore = Span.point(1, 1, 30) } },
    }};
    var diags = runOn(&events);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings(
        "both \"tags\" and \"tags-ignore\" filters cannot be used for the same event",
        diags.get(0).message,
    );
}

test "SYN012: paths with paths-ignore is an error" {
    const events = [_]EventConfig{.{
        .event = .push,
        .filter = .{ .spans = .{ .paths = Span.point(1, 1, 10), .paths_ignore = Span.point(1, 1, 30) } },
    }};
    var diags = runOn(&events);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings(
        "both \"paths\" and \"paths-ignore\" filters cannot be used for the same event",
        diags.get(0).message,
    );
}

test "SYN012: all three conflicting pairs are reported separately" {
    const events = [_]EventConfig{.{
        .event = .push,
        .filter = .{ .spans = .{
            .branches = Span.point(1, 1, 10),
            .branches_ignore = Span.point(1, 1, 20),
            .tags = Span.point(1, 1, 30),
            .tags_ignore = Span.point(1, 1, 40),
            .paths = Span.point(1, 1, 50),
            .paths_ignore = Span.point(1, 1, 60),
        } },
    }};
    var diags = runOn(&events);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 3), diags.len());
}

test "SYN012: filters from different pairs may coexist" {
    const events = [_]EventConfig{.{
        .event = .push,
        .filter = .{ .spans = .{ .branches = Span.point(1, 1, 10), .paths_ignore = Span.point(1, 1, 30) } },
    }};
    var diags = runOn(&events);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN012: an empty filter value still counts as present" {
    // `branches: []` parses to an empty array but the key is there, so the
    // conflict with `branches-ignore` must still be reported.
    const events = [_]EventConfig{.{
        .event = .push,
        .filter = .{
            .branches = .{},
            .branches_ignore = .{ .values = &.{"wip/**"} },
            .spans = .{ .branches = Span.point(1, 1, 10), .branches_ignore = Span.point(1, 1, 30) },
        },
    }};
    var diags = runOn(&events);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
}

test "SYN012: separate events using opposite halves are fine" {
    const events = [_]EventConfig{
        .{
            .event = .push,
            .filter = .{ .spans = .{ .branches = Span.point(1, 1, 10) } },
        },
        .{
            .event = .pull_request,
            .filter = .{ .spans = .{ .branches_ignore = Span.point(1, 1, 40) } },
        },
    };
    var diags = runOn(&events);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN012: event without a filter is ignored" {
    const events = [_]EventConfig{.{ .event = .push }};
    var diags = runOn(&events);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN012: diagnostic points at the first key when the ignore form comes first" {
    const events = [_]EventConfig{.{
        .event = .push,
        .filter = .{ .spans = .{ .branches = Span.point(1, 1, 40), .branches_ignore = Span.point(1, 1, 10) } },
    }};
    var diags = runOn(&events);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqual(@as(usize, 40), diags.get(0).span.start_byte);
}

fn runSyn013(source: []const u8) !DiagnosticList {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);
    var list = DiagnosticList.init(testing.allocator);
    checkGlobFilters(&wf, &list);
    return list;
}

fn runScheduleRules(source: []const u8) !DiagnosticList {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);
    var list = DiagnosticList.init(testing.allocator);
    checkScheduleCronSyntax(&wf, &list);
    checkScheduleCronFrequency(&wf, &list);
    checkScheduleTimezone(&wf, &list);
    return list;
}

test "SYN013: unclosed character class in branches" {
    const source =
        \\on:
        \\  push:
        \\    branches:
        \\      - 'v[1.*'
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn013(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings("SYN013", diags.get(0).rule_id);
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "missing ]") != null);
}

test "SYN013: + at start of path pattern" {
    const source =
        \\on:
        \\  push:
        \\    paths:
        \\      - '+foo'
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn013(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings("SYN013", diags.get(0).rule_id);
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "the preceding character must not be special character") != null);
    try testing.expectEqual(@as(u32, 10), diags.get(0).span.start_col);
}

test "SYN013: valid filter patterns produce no diagnostic" {
    const source =
        \\on:
        \\  push:
        \\    branches:
        \\      - main
        \\      - releases/**
        \\      - v[0-9].*
        \\    paths:
        \\      - src/**/*.zig
        \\      - '!src/vendor/**'
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn013(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN013: rejects ./ path prefix" {
    const source =
        \\on:
        \\  push:
        \\    paths:
        \\      - './src/**'
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn013(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "'.' and '..' are not allowed") != null);
}

test "SYN014: invalid cron expressions are reported" {
    const source =
        \\on:
        \\  schedule:
        \\    - cron: '0 0 * *'
        \\    - cron: '@daily'
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var diags = try runScheduleRules(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 2), test_support.countDiagnostics(&diags, "SYN014"));
    try testing.expectEqual(@as(usize, 0), test_support.countDiagnostics(&diags, "SYN015"));
}

test "SYN015: schedules shorter than 5 minutes are reported" {
    const source =
        \\on:
        \\  schedule:
        \\    - cron: '* * * * *'
        \\    - cron: '*/5 * * * *'
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var diags = try runScheduleRules(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), test_support.countDiagnostics(&diags, "SYN014"));
    try testing.expectEqual(@as(usize, 1), test_support.countDiagnostics(&diags, "SYN015"));
    const diag = test_support.findDiagnostic(&diags, "SYN015").?;
    try testing.expect(std.mem.indexOf(u8, diag.message, "60 seconds") != null);
}

test "SYN014/SYN015: valid daily schedule is clean" {
    const source =
        \\on:
        \\  schedule:
        \\    - cron: '0 0 * * *'
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var diags = try runScheduleRules(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), test_support.countDiagnostics(&diags, "SYN014"));
    try testing.expectEqual(@as(usize, 0), test_support.countDiagnostics(&diags, "SYN015"));
}

test "SYN016: unknown timezone names are reported" {
    const source =
        \\on:
        \\  schedule:
        \\    - cron: '0 0 * * *'
        \\      timezone: 'Asia/Tokio'
        \\    - cron: '0 9 * * *'
        \\      timezone: 'JST'
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var diags = try runScheduleRules(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 2), test_support.countDiagnostics(&diags, "SYN016"));
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "did you mean \"Asia/Tokyo\"") != null);
    try testing.expectEqual(@as(usize, 4), diags.get(0).span.start_line);
    try testing.expect(std.mem.indexOf(u8, diags.get(1).message, "\"JST\"") != null);
    try testing.expect(std.mem.indexOf(u8, diags.get(1).message, "did you mean") == null);
}

test "SYN016: IANA names and expression values are clean" {
    const source =
        \\on:
        \\  schedule:
        \\    - cron: '0 0 * * *'
        \\      timezone: 'Asia/Tokyo'
        \\    - cron: '0 1 * * *'
        \\      timezone: UTC
        \\    - cron: '0 2 * * *'
        \\      timezone: ${{ vars.TZ }}
        \\    - cron: '0 3 * * *'
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var diags = try runScheduleRules(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

fn runSyn017(source: []const u8) !DiagnosticList {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);
    var list = DiagnosticList.init(testing.allocator);
    checkWorkflowDispatchInputs(&wf, &list);
    return list;
}

test "SYN017: invalid workflow_dispatch inputs from the issue example" {
    const source =
        \\on:
        \\  workflow_dispatch:
        \\    inputs:
        \\      env:
        \\        type: choice
        \\        default: staging
        \\        options: [dev, prod]
        \\      verbose:
        \\        type: boolean
        \\        default: "yes"
        \\      level:
        \\        type: enum
        \\      target:
        \\        type: choice
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var diags = try runSyn017(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 4), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "default \"staging\"") != null);
    try testing.expectEqual(@as(usize, 6), diags.get(0).span.start_line);
    try testing.expect(std.mem.indexOf(u8, diags.get(1).message, "is not a valid \"boolean\" value") != null);
    try testing.expect(std.mem.indexOf(u8, diags.get(2).message, "invalid input type \"enum\"") != null);
    try testing.expect(std.mem.indexOf(u8, diags.get(3).message, "\"options\" is required") != null);
}

test "SYN017: options outside type choice and an empty options list are reported" {
    const source =
        \\on:
        \\  workflow_dispatch:
        \\    inputs:
        \\      name:
        \\        type: string
        \\        options: [a, b]
        \\      pick:
        \\        type: choice
        \\        options: []
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var diags = try runSyn017(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "only available for type \"choice\"") != null);
    try testing.expect(std.mem.indexOf(u8, diags.get(1).message, "is empty") != null);
}

test "SYN017: number default and untyped inputs" {
    const source =
        \\on:
        \\  workflow_dispatch:
        \\    inputs:
        \\      retries:
        \\        type: number
        \\        default: many
        \\      note:
        \\        description: free text
        \\        default: hello
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var diags = try runSyn017(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "is not a valid \"number\" value") != null);
}

test "SYN017: valid workflow_dispatch inputs are clean" {
    const source =
        \\on:
        \\  workflow_dispatch:
        \\    inputs:
        \\      env:
        \\        type: choice
        \\        default: dev
        \\        options: [dev, staging, prod]
        \\      verbose:
        \\        type: boolean
        \\        default: false
        \\      retries:
        \\        type: number
        \\        default: 3
        \\      target:
        \\        type: environment
        \\        default: production
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var diags = try runSyn017(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN017: an untyped input carrying options is still reported" {
    const source =
        \\on:
        \\  workflow_dispatch:
        \\    inputs:
        \\      env:
        \\        options: [dev, prod]
        \\        default: staging
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var diags = try runSyn017(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "only available for type \"choice\"") != null);
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "has type \"string\"") != null);
}

test "SYN017: a malformed options list does not abort the parse" {
    const source =
        \\on:
        \\  workflow_dispatch:
        \\    inputs:
        \\      pick:
        \\        type: choice
        \\        options:
        \\          - dev
        \\          - nested: value
        \\        default: prod
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var diags = try runSyn017(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "default \"prod\"") != null);
}

test "SYN017: YAML 1.2 boolean spellings are accepted as defaults" {
    const source =
        \\on:
        \\  workflow_dispatch:
        \\    inputs:
        \\      a:
        \\        type: boolean
        \\        default: True
        \\      b:
        \\        type: boolean
        \\        default: FALSE
        \\      c:
        \\        type: boolean
        \\        default: yes
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var diags = try runSyn017(source);
    defer diags.deinit();

    // `yes` is YAML 1.1 only, so it stays a string and is still reported.
    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "\"c\"") != null);
}

test "SYN017: a scalar options value counts as no options" {
    const source =
        \\on:
        \\  workflow_dispatch:
        \\    inputs:
        \\      pick:
        \\        type: choice
        \\        options: dev
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo
    ;

    var diags = try runSyn017(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "is empty") != null);
}
