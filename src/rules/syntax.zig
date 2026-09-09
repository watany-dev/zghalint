const std = @import("std");
const engine = @import("engine.zig");
const glob = @import("glob.zig");
const workflow_types = @import("../workflow/types.zig");
const workflow_events = @import("../workflow/events.zig");
const workflow_parser = @import("../workflow/parser.zig");
const yaml_types = @import("../yaml/types.zig");
const util = @import("../util.zig");
const fix_builder = @import("../fix/builder.zig");
const diagnostics_mod = @import("../diagnostics.zig");
const rename = @import("rename.zig");

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

/// An emptied-out workflow that was never deleted is a finding of its own, but
/// the workflow parser needs `on` and `jobs` and gives up on it, which would
/// drop the file as unlintable. So SYN020 is reported from the YAML document,
/// before the parse the CLI skips when this returns true.
pub fn lintEmptyWorkflow(root: Node, list: *DiagnosticList) bool {
    const empty = switch (root) {
        .null_value => true,
        .scalar => |s| std.mem.trim(u8, s.value, " \t\r\n").len == 0,
        .mapping => |m| m.entries.len == 0,
        // A root sequence has content, just not the shape a workflow takes;
        // the workflow parser reports that as a type error.
        .sequence => false,
    };
    if (!empty) return false;
    list.append(.{
        .rule_id = "SYN020",
        .severity = .@"error",
        .message = "workflow file is empty",
        // The document's own span sits wherever the parser stopped, which for
        // a comments-only file is the line past the last comment. The finding
        // is about the whole file, so it is anchored at its first line.
        .span = Span.point(1, 1, 0),
        .fix_hint = "delete the file, or give it \"on\" and \"jobs\"",
    }) catch {};
    return true;
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

fn siblingHasKeyIgnoreCase(m: Mapping, self_span: Span, key: []const u8) bool {
    for (m.entries) |entry| {
        if (entry.key.span.start_byte == self_span.start_byte and
            entry.key.span.end_byte == self_span.end_byte) continue;
        if (std.ascii.eqlIgnoreCase(entry.key.value, key)) return true;
    }
    return false;
}

/// A rename that would duplicate a sibling key is dropped: applying it would
/// turn SYN001 into SYN002 (#347). The unknown key itself is not a sibling,
/// even when it equals the suggestion ignoring case (`Timeout-minutes`).
fn unknownKeyFix(list: *DiagnosticList, uk: UnknownKey, suggestion: []const u8) ?diagnostics_mod.Fix {
    if (siblingHasKeyIgnoreCase(uk.mapping, uk.span, suggestion)) return null;
    return rename.tokenFix(list, uk.span, uk.key, suggestion);
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
            .fix = if (suggestion) |s| unknownKeyFix(list, uk, s) else null,
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

/// Removes every repeat of `dep` from index `first_repeat` on, so an ID
/// written three times is down to one after a single `--fix` run. The first
/// occurrence sits before `first_repeat` and is left alone, which is also why
/// the deletion can never empty the sequence.
fn buildDuplicateNeedsFix(
    job: *const Job,
    diag_list: *DiagnosticList,
    dep: []const u8,
    first_repeat: usize,
) ?diagnostics_mod.Fix {
    if (job.needs_deletes.len != job.needs.len) return null;

    const alloc = diag_list.fixAllocator();
    var indices = std.ArrayList(usize){};
    for (job.needs[first_repeat..], first_repeat..) |later, i| {
        if (!std.ascii.eqlIgnoreCase(later, dep)) continue;
        indices.append(alloc, i) catch return null;
    }

    const edits = fix_builder.deleteSequenceItems(alloc, job.needs_deletes, indices.items) orelse return null;
    return .{
        .description = "remove the duplicated job ID from 'needs'",
        .safety = .safe,
        .edits = edits,
    };
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
            .fix = buildDuplicateNeedsFix(job, diag_list, dep, i),
        }) catch return;
    }
}

/// Removes every repeat of `value` from index `first_repeat` on. Attaching one
/// fix that covers them all — rather than one per diagnostic — is what keeps a
/// value written three times fixable in a single run: `fix.engine` drops a fix
/// whose edits overlap another's, and in `[a, a, a]` the ranges of the second
/// and third item do overlap.
fn buildDuplicateMatrixFix(
    alloc: std.mem.Allocator,
    axis: workflow_types.MatrixAxis,
    value: yaml_types.Node,
    first_repeat: usize,
) ?diagnostics_mod.Fix {
    if (axis.value_deletes.len != axis.values.len) return null;

    var indices = std.ArrayList(usize){};
    for (axis.values[first_repeat..], first_repeat..) |later, i| {
        if (!later.eql(value)) continue;
        indices.append(alloc, i) catch return null;
    }

    const edits = fix_builder.deleteSequenceItems(alloc, axis.value_deletes, indices.items) orelse return null;
    return .{
        .description = "remove the duplicated matrix value",
        .safety = .safe,
        .edits = edits,
    };
}

/// A repeated matrix value produces no new combination, so the extra entry
/// never yields the job variation the author was reaching for.
fn checkDuplicateMatrixValues(job: *const Job, list: *DiagnosticList) void {
    const matrix = (job.strategy orelse return).matrix orelse return;
    const alloc = list.fixAllocator();

    for (matrix.axes) |axis| {
        for (axis.values, 0..) |value, i| {
            var prior_count: usize = 0;
            for (axis.values[0..i]) |earlier| {
                if (earlier.eql(value)) prior_count += 1;
            }
            for (axis.values[0..i]) |prior| {
                if (!value.eql(prior)) continue;

                // Only a scalar has text worth quoting back: `include` and
                // `exclude` entries are mappings.
                const noun: []const u8 = if (value == .scalar) "value" else "entry";
                const quoted = switch (value) {
                    .scalar => |s| std.fmt.allocPrint(alloc, " \"{s}\"", .{s.value}) catch "",
                    else => "",
                };
                const prior_span = prior.getSpan();

                // Only the first repeat carries the fix; it already removes the
                // ones the later diagnostics point at.
                const fix: ?diagnostics_mod.Fix = if (prior_count == 1)
                    buildDuplicateMatrixFix(alloc, axis, value, i)
                else
                    null;

                list.append(.{
                    .rule_id = "SYN018",
                    .severity = .warning,
                    .message = std.fmt.allocPrint(
                        alloc,
                        "duplicate {s}{s} is found in matrix \"{s}\". the same {s} is at line {d}, col {d}",
                        .{ noun, quoted, axis.name, noun, prior_span.start_line, prior_span.start_col },
                    ) catch "duplicate value is found in matrix",
                    .span = value.getSpan(),
                    .fix_hint = "remove the repeated value; it produces no combination the earlier one does not",
                    .fix = fix,
                }) catch return;
                break;
            }
        }
    }
}

/// `include` and `exclude` sit in the axis list beside the real axes, but they
/// configure the matrix rather than adding a dimension to it.
fn isMatrixModifier(name: []const u8) bool {
    return std.mem.eql(u8, name, "include") or std.mem.eql(u8, name, "exclude");
}

fn findMatrixAxis(matrix: workflow_types.Matrix, name: []const u8) ?workflow_types.MatrixAxis {
    for (matrix.axes) |axis| {
        if (isMatrixModifier(axis.name)) continue;
        if (std.mem.eql(u8, axis.name, name)) return axis;
    }
    return null;
}

fn matrixModifier(matrix: workflow_types.Matrix, name: []const u8) ?workflow_types.MatrixAxis {
    for (matrix.axes) |axis| {
        if (std.mem.eql(u8, axis.name, name)) return axis;
    }
    return null;
}

fn isExpression(node: Node) bool {
    return switch (node) {
        .scalar => |s| std.mem.indexOf(u8, s.value, "${{") != null,
        else => false,
    };
}

/// YAML resolves `1.10` and `1.1` to the same number and `True` and `true` to
/// the same boolean, so comparing the source text alone would flag a value the
/// axis does list.
fn scalarsEquivalent(a: yaml_types.Scalar, b: yaml_types.Scalar) bool {
    if (std.mem.eql(u8, a.value, b.value)) return true;

    // Quoting makes a scalar a string, and `"3.10"` and `"3.1"` are two strings.
    if (a.style != .plain or b.style != .plain) return false;

    if (isBooleanSpelling(a.value) and isBooleanSpelling(b.value)) {
        return std.ascii.eqlIgnoreCase(a.value, b.value);
    }
    const num_a = std.fmt.parseFloat(f64, a.value) catch return false;
    const num_b = std.fmt.parseFloat(f64, b.value) catch return false;
    return num_a == num_b;
}

fn isBooleanSpelling(text: []const u8) bool {
    return std.ascii.eqlIgnoreCase(text, "true") or std.ascii.eqlIgnoreCase(text, "false");
}

/// Whether the axis `key` takes `value`, or null when the answer is not knowable
/// from the source alone (an expression, or an axis that is not a list).
///
/// `include` is deliberately not consulted: GitHub applies `exclude` to the base
/// matrix and merges `include` afterwards, so a combination only `include`
/// contributes is never removed by `exclude`.
fn axisTakesValue(axis: workflow_types.MatrixAxis, value: Node) ?bool {
    if (isExpression(value)) return null;
    // An axis built from an expression carries no values to compare against.
    if (axis.values.len == 0) return null;

    for (axis.values) |candidate| {
        if (isExpression(candidate)) return null;
        if (candidate == .scalar and value == .scalar) {
            if (scalarsEquivalent(candidate.scalar, value.scalar)) return true;
        } else if (candidate.eql(value)) return true;
    }
    return false;
}

/// The axis names an `include` / `exclude` key may plausibly have meant. Capped
/// because the list only feeds a "did you mean" suggestion.
fn collectAxisNames(matrix: workflow_types.Matrix, buf: [][]const u8) [][]const u8 {
    var len: usize = 0;
    for (matrix.axes) |axis| {
        if (isMatrixModifier(axis.name)) continue;
        if (len == buf.len) break;
        buf[len] = axis.name;
        len += 1;
    }
    return buf[0..len];
}

/// An `exclude` entry that names a key or a value the matrix never produces
/// removes nothing, so the matrix still runs the combination the author meant to
/// drop.
fn checkMatrixExclude(
    matrix: workflow_types.Matrix,
    axis_names: []const []const u8,
    list: *DiagnosticList,
) void {
    const exclude = matrixModifier(matrix, "exclude") orelse return;
    const alloc = list.fixAllocator();

    for (exclude.values) |entry| {
        const mapping = switch (entry) {
            .mapping => |m| m,
            else => continue,
        };
        for (mapping.entries) |kv| {
            const key = kv.key.value;
            if (std.mem.indexOf(u8, key, "${{") != null) continue;

            const axis = findMatrixAxis(matrix, key) orelse {
                var suffix_buf: [64]u8 = undefined;
                const suggestion = util.didYouMean(key, axis_names);
                const suffix = if (suggestion) |s|
                    std.fmt.bufPrint(&suffix_buf, ". did you mean \"{s}\"?", .{s}) catch ""
                else
                    "";

                list.append(.{
                    .rule_id = "SYN019",
                    .severity = .warning,
                    .message = std.fmt.allocPrint(
                        alloc,
                        "unknown key \"{s}\" in \"exclude\"{s}",
                        .{ key, suffix },
                    ) catch "unknown key in \"exclude\"",
                    .span = kv.key.span,
                    .fix_hint = "name one of the matrix axes, or drop the entry",
                    .fix = if (suggestion) |s| rename.tokenFix(list, kv.key.span, key, s) else null,
                }) catch return;
                continue;
            };

            // Only a scalar has text the message can quote back.
            const quoted = switch (kv.value) {
                .scalar => |s| s.value,
                else => continue,
            };

            const takes = axisTakesValue(axis, kv.value) orelse continue;
            if (takes) continue;

            list.append(.{
                .rule_id = "SYN019",
                .severity = .warning,
                .message = std.fmt.allocPrint(
                    alloc,
                    "\"{s}\" does not exist in \"{s}\" axis",
                    .{ quoted, key },
                ) catch "value does not exist in the matrix axis",
                .span = kv.value.getSpan(),
                .fix_hint = "use a value the axis produces; this entry excludes no combination",
            }) catch return;
        }
    }
}

/// A key that shares an entry with the axis it resembles is a deliberate second
/// key rather than a misspelling, and that holds for every entry in the block:
/// `mode` beside `node` once makes `mode` a real key throughout `include`.
fn includePairsKeyWithAxis(
    include: workflow_types.MatrixAxis,
    key: []const u8,
    axis_name: []const u8,
) bool {
    for (include.values) |entry| {
        const mapping = switch (entry) {
            .mapping => |m| m,
            else => continue,
        };
        if (mapping.getKeySpan(key) != null and mapping.getKeySpan(axis_name) != null) return true;
    }
    return false;
}

/// `include` is free to add keys, so only a key one edit away from an existing
/// axis — and never one the block pairs with that axis — reads as a typo.
fn checkMatrixInclude(
    matrix: workflow_types.Matrix,
    axis_names: []const []const u8,
    list: *DiagnosticList,
) void {
    const include = matrixModifier(matrix, "include") orelse return;
    const alloc = list.fixAllocator();

    for (include.values) |entry| {
        const mapping = switch (entry) {
            .mapping => |m| m,
            else => continue,
        };
        for (mapping.entries) |kv| {
            const key = kv.key.value;
            if (std.mem.indexOf(u8, key, "${{") != null) continue;
            if (findMatrixAxis(matrix, key) != null) continue;

            var near: ?[]const u8 = null;
            var near_count: usize = 0;
            for (axis_names) |name| {
                if (util.levenshteinDistance(key, name) != 1) continue;
                if (includePairsKeyWithAxis(include, key, name)) continue;
                near = name;
                near_count += 1;
            }
            if (near_count != 1) continue;

            list.append(.{
                .rule_id = "SYN019",
                .severity = .warning,
                .message = std.fmt.allocPrint(
                    alloc,
                    "unknown key \"{s}\" in \"include\". did you mean \"{s}\"?",
                    .{ key, near.? },
                ) catch "unknown key in \"include\"",
                .span = kv.key.span,
                .fix_hint = "rename the key to the axis it shadows, or keep it if the new key is intentional",
            }) catch return;
        }
    }
}

fn checkMatrixIncludeExclude(job: *const Job, list: *DiagnosticList) void {
    const matrix = (job.strategy orelse return).matrix orelse return;

    var name_buf: [32][]const u8 = undefined;
    const axis_names = collectAxisNames(matrix, &name_buf);

    checkMatrixExclude(matrix, axis_names, list);
    checkMatrixInclude(matrix, axis_names, list);
}

/// Privileged triggers (`pull_request_target`, `workflow_run`) run with the
/// default branch's secrets, so correcting a typo into one of them is unsafe
/// (#346). Ordinary trigger names stay `safe`.
fn eventNameFix(
    list: *DiagnosticList,
    span: Span,
    old_name: []const u8,
    suggestion: []const u8,
) ?diagnostics_mod.Fix {
    var fix = rename.tokenFix(list, span, old_name, suggestion) orelse return null;
    if (workflow_events.isPrivileged(suggestion)) fix.safety = .unsafe;
    return fix;
}

fn checkUnknownEvents(wf: *const Workflow, list: *DiagnosticList) void {
    const alloc = list.fixAllocator();
    for (wf.on.events) |event| {
        // A name built from an expression is not a literal event name at all.
        // An empty name is not exempt: `on: ""` triggers nothing either.
        if (std.mem.indexOf(u8, event.name, "${{") != null) continue;
        if (workflow_events.isKnown(event.name)) continue;

        var suffix_buf: [64]u8 = undefined;
        const suggestion = util.didYouMean(event.name, &workflow_events.trigger_names);
        const suffix = if (suggestion) |s|
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
            .fix = if (suggestion) |s| eventNameFix(list, event.name_span, event.name, s) else null,
        }) catch return;
    }
}

/// `<prefix> a, b, c` — the shape every SYN010/SYN011 hint takes. Returns
/// `fallback` when there is nothing to list, or when the arena is exhausted.
fn availableHint(
    alloc: std.mem.Allocator,
    prefix: []const u8,
    names: []const []const u8,
    fallback: []const u8,
) []const u8 {
    if (names.len == 0) return fallback;
    const list = std.mem.join(alloc, ", ", names) catch return fallback;
    return std.fmt.allocPrint(alloc, "{s} {s}", .{ prefix, list }) catch fallback;
}

/// SYN010/SYN011 both trust the trigger table, so an event the table does not
/// know is left to SYN009 rather than reported twice with a second wording.
fn knownEventSpec(event: workflow_types.EventConfig) ?workflow_events.EventSpec {
    if (std.mem.indexOf(u8, event.name, "${{") != null) return null;
    return workflow_events.find(event.name);
}

fn checkActivityTypes(wf: *const Workflow, list: *DiagnosticList) void {
    const alloc = list.fixAllocator();
    for (wf.on.events) |event| {
        const spec = knownEventSpec(event) orelse continue;

        if (!spec.acceptsTypes()) {
            const key_span = event.types_key_span orelse continue;
            list.append(.{
                .rule_id = "SYN010",
                .severity = .@"error",
                .message = std.fmt.allocPrint(
                    alloc,
                    "\"types\" is not available for \"{s}\" event",
                    .{event.name},
                ) catch "\"types\" is not available for this event",
                .span = key_span,
                .fix_hint = "remove 'types'; this event has no activity types to filter on",
            }) catch return;
            continue;
        }

        // A null table means the names are the caller's to choose
        // (`repository_dispatch`), so only the key itself is validated above.
        const known = spec.activity_types orelse continue;

        for (event.activity_types.values, 0..) |value, i| {
            if (std.mem.indexOf(u8, value, "${{") != null) continue;

            var found = false;
            for (known) |name| {
                if (std.mem.eql(u8, name, value)) found = true;
            }
            if (found) continue;

            var suffix_buf: [64]u8 = undefined;
            const suggestion = util.didYouMean(value, known);
            const suffix = if (suggestion) |s|
                std.fmt.bufPrint(&suffix_buf, ". did you mean \"{s}\"?", .{s}) catch ""
            else
                "";
            const value_span: ?Span = if (i < event.activity_types.spans.len)
                event.activity_types.spans[i]
            else
                null;

            list.append(.{
                .rule_id = "SYN010",
                .severity = .@"error",
                .message = std.fmt.allocPrint(
                    alloc,
                    "invalid activity type \"{s}\" for \"{s}\" event{s}",
                    .{ value, event.name, suffix },
                ) catch "invalid activity type",
                .span = value_span orelse event.name_span,
                .fix_hint = availableHint(
                    alloc,
                    "available types are",
                    known,
                    "use one of the activity types this event defines",
                ),
                .fix = if (suggestion) |s|
                    if (value_span) |vs| rename.tokenFix(list, vs, value, s) else null
                else
                    null,
            }) catch return;
        }
    }
}

/// Dropping the whole `<key>:` entry is what both halves of SYN011 ask for:
/// the event does not read the key, so nothing is lost but the lines. Unsafe
/// because a filter that goes away widens what the workflow runs on — the
/// author more often meant to move it under an event that accepts it.
fn buildEventKeyFix(
    alloc: std.mem.Allocator,
    key: workflow_types.EventConfigKey,
    description: []const u8,
) ?diagnostics_mod.Fix {
    const full_span = key.full_span orelse return null;
    const edits = fix_builder.deleteMappingEntry(alloc, full_span) orelse return null;
    return .{
        .description = description,
        .safety = .unsafe,
        .edits = edits,
    };
}

fn checkEventFilters(wf: *const Workflow, list: *DiagnosticList) void {
    const alloc = list.fixAllocator();
    for (wf.on.events) |event| {
        const spec = knownEventSpec(event) orelse continue;

        var candidate_buf: [workflow_events.max_event_keys][]const u8 = undefined;
        const candidates = spec.keyCandidates(&candidate_buf);

        for (event.config_keys) |key| {
            // `types` is SYN010's to judge, availability included.
            if (std.mem.eql(u8, key.name, "types")) continue;
            if (spec.accepts(key.name)) continue;

            if (workflow_events.isFilter(key.name)) {
                list.append(.{
                    .rule_id = "SYN011",
                    .severity = .@"error",
                    .message = std.fmt.allocPrint(
                        alloc,
                        "\"{s}\" filter is not available for \"{s}\" event",
                        .{ key.name, event.name },
                    ) catch "this filter is not available for this event",
                    .span = key.span,
                    .fix_hint = availableHint(
                        alloc,
                        "this event accepts only",
                        spec.filters,
                        "remove this filter; this event accepts no ref or path filters",
                    ),
                    .fix = buildEventKeyFix(alloc, key, "remove the filter this event does not accept"),
                }) catch return;
                continue;
            }

            var suffix_buf: [64]u8 = undefined;
            const suggestion = util.didYouMean(key.name, candidates);
            const suffix = if (suggestion) |s|
                std.fmt.bufPrint(&suffix_buf, ". did you mean \"{s}\"?", .{s}) catch ""
            else
                "";
            // "filter" reads wrong for a key that is not one: `workflows` under
            // `workflow_run`, or `inputs` under `workflow_call`.
            const noun = if (suggestion) |s|
                if (workflow_events.isFilter(s)) "filter" else "key"
            else
                "key";

            list.append(.{
                .rule_id = "SYN011",
                .severity = .@"error",
                .message = std.fmt.allocPrint(
                    alloc,
                    "unknown {s} \"{s}\" for \"{s}\" event{s}",
                    .{ noun, key.name, event.name, suffix },
                ) catch "unknown event configuration key",
                .span = key.span,
                .fix_hint = availableHint(
                    alloc,
                    "this event accepts only",
                    candidates,
                    "remove this key; the event does not read it",
                ),
                // A key we know how to spell is renamed rather than removed;
                // deletion is the fallback when there is no candidate.
                .fix = if (suggestion) |s|
                    rename.tokenFix(list, key.span, key.name, s) orelse
                        buildEventKeyFix(alloc, key, "remove the key this event does not read")
                else
                    buildEventKeyFix(alloc, key, "remove the key this event does not read"),
            }) catch return;
        }
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
            const suggestion = util.didYouMean(tz, &timezones.timezone_names);
            const suffix = if (suggestion) |s|
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
                .fix = if (suggestion) |s|
                    if (entry.timezone_span) |ts| rename.tokenFix(list, ts, tz, s) else null
                else
                    null,
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
        .id = "SYN010",
        .name = "invalid-activity-type",
        .description = "'types' names an activity type the event does not define, so the workflow never triggers",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkActivityTypes,
    },
    .{
        .id = "SYN011",
        .name = "unavailable-event-filter",
        .description = "Event filter is not available for the event it is written under, or is not a filter name at all",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkEventFilters,
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
    .{
        .id = "SYN018",
        .name = "duplicate-matrix-value",
        .description = "the same value appears more than once in a 'strategy.matrix' axis",
        .severity = .warning,
        .category = .syntax,
        .check_job = &checkDuplicateMatrixValues,
    },
    .{
        .id = "SYN019",
        .name = "matrix-include-exclude",
        .description = "'strategy.matrix' include/exclude names a key or value the matrix never produces",
        .severity = .warning,
        .category = .syntax,
        .check_job = &checkMatrixIncludeExclude,
    },
    // `lintEmptyWorkflow` runs before the workflow parser, so there is no
    // `check_*` to hang this on; the entry exists so the ID is configurable
    // and documented like every other rule.
    .{
        .id = "SYN020",
        .name = "empty-workflow",
        .description = "the workflow file has no content at all",
        .severity = .@"error",
        .category = .syntax,
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

test "SYN001: a typo is a safe rename when the target key is absent" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    timeout-minute: 10
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const outcome = try test_support.lintAndFix(
        testing.allocator,
        source,
        .{ .workflow = &checkUnknownKeys },
        false,
    );
    defer outcome.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), outcome.diagnostic_count);
    try testing.expectEqual(diagnostics_mod.FixSafety.safe, outcome.first_safety.?);
    try testing.expectEqual(@as(usize, 1), outcome.edits_applied);
    try testing.expect(std.mem.indexOf(u8, outcome.content, "timeout-minutes:") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.content, "timeout-minute:") == null);
}

test "SYN001: no autofix when the suggested sibling already exists" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    runs-onn: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const outcome = try test_support.lintAndFix(
        testing.allocator,
        source,
        .{ .workflow = &checkUnknownKeys },
        false,
    );
    defer outcome.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), outcome.diagnostic_count);
    try testing.expectEqual(@as(usize, 0), outcome.fix_count);
    try testing.expectEqualStrings(source, outcome.content);
}

test "SYN001: a case-only mismatch of a known key is still renamed" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    Timeout-minutes: 10
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const outcome = try test_support.lintAndFix(
        testing.allocator,
        source,
        .{ .workflow = &checkUnknownKeys },
        false,
    );
    defer outcome.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), outcome.diagnostic_count);
    try testing.expectEqual(@as(usize, 1), outcome.edits_applied);
    try testing.expect(std.mem.indexOf(u8, outcome.content, "timeout-minutes:") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.content, "Timeout-minutes:") == null);
}

test "SYN001: no autofix when a sibling differs only in letter case" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    Timeout-minutes: 10
        \\    timeout-minute: 5
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const outcome = try test_support.lintAndFix(
        testing.allocator,
        source,
        .{ .workflow = &checkUnknownKeys },
        false,
    );
    defer outcome.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 2), outcome.diagnostic_count);
    try testing.expect(std.mem.indexOf(u8, outcome.content, "timeout-minute:") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, outcome.content, "timeout-minutes:"));
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

test "SYN008: autofix drops the repeated entry from a block needs list" {
    const source =
        \\on: push
        \\jobs:
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    needs:
        \\      - build
        \\      - test
        \\      - build
        \\    steps:
        \\      - run: make
        \\
    ;
    const result = try test_support.lintAndFix(testing.allocator, source, .{ .job = &checkDuplicateNeeds }, false);
    defer testing.allocator.free(result.content);

    try testing.expectEqual(@as(usize, 1), result.fix_count);
    try testing.expect(result.first_safety.? == .safe);
    try testing.expectEqualStrings(
        \\on: push
        \\jobs:
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    needs:
        \\      - build
        \\      - test
        \\    steps:
        \\      - run: make
        \\
    , result.content);
}

test "SYN008: autofix drops every repeat, so one run leaves a single entry" {
    const source =
        \\on: push
        \\jobs:
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    needs: [build, build, build]
        \\    steps:
        \\      - run: make
        \\
    ;
    const result = try test_support.lintAndFix(testing.allocator, source, .{ .job = &checkDuplicateNeeds }, false);
    defer testing.allocator.free(result.content);

    try testing.expectEqualStrings(
        \\on: push
        \\jobs:
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    needs: [build]
        \\    steps:
        \\      - run: make
        \\
    , result.content);
}

test "SYN008: a scalar needs has no entry to remove, so no fix" {
    const source =
        \\on: push
        \\jobs:
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    needs: build
        \\    steps:
        \\      - run: make
        \\
    ;
    const result = try test_support.lintAndFix(testing.allocator, source, .{ .job = &checkDuplicateNeeds }, true);
    defer testing.allocator.free(result.content);

    try testing.expectEqual(@as(usize, 0), result.fix_count);
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

fn runSyn010(source: []const u8, alloc: std.mem.Allocator, list: *DiagnosticList) !void {
    const wf = try test_support.parseWorkflowSource(alloc, source);
    checkActivityTypes(&wf, list);
}

fn runSyn011(source: []const u8, alloc: std.mem.Allocator, list: *DiagnosticList) !void {
    const wf = try test_support.parseWorkflowSource(alloc, source);
    checkEventFilters(&wf, list);
}

const trailer =
    \\jobs:
    \\  build:
    \\    runs-on: ubuntu-latest
    \\    steps:
    \\      - run: echo hi
    \\
;

test "SYN010: an invalid activity type is reported with a suggestion" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on:
        \\  issues:
        \\    types: [open, closed]
        \\
    ++ trailer;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn010(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("SYN010", diag.rule_id);
    try testing.expectEqualStrings(
        "invalid activity type \"open\" for \"issues\" event. did you mean \"opened\"?",
        diag.message,
    );
    // The span points at the offending item, not the whole `types` sequence.
    try testing.expectEqual(@as(u32, 3), diag.span.start_line);
    try testing.expectEqual(@as(u32, 13), diag.span.start_col);
}

test "SYN010: a type with no near match still lists the available names" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on:
        \\  watch:
        \\    types: [everything]
        \\
    ++ trailer;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn010(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings(
        "invalid activity type \"everything\" for \"watch\" event",
        diags.get(0).message,
    );
    try testing.expectEqualStrings("available types are started", diags.get(0).fix_hint.?);
}

test "SYN010: `types` on an event without activity types is reported" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on:
        \\  push:
        \\    types: [opened]
        \\
    ++ trailer;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn010(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings(
        "\"types\" is not available for \"push\" event",
        diags.get(0).message,
    );
    try testing.expectEqual(@as(u32, 3), diags.get(0).span.start_line);
}

test "SYN010: valid types, dispatch types and unknown events stay quiet" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const sources = [_][]const u8{
        \\on:
        \\  issues:
        \\    types: [opened, reopened]
        \\  pull_request:
        \\    types: [opened, synchronize, ready_for_review]
        \\
        ,
        // The names belong to the dispatch sender, so nothing to check.
        \\on:
        \\  repository_dispatch:
        \\    types: [deploy-please]
        \\
        ,
        // SYN009 owns the unknown event; SYN010 must not pile on.
        \\on:
        \\  isues:
        \\    types: [open]
        \\
        ,
        // A type built from an expression is not a literal name.
        \\on:
        \\  issues:
        \\    types: ["${{ env.KIND }}"]
        \\
        ,
    };

    for (sources) |head| {
        const source = try std.mem.concat(arena.allocator(), u8, &.{ head, trailer });
        var diags = DiagnosticList.init(testing.allocator);
        defer diags.deinit();
        try runSyn010(source, arena.allocator(), &diags);
        try testing.expectEqual(@as(usize, 0), diags.len());
    }
}

test "SYN011: a filter the event does not offer is reported" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on:
        \\  issues:
        \\    branches: [main]
        \\
    ++ trailer;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn011(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("SYN011", diag.rule_id);
    try testing.expectEqualStrings(
        "\"branches\" filter is not available for \"issues\" event",
        diag.message,
    );
    try testing.expectEqualStrings(
        "remove this filter; this event accepts no ref or path filters",
        diag.fix_hint.?,
    );
}

test "SYN011: autofix removes the filter the event does not accept" {
    const source =
        \\on:
        \\  issues:
        \\    branches: [main]
        \\
    ++ trailer;

    const result = try test_support.lintAndFix(testing.allocator, source, .{ .workflow = &checkEventFilters }, true);
    defer testing.allocator.free(result.content);

    try testing.expectEqual(@as(usize, 1), result.fix_count);
    try testing.expect(result.first_safety.? == .unsafe);
    try testing.expectEqualStrings("on:\n  issues:\n" ++ trailer, result.content);
}

test "SYN011: a misspelled key is renamed rather than removed" {
    const source =
        \\on:
        \\  push:
        \\    brancehs: [main]
        \\
    ++ trailer;

    const result = try test_support.lintAndFix(testing.allocator, source, .{ .workflow = &checkEventFilters }, false);
    defer testing.allocator.free(result.content);

    try testing.expectEqual(@as(usize, 1), result.fix_count);
    try testing.expect(result.first_safety.? == .safe);
    try testing.expectEqualStrings("on:\n  push:\n    branches: [main]\n" ++ trailer, result.content);
}

test "SYN011: the filter fix is unsafe, so --fix alone leaves it in place" {
    const source =
        \\on:
        \\  issues:
        \\    branches: [main]
        \\
    ++ trailer;

    const result = try test_support.lintAndFix(testing.allocator, source, .{ .workflow = &checkEventFilters }, false);
    defer testing.allocator.free(result.content);

    try testing.expectEqual(@as(usize, 0), result.fix_count);
    try testing.expectEqualStrings(source, result.content);
}

test "SYN011: pull_request rejects tags but keeps branches" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on:
        \\  pull_request:
        \\    branches: [main]
        \\    tags: [v*]
        \\
    ++ trailer;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn011(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings(
        "\"tags\" filter is not available for \"pull_request\" event",
        diags.get(0).message,
    );
    try testing.expectEqualStrings(
        "this event accepts only branches, branches-ignore, paths, paths-ignore",
        diags.get(0).fix_hint.?,
    );
}

test "SYN011: workflow_run offers only the branch filters" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on:
        \\  workflow_run:
        \\    workflows: [CI]
        \\    types: [completed]
        \\    branches: [main]
        \\    paths: ['src/**']
        \\
    ++ trailer;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn011(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings(
        "\"paths\" filter is not available for \"workflow_run\" event",
        diags.get(0).message,
    );
}

test "SYN011: a misspelled key is reported with a suggestion" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on:
        \\  push:
        \\    brancehs: [main]
        \\  workflow_dispatch:
        \\    inptus: {}
        \\
    ++ trailer;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn011(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expectEqualStrings(
        "unknown filter \"brancehs\" for \"push\" event. did you mean \"branches\"?",
        diags.get(0).message,
    );
    // `workflow_dispatch` has no ref filters, so "filter" would misname its keys.
    try testing.expectEqualStrings(
        "unknown key \"inptus\" for \"workflow_dispatch\" event. did you mean \"inputs\"?",
        diags.get(1).message,
    );
}

test "SYN011: an event with no keys at all gets a hint that lists nothing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on:
        \\  fork:
        \\    brancehs: [main]
        \\
    ++ trailer;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn011(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings(
        "unknown key \"brancehs\" for \"fork\" event",
        diags.get(0).message,
    );
    try testing.expectEqualStrings(
        "remove this key; the event does not read it",
        diags.get(0).fix_hint.?,
    );
}

test "SYN011: a misspelled non-filter key is not called a filter" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\on:
        \\  workflow_run:
        \\    workflowss: [CI]
        \\
    ++ trailer;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try runSyn011(source, arena.allocator(), &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    // `workflow_run` does take filters, so the noun has to come from the
    // suggestion rather than from the event.
    try testing.expectEqualStrings(
        "unknown key \"workflowss\" for \"workflow_run\" event. did you mean \"workflows\"?",
        diags.get(0).message,
    );
}

test "SYN011: filters the event offers stay quiet" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const sources = [_][]const u8{
        \\on:
        \\  push:
        \\    branches: [main]
        \\    paths: ['src/**']
        \\  pull_request:
        \\    branches-ignore: [wip/**]
        \\
        ,
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      name:
        \\        type: string
        \\    secrets:
        \\      token:
        \\        required: true
        \\
        ,
        // SYN009 owns the unknown event.
        \\on:
        \\  isues:
        \\    branches: [main]
        \\
        ,
    };

    for (sources) |head| {
        const source = try std.mem.concat(arena.allocator(), u8, &.{ head, trailer });
        var diags = DiagnosticList.init(testing.allocator);
        defer diags.deinit();
        try runSyn011(source, arena.allocator(), &diags);
        try testing.expectEqual(@as(usize, 0), diags.len());
    }
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

test "SYN009: a block scalar event name is reported but never rewritten" {
    // `on: >` drops the indicator and the newline from the value, so the span is
    // two bytes wider than the name -- the same shape as a quoted scalar. Only
    // the byte check in `fix/engine.zig` tells them apart.
    const source =
        \\on: >
        \\ pusg
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const outcome = try test_support.lintAndFix(
        testing.allocator,
        source,
        .{ .workflow = &checkUnknownEvents },
        false,
    );
    defer outcome.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), outcome.diagnostic_count);
    try testing.expectEqual(@as(usize, 0), outcome.edits_applied);
    try testing.expectEqualStrings(source, outcome.content);
}

test "SYN009: a typo of a non-privileged trigger is a safe rename" {
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

    const outcome = try test_support.lintAndFix(
        testing.allocator,
        source,
        .{ .workflow = &checkUnknownEvents },
        false,
    );
    defer outcome.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), outcome.diagnostic_count);
    try testing.expectEqual(diagnostics_mod.FixSafety.safe, outcome.first_safety.?);
    try testing.expectEqual(@as(usize, 1), outcome.edits_applied);
    try testing.expect(std.mem.indexOf(u8, outcome.content, "pull_request:") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.content, "pull_reqeust:") == null);
}

test "SYN009: a typo of pull_request_target is unsafe and --fix leaves it" {
    const source =
        \\on:
        \\  pull_request_targt:
        \\    types: [opened]
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const safe = try test_support.lintAndFix(
        testing.allocator,
        source,
        .{ .workflow = &checkUnknownEvents },
        false,
    );
    defer safe.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), safe.diagnostic_count);
    try testing.expectEqual(@as(usize, 0), safe.fix_count);
    try testing.expectEqualStrings(source, safe.content);

    const unsafe = try test_support.lintAndFix(
        testing.allocator,
        source,
        .{ .workflow = &checkUnknownEvents },
        true,
    );
    defer unsafe.deinit(testing.allocator);
    try testing.expectEqual(diagnostics_mod.FixSafety.unsafe, unsafe.first_safety.?);
    try testing.expectEqual(@as(usize, 1), unsafe.edits_applied);
    try testing.expect(std.mem.indexOf(u8, unsafe.content, "pull_request_target:") != null);
    try testing.expect(std.mem.indexOf(u8, unsafe.content, "pull_request_targt:") == null);
}

test "SYN009: a typo of workflow_run is unsafe" {
    const source =
        \\on:
        \\  workflow_rn:
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const safe = try test_support.lintAndFix(
        testing.allocator,
        source,
        .{ .workflow = &checkUnknownEvents },
        false,
    );
    defer safe.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), safe.fix_count);
    try testing.expectEqualStrings(source, safe.content);

    const unsafe = try test_support.lintAndFix(
        testing.allocator,
        source,
        .{ .workflow = &checkUnknownEvents },
        true,
    );
    defer unsafe.deinit(testing.allocator);
    try testing.expectEqual(diagnostics_mod.FixSafety.unsafe, unsafe.first_safety.?);
    try testing.expectEqual(@as(usize, 1), unsafe.edits_applied);
    try testing.expect(std.mem.indexOf(u8, unsafe.content, "workflow_run:") != null);
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

fn runSyn018(source: []const u8) !DiagnosticList {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);
    var list = DiagnosticList.init(testing.allocator);
    for (wf.jobs) |*job| checkDuplicateMatrixValues(job, &list);
    return list;
}

test "SYN018: duplicate scalar values in matrix axes are reported" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest, ubuntu-latest, macos-latest]
        \\        node: [18, 20, 18]
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn018(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 2), diags.len());
    const first = diags.get(0);
    try testing.expectEqualStrings("SYN018", first.rule_id);
    try testing.expect(first.severity == .warning);
    try testing.expect(std.mem.indexOf(u8, first.message, "\"ubuntu-latest\"") != null);
    try testing.expect(std.mem.indexOf(u8, first.message, "matrix \"os\"") != null);
    try testing.expectEqual(@as(u32, 6), first.span.start_line);
    try testing.expectEqual(@as(u32, 7), diags.get(1).span.start_line);
}

test "SYN018: autofix drops the duplicated value from a flow axis" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest, ubuntu-latest, macos-latest]
        \\    steps:
        \\      - run: echo hi
        \\
    ;
    const result = try test_support.lintAndFix(testing.allocator, source, .{ .job = &checkDuplicateMatrixValues }, false);
    defer testing.allocator.free(result.content);

    try testing.expectEqual(@as(usize, 1), result.fix_count);
    try testing.expect(result.first_safety.? == .safe);
    try testing.expectEqualStrings(
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest, macos-latest]
        \\    steps:
        \\      - run: echo hi
        \\
    , result.content);
}

test "SYN018: autofix drops the duplicated value line from a block axis" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        node:
        \\          - 18
        \\          - 20
        \\          - 18
        \\    steps:
        \\      - run: echo hi
        \\
    ;
    const result = try test_support.lintAndFix(testing.allocator, source, .{ .job = &checkDuplicateMatrixValues }, false);
    defer testing.allocator.free(result.content);

    try testing.expectEqualStrings(
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        node:
        \\          - 18
        \\          - 20
        \\    steps:
        \\      - run: echo hi
        \\
    , result.content);
}

test "SYN018: autofix drops every repeat, so one run leaves a single value" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest, ubuntu-latest, ubuntu-latest]
        \\    steps:
        \\      - run: echo hi
        \\
    ;
    const result = try test_support.lintAndFix(testing.allocator, source, .{ .job = &checkDuplicateMatrixValues }, false);
    defer testing.allocator.free(result.content);

    try testing.expectEqual(@as(usize, 2), result.diagnostic_count);
    try testing.expectEqual(@as(usize, 1), result.fix_count);
    try testing.expectEqualStrings(
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\    steps:
        \\      - run: echo hi
        \\
    , result.content);
}

test "SYN018: a matrix from an expression has no value ranges, so no fix" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        os: ${{ fromJSON(inputs.os) }}
        \\    steps:
        \\      - run: echo hi
        \\
    ;
    const result = try test_support.lintAndFix(testing.allocator, source, .{ .job = &checkDuplicateMatrixValues }, true);
    defer testing.allocator.free(result.content);

    try testing.expectEqual(@as(usize, 0), result.fix_count);
}

test "SYN018: distinct values produce no diagnostic" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest, macos-latest]
        \\        node: [18, 20]
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn018(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN018: a value repeated three times reports once per extra occurrence" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        node: [18, 18, 18]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn018(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 2), diags.len());
}

test "SYN018: quoting style does not hide a duplicate" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest, 'ubuntu-latest']
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn018(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
}

test "SYN018: duplicate include entries are reported as entries" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\        include:
        \\          - os: ubuntu-latest
        \\            node: 18
        \\          - node: 18
        \\            os: ubuntu-latest
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn018(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "duplicate entry") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "matrix \"include\"") != null);
}

test "SYN018: include entries differing in one value are clean" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        include:
        \\          - os: ubuntu-latest
        \\            node: 18
        \\          - os: ubuntu-latest
        \\            node: 20
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn018(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN018: a matrix built from an expression is skipped" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix: ${{ fromJSON(needs.setup.outputs.matrix) }}
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn018(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN018: a job without a strategy is clean" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn018(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

fn runSyn019(source: []const u8) !DiagnosticList {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);
    var list = DiagnosticList.init(testing.allocator);
    for (wf.jobs) |*job| checkMatrixIncludeExclude(job, &list);
    return list;
}

test "SYN019: exclude naming a missing value and an unknown key is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest, macos-latest]
        \\        node: [18, 20]
        \\        exclude:
        \\          - os: windows-latest
        \\            node: 18
        \\          - oss: ubuntu-latest
        \\            node: 20
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn019(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expectEqualStrings("SYN019", diags.get(0).rule_id);
    try testing.expectEqualStrings(
        "\"windows-latest\" does not exist in \"os\" axis",
        diags.get(0).message,
    );
    try testing.expectEqualStrings(
        "unknown key \"oss\" in \"exclude\". did you mean \"os\"?",
        diags.get(1).message,
    );
}

test "SYN019: a valid exclude and an include adding a new key are clean" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest, macos-latest]
        \\        node: [18, 20]
        \\        exclude:
        \\          - os: macos-latest
        \\            node: 18
        \\        include:
        \\          - os: ubuntu-latest
        \\            node: 20
        \\            experimental: true
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn019(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN019: an include key one edit from an axis is reported as a typo" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest, macos-latest]
        \\        node: [18, 20]
        \\        include:
        \\          - os: ubuntu-latest
        \\            nodes: 22
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn019(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings(
        "unknown key \"nodes\" in \"include\". did you mean \"node\"?",
        diags.get(0).message,
    );
}

test "SYN019: a value only include contributes is still an empty exclude" {
    // GitHub applies `exclude` to the base matrix and merges `include`
    // afterwards, so neither entry here removes the windows combination.
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\        include:
        \\          - os: windows-latest
        \\            experimental: true
        \\        exclude:
        \\          - os: windows-latest
        \\          - experimental: true
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn019(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expectEqualStrings(
        "\"windows-latest\" does not exist in \"os\" axis",
        diags.get(0).message,
    );
    try testing.expectEqualStrings(
        "unknown key \"experimental\" in \"exclude\"",
        diags.get(1).message,
    );
}

test "SYN019: an include key paired with the axis it resembles is not a typo" {
    // `mode` shares the first entry with `node`, which settles it as a real key
    // for the whole block — the second entry must not be reported either.
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        node: [18, 20]
        \\        include:
        \\          - node: 18
        \\            mode: fast
        \\          - node: 20
        \\            mode: slow
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn019(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN019: quoted numeric strings are compared as text" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        python-version: ["3.10", "3.11"]
        \\        exclude:
        \\          - python-version: "3.1"
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn019(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings(
        "\"3.1\" does not exist in \"python-version\" axis",
        diags.get(0).message,
    );
}

test "SYN019: YAML-equivalent numbers and booleans are not missing values" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        version: [1.0, 1.10]
        \\        debug: [true, false]
        \\        exclude:
        \\          - version: 1.1
        \\            debug: True
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn019(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN019: an axis built from an expression suppresses the value check" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        os: ${{ fromJSON(needs.setup.outputs.os) }}
        \\        exclude:
        \\          - os: windows-latest
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn019(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN019: an expression among the axis values suppresses the value check" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest, "${{ env.EXTRA_OS }}"]
        \\        exclude:
        \\          - os: windows-latest
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn019(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN019: an unrelated include key stays unreported" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest, macos-latest]
        \\        include:
        \\          - os: ubuntu-latest
        \\            coverage: true
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn019(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN019: a job without a matrix is clean" {
    const source =
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn019(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

fn runSyn020(source: []const u8) !struct { empty: bool, list: DiagnosticList } {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var parser = yaml_parser.Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    var list = DiagnosticList.init(testing.allocator);
    return .{ .empty = lintEmptyWorkflow(root, &list), .list = list };
}

test "SYN020: a comments-only file is reported instead of failing to parse" {
    var result = try runSyn020(
        \\# a workflow that was emptied out but never deleted
        \\# nothing else is left
        \\
    );
    defer result.list.deinit();

    try testing.expect(result.empty);
    try testing.expectEqual(@as(usize, 1), result.list.len());
    const diag = result.list.items.items[0];
    try testing.expectEqualStrings("SYN020", diag.rule_id);
    try testing.expectEqual(@as(u32, 1), diag.span.start_line);
}

test "SYN020: a file with only whitespace is empty" {
    var result = try runSyn020("   \n\n");
    defer result.list.deinit();

    try testing.expect(result.empty);
    try testing.expectEqual(@as(usize, 1), result.list.len());
}

test "SYN020: an empty flow mapping is empty" {
    var result = try runSyn020("{}\n");
    defer result.list.deinit();

    try testing.expect(result.empty);
    try testing.expectEqual(@as(usize, 1), result.list.len());
}

test "SYN020: a workflow with content is left to the workflow parser" {
    var result = try runSyn020(
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    );
    defer result.list.deinit();

    try testing.expect(!result.empty);
    try testing.expectEqual(@as(usize, 0), result.list.len());
}

test "SYN020: a document whose only key is a comment-out is not empty" {
    var result = try runSyn020(
        \\# on: push
        \\name: leftover
    );
    defer result.list.deinit();

    try testing.expect(!result.empty);
    try testing.expectEqual(@as(usize, 0), result.list.len());
}
