const std = @import("std");
const engine = @import("engine.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_types = @import("../yaml/types.zig");
const diagnostics_mod = @import("../diagnostics.zig");
const spans = @import("spans.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const DiagnosticList = engine.DiagnosticList;
const Severity = engine.Severity;
const Diagnostic = diagnostics_mod.Diagnostic;
const Fix = diagnostics_mod.Fix;
const Edit = diagnostics_mod.Edit;
const Span = yaml_types.Span;

const LabelStatus = enum {
    current,
    deprecated,
    retired,

    /// A retired label makes the run fail outright; a deprecated one still works.
    fn severity(self: LabelStatus) Severity {
        return switch (self) {
            .retired => .@"error",
            .deprecated => .warning,
            .current => unreachable,
        };
    }

    fn message(self: LabelStatus) []const u8 {
        return switch (self) {
            .retired => "runs-on label is retired and the workflow will fail to start",
            .deprecated => "runs-on label is deprecated and scheduled for retirement",
            .current => unreachable,
        };
    }
};

/// Every `runs-on` label zghalint recognises, in one pile: RUNNER001 reports
/// the retired/deprecated ones, RUNNER002 treats membership here (plus the
/// user's own `runner.labels`) as the definition of "known".
const KnownLabel = struct {
    label: []const u8,
    kind: LabelKind = .hosted,
    status: LabelStatus = .current,
    replacement: []const u8 = "",
};

const LabelKind = enum {
    /// A GitHub-hosted runner image. Larger runners extend these with their own
    /// suffix (`ubuntu-latest-4-cores`), and a typo near one is worth naming.
    hosted,
    /// A label GitHub attaches to self-hosted runners. Suffix matching would
    /// let `macos` swallow `macos-99`, and suggesting one would rewrite a
    /// working `runs-on: mac` into a runner that does not exist — so these are
    /// recognised by exact match only.
    convention,
};

const known_labels = [_]KnownLabel{
    .{ .label = "ubuntu-latest" },
    .{ .label = "ubuntu-24.04" },
    .{ .label = "ubuntu-22.04" },
    .{ .label = "ubuntu-26.04" },
    .{ .label = "ubuntu-24.04-arm" },
    .{ .label = "ubuntu-22.04-arm" },
    // 1 vCPU Linux image. It does not extend any other label, so the prefix
    // match cannot cover it and it needs its own entry.
    .{ .label = "ubuntu-slim" },
    .{ .label = "windows-latest" },
    .{ .label = "windows-2025" },
    .{ .label = "windows-2022" },
    .{ .label = "windows-11-arm" },
    .{ .label = "macos-latest" },
    .{ .label = "macos-26" },
    .{ .label = "macos-15" },
    .{ .label = "macos-14" },
    .{ .label = "macos-13" },
    .{ .label = "self-hosted", .kind = .convention },
    .{ .label = "linux", .kind = .convention },
    .{ .label = "windows", .kind = .convention },
    .{ .label = "macos", .kind = .convention },
    .{ .label = "x64", .kind = .convention },
    .{ .label = "x86", .kind = .convention },
    .{ .label = "arm", .kind = .convention },
    .{ .label = "arm64", .kind = .convention },
    .{ .label = "ubuntu-18.04", .status = .retired, .replacement = "ubuntu-22.04" },
    .{ .label = "ubuntu-20.04", .status = .retired, .replacement = "ubuntu-22.04" },
    .{ .label = "macos-11", .status = .retired, .replacement = "macos-13" },
    .{ .label = "macos-12", .status = .retired, .replacement = "macos-13" },
    .{ .label = "windows-2019", .status = .deprecated, .replacement = "windows-2022" },
};

comptime {
    for (known_labels) |entry| {
        if (entry.status != .current and entry.replacement.len == 0) {
            @compileError("deprecated/retired label needs a replacement: " ++ entry.label);
        }
    }
}

pub const LabelRef = struct {
    value: []const u8,
    value_span: ?Span,
};

/// Walks a job's `runs-on` labels. The parser fills `runs_on_labels` for the
/// scalar and the sequence form alike, so the rules never have to know which
/// one the user wrote; the `runs_on` scalar is the fallback for hand-built
/// `Job` values that only set it.
pub const LabelIterator = struct {
    job: *const Job,
    index: usize = 0,

    pub fn next(self: *LabelIterator) ?LabelRef {
        if (self.job.runs_on_labels.len > 0) {
            if (self.index >= self.job.runs_on_labels.len) return null;
            const i = self.index;
            self.index += 1;
            return .{
                .value = self.job.runs_on_labels[i],
                .value_span = if (i < self.job.runs_on_label_spans.len)
                    self.job.runs_on_label_spans[i]
                else
                    null,
            };
        }

        if (self.index > 0) return null;
        self.index = 1;
        return .{
            .value = self.job.runs_on orelse return null,
            .value_span = self.job.runs_on_value_span,
        };
    }
};

pub fn runsOnLabels(job: *const Job) LabelIterator {
    return .{ .job = job };
}

fn checkDeprecatedRunner(job: *const Job, diag_list: *DiagnosticList) void {
    var labels = runsOnLabels(job);
    while (labels.next()) |label| {
        for (known_labels) |entry| {
            if (entry.status == .current) continue;
            if (!std.mem.eql(u8, label.value, entry.label)) continue;

            const span = label.value_span orelse job.span;
            const fix: ?Fix = if (label.value_span) |vs| blk: {
                const edits = diag_list.allocEdit(.{
                    .start_byte = vs.start_byte,
                    .end_byte = vs.end_byte,
                    .replacement = entry.replacement,
                }) orelse break :blk null;
                break :blk Fix{
                    .description = "Replace with supported runner label",
                    .safety = .unsafe,
                    .edits = edits,
                };
            } else null;

            diag_list.append(.{
                .rule_id = "RUNNER001",
                .severity = entry.status.severity(),
                .message = entry.status.message(),
                .span = span,
                .fix_hint = entry.replacement,
                .fix = fix,
            }) catch return;
            break;
        }
    }
}

/// Extra `runs-on` labels the user declared in `.zghalint.yml`
/// (`runner.labels`). Rules get no config handle of their own, so `main`
/// installs the list here once at startup, the same way PERF001 receives the
/// workspace probe.
var allowed_labels: []const []const u8 = &.{};

pub fn setAllowedLabels(labels: []const []const u8) void {
    allowed_labels = labels;
}

/// Runner labels are matched case-insensitively by GitHub.
fn eqlLabel(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn hasLabelPrefix(label: []const u8, base: []const u8) bool {
    if (label.len <= base.len + 1) return false;
    if (label[base.len] != '-') return false;
    return eqlLabel(label[0..base.len], base);
}

/// Larger runners and self-hosted fleets extend a known base label with their
/// own suffix, so a prefix match counts as known — guessing at those names
/// would only produce false positives.
fn isKnownLabel(label: []const u8) bool {
    for (known_labels) |entry| {
        if (eqlLabel(label, entry.label)) return true;
        if (entry.kind == .hosted and hasLabelPrefix(label, entry.label)) return true;
    }
    for (allowed_labels) |extra| {
        if (eqlLabel(label, extra)) return true;
    }
    return false;
}

/// Longest label worth comparing; anything longer is a custom name, not a typo.
const max_label_len = 63;
const max_edit_distance = 2;

fn editDistance(a: []const u8, b: []const u8) usize {
    if (a.len > max_label_len or b.len > max_label_len) return max_edit_distance + 1;

    var prev: [max_label_len + 1]usize = undefined;
    var curr: [max_label_len + 1]usize = undefined;
    for (0..b.len + 1) |j| prev[j] = j;

    for (a, 0..) |ca, i| {
        curr[0] = i + 1;
        for (b, 0..) |cb, j| {
            const cost: usize = if (std.ascii.toLower(ca) == std.ascii.toLower(cb)) 0 else 1;
            curr[j + 1] = @min(@min(curr[j] + 1, prev[j + 1] + 1), prev[j] + cost);
        }
        @memcpy(prev[0 .. b.len + 1], curr[0 .. b.len + 1]);
    }
    return prev[b.len];
}

/// Nearest currently-offered label, but only when the guess is unmistakable:
/// `macos-99` sits two edits from macos-13, macos-14 and macos-15 alike, and a
/// tie is no basis for rewriting somebody's workflow.
fn nearestKnownLabel(label: []const u8) ?[]const u8 {
    var best: ?[]const u8 = null;
    var best_distance: usize = max_edit_distance + 1;
    var tied = false;

    for (known_labels) |entry| {
        if (entry.status != .current or entry.kind != .hosted) continue;
        const d = editDistance(label, entry.label);
        if (d < best_distance) {
            best_distance = d;
            best = entry.label;
            tied = false;
        } else if (d == best_distance) {
            tied = true;
        }
    }

    if (best_distance > max_edit_distance or tied) return null;
    return best;
}

const os_prefixes = [_][]const u8{ "ubuntu", "windows", "macos" };

/// An unknown label is only worth reporting when it claims to be a
/// GitHub-hosted one. Bare names (`gpu`, `build-box`) belong to somebody's
/// self-hosted fleet, which zghalint cannot enumerate.
fn looksLikeHostedLabel(label: []const u8) bool {
    for (os_prefixes) |prefix| {
        if (hasLabelPrefix(label, prefix)) return true;
    }
    return false;
}

/// `self-hosted` marks every other label in the set as a name the fleet's
/// operator chose: `windows-gpu` is then a machine of theirs, not a misspelt
/// GitHub image. zghalint cannot enumerate those, so it says nothing.
fn hasSelfHostedLabel(job: *const Job) bool {
    var labels = runsOnLabels(job);
    while (labels.next()) |label| {
        if (eqlLabel(label.value, "self-hosted")) return true;
    }
    return false;
}

const UnknownLabel = struct {
    suggestion: ?[]const u8,
};

/// Null when the label is fine to leave alone: a known one, or an unknown one
/// shaped like somebody's self-hosted fleet name, which zghalint cannot
/// enumerate.
fn classifyLabel(label: []const u8) ?UnknownLabel {
    if (label.len == 0) return null;
    if (isKnownLabel(label)) return null;

    const suggestion = nearestKnownLabel(label);
    if (suggestion == null and !looksLikeHostedLabel(label)) return null;
    return .{ .suggestion = suggestion };
}

fn reportUnknownLabel(
    unknown: UnknownLabel,
    span: Span,
    edits: ?[]const Edit,
    diag_list: *DiagnosticList,
) void {
    const hint: ?[]const u8 = if (unknown.suggestion) |name|
        std.fmt.allocPrint(diag_list.fixAllocator(), "did you mean \"{s}\"?", .{name}) catch null
    else
        null;
    const fix: ?Fix = if (edits) |e| Fix{
        .description = "Replace with the nearest known runner label",
        .safety = .unsafe,
        .edits = e,
    } else null;

    diag_list.append(.{
        .rule_id = "RUNNER002",
        .severity = .@"error",
        .message = "unknown runs-on label; no runner will ever pick this job up",
        .span = span,
        .fix_hint = hint,
        .fix = fix,
    }) catch return;
}

/// Axis name behind a `runs-on` that is exactly one `${{ matrix.<key> }}`.
/// Anything else — `fromJSON(...)`, another context, an expression pasted into
/// surrounding text — names labels zghalint cannot recover statically.
fn matrixAxisKey(runs_on: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, runs_on, " \t");
    if (trimmed.len < "${{}}".len) return null;
    if (!std.mem.startsWith(u8, trimmed, "${{")) return null;
    if (!std.mem.endsWith(u8, trimmed, "}}")) return null;

    const inner = std.mem.trim(u8, trimmed[3 .. trimmed.len - 2], " \t");
    // A second `}}` means two expressions were concatenated, not one reference.
    if (std.mem.indexOf(u8, inner, "}}") != null) return null;

    const prefix = "matrix.";
    if (inner.len <= prefix.len) return null;
    if (!std.ascii.eqlIgnoreCase(inner[0..prefix.len], prefix)) return null;

    const key = inner[prefix.len..];
    for (key) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-') return null;
    }
    return key;
}

/// The labels behind `runs-on: ${{ matrix.os }}` are still written out in
/// `strategy.matrix`, so a typo among them is detectable. The diagnostic goes
/// on the matrix value: the `runs-on:` line holds nothing to correct.
fn checkMatrixRunner(job: *const Job, key: []const u8, diag_list: *DiagnosticList) void {
    const matrix = (job.strategy orelse return).matrix orelse return;

    for (matrix.axes) |axis| {
        // `exclude` entries drop combinations, so a label there runs nowhere.
        if (std.ascii.eqlIgnoreCase(axis.name, "exclude")) continue;

        if (std.ascii.eqlIgnoreCase(axis.name, key)) {
            for (axis.values) |value| checkMatrixValue(matrix, key, value, diag_list);
        } else if (std.ascii.eqlIgnoreCase(axis.name, "include")) {
            for (axis.values) |entry| {
                const mapping = switch (entry) {
                    .mapping => |m| m,
                    else => continue,
                };
                for (mapping.entries) |item| {
                    if (std.ascii.eqlIgnoreCase(item.key.value, key)) {
                        checkMatrixValue(matrix, key, item.value, diag_list);
                    }
                }
            }
        }
    }
}

fn checkMatrixValue(
    matrix: workflow_types.Matrix,
    key: []const u8,
    value: yaml_types.Node,
    diag_list: *DiagnosticList,
) void {
    const scalar = switch (value) {
        .scalar => |s| s,
        else => return,
    };
    // A matrix value can itself be an expression, which lands back at unexpandable.
    if (std.mem.indexOf(u8, scalar.value, "${{") != null) return;

    const unknown = classifyLabel(scalar.value) orelse return;
    const edits: ?[]const Edit = if (unknown.suggestion) |name|
        matrixLabelEdits(matrix, key, scalar, name, diag_list)
    else
        null;
    reportUnknownLabel(unknown, scalarSpan(scalar), edits, diag_list);
}

/// The scalar's token span covers the surrounding quotes; diagnostics and
/// edits address the value itself.
fn scalarSpan(scalar: yaml_types.Scalar) Span {
    return spans.Anchor
        .fromMeta(.{ .value_span = scalar.span, .style = scalar.style }, scalar.span)
        .at(scalar.value, 0, scalar.value.len);
}

/// Null for block scalars, whose byte range covers the `|` indicator line as
/// well, so a byte-level swap cannot rewrite them.
fn labelEdit(scalar: yaml_types.Scalar, replacement: []const u8) ?Edit {
    switch (scalar.style) {
        .literal, .folded => return null,
        else => {},
    }
    const span = scalarSpan(scalar);
    return .{ .start_byte = span.start_byte, .end_byte = span.end_byte, .replacement = replacement };
}

/// The axis value and every `exclude` entry naming it are rewritten together:
/// correcting the axis alone would leave an exclusion matching nothing, which
/// quietly revives the combination the author removed.
fn matrixLabelEdits(
    matrix: workflow_types.Matrix,
    key: []const u8,
    scalar: yaml_types.Scalar,
    replacement: []const u8,
    diag_list: *DiagnosticList,
) ?[]const Edit {
    const alloc = diag_list.fixAllocator();
    var edits = std.ArrayList(Edit){};
    edits.append(alloc, labelEdit(scalar, replacement) orelse return null) catch return null;

    for (matrix.axes) |axis| {
        if (!std.ascii.eqlIgnoreCase(axis.name, "exclude")) continue;
        for (axis.values) |entry| {
            const mapping = switch (entry) {
                .mapping => |m| m,
                else => continue,
            };
            for (mapping.entries) |item| {
                if (!std.ascii.eqlIgnoreCase(item.key.value, key)) continue;
                const excluded = switch (item.value) {
                    .scalar => |s| s,
                    else => continue,
                };
                if (!eqlLabel(excluded.value, scalar.value)) continue;
                const edit = labelEdit(excluded, replacement) orelse continue;
                edits.append(alloc, edit) catch return null;
            }
        }
    }
    return edits.toOwnedSlice(alloc) catch null;
}

fn checkUnknownRunner(job: *const Job, diag_list: *DiagnosticList) void {
    if (hasSelfHostedLabel(job)) return;

    var labels = runsOnLabels(job);
    while (labels.next()) |label| {
        checkUnknownLabel(job, label, diag_list);
    }
}

fn checkUnknownLabel(job: *const Job, label: LabelRef, diag_list: *DiagnosticList) void {
    if (label.value.len == 0) return;

    // `runs-on: ${{ matrix.os }}` names no label of its own; the values behind
    // the axis are where a typo is visible.
    if (std.mem.indexOf(u8, label.value, "${{") != null) {
        const key = matrixAxisKey(label.value) orelse return;
        return checkMatrixRunner(job, key, diag_list);
    }

    const unknown = classifyLabel(label.value) orelse return;
    const edits: ?[]const Edit = if (unknown.suggestion) |name| blk: {
        const value_span = label.value_span orelse break :blk null;
        break :blk diag_list.allocEdit(.{
            .start_byte = value_span.start_byte,
            .end_byte = value_span.end_byte,
            .replacement = name,
        });
    } else null;
    reportUnknownLabel(unknown, label.value_span orelse job.span, edits, diag_list);
}

const RunnerOs = enum {
    linux,
    windows,
    macos,
};

fn labelOs(label: []const u8) ?RunnerOs {
    // A fleet is free to call a Linux box `macos-m1`, so an unrecognised label
    // names no OS: guessing at one would invent conflicts that do not exist.
    if (!isKnownLabel(label)) return null;
    if (eqlLabel(label, "linux") or eqlLabel(label, "ubuntu") or hasLabelPrefix(label, "ubuntu")) return .linux;
    if (eqlLabel(label, "windows") or hasLabelPrefix(label, "windows")) return .windows;
    if (eqlLabel(label, "macos") or hasLabelPrefix(label, "macos")) return .macos;
    return null;
}

/// An expression only resolves at run time, so the OS it contributes is
/// unknown — and so is the whole set, whatever order the labels appear in.
fn hasExpressionLabel(job: *const Job) bool {
    var labels = runsOnLabels(job);
    while (labels.next()) |label| {
        if (std.mem.indexOf(u8, label.value, "${{") != null) return true;
    }
    return false;
}

/// A job runs on one runner carrying *every* label listed, so two labels that
/// name different operating systems can never both be satisfied: the job sits
/// queued until it times out.
fn checkRunnerConflict(job: *const Job, diag_list: *DiagnosticList) void {
    if (hasExpressionLabel(job)) return;

    var labels = runsOnLabels(job);
    var first: ?LabelRef = null;
    var first_os: RunnerOs = undefined;

    while (labels.next()) |label| {
        const os = labelOs(label.value) orelse continue;
        const previous = first orelse {
            first = label;
            first_os = os;
            continue;
        };
        if (os == first_os) continue;

        diag_list.append(.{
            .rule_id = "RUNNER003",
            .severity = .@"error",
            .message = std.fmt.allocPrint(
                diag_list.fixAllocator(),
                "runs-on labels \"{s}\" and \"{s}\" name different operating systems; no runner can carry both and the job stays queued",
                .{ previous.value, label.value },
            ) catch "runs-on labels name different operating systems; no runner can carry both and the job stays queued",
            .span = label.value_span orelse job.span,
            .fix_hint = "Keep the labels of a single operating system, or split the job per OS with a matrix",
        }) catch return;
        return;
    }
}

pub const rules = [_]Rule{
    .{
        .id = "RUNNER001",
        .name = "deprecated-runner",
        .description = "runs-on label is retired or scheduled for retirement by GitHub",
        .severity = .warning,
        .category = .runner,
        .check_job = &checkDeprecatedRunner,
    },
    .{
        .id = "RUNNER002",
        .name = "unknown-runner",
        .description = "runs-on label is not a known GitHub-hosted runner",
        .severity = .@"error",
        .category = .runner,
        .check_job = &checkUnknownRunner,
    },
    .{
        .id = "RUNNER003",
        .name = "runner-label-conflict",
        .description = "runs-on labels name different operating systems, so no runner matches",
        .severity = .@"error",
        .category = .runner,
        .check_job = &checkRunnerConflict,
    },
};

const testing = std.testing;
const test_support = @import("../test_support.zig");

const dummySpan = test_support.dummySpan;

test "RUNNER001: retired ubuntu-20.04 emits error with unsafe fix" {
    const job = Job{
        .id = "build",
        .runs_on = "ubuntu-20.04",
        .runs_on_value_span = dummySpan(100, 112),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkDeprecatedRunner(&job, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("RUNNER001", diag.rule_id);
    try testing.expect(diag.severity == .@"error");

    const fix = diag.fix orelse return error.TestUnexpectedResult;
    try testing.expect(fix.safety == .unsafe);
    try testing.expectEqual(@as(usize, 1), fix.edits.len);
    try testing.expectEqualStrings("ubuntu-22.04", fix.edits[0].replacement);
    try testing.expectEqual(@as(usize, 100), fix.edits[0].start_byte);
    try testing.expectEqual(@as(usize, 112), fix.edits[0].end_byte);
}

test "RUNNER001: deprecated windows-2019 emits warning" {
    const job = Job{
        .id = "build",
        .runs_on = "windows-2019",
        .runs_on_value_span = dummySpan(50, 62),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkDeprecatedRunner(&job, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(diag.severity == .warning);
    const fix = diag.fix orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("windows-2022", fix.edits[0].replacement);
}

test "RUNNER001: current runner produces no diagnostic" {
    const job = Job{
        .id = "build",
        .runs_on = "ubuntu-24.04",
        .runs_on_value_span = dummySpan(10, 22),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkDeprecatedRunner(&job, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RUNNER001: reusable workflow job without runs-on is ignored" {
    const job = Job{
        .id = "call",
        .runs_on = null,
        .uses = "./.github/workflows/reusable.yml",
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkDeprecatedRunner(&job, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RUNNER001: unknown label produces no diagnostic" {
    const job = Job{
        .id = "build",
        .runs_on = "self-hosted-custom",
        .runs_on_value_span = dummySpan(10, 28),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkDeprecatedRunner(&job, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RUNNER001: autofix end-to-end replaces label in YAML source" {
    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-20.04
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const result = try test_support.lintAndFix(testing.allocator, source, .{ .job = &checkDeprecatedRunner }, true);
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), result.diagnostic_count);
    try testing.expectEqual(@as(usize, 1), result.edits_applied);
    try testing.expect(std.mem.indexOf(u8, result.content, "ubuntu-22.04") != null);
    try testing.expect(std.mem.indexOf(u8, result.content, "ubuntu-20.04") == null);
}

test "RUNNER002: typo'd label is reported with an unsafe fix" {
    const job = Job{
        .id = "build",
        .runs_on = "ubunut-latest",
        .runs_on_value_span = dummySpan(40, 53),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkUnknownRunner(&job, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("RUNNER002", diag.rule_id);
    try testing.expect(diag.severity == .@"error");
    try testing.expectEqualStrings("did you mean \"ubuntu-latest\"?", diag.fix_hint.?);

    const fix = diag.fix orelse return error.TestUnexpectedResult;
    try testing.expect(fix.safety == .unsafe);
    try testing.expectEqualStrings("ubuntu-latest", fix.edits[0].replacement);
}

test "RUNNER002: unknown version of a hosted OS is reported without a guess" {
    const job = Job{
        .id = "build",
        .runs_on = "macos-99",
        .runs_on_value_span = dummySpan(10, 18),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkUnknownRunner(&job, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    // macos-13/14/15 are all two edits away, so no single label can be named.
    try testing.expect(diags.get(0).fix_hint == null);
    try testing.expect(diags.get(0).fix == null);
}

test "RUNNER002: known and larger-runner labels are accepted" {
    const labels = [_][]const u8{
        "ubuntu-latest",       "ubuntu-24.04-arm", "windows-2025",
        "macos-latest",        "self-hosted",      "ubuntu-latest-4-cores",
        "macos-latest-xlarge", "linux",            "UBUNTU-LATEST",
        "ubuntu-slim",         "ubuntu-26.04",     "macos-26-intel",
        "windows-2025-vs2026",
    };
    for (labels) |label| {
        const job = Job{ .id = "build", .runs_on = label, .runs_on_value_span = dummySpan(0, 10) };
        var diags = DiagnosticList.init(testing.allocator);
        defer diags.deinit();

        checkUnknownRunner(&job, &diags);

        testing.expectEqual(@as(usize, 0), diags.len()) catch |err| {
            std.debug.print("label '{s}' unexpectedly flagged\n", .{label});
            return err;
        };
    }
}

test "RUNNER002: bare self-hosted fleet labels are left alone" {
    // The short ones sit within two edits of a convention label (`mac` of
    // `macos`, `x64s` of `x64`): suggesting those would rewrite a working
    // self-hosted `runs-on` into a runner that does not exist.
    const labels = [_][]const u8{
        "gpu",       "build-box", "my-runner-2xlarge", "mac",
        "lin",       "arms",      "x64s",              "arm-64",
        "linux-gpu",
    };
    for (labels) |label| {
        const job = Job{ .id = "build", .runs_on = label, .runs_on_value_span = dummySpan(0, 10) };
        var diags = DiagnosticList.init(testing.allocator);
        defer diags.deinit();

        checkUnknownRunner(&job, &diags);

        testing.expectEqual(@as(usize, 0), diags.len()) catch |err| {
            std.debug.print("label '{s}' unexpectedly flagged\n", .{label});
            return err;
        };
    }
}

test "RUNNER002: deprecated labels are left to RUNNER001" {
    const job = Job{
        .id = "build",
        .runs_on = "ubuntu-20.04",
        .runs_on_value_span = dummySpan(0, 12),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkUnknownRunner(&job, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RUNNER002: a matrix expression without a matrix to expand is skipped" {
    const job = Job{
        .id = "build",
        .runs_on = "${{ matrix.os }}",
        .runs_on_value_span = dummySpan(0, 16),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkUnknownRunner(&job, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RUNNER002: configured runner.labels suppress the diagnostic" {
    const configured = [_][]const u8{"ubuntu-nvidia"};
    setAllowedLabels(&configured);
    defer setAllowedLabels(&.{});

    const job = Job{
        .id = "build",
        .runs_on = "ubuntu-nvidia",
        .runs_on_value_span = dummySpan(0, 13),
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    checkUnknownRunner(&job, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RUNNER002: autofix end-to-end replaces the typo in YAML source" {
    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubunut-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const result = try test_support.lintAndFix(testing.allocator, source, .{ .job = &checkUnknownRunner }, true);
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), result.diagnostic_count);
    try testing.expectEqual(@as(usize, 1), result.edits_applied);
    try testing.expect(std.mem.indexOf(u8, result.content, "runs-on: ubuntu-latest") != null);
}

fn runRunner002(source: []const u8) !DiagnosticList {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);
    var list = DiagnosticList.init(testing.allocator);
    for (wf.jobs) |*job| checkUnknownRunner(job, &list);
    return list;
}

test "RUNNER002: matrix values behind runs-on are expanded and checked" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    strategy:
        \\      matrix:
        \\        os: [ubunut-latest, ubuntu-latest, macos-99]
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runRunner002(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 2), diags.len());
    const first = diags.get(0);
    try testing.expectEqualStrings("RUNNER002", first.rule_id);
    try testing.expectEqualStrings("did you mean \"ubuntu-latest\"?", first.fix_hint.?);
    // The diagnostic points at the matrix value, not at the `runs-on:` line.
    try testing.expectEqual(@as(u32, 6), first.span.start_line);
    try testing.expectEqual(@as(u32, 14), first.span.start_col);
    try testing.expect(diags.get(1).fix_hint == null);
    try testing.expectEqual(@as(u32, 6), diags.get(1).span.start_line);
}

test "RUNNER002: include entries contribute labels too" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\        include:
        \\          - os: windwos-latest
        \\            node: 20
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runRunner002(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings("did you mean \"windows-latest\"?", diags.get(0).fix_hint.?);
    try testing.expectEqual(@as(u32, 8), diags.get(0).span.start_line);
}

test "RUNNER002: exclude entries and known matrix values are left alone" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest, "macos-latest", self-hosted]
        \\        node: [18, 20]
        \\        exclude:
        \\          - os: macos-99
        \\            node: 18
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runRunner002(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "RUNNER002: unexpandable runs-on expressions stay out of scope" {
    const sources = [_][]const u8{
        // Another context: nothing in the matrix to expand.
        \\on: push
        \\jobs:
        \\  build:
        \\    strategy:
        \\      matrix:
        \\        os: [ubunut-latest]
        \\    runs-on: ${{ inputs.os }}
        \\    steps:
        \\      - run: echo hi
        ,
        // Concatenation: the label is not the matrix value itself.
        \\on: push
        \\jobs:
        \\  build:
        \\    strategy:
        \\      matrix:
        \\        os: [ubunut-latest]
        \\    runs-on: ${{ matrix.os }}-4-cores
        \\    steps:
        \\      - run: echo hi
        ,
        // The axis holds an expression, not a label.
        \\on: push
        \\jobs:
        \\  build:
        \\    strategy:
        \\      matrix:
        \\        os: ${{ fromJSON(needs.setup.outputs.os) }}
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
        ,
        // A function call is not a plain property reference.
        \\on: push
        \\jobs:
        \\  build:
        \\    strategy:
        \\      matrix:
        \\        os: [ubunut-latest]
        \\    runs-on: ${{ format('{0}', matrix.os) }}
        \\    steps:
        \\      - run: echo hi
    };

    for (sources, 0..) |source, i| {
        var diags = try runRunner002(source);
        defer diags.deinit();

        testing.expectEqual(@as(usize, 0), diags.len()) catch |err| {
            std.debug.print("source {d} unexpectedly flagged\n", .{i});
            return err;
        };
    }
}

test "RUNNER002: matrix autofix rewrites the value, not the runs-on line" {
    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    strategy:
        \\      matrix:
        \\        os: ["ubunut-latest"]
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const result = try test_support.lintAndFix(testing.allocator, source, .{ .job = &checkUnknownRunner }, true);
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), result.diagnostic_count);
    try testing.expectEqual(@as(usize, 1), result.edits_applied);
    // The quotes around the value survive the replacement.
    try testing.expect(std.mem.indexOf(u8, result.content, "os: [\"ubuntu-latest\"]") != null);
    try testing.expect(std.mem.indexOf(u8, result.content, "runs-on: ${{ matrix.os }}") != null);
}

test "RUNNER002: the autofix rewrites the matching exclude entry too" {
    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest, windwos-latest]
        \\        node: [18, 20]
        \\        exclude:
        \\          - os: windwos-latest
        \\            node: 18
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const result = try test_support.lintAndFix(testing.allocator, source, .{ .job = &checkUnknownRunner }, true);
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), result.diagnostic_count);
    try testing.expectEqual(@as(usize, 2), result.edits_applied);
    // Leaving the exclusion behind would revive the combination it removed.
    try testing.expect(std.mem.indexOf(u8, result.content, "windwos") == null);
    try testing.expect(std.mem.indexOf(u8, result.content, "- os: windows-latest") != null);
}

/// Runs a job check over real workflow source, so a sequence `runs-on` reaches
/// the rule through the parser instead of a hand-built label list.
fn runJobCheckSource(
    arena: std.mem.Allocator,
    source: []const u8,
    check: *const fn (*const Job, *DiagnosticList) void,
    diags: *DiagnosticList,
) !void {
    const wf = try test_support.parseWorkflowSource(arena, source);
    for (wf.jobs) |*job| check(job, diags);
}

fn countForRunsOn(
    labels: []const u8,
    check: *const fn (*const Job, *DiagnosticList) void,
) !usize {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source = try std.fmt.allocPrint(
        arena.allocator(),
        "name: CI\non: push\njobs:\n  build:\n    runs-on: {s}\n    steps:\n      - run: echo hi\n",
        .{labels},
    );

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try runJobCheckSource(arena.allocator(), source, check, &diags);
    return diags.len();
}

test "RUNNER003: only label sets naming two operating systems conflict" {
    const cases = [_]struct { labels: []const u8, conflicts: usize }{
        .{ .labels = "[ubuntu-latest, windows-latest]", .conflicts = 1 },
        .{ .labels = "[self-hosted, linux, macos-14]", .conflicts = 1 },
        // One OS plus labels that name none.
        .{ .labels = "[self-hosted, linux, x64]", .conflicts = 0 },
        .{ .labels = "[ubuntu-latest, linux, ubuntu-22.04]", .conflicts = 0 },
        .{ .labels = "ubuntu-latest", .conflicts = 0 },
        // `macos-m1` is a name the fleet chose, not GitHub's macOS image.
        .{ .labels = "[self-hosted, linux, macos-m1]", .conflicts = 0 },
        // An expression puts the set out of scope wherever it sits.
        .{ .labels = "[windows-latest, \"${{ matrix.os }}\"]", .conflicts = 0 },
        .{ .labels = "[ubuntu-latest, windows-latest, \"${{ matrix.os }}\"]", .conflicts = 0 },
    };

    for (cases) |case| {
        const count = try countForRunsOn(case.labels, &checkRunnerConflict);
        testing.expectEqual(case.conflicts, count) catch |err| {
            std.debug.print("runs-on: {s}\n", .{case.labels});
            return err;
        };
    }
}

test "RUNNER003: the diagnostic names both conflicting labels" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: [ubuntu-latest, windows-latest]
        \\    steps:
        \\      - run: echo hi
        \\
    ;
    try runJobCheckSource(arena.allocator(), source, &checkRunnerConflict, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("RUNNER003", diag.rule_id);
    try testing.expect(diag.severity == .@"error");
    try testing.expect(std.mem.indexOf(u8, diag.message, "ubuntu-latest") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "windows-latest") != null);
    // The span points at the label that broke the set, not at the job.
    try testing.expectEqualStrings("windows-latest", source[diag.span.start_byte..diag.span.end_byte]);
}

test "RUNNER001: a retired label inside a sequence is reported" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: [ubuntu-20.04, x64]
        \\    steps:
        \\      - run: echo hi
        \\
    ;
    try runJobCheckSource(arena.allocator(), source, &checkDeprecatedRunner, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("RUNNER001", diag.rule_id);
    const fix = diag.fix orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("ubuntu-22.04", fix.edits[0].replacement);
}

test "RUNNER002: an unknown label inside a sequence is reported once" {
    try testing.expectEqual(
        @as(usize, 1),
        try countForRunsOn("[ubuntu-latest, ubunut-latest]", &checkUnknownRunner),
    );
}

test "RUNNER002: a self-hosted set's own labels are left alone" {
    // Every label beside `self-hosted` is the fleet operator's own name, even
    // when it wears an OS prefix.
    try testing.expectEqual(
        @as(usize, 0),
        try countForRunsOn("[self-hosted, windows-gpu, macos-m1]", &checkUnknownRunner),
    );
}

test "RUNNER002: a runner group's labels are checked" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on:
        \\      group: ubuntu-runners
        \\      labels: [ubunut-latest]
        \\    steps:
        \\      - run: echo hi
        \\
    ;
    try runJobCheckSource(arena.allocator(), source, &checkUnknownRunner, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings("RUNNER002", diags.get(0).rule_id);
}
