//! DEP005 / DEP006: validate `with:` against the metadata of widely used
//! actions, and expose their declared runtime to BP003.
//!
//! The metadata is embedded (`data/popular_actions.zig`) rather than fetched,
//! so these checks behave identically under `--quick` / `--offline` and cost
//! nothing at runtime. The table is generated from the actions' own
//! `action.yml` by `scripts/gen-popular-actions.py`; see docs/maintenance.md
//! for the refresh procedure.
//!
//! An action that is not in the table is not validated at all. That is the
//! whole false-positive story of this rule: the linter only ever speaks about
//! inputs it has actually read from the action.

const std = @import("std");
const engine = @import("engine.zig");
const spans = @import("spans.zig");
const with_inputs = @import("with_inputs.zig");
const workflow_types = @import("../workflow/types.zig");
const data = @import("data/popular_actions.zig");

const Rule = engine.Rule;
const Step = engine.Step;
const DiagnosticList = engine.DiagnosticList;
const ActionRef = workflow_types.ActionRef;

const ActionMeta = data.ActionMeta;
const Input = data.Input;

/// The metadata for `action`, or null when nothing can be said about it.
///
/// A reference is only matched when the ref names a major version, because
/// that is what the table is keyed by. A SHA pin therefore resolves to
/// nothing: mapping it back to a tag needs the network (SC005 does that), and
/// guessing would risk reporting inputs of a version the workflow does not
/// use.
pub fn lookup(action: ActionRef) ?ActionMeta {
    if (action.is_local or action.is_docker or action.is_pinned) return null;

    const owner = action.owner orelse return null;
    const repo = action.repo orelse return null;
    const major = majorFromRef(action.ref orelse return null) orelse return null;
    const path = action.path orelse "";

    for (data.popular_actions) |meta| {
        if (meta.major != major) continue;
        if (!std.ascii.eqlIgnoreCase(meta.owner, owner)) continue;
        if (!std.ascii.eqlIgnoreCase(meta.repo, repo)) continue;
        // Paths inside a repository are case-sensitive, unlike owner and repo.
        if (!std.mem.eql(u8, meta.path, path)) continue;
        return meta;
    }
    return null;
}

/// The major version a ref names (`v4`, `v4.2.2`), or null when the ref is a
/// branch, a SHA, or a tag that is not a plain version (`v4-beta`).
///
/// The accepted shape is `v` followed by dot-separated numbers, and nothing
/// else. Every action in the table publishes its versions that way, so a ref
/// that deviates — `V4`, `4`, `4.x-maintenance` — names something the table
/// cannot speak about, and reporting on it would be a guess.
pub fn majorFromRef(ref: []const u8) ?u16 {
    if (ref.len < 2 or ref[0] != 'v') return null;

    var major: ?u16 = null;
    var parts = std.mem.splitScalar(u8, ref[1..], '.');
    while (parts.next()) |part| {
        if (part.len == 0) return null;
        for (part) |c| {
            if (!std.ascii.isDigit(c)) return null;
        }
        if (major == null) major = std.fmt.parseInt(u16, part, 10) catch return null;
    }
    return major;
}

pub fn checkPopularActionInputs(step: *const Step, list: *DiagnosticList) void {
    const meta = lookup(step.uses orelse return) orelse return;
    with_inputs.check(Input, step, meta.inputs, meta.using, .{
        .rule_id = "DEP005",
        .noun = "action",
        .unknown_hint = "remove the input; the action ignores keys it does not declare",
    }, list);
}

pub fn checkDeprecatedInputs(step: *const Step, list: *DiagnosticList) void {
    const action = step.uses orelse return;
    const with = step.with orelse return;
    const meta = lookup(action) orelse return;
    const alloc = list.fixAllocator();

    for (with.keys()) |key| {
        const input = with_inputs.find(Input, meta.inputs, key) orelse continue;
        const deprecation = input.deprecation orelse continue;

        const message = std.fmt.allocPrint(
            alloc,
            "input \"{s}\" of action \"{s}\" is deprecated: {s}",
            // `deprecationMessage:` is often a block scalar, whose trailing
            // newline would break a one-line diagnostic.
            .{ key, action.raw, std.mem.trimRight(u8, deprecation, " \t\r\n") },
        ) catch return;

        list.append(.{
            .rule_id = "DEP006",
            .severity = .warning,
            .message = message,
            .span = with_inputs.keySpan(step, key),
            .fix_hint = "follow the action's deprecation notice, or drop the input",
        }) catch return;
    }
}

pub const rules = [_]Rule{
    .{
        .id = "DEP005",
        .name = "action-inputs",
        .description = "`with:` must match the `inputs:` declared by the referenced action",
        .severity = .@"error",
        .category = .dependency,
        .check_step = &checkPopularActionInputs,
    },
    .{
        .id = "DEP006",
        .name = "deprecated-action-input",
        .description = "the action declares the input as deprecated",
        .severity = .warning,
        .category = .dependency,
        .check_step = &checkDeprecatedInputs,
    },
};

const testing = std.testing;
const test_support = @import("../test_support.zig");

test "majorFromRef reads a major version only from a version tag" {
    try testing.expectEqual(@as(?u16, 4), majorFromRef("v4"));
    try testing.expectEqual(@as(?u16, 4), majorFromRef("v4.2.2"));
    // Only the `vN` spelling the actions actually publish is read as a version.
    try testing.expectEqual(@as(?u16, null), majorFromRef("4"));
    try testing.expectEqual(@as(?u16, null), majorFromRef("V4"));
    try testing.expectEqual(@as(?u16, null), majorFromRef("v4."));
    try testing.expectEqual(@as(?u16, null), majorFromRef("v4..2"));
    try testing.expectEqual(@as(?u16, null), majorFromRef("v"));
    try testing.expectEqual(@as(?u16, 12), majorFromRef("v12.0"));
    try testing.expectEqual(@as(?u16, null), majorFromRef("main"));
    try testing.expectEqual(@as(?u16, null), majorFromRef("v4-beta"));
    // Maintenance branches start with a major but do not name a version.
    try testing.expectEqual(@as(?u16, null), majorFromRef("4.x-maintenance"));
    try testing.expectEqual(@as(?u16, null), majorFromRef("v1.x"));
    try testing.expectEqual(@as(?u16, null), majorFromRef("2.0-beta"));
    try testing.expectEqual(@as(?u16, null), majorFromRef("releases/v1"));
    try testing.expectEqual(@as(?u16, null), majorFromRef(""));
}

test "lookup matches a major version and ignores everything else" {
    const checkout = lookup(ActionRef.parse("actions/checkout@v4")) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqualStrings("checkout", checkout.repo);
    try testing.expectEqual(@as(u16, 4), checkout.major);

    // Owner and repo are case-insensitive on GitHub.
    try testing.expect(lookup(ActionRef.parse("Actions/Checkout@v4.2.2")) != null);

    try testing.expect(lookup(ActionRef.parse("actions/checkout@main")) == null);
    try testing.expect(lookup(ActionRef.parse("actions/checkout@4.x-maintenance")) == null);
    try testing.expect(lookup(ActionRef.parse("actions/CACHE/Restore@v4")) == null);
    try testing.expect(lookup(ActionRef.parse("some-org/unknown-action@v1")) == null);
    try testing.expect(lookup(ActionRef.parse("./local")) == null);
    try testing.expect(lookup(ActionRef.parse("docker://alpine:3.19")) == null);
    try testing.expect(
        lookup(ActionRef.parse("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")) == null,
    );
}

test "lookup distinguishes an action in a sub-directory" {
    const restore = lookup(ActionRef.parse("actions/cache/restore@v4")) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqualStrings("restore", restore.path);

    const root = lookup(ActionRef.parse("actions/cache@v4")) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqualStrings("", root.path);
}

/// Runs both rules of this module over `source`. The arena owns the parsed
/// workflow and the diagnostics, so the caller only has to drop the arena.
fn lint(alloc: std.mem.Allocator, source: []const u8) !engine.DiagnosticList {
    const wf = try test_support.parseWorkflowSource(alloc, source);
    return engine.Engine.init(&rules).run(alloc, &wf);
}

test "DEP005: a misspelled input is reported with a suggestion" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var result = try lint(arena.allocator(),
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\        with:
        \\          fetch-dept: 0
        \\
    );

    try testing.expectEqual(@as(usize, 1), result.len());
    const d = result.get(0);
    try testing.expectEqualStrings("DEP005", d.rule_id);
    try testing.expect(std.mem.indexOf(u8, d.message, "fetch-dept") != null);
    try testing.expectEqualStrings("did you mean \"fetch-depth\"?", d.fix_hint.?);
}

test "DEP005: a missing required input is reported" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var result = try lint(arena.allocator(),
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/cache@v4
        \\        with:
        \\          path: ~/.cache
        \\
    );

    try testing.expectEqual(@as(usize, 1), result.len());
    try testing.expectEqualStrings("DEP005", result.get(0).rule_id);
    try testing.expect(std.mem.indexOf(u8, result.get(0).message, "\"key\"") != null);
}

test "DEP005: correct inputs and unknown actions are left alone" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var result = try lint(arena.allocator(),
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\        with:
        \\          fetch-depth: 0
        \\      - uses: some-org/unknown-action@v1
        \\        with:
        \\          anything: ok
        \\      - uses: actions/checkout@v4
        \\
    );

    try testing.expectEqual(@as(usize, 0), result.len());
}

test "DEP005: an input is matched without regard to case" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var result = try lint(arena.allocator(),
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\        with:
        \\          Fetch-Depth: 0
        \\
    );

    try testing.expectEqual(@as(usize, 0), result.len());
}

test "DEP006: a deprecated input reports the action's own message" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var result = try lint(arena.allocator(),
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/setup-node@v2
        \\        with:
        \\          version: '20'
        \\
    );

    try testing.expectEqual(@as(usize, 1), result.len());
    const d = result.get(0);
    try testing.expectEqualStrings("DEP006", d.rule_id);
    try testing.expect(std.mem.indexOf(u8, d.message, "node-version instead") != null);
    // The message is a single line even though the action wrote a block scalar.
    try testing.expect(std.mem.indexOf(u8, d.message, "\n") == null);
}

test "DEP006: a supported input is not reported" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var result = try lint(arena.allocator(),
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/setup-node@v4
        \\        with:
        \\          node-version: '20'
        \\
    );

    try testing.expectEqual(@as(usize, 0), result.len());
}

test "DEP005: a step with no `with:` at all reports every required input" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var result = try lint(arena.allocator(),
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/cache@v4
        \\
    );

    try testing.expectEqual(@as(usize, 2), result.len());
    try testing.expectEqualStrings("DEP005", result.get(0).rule_id);
    try testing.expect(std.mem.indexOf(u8, result.get(0).message, "\"path\"") != null);
    try testing.expect(std.mem.indexOf(u8, result.get(1).message, "\"key\"") != null);
}

test "every manifest entry is present in the generated table" {
    // The table is generated from this manifest, so a hand-edit or an
    // interrupted run that drops an entry has to fail here rather than
    // silently stop validating that action.
    const manifest = @embedFile("popular_actions_manifest");

    var lines = std.mem.splitScalar(u8, manifest, '\n');
    var seen: usize = 0;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        const meta = lookup(ActionRef.parse(line));
        if (meta == null) {
            std.debug.print("manifest entry {s} is missing from the generated table\n", .{line});
            return error.MissingActionMetadata;
        }
        seen += 1;
    }

    try testing.expectEqual(data.popular_actions.len, seen);
}

test "the generated table stays well-formed" {
    for (data.popular_actions) |meta| {
        try testing.expect(meta.owner.len > 0);
        try testing.expect(meta.repo.len > 0);
        try testing.expect(meta.using.len > 0);
        try testing.expect(meta.major > 0);
        for (meta.inputs) |input| try testing.expect(input.name.len > 0);
    }
}
