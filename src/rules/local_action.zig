//! Local action metadata: read `action.yml` next to a `uses: ./path`
//! reference and expose what it declares.
//!
//! The store is the only place that turns a local `uses:` into the referenced
//! action's own metadata, so it hosts DEP004 (input validation) and the
//! runtime table that BP003 consults for a deprecated `runs.using`. Both live
//! here rather than in `action_metadata.zig` because that module sits above
//! the step rules in the import graph (it drives composite step linting), and
//! a shared table there would close the cycle.
//!
//! Everything is read from disk, so the store stays useful under
//! `--quick` / `--offline`: those flags only disable network access.

const std = @import("std");
const runtime = @import("../runtime.zig");
const engine = @import("engine.zig");
const spans = @import("spans.zig");
const uses = @import("uses.zig");
const with_inputs = @import("with_inputs.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_parser = @import("../yaml/parser.zig");
const yaml_types = @import("../yaml/types.zig");

const Allocator = std.mem.Allocator;
const DiagnosticList = engine.DiagnosticList;
const Rule = engine.Rule;
const Step = engine.Step;
const Node = yaml_types.Node;

/// `runs.using` values GitHub has retired. Kept as data so a future runtime
/// retirement is a one-line change instead of a new branch.
pub const deprecated_runtimes = [_][]const u8{ "node12", "node16" };

/// What a deprecated runtime should migrate to.
pub const recommended_runtime = "node24";

pub fn isDeprecatedRuntime(using: []const u8) bool {
    for (deprecated_runtimes) |candidate| {
        if (std.mem.eql(u8, candidate, using)) return true;
    }
    return false;
}

/// One entry of the referenced action's `inputs:` mapping. A `required: true`
/// input that also carries a `default:` is satisfied without the caller
/// passing anything, so it is not recorded as required.
pub const Input = struct {
    name: []const u8,
    required: bool = false,
};

pub const Meta = struct {
    using: ?[]const u8 = null,
    inputs: []const Input = &.{},
};

pub const Resolution = union(enum) {
    /// No workspace root is configured, or the reference escapes it. Nothing
    /// is reported: the store cannot tell "absent" from "not looked at".
    unavailable,
    /// The directory exists in the reference but holds no action metadata.
    not_found,
    found: Meta,
};

/// Module state mirrors `stale_refs.zig`: one arena owns the root path, the
/// parsed metadata, and the cache keys, and `deinit` frees them together.
var local_action_arena: ?std.heap.ArenaAllocator = null;
var root_path: ?[]const u8 = null;
var cache: ?std.StringHashMap(Resolution) = null;

pub fn init(backing_allocator: Allocator, root: []const u8) void {
    local_action_arena = std.heap.ArenaAllocator.init(backing_allocator);
    const alloc = local_action_arena.?.allocator();
    root_path = alloc.dupe(u8, root) catch {
        local_action_arena.?.deinit();
        local_action_arena = null;
        return;
    };
    cache = std.StringHashMap(Resolution).init(alloc);
}

pub fn deinit() void {
    if (local_action_arena) |*arena| {
        arena.deinit();
        local_action_arena = null;
    }
    root_path = null;
    cache = null;
}

pub fn isActive() bool {
    return root_path != null;
}

/// `uses_path` is the raw `uses:` value of a local reference (`./x/y`).
/// Results are memoized because a workflow commonly calls the same local
/// action from several jobs.
pub fn resolve(uses_path: []const u8) Resolution {
    const root = root_path orelse return .unavailable;
    const alloc = if (local_action_arena) |*arena| arena.allocator() else return .unavailable;

    if (cache) |*c| {
        if (c.get(uses_path)) |hit| return hit;
    }

    const result = load(alloc, root, uses_path);

    if (cache) |*c| {
        const key = alloc.dupe(u8, uses_path) catch return result;
        c.put(key, result) catch {};
    }
    return result;
}

fn load(alloc: Allocator, root: []const u8, uses_path: []const u8) Resolution {
    const rel = relativeDir(uses_path) orelse return .unavailable;

    const dir = if (rel.len == 0)
        root
    else
        std.Io.Dir.path.join(alloc, &.{ root, rel }) catch return .unavailable;

    for ([_][]const u8{ "action.yml", "action.yaml" }) |name| {
        const path = std.Io.Dir.path.join(alloc, &.{ dir, name }) catch return .unavailable;
        // 1MiB is far above any real action manifest; a larger file is
        // treated as unreadable rather than parsed.
        const source = std.Io.Dir.cwd().readFileAlloc(runtime.io(), path, alloc, .limited(1024 * 1024)) catch continue;
        return .{ .found = parseMeta(alloc, source) orelse return .unavailable };
    }

    return .not_found;
}

/// The reference's directory relative to the repository root, or null when it
/// is not a root-relative path the store may follow. `..` is rejected so a
/// workflow cannot make the linter read outside the checkout.
fn relativeDir(uses_path: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, uses_path, "./")) return null;
    const rel = uses_path["./".len..];

    // Windows treats `\\` as a separator too, so splitting on `/` alone would
    // let `./..\\..\\etc` through the escape guard.
    var it = std.mem.splitAny(u8, rel, "/\\");
    while (it.next()) |segment| {
        if (std.mem.eql(u8, segment, "..")) return null;
    }
    return rel;
}

/// Null when the manifest does not parse: the caller turns that into
/// `.unavailable` so DEP004 stays silent instead of reading an empty `Meta`
/// and flagging every `with:` key. ACT00x already covers a malformed
/// `action.yml` at its own path.
fn parseMeta(alloc: Allocator, source: []const u8) ?Meta {
    var parser = yaml_parser.Parser.init(alloc, source);
    const root = parser.parse() catch return null;
    const map = switch (root) {
        .mapping => |m| m,
        else => return null,
    };

    var meta = Meta{};

    if (map.get("runs")) |runs| {
        if (runs == .mapping) {
            if (runs.mapping.get("using")) |using| {
                if (using == .scalar) meta.using = using.scalar.value;
            }
        }
    }

    if (map.get("inputs")) |inputs| {
        if (inputs == .mapping) {
            meta.inputs = parseInputs(alloc, inputs.mapping);
        }
    }

    return meta;
}

fn parseInputs(alloc: Allocator, m: yaml_types.Mapping) []const Input {
    const out = alloc.alloc(Input, m.entries.len) catch return &.{};
    for (m.entries, 0..) |entry, i| {
        var input = Input{ .name = entry.key.value };
        if (entry.value == .mapping) {
            const spec = entry.value.mapping;
            if (spec.get("required")) |req| {
                if (req == .scalar) input.required = isYamlTrue(req.scalar.value);
            }
            input.required = input.required and spec.get("default") == null;
        }
        out[i] = input;
    }
    return out;
}

fn isYamlTrue(value: []const u8) bool {
    return std.ascii.eqlIgnoreCase(value, "true");
}

fn report(
    list: *DiagnosticList,
    message: []const u8,
    span: spans.Span,
    hint: []const u8,
) void {
    list.append(.{
        .rule_id = "DEP004",
        .severity = .@"error",
        .message = message,
        .span = span,
        .fix_hint = hint,
    }) catch return;
}

pub fn checkLocalActionInputs(step: *const Step, list: *DiagnosticList) void {
    const action = step.uses orelse return;
    if (!action.is_local) return;
    // A malformed reference is DEP003's finding; resolving it would only add
    // a second diagnostic for the same defect.
    if (uses.actionProblem(action.raw) != null) return;

    switch (resolve(action.raw)) {
        .unavailable => {},
        .not_found => reportMissingManifest(step, action.raw, list),
        .found => |meta| checkWith(step, meta, list),
    }
}

/// DEP004 with the surrounding step list in hand: `steps[index]` is checked
/// unless an earlier `actions/checkout` creates its directory at run time
/// (#305). Both the job path and the composite-action path go through here.
pub fn checkStepAmongSteps(steps: []const Step, index: usize, list: *DiagnosticList) void {
    if (isCheckedOutAtRuntime(steps, index)) return;
    checkLocalActionInputs(&steps[index], list);
}

fn checkJobLocalActionInputs(job: *const engine.Job, list: *DiagnosticList) void {
    for (job.steps, 0..) |_, index| checkStepAmongSteps(job.steps, index, list);
}

/// True when `steps[index]` uses a local action under a directory that an
/// earlier `actions/checkout` in the same job populates through its `path:`
/// input — the pattern an action's own test workflow uses to check itself
/// out beside the workflow. Nothing lives at that path in the repository as
/// checked out here, so whatever DEP004 would read there is not the tree the
/// runner sees.
fn isCheckedOutAtRuntime(steps: []const Step, index: usize) bool {
    const action = steps[index].uses orelse return false;
    if (!action.is_local) return false;
    const rel = relativeDir(action.raw) orelse return false;

    for (steps[0..index]) |prior| {
        const prior_action = prior.uses orelse continue;
        if (!isCheckoutAction(prior_action)) continue;
        const with = prior.with orelse continue;
        const path = with.get("path") orelse continue;

        // Only the part before the first `${{` is knowable here; the rest
        // resolves on the runner, so everything under that prefix has to be
        // treated as possibly created.
        const expression = std.mem.find(u8, path, "${{");
        const dir = normalizeCheckoutPath(path[0..(expression orelse path.len)]);
        // A literal `path: .` checks the repository out over the workspace
        // root, which is the tree already on disk here: no new directory
        // appears, so the step is judged as usual.
        if (dir.len == 0 and expression == null) continue;
        if (dirContains(dir, rel)) return true;
    }
    return false;
}

fn isCheckoutAction(action: workflow_types.ActionRef) bool {
    if (action.is_local or action.is_docker) return false;
    const owner = action.owner orelse return false;
    const repo = action.repo orelse return false;
    // Action references resolve case-insensitively on GitHub.
    return std.ascii.eqlIgnoreCase(owner, "actions") and
        std.ascii.eqlIgnoreCase(repo, "checkout");
}

/// `path:` is relative to the workspace, so it is written the same way as a
/// local `uses:` minus the mandatory `./`. `.` and `./` name the workspace
/// root itself and normalize to the empty path.
fn normalizeCheckoutPath(path: []const u8) []const u8 {
    var out = std.mem.trim(u8, path, " \t");
    while (std.mem.startsWith(u8, out, "./")) out = out["./".len..];
    out = std.mem.trimEnd(u8, out, "/");
    if (std.mem.eql(u8, out, ".")) return "";
    return out;
}

/// True when `dir` is `path` or one of its ancestors. Both are
/// workspace-relative and compared case-sensitively, matching how a runner's
/// filesystem resolves them. An empty `dir` is the workspace root, which
/// contains every path.
fn dirContains(dir: []const u8, path: []const u8) bool {
    if (dir.len == 0) return true;
    if (!std.mem.startsWith(u8, path, dir)) return false;
    if (path.len == dir.len) return true;
    // Windows accepts both separators, same as `relativeDir`.
    return path[dir.len] == '/' or path[dir.len] == '\\';
}

fn reportMissingManifest(step: *const Step, raw: []const u8, list: *DiagnosticList) void {
    const alloc = list.fixAllocator();
    const message = std.fmt.allocPrint(
        alloc,
        "local action \"{s}\" has no action.yml or action.yaml",
        .{raw},
    ) catch return;
    const hint = std.fmt.allocPrint(
        alloc,
        "create \"{s}/action.yml\" or correct the path (it is relative to the repository root)",
        .{raw},
    ) catch return;

    report(list, message, spans.usesSpan(step), hint);
}

fn checkWith(step: *const Step, meta: Meta, list: *DiagnosticList) void {
    with_inputs.check(Input, step, meta.inputs, meta.using, .{
        .rule_id = "DEP004",
        .noun = "local action",
        .unknown_hint = "remove the input or declare it under `inputs:` in the action",
    }, list);
}

pub const rules = [_]Rule{
    .{
        .id = "DEP004",
        .name = "local-action-inputs",
        .description = "`with:` must match the `inputs:` declared by the referenced local action",
        .severity = .@"error",
        .category = .dependency,
        // Job-scoped rather than step-scoped: the sibling steps decide
        // whether the referenced directory exists at run time (#305).
        .check_job = &checkJobLocalActionInputs,
    },
};

const testing = std.testing;
const test_support = @import("../test_support.zig");

const ActionRef = workflow_types.ActionRef;
const hasDiagnostic = test_support.hasDiagnostic;

test "isDeprecatedRuntime recognises the retired Node runtimes" {
    try testing.expect(isDeprecatedRuntime("node12"));
    try testing.expect(isDeprecatedRuntime("node16"));
    try testing.expect(!isDeprecatedRuntime("node20"));
    try testing.expect(!isDeprecatedRuntime("composite"));
}

test "relativeDir strips ./ and rejects escapes" {
    try testing.expectEqualStrings(".github/actions/setup", relativeDir("./.github/actions/setup").?);
    try testing.expectEqualStrings("", relativeDir("./").?);
    try testing.expect(relativeDir("../shared") == null);
    try testing.expect(relativeDir("./a/../../etc") == null);
    try testing.expect(relativeDir("actions/checkout@v4") == null);
    try testing.expect(relativeDir("./..\\..\\etc") == null);
}

/// Runs DEP004 against a temporary repository root. Module state is saved and
/// restored so the test does not leak a root into its neighbours.
const Fixture = struct {
    tmp: testing.TmpDir,
    prev_arena: ?std.heap.ArenaAllocator,
    prev_root: ?[]const u8,
    prev_cache: ?std.StringHashMap(Resolution),

    fn init() !Fixture {
        var fx = Fixture{
            .tmp = testing.tmpDir(.{}),
            .prev_arena = local_action_arena,
            .prev_root = root_path,
            .prev_cache = cache,
        };
        local_action_arena = null;
        root_path = null;
        cache = null;

        const abs = try fx.tmp.dir.realPathFileAlloc(runtime.io(), ".", testing.allocator);
        defer testing.allocator.free(abs);
        local_action.init(testing.allocator, abs);
        return fx;
    }

    fn write(self: *Fixture, sub_path: []const u8, data: []const u8) !void {
        if (std.Io.Dir.path.dirname(sub_path)) |dir| try self.tmp.dir.createDirPath(runtime.io(), dir);
        try self.tmp.dir.writeFile(runtime.io(), .{ .sub_path = sub_path, .data = data });
    }

    fn deinit(self: *Fixture) void {
        local_action.deinit();
        local_action_arena = self.prev_arena;
        root_path = self.prev_root;
        cache = self.prev_cache;
        self.tmp.cleanup();
    }
};

const local_action = @This();

fn runStep(step: *const Step) DiagnosticList {
    var list = DiagnosticList.init(testing.allocator);
    checkLocalActionInputs(step, &list);
    return list;
}

test "DEP004: missing action.yml is reported" {
    var fx = try Fixture.init();
    defer fx.deinit();

    const step = Step{ .uses = ActionRef.parse("./.github/actions/missing") };
    var list = runStep(&step);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expectEqualStrings("DEP004", list.get(0).rule_id);
    try testing.expect(std.mem.find(u8, list.get(0).message, "no action.yml") != null);
}

test "DEP004: unknown input is reported with a suggestion" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.write(".github/actions/setup/action.yml",
        \\name: Setup
        \\description: d
        \\inputs:
        \\  version:
        \\    description: v
        \\runs:
        \\  using: node24
        \\  main: index.js
        \\
    );

    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "versoin", "1");

    const step = Step{ .uses = ActionRef.parse("./.github/actions/setup"), .with = with };
    var list = runStep(&step);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expect(std.mem.find(u8, list.get(0).message, "not declared") != null);
    try testing.expect(std.mem.find(u8, list.get(0).fix_hint.?, "version") != null);
}

test "DEP004: declared inputs are accepted" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.write(".github/actions/setup/action.yaml",
        \\name: Setup
        \\description: d
        \\inputs:
        \\  version:
        \\    description: v
        \\runs:
        \\  using: node24
        \\  main: index.js
        \\
    );

    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "version", "1");

    const step = Step{ .uses = ActionRef.parse("./.github/actions/setup"), .with = with };
    var list = runStep(&step);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.len());
}

test "DEP004: required input without a default must be passed" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.write(".github/actions/setup/action.yml",
        \\name: Setup
        \\description: d
        \\inputs:
        \\  token:
        \\    description: t
        \\    required: true
        \\  region:
        \\    description: r
        \\    required: true
        \\    default: us-east-1
        \\runs:
        \\  using: node24
        \\  main: index.js
        \\
    );

    const step = Step{ .uses = ActionRef.parse("./.github/actions/setup") };
    var list = runStep(&step);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expect(std.mem.find(u8, list.get(0).message, "token") != null);
}

test "DEP004: a manifest that is not a mapping reports nothing" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.write(".github/actions/bad/action.yml",
        \\- not
        \\- a mapping
        \\
    );

    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "version", "1");

    const step = Step{ .uses = ActionRef.parse("./.github/actions/bad"), .with = with };
    var list = runStep(&step);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.len());
}

test "DEP004: with keys match inputs case-insensitively" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.write(".github/actions/setup/action.yml",
        \\name: Setup
        \\description: d
        \\inputs:
        \\  version:
        \\    description: v
        \\    required: true
        \\runs:
        \\  using: node24
        \\  main: index.js
        \\
    );

    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "Version", "1");

    const step = Step{ .uses = ActionRef.parse("./.github/actions/setup"), .with = with };
    var list = runStep(&step);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.len());
}

test "DEP004: docker args and entrypoint are not inputs" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.write("tool/action.yml",
        \\name: Tool
        \\description: d
        \\runs:
        \\  using: docker
        \\  image: Dockerfile
        \\
    );

    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "args", "--help");
    try with.put(testing.allocator, "entrypoint", "/bin/sh");

    const step = Step{ .uses = ActionRef.parse("./tool"), .with = with };
    var list = runStep(&step);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.len());
}

test "DEP004: remote actions are not resolved" {
    var fx = try Fixture.init();
    defer fx.deinit();

    const step = Step{ .uses = ActionRef.parse("actions/checkout@v4") };
    var list = runStep(&step);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.len());
}

test "DEP004: a reference DEP003 already rejects is left alone" {
    var fx = try Fixture.init();
    defer fx.deinit();

    const step = Step{ .uses = ActionRef.parse("../shared/action") };
    var list = runStep(&step);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.len());
}

test "DEP004: without a workspace root nothing is reported" {
    const prev_root = root_path;
    root_path = null;
    defer root_path = prev_root;

    const step = Step{ .uses = ActionRef.parse("./.github/actions/setup") };
    var list = runStep(&step);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.len());
}

test "resolve exposes runs.using for BP003" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.write("legacy/action.yml",
        \\name: Legacy
        \\description: d
        \\runs:
        \\  using: node16
        \\  main: index.js
        \\
    );

    const resolution = resolve("./legacy");
    try testing.expect(resolution == .found);
    try testing.expectEqualStrings("node16", resolution.found.using.?);
    try testing.expect(isDeprecatedRuntime(resolution.found.using.?));
}

test "resolve memoizes repeated lookups" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.write("tool/action.yml",
        \\name: Tool
        \\description: d
        \\runs:
        \\  using: node24
        \\  main: index.js
        \\
    );

    try testing.expect(resolve("./tool") == .found);
    try testing.expectEqual(@as(usize, 1), cache.?.count());
    try testing.expect(resolve("./tool") == .found);
    try testing.expectEqual(@as(usize, 1), cache.?.count());
}

test "normalizeCheckoutPath reduces a path: value to a workspace-relative dir" {
    try testing.expectEqualStrings("action-under-test", normalizeCheckoutPath("action-under-test"));
    try testing.expectEqualStrings("action-under-test", normalizeCheckoutPath("./action-under-test/"));
    try testing.expectEqualStrings("a/b", normalizeCheckoutPath("  a/b  "));
    try testing.expectEqualStrings("", normalizeCheckoutPath("."));
    try testing.expectEqualStrings("", normalizeCheckoutPath("./"));
}

test "dirContains covers a directory and everything below it" {
    try testing.expect(dirContains("action", "action"));
    try testing.expect(dirContains("action", "action/nested"));
    try testing.expect(dirContains("action", "action\\nested"));
    try testing.expect(!dirContains("action", "action-under-test"));
    try testing.expect(!dirContains("action", "other"));
    // The empty dir is what an unresolvable `path: ${{ ... }}` reduces to.
    try testing.expect(dirContains("", "anything"));
}

/// The tests below cover #305: an action's own test workflow checks the
/// repository out into a sibling directory and then runs it, so that
/// directory only exists on the runner and DEP004 has nothing to read.
///
/// `with` is borrowed rather than owned so the caller can free it.
fn checkoutStep(path: []const u8, with: *workflow_types.StringMap) !Step {
    try with.put(testing.allocator, "path", path);
    return .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with.* };
}

fn runSteps(steps: []const Step) DiagnosticList {
    var list = DiagnosticList.init(testing.allocator);
    for (steps, 0..) |_, index| checkStepAmongSteps(steps, index, &list);
    return list;
}

test "DEP004: a directory an earlier checkout creates is not reported" {
    var fx = try Fixture.init();
    defer fx.deinit();

    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);

    const steps = [_]Step{
        try checkoutStep("action-under-test", &with),
        .{ .uses = ActionRef.parse("./action-under-test") },
        .{ .uses = ActionRef.parse("./action-under-test/nested") },
    };
    var list = runSteps(&steps);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.len());
}

test "DEP004: a directory no checkout creates is still reported" {
    var fx = try Fixture.init();
    defer fx.deinit();

    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);

    const steps = [_]Step{
        try checkoutStep("action-under-test", &with),
        .{ .uses = ActionRef.parse("./elsewhere") },
    };
    var list = runSteps(&steps);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expect(std.mem.find(u8, list.get(0).message, "./elsewhere") != null);
}

test "DEP004: a checkout without path: creates no directory" {
    var fx = try Fixture.init();
    defer fx.deinit();

    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
        .{ .uses = ActionRef.parse("./action-under-test") },
    };
    var list = runSteps(&steps);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.len());
}

test "DEP004: a checkout after the step does not excuse it" {
    var fx = try Fixture.init();
    defer fx.deinit();

    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);

    const steps = [_]Step{
        .{ .uses = ActionRef.parse("./action-under-test") },
        try checkoutStep("action-under-test", &with),
    };
    var list = runSteps(&steps);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.len());
}

test "DEP004: an expression path: is unresolvable, so nothing is reported" {
    var fx = try Fixture.init();
    defer fx.deinit();

    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);

    const steps = [_]Step{
        try checkoutStep("${{ inputs.dir }}", &with),
        .{ .uses = ActionRef.parse("./candidate") },
    };
    var list = runSteps(&steps);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.len());
}

test "DEP004: a checkout over the workspace root creates no new directory" {
    var fx = try Fixture.init();
    defer fx.deinit();

    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);

    const steps = [_]Step{
        try checkoutStep(".", &with),
        .{ .uses = ActionRef.parse("./missing-local-action") },
    };
    var list = runSteps(&steps);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.len());
}

test "DEP004: an expression path: excuses only what its literal prefix covers" {
    var fx = try Fixture.init();
    defer fx.deinit();

    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);

    const steps = [_]Step{
        try checkoutStep("vendor/${{ matrix.repo }}", &with),
        .{ .uses = ActionRef.parse("./vendor/tool") },
        .{ .uses = ActionRef.parse("./.github/actions/setup") },
    };
    var list = runSteps(&steps);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expect(std.mem.find(u8, list.get(0).message, "./.github/actions/setup") != null);
}

test "DEP004: another action's path: input does not excuse the step" {
    var fx = try Fixture.init();
    defer fx.deinit();

    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "path", "action-under-test");

    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/cache@v4"), .with = with },
        .{ .uses = ActionRef.parse("./action-under-test") },
    };
    var list = runSteps(&steps);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.len());
}

test "DEP004: with: is not checked against a tree the checkout replaces" {
    var fx = try Fixture.init();
    defer fx.deinit();
    // A directory of the same name exists here, but the runner overwrites it
    // with whatever the checkout fetches, so its inputs say nothing.
    try fx.write("action-under-test/action.yml",
        \\name: Stale
        \\description: d
        \\runs:
        \\  using: node24
        \\  main: index.js
        \\
    );

    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);

    var step_with: workflow_types.StringMap = .empty;
    defer step_with.deinit(testing.allocator);
    try step_with.put(testing.allocator, "version", "1");

    const steps = [_]Step{
        try checkoutStep("action-under-test", &with),
        .{ .uses = ActionRef.parse("./action-under-test"), .with = step_with },
    };
    var list = runSteps(&steps);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.len());
}
