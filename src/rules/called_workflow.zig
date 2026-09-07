//! Reads the reusable workflow a job-level `uses:` names, for the RW rules
//! that validate a call against the workflow it calls (RW002-RW004).
//!
//! Only a local call (`./.github/workflows/x.yml`) names a file zghalint can
//! open; a call into another repository is never checked. Nothing parsed here
//! outlives the caller's arena, and every diagnostic still points into the
//! *calling* file, so the called workflow only ever contributes names.
//!
//! The called file is read but never followed: a workflow that calls itself,
//! or a pair that call each other, is parsed once per call and never recursed
//! into, so a cycle cannot loop.

const std = @import("std");
const workspace = @import("../workspace.zig");
const yaml_parser = @import("../yaml/parser.zig");
const workflow_parser = @import("../workflow/parser.zig");
const types = @import("../workflow/types.zig");

pub const Interface = struct {
    inputs: []const types.InputDef = &.{},
    secrets: []const types.SecretDef = &.{},
    outputs: []const types.CallOutputDef = &.{},
};

/// Test seam: when set, sources come from memory instead of the filesystem, so
/// the rules can be tested without laying out a repository on disk.
pub var source_override: ?*const fn (path: []const u8) ?[]const u8 = null;

/// GitHub caps a workflow file well below this; anything larger is not a
/// workflow whose interface is worth reading.
const max_file_bytes = 1024 * 1024;

/// The repository-relative path a job-level `uses:` names, or null when the
/// call is not local. `..` is rejected rather than resolved: it would escape
/// the repository, and DEP003 already reports the malformed reference.
pub fn localPath(uses: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, uses, "./")) return null;
    const rel = uses[2..];
    if (rel.len == 0) return null;
    if (std.mem.indexOf(u8, rel, "..") != null) return null;
    // A local call carries no `@ref` (DEP003); one here would make the path
    // name a file that does not exist.
    if (std.mem.indexOfScalar(u8, rel, '@') != null) return null;
    return rel;
}

fn readSource(arena: std.mem.Allocator, rel_path: []const u8) ?[]const u8 {
    if (source_override) |lookup| return lookup(rel_path);

    const root = workspace.repoRoot() orelse return null;
    const full = std.fs.path.join(arena, &.{ root, rel_path }) catch return null;

    // stat before open: opening a FIFO for reading blocks until a writer
    // appears, so the kind check cannot come after openFile.
    const stat = std.fs.cwd().statFile(full) catch return null;
    if (stat.kind != .file) return null;

    const file = std.fs.cwd().openFile(full, .{}) catch return null;
    defer file.close();
    return file.readToEndAlloc(arena, max_file_bytes) catch null;
}

/// Returns the called workflow's `workflow_call` interface, or null when the
/// call is not local, the file cannot be read or parsed, or the called
/// workflow declares no `workflow_call` trigger. None of those is reported by
/// the caller-side rules: a call zghalint cannot see is never a finding.
pub fn load(arena: std.mem.Allocator, uses: []const u8) ?Interface {
    const rel = localPath(uses) orelse return null;
    const source = readSource(arena, rel) orelse return null;

    var parser = yaml_parser.Parser.init(arena, source);
    const root_node = parser.parse() catch return null;
    const wf = workflow_parser.parseWorkflow(arena, root_node) catch return null;

    for (wf.on.events) |event| {
        if (event.event != .workflow_call) continue;
        return .{
            .inputs = event.workflow_call_inputs,
            .secrets = event.workflow_call_secrets,
            .outputs = event.workflow_call_outputs,
        };
    }
    return null;
}

const testing = std.testing;

test "localPath accepts a local call and strips the ./" {
    try testing.expectEqualStrings(
        ".github/workflows/reusable.yml",
        localPath("./.github/workflows/reusable.yml").?,
    );
}

test "localPath rejects references it cannot resolve" {
    try testing.expect(localPath("octo-org/repo/.github/workflows/ci.yml@main") == null);
    try testing.expect(localPath("./") == null);
    try testing.expect(localPath("./../other/ci.yml") == null);
    try testing.expect(localPath("./.github/workflows/ci.yml@main") == null);
}

var test_source: ?[]const u8 = null;

fn testLookup(path: []const u8) ?[]const u8 {
    if (!std.mem.eql(u8, path, ".github/workflows/reusable.yml")) return null;
    return test_source;
}

test "load returns the workflow_call interface of the called file" {
    test_source =
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      version:
        \\        type: string
        \\        required: true
        \\    secrets:
        \\      npm_token:
        \\        required: true
        \\    outputs:
        \\      artifact:
        \\        value: ${{ jobs.build.outputs.artifact }}
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo ok
        \\
    ;
    source_override = &testLookup;
    defer source_override = null;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const iface = load(arena.allocator(), "./.github/workflows/reusable.yml").?;
    try testing.expectEqual(@as(usize, 1), iface.inputs.len);
    try testing.expectEqualStrings("version", iface.inputs[0].name);
    try testing.expectEqual(@as(usize, 1), iface.secrets.len);
    try testing.expectEqualStrings("npm_token", iface.secrets[0].name);
    try testing.expectEqual(@as(usize, 1), iface.outputs.len);
    try testing.expectEqualStrings("artifact", iface.outputs[0].name);
    try testing.expectEqualStrings("${{ jobs.build.outputs.artifact }}", iface.outputs[0].value.?);
}

test "load returns null for a workflow without workflow_call" {
    test_source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo ok
        \\
    ;
    source_override = &testLookup;
    defer source_override = null;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expect(load(arena.allocator(), "./.github/workflows/reusable.yml") == null);
}

test "load returns null for an unreadable call" {
    source_override = &testLookup;
    defer source_override = null;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expect(load(arena.allocator(), "./.github/workflows/missing.yml") == null);
    try testing.expect(load(arena.allocator(), "octo/repo/.github/workflows/ci.yml@v1") == null);
}
