//! EXPR014 — match `secrets.<name>` against `workflow_call.secrets` (issue #90).
//!
//! Only a reusable workflow that declares `on.workflow_call.secrets` has a
//! closed secret set: everywhere else the repository, organization or
//! environment can supply any name, so checking would be pure false
//! positives. That restriction is the whole point of the rule, and it is why
//! a `workflow_call` without a `secrets:` declaration (the `secrets: inherit`
//! caller path) is skipped as well. Secret names match case-insensitively,
//! like every other context key.

const std = @import("std");
const engine = @import("engine.zig");
const expr_check = @import("expr_check.zig");
const expr_scan = @import("expr_scan.zig");
const spans = @import("spans.zig");
const util = @import("../util.zig");
const rename = @import("rename.zig");
const test_support = @import("../test_support.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const DiagnosticList = engine.DiagnosticList;
const Span = spans.Span;

/// Always present, whatever `workflow_call.secrets` declares.
const builtin_secrets = [_][]const u8{"GITHUB_TOKEN"};

/// The declared names, or null when this workflow's secret set is open and
/// nothing can be checked.
fn collectSecrets(wf: *const Workflow, alloc: std.mem.Allocator) ?[]const []const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    var declared = false;

    for (wf.on.events) |event| {
        if (event.event != .workflow_call) continue;
        // An empty declaration is indistinguishable from none in practice, so
        // it is treated as an open set rather than as "no secret is valid".
        if (event.workflow_call_secrets.len == 0) continue;
        declared = true;
        for (event.workflow_call_secrets) |secret| {
            for (names.items) |seen| {
                if (std.ascii.eqlIgnoreCase(seen, secret.name)) break;
            } else names.append(alloc, secret.name) catch return null;
        }
    }
    if (!declared) return null;

    for (builtin_secrets) |builtin| names.append(alloc, builtin) catch return null;
    return names.toOwnedSlice(alloc) catch null;
}

const Resolver = struct {
    declared: []const []const u8,
    /// Backs the expression parse trees; diagnostic messages are allocated
    /// from the list's own arena instead.
    alloc: std.mem.Allocator,
    list: *DiagnosticList,

    pub fn checkPath(self: Resolver, path: []const u8, loc: expr_scan.Loc) void {
        var iter = expr_check.SegmentIter{ .path = path };
        const root = iter.nextName() orelse return;
        if (!std.ascii.eqlIgnoreCase(root, "secrets")) return;

        // `secrets` alone (`toJSON(secrets)`) and computed keys
        // (`secrets[matrix.name]`) carry no name to resolve.
        const name = iter.nextName() orelse return;
        for (self.declared) |declared| {
            if (std.ascii.eqlIgnoreCase(declared, name)) return;
        }
        self.report(path, name, loc.resolve());
    }

    fn report(self: Resolver, path: []const u8, name: []const u8, span: Span) void {
        const alloc = self.list.fixAllocator();
        const suggestion = util.didYouMean(name, self.declared);
        const suffix = util.suggestionSuffix(alloc, suggestion);
        const message = std.fmt.allocPrint(
            alloc,
            "secret \"{s}\" is not declared in \"workflow_call.secrets\"{s}",
            .{ name, suffix },
        ) catch return;

        self.list.append(.{
            .rule_id = "EXPR014",
            .severity = .@"error",
            .message = message,
            .span = span,
            .fix_hint = "declare the secret under `on.workflow_call.secrets:`",
            .fix = if (suggestion) |s| rename.pathSegmentFix(self.list, span, path, 1, s) else null,
        }) catch return;
    }
};

/// Only plain identifiers are resolved: a globbed or computed segment
/// (`secrets.*`, `secrets[matrix.name]`) has no literal name.
pub fn checkWorkflow(wf: *const Workflow, list: *DiagnosticList) void {
    // Scratch for the expression parser: no diagnostic points at it, and
    // the list's allocator keeps it under the run's leak detection (#159).
    var arena = std.heap.ArenaAllocator.init(list.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const declared = collectSecrets(wf, alloc) orelse return;
    const resolver = Resolver{ .declared = declared, .alloc = alloc, .list = list };

    expr_scan.scanScalarMap(resolver, wf.env, wf.env_meta, spans.workflow_head);
    for (wf.jobs) |*job| expr_scan.scanJob(resolver, job);
}

pub const rules = [_]Rule{
    .{
        .id = "EXPR014",
        .name = "secrets-context",
        .description = "`secrets.<name>` must be declared in `on.workflow_call.secrets`",
        .severity = .@"error",
        .category = .expression,
        .check_workflow = &checkWorkflow,
    },
};

const testing = std.testing;

const workflow_check: test_support.Check = .{ .workflow = &checkWorkflow };

fn expectNoDiagnostics(source: []const u8) !void {
    try test_support.expectNoDiagnostics(source, workflow_check);
}

fn expectMessage(source: []const u8, needle: []const u8) !void {
    try test_support.expectMessage(source, workflow_check, "EXPR014", needle);
}

test "EXPR014: a misspelled secret is reported with a suggestion" {
    try expectMessage(
        \\on:
        \\  workflow_call:
        \\    secrets:
        \\      npm_token:
        \\        required: true
        \\jobs:
        \\  publish:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: npm publish
        \\        env:
        \\          NPM_TOKEN: ${{ secrets.npm_tokne }}
    , "secret \"npm_tokne\" is not declared in \"workflow_call.secrets\". did you mean \"npm_token\"?");
}

test "EXPR014: an undeclared secret is reported" {
    try expectMessage(
        \\on:
        \\  workflow_call:
        \\    secrets:
        \\      npm_token:
        \\        required: true
        \\jobs:
        \\  publish:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: npm publish
        \\        env:
        \\          OTHER: ${{ secrets.AWS_KEY }}
    , "secret \"AWS_KEY\" is not declared");
}

test "EXPR014: declared secrets and GITHUB_TOKEN are accepted" {
    try expectNoDiagnostics(
        \\on:
        \\  workflow_call:
        \\    secrets:
        \\      npm_token:
        \\        required: true
        \\jobs:
        \\  publish:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: npm publish
        \\        env:
        \\          NPM_TOKEN: ${{ secrets.npm_token }}
        \\          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    );
}

test "EXPR014: a workflow without workflow_call is left alone" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ secrets.ANY_REPO_SECRET }}"
    );
}

test "EXPR014: workflow_call without a secrets declaration is left alone" {
    try expectNoDiagnostics(
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      version:
        \\        type: string
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ secrets.INHERITED }}"
    );
}

test "EXPR014: secret names resolve case-insensitively" {
    try expectNoDiagnostics(
        \\on:
        \\  workflow_call:
        \\    secrets:
        \\      npm_token:
        \\        required: true
        \\jobs:
        \\  publish:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ secrets.NPM_TOKEN }}"
    );
}

test "EXPR014: a bare secrets reference carries no name to resolve" {
    try expectNoDiagnostics(
        \\on:
        \\  workflow_call:
        \\    secrets:
        \\      npm_token:
        \\        required: true
        \\jobs:
        \\  publish:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ toJSON(secrets) }}"
    );
}
