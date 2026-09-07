//! EXPR014 — match `secrets.<name>` against `workflow_call.secrets` (issue #90).
//!
//! Only a reusable workflow that declares `on.workflow_call.secrets` has a
//! closed secret set: everywhere else the repository, organization or
//! environment can supply any name, so checking would be pure false
//! positives. That restriction is the whole point of the rule, and it is why
//! a `workflow_call` without a `secrets:` declaration (the `secrets: inherit`
//! caller path) is skipped as well.

const std = @import("std");
const engine = @import("engine.zig");
const expr_check = @import("expr_check.zig");
const expr_scan = @import("expr_scan.zig");
const spans = @import("spans.zig");
const util = @import("../util.zig");
const test_support = @import("../test_support.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const DiagnosticList = engine.DiagnosticList;
const Span = spans.Span;

/// Always present, whatever `workflow_call.secrets` declares.
const builtin_secrets = [_][]const u8{"GITHUB_TOKEN"};

/// Secret names are case-insensitive, like every other context key.
fn nameEql(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

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
                if (nameEql(seen, secret.name)) break;
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

    pub fn checkPath(self: Resolver, path: []const u8, span: Span) void {
        var iter = expr_check.SegmentIter{ .path = path };
        const root = identSegment(iter.next()) orelse return;
        if (!nameEql(root, "secrets")) return;

        // `secrets` alone (`toJSON(secrets)`) and computed keys
        // (`secrets[matrix.name]`) carry no name to resolve.
        const name = identSegment(iter.next()) orelse return;
        for (self.declared) |declared| {
            if (nameEql(declared, name)) return;
        }
        self.report(name, span);
    }

    fn report(self: Resolver, name: []const u8, span: Span) void {
        const alloc = self.list.fixAllocator();
        const suffix = if (util.didYouMean(name, self.declared)) |s|
            std.fmt.allocPrint(alloc, ". did you mean \"{s}\"?", .{s}) catch ""
        else
            "";
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
        }) catch return;
    }
};

/// Only plain identifiers are resolved: a globbed or computed segment
/// (`secrets.*`, `secrets[matrix.name]`) has no literal name.
fn identSegment(segment: ?expr_check.Segment) ?[]const u8 {
    const seg = segment orelse return null;
    return switch (seg) {
        .ident => |name| name,
        .index_string => |name| name,
        .star => null,
    };
}

pub fn checkWorkflow(wf: *const Workflow, list: *DiagnosticList) void {
    // The engine hands rules no arena (#159), so this one owns the memory the
    // expression parser needs and frees it as soon as the workflow is scanned.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
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

fn diagnose(arena: std.mem.Allocator, source: []const u8, list: *DiagnosticList) !void {
    const wf = try test_support.parseWorkflowSource(arena, source);
    checkWorkflow(&wf, list);
}

fn expectNoDiagnostics(source: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    try diagnose(arena.allocator(), source, &list);
    if (list.len() != 0) {
        std.debug.print("unexpected diagnostic: {s}\n", .{list.get(0).message});
    }
    try testing.expectEqual(@as(usize, 0), list.len());
}

fn expectMessage(source: []const u8, needle: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    try diagnose(arena.allocator(), source, &list);
    for (list.items.items) |diag| {
        if (std.mem.indexOf(u8, diag.message, needle) != null) {
            try testing.expectEqualStrings("EXPR014", diag.rule_id);
            return;
        }
    }
    if (list.len() != 0) {
        std.debug.print("messages did not contain \"{s}\"; first: {s}\n", .{ needle, list.get(0).message });
    }
    return error.MessageNotFound;
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
