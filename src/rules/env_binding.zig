//! The one fix SEC002 / SEC008 / SEC019 share: bind an untrusted or secret
//! `${{ ... }}` in a step's `run:` to that step's `env:`, and read it back as a
//! shell variable so the value never reaches the shell as code.
//!
//! Design: `docs/design/af5-env-binding-autofix-design.md`.

const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const util = @import("../util.zig");
const spans = @import("spans.zig");
const fix_builder = @import("../fix/builder.zig");

const DiagnosticList = diagnostics.DiagnosticList;
const Fix = diagnostics.Fix;
const Edit = diagnostics.Edit;
const Step = workflow_types.Step;
const Job = workflow_types.Job;
const Workflow = workflow_types.Workflow;

/// A `${{ ... }}` occurrence inside `Step.run`, in normalized-value offsets.
pub const Occurrence = struct {
    offset: usize,
    len: usize,
};

/// The occurrences of one step. A step with more than this many offending
/// expressions gets no fix rather than a partial one.
pub const max_occurrences = 16;

pub const Occurrences = struct {
    buf: [max_occurrences]Occurrence = undefined,
    len: usize = 0,
    /// Set when the step had more occurrences than fit, which makes any fix
    /// built from the list a partial rewrite.
    overflowed: bool = false,

    pub fn append(self: *Occurrences, occ: Occurrence) void {
        if (self.len == max_occurrences) {
            self.overflowed = true;
            return;
        }
        self.buf[self.len] = occ;
        self.len += 1;
    }

    pub fn slice(self: *const Occurrences) []const Occurrence {
        return self.buf[0..self.len];
    }
};

/// How a bound variable is spelled in the shell that runs the step.
pub const Shell = enum {
    /// `bash`, `sh` and the `<name> {0}` forms of both.
    posix,
    /// `pwsh` / `powershell`.
    pwsh,
    cmd,
};

/// `python` (and any other non-shell interpreter) is absent on purpose: an
/// env var is readable there, but not with a spelling that can be substituted
/// into the script text.
fn shellFromName(name: []const u8) ?Shell {
    if (std.mem.eql(u8, name, "bash") or std.mem.eql(u8, name, "sh")) return .posix;
    if (std.mem.eql(u8, name, "pwsh") or std.mem.eql(u8, name, "powershell")) return .pwsh;
    if (std.mem.eql(u8, name, "cmd")) return .cmd;
    return null;
}

/// The runner OS decides the default shell only when `runs-on` names it
/// plainly; a matrix expression or a self-hosted label leaves it unknown.
///
/// Windows is deliberately not resolved to its `pwsh` default. BP004 offers a
/// `shell: bash` fix for exactly that step -- a Windows `run:` with no explicit
/// shell -- and the two fixes touch different bytes, so both would apply and
/// leave a bash step reading `$env:NAME`. With an explicit `shell:` present
/// BP004 stays quiet and this resolves the shell from it as usual.
fn shellFromRunsOn(runs_on: []const u8) ?Shell {
    if (std.mem.indexOf(u8, runs_on, "${{") != null) return null;
    if (containsIgnoreCase(runs_on, "windows")) return null;
    if (containsIgnoreCase(runs_on, "ubuntu") or
        containsIgnoreCase(runs_on, "linux") or
        containsIgnoreCase(runs_on, "macos")) return .posix;
    return null;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(haystack, needle) != null;
}

/// `step.shell` first, then the job's and the workflow's `defaults.run.shell`,
/// then the runner OS. Null means "cannot be decided", and no fix is built:
/// guessing the wrong shell rewrites a working script into a broken one.
pub fn resolveShell(step: *const Step, job: ?*const Job, wf: ?*const Workflow) ?Shell {
    if (step.shell) |s| return shellFromName(std.mem.trim(u8, s, " \t"));
    if (job) |j| {
        if (j.defaults) |d| return shellFromName(std.mem.trim(u8, d.run_shell, " \t"));
    }
    if (wf) |w| {
        if (w.defaults) |d| return shellFromName(std.mem.trim(u8, d.run_shell, " \t"));
    }
    const j = job orelse return null;
    const runs_on = j.runs_on orelse return null;
    return shellFromRunsOn(runs_on);
}

/// Where in the shell's own quoting the occurrence sits, which decides whether
/// the reference has to bring its own quotes.
const QuoteState = enum { plain, dquote, squote };

/// The `run:` body is scanned per line, because a quote never spans a newline
/// in any of the three shells without an explicit continuation, and treating
/// the body as one string would let an unbalanced quote on one line poison
/// every line below it.
fn quoteStateAt(run: []const u8, offset: usize) QuoteState {
    const line_start = if (std.mem.lastIndexOfScalar(u8, run[0..offset], '\n')) |nl| nl + 1 else 0;
    var state: QuoteState = .plain;
    var i = line_start;
    while (i < offset) : (i += 1) {
        switch (run[i]) {
            '\\' => if (state != .squote) {
                i += 1;
            },
            '"' => switch (state) {
                .plain => state = .dquote,
                .dquote => state = .plain,
                .squote => {},
            },
            '\'' => switch (state) {
                .plain => state = .squote,
                .squote => state = .plain,
                .dquote => {},
            },
            else => {},
        }
    }
    return state;
}

fn reference(alloc: std.mem.Allocator, shell: Shell, name: []const u8, state: QuoteState) ?[]const u8 {
    const bare: []const u8 = switch (shell) {
        .posix => std.fmt.allocPrint(alloc, "${s}", .{name}) catch return null,
        .pwsh => std.fmt.allocPrint(alloc, "$env:{s}", .{name}) catch return null,
        .cmd => std.fmt.allocPrint(alloc, "%{s}%", .{name}) catch return null,
    };
    return switch (state) {
        .dquote => bare,
        .plain => std.fmt.allocPrint(alloc, "\"{s}\"", .{bare}) catch return null,
        // Inside single quotes nothing expands, so there is no in-place
        // rewrite that keeps the script's meaning.
        .squote => null,
    };
}

/// Segments that carry no information about *which* value is being bound, so
/// dropping them from the front makes the derived name readable.
const root_noise = [_][]const u8{ "github", "event", "secrets", "steps", "needs", "inputs" };

const max_name_segments = 3;

fn isNoise(seg: []const u8) bool {
    for (root_noise) |n| {
        if (std.ascii.eqlIgnoreCase(n, seg)) return true;
    }
    return false;
}

fn isNameSegment(seg: []const u8) bool {
    if (seg.len == 0) return false;
    if (!std.ascii.isAlphabetic(seg[0]) and seg[0] != '_') return false;
    for (seg[1..]) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-') return false;
    }
    return true;
}

/// The env var name for one expression, or null when the expression is not a
/// plain context path (a function call, an index, an operator). Null means the
/// whole step gets no fix: a partly bound step reads as fixed without being it.
pub fn deriveName(alloc: std.mem.Allocator, inner: []const u8) ?[]const u8 {
    const path = std.mem.trim(u8, inner, " \t\n\r");
    if (path.len == 0) return null;

    var segs: [16][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, path, '.');
    while (it.next()) |seg| {
        if (n == segs.len) return null;
        if (!isNameSegment(seg)) return null;
        segs[n] = seg;
        n += 1;
    }

    var start: usize = 0;
    while (start < n and isNoise(segs[start])) start += 1;
    // A path made of nothing but root segments (`github.event`) keeps them all;
    // an empty name is worse than a noisy one.
    if (start == n) start = 0;

    const kept = segs[start..n];
    const from = if (kept.len > max_name_segments) kept.len - max_name_segments else 0;

    var buf = std.ArrayList(u8){};
    defer buf.deinit(alloc);
    for (kept[from..], 0..) |seg, i| {
        if (i > 0) buf.append(alloc, '_') catch return null;
        for (seg) |c| {
            buf.append(alloc, if (c == '-') '_' else std.ascii.toUpper(c)) catch return null;
        }
    }
    return buf.toOwnedSlice(alloc) catch null;
}

const Binding = struct {
    /// The whole `${{ ... }}` text, moved into `env:` verbatim.
    expr: []const u8,
    name: []const u8,
};

/// Names the runner already owns. Binding one of them would not just shadow a
/// value the script reads, it would break the step: `PATH: ${{ ... }}` leaves
/// the shell without its own `PATH`. They are treated as taken so the binding
/// gets a `_2` suffix instead.
fn isReserved(name: []const u8) bool {
    for ([_][]const u8{ "PATH", "HOME", "SHELL" }) |n| {
        if (std.mem.eql(u8, n, name)) return true;
    }
    for ([_][]const u8{ "GITHUB_", "RUNNER_", "ACTIONS_" }) |prefix| {
        if (std.mem.startsWith(u8, name, prefix)) return true;
    }
    return false;
}

fn nameTaken(step: *const Step, bindings: []const Binding, name: []const u8) bool {
    if (isReserved(name)) return true;
    for (step.env_keys) |k| {
        if (std.mem.eql(u8, k.name, name)) return true;
    }
    for (bindings) |b| {
        if (std.mem.eql(u8, b.name, name)) return true;
    }
    return false;
}

fn uniqueName(alloc: std.mem.Allocator, step: *const Step, bindings: []const Binding, base: []const u8) ?[]const u8 {
    if (!nameTaken(step, bindings, base)) return base;
    var suffix: usize = 2;
    while (suffix < 100) : (suffix += 1) {
        const candidate = std.fmt.allocPrint(alloc, "{s}_{d}", .{ base, suffix }) catch return null;
        if (!nameTaken(step, bindings, candidate)) return candidate;
    }
    return null;
}

/// Builds the single `Fix` that binds every occurrence of one step. Returns
/// null — no fix at all — whenever any part of the rewrite cannot be made
/// exactly, because `fix/engine.zig` drops individual invalid edits rather
/// than the fix around them, and a half-applied binding is worse than none.
pub fn buildFix(
    list: *DiagnosticList,
    step: *const Step,
    shell: Shell,
    occs: *const Occurrences,
    description: []const u8,
) ?Fix {
    if (occs.overflowed or occs.len == 0) return null;

    const run = step.run orelse return null;
    const meta = step.run_meta orelse return null;
    // Only these two styles keep `run` byte-identical to the source, which is
    // what makes the offset mapping exact (design doc §4).
    switch (meta.style) {
        .plain, .literal => {},
        else => return null,
    }
    // `env:` present but empty leaves no anchor to append to and no room to
    // insert a second `env:` key (#171).
    if (util.hasEmptySection(step.empty_sections, "env")) return null;

    const alloc = list.fixAllocator();

    var bindings: [max_occurrences]Binding = undefined;
    var binding_count: usize = 0;
    var edits = std.ArrayList(Edit){};
    defer edits.deinit(alloc);

    for (occs.slice()) |occ| {
        if (occ.offset + occ.len > run.len) return null;
        const expr = run[occ.offset .. occ.offset + occ.len];
        if (!std.mem.startsWith(u8, expr, "${{") or !std.mem.endsWith(u8, expr, "}}")) return null;
        const inner = expr[3 .. expr.len - 2];

        const state = quoteStateAt(run, occ.offset);
        if (state == .squote) return null;

        // The same expression twice in one step shares one binding.
        var name: ?[]const u8 = null;
        for (bindings[0..binding_count]) |b| {
            if (std.mem.eql(u8, b.expr, expr)) name = b.name;
        }
        if (name == null) {
            const base = deriveName(alloc, inner) orelse return null;
            const unique = uniqueName(alloc, step, bindings[0..binding_count], base) orelse return null;
            bindings[binding_count] = .{ .expr = expr, .name = unique };
            binding_count += 1;
            name = unique;
        }

        const ref = reference(alloc, shell, name.?, state) orelse return null;
        const span = spans.runAnchor(step).at(run, occ.offset, occ.len);
        edits.append(alloc, .{
            .start_byte = span.start_byte,
            .end_byte = span.end_byte,
            .replacement = ref,
            .expects = expr,
        }) catch return null;
    }

    var subs: [max_occurrences]fix_builder.SubEntry = undefined;
    for (bindings[0..binding_count], 0..) |b, i| {
        subs[i] = .{ .key = b.name, .value = b.expr };
    }

    const env_edits = buildEnvEdits(alloc, step, subs[0..binding_count]) orelse return null;
    edits.appendSlice(alloc, env_edits) catch return null;

    const owned = edits.toOwnedSlice(alloc) catch return null;
    return .{ .description = description, .safety = .unsafe, .edits = owned };
}

fn buildEnvEdits(
    alloc: std.mem.Allocator,
    step: *const Step,
    subs: []const fix_builder.SubEntry,
) ?[]const Edit {
    if (step.env != null) {
        const after = step.env_last_entry_end_byte orelse return null;
        const col = step.env_key_col orelse return null;
        if (col == 0) return null;
        return fix_builder.appendMappingEntries(alloc, after, col - 1, subs);
    }

    const byte = step.first_key_start_byte orelse return null;
    const col = step.first_key_col orelse return null;
    if (col == 0) return null;
    return fix_builder.insertMappingEntryBlockBefore(
        alloc,
        .{ .byte = byte, .indent = col - 1 },
        "env",
        subs,
        2,
    );
}

const testing = std.testing;

test "deriveName drops the root segments and uppercases the rest" {
    const alloc = testing.allocator;
    const cases = [_]struct { in: []const u8, out: []const u8 }{
        .{ .in = "github.event.pull_request.title", .out = "PULL_REQUEST_TITLE" },
        .{ .in = "github.event.issue.body", .out = "ISSUE_BODY" },
        .{ .in = "github.head_ref", .out = "HEAD_REF" },
        .{ .in = "secrets.NPM_TOKEN", .out = "NPM_TOKEN" },
        .{ .in = " github.event.comment.body ", .out = "COMMENT_BODY" },
    };
    for (cases) |c| {
        const got = deriveName(alloc, c.in).?;
        defer alloc.free(got);
        try testing.expectEqualStrings(c.out, got);
    }
}

test "deriveName keeps the root segments when nothing else is left" {
    const got = deriveName(testing.allocator, "github.event").?;
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("GITHUB_EVENT", got);
}

test "deriveName keeps only the last three segments" {
    const got = deriveName(testing.allocator, "steps.build.outputs.name.extra").?;
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("OUTPUTS_NAME_EXTRA", got);
}

test "a name the runner owns is suffixed instead of shadowed" {
    const alloc = testing.allocator;
    const base = deriveName(alloc, "github.event.inputs.path").?;
    defer alloc.free(base);
    try testing.expectEqualStrings("PATH", base);

    var step: Step = .{};
    const unique = uniqueName(alloc, &step, &.{}, base).?;
    defer alloc.free(unique);
    try testing.expectEqualStrings("PATH_2", unique);
}

test "deriveName rewrites a hyphen to an underscore" {
    const got = deriveName(testing.allocator, "github.event.inputs.some-input").?;
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("SOME_INPUT", got);
}

test "deriveName returns null for anything but a plain context path" {
    const alloc = testing.allocator;
    const bad = [_][]const u8{
        "fromJSON(github.event.inputs.x)",
        "github.event.commits[0].message",
        "github.event.commits.*.message",
        "github.event.issue.title == 'x'",
        "",
        "1abc",
    };
    for (bad) |b| try testing.expect(deriveName(alloc, b) == null);
}

test "quoteStateAt tracks quoting within the occurrence's own line" {
    const run = "echo \"${{ a.b }}\"\necho ${{ c.d }}\necho '${{ e.f }}'\n";
    try testing.expectEqual(QuoteState.dquote, quoteStateAt(run, std.mem.indexOf(u8, run, "${{ a.b }}").?));
    try testing.expectEqual(QuoteState.plain, quoteStateAt(run, std.mem.indexOf(u8, run, "${{ c.d }}").?));
    try testing.expectEqual(QuoteState.squote, quoteStateAt(run, std.mem.indexOf(u8, run, "${{ e.f }}").?));
}

test "quoteStateAt ignores an escaped quote" {
    const run = "echo \\\"${{ a.b }}\n";
    try testing.expectEqual(QuoteState.plain, quoteStateAt(run, std.mem.indexOf(u8, run, "${{").?));
}

test "reference spells the variable per shell and adds quotes only when needed" {
    const alloc = testing.allocator;
    const cases = [_]struct { shell: Shell, state: QuoteState, out: []const u8 }{
        .{ .shell = .posix, .state = .dquote, .out = "$X" },
        .{ .shell = .posix, .state = .plain, .out = "\"$X\"" },
        .{ .shell = .pwsh, .state = .dquote, .out = "$env:X" },
        .{ .shell = .pwsh, .state = .plain, .out = "\"$env:X\"" },
        .{ .shell = .cmd, .state = .dquote, .out = "%X%" },
        .{ .shell = .cmd, .state = .plain, .out = "\"%X%\"" },
    };
    for (cases) |c| {
        // The bare form leaks when the quoted form wraps it; an arena stands in
        // for the fix arena the real caller uses.
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const got = reference(arena.allocator(), c.shell, "X", c.state).?;
        try testing.expectEqualStrings(c.out, got);
    }
}

test "reference declines a single-quoted occurrence" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expect(reference(arena.allocator(), .posix, "X", .squote) == null);
}

test "Occurrences marks the overflow instead of truncating silently" {
    var occs: Occurrences = .{};
    var i: usize = 0;
    while (i < max_occurrences + 1) : (i += 1) occs.append(.{ .offset = i, .len = 1 });
    try testing.expectEqual(max_occurrences, occs.len);
    try testing.expect(occs.overflowed);
}
