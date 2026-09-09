//! SYN021 / SYN022 — the shape of the job dependency graph (issue #281).
//!
//! `needs:` names other jobs of the same workflow. A name no job carries and a
//! cycle in the graph both make the run fail before a single step executes, so
//! they are errors even though the YAML itself parses. Both need the whole
//! workflow, which is why they live here instead of in the per-job checks of
//! `syntax.zig`.

const std = @import("std");
const engine = @import("engine.zig");
const util = @import("../util.zig");
const rename = @import("rename.zig");
const yaml = @import("../yaml/types.zig");
const test_support = @import("../test_support.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const Job = engine.Job;
const DiagnosticList = engine.DiagnosticList;
const Span = yaml.Span;

/// Job IDs are matched case-insensitively, the way the runner resolves them.
fn eqlId(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn findJob(wf: *const Workflow, job_id: []const u8) ?usize {
    for (wf.jobs, 0..) |*candidate, i| {
        if (eqlId(candidate.id, job_id)) return i;
    }
    return null;
}

/// The span to point a `needs` diagnostic at. `needs_spans` is parallel to
/// `needs` but empty when the parser captured no per-entry span, so the job
/// itself stands in.
fn needsSpan(job: *const Job, index: usize) Span {
    if (index < job.needs_spans.len) return job.needs_spans[index];
    return job.span;
}

/// An entry SYN006 already rejects as a malformed ID, or one built from an
/// expression, has no name to look up: reporting it again here would put two
/// errors on the same span. An empty entry is checked here rather than left
/// to SYN006, whose ID grammar accepts the empty string.
fn isCheckable(need: []const u8) bool {
    if (need.len == 0) return true;
    if (std.mem.indexOf(u8, need, "${{") != null) return false;
    const first = need[0];
    if (first != '_' and !std.ascii.isAlphabetic(first)) return false;
    for (need[1..]) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return false;
    }
    return true;
}

fn checkUndefinedNeeds(wf: *const Workflow, list: *DiagnosticList) void {
    for (wf.jobs) |*job| {
        for (job.needs, 0..) |need, i| {
            if (!isCheckable(need)) continue;
            if (findJob(wf, need) != null) continue;
            reportUndefined(wf, job, need, needsSpan(job, i), list);
        }
    }
}

fn reportUndefined(
    wf: *const Workflow,
    job: *const Job,
    need: []const u8,
    span: Span,
    list: *DiagnosticList,
) void {
    const alloc = list.fixAllocator();
    const nearest = nearestJobId(wf, job, need, list);
    const suffix = if (nearest) |near|
        std.fmt.allocPrint(alloc, ". did you mean \"{s}\"?", .{near}) catch ""
    else
        "";
    const message = std.fmt.allocPrint(
        alloc,
        "\"{s}\" in \"needs\" is not a job in this workflow{s}",
        .{ need, suffix },
    ) catch return;

    list.append(.{
        .rule_id = "SYN021",
        .severity = .@"error",
        .message = message,
        .span = span,
        .fix_hint = "name a job defined under 'jobs', or drop the entry",
        // A job ID the source cannot carry unquoted (`g]t`) closes the flow
        // sequence it is written into, so `needs: [ight]` becomes `[g]t]` and
        // every `--fix` round appends another `t]` (fuzz).
        .fix = if (nearest) |near| blk: {
            if (!rename.isSimpleName(near)) break :blk null;
            break :blk rename.tokenFix(list, span, need, near);
        } else null,
    }) catch return;
}

/// The owning job is not a candidate: renaming `needs: [deplo]` in job
/// `deploy` to its own ID would trade the SYN021 error for a SYN022 self-cycle.
/// An empty entry has no typo to correct either, and every short job ID would
/// sit within edit distance of it.
fn nearestJobId(
    wf: *const Workflow,
    job: *const Job,
    need: []const u8,
    list: *DiagnosticList,
) ?[]const u8 {
    if (need.len == 0) return null;
    const alloc = list.fixAllocator();
    var names = alloc.alloc([]const u8, wf.jobs.len) catch return null;
    var n: usize = 0;
    for (wf.jobs) |*candidate| {
        if (eqlId(candidate.id, job.id)) continue;
        names[n] = candidate.id;
        n += 1;
    }
    return util.didYouMean(need, names[0..n]);
}

const Color = enum { white, gray, black };

/// One depth-first walk over the whole graph. Every back edge — an edge into a
/// job still on the current path — closes exactly one cycle, so each is
/// reported once, at the job the cycle returns to. The walk is iterative
/// because a workflow can chain arbitrarily many jobs.
const CycleWalk = struct {
    wf: *const Workflow,
    list: *DiagnosticList,
    color: []Color,

    const Frame = struct { job: usize, next_need: usize };
    /// The gray jobs, outermost first: the stack *is* the current path.
    const Stack = std.ArrayList(Frame);

    fn run(self: *CycleWalk, alloc: std.mem.Allocator) void {
        var stack = Stack{};
        defer stack.deinit(alloc);

        for (self.wf.jobs, 0..) |_, start| {
            if (self.color[start] != .white) continue;
            self.enter(alloc, &stack, start) catch return;

            while (stack.items.len > 0) {
                const frame = &stack.items[stack.items.len - 1];
                const job = &self.wf.jobs[frame.job];
                if (frame.next_need >= job.needs.len) {
                    self.leave(&stack);
                    continue;
                }
                const need = job.needs[frame.next_need];
                frame.next_need += 1;

                const target = findJob(self.wf, need) orelse continue;
                switch (self.color[target]) {
                    .gray => self.reportCycle(&stack, target),
                    .white => self.enter(alloc, &stack, target) catch return,
                    .black => {},
                }
            }
        }
    }

    fn enter(self: *CycleWalk, alloc: std.mem.Allocator, stack: *Stack, job: usize) !void {
        try stack.append(alloc, .{ .job = job, .next_need = 0 });
        self.color[job] = .gray;
    }

    fn leave(self: *CycleWalk, stack: *Stack) void {
        const frame = stack.pop().?;
        self.color[frame.job] = .black;
    }

    /// `target` is on the current path, so the cycle is the path from it to
    /// the job being visited, closed by the edge back to `target`.
    fn reportCycle(self: *CycleWalk, stack: *const Stack, target: usize) void {
        const start = for (stack.items, 0..) |frame, i| {
            if (frame.job == target) break i;
        } else return;

        const alloc = self.list.fixAllocator();
        var chain: std.ArrayList(u8) = .{};
        for (stack.items[start..]) |frame| {
            chain.appendSlice(alloc, self.wf.jobs[frame.job].id) catch return;
            chain.appendSlice(alloc, " -> ") catch return;
        }
        chain.appendSlice(alloc, self.wf.jobs[target].id) catch return;

        const job = &self.wf.jobs[target];
        const message = std.fmt.allocPrint(
            alloc,
            "job \"{s}\" is in a dependency cycle: {s}",
            .{ job.id, chain.items },
        ) catch return;

        self.list.append(.{
            .rule_id = "SYN022",
            .severity = .@"error",
            .message = message,
            .span = job.id_span orelse job.span,
            .fix_hint = "break the cycle by removing one of the 'needs' entries",
        }) catch return;
    }
};

fn checkNeedsCycle(wf: *const Workflow, list: *DiagnosticList) void {
    if (wf.jobs.len == 0) return;

    const color = list.allocator.alloc(Color, wf.jobs.len) catch return;
    defer list.allocator.free(color);
    @memset(color, .white);

    var walk = CycleWalk{ .wf = wf, .list = list, .color = color };
    walk.run(list.allocator);
}

pub const rules = [_]Rule{
    .{
        .id = "SYN021",
        .name = "undefined-needs-job",
        .description = "'needs' names a job the workflow does not define, so the run never starts",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkUndefinedNeeds,
    },
    .{
        .id = "SYN022",
        .name = "needs-cycle",
        .description = "job dependencies form a cycle, so none of the jobs in it can ever run",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkNeedsCycle,
    },
};

const testing = std.testing;

fn runOn(source: []const u8, list: *DiagnosticList) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);
    checkUndefinedNeeds(&wf, list);
    checkNeedsCycle(&wf, list);
}

fn expectClean(source: []const u8) !void {
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    try runOn(source, &list);
    if (list.len() != 0) {
        for (list.items.items) |diag| std.debug.print("unexpected {s}: {s}\n", .{ diag.rule_id, diag.message });
    }
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SYN021: needs naming no job is reported at the entry" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make
        \\  deploy:
        \\    needs: [buld]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make deploy
    ;
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    try runOn(source, &list);

    try testing.expectEqual(@as(usize, 1), list.len());
    const diag = list.get(0);
    try testing.expectEqualStrings("SYN021", diag.rule_id);
    try testing.expectEqual(@as(u32, 8), diag.span.start_line);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean \"build\"") != null);
    try testing.expect(diag.fix != null);
}

test "SYN021: the owning job is not a rename candidate" {
    // Renaming `deplo` to `deploy` would only trade the error for a SYN022
    // self-cycle, so no fix is offered.
    const source =
        \\on: push
        \\jobs:
        \\  deploy:
        \\    needs: [deplo]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make deploy
    ;
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    try runOn(source, &list);

    try testing.expectEqual(@as(usize, 1), list.len());
    const diag = list.get(0);
    try testing.expectEqualStrings("SYN021", diag.rule_id);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean") == null);
    try testing.expect(diag.fix == null);
}

test "SYN021: no rename onto a job ID the source cannot carry (fuzz)" {
    // `g]t` closes the flow sequence it would be written into, so `[ight]`
    // would become `[g]t]` and every `--fix` round would append another `t]`.
    const source =
        \\on: push
        \\jobs:
        \\  d:
        \\    needs: [ight]
        \\    runs-on: ubuntu-latest
        \\  g]t:
        \\    runs-on: ubuntu-latest
    ;
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    try runOn(source, &list);

    const diag = list.get(0);
    try testing.expectEqualStrings("SYN021", diag.rule_id);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean") != null);
    try testing.expect(diag.fix == null);
}

test "SYN021: an empty entry is reported without a suggestion" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make
        \\  deploy:
        \\    needs: [""]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make deploy
    ;
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    try runOn(source, &list);

    try testing.expectEqual(@as(usize, 1), list.len());
    const diag = list.get(0);
    try testing.expectEqualStrings("SYN021", diag.rule_id);
    try testing.expect(diag.fix == null);
}

test "SYN021: a job ID differing only in case is the same job" {
    try expectClean(
        \\on: push
        \\jobs:
        \\  Build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make
        \\  deploy:
        \\    needs: [build]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make deploy
    );
}

test "SYN021: a malformed entry is left to SYN006" {
    try expectClean(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make
        \\  deploy:
        \\    needs: ["1-build"]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make deploy
    );
}

test "SYN021: a fanned-out graph produces no diagnostic" {
    try expectClean(
        \\on: push
        \\jobs:
        \\  setup:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make setup
        \\  test:
        \\    needs: setup
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make test
        \\  deploy:
        \\    needs: [setup, test]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make deploy
    );
}

test "SYN022: a two-job cycle is reported once, at the job it returns to" {
    const source =
        \\on: push
        \\jobs:
        \\  a:
        \\    needs: [b]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make a
        \\  b:
        \\    needs: [a]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make b
    ;
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    try runOn(source, &list);

    try testing.expectEqual(@as(usize, 1), list.len());
    const diag = list.get(0);
    try testing.expectEqualStrings("SYN022", diag.rule_id);
    try testing.expectEqual(@as(u32, 3), diag.span.start_line);
    try testing.expect(std.mem.indexOf(u8, diag.message, "a -> b -> a") != null);
}

test "SYN022: a job needing itself is a cycle" {
    const source =
        \\on: push
        \\jobs:
        \\  loop:
        \\    needs: loop
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make
    ;
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    try runOn(source, &list);

    try testing.expectEqual(@as(usize, 1), list.len());
    const diag = list.get(0);
    try testing.expectEqualStrings("SYN022", diag.rule_id);
    try testing.expect(std.mem.indexOf(u8, diag.message, "loop -> loop") != null);
}

test "SYN022: a diamond is not a cycle" {
    try expectClean(
        \\on: push
        \\jobs:
        \\  setup:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make setup
        \\  left:
        \\    needs: [setup]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make left
        \\  right:
        \\    needs: [setup]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make right
        \\  join:
        \\    needs: [left, right]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make join
    );
}

test "SYN022: a longer cycle is reported once even with a job leading into it" {
    const source =
        \\on: push
        \\jobs:
        \\  entry:
        \\    needs: [a]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make entry
        \\  a:
        \\    needs: [b]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make a
        \\  b:
        \\    needs: [c]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make b
        \\  c:
        \\    needs: [a]
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make c
    ;
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    try runOn(source, &list);

    try testing.expectEqual(@as(usize, 1), list.len());
    const diag = list.get(0);
    try testing.expectEqualStrings("SYN022", diag.rule_id);
    try testing.expect(std.mem.indexOf(u8, diag.message, "a -> b -> c -> a") != null);
}

test "SYN021/SYN022: a workflow without any needs produces no diagnostic" {
    try expectClean(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: make
    );
}
