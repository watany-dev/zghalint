const std = @import("std");

/// Package manager that actions/setup-node supports for its `cache` input.
pub const NodeCache = enum {
    npm,
    yarn,
    pnpm,

    pub fn toString(self: NodeCache) []const u8 {
        return @tagName(self);
    }

    pub fn fromString(s: []const u8) ?NodeCache {
        return std.meta.stringToEnum(NodeCache, s);
    }
};

/// Package manager that actions/setup-python supports for its `cache` input.
pub const PythonCache = enum {
    pip,
    pipenv,
    poetry,

    pub fn toString(self: PythonCache) []const u8 {
        return @tagName(self);
    }

    pub fn fromString(s: []const u8) ?PythonCache {
        return std.meta.stringToEnum(PythonCache, s);
    }
};

/// Strings (ambiguous lockfile names) are borrowed from a caller-owned arena;
/// the Context itself is POD.
pub const Context = struct {
    node_cache: ?NodeCache = null,
    python_cache: ?PythonCache = null,
    go_sum_present: bool = false,
    bun_lockfile_present: bool = false,
    ambiguous_node_lockfiles: []const []const u8 = &.{},
    ambiguous_python_lockfiles: []const []const u8 = &.{},
};

/// Mirrors the `engine.network_deadline_ns` pattern: a module-scope variable
/// kept simple because tests set/clear it directly and production runs
/// initialize it before any rule executes.
pub var current: Context = .{};

pub fn set(ctx: Context) void {
    current = ctx;
}

pub fn clear() void {
    current = .{};
}

const node_lockfiles = [_]struct {
    name: []const u8,
    manager: NodeCache,
}{
    .{ .name = "package-lock.json", .manager = .npm },
    .{ .name = "npm-shrinkwrap.json", .manager = .npm },
    .{ .name = "yarn.lock", .manager = .yarn },
    .{ .name = "pnpm-lock.yaml", .manager = .pnpm },
};

const python_lockfiles = [_]struct {
    name: []const u8,
    manager: PythonCache,
}{
    .{ .name = "Pipfile.lock", .manager = .pipenv },
    .{ .name = "poetry.lock", .manager = .poetry },
    .{ .name = "requirements.txt", .manager = .pip },
};

pub fn findWorkspaceRoot(allocator: std.mem.Allocator, hint_path: []const u8) ![]const u8 {
    // Resolve to an absolute path so walking parent directories terminates.
    const abs = std.fs.cwd().realpathAlloc(allocator, hint_path) catch |err| switch (err) {
        error.FileNotFound, error.AccessDenied => return fallbackCwd(allocator),
        else => return err,
    };
    defer allocator.free(abs);

    var dir = std.fs.path.dirname(abs) orelse return fallbackCwd(allocator);

    while (true) {
        const candidate = try std.fs.path.join(allocator, &.{ dir, ".git" });
        defer allocator.free(candidate);

        if (std.fs.accessAbsolute(candidate, .{})) |_| {
            return try allocator.dupe(u8, dir);
        } else |_| {}

        const parent = std.fs.path.dirname(dir) orelse break;
        if (std.mem.eql(u8, parent, dir)) break;
        dir = parent;
    }

    return fallbackCwd(allocator);
}

fn fallbackCwd(allocator: std.mem.Allocator) ![]const u8 {
    return std.fs.cwd().realpathAlloc(allocator, ".") catch |err| switch (err) {
        error.FileNotFound, error.AccessDenied => try allocator.dupe(u8, "."),
        else => err,
    };
}

/// FS access errors are treated uniformly as "absent"; errno distinctions are
/// intentionally ignored to keep probe behavior deterministic.
///
/// Strings in the returned Context's `ambiguous_*_lockfiles` are allocated in
/// `allocator`, so callers pair this with an arena that lives for the lint run.
pub fn detectFromRoot(allocator: std.mem.Allocator, root: []const u8) !Context {
    var dir = std.fs.openDirAbsolute(root, .{ .iterate = true }) catch {
        return Context{};
    };
    defer dir.close();

    // One getdents sweep instead of one `access` syscall per candidate.
    const present = scanRoot(&dir);

    var node_found = std.ArrayList([]const u8){};
    defer node_found.deinit(allocator);
    var node_manager_set = std.EnumSet(NodeCache).initEmpty();

    // Iterated in table order so an ambiguity hint lists lockfiles
    // deterministically regardless of directory iteration order.
    for (node_lockfiles, 0..) |entry, i| {
        if (!present.node.isSet(i)) continue;
        try node_found.append(allocator, entry.name);
        node_manager_set.insert(entry.manager);
    }

    var python_found = std.ArrayList([]const u8){};
    defer python_found.deinit(allocator);
    var python_manager_set = std.EnumSet(PythonCache).initEmpty();

    for (python_lockfiles, 0..) |entry, i| {
        if (!present.python.isSet(i)) continue;
        try python_found.append(allocator, entry.name);
        python_manager_set.insert(entry.manager);
    }

    var ctx = Context{
        .go_sum_present = present.go_sum,
        .bun_lockfile_present = present.bun,
    };

    const node_unique = node_manager_set.count();
    if (node_unique == 1) {
        var it = node_manager_set.iterator();
        ctx.node_cache = it.next().?;
    } else if (node_unique > 1) {
        ctx.ambiguous_node_lockfiles = try dupeLockfiles(allocator, node_found.items);
    }

    const python_unique = python_manager_set.count();
    if (python_unique == 1) {
        var it = python_manager_set.iterator();
        ctx.python_cache = it.next().?;
    } else if (python_unique > 1) {
        ctx.ambiguous_python_lockfiles = try dupeLockfiles(allocator, python_found.items);
    }

    return ctx;
}

/// Which of the probed candidates exist in the workspace root. Bit `i`
/// corresponds to index `i` of the matching lockfile table.
const RootEntries = struct {
    node: std.StaticBitSet(node_lockfiles.len) = std.StaticBitSet(node_lockfiles.len).initEmpty(),
    python: std.StaticBitSet(python_lockfiles.len) = std.StaticBitSet(python_lockfiles.len).initEmpty(),
    go_sum: bool = false,
    bun: bool = false,
};

fn scanRoot(dir: *std.fs.Dir) RootEntries {
    var present: RootEntries = .{};

    var it = dir.iterate();
    while (true) {
        // A half-read directory could hide one lockfile of an ambiguous pair and
        // turn the hint into a confident wrong answer, so a failed sweep reports
        // nothing rather than what it managed to collect.
        const entry = (it.next() catch return .{}) orelse break;

        for (node_lockfiles, 0..) |candidate, i| {
            if (matches(dir, entry, candidate.name)) present.node.set(i);
        }
        for (python_lockfiles, 0..) |candidate, i| {
            if (matches(dir, entry, candidate.name)) present.python.set(i);
        }
        if (matches(dir, entry, "go.sum")) present.go_sum = true;
        if (matches(dir, entry, "bun.lock") or matches(dir, entry, "bun.lockb")) present.bun = true;
    }

    return present;
}

/// A listing reports dangling symlinks and non-regular entries that the
/// previous `access` probe rejected, so a matching name is only accepted once
/// it is known to resolve to something readable.
fn matches(dir: *std.fs.Dir, entry: std.fs.Dir.Entry, candidate: []const u8) bool {
    if (!std.mem.eql(u8, entry.name, candidate)) return false;
    if (entry.kind == .file) return true;
    if (entry.kind != .sym_link) return false;
    dir.access(entry.name, .{}) catch return false;
    return true;
}

fn dupeLockfiles(allocator: std.mem.Allocator, names: []const []const u8) ![]const []const u8 {
    const out = try allocator.alloc([]const u8, names.len);
    for (names, 0..) |name, i| {
        out[i] = try allocator.dupe(u8, name);
    }
    return out;
}

const testing = std.testing;

test "NodeCache.fromString roundtrip" {
    try testing.expectEqual(NodeCache.npm, NodeCache.fromString("npm").?);
    try testing.expectEqual(NodeCache.yarn, NodeCache.fromString("yarn").?);
    try testing.expectEqual(NodeCache.pnpm, NodeCache.fromString("pnpm").?);
    try testing.expect(NodeCache.fromString("bun") == null);
}

test "PythonCache.fromString roundtrip" {
    try testing.expectEqual(PythonCache.pip, PythonCache.fromString("pip").?);
    try testing.expectEqual(PythonCache.pipenv, PythonCache.fromString("pipenv").?);
    try testing.expectEqual(PythonCache.poetry, PythonCache.fromString("poetry").?);
    try testing.expect(PythonCache.fromString("conda") == null);
}

test "detectFromRoot returns empty Context for empty dir" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(abs);

    const ctx = try detectFromRoot(testing.allocator, abs);
    try testing.expect(ctx.node_cache == null);
    try testing.expect(ctx.python_cache == null);
    try testing.expect(!ctx.go_sum_present);
    try testing.expectEqual(@as(usize, 0), ctx.ambiguous_node_lockfiles.len);
}

test "detectFromRoot picks npm when only package-lock.json present" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "package-lock.json", .data = "{}" });

    const abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(abs);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ctx = try detectFromRoot(arena.allocator(), abs);
    try testing.expectEqual(NodeCache.npm, ctx.node_cache.?);
    try testing.expectEqual(@as(usize, 0), ctx.ambiguous_node_lockfiles.len);
}

test "detectFromRoot picks yarn for yarn.lock" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "yarn.lock", .data = "" });

    const abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(abs);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ctx = try detectFromRoot(arena.allocator(), abs);
    try testing.expectEqual(NodeCache.yarn, ctx.node_cache.?);
}

test "detectFromRoot flags ambiguity when multiple node lockfiles exist" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "package-lock.json", .data = "{}" });
    try tmp.dir.writeFile(.{ .sub_path = "yarn.lock", .data = "" });

    const abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(abs);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ctx = try detectFromRoot(arena.allocator(), abs);
    try testing.expect(ctx.node_cache == null);
    try testing.expectEqual(@as(usize, 2), ctx.ambiguous_node_lockfiles.len);
}

test "detectFromRoot identifies python lockfiles" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "poetry.lock", .data = "" });

    const abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(abs);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ctx = try detectFromRoot(arena.allocator(), abs);
    try testing.expectEqual(PythonCache.poetry, ctx.python_cache.?);
}

test "detectFromRoot npm-shrinkwrap aliases to npm without ambiguity" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "package-lock.json", .data = "{}" });
    try tmp.dir.writeFile(.{ .sub_path = "npm-shrinkwrap.json", .data = "{}" });

    const abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(abs);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ctx = try detectFromRoot(arena.allocator(), abs);
    try testing.expectEqual(NodeCache.npm, ctx.node_cache.?);
    try testing.expectEqual(@as(usize, 0), ctx.ambiguous_node_lockfiles.len);
}

test "detectFromRoot detects go.sum" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "go.sum", .data = "" });

    const abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(abs);

    const ctx = try detectFromRoot(testing.allocator, abs);
    try testing.expect(ctx.go_sum_present);
}

test "detectFromRoot detects bun.lock" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "bun.lock", .data = "" });

    const abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(abs);

    const ctx = try detectFromRoot(testing.allocator, abs);
    try testing.expect(ctx.bun_lockfile_present);
}

test "detectFromRoot detects bun.lockb" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "bun.lockb", .data = "" });

    const abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(abs);

    const ctx = try detectFromRoot(testing.allocator, abs);
    try testing.expect(ctx.bun_lockfile_present);
}

test "detectFromRoot leaves bun_lockfile_present false without bun lockfile" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(abs);

    const ctx = try detectFromRoot(testing.allocator, abs);
    try testing.expect(!ctx.bun_lockfile_present);
}

test "detectFromRoot ignores a directory named like a lockfile" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("yarn.lock");

    const abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(abs);

    const ctx = try detectFromRoot(testing.allocator, abs);
    try testing.expect(ctx.node_cache == null);
}

test "detectFromRoot ignores a dangling symlink named like a lockfile" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    tmp.dir.symLink("nowhere", "package-lock.json", .{}) catch return error.SkipZigTest;

    const abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(abs);

    const ctx = try detectFromRoot(testing.allocator, abs);
    try testing.expect(ctx.node_cache == null);
}

test "detectFromRoot follows a symlink that resolves to a lockfile" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "real.json", .data = "{}" });
    tmp.dir.symLink("real.json", "package-lock.json", .{}) catch return error.SkipZigTest;

    const abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(abs);

    const ctx = try detectFromRoot(testing.allocator, abs);
    try testing.expectEqual(NodeCache.npm, ctx.node_cache.?);
}

test "detectFromRoot ambiguity list follows table order, not directory order" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // Written yarn-first so a directory-order-dependent implementation would
    // produce the reversed list.
    try tmp.dir.writeFile(.{ .sub_path = "yarn.lock", .data = "" });
    try tmp.dir.writeFile(.{ .sub_path = "package-lock.json", .data = "{}" });

    const abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(abs);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ctx = try detectFromRoot(arena.allocator(), abs);
    try testing.expectEqual(@as(usize, 2), ctx.ambiguous_node_lockfiles.len);
    try testing.expectEqualStrings("package-lock.json", ctx.ambiguous_node_lockfiles[0]);
    try testing.expectEqualStrings("yarn.lock", ctx.ambiguous_node_lockfiles[1]);
}

test "detectFromRoot returns empty Context for missing dir" {
    const ctx = try detectFromRoot(testing.allocator, "/nonexistent/zghalint/probe");
    try testing.expect(ctx.node_cache == null);
    try testing.expect(!ctx.go_sum_present);
}

test "findWorkspaceRoot returns dir containing .git" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir(".git");
    try tmp.dir.makePath(".github/workflows");
    try tmp.dir.writeFile(.{ .sub_path = ".github/workflows/ci.yml", .data = "name: CI" });

    const hint = try tmp.dir.realpathAlloc(testing.allocator, ".github/workflows/ci.yml");
    defer testing.allocator.free(hint);
    const expected = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(expected);

    const root = try findWorkspaceRoot(testing.allocator, hint);
    defer testing.allocator.free(root);

    try testing.expectEqualStrings(expected, root);
}

test "set and clear manage module state" {
    defer clear();
    set(.{ .node_cache = .npm, .go_sum_present = true });
    try testing.expectEqual(NodeCache.npm, current.node_cache.?);
    try testing.expect(current.go_sum_present);

    clear();
    try testing.expect(current.node_cache == null);
    try testing.expect(!current.go_sum_present);
}
