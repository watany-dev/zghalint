//! Spec-follow catalog for e2e fixtures that track GitHub Actions additions
//! (issue #441).
//!
//! Existing fixtures stay as they are. A `ga*.yml` file added for this track
//! needs a sibling `ga*.yml.meta.yml` so the introduction date, spec URL, and
//! autofix expectation cannot drift out of the fixture. The sidecar is not a
//! second harness: `# zghalint:expect` still owns pass/fail.

const std = @import("std");
const runtime = @import("runtime.zig");
const yaml_parser = @import("yaml/parser.zig");
const diagnostics = @import("diagnostics.zig");

const fixture_dir = "tests/fixtures/e2e";

const required_keys = [_][]const u8{
    "actionlint",
    "autofix",
    "category",
    "ghalint",
    "introduced",
    "kind",
    "runner",
    "spec",
    "zizmor",
};

const competitor_keys = [_][]const u8{ "actionlint", "ghalint", "zizmor" };
const kinds = [_][]const u8{ "invalid", "valid" };
const autofix_values = [_][]const u8{ "none", "safe", "unsafe" };
const support_values = [_][]const u8{ "supported", "unknown", "unsupported" };

const testing = std.testing;

fn listed(value: []const u8, allowed: []const []const u8) bool {
    for (allowed) |item| {
        if (std.mem.eql(u8, value, item)) return true;
    }
    return false;
}

fn isIsoDate(value: []const u8) bool {
    if (value.len != 10 or value[4] != '-' or value[7] != '-') return false;
    for (value, 0..) |c, i| {
        if (i == 4 or i == 7) continue;
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

fn valueOk(key: []const u8, value: []const u8) bool {
    if (std.mem.eql(u8, key, "kind")) return listed(value, &kinds);
    if (std.mem.eql(u8, key, "autofix")) return listed(value, &autofix_values);
    if (std.mem.eql(u8, key, "category")) return std.meta.stringToEnum(diagnostics.Category, value) != null;
    if (listed(key, &competitor_keys)) return listed(value, &support_values);
    if (std.mem.eql(u8, key, "introduced")) return isIsoDate(value);
    return value.len > 0;
}

fn isGaWorkflow(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "ga") and
        std.mem.endsWith(u8, name, ".yml") and
        !std.mem.endsWith(u8, name, ".meta.yml");
}

fn isGaSidecar(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "ga") and std.mem.endsWith(u8, name, ".yml.meta.yml");
}

fn fileExists(dir: std.Io.Dir, name: []const u8) bool {
    dir.access(runtime.io(), name, .{}) catch return false;
    return true;
}

const Meta = struct {
    autofix: []const u8,
};

fn loadMeta(alloc: std.mem.Allocator, dir: std.Io.Dir, name: []const u8) !Meta {
    const source = try dir.readFileAlloc(runtime.io(), name, alloc, .limited(64 * 1024));
    var parser = yaml_parser.Parser.init(alloc, source);
    const root = parser.parse() catch return error.MetaUnreadable;
    const mapping = switch (root) {
        .mapping => |m| m,
        else => return error.MetaNotAMapping,
    };

    var autofix: []const u8 = &.{};
    for (required_keys) |key| {
        const node = mapping.get(key) orelse {
            std.debug.print("{s}: missing key {s}\n", .{ name, key });
            return error.MetaMissingKey;
        };
        const value = switch (node) {
            .scalar => |s| s.value,
            else => {
                std.debug.print("{s}: {s} must be a scalar\n", .{ name, key });
                return error.MetaValueNotScalar;
            },
        };
        if (!valueOk(key, value)) {
            std.debug.print("{s}: invalid {s} \"{s}\"\n", .{ name, key, value });
            return error.MetaInvalidValue;
        }
        if (std.mem.eql(u8, key, "autofix")) autofix = value;
    }
    return .{ .autofix = autofix };
}

fn checkAutofixSiblings(alloc: std.mem.Allocator, dir: std.Io.Dir, fixture: []const u8, autofix: []const u8) !void {
    const fixed = try std.fmt.allocPrint(alloc, "{s}.fixed", .{fixture});
    const fixed_unsafe = try std.fmt.allocPrint(alloc, "{s}.fixed-unsafe", .{fixture});
    const has_fixed = fileExists(dir, fixed);
    const has_unsafe = fileExists(dir, fixed_unsafe);
    const ok = if (std.mem.eql(u8, autofix, "safe"))
        has_fixed
    else if (std.mem.eql(u8, autofix, "unsafe"))
        has_unsafe
    else
        !has_fixed and !has_unsafe;
    if (ok) return;
    std.debug.print("{s}: autofix {s} does not match .fixed siblings\n", .{ fixture, autofix });
    return error.MetaAutofixMismatch;
}

fn scanCatalog(alloc: std.mem.Allocator, dir: std.Io.Dir) !void {
    var missing: usize = 0;
    var seen: usize = 0;
    var it = dir.iterate();
    while (try it.next(runtime.io())) |entry| {
        if (entry.kind != .file) continue;
        if (!isGaWorkflow(entry.name)) continue;

        seen += 1;
        const meta_name = try std.fmt.allocPrint(alloc, "{s}.meta.yml", .{entry.name});
        const meta = loadMeta(alloc, dir, meta_name) catch |err| switch (err) {
            error.FileNotFound => {
                std.debug.print("{s}: missing {s}\n", .{ entry.name, meta_name });
                missing += 1;
                continue;
            },
            else => return err,
        };
        try checkAutofixSiblings(alloc, dir, entry.name, meta.autofix);
    }

    var orphans: usize = 0;
    it = dir.iterate();
    while (try it.next(runtime.io())) |entry| {
        if (entry.kind != .file) continue;
        if (!isGaSidecar(entry.name)) continue;
        const fixture = entry.name[0 .. entry.name.len - ".meta.yml".len];
        if (fileExists(dir, fixture)) continue;
        std.debug.print("{s}: sidecar has no {s}\n", .{ entry.name, fixture });
        orphans += 1;
    }

    if (orphans != 0) return error.MetaOrphanSidecar;
    if (seen == 0 or missing != 0) return error.GaFixtureMissingCatalog;
}

const valid_meta =
    \\introduced: 2026-01-02
    \\spec: https://example.test/workflow-syntax
    \\runner: github.com
    \\kind: invalid
    \\category: syntax
    \\actionlint: unknown
    \\zizmor: unknown
    \\ghalint: unknown
    \\autofix: none
;

fn write(tmp: *testing.TmpDir, name: []const u8, data: []const u8) !void {
    try tmp.dir.writeFile(runtime.io(), .{ .sub_path = name, .data = data });
}

fn scanTmp(tmp: *testing.TmpDir) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try scanCatalog(arena.allocator(), tmp.dir);
}

test "ga* e2e fixtures have a spec catalog sidecar" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var dir = try std.Io.Dir.cwd().openDir(runtime.io(), fixture_dir, .{ .iterate = true });
    defer dir.close(runtime.io());

    try scanCatalog(arena.allocator(), dir);
}

test "catalog: a valid sidecar pair is accepted" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try write(&tmp, "ga-ok.yml", "on: push\n");
    try write(&tmp, "ga-ok.yml.meta.yml", valid_meta);
    try scanTmp(&tmp);
}

test "catalog: a missing sidecar is rejected" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try write(&tmp, "ga-missing.yml", "on: push\n");
    try testing.expectError(error.GaFixtureMissingCatalog, scanTmp(&tmp));
}

test "catalog: an invalid introduced date is rejected" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try write(&tmp, "ga-date.yml", "on: push\n");
    try write(&tmp, "ga-date.yml.meta.yml",
        \\introduced: aaaa-bb-cc
        \\spec: https://example.test
        \\runner: github.com
        \\kind: invalid
        \\category: syntax
        \\actionlint: unknown
        \\zizmor: unknown
        \\ghalint: unknown
        \\autofix: none
    );
    try testing.expectError(error.MetaInvalidValue, scanTmp(&tmp));
}

test "catalog: autofix safe requires a .fixed sibling" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try write(&tmp, "ga-safe.yml", "on: push\n");
    try write(&tmp, "ga-safe.yml.meta.yml",
        \\introduced: 2026-01-02
        \\spec: https://example.test
        \\runner: github.com
        \\kind: invalid
        \\category: syntax
        \\actionlint: unknown
        \\zizmor: unknown
        \\ghalint: unknown
        \\autofix: safe
    );
    try testing.expectError(error.MetaAutofixMismatch, scanTmp(&tmp));

    try write(&tmp, "ga-safe.yml.fixed", "on: push\n");
    try scanTmp(&tmp);
}

test "catalog: autofix unsafe requires a .fixed-unsafe sibling" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try write(&tmp, "ga-unsafe.yml", "on: push\n");
    try write(&tmp, "ga-unsafe.yml.meta.yml",
        \\introduced: 2026-01-02
        \\spec: https://example.test
        \\runner: github.com
        \\kind: invalid
        \\category: syntax
        \\actionlint: unknown
        \\zizmor: unknown
        \\ghalint: unknown
        \\autofix: unsafe
    );
    try testing.expectError(error.MetaAutofixMismatch, scanTmp(&tmp));

    try write(&tmp, "ga-unsafe.yml.fixed-unsafe", "on: push\n");
    try scanTmp(&tmp);
}

test "catalog: autofix none rejects a leftover .fixed sibling" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try write(&tmp, "ga-none.yml", "on: push\n");
    try write(&tmp, "ga-none.yml.meta.yml", valid_meta);
    try write(&tmp, "ga-none.yml.fixed", "on: push\n");
    try testing.expectError(error.MetaAutofixMismatch, scanTmp(&tmp));
}

test "catalog: an orphan sidecar is rejected" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try write(&tmp, "ga-orphan.yml.meta.yml", valid_meta);
    try testing.expectError(error.MetaOrphanSidecar, scanTmp(&tmp));
}

test "catalog: a sidecar missing a required key is rejected" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try write(&tmp, "ga-key.yml", "on: push\n");
    try write(&tmp, "ga-key.yml.meta.yml",
        \\introduced: 2026-01-02
        \\runner: github.com
        \\kind: invalid
        \\category: syntax
        \\actionlint: unknown
        \\zizmor: unknown
        \\ghalint: unknown
        \\autofix: none
    );
    try testing.expectError(error.MetaMissingKey, scanTmp(&tmp));
}
