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

const kinds = [_][]const u8{ "invalid", "valid" };
const autofix_values = [_][]const u8{ "none", "safe", "unsafe" };
const support_values = [_][]const u8{ "supported", "unknown", "unsupported" };
const categories = [_][]const u8{
    "best_practice",
    "dependency",
    "expression",
    "performance",
    "permissions",
    "runner",
    "security",
    "syntax",
};

const testing = std.testing;

fn listed(value: []const u8, allowed: []const []const u8) bool {
    for (allowed) |item| {
        if (std.mem.eql(u8, value, item)) return true;
    }
    return false;
}

fn loadMeta(alloc: std.mem.Allocator, dir: std.Io.Dir, name: []const u8) !void {
    const source = try dir.readFileAlloc(runtime.io(), name, alloc, .limited(64 * 1024));
    var parser = yaml_parser.Parser.init(alloc, source);
    const root = parser.parse() catch return error.MetaUnreadable;
    const mapping = switch (root) {
        .mapping => |m| m,
        else => return error.MetaNotAMapping,
    };

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
        const ok = if (std.mem.eql(u8, key, "kind"))
            listed(value, &kinds)
        else if (std.mem.eql(u8, key, "autofix"))
            listed(value, &autofix_values)
        else if (std.mem.eql(u8, key, "category"))
            listed(value, &categories)
        else if (std.mem.eql(u8, key, "actionlint") or std.mem.eql(u8, key, "zizmor") or std.mem.eql(u8, key, "ghalint"))
            listed(value, &support_values)
        else if (std.mem.eql(u8, key, "introduced"))
            value.len == 10 and value[4] == '-' and value[7] == '-'
        else
            value.len > 0;
        if (!ok) {
            std.debug.print("{s}: invalid {s} \"{s}\"\n", .{ name, key, value });
            return error.MetaInvalidValue;
        }
    }
}

test "ga* e2e fixtures have a spec catalog sidecar" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var dir = try std.Io.Dir.cwd().openDir(runtime.io(), fixture_dir, .{ .iterate = true });
    defer dir.close(runtime.io());

    var it = dir.iterate();
    var missing: usize = 0;
    var seen: usize = 0;
    while (try it.next(runtime.io())) |entry| {
        if (entry.kind != .file) continue;
        const name = entry.name;
        if (!std.mem.startsWith(u8, name, "ga")) continue;
        if (!std.mem.endsWith(u8, name, ".yml")) continue;
        if (std.mem.endsWith(u8, name, ".meta.yml")) continue;
        if (std.mem.indexOf(u8, name, ".fixed") != null) continue;

        seen += 1;
        const meta_name = try std.fmt.allocPrint(alloc, "{s}.meta.yml", .{name});
        dir.access(runtime.io(), meta_name, .{}) catch {
            std.debug.print("{s}/{s}: missing {s}\n", .{ fixture_dir, name, meta_name });
            missing += 1;
            continue;
        };
        try loadMeta(alloc, dir, meta_name);
    }

    try testing.expect(seen > 0);
    if (missing != 0) return error.GaFixtureMissingCatalog;
}
