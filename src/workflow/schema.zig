const std = @import("std");
const yaml = @import("../yaml/types.zig");

pub const UnknownKey = struct {
    key: []const u8,
    section: []const u8,
    span: yaml.Span,
    expected: []const []const u8,
};

pub const workflow_keys = [_][]const u8{
    "concurrency",
    "defaults",
    "env",
    "jobs",
    "name",
    "on",
    "permissions",
    "run-name",
};

/// YAML 1.1 may parse a bare `on:` key as boolean `true`. Accept it during
/// collection so the trigger is not reported as unknown, but never include it
/// in user-facing "expected one of" lists.
pub const workflow_on_key_alias = "true";

pub const job_keys = [_][]const u8{
    "concurrency",
    "container",
    "continue-on-error",
    "defaults",
    "env",
    "environment",
    "if",
    "name",
    "needs",
    "outputs",
    "permissions",
    "runs-on",
    "secrets",
    "services",
    "snapshot",
    "steps",
    "strategy",
    "timeout-minutes",
    "uses",
    "with",
};

pub const step_action_keys = [_][]const u8{
    "continue-on-error",
    "env",
    "id",
    "if",
    "name",
    "timeout-minutes",
    "uses",
    "with",
};

pub const step_run_keys = [_][]const u8{
    "continue-on-error",
    "env",
    "id",
    "if",
    "name",
    "run",
    "shell",
    "timeout-minutes",
    "working-directory",
};

pub const step_all_keys = [_][]const u8{
    "continue-on-error",
    "env",
    "id",
    "if",
    "name",
    "run",
    "shell",
    "timeout-minutes",
    "uses",
    "with",
    "working-directory",
};

pub const strategy_keys = [_][]const u8{
    "fail-fast",
    "matrix",
    "max-parallel",
};

pub const defaults_keys = [_][]const u8{
    "run",
};

pub const defaults_run_keys = [_][]const u8{
    "shell",
    "working-directory",
};

pub const container_keys = [_][]const u8{
    "credentials",
    "env",
    "image",
    "options",
    "ports",
    "volumes",
};

pub const service_container_keys = [_][]const u8{
    "command",
    "credentials",
    "entrypoint",
    "env",
    "image",
    "options",
    "ports",
    "volumes",
};

pub fn isAllowedKey(key: []const u8, allowed: []const []const u8) bool {
    for (allowed) |candidate| {
        if (std.mem.eql(u8, key, candidate)) return true;
    }
    return false;
}

pub fn stepExpectedKeys(m: yaml.Mapping) []const []const u8 {
    const has_run = m.get("run") != null;
    const has_uses = m.get("uses") != null;
    if (has_run) return &step_run_keys;
    if (has_uses) return &step_action_keys;
    return &step_all_keys;
}

pub const UnknownKeyCollector = struct {
    list: std.ArrayList(UnknownKey),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) UnknownKeyCollector {
        return .{
            .list = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *UnknownKeyCollector) void {
        self.list.deinit(self.allocator);
    }

    pub fn toOwnedSlice(self: *UnknownKeyCollector) ![]const UnknownKey {
        return try self.list.toOwnedSlice(self.allocator);
    }

    pub fn checkMapping(
        self: *UnknownKeyCollector,
        m: yaml.Mapping,
        section: []const u8,
        allowed: []const []const u8,
        excluded: []const []const u8,
    ) !void {
        for (m.entries) |entry| {
            if (isAllowedKey(entry.key.value, allowed)) continue;
            if (isAllowedKey(entry.key.value, excluded)) continue;
            try self.list.append(self.allocator, .{
                .key = entry.key.value,
                .section = section,
                .span = entry.key.span,
                .expected = allowed,
            });
        }
    }

    pub fn checkDefaults(self: *UnknownKeyCollector, node: yaml.Node) !void {
        const m = switch (node) {
            .mapping => |mp| mp,
            else => return,
        };
        try self.checkMapping(m, "defaults", &defaults_keys, &.{});
        if (m.get("run")) |run_node| {
            const run_mapping = switch (run_node) {
                .mapping => |mp| mp,
                else => return,
            };
            try self.checkMapping(run_mapping, "run", &defaults_run_keys, &.{});
        }
    }

    pub fn checkContainer(self: *UnknownKeyCollector, node: yaml.Node, section: []const u8) !void {
        const allowed: []const []const u8 = if (std.mem.eql(u8, section, "services"))
            &service_container_keys
        else
            &container_keys;

        switch (node) {
            .scalar => {},
            .mapping => |mp| try self.checkMapping(mp, section, allowed, &.{}),
            else => {},
        }
    }
};

test "schema key tables are sorted" {
    const tables = [_][]const []const u8{
        &workflow_keys,
        &job_keys,
        &step_action_keys,
        &step_run_keys,
        &step_all_keys,
        &strategy_keys,
        &defaults_keys,
        &defaults_run_keys,
        &container_keys,
        &service_container_keys,
    };
    for (tables) |keys| {
        var i: usize = 1;
        while (i < keys.len) : (i += 1) {
            try std.testing.expectEqual(std.math.Order.lt, std.mem.order(u8, keys[i - 1], keys[i]));
        }
    }
}

test "isAllowedKey exact match" {
    try std.testing.expect(isAllowedKey("runs-on", &job_keys));
    try std.testing.expect(!isAllowedKey("runs-on", &step_run_keys));
    try std.testing.expect(!isAllowedKey("Shell", &step_run_keys));
    try std.testing.expect(!isAllowedKey(workflow_on_key_alias, &workflow_keys));
}

test "stepExpectedKeys prefers run over uses" {
    var entries = [_]yaml.MappingEntry{
        .{
            .key = .{ .value = "run", .style = .plain, .span = yaml.Span.point(1, 1, 0) },
            .value = .{ .scalar = .{ .value = "echo", .style = .plain, .span = yaml.Span.point(1, 1, 0) } },
            .span = yaml.Span.point(1, 1, 0),
        },
        .{
            .key = .{ .value = "uses", .style = .plain, .span = yaml.Span.point(1, 1, 0) },
            .value = .{ .scalar = .{ .value = "actions/checkout@v4", .style = .plain, .span = yaml.Span.point(1, 1, 0) } },
            .span = yaml.Span.point(1, 1, 0),
        },
    };
    const m = yaml.Mapping{ .entries = &entries, .span = yaml.Span.point(1, 1, 0) };
    const keys = stepExpectedKeys(m);
    for (step_run_keys) |key| {
        try std.testing.expect(isAllowedKey(key, keys));
    }
    try std.testing.expect(!isAllowedKey("with", keys));
}
