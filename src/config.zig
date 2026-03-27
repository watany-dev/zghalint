const std = @import("std");
const yaml_parser = @import("yaml/parser.zig");
const yaml_types = @import("yaml/types.zig");
const diagnostics = @import("diagnostics.zig");

const Node = yaml_types.Node;
const Mapping = yaml_types.Mapping;
const Severity = diagnostics.Severity;

pub const OutputFormat = enum {
    terminal,
    json,
    sarif,

    pub fn fromString(s: []const u8) ?OutputFormat {
        if (std.mem.eql(u8, s, "terminal")) return .terminal;
        if (std.mem.eql(u8, s, "json")) return .json;
        if (std.mem.eql(u8, s, "sarif")) return .sarif;
        return null;
    }
};

pub const ColorMode = enum {
    auto,
    always,
    never,

    pub fn fromString(s: []const u8) ?ColorMode {
        if (std.mem.eql(u8, s, "auto")) return .auto;
        if (std.mem.eql(u8, s, "always")) return .always;
        if (std.mem.eql(u8, s, "never")) return .never;
        return null;
    }
};

pub const RuleOverride = struct {
    severity: ?Severity = null,
    enabled: bool = true,
};

pub const Config = struct {
    rule_overrides: std.StringHashMap(RuleOverride),
    ignore_patterns: std.ArrayList([]const u8),
    output_format: OutputFormat = .terminal,
    color_mode: ColorMode = .auto,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Config {
        return .{
            .rule_overrides = std.StringHashMap(RuleOverride).init(allocator),
            .ignore_patterns = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Config) void {
        self.rule_overrides.deinit();
        self.ignore_patterns.deinit(self.allocator);
    }

    pub fn isRuleEnabled(self: *const Config, rule_id: []const u8) bool {
        if (self.rule_overrides.get(rule_id)) |override| {
            return override.enabled;
        }
        return true;
    }

    pub fn getEffectiveSeverity(self: *const Config, rule_id: []const u8, default: Severity) Severity {
        if (self.rule_overrides.get(rule_id)) |override| {
            return override.severity orelse default;
        }
        return default;
    }

    pub fn isIgnored(self: *const Config, path: []const u8) bool {
        for (self.ignore_patterns.items) |pattern| {
            if (matchGlob(pattern, path)) return true;
        }
        return false;
    }
};

pub const ConfigError = error{
    InvalidYaml,
    InvalidConfig,
    OutOfMemory,
};

/// Parse a .zghalint.yml config from source text.
pub fn parseConfig(allocator: std.mem.Allocator, source: []const u8) ConfigError!Config {
    var parser = yaml_parser.Parser.init(allocator, source);
    defer parser.deinit();

    const node = parser.parse() catch return ConfigError.InvalidYaml;

    return parseConfigFromNode(allocator, node);
}

fn parseConfigFromNode(allocator: std.mem.Allocator, node: Node) ConfigError!Config {
    var config = Config.init(allocator);
    errdefer config.deinit();

    const root = switch (node) {
        .mapping => |m| m,
        .null_value => return config,
        else => return ConfigError.InvalidConfig,
    };

    // Parse "rules" section
    if (root.get("rules")) |rules_node| {
        switch (rules_node) {
            .mapping => |m| {
                for (m.entries) |entry| {
                    const rule_id = entry.key.value;
                    var override = RuleOverride{};

                    switch (entry.value) {
                        .mapping => |rule_map| {
                            if (rule_map.getScalar("severity")) |sev_str| {
                                override.severity = parseSeverity(sev_str);
                            }
                            if (rule_map.getScalar("enabled")) |en_str| {
                                override.enabled = parseBool(en_str);
                            }
                        },
                        else => {},
                    }

                    config.rule_overrides.put(rule_id, override) catch return ConfigError.OutOfMemory;
                }
            },
            else => {},
        }
    }

    // Parse "ignore" section
    if (root.get("ignore")) |ignore_node| {
        switch (ignore_node) {
            .sequence => |seq| {
                for (seq.items) |item| {
                    switch (item) {
                        .scalar => |s| {
                            config.ignore_patterns.append(allocator, s.value) catch return ConfigError.OutOfMemory;
                        },
                        else => {},
                    }
                }
            },
            else => {},
        }
    }

    // Parse "output" section
    if (root.get("output")) |output_node| {
        switch (output_node) {
            .mapping => |m| {
                if (m.getScalar("format")) |fmt_str| {
                    if (OutputFormat.fromString(fmt_str)) |fmt| {
                        config.output_format = fmt;
                    }
                }
                if (m.getScalar("color")) |color_str| {
                    if (ColorMode.fromString(color_str)) |mode| {
                        config.color_mode = mode;
                    }
                }
            },
            else => {},
        }
    }

    return config;
}

fn parseSeverity(s: []const u8) ?Severity {
    if (std.mem.eql(u8, s, "error")) return .@"error";
    if (std.mem.eql(u8, s, "warning")) return .warning;
    if (std.mem.eql(u8, s, "info")) return .info;
    if (std.mem.eql(u8, s, "hint")) return .hint;
    return null;
}

fn parseBool(s: []const u8) bool {
    if (std.mem.eql(u8, s, "false")) return false;
    if (std.mem.eql(u8, s, "no")) return false;
    return true;
}

/// Simple glob matching supporting '*' wildcards.
fn matchGlob(pattern: []const u8, str: []const u8) bool {
    var pi: usize = 0;
    var si: usize = 0;
    var star_pi: ?usize = null;
    var star_si: usize = 0;

    while (si < str.len) {
        if (pi < pattern.len and (pattern[pi] == str[si] or pattern[pi] == '?')) {
            pi += 1;
            si += 1;
        } else if (pi < pattern.len and pattern[pi] == '*') {
            star_pi = pi;
            star_si = si;
            pi += 1;
        } else if (star_pi) |sp| {
            pi = sp + 1;
            star_si += 1;
            si = star_si;
        } else {
            return false;
        }
    }

    while (pi < pattern.len and pattern[pi] == '*') {
        pi += 1;
    }

    return pi == pattern.len;
}

/// Find .zghalint.yml by searching from the given directory upwards.
pub fn findConfigFile(start_dir: []const u8) ?[]const u8 {
    // We just check the given directory for .zghalint.yml
    // In a real implementation we'd walk upward, but for simplicity
    // we check a fixed name in the start directory.
    _ = start_dir;
    const path = ".zghalint.yml";
    std.fs.cwd().access(path, .{}) catch return null;
    return path;
}

// ============================================================
// Tests
// ============================================================

test "parse empty config" {
    var config = try parseConfig(std.testing.allocator, "");
    defer config.deinit();

    try std.testing.expectEqual(OutputFormat.terminal, config.output_format);
    try std.testing.expectEqual(ColorMode.auto, config.color_mode);
    try std.testing.expectEqual(@as(usize, 0), config.ignore_patterns.items.len);
}

test "parse config with rules" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\rules:
        \\  SEC001:
        \\    severity: error
        \\  BP002:
        \\    enabled: false
    ;

    var config = try parseConfig(arena.allocator(), source);
    defer config.deinit();

    try std.testing.expect(!config.isRuleEnabled("BP002"));
    try std.testing.expect(config.isRuleEnabled("SEC001"));
    try std.testing.expectEqual(Severity.@"error", config.getEffectiveSeverity("SEC001", .warning));
}

test "parse config with ignore patterns" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\ignore:
        \\  - '.github/workflows/legacy-*.yml'
        \\  - 'test/*.yml'
    ;

    var config = try parseConfig(arena.allocator(), source);
    defer config.deinit();

    try std.testing.expectEqual(@as(usize, 2), config.ignore_patterns.items.len);
}

test "parse config with output section" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\output:
        \\  format: json
        \\  color: never
    ;

    var config = try parseConfig(arena.allocator(), source);
    defer config.deinit();

    try std.testing.expectEqual(OutputFormat.json, config.output_format);
    try std.testing.expectEqual(ColorMode.never, config.color_mode);
}

test "parse full config" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\rules:
        \\  SEC001:
        \\    severity: error
        \\  BP002:
        \\    enabled: false
        \\ignore:
        \\  - '.github/workflows/legacy-*.yml'
        \\output:
        \\  format: terminal
        \\  color: auto
    ;

    var config = try parseConfig(arena.allocator(), source);
    defer config.deinit();

    try std.testing.expect(!config.isRuleEnabled("BP002"));
    try std.testing.expectEqual(Severity.@"error", config.getEffectiveSeverity("SEC001", .warning));
    try std.testing.expectEqual(@as(usize, 1), config.ignore_patterns.items.len);
    try std.testing.expectEqual(OutputFormat.terminal, config.output_format);
    try std.testing.expectEqual(ColorMode.auto, config.color_mode);
}

test "default severity when no override" {
    var config = Config.init(std.testing.allocator);
    defer config.deinit();

    try std.testing.expectEqual(Severity.warning, config.getEffectiveSeverity("SEC001", .warning));
}

test "isRuleEnabled returns true by default" {
    var config = Config.init(std.testing.allocator);
    defer config.deinit();

    try std.testing.expect(config.isRuleEnabled("UNKNOWN_RULE"));
}

test "glob matching" {
    // Simple wildcard
    try std.testing.expect(matchGlob("*.yml", "ci.yml"));
    try std.testing.expect(matchGlob("*.yml", "test.yml"));
    try std.testing.expect(!matchGlob("*.yml", "ci.yaml"));

    // Prefix wildcard
    try std.testing.expect(matchGlob("legacy-*", "legacy-deploy.yml"));
    try std.testing.expect(!matchGlob("legacy-*", "ci.yml"));

    // Middle wildcard
    try std.testing.expect(matchGlob("*.workflows/*.yml", ".github/workflows/ci.yml") == false);
    try std.testing.expect(matchGlob(".github/workflows/legacy-*.yml", ".github/workflows/legacy-deploy.yml"));
    try std.testing.expect(!matchGlob(".github/workflows/legacy-*.yml", ".github/workflows/ci.yml"));

    // Exact match
    try std.testing.expect(matchGlob("ci.yml", "ci.yml"));
    try std.testing.expect(!matchGlob("ci.yml", "cd.yml"));
}

test "isIgnored matches patterns" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\ignore:
        \\  - '.github/workflows/legacy-*.yml'
    ;

    var config = try parseConfig(arena.allocator(), source);
    defer config.deinit();

    try std.testing.expect(config.isIgnored(".github/workflows/legacy-deploy.yml"));
    try std.testing.expect(!config.isIgnored(".github/workflows/ci.yml"));
}

test "parse config with sarif format" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\output:
        \\  format: sarif
    ;

    var config = try parseConfig(arena.allocator(), source);
    defer config.deinit();

    try std.testing.expectEqual(OutputFormat.sarif, config.output_format);
}

test "OutputFormat fromString" {
    try std.testing.expectEqual(OutputFormat.terminal, OutputFormat.fromString("terminal").?);
    try std.testing.expectEqual(OutputFormat.json, OutputFormat.fromString("json").?);
    try std.testing.expectEqual(OutputFormat.sarif, OutputFormat.fromString("sarif").?);
    try std.testing.expect(OutputFormat.fromString("invalid") == null);
}

test "ColorMode fromString" {
    try std.testing.expectEqual(ColorMode.auto, ColorMode.fromString("auto").?);
    try std.testing.expectEqual(ColorMode.always, ColorMode.fromString("always").?);
    try std.testing.expectEqual(ColorMode.never, ColorMode.fromString("never").?);
    try std.testing.expect(ColorMode.fromString("invalid") == null);
}

test "rule override with severity only" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\rules:
        \\  SEC001:
        \\    severity: info
    ;

    var config = try parseConfig(arena.allocator(), source);
    defer config.deinit();

    try std.testing.expect(config.isRuleEnabled("SEC001"));
    try std.testing.expectEqual(Severity.info, config.getEffectiveSeverity("SEC001", .@"error"));
}

test "rule override with enabled only" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\rules:
        \\  BP001:
        \\    enabled: false
    ;

    var config = try parseConfig(arena.allocator(), source);
    defer config.deinit();

    try std.testing.expect(!config.isRuleEnabled("BP001"));
    // No severity override, should return default
    try std.testing.expectEqual(Severity.warning, config.getEffectiveSeverity("BP001", .warning));
}
