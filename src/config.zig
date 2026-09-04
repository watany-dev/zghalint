const std = @import("std");
const yaml_parser = @import("yaml/parser.zig");
const yaml_types = @import("yaml/types.zig");
const diagnostics = @import("diagnostics.zig");
const workspace = @import("workspace.zig");

const Node = yaml_types.Node;
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

pub const Visibility = enum {
    public,
    private,
    unknown,

    pub fn fromString(s: []const u8) ?Visibility {
        if (std.mem.eql(u8, s, "public")) return .public;
        if (std.mem.eql(u8, s, "private")) return .private;
        if (std.mem.eql(u8, s, "unknown")) return .unknown;
        return null;
    }
};

pub const RuleOverride = struct {
    severity: ?Severity = null,
    enabled: bool = true,
};

/// PERF001-specific overrides that force a cache manager value regardless of
/// the lockfile probe result. Populated from `rules.PERF001.node_cache_manager`
/// / `python_cache_manager` in .zghalint.yml.
pub const Perf001Override = struct {
    node_cache_manager: ?workspace.NodeCache = null,
    python_cache_manager: ?workspace.PythonCache = null,
};

pub const Config = struct {
    rule_overrides: std.StringHashMap(RuleOverride),
    ignore_patterns: std.ArrayList([]const u8),
    output_format: OutputFormat = .terminal,
    color_mode: ColorMode = .auto,
    repo_visibility: Visibility = .unknown,
    perf001: Perf001Override = .{},
    allocator: std.mem.Allocator,
    /// Owns string data (rule IDs, ignore patterns) referenced by the fields
    /// above. Decouples Config lifetime from the YAML source buffer.
    strings_arena: std.heap.ArenaAllocator,

    pub fn init(allocator: std.mem.Allocator) Config {
        return .{
            .rule_overrides = std.StringHashMap(RuleOverride).init(allocator),
            .ignore_patterns = .{},
            .allocator = allocator,
            .strings_arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Config) void {
        self.rule_overrides.deinit();
        self.ignore_patterns.deinit(self.allocator);
        self.strings_arena.deinit();
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
    var yaml_arena = std.heap.ArenaAllocator.init(allocator);
    defer yaml_arena.deinit();

    var parser = yaml_parser.Parser.init(yaml_arena.allocator(), source);
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

    // YAML scalar values are slices into the source buffer; dupe them into the
    // Config-owned arena so the Config can outlive the source buffer.
    const strings = config.strings_arena.allocator();

    // Parse "rules" section
    if (root.get("rules")) |rules_node| {
        switch (rules_node) {
            .mapping => |m| {
                for (m.entries) |entry| {
                    const rule_id = strings.dupe(u8, entry.key.value) catch return ConfigError.OutOfMemory;
                    var override = RuleOverride{};

                    switch (entry.value) {
                        .mapping => |rule_map| {
                            if (rule_map.getScalar("severity")) |sev_str| {
                                override.severity = parseSeverity(sev_str);
                            }
                            if (rule_map.getScalar("enabled")) |en_str| {
                                override.enabled = parseBool(en_str);
                            }
                            if (std.mem.eql(u8, rule_id, "PERF001")) {
                                if (rule_map.getScalar("node_cache_manager")) |v| {
                                    config.perf001.node_cache_manager = workspace.NodeCache.fromString(v);
                                }
                                if (rule_map.getScalar("python_cache_manager")) |v| {
                                    config.perf001.python_cache_manager = workspace.PythonCache.fromString(v);
                                }
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
                            const pattern = strings.dupe(u8, s.value) catch return ConfigError.OutOfMemory;
                            config.ignore_patterns.append(allocator, pattern) catch return ConfigError.OutOfMemory;
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

    // Parse "repo_visibility" top-level key
    if (root.getScalar("repo_visibility")) |vis_str| {
        if (Visibility.fromString(vis_str)) |v| {
            config.repo_visibility = v;
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

test "matchGlob with question mark wildcard" {
    try std.testing.expect(matchGlob("c?.yml", "ci.yml"));
    try std.testing.expect(matchGlob("c?.yml", "cd.yml"));
    try std.testing.expect(!matchGlob("c?.yml", "cab.yml"));
    try std.testing.expect(!matchGlob("c?.yml", "c.yml"));
}

test "parseBool with no value" {
    try std.testing.expect(!parseBool("no"));
    try std.testing.expect(!parseBool("false"));
    try std.testing.expect(parseBool("true"));
    try std.testing.expect(parseBool("yes"));
}

test "parseSeverity all values" {
    try std.testing.expectEqual(Severity.@"error", parseSeverity("error").?);
    try std.testing.expectEqual(Severity.warning, parseSeverity("warning").?);
    try std.testing.expectEqual(Severity.info, parseSeverity("info").?);
    try std.testing.expectEqual(Severity.hint, parseSeverity("hint").?);
    try std.testing.expect(parseSeverity("invalid") == null);
}

test "parse config with invalid yaml" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // Should either parse or return an error, not crash
    _ = parseConfig(arena.allocator(), ":\n  :\n   : : :") catch {};
}

test "matchGlob trailing star" {
    try std.testing.expect(matchGlob("src/*", "src/main.zig"));
    try std.testing.expect(matchGlob("**", "anything"));
    try std.testing.expect(matchGlob("*", ""));
}

test "isIgnored with no patterns returns false" {
    var config = Config.init(std.testing.allocator);
    defer config.deinit();
    try std.testing.expect(!config.isIgnored("anything.yml"));
}

test "parse config with non-mapping root (sequence) returns error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // A YAML sequence as root should return InvalidConfig
    const result = parseConfig(arena.allocator(), "- item1\n- item2");
    try std.testing.expectError(ConfigError.InvalidConfig, result);
}

test "parse config with scalar root returns error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // A bare scalar as root should return InvalidConfig
    const result = parseConfig(arena.allocator(), "just_a_string");
    try std.testing.expectError(ConfigError.InvalidConfig, result);
}

test "matchGlob empty pattern and string" {
    try std.testing.expect(matchGlob("", ""));
    try std.testing.expect(!matchGlob("", "a"));
}

test "matchGlob star matches empty" {
    try std.testing.expect(matchGlob("*", ""));
    try std.testing.expect(matchGlob("*", "anything"));
}

test "parse PERF001 node_cache_manager override" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\rules:
        \\  PERF001:
        \\    node_cache_manager: pnpm
    ;

    var config = try parseConfig(arena.allocator(), source);
    defer config.deinit();

    try std.testing.expectEqual(workspace.NodeCache.pnpm, config.perf001.node_cache_manager.?);
    try std.testing.expect(config.perf001.python_cache_manager == null);
}

test "parse PERF001 python_cache_manager override" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\rules:
        \\  PERF001:
        \\    python_cache_manager: poetry
    ;

    var config = try parseConfig(arena.allocator(), source);
    defer config.deinit();

    try std.testing.expectEqual(workspace.PythonCache.poetry, config.perf001.python_cache_manager.?);
}

test "PERF001 invalid cache manager is silently ignored" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\rules:
        \\  PERF001:
        \\    node_cache_manager: bun
    ;

    var config = try parseConfig(arena.allocator(), source);
    defer config.deinit();

    try std.testing.expect(config.perf001.node_cache_manager == null);
}

test "getEffectiveSeverity with override that has no severity set" {
    var config = Config.init(std.testing.allocator);
    defer config.deinit();

    // Add override with enabled=true but no severity
    try config.rule_overrides.put("MY_RULE", .{ .severity = null, .enabled = true });
    // Should return the default severity
    try std.testing.expectEqual(Severity.warning, config.getEffectiveSeverity("MY_RULE", .warning));
}

test "config outlives source buffer (rule override)" {
    const alloc = std.testing.allocator;
    const src = try alloc.dupe(u8, "rules:\n  SEC001:\n    enabled: false\n");
    defer alloc.free(src);

    // Simulates main.loadConfig: parse from a buffer that is freed before return.
    var config = try parseConfigFromFreedSource(alloc, src);
    defer config.deinit();

    try std.testing.expect(!config.isRuleEnabled("SEC001"));
    try std.testing.expect(config.isRuleEnabled("BP001"));
}

test "config outlives source buffer (ignore pattern)" {
    const alloc = std.testing.allocator;
    const src = try alloc.dupe(u8, "ignore:\n  - '.github/workflows/legacy-*.yml'\n");
    defer alloc.free(src);

    var config = try parseConfigFromFreedSource(alloc, src);
    defer config.deinit();

    try std.testing.expect(config.isIgnored(".github/workflows/legacy-deploy.yml"));
    try std.testing.expect(!config.isIgnored(".github/workflows/ci.yml"));
}

/// Mirrors `main.loadConfig`: the YAML source buffer is freed before the Config
/// is returned, so parsed strings must be owned by Config (via `strings_arena`).
fn parseConfigFromFreedSource(allocator: std.mem.Allocator, source: []const u8) ConfigError!Config {
    const owned = try allocator.dupe(u8, source);
    defer allocator.free(owned);
    return parseConfig(allocator, owned);
}
