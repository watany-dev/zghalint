const std = @import("std");
const engine = @import("engine.zig");
const yaml_types = @import("../yaml/types.zig");
const diagnostics_mod = @import("../diagnostics.zig");
const fix_builder = @import("../fix/builder.zig");

const Rule = engine.Rule;
const DiagnosticList = engine.DiagnosticList;
const Node = yaml_types.Node;
const Mapping = yaml_types.Mapping;
const Fix = diagnostics_mod.Fix;

fn buildCooldownFix(list: *DiagnosticList, entry: yaml_types.Mapping) ?Fix {
    if (entry.entries.len == 0) return null;

    // 1-based column → 0-based indent (空白数)
    const indent_col = entry.entries[0].key.span.start_col;
    if (indent_col == 0) return null;
    const indent: u32 = @intCast(indent_col - 1);

    // flow-style entry の場合 full_span が null になる。いずれか 1 つでも欠けて
    // いれば anchor の信頼性が崩れるため fix を付けない。
    var end_byte: usize = 0;
    for (entry.entries) |e| {
        const fs = e.full_span orelse return null;
        end_byte = fs.end_byte;
    }

    const subs = [_]fix_builder.SubEntry{
        .{ .key = "default-days", .value = "7" },
    };

    const edits = fix_builder.insertMappingEntryBlock(
        list.fixAllocator(),
        .{ .byte = end_byte, .indent = indent },
        "cooldown",
        &subs,
        2,
    ) orelse return null;

    return .{
        .description = "insert cooldown block",
        .safety = .unsafe,
        .edits = edits,
    };
}

fn updateEntries(root: Mapping) UpdateEntryIterator {
    const node = root.get("updates") orelse return .{ .items = &.{} };
    return .{ .items = switch (node) {
        .sequence => |seq| seq.items,
        else => &.{},
    } };
}

const UpdateEntryIterator = struct {
    items: []const yaml_types.Node,
    index: usize = 0,

    fn next(self: *UpdateEntryIterator) ?Mapping {
        while (self.index < self.items.len) {
            const item = self.items[self.index];
            self.index += 1;
            switch (item) {
                .mapping => |m| return m,
                else => continue,
            }
        }
        return null;
    }
};

fn checkCooldown(root: Mapping, diag_list: *DiagnosticList) void {
    var it = updateEntries(root);
    while (it.next()) |entry| {
        if (entry.get("cooldown") == null) {
            var diag = diagnostics_mod.Diagnostic{
                .rule_id = "DEP001",
                .severity = .info,
                .message = "Dependabot update is missing 'cooldown' configuration. Without cooldown, Dependabot may create excessive pull requests.",
                .span = entry.span,
                .fix_hint = "Add a 'cooldown' section to throttle update frequency (e.g., cooldown:\n  default-days: 7).",
            };
            diag.fix = buildCooldownFix(diag_list, entry);
            diag_list.append(diag) catch return;
        }
    }
}

fn buildInsecureExecutionFix(
    list: *DiagnosticList,
    value: yaml_types.Scalar,
) ?Fix {
    const edits = fix_builder.replaceScalar(
        list.fixAllocator(),
        value.span,
        value.style,
        "deny",
    ) orelse return null;

    return .{
        .description = "set insecure-external-code-execution to deny",
        .safety = .safe,
        .edits = edits,
    };
}

fn checkInsecureExecution(root: Mapping, diag_list: *DiagnosticList) void {
    var it = updateEntries(root);
    while (it.next()) |entry| {
        for (entry.entries) |map_entry| {
            if (std.mem.eql(u8, map_entry.key.value, "insecure-external-code-execution")) {
                switch (map_entry.value) {
                    .scalar => |s| {
                        if (std.mem.eql(u8, s.value, "allow")) {
                            var diag = diagnostics_mod.Diagnostic{
                                .rule_id = "DEP002",
                                .severity = .warning,
                                .message = "'insecure-external-code-execution: allow' permits running untrusted external code during dependency updates. This is a supply chain attack risk.",
                                .span = map_entry.span,
                                .fix_hint = "Remove 'insecure-external-code-execution: allow' or set it to 'deny'.",
                            };
                            diag.fix = buildInsecureExecutionFix(diag_list, s);
                            diag_list.append(diag) catch return;
                        }
                    },
                    else => {},
                }
                break;
            }
        }
    }
}

pub fn lintDependabot(root: Node, diag_list: *DiagnosticList) void {
    const mapping = switch (root) {
        .mapping => |m| m,
        else => return,
    };
    checkCooldown(mapping, diag_list);
    checkInsecureExecution(mapping, diag_list);
}

pub const rules = [_]Rule{
    .{
        .id = "DEP001",
        .name = "dependabot-cooldown",
        .description = "Dependabot updates should configure a cooldown period to avoid excessive PRs",
        .severity = .info,
        .category = .dependency,
    },
    .{
        .id = "DEP002",
        .name = "dependabot-execution",
        .description = "insecure-external-code-execution: allow is a supply chain attack risk",
        .severity = .warning,
        .category = .dependency,
    },
};

const yaml_parser_mod = @import("../yaml/parser.zig");
const test_support = @import("../test_support.zig");

const hasDiagnostic = test_support.hasDiagnostic;
const findDiagnostic = test_support.findDiagnostic;

fn parseYamlWithArena(arena: *std.heap.ArenaAllocator, source: []const u8) !Node {
    const alloc = arena.allocator();
    var parser = yaml_parser_mod.Parser.init(alloc, source);
    return parser.parse();
}

test "DEP001: detect missing cooldown" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const node = try parseYamlWithArena(&arena,
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    directory: "/"
        \\    schedule:
        \\      interval: "weekly"
    );
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    lintDependabot(node, &diags);

    try std.testing.expect(hasDiagnostic(&diags, "DEP001"));
}

test "DEP001: no warning when cooldown is configured" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const node = try parseYamlWithArena(&arena,
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    directory: "/"
        \\    schedule:
        \\      interval: "weekly"
        \\    cooldown:
        \\      initial-interval: 5
        \\      max-interval: 30
    );
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    lintDependabot(node, &diags);

    for (diags.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "DEP001")) {
            try std.testing.expect(false);
        }
    }
}

test "DEP001: no warning when updates is missing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const node = try parseYamlWithArena(&arena,
        \\version: 2
    );
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    lintDependabot(node, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "DEP001: multiple updates, mixed cooldown" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const node = try parseYamlWithArena(&arena,
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    directory: "/"
        \\    schedule:
        \\      interval: "weekly"
        \\    cooldown:
        \\      initial-interval: 5
        \\  - package-ecosystem: "docker"
        \\    directory: "/"
        \\    schedule:
        \\      interval: "daily"
    );
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    lintDependabot(node, &diags);

    var dep001_count: usize = 0;
    for (diags.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "DEP001")) dep001_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), dep001_count);
}

test "DEP002: detect insecure-external-code-execution allow" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const node = try parseYamlWithArena(&arena,
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    directory: "/"
        \\    schedule:
        \\      interval: "weekly"
        \\    insecure-external-code-execution: allow
    );
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    lintDependabot(node, &diags);

    const d = findDiagnostic(&diags, "DEP002") orelse return error.TestUnexpectedResult;
    try std.testing.expect(d.fix != null);
    const fix = d.fix.?;
    try std.testing.expectEqualStrings("set insecure-external-code-execution to deny", fix.description);
    try std.testing.expect(fix.safety == .safe);
    try std.testing.expectEqual(@as(usize, 1), fix.edits.len);
    try std.testing.expectEqualStrings("deny", fix.edits[0].replacement);
}

test "DEP002: fix preserves single quoted style" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const node = try parseYamlWithArena(&arena,
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    insecure-external-code-execution: 'allow'
    );
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    lintDependabot(node, &diags);

    const d = findDiagnostic(&diags, "DEP002") orelse return error.TestUnexpectedResult;
    const fix = d.fix orelse return error.TestUnexpectedResult;
    // replaceScalar swaps only the inner content between quotes.
    try std.testing.expectEqualStrings("deny", fix.edits[0].replacement);
}

test "DEP002: fix preserves double quoted style" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const node = try parseYamlWithArena(&arena,
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    insecure-external-code-execution: "allow"
    );
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    lintDependabot(node, &diags);

    const d = findDiagnostic(&diags, "DEP002") orelse return error.TestUnexpectedResult;
    const fix = d.fix orelse return error.TestUnexpectedResult;
    // replaceScalar swaps only the inner content between quotes.
    try std.testing.expectEqualStrings("deny", fix.edits[0].replacement);
}

test "DEP002: no warning when set to deny" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const node = try parseYamlWithArena(&arena,
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    directory: "/"
        \\    schedule:
        \\      interval: "weekly"
        \\    insecure-external-code-execution: deny
    );
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    lintDependabot(node, &diags);

    for (diags.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "DEP002")) {
            try std.testing.expect(false);
        }
    }
}

test "DEP002: no warning when key is absent" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const node = try parseYamlWithArena(&arena,
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    directory: "/"
        \\    schedule:
        \\      interval: "weekly"
    );
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    lintDependabot(node, &diags);

    for (diags.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "DEP002")) {
            try std.testing.expect(false);
        }
    }
}

test "DEP002: autofix rewrites allow to deny without disturbing other updates" {
    const source =
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    directory: "/"
        \\    insecure-external-code-execution: allow
        \\  - package-ecosystem: "docker"
        \\    directory: "/"
        \\    insecure-external-code-execution: "allow"
        \\  - package-ecosystem: "github-actions"
        \\    directory: "/"
        \\    insecure-external-code-execution: deny
    ;

    const result = try test_support.lintAndFix(std.testing.allocator, source, .{ .document = &lintDependabot }, false);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), result.fix_count);
    try std.testing.expectEqual(@as(usize, 2), result.edits_applied);
    try std.testing.expectEqualStrings(
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    directory: "/"
        \\    insecure-external-code-execution: deny
        \\  - package-ecosystem: "docker"
        \\    directory: "/"
        \\    insecure-external-code-execution: "deny"
        \\  - package-ecosystem: "github-actions"
        \\    directory: "/"
        \\    insecure-external-code-execution: deny
    ,
        result.content,
    );
}

test "lintDependabot: both rules detected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const node = try parseYamlWithArena(&arena,
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    directory: "/"
        \\    schedule:
        \\      interval: "weekly"
        \\    insecure-external-code-execution: allow
    );
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    lintDependabot(node, &diags);

    var dep001 = false;
    var dep002 = false;
    for (diags.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "DEP001")) dep001 = true;
        if (std.mem.eql(u8, d.rule_id, "DEP002")) dep002 = true;
    }
    try std.testing.expect(dep001);
    try std.testing.expect(dep002);
}

test "lintDependabot: non-mapping root is gracefully handled" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const node = try parseYamlWithArena(&arena,
        \\- item1
        \\- item2
    );
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    lintDependabot(node, &diags);
    try std.testing.expectEqual(@as(usize, 0), diags.len());
}

test "DEP001: fix metadata is attached with .unsafe" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const node = try parseYamlWithArena(&arena,
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    directory: "/"
        \\    schedule:
        \\      interval: "weekly"
    );
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    lintDependabot(node, &diags);

    const d = findDiagnostic(&diags, "DEP001") orelse return error.TestUnexpectedResult;
    const fix = d.fix orelse return error.TestExpectedNonNull;
    try std.testing.expect(fix.safety == .unsafe);
    try std.testing.expectEqualStrings("insert cooldown block", fix.description);
}

test "DEP001: autofix inserts cooldown at end of entry (block form)" {
    const source =
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    directory: "/"
        \\    schedule:
        \\      interval: "weekly"
        \\
    ;

    const result = try test_support.lintAndFix(std.testing.allocator, source, .{ .document = &lintDependabot }, true);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.fix_count);
    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
    try std.testing.expectEqualStrings(
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    directory: "/"
        \\    schedule:
        \\      interval: "weekly"
        \\    cooldown:
        \\      default-days: 7
        \\
    ,
        result.content,
    );
}

test "DEP001: fix is null for flow-style mapping entry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const node = try parseYamlWithArena(&arena,
        \\version: 2
        \\updates:
        \\  - { package-ecosystem: "npm", directory: "/" }
    );
    var diags = DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    lintDependabot(node, &diags);

    const d = findDiagnostic(&diags, "DEP001") orelse return error.TestUnexpectedResult;
    try std.testing.expect(d.fix == null);
}

test "DEP001 + DEP002: coexist on the same entry" {
    const source =
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    directory: "/"
        \\    schedule:
        \\      interval: "weekly"
        \\    insecure-external-code-execution: allow
        \\
    ;

    const result = try test_support.lintAndFix(std.testing.allocator, source, .{ .document = &lintDependabot }, true);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), result.fix_count);
    try std.testing.expectEqual(@as(usize, 2), result.edits_applied);
    try std.testing.expectEqualStrings(
        \\version: 2
        \\updates:
        \\  - package-ecosystem: "npm"
        \\    directory: "/"
        \\    schedule:
        \\      interval: "weekly"
        \\    insecure-external-code-execution: deny
        \\    cooldown:
        \\      default-days: 7
        \\
    ,
        result.content,
    );
}

test "rule descriptors are valid" {
    try std.testing.expectEqualStrings("DEP001", rules[0].id);
    try std.testing.expectEqualStrings("dependabot-cooldown", rules[0].name);
    try std.testing.expect(rules[0].severity == .info);
    try std.testing.expect(rules[0].category == .dependency);
    try std.testing.expect(rules[0].check_workflow == null);
    try std.testing.expect(rules[0].check_job == null);
    try std.testing.expect(rules[0].check_step == null);

    try std.testing.expectEqualStrings("DEP002", rules[1].id);
    try std.testing.expectEqualStrings("dependabot-execution", rules[1].name);
    try std.testing.expect(rules[1].severity == .warning);
    try std.testing.expect(rules[1].category == .dependency);
}
