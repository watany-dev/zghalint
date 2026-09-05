const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const Diagnostic = diagnostics.Diagnostic;
const DiagnosticList = diagnostics.DiagnosticList;
const Severity = diagnostics.Severity;
const engine_mod = @import("../rules/engine.zig");
const Rule = engine_mod.Rule;

const schema_url = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";

/// SARIF severity level mapping.
/// Maps zghalint Severity to SARIF "level" values.
fn sarifLevel(sev: Severity) []const u8 {
    return switch (sev) {
        .@"error" => "error",
        .warning => "warning",
        .info => "note",
        .hint => "note",
    };
}

/// Render diagnostics in SARIF 2.1.0 format.
/// `rules` are the rule definitions used to populate the tool.driver.rules array.
pub fn renderSarif(writer: *std.Io.Writer, list: DiagnosticList, rules: []const Rule) !void {
    var js: std.json.Stringify = .{ .writer = writer };

    try js.beginObject();
    try js.objectField("$schema");
    try js.write(schema_url);
    try js.objectField("version");
    try js.write("2.1.0");

    try js.objectField("runs");
    try js.beginArray();
    try js.beginObject();

    // -- tool.driver
    try js.objectField("tool");
    try js.beginObject();
    try js.objectField("driver");
    try js.beginObject();
    try js.objectField("name");
    try js.write("zghalint");
    try js.objectField("informationUri");
    try js.write("https://github.com/zghalint/zghalint");
    try js.objectField("rules");
    try js.beginArray();
    for (rules) |rule| {
        try js.write(.{
            .id = rule.id,
            .name = rule.name,
            .shortDescription = .{ .text = rule.description },
            .defaultConfiguration = .{ .level = sarifLevel(rule.severity) },
        });
    }
    try js.endArray();
    try js.endObject();
    try js.endObject();

    // -- results
    try js.objectField("results");
    try js.beginArray();
    for (list.items.items) |diag| {
        try writeResult(&js, diag, rules);
    }
    try js.endArray();

    try js.endObject();
    try js.endArray();
    try js.endObject();
}

fn writeResult(js: *std.json.Stringify, diag: Diagnostic, rules: []const Rule) !void {
    try js.beginObject();
    try js.objectField("ruleId");
    try js.write(diag.rule_id);

    if (findRuleIndex(rules, diag.rule_id)) |idx| {
        try js.objectField("ruleIndex");
        try js.write(idx);
    }

    try js.objectField("level");
    try js.write(sarifLevel(diag.severity));

    try js.objectField("message");
    var msg_buf: [combined_msg_len]u8 = undefined;
    try js.write(.{ .text = combinedMessage(&msg_buf, diag) });

    try js.objectField("locations");
    try js.beginArray();
    try js.write(.{
        .physicalLocation = .{
            .artifactLocation = .{
                .uri = diag.file orelse "<unknown>",
                .uriBaseId = "%SRCROOT%",
            },
            .region = .{
                .startLine = diag.span.start_line,
                .startColumn = diag.span.start_col,
                .endLine = diag.span.end_line,
                .endColumn = diag.span.end_col,
            },
        },
    });
    try js.endArray();

    try js.endObject();
}

const max_msg_part = 512;
const hint_sep = ". ";
const max_hint_part = max_msg_part - hint_sep.len;
const combined_msg_len = max_msg_part + hint_sep.len + max_hint_part;

/// SARIF carries the fix hint inside the result message, so append it to the
/// diagnostic text. Both halves are truncated to keep the result bounded.
fn combinedMessage(buf: *[combined_msg_len]u8, diag: Diagnostic) []const u8 {
    const hint = diag.fix_hint orelse return diag.message;
    return std.fmt.bufPrint(buf, "{s}{s}{s}", .{
        diag.message[0..@min(diag.message.len, max_msg_part)],
        hint_sep,
        hint[0..@min(hint.len, max_hint_part)],
    }) catch diag.message;
}

fn findRuleIndex(rules: []const Rule, rule_id: []const u8) ?usize {
    for (rules, 0..) |rule, i| {
        if (std.mem.eql(u8, rule.id, rule_id)) return i;
    }
    return null;
}

// ============================================================
// Tests
// ============================================================

const Span = @import("../yaml/types.zig").Span;
const Category = diagnostics.Category;

const test_rules = [_]Rule{
    .{
        .id = "SEC001",
        .name = "pinned-action",
        .description = "Actions should be pinned to a full commit SHA",
        .severity = .warning,
        .category = .security,
    },
    .{
        .id = "SEC002",
        .name = "script-injection",
        .description = "Potential script injection in run command",
        .severity = .@"error",
        .category = .security,
    },
    .{
        .id = "BP001",
        .name = "timeout-minutes",
        .description = "Jobs should have a timeout-minutes set",
        .severity = .info,
        .category = .best_practice,
    },
};

test "renderSarif empty diagnostics" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try renderSarif(&out.writer, list, &test_rules);
    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "\"version\":\"2.1.0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"name\":\"zghalint\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"results\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "sarif-schema-2.1.0") != null);
}

test "renderSarif with diagnostic" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{
        .rule_id = "SEC002",
        .severity = .@"error",
        .message = "Potential script injection via github.event.issue.title",
        .file = ".github/workflows/ci.yml",
        .span = .{
            .start_line = 15,
            .start_col = 9,
            .end_line = 15,
            .end_col = 45,
            .start_byte = 200,
            .end_byte = 236,
        },
        .fix_hint = "Use an environment variable instead",
    });

    try renderSarif(&out.writer, list, &test_rules);
    const output = out.written();

    // Check SARIF structure
    try std.testing.expect(std.mem.indexOf(u8, output, "\"version\":\"2.1.0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"ruleId\":\"SEC002\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"ruleIndex\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"level\":\"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"startLine\":15") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"startColumn\":9") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "%SRCROOT%") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "script injection") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "environment variable") != null);
}

test "renderSarif rule descriptors" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try renderSarif(&out.writer, list, &test_rules);
    const output = out.written();

    // All rules should appear in driver.rules
    try std.testing.expect(std.mem.indexOf(u8, output, "\"id\":\"SEC001\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"id\":\"SEC002\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"id\":\"BP001\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"name\":\"pinned-action\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"level\":\"warning\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"level\":\"note\"") != null);
}

test "sarifLevel mapping" {
    try std.testing.expectEqualStrings("error", sarifLevel(.@"error"));
    try std.testing.expectEqualStrings("warning", sarifLevel(.warning));
    try std.testing.expectEqualStrings("note", sarifLevel(.info));
    try std.testing.expectEqualStrings("note", sarifLevel(.hint));
}

test "renderSarif multiple results" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{ .rule_id = "SEC001", .severity = .warning, .message = "unpinned action", .file = "ci.yml", .span = Span.point(1, 1, 0) });
    try list.append(.{ .rule_id = "BP001", .severity = .info, .message = "no timeout", .file = "ci.yml", .span = Span.point(5, 1, 40) });

    try renderSarif(&out.writer, list, &test_rules);
    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "\"ruleId\":\"SEC001\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"ruleId\":\"BP001\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"ruleIndex\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"ruleIndex\":2") != null);
}

test "renderSarif unknown rule id has no ruleIndex" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{ .rule_id = "UNKNOWN", .severity = .@"error", .message = "mystery", .span = Span.point(1, 1, 0) });

    try renderSarif(&out.writer, list, &test_rules);
    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "\"ruleId\":\"UNKNOWN\"") != null);
    // Should not have ruleIndex for unknown rule
    try std.testing.expect(std.mem.indexOf(u8, output, "\"ruleIndex\":") == null);
}

test "renderSarif with no file" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try list.append(.{ .rule_id = "SEC001", .severity = .warning, .message = "test msg", .span = Span.point(1, 1, 0) });

    try renderSarif(&out.writer, list, &test_rules);
    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "\"<unknown>\"") != null);
}

test "renderSarif empty rules array" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    const empty_rules: []const Rule = &.{};
    try renderSarif(&out.writer, list, empty_rules);
    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "\"rules\":[]") != null);
}
