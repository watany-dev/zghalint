const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const Diagnostic = diagnostics.Diagnostic;
const DiagnosticList = diagnostics.DiagnosticList;
const Severity = diagnostics.Severity;
const engine_mod = @import("../rules/engine.zig");
const Rule = engine_mod.Rule;

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
pub fn renderSarif(writer: anytype, list: DiagnosticList, rules: []const Rule) !void {
    // -- Preamble
    try writer.writeAll("{\"$schema\":\"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json\"");
    try writer.writeAll(",\"version\":\"2.1.0\"");
    try writer.writeAll(",\"runs\":[{");

    // -- tool.driver
    try writer.writeAll("\"tool\":{\"driver\":{");
    try writer.writeAll("\"name\":\"zghalint\"");
    try writer.writeAll(",\"informationUri\":\"https://github.com/zghalint/zghalint\"");
    try writer.writeAll(",\"rules\":[");
    for (rules, 0..) |rule, i| {
        if (i > 0) try writer.writeAll(",");
        try writeRuleDescriptor(writer, rule);
    }
    try writer.writeAll("]}}");

    // -- results
    try writer.writeAll(",\"results\":[");
    for (list.items.items, 0..) |diag, i| {
        if (i > 0) try writer.writeAll(",");
        try writeResult(writer, diag, rules);
    }
    try writer.writeAll("]}]}");
}

fn writeRuleDescriptor(writer: anytype, rule: Rule) !void {
    try writer.writeAll("{\"id\":");
    try writeJsonString(writer, rule.id);
    try writer.writeAll(",\"name\":");
    try writeJsonString(writer, rule.name);
    try writer.writeAll(",\"shortDescription\":{\"text\":");
    try writeJsonString(writer, rule.description);
    try writer.writeAll("},\"defaultConfiguration\":{\"level\":");
    try writeJsonString(writer, sarifLevel(rule.severity));
    try writer.writeAll("}}");
}

fn writeResult(writer: anytype, diag: Diagnostic, rules: []const Rule) !void {
    try writer.writeAll("{\"ruleId\":");
    try writeJsonString(writer, diag.rule_id);

    // ruleIndex
    const rule_index = findRuleIndex(rules, diag.rule_id);
    if (rule_index) |idx| {
        try writer.print(",\"ruleIndex\":{d}", .{idx});
    }

    try writer.writeAll(",\"level\":");
    try writeJsonString(writer, sarifLevel(diag.severity));

    try writer.writeAll(",\"message\":{\"text\":");
    var msg_buf: [1024]u8 = undefined;
    const msg = if (diag.fix_hint) |hint| blk: {
        // Append hint to message
        const msg_len = @min(diag.message.len, 512);
        @memcpy(msg_buf[0..msg_len], diag.message[0..msg_len]);
        const sep = ". ";
        @memcpy(msg_buf[msg_len .. msg_len + sep.len], sep);
        const hint_len = @min(hint.len, 512 - sep.len);
        @memcpy(msg_buf[msg_len + sep.len .. msg_len + sep.len + hint_len], hint[0..hint_len]);
        break :blk msg_buf[0 .. msg_len + sep.len + hint_len];
    } else diag.message;
    try writeJsonString(writer, msg);
    try writer.writeAll("}");

    // locations
    try writer.writeAll(",\"locations\":[{\"physicalLocation\":{");
    try writer.writeAll("\"artifactLocation\":{\"uri\":");
    try writeJsonString(writer, diag.file orelse "<unknown>");
    try writer.writeAll(",\"uriBaseId\":\"%SRCROOT%\"}");
    try writer.writeAll(",\"region\":{");
    try writer.print("\"startLine\":{d},\"startColumn\":{d}", .{
        diag.span.start_line,
        diag.span.start_col,
    });
    try writer.print(",\"endLine\":{d},\"endColumn\":{d}", .{
        diag.span.end_line,
        diag.span.end_col,
    });
    try writer.writeAll("}}}]");

    try writer.writeAll("}");
}

fn findRuleIndex(rules: []const Rule, rule_id: []const u8) ?usize {
    for (rules, 0..) |rule, i| {
        if (std.mem.eql(u8, rule.id, rule_id)) return i;
    }
    return null;
}

/// Write a JSON-escaped string (with surrounding quotes).
fn writeJsonString(writer: anytype, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
    try writer.writeByte('"');
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
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try renderSarif(buf.writer(std.testing.allocator), list, &test_rules);
    const output = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, output, "\"version\":\"2.1.0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"name\":\"zghalint\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"results\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "sarif-schema-2.1.0") != null);
}

test "renderSarif with diagnostic" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    list.append(.{
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

    try renderSarif(buf.writer(std.testing.allocator), list, &test_rules);
    const output = buf.items;

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
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    try renderSarif(buf.writer(std.testing.allocator), list, &test_rules);
    const output = buf.items;

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
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    list.append(.{ .rule_id = "SEC001", .severity = .warning, .message = "unpinned action", .file = "ci.yml", .span = Span.point(1, 1, 0) });
    list.append(.{ .rule_id = "BP001", .severity = .info, .message = "no timeout", .file = "ci.yml", .span = Span.point(5, 1, 40) });

    try renderSarif(buf.writer(std.testing.allocator), list, &test_rules);
    const output = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, output, "\"ruleId\":\"SEC001\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"ruleId\":\"BP001\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"ruleIndex\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"ruleIndex\":2") != null);
}

test "renderSarif unknown rule id has no ruleIndex" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    list.append(.{ .rule_id = "UNKNOWN", .severity = .@"error", .message = "mystery", .span = Span.point(1, 1, 0) });

    try renderSarif(buf.writer(std.testing.allocator), list, &test_rules);
    const output = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, output, "\"ruleId\":\"UNKNOWN\"") != null);
    // Should not have ruleIndex for unknown rule
    try std.testing.expect(std.mem.indexOf(u8, output, "\"ruleIndex\":") == null);
}

test "writeJsonString escapes control chars" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    try writeJsonString(buf.writer(std.testing.allocator), "a\tb\rc\nd\\e\"f");
    const output = buf.items;
    try std.testing.expectEqualStrings("\"a\\tb\\rc\\nd\\\\e\\\"f\"", output);
}

test "writeJsonString escapes low control characters" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    try writeJsonString(buf.writer(std.testing.allocator), "\x01\x02");
    try std.testing.expectEqualStrings("\"\\u0001\\u0002\"", buf.items);
}

test "renderSarif with no file" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    list.append(.{ .rule_id = "SEC001", .severity = .warning, .message = "test msg", .span = Span.point(1, 1, 0) });

    try renderSarif(buf.writer(std.testing.allocator), list, &test_rules);
    const output = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, output, "\"<unknown>\"") != null);
}

test "renderSarif empty rules array" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    const empty_rules: []const Rule = &.{};
    try renderSarif(buf.writer(std.testing.allocator), list, empty_rules);
    const output = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, output, "\"rules\":[]") != null);
}
