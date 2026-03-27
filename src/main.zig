const std = @import("std");
const zghalint = @import("zghalint");
const Config = zghalint.Config;
const OutputFormat = zghalint.OutputFormat;
const ColorMode = zghalint.ColorMode;

const version = "0.1.0";

const CliArgs = struct {
    files: std.ArrayList([]const u8),
    allocator: std.mem.Allocator,
    config_path: ?[]const u8 = null,
    format: ?OutputFormat = null,
    color: ?ColorMode = null,
    show_help: bool = false,
    show_version: bool = false,

    fn deinit(self: *CliArgs) void {
        self.files.deinit();
    }
};

fn parseArgs(allocator: std.mem.Allocator) !CliArgs {
    var args = CliArgs{ .files = std.ArrayList([]const u8).init(allocator), .allocator = allocator };
    var iter = try std.process.argsWithAllocator(allocator);
    defer iter.deinit();

    _ = iter.next(); // skip program name

    while (iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            args.show_help = true;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            args.show_version = true;
        } else if (std.mem.eql(u8, arg, "--config")) {
            args.config_path = iter.next();
        } else if (std.mem.eql(u8, arg, "--format")) {
            if (iter.next()) |fmt_str| {
                args.format = OutputFormat.fromString(fmt_str);
            }
        } else if (std.mem.eql(u8, arg, "--color")) {
            if (iter.next()) |color_str| {
                args.color = ColorMode.fromString(color_str);
            }
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            try args.files.append(arg);
        }
    }

    return args;
}

fn printHelp(writer: anytype) !void {
    try writer.writeAll(
        \\Usage: zghalint [OPTIONS] [FILES...]
        \\
        \\GitHub Actions workflow linter
        \\
        \\Arguments:
        \\  [FILES...]  Workflow files to lint (default: .github/workflows/*.yml)
        \\
        \\Options:
        \\  --config <path>   Path to config file (default: .zghalint.yml)
        \\  --format <fmt>    Output format: terminal, json, sarif (default: terminal)
        \\  --color <mode>    Color mode: auto, always, never (default: auto)
        \\  -h, --help        Show this help
        \\  -v, --version     Show version
        \\
    );
}

fn collectDefaultFiles(allocator: std.mem.Allocator) !std.ArrayList([]const u8) {
    var files = std.ArrayList([]const u8).init(allocator);
    var dir = std.fs.cwd().openDir(".github/workflows", .{ .iterate = true }) catch return files;
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind == .file) {
            if (std.mem.endsWith(u8, entry.name, ".yml") or std.mem.endsWith(u8, entry.name, ".yaml")) {
                const full_path = try std.fmt.allocPrint(allocator, ".github/workflows/{s}", .{entry.name});
                try files.append(full_path);
            }
        }
    }

    return files;
}

fn loadConfig(allocator: std.mem.Allocator, config_path: ?[]const u8) !Config {
    const path = config_path orelse zghalint.config.findConfigFile(".") orelse return Config.init(allocator);

    const file = std.fs.cwd().openFile(path, .{}) catch return Config.init(allocator);
    defer file.close();

    const source = file.readToEndAlloc(allocator, 1024 * 1024) catch return Config.init(allocator);
    defer allocator.free(source);

    return zghalint.config.parseConfig(allocator, source) catch return Config.init(allocator);
}

fn lintFile(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    config: *const Config,
    all_diags: *zghalint.DiagnosticList,
) !void {
    const file = std.fs.cwd().openFile(file_path, .{}) catch |err| {
        const stderr = std.io.getStdErr().writer();
        try stderr.print("error: cannot open '{s}': {}\n", .{ file_path, err });
        return;
    };
    defer file.close();

    const source = file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch |err| {
        const stderr = std.io.getStdErr().writer();
        try stderr.print("error: cannot read '{s}': {}\n", .{ file_path, err });
        return;
    };
    defer allocator.free(source);

    // YAML parse
    var yaml_parser = zghalint.yaml.Parser.init(allocator, source);
    defer yaml_parser.deinit();

    const yaml_node = yaml_parser.parse() catch {
        const stderr = std.io.getStdErr().writer();
        try stderr.print("{s}: YAML parse error\n", .{file_path});
        return;
    };

    // Workflow conversion
    const workflow = zghalint.workflow.parseWorkflow(allocator, yaml_node) catch {
        const stderr = std.io.getStdErr().writer();
        try stderr.print("{s}: workflow parse error\n", .{file_path});
        return;
    };

    // Collect all rules
    const all_rules = zghalint.rules.security.security_rules ++
        zghalint.rules.best_practices.rules ++
        zghalint.rules.performance.rules ++
        zghalint.rules.permissions.rules ++
        [_]zghalint.rules.Rule{zghalint.rules.expressions.expression_rule};

    // Run engine
    const engine = zghalint.rules.Engine.init(&all_rules);
    var diag_list = engine.run(allocator, &workflow);
    defer diag_list.deinit();

    // Apply config: filter disabled rules, override severity, set file
    for (diag_list.items.items) |diag| {
        if (!config.isRuleEnabled(diag.rule_id)) continue;
        var d = diag;
        d.severity = config.getEffectiveSeverity(diag.rule_id, diag.severity);
        d.file = file_path;
        all_diags.append(d);
    }
}

fn outputTerminal(diag_list: *zghalint.DiagnosticList, allocator: std.mem.Allocator) !void {
    const stdout = std.io.getStdOut().writer();
    for (diag_list.items.items) |diag| {
        const formatted = try diag.format(allocator);
        defer allocator.free(formatted);
        try stdout.print("{s}\n", .{formatted});
    }
}

fn outputJson(diag_list: *zghalint.DiagnosticList, writer: anytype) !void {
    try writer.writeAll("[");
    for (diag_list.items.items, 0..) |diag, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("{");
        try writer.print("\"rule_id\":\"{s}\",", .{diag.rule_id});
        try writer.print("\"severity\":\"{s}\",", .{diag.severity.toString()});
        try writer.print("\"message\":\"{s}\",", .{diag.message});
        try writer.print("\"file\":\"{s}\",", .{diag.file orelse "<unknown>"});
        try writer.print("\"line\":{d},", .{diag.span.start_line});
        try writer.print("\"column\":{d}", .{diag.span.start_col});
        if (diag.fix_hint) |hint| {
            try writer.print(",\"fix_hint\":\"{s}\"", .{hint});
        }
        try writer.writeAll("}");
    }
    try writer.writeAll("]\n");
}

fn outputSarif(diag_list: *zghalint.DiagnosticList, writer: anytype) !void {
    try writer.writeAll("{\"$schema\":\"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json\",\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"zghalint\",\"version\":\"");
    try writer.writeAll(version);
    try writer.writeAll("\"}},\"results\":[");

    for (diag_list.items.items, 0..) |diag, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("{");
        try writer.print("\"ruleId\":\"{s}\",", .{diag.rule_id});
        try writer.print("\"level\":\"{s}\",", .{sarifLevel(diag.severity)});
        try writer.print("\"message\":{{\"text\":\"{s}\"}},", .{diag.message});
        try writer.writeAll("\"locations\":[{\"physicalLocation\":{");
        try writer.print("\"artifactLocation\":{{\"uri\":\"{s}\"}},", .{diag.file orelse "<unknown>"});
        try writer.print("\"region\":{{\"startLine\":{d},\"startColumn\":{d}}}", .{ diag.span.start_line, diag.span.start_col });
        try writer.writeAll("}}]");
        try writer.writeAll("}");
    }

    try writer.writeAll("]}]}\n");
}

fn sarifLevel(severity: zghalint.Severity) []const u8 {
    return switch (severity) {
        .@"error" => "error",
        .warning => "warning",
        .info => "note",
        .hint => "note",
    };
}

fn hasErrors(diag_list: *zghalint.DiagnosticList) bool {
    for (diag_list.items.items) |diag| {
        if (diag.severity == .@"error") return true;
    }
    return false;
}

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    var cli_args = parseArgs(allocator) catch {
        try stderr.writeAll("error: failed to parse arguments\n");
        return 2;
    };
    defer cli_args.deinit();

    if (cli_args.show_help) {
        try printHelp(stdout);
        return 0;
    }

    if (cli_args.show_version) {
        try stdout.print("zghalint v{s}\n", .{version});
        return 0;
    }

    // Load config
    var config = loadConfig(allocator, cli_args.config_path) catch {
        try stderr.writeAll("error: failed to load config\n");
        return 2;
    };
    defer config.deinit();

    // CLI args override config
    if (cli_args.format) |fmt| config.output_format = fmt;
    if (cli_args.color) |color| config.color_mode = color;

    // Collect files
    var owned_files: ?std.ArrayList([]const u8) = null;
    defer if (owned_files) |*of| {
        for (of.items) |p| allocator.free(p);
        of.deinit();
    };

    const files = if (cli_args.files.items.len > 0)
        cli_args.files.items
    else blk: {
        owned_files = collectDefaultFiles(allocator) catch {
            try stderr.writeAll("error: failed to scan default workflow directory\n");
            return 2;
        };
        break :blk owned_files.?.items;
    };

    if (files.len == 0) {
        try stderr.writeAll("No workflow files found.\n");
        return 0;
    }

    // Lint each file
    var all_diags = zghalint.DiagnosticList.init(allocator);
    defer all_diags.deinit();

    for (files) |file_path| {
        if (config.isIgnored(file_path)) continue;
        lintFile(allocator, file_path, &config, &all_diags) catch {
            try stderr.print("error: internal error while linting '{s}'\n", .{file_path});
        };
    }

    all_diags.sort();

    // Output
    switch (config.output_format) {
        .terminal => outputTerminal(&all_diags, allocator) catch {
            return 2;
        },
        .json => outputJson(&all_diags, stdout) catch {
            return 2;
        },
        .sarif => outputSarif(&all_diags, stdout) catch {
            return 2;
        },
    }

    // Exit code
    if (hasErrors(&all_diags)) return 1;
    return 0;
}

test {
    _ = zghalint;
}
