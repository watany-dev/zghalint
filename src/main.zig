const std = @import("std");
const zghalint = @import("zghalint");
const Config = zghalint.Config;
const OutputFormat = zghalint.OutputFormat;
const ColorMode = zghalint.ColorMode;

const version = "0.0.1-rc.1";

const FixMode = enum {
    off,
    safe,
    all,
};

/// All lint rules used by the engine and SARIF output.
const all_rules = zghalint.rules.security.security_rules ++
    zghalint.rules.best_practices.rules ++
    zghalint.rules.performance.rules ++
    zghalint.rules.permissions.rules ++
    [_]zghalint.rules.Rule{zghalint.rules.expressions.expression_rule} ++
    zghalint.rules.dependabot.rules ++
    zghalint.rules.runner.rules ++
    zghalint.rules.syntax.rules;

const CliArgs = struct {
    files: std.ArrayList([]const u8),
    allocator: std.mem.Allocator,
    config_path: ?[]const u8 = null,
    format: ?OutputFormat = null,
    color: ?ColorMode = null,
    offline: bool = false,
    no_cache: bool = false,
    show_help: bool = false,
    show_version: bool = false,
    fix_mode: FixMode = .off,

    fn deinit(self: *CliArgs) void {
        self.files.deinit(self.allocator);
    }
};

fn parseArgs(allocator: std.mem.Allocator) !CliArgs {
    var raw_args = std.ArrayList([]const u8){};
    defer raw_args.deinit(allocator);

    var iter = try std.process.argsWithAllocator(allocator);
    defer iter.deinit();

    _ = iter.next(); // skip program name
    while (iter.next()) |arg| {
        try raw_args.append(allocator, arg);
    }

    return parseArgsSlice(allocator, raw_args.items);
}

fn parseArgsSlice(allocator: std.mem.Allocator, argv: []const []const u8) !CliArgs {
    var args = CliArgs{ .files = .{}, .allocator = allocator };

    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            args.show_help = true;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            args.show_version = true;
        } else if (std.mem.eql(u8, arg, "--config")) {
            // Match the current permissive behavior: missing values are ignored.
            // The slice walker below advances over consumed option values.
        } else if (std.mem.eql(u8, arg, "--format")) {
            // handled in indexed loop below
        } else if (std.mem.eql(u8, arg, "--color")) {
            // handled in indexed loop below
        } else if (std.mem.eql(u8, arg, "--offline") or std.mem.eql(u8, arg, "--quick")) {
            args.offline = true;
        } else if (std.mem.eql(u8, arg, "--no-cache")) {
            args.no_cache = true;
        }
    }

    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--config")) {
            if (i + 1 < argv.len) {
                i += 1;
                args.config_path = argv[i];
            }
        } else if (std.mem.eql(u8, arg, "--format")) {
            if (i + 1 < argv.len) {
                i += 1;
                args.format = OutputFormat.fromString(argv[i]);
            }
        } else if (std.mem.eql(u8, arg, "--color")) {
            if (i + 1 < argv.len) {
                i += 1;
                args.color = ColorMode.fromString(argv[i]);
            }
        } else if (std.mem.eql(u8, arg, "--fix")) {
            args.fix_mode = .safe;
        } else if (std.mem.eql(u8, arg, "--fix-unsafe")) {
            args.fix_mode = .all;
        } else if (!std.mem.eql(u8, arg, "--help") and
            !std.mem.eql(u8, arg, "-h") and
            !std.mem.eql(u8, arg, "--version") and
            !std.mem.eql(u8, arg, "-v") and
            !std.mem.eql(u8, arg, "--offline") and
            !std.mem.eql(u8, arg, "--quick") and
            !std.mem.eql(u8, arg, "--no-cache") and
            !std.mem.startsWith(u8, arg, "-"))
        {
            try args.files.append(allocator, arg);
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
        \\  [FILES...]  Files to lint (default: .github/workflows/*.yml, .github/dependabot.yml)
        \\
        \\Options:
        \\  --config <path>   Path to config file (default: .zghalint.yml)
        \\  --format <fmt>    Output format: terminal, json, sarif (default: terminal)
        \\  --color <mode>    Color mode: auto, always, never (default: auto)
        \\  --quick           Disable network requests and use only local data/cache
        \\  --offline         Alias for --quick
        \\  --no-cache        Ignore the on-disk prefetch cache and refetch from the network
        \\  --fix             Apply safe auto-fixes and rewrite files
        \\  --fix-unsafe      Apply all auto-fixes (safe + unsafe)
        \\  -h, --help        Show this help
        \\  -v, --version     Show version
        \\
    );
}

fn collectDefaultFiles(allocator: std.mem.Allocator) !std.ArrayList([]const u8) {
    var files = std.ArrayList([]const u8){};
    var dir = std.fs.cwd().openDir(".github/workflows", .{ .iterate = true }) catch return files;
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind == .file) {
            if (std.mem.endsWith(u8, entry.name, ".yml") or std.mem.endsWith(u8, entry.name, ".yaml")) {
                const full_path = try std.fmt.allocPrint(allocator, ".github/workflows/{s}", .{entry.name});
                try files.append(allocator, full_path);
            }
        }
    }

    // Also check for .github/dependabot.yml and .github/dependabot.yaml
    inline for ([_][]const u8{ ".github/dependabot.yml", ".github/dependabot.yaml" }) |dep_path| {
        if (std.fs.cwd().access(dep_path, .{})) |_| {
            const path_copy = try std.fmt.allocPrint(allocator, "{s}", .{dep_path});
            try files.append(allocator, path_copy);
        } else |_| {}
    }

    return files;
}

fn isDependabotFile(path: []const u8) bool {
    return std.mem.endsWith(u8, path, "dependabot.yml") or
        std.mem.endsWith(u8, path, "dependabot.yaml");
}

fn lintDependabotFile(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    config: *const Config,
    all_diags: *zghalint.DiagnosticList,
) !void {
    var stderr_buf: [1024]u8 = undefined;
    var stderr_bw = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_bw.interface;

    const file = std.fs.cwd().openFile(file_path, .{}) catch |err| {
        stderr.print("error: cannot open '{s}': {}\n", .{ file_path, err }) catch {};
        return;
    };
    defer file.close();

    const source = file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch |err| {
        stderr.print("error: cannot read '{s}': {}\n", .{ file_path, err }) catch {};
        return;
    };
    defer allocator.free(source);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var yaml_parser = zghalint.yaml.Parser.init(arena_alloc, source);
    defer yaml_parser.deinit();

    const yaml_node = yaml_parser.parse() catch {
        stderr.print("{s}: YAML parse error\n", .{file_path}) catch {};
        return;
    };

    var diag_list = zghalint.DiagnosticList.init(allocator);
    defer diag_list.deinit();

    zghalint.rules.dependabot.lintDependabot(yaml_node, &diag_list);

    for (diag_list.items.items) |diag| {
        if (!config.isRuleEnabled(diag.rule_id)) continue;
        var d = diag;
        d.severity = config.getEffectiveSeverity(diag.rule_id, diag.severity);
        d.file = file_path;
        all_diags.appendOwning(d) catch {};
    }
}

/// Pre-parse every workflow file and pre-fetch network-dependent rule data
/// in one shot before the lint phase. Runs on a throwaway arena so the cost
/// of parsing twice (once here, once in lintFile) is bounded.
fn prefetchNetworkData(
    allocator: std.mem.Allocator,
    files: []const []const u8,
    config: *const Config,
    no_cache: bool,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();

    var workflows = std.ArrayList(zghalint.workflow.Workflow){};
    defer workflows.deinit(scratch);

    for (files) |file_path| {
        if (config.isIgnored(file_path)) continue;
        if (isDependabotFile(file_path)) continue;

        const file = std.fs.cwd().openFile(file_path, .{}) catch continue;
        defer file.close();

        const source = file.readToEndAlloc(scratch, 10 * 1024 * 1024) catch continue;

        var yaml_parser = zghalint.yaml.Parser.init(scratch, source);
        defer yaml_parser.deinit();

        const yaml_node = yaml_parser.parse() catch continue;
        const workflow = zghalint.workflow.parseWorkflow(scratch, yaml_node) catch continue;
        try workflows.append(scratch, workflow);
    }

    _ = zghalint.rules.prefetch.prefetchAllWithOptions(
        scratch,
        workflows.items,
        .{ .no_cache = no_cache },
    ) catch return;
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
    var stderr_buf: [1024]u8 = undefined;
    var stderr_bw = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_bw.interface;

    const file = std.fs.cwd().openFile(file_path, .{}) catch |err| {
        stderr.print("error: cannot open '{s}': {}\n", .{ file_path, err }) catch {};
        return;
    };
    defer file.close();

    const source = file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch |err| {
        stderr.print("error: cannot read '{s}': {}\n", .{ file_path, err }) catch {};
        return;
    };
    defer allocator.free(source);

    // Arena for YAML/workflow parsing (freed after diagnostics are collected)
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    // YAML parse
    var yaml_parser = zghalint.yaml.Parser.init(arena_alloc, source);
    defer yaml_parser.deinit();

    const yaml_node = yaml_parser.parse() catch {
        stderr.print("{s}: YAML parse error\n", .{file_path}) catch {};
        return;
    };

    // Workflow conversion
    const workflow = zghalint.workflow.parseWorkflow(arena_alloc, yaml_node) catch {
        var yaml_diags = zghalint.DiagnosticList.init(allocator);
        defer yaml_diags.deinit();
        zghalint.rules.syntax.emitDuplicateKeyDiagnostics(yaml_node, &yaml_diags);
        for (yaml_diags.items.items) |diag| {
            if (!config.isRuleEnabled(diag.rule_id)) continue;
            var d = diag;
            d.severity = config.getEffectiveSeverity(diag.rule_id, diag.severity);
            d.file = file_path;
            all_diags.appendOwning(d) catch {};
        }
        stderr.print("{s}: workflow parse error\n", .{file_path}) catch {};
        return;
    };

    // Propagate config to security rules that need it (SEC020)
    zghalint.rules.security.setRepoVisibility(config.repo_visibility);

    // Run engine
    const engine = zghalint.rules.Engine.init(&all_rules);
    var diag_list = engine.run(allocator, &workflow);
    defer diag_list.deinit();

    // Strip SC005 entries that overlap with SC008 verdicts so the user
    // doesn't see two diagnostics for the same impostor SHA. Guard on
    // SC008 being enabled in the config; otherwise SC008 itself would
    // get filtered out below, leaving neither diagnostic visible.
    if (config.isRuleEnabled("SC008")) {
        zghalint.rules.engine.postProcess(allocator, &workflow, &diag_list);
    }

    // Apply config: filter disabled rules, override severity, set file.
    // Use `appendOwning` because `diag_list`'s fix_arena is deinitialized when
    // this function returns; Fix.edits would otherwise dangle.
    for (diag_list.items.items) |diag| {
        if (!config.isRuleEnabled(diag.rule_id)) continue;
        var d = diag;
        d.severity = config.getEffectiveSeverity(diag.rule_id, diag.severity);
        d.file = file_path;
        all_diags.appendOwning(d) catch {};
    }
}

fn outputTerminal(diag_list: *zghalint.DiagnosticList, writer: anytype, use_color: bool) !void {
    try zghalint.output.terminal.renderDiagnostics(writer, diag_list.*, null, use_color);
}

fn outputJson(diag_list: *zghalint.DiagnosticList, writer: anytype, files_checked: usize) !void {
    try zghalint.output.renderJson(writer, diag_list.*, files_checked);
    try writer.writeAll("\n");
}

fn outputSarif(diag_list: *zghalint.DiagnosticList, writer: anytype) !void {
    try zghalint.output.renderSarif(writer, diag_list.*, &all_rules);
    try writer.writeAll("\n");
}

fn applyFixesForFile(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    all_diags: *zghalint.DiagnosticList,
    include_unsafe: bool,
) !usize {
    // Collect diagnostics for this file that have fixes
    var file_diags = std.ArrayList(zghalint.Diagnostic){};
    defer file_diags.deinit(allocator);

    for (all_diags.items.items) |d| {
        if (d.fix != null) {
            const f = d.file orelse continue;
            if (std.mem.eql(u8, f, file_path)) {
                try file_diags.append(allocator, d);
            }
        }
    }

    if (file_diags.items.len == 0) return 0;

    // Collect applicable fixes
    const fixes = try zghalint.fix.collectFixes(allocator, file_diags.items, include_unsafe);
    defer allocator.free(fixes);

    if (fixes.len == 0) return 0;

    // Refuse to rewrite through a symlink: otherwise `--fix` on a crafted
    // `workflow.yml -> /etc/passwd` would read and then overwrite the link
    // target. `readLink` succeeding means the path itself is a symlink.
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (std.fs.cwd().readLink(file_path, &link_buf)) |_| {
        return error.RefusingToFixSymlink;
    } else |err| switch (err) {
        error.NotLink => {},
        else => return err,
    }

    // Read file content
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();
    const source = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(source);

    // Apply fixes
    const result = try zghalint.fix.applyFixes(allocator, source, fixes);
    defer result.deinit(allocator);

    if (result.edits_applied == 0) return 0;

    // Atomically replace the file: write a random-named sibling and rename
    // it into place. `rename(2)` replaces the directory entry itself, so if
    // the destination was swapped to a symlink between our check and now,
    // the symlink is replaced — the link target is never written through.
    var write_buf: [4096]u8 = undefined;
    var af = try std.fs.cwd().atomicFile(file_path, .{ .write_buffer = &write_buf });
    defer af.deinit();
    try af.file_writer.interface.writeAll(result.content);
    try af.finish();

    return result.edits_applied;
}

fn hasErrors(diag_list: *zghalint.DiagnosticList) bool {
    for (diag_list.items.items) |diag| {
        if (diag.severity == .@"error") return true;
    }
    return false;
}

/// Populate `workspace.current` from the repository containing `files[0]`.
/// Errors are swallowed; PERF001 simply emits diagnostics without fix when
/// probing fails. Config overrides take precedence over probe results.
fn initWorkspaceContext(
    arena: std.mem.Allocator,
    files: []const []const u8,
    config: *const Config,
) void {
    const hint = if (files.len > 0) files[0] else ".";
    const root = zghalint.workspace.findWorkspaceRoot(arena, hint) catch return;
    var ctx = zghalint.workspace.detectFromRoot(arena, root) catch zghalint.workspace.Context{};

    if (config.perf001.node_cache_manager) |mgr| {
        ctx.node_cache = mgr;
        ctx.ambiguous_node_lockfiles = &.{};
    }
    if (config.perf001.python_cache_manager) |mgr| {
        ctx.python_cache = mgr;
        ctx.ambiguous_python_lockfiles = &.{};
    }

    zghalint.workspace.set(ctx);
}

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_bw = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_bw.interface;

    var stderr_buf: [1024]u8 = undefined;
    var stderr_bw = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_bw.interface;

    var cli_args = parseArgs(allocator) catch {
        stderr.writeAll("error: failed to parse arguments\n") catch {};
        return 2;
    };
    defer cli_args.deinit();

    if (cli_args.show_help) {
        try printHelp(stdout);
        try stdout.flush();
        return 0;
    }

    if (cli_args.show_version) {
        try stdout.print("zghalint v{s}\n", .{version});
        try stdout.flush();
        return 0;
    }

    // Load config
    var config = loadConfig(allocator, cli_args.config_path) catch {
        stderr.writeAll("error: failed to load config\n") catch {};
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
        of.deinit(allocator);
    };

    const files = if (cli_args.files.items.len > 0)
        cli_args.files.items
    else blk: {
        owned_files = collectDefaultFiles(allocator) catch {
            stderr.writeAll("error: failed to scan default workflow directory\n") catch {};
            return 2;
        };
        break :blk owned_files.?.items;
    };

    if (files.len == 0) {
        stderr.writeAll("No workflow files found.\n") catch {};
        return 0;
    }

    // Probe the workspace for lockfiles so PERF001 can emit concrete
    // `cache: <manager>` fixes for setup-node / setup-python / setup-go.
    var workspace_arena = std.heap.ArenaAllocator.init(allocator);
    defer workspace_arena.deinit();
    initWorkspaceContext(workspace_arena.allocator(), files, &config);
    defer zghalint.workspace.clear();

    // Set a 10-second deadline for all network operations to prevent hangs
    zghalint.rules.engine.setNetworkDeadline(10 * std.time.ns_per_s);
    defer zghalint.rules.engine.clearNetworkDeadline();

    // Shared HTTP client amortizes TLS/TCP handshakes across rule fetches.
    zghalint.rules.http_client.init(allocator);
    defer zghalint.rules.http_client.deinit();

    // Initialize network-dependent rule databases (graceful offline skip)
    zghalint.rules.advisory.initAdvisories(allocator, cli_args.offline);
    defer zghalint.rules.advisory.deinitAdvisories();
    zghalint.rules.archived.initArchived(allocator, cli_args.offline);
    defer zghalint.rules.archived.deinitArchived();
    zghalint.rules.stale_refs.initStaleRefs(allocator, cli_args.offline);
    defer zghalint.rules.stale_refs.deinitStaleRefs();

    // Initialize ref-confusion checker (network call, graceful offline skip)
    zghalint.rules.refconfusion.initRefConfusion(allocator, cli_args.offline);
    defer zghalint.rules.refconfusion.deinitRefConfusion();

    // SC008: impostor-commit. Shares the GraphQL+REST batch with SC005/SC006.
    zghalint.rules.impostor.initImpostor(allocator, cli_args.offline);
    defer zghalint.rules.impostor.deinitImpostor();

    // Batch all network-rule fetches before the lint pass so TLS/TCP
    // connections, advisories, and repo metadata are primed in the caches.
    if (!cli_args.offline) {
        prefetchNetworkData(allocator, files, &config, cli_args.no_cache) catch {};
    }

    // Lint each file
    var all_diags = zghalint.DiagnosticList.init(allocator);
    defer all_diags.deinit();

    for (files) |file_path| {
        if (config.isIgnored(file_path)) continue;
        if (isDependabotFile(file_path)) {
            lintDependabotFile(allocator, file_path, &config, &all_diags) catch {
                stderr.print("error: internal error while linting '{s}'\n", .{file_path}) catch {};
            };
        } else {
            lintFile(allocator, file_path, &config, &all_diags) catch {
                stderr.print("error: internal error while linting '{s}'\n", .{file_path}) catch {};
            };
        }
    }

    // Apply fixes if requested
    if (cli_args.fix_mode != .off) {
        const include_unsafe = cli_args.fix_mode == .all;
        var total_fixed: usize = 0;
        for (files) |file_path| {
            if (config.isIgnored(file_path)) continue;
            const fixed = applyFixesForFile(allocator, file_path, &all_diags, include_unsafe) catch |err| {
                try stderr.print("error: failed to apply fixes to '{s}': {}\n", .{ file_path, err });
                continue;
            };
            total_fixed += fixed;
        }
        if (total_fixed > 0) {
            try stderr.print("Applied {d} fix(es).\n", .{total_fixed});
        }
    }

    all_diags.sort();

    // Determine color usage
    const use_color = switch (config.color_mode) {
        .always => true,
        .never => false,
        .auto => std.posix.isatty(std.fs.File.stdout().handle),
    };

    // Output
    switch (config.output_format) {
        .terminal => {
            outputTerminal(&all_diags, stdout, use_color) catch {
                return 2;
            };
            try stdout.flush();
        },
        .json => {
            outputJson(&all_diags, stdout, files.len) catch {
                return 2;
            };
            try stdout.flush();
        },
        .sarif => {
            outputSarif(&all_diags, stdout) catch {
                return 2;
            };
            try stdout.flush();
        },
    }

    // Exit code
    if (hasErrors(&all_diags)) return 1;
    return 0;
}

test {
    _ = zghalint;
}

test "isDependabotFile detects dependabot yml" {
    try std.testing.expect(isDependabotFile(".github/dependabot.yml"));
    try std.testing.expect(isDependabotFile(".github/dependabot.yaml"));
    try std.testing.expect(isDependabotFile("some/path/dependabot.yml"));
    try std.testing.expect(!isDependabotFile(".github/workflows/ci.yml"));
    try std.testing.expect(!isDependabotFile("dependabot.txt"));
}

test "hasErrors detects error severity" {
    var list = zghalint.DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    // No errors
    try std.testing.expect(!hasErrors(&list));

    // Warning only
    try list.append(.{
        .rule_id = "W1",
        .severity = .warning,
        .message = "warn",
        .span = zghalint.yaml.types.Span.point(1, 1, 0),
    });
    try std.testing.expect(!hasErrors(&list));

    // Add error
    try list.append(.{
        .rule_id = "E1",
        .severity = .@"error",
        .message = "err",
        .span = zghalint.yaml.types.Span.point(2, 1, 0),
    });
    try std.testing.expect(hasErrors(&list));
}

test "printHelp outputs usage text" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    try printHelp(buf.writer(std.testing.allocator));
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "Usage: zghalint") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "--config") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "--format") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "--color") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "--quick") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "--offline") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "--no-cache") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "--fix") != null);
}

test "parseArgsSlice parses offline flag" {
    const argv = [_][]const u8{ "--offline", ".github/workflows/ci.yml" };
    var args = try parseArgsSlice(std.testing.allocator, &argv);
    defer args.deinit();

    try std.testing.expect(args.offline);
    try std.testing.expectEqual(@as(usize, 1), args.files.items.len);
    try std.testing.expectEqualStrings(".github/workflows/ci.yml", args.files.items[0]);
}

test "parseArgsSlice parses no-cache flag" {
    const argv = [_][]const u8{ "--no-cache", ".github/workflows/ci.yml" };
    var args = try parseArgsSlice(std.testing.allocator, &argv);
    defer args.deinit();

    try std.testing.expect(args.no_cache);
    try std.testing.expectEqual(@as(usize, 1), args.files.items.len);
    try std.testing.expectEqualStrings(".github/workflows/ci.yml", args.files.items[0]);
}

test "parseArgsSlice parses quick flag" {
    const argv = [_][]const u8{ "--quick", ".github/workflows/ci.yml" };
    var args = try parseArgsSlice(std.testing.allocator, &argv);
    defer args.deinit();

    try std.testing.expect(args.offline);
    try std.testing.expectEqual(@as(usize, 1), args.files.items.len);
    try std.testing.expectEqualStrings(".github/workflows/ci.yml", args.files.items[0]);
}

test "parseArgsSlice parses config and format options" {
    const argv = [_][]const u8{
        "--config",
        ".zghalint.yml",
        "--format",
        "json",
        "--color",
        "never",
        "--fix-unsafe",
    };
    var args = try parseArgsSlice(std.testing.allocator, &argv);
    defer args.deinit();

    try std.testing.expectEqualStrings(".zghalint.yml", args.config_path.?);
    try std.testing.expectEqual(OutputFormat.json, args.format.?);
    try std.testing.expectEqual(ColorMode.never, args.color.?);
    try std.testing.expectEqual(FixMode.all, args.fix_mode);
}
