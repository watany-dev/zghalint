const std = @import("std");
const builtin = @import("builtin");
const zghalint = @import("zghalint");
const Config = zghalint.Config;
const OutputFormat = zghalint.OutputFormat;
const ColorMode = zghalint.ColorMode;

const version = @import("build_options").version;

const FixMode = enum {
    off,
    safe,
    all,
};

const all_rules = zghalint.rules.registry.all_rules;

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

fn parseArgs(allocator: std.mem.Allocator, stderr: *std.Io.Writer) !CliArgs {
    var raw_args = std.ArrayList([]const u8){};
    defer raw_args.deinit(allocator);

    var iter = try std.process.argsWithAllocator(allocator);
    defer iter.deinit();

    _ = iter.next();
    while (iter.next()) |arg| {
        try raw_args.append(allocator, arg);
    }

    return parseArgsSlice(allocator, raw_args.items, stderr);
}

const ArgError = error{
    UnknownOption,
    MissingOptionValue,
    InvalidOptionValue,
    OutOfMemory,
};

/// Unknown options, options without a value, and unrecognised enum values are
/// rejected instead of being ignored: a typo such as `--fmt sarif` must not
/// silently fall back to another format, and `--config --fix` must not eat
/// `--fix` as the config path.
fn parseArgsSlice(allocator: std.mem.Allocator, argv: []const []const u8, stderr: *std.Io.Writer) ArgError!CliArgs {
    var args = CliArgs{ .files = .{}, .allocator = allocator };
    errdefer args.deinit();

    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--")) {
            // Everything after `--` is a file, even if it begins with `-`.
            for (argv[i + 1 ..]) |file| {
                try args.files.append(allocator, file);
            }
            break;
        }
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            args.show_help = true;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            args.show_version = true;
        } else if (std.mem.eql(u8, arg, "--config")) {
            args.config_path = try optionValue(argv, &i, stderr);
        } else if (std.mem.eql(u8, arg, "--format")) {
            const value = try optionValue(argv, &i, stderr);
            args.format = OutputFormat.fromString(value) orelse return invalidValue(arg, value, stderr);
        } else if (std.mem.eql(u8, arg, "--color")) {
            const value = try optionValue(argv, &i, stderr);
            args.color = ColorMode.fromString(value) orelse return invalidValue(arg, value, stderr);
        } else if (std.mem.eql(u8, arg, "--offline") or std.mem.eql(u8, arg, "--quick")) {
            args.offline = true;
        } else if (std.mem.eql(u8, arg, "--no-cache")) {
            args.no_cache = true;
        } else if (std.mem.eql(u8, arg, "--fix")) {
            args.fix_mode = .safe;
        } else if (std.mem.eql(u8, arg, "--fix-unsafe")) {
            args.fix_mode = .all;
        } else if (std.mem.startsWith(u8, arg, "-") and arg.len > 1) {
            stderr.print("error: unknown option '{s}' (see --help)\n", .{arg}) catch {};
            return error.UnknownOption;
        } else {
            try args.files.append(allocator, arg);
        }
    }

    return args;
}

/// A value that itself looks like an option is treated as missing so a
/// dropped argument cannot silently swallow the next flag.
fn optionValue(argv: []const []const u8, i: *usize, stderr: *std.Io.Writer) ArgError![]const u8 {
    const option = argv[i.*];
    if (i.* + 1 >= argv.len or std.mem.startsWith(u8, argv[i.* + 1], "-")) {
        stderr.print("error: option '{s}' requires a value\n", .{option}) catch {};
        return error.MissingOptionValue;
    }
    i.* += 1;
    return argv[i.*];
}

fn invalidValue(option: []const u8, value: []const u8, stderr: *std.Io.Writer) ArgError {
    stderr.print("error: invalid value '{s}' for option '{s}'\n", .{ value, option }) catch {};
    return error.InvalidOptionValue;
}

fn printHelp(writer: anytype) !void {
    try writer.writeAll(
        \\Usage: zghalint [OPTIONS] [FILES...]
        \\
        \\GitHub Actions workflow linter
        \\
        \\Arguments:
        \\  [FILES...]  Files to lint (default: .github/workflows/*.yml, .github/dependabot.yml)
        \\              Use `--` before files whose names begin with `-`.
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
        \\Exit codes:
        \\  0  no error-severity diagnostics
        \\  1  at least one error-severity diagnostic
        \\  2  a file or the config could not be read or parsed, invalid arguments,
        \\     or a --fix write failed
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

    inline for ([_][]const u8{ ".github/dependabot.yml", ".github/dependabot.yaml" }) |dep_path| {
        if (std.fs.cwd().access(dep_path, .{})) |_| {
            const path_copy = try allocator.dupe(u8, dep_path);
            try files.append(allocator, path_copy);
        } else |_| {}
    }

    return files;
}

fn isDependabotFile(path: []const u8) bool {
    return std.mem.endsWith(u8, path, "dependabot.yml") or
        std.mem.endsWith(u8, path, "dependabot.yaml");
}

fn readSourceFile(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    stderr: *std.Io.Writer,
) ?[]u8 {
    // stat before open: opening a FIFO for reading blocks until a writer
    // appears, so the kind check cannot come after openFile.
    const stat = std.fs.cwd().statFile(file_path) catch |err| {
        stderr.print("error: cannot open '{s}': {s}\n", .{ file_path, @errorName(err) }) catch {};
        return null;
    };
    if (stat.kind != .file) {
        stderr.print("error: '{s}' is not a regular file\n", .{file_path}) catch {};
        return null;
    }

    const file = std.fs.cwd().openFile(file_path, .{}) catch |err| {
        stderr.print("error: cannot open '{s}': {s}\n", .{ file_path, @errorName(err) }) catch {};
        return null;
    };
    defer file.close();

    return file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch |err| {
        stderr.print("error: cannot read '{s}': {s}\n", .{ file_path, @errorName(err) }) catch {};
        return null;
    };
}

/// Errors that `lintFile` / `lintDependabotFile` have already reported on
/// stderr; the caller only has to record that the run cannot be trusted.
const LintFileError = error{
    UnreadableFile,
    YamlParseError,
    WorkflowParseError,
};

/// `appendOwning` is required because `diag_list`'s fix arena dies with the
/// caller's frame; `Fix.edits` would otherwise dangle.
fn appendFiltered(
    all_diags: *zghalint.DiagnosticList,
    diag_list: *zghalint.DiagnosticList,
    config: *const Config,
    file_path: []const u8,
) void {
    for (diag_list.items.items) |diag| {
        if (!config.isRuleEnabled(diag.rule_id)) continue;
        var d = diag;
        d.severity = config.getEffectiveSeverity(diag.rule_id, diag.severity);
        d.file = file_path;
        all_diags.appendOwning(d) catch {};
    }
}

fn lintDependabotFile(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    config: *const Config,
    all_diags: *zghalint.DiagnosticList,
    stderr: *std.Io.Writer,
) !void {
    const source = readSourceFile(allocator, file_path, stderr) orelse return error.UnreadableFile;
    defer allocator.free(source);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var yaml_parser = zghalint.yaml.Parser.init(arena_alloc, source);

    const yaml_node = yaml_parser.parse() catch {
        stderr.print("{s}: YAML parse error\n", .{file_path}) catch {};
        return error.YamlParseError;
    };

    var diag_list = zghalint.DiagnosticList.init(allocator);
    defer diag_list.deinit();

    zghalint.rules.dependabot.lintDependabot(yaml_node, &diag_list);

    appendFiltered(all_diags, &diag_list, config, file_path);
}

/// Runs on a throwaway arena so the cost of parsing twice (once here, once
/// in lintFile) is bounded.
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

        const yaml_node = yaml_parser.parse() catch continue;
        const workflow = zghalint.workflow.parseWorkflow(scratch, yaml_node) catch continue;
        try workflows.append(scratch, workflow);
    }

    zghalint.rules.prefetch.prefetchAllWithOptions(
        scratch,
        workflows.items,
        .{ .no_cache = no_cache },
    ) catch return;
}

/// A config that exists but cannot be read or parsed is an error, not a
/// silent fallback to defaults: the run would otherwise drop the user's
/// severity overrides and report a clean result.
fn loadConfig(allocator: std.mem.Allocator, config_path: ?[]const u8, stderr: *std.Io.Writer) !Config {
    const path = config_path orelse zghalint.config.defaultConfigPath() orelse return Config.init(allocator);

    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        stderr.print("error: cannot open config '{s}': {s}\n", .{ path, @errorName(err) }) catch {};
        return err;
    };
    defer file.close();

    const source = file.readToEndAlloc(allocator, 1024 * 1024) catch |err| {
        stderr.print("error: cannot read config '{s}': {s}\n", .{ path, @errorName(err) }) catch {};
        return err;
    };
    defer allocator.free(source);

    return zghalint.config.parseConfig(allocator, source) catch |err| {
        stderr.print("error: invalid config '{s}': {s}\n", .{ path, @errorName(err) }) catch {};
        return err;
    };
}

/// `--fix` re-reads each file and applies offsets computed during the lint
/// pass, so a path listed twice (`a.yml ./a.yml`) would apply the same edits
/// to already-rewritten content. Ignored spellings are dropped before the
/// path is resolved, so a symlink to an ignored file is still linted under
/// its own name. Returned entries borrow from `files`.
fn dedupeFiles(allocator: std.mem.Allocator, files: []const []const u8, config: *const Config) ![]const []const u8 {
    var seen = std.StringHashMap(void).init(allocator);
    defer {
        var keys = seen.keyIterator();
        while (keys.next()) |key| allocator.free(key.*);
        seen.deinit();
    }

    var unique = std.ArrayList([]const u8){};
    errdefer unique.deinit(allocator);

    for (files) |file_path| {
        if (config.isIgnored(file_path)) continue;
        const key = std.fs.cwd().realpathAlloc(allocator, file_path) catch try allocator.dupe(u8, file_path);
        const entry = try seen.getOrPut(key);
        if (entry.found_existing) {
            allocator.free(key);
            continue;
        }
        try unique.append(allocator, file_path);
    }

    return unique.toOwnedSlice(allocator);
}

fn lintFile(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    config: *const Config,
    all_diags: *zghalint.DiagnosticList,
    stderr: *std.Io.Writer,
) !void {
    const source = readSourceFile(allocator, file_path, stderr) orelse return error.UnreadableFile;
    defer allocator.free(source);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var yaml_parser = zghalint.yaml.Parser.init(arena_alloc, source);

    const yaml_node = yaml_parser.parse() catch {
        stderr.print("{s}: YAML parse error\n", .{file_path}) catch {};
        return error.YamlParseError;
    };

    const workflow = zghalint.workflow.parseWorkflow(arena_alloc, yaml_node) catch |err| {
        stderr.print("{s}: workflow parse error: {s}\n", .{ file_path, @errorName(err) }) catch {};
        return error.WorkflowParseError;
    };

    zghalint.rules.security.setRepoVisibility(config.repo_visibility);

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

    appendFiltered(all_diags, &diag_list, config, file_path);
}

fn applyFixesForFile(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    all_diags: *zghalint.DiagnosticList,
    include_unsafe: bool,
) !usize {
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

    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();
    const stat = try file.stat();
    const source = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(source);

    const result = try zghalint.fix.applyFixes(allocator, source, fixes);
    defer result.deinit(allocator);

    if (result.edits_applied == 0) return 0;

    // Atomically replace the file: write a random-named sibling and rename
    // it into place. `rename(2)` replaces the directory entry itself, so if
    // the destination was swapped to a symlink between our check and now,
    // the symlink is replaced — the link target is never written through.
    var write_buf: [4096]u8 = undefined;
    // rename(2) replaces the inode, so the new file must carry the original
    // permission bits or an executable / group-readable workflow would be
    // reset to the umask default.
    var af = try std.fs.cwd().atomicFile(file_path, .{
        .write_buffer = &write_buf,
        .mode = if (builtin.os.tag == .windows) std.fs.File.default_mode else stat.mode & 0o7777,
    });
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

/// Errors are swallowed: PERF001 simply emits diagnostics without a fix when
/// probing fails. Config overrides take precedence over probe results.
fn initWorkspaceContext(
    arena: std.mem.Allocator,
    files: []const []const u8,
    config: *const Config,
) void {
    // PERF001 is the sole consumer of the probe, so a disabled rule makes the
    // repo-root walk and the directory scan pure startup cost.
    if (!config.isRuleEnabled("PERF001")) return;

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

    // 64KB: a large workflow set emits megabytes of diagnostics, and a 4KB
    // buffer turned that into thousands of `write` syscalls (0.94s of sys
    // time on a 8.4MB terminal render).
    var stdout_buf: [64 * 1024]u8 = undefined;
    var stdout_bw = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_bw.interface;

    var stderr_buf: [1024]u8 = undefined;
    var stderr_bw = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_bw.interface;
    defer stderr.flush() catch {};

    var cli_args = parseArgs(allocator, stderr) catch return 2;
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

    var config = loadConfig(allocator, cli_args.config_path, stderr) catch return 2;
    defer config.deinit();

    if (cli_args.format) |fmt| config.output_format = fmt;
    if (cli_args.color) |color| config.color_mode = color;

    var owned_files: ?std.ArrayList([]const u8) = null;
    defer if (owned_files) |*of| {
        for (of.items) |p| allocator.free(p);
        of.deinit(allocator);
    };

    const requested_files = if (cli_args.files.items.len > 0)
        cli_args.files.items
    else blk: {
        owned_files = collectDefaultFiles(allocator) catch {
            stderr.writeAll("error: failed to scan default workflow directory\n") catch {};
            return 2;
        };
        break :blk owned_files.?.items;
    };

    const files = dedupeFiles(allocator, requested_files, &config) catch {
        stderr.writeAll("error: out of memory\n") catch {};
        return 2;
    };
    defer allocator.free(files);

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

    // RUNNER002 cannot enumerate a self-hosted fleet, so the user's own labels
    // come from `runner.labels` in .zghalint.yml.
    zghalint.rules.runner.setAllowedLabels(config.runner_labels.items);
    defer zghalint.rules.runner.setAllowedLabels(&.{});

    // Set a 10-second deadline for all network operations to prevent hangs
    zghalint.rules.engine.setNetworkDeadline(10 * std.time.ns_per_s);
    defer zghalint.rules.engine.clearNetworkDeadline();

    // Shared HTTP client amortizes TLS/TCP handshakes across rule fetches.
    zghalint.rules.http_client.init(allocator);
    defer zghalint.rules.http_client.deinit();

    zghalint.rules.advisory.initAdvisories(allocator, cli_args.offline);
    defer zghalint.rules.advisory.deinitAdvisories();
    zghalint.rules.archived.initArchived(allocator, cli_args.offline);
    defer zghalint.rules.archived.deinitArchived();
    zghalint.rules.stale_refs.initStaleRefs(allocator, cli_args.offline);
    defer zghalint.rules.stale_refs.deinitStaleRefs();

    zghalint.rules.refconfusion.initRefConfusion(allocator, cli_args.offline);
    defer zghalint.rules.refconfusion.deinitRefConfusion();

    zghalint.rules.impostor.initImpostor(allocator, cli_args.offline);
    defer zghalint.rules.impostor.deinitImpostor();

    // Batch all network-rule fetches before the lint pass so TLS/TCP
    // connections, advisories, and repo metadata are primed in the caches.
    if (!cli_args.offline) {
        prefetchNetworkData(allocator, files, &config, cli_args.no_cache) catch {};
    }

    var all_diags = zghalint.DiagnosticList.init(allocator);
    defer all_diags.deinit();

    // A file that could not be read or parsed produced no diagnostics, so a
    // clean report would be a false negative; such runs exit 2 instead.
    var had_fatal = false;
    var unlinted_count: usize = 0;

    for (files) |file_path| {
        if (config.isIgnored(file_path)) continue;
        const lint_result = if (isDependabotFile(file_path))
            lintDependabotFile(allocator, file_path, &config, &all_diags, stderr)
        else
            lintFile(allocator, file_path, &config, &all_diags, stderr);
        // lintFile / lintDependabotFile already reported the reason on stderr.
        lint_result catch {
            had_fatal = true;
            unlinted_count += 1;
        };
    }

    if (cli_args.fix_mode != .off) {
        const include_unsafe = cli_args.fix_mode == .all;
        var total_fixed: usize = 0;
        for (files) |file_path| {
            if (config.isIgnored(file_path)) continue;
            const fixed = applyFixesForFile(allocator, file_path, &all_diags, include_unsafe) catch |err| {
                stderr.print("error: failed to apply fixes to '{s}': {s}\n", .{ file_path, @errorName(err) }) catch {};
                had_fatal = true;
                continue;
            };
            total_fixed += fixed;
        }
        if (total_fixed > 0) {
            stderr.print("Applied {d} fix(es).\n", .{total_fixed}) catch {};
        }
    }

    // Errors go out before the report so a CI log shows the cause first.
    stderr.flush() catch {};

    all_diags.sort();

    const use_color = switch (config.color_mode) {
        .always => true,
        .never => false,
        .auto => std.Io.tty.detectConfig(std.fs.File.stdout()) != .no_color,
    };

    // Output. Only the terminal format is self-terminating; the machine-readable
    // formats get an explicit trailing newline.
    const rendered = switch (config.output_format) {
        .terminal => zghalint.output.terminal.renderDiagnostics(stdout, all_diags, use_color),
        .json => zghalint.output.renderJson(stdout, all_diags, files.len),
        .sarif => zghalint.output.renderSarif(stdout, all_diags, &all_rules),
    };
    rendered catch return 2;
    if (config.output_format != .terminal) stdout.writeAll("\n") catch return 2;
    try stdout.flush();

    // The rendered summary only covers files that were actually linted; make
    // the partial result explicit so "No issues found." is not misread.
    if (unlinted_count > 0) {
        stderr.print("error: {d} file(s) could not be linted; results above are incomplete\n", .{unlinted_count}) catch {};
    }
    if (had_fatal) return 2;
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

    try std.testing.expect(!hasErrors(&list));

    try list.append(.{
        .rule_id = "W1",
        .severity = .warning,
        .message = "warn",
        .span = zghalint.yaml.types.Span.point(1, 1, 0),
    });
    try std.testing.expect(!hasErrors(&list));

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
    var discard = std.Io.Writer.Discarding.init(&.{});
    var args = try parseArgsSlice(std.testing.allocator, &argv, &discard.writer);
    defer args.deinit();

    try std.testing.expect(args.offline);
    try std.testing.expectEqual(@as(usize, 1), args.files.items.len);
    try std.testing.expectEqualStrings(".github/workflows/ci.yml", args.files.items[0]);
}

test "parseArgsSlice parses no-cache flag" {
    const argv = [_][]const u8{ "--no-cache", ".github/workflows/ci.yml" };
    var discard = std.Io.Writer.Discarding.init(&.{});
    var args = try parseArgsSlice(std.testing.allocator, &argv, &discard.writer);
    defer args.deinit();

    try std.testing.expect(args.no_cache);
    try std.testing.expectEqual(@as(usize, 1), args.files.items.len);
    try std.testing.expectEqualStrings(".github/workflows/ci.yml", args.files.items[0]);
}

test "parseArgsSlice parses quick flag" {
    const argv = [_][]const u8{ "--quick", ".github/workflows/ci.yml" };
    var discard = std.Io.Writer.Discarding.init(&.{});
    var args = try parseArgsSlice(std.testing.allocator, &argv, &discard.writer);
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
    var discard = std.Io.Writer.Discarding.init(&.{});
    var args = try parseArgsSlice(std.testing.allocator, &argv, &discard.writer);
    defer args.deinit();

    try std.testing.expectEqualStrings(".zghalint.yml", args.config_path.?);
    try std.testing.expectEqual(OutputFormat.json, args.format.?);
    try std.testing.expectEqual(ColorMode.never, args.color.?);
    try std.testing.expectEqual(FixMode.all, args.fix_mode);
}

test "parseArgsSlice treats everything after -- as files" {
    var discard = std.Io.Writer.Discarding.init(&.{});
    var args = try parseArgsSlice(std.testing.allocator, &.{ "--offline", "--", "--fix-unsafe", "-h", "a.yml" }, &discard.writer);
    defer args.deinit();
    try std.testing.expect(args.offline);
    try std.testing.expect(!args.show_help);
    try std.testing.expectEqual(FixMode.off, args.fix_mode);
    try std.testing.expectEqual(@as(usize, 3), args.files.items.len);
    try std.testing.expectEqualStrings("--fix-unsafe", args.files.items[0]);
    try std.testing.expectEqualStrings("-h", args.files.items[1]);
    try std.testing.expectEqualStrings("a.yml", args.files.items[2]);
}

test "parseArgsSlice rejects an unknown option" {
    var discard = std.Io.Writer.Discarding.init(&.{});
    try std.testing.expectError(error.UnknownOption, parseArgsSlice(std.testing.allocator, &.{ "--fmt", "json" }, &discard.writer));
}

test "parseArgsSlice rejects an invalid --format value" {
    var discard = std.Io.Writer.Discarding.init(&.{});
    try std.testing.expectError(error.InvalidOptionValue, parseArgsSlice(std.testing.allocator, &.{ "--format", "bogus" }, &discard.writer));
}

test "parseArgsSlice does not consume a flag as an option value" {
    var discard = std.Io.Writer.Discarding.init(&.{});
    try std.testing.expectError(error.MissingOptionValue, parseArgsSlice(std.testing.allocator, &.{ "--config", "--fix" }, &discard.writer));
    try std.testing.expectError(error.MissingOptionValue, parseArgsSlice(std.testing.allocator, &.{"--config"}, &discard.writer));
}

test "parseArgsSlice reports the offending argument" {
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.UnknownOption, parseArgsSlice(std.testing.allocator, &.{"--nope"}, &out.writer));
    try std.testing.expectEqualStrings("error: unknown option '--nope' (see --help)\n", out.written());
}

test "dedupeFiles keeps the first spelling of a repeated path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "a.yml", .data = "" });
    const dir_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);
    const direct = try std.fs.path.join(std.testing.allocator, &.{ dir_path, "a.yml" });
    defer std.testing.allocator.free(direct);
    const dotted = try std.fs.path.join(std.testing.allocator, &.{ dir_path, ".", "a.yml" });
    defer std.testing.allocator.free(dotted);

    const config = Config.init(std.testing.allocator);
    const files = try dedupeFiles(std.testing.allocator, &.{ direct, dotted, direct, "missing.yml", "missing.yml" }, &config);
    defer std.testing.allocator.free(files);
    try std.testing.expectEqual(@as(usize, 2), files.len);
    try std.testing.expectEqualStrings(direct, files[0]);
    try std.testing.expectEqualStrings("missing.yml", files[1]);
}

test "dedupeFiles drops ignored spellings before collapsing by real path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "a.yml", .data = "" });
    try tmp.dir.symLink("a.yml", "b.yml", .{});
    const dir_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);
    const ignored = try std.fs.path.join(std.testing.allocator, &.{ dir_path, "a.yml" });
    defer std.testing.allocator.free(ignored);
    const link = try std.fs.path.join(std.testing.allocator, &.{ dir_path, "b.yml" });
    defer std.testing.allocator.free(link);

    var config = Config.init(std.testing.allocator);
    defer config.deinit();
    try config.ignore_patterns.append(std.testing.allocator, try config.strings_arena.allocator().dupe(u8, ignored));

    const files = try dedupeFiles(std.testing.allocator, &.{ ignored, link }, &config);
    defer std.testing.allocator.free(files);
    try std.testing.expectEqual(@as(usize, 1), files.len);
    try std.testing.expectEqualStrings(link, files[0]);
}
