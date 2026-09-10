const std = @import("std");
const runtime = zghalint.runtime;
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
    var args = CliArgs{ .files = .empty, .allocator = allocator };
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
        \\  [FILES...]  Files to lint (default: .github/workflows/*.yml, .github/dependabot.yml,
        \\              action.yml, .github/actions/*/action.yml)
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
    var files = std.ArrayList([]const u8).empty;
    var dir = std.Io.Dir.cwd().openDir(runtime.io(), ".github/workflows", .{ .iterate = true }) catch return files;
    defer dir.close(runtime.io());

    var iter = dir.iterate();
    while (try iter.next(runtime.io())) |entry| {
        if (entry.kind == .file) {
            if (std.mem.endsWith(u8, entry.name, ".yml") or std.mem.endsWith(u8, entry.name, ".yaml")) {
                const full_path = try std.fmt.allocPrint(allocator, ".github/workflows/{s}", .{entry.name});
                try files.append(allocator, full_path);
            }
        }
    }

    inline for ([_][]const u8{ ".github/dependabot.yml", ".github/dependabot.yaml" }) |dep_path| {
        if (std.Io.Dir.cwd().access(runtime.io(), dep_path, .{})) |_| {
            const path_copy = try allocator.dupe(u8, dep_path);
            try files.append(allocator, path_copy);
        } else |_| {}
    }

    try collectDefaultActionFiles(allocator, &files);

    return files;
}

/// The two layouts GitHub itself documents: an action at the repository root,
/// and one action per directory under `.github/actions/`. Deeper nestings are
/// not searched; those paths can still be passed explicitly.
fn collectDefaultActionFiles(
    allocator: std.mem.Allocator,
    files: *std.ArrayList([]const u8),
) !void {
    inline for ([_][]const u8{ "action.yml", "action.yaml" }) |name| {
        if (std.Io.Dir.cwd().access(runtime.io(), name, .{})) |_| {
            try files.append(allocator, try allocator.dupe(u8, name));
        } else |_| {}
    }

    var dir = std.Io.Dir.cwd().openDir(runtime.io(), ".github/actions", .{ .iterate = true }) catch return;
    defer dir.close(runtime.io());

    // A directory that cannot be walked is treated like one that is not
    // there: every other probe here is best-effort too, and a default-file
    // scan should not fail the whole run.
    var iter = dir.iterate();
    while (iter.next(runtime.io()) catch return) |entry| {
        // The kind is not checked: a symlinked action directory is as valid
        // as a real one, and `access` on the file below settles it either way.
        inline for ([_][]const u8{ "action.yml", "action.yaml" }) |name| {
            const path = try std.fmt.allocPrint(allocator, ".github/actions/{s}/{s}", .{ entry.name, name });
            errdefer allocator.free(path);
            if (std.Io.Dir.cwd().access(runtime.io(), path, .{})) |_| {
                try files.append(allocator, path);
            } else |_| {
                allocator.free(path);
            }
        }
    }
}

/// `automerge-dependabot.yml` is an ordinary workflow, not Dependabot config (#349).
fn isDependabotFile(path: []const u8) bool {
    return isDocumentFileNamed(path, "dependabot.yml", "dependabot.yaml");
}

/// Matches on the file name, not a suffix: `my-action.yml` is a workflow-shaped
/// file name, not action metadata.
fn isActionMetadataFile(path: []const u8) bool {
    return isDocumentFileNamed(path, "action.yml", "action.yaml");
}

/// A file under `.github/workflows/` is a workflow whatever it is called, so
/// `workflows/action.yml` and `workflows/dependabot.yml` keep the workflow rules.
fn isDocumentFileNamed(path: []const u8, yml: []const u8, yaml: []const u8) bool {
    const base = std.Io.Dir.path.basename(path);
    if (!std.mem.eql(u8, base, yml) and !std.mem.eql(u8, base, yaml)) return false;

    const dir = std.Io.Dir.path.dirname(path) orelse return true;
    return !std.mem.eql(u8, std.Io.Dir.path.basename(dir), "workflows");
}

fn readSourceFile(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    stderr: *std.Io.Writer,
) ?[]u8 {
    // stat before open: opening a FIFO for reading blocks until a writer
    // appears, so the kind check cannot come after openFile.
    const stat = std.Io.Dir.cwd().statFile(runtime.io(), file_path, .{}) catch |err| {
        stderr.print("error: cannot open '{s}': {s}\n", .{ file_path, @errorName(err) }) catch {};
        return null;
    };
    if (stat.kind != .file) {
        stderr.print("error: '{s}' is not a regular file\n", .{file_path}) catch {};
        return null;
    }

    const file = std.Io.Dir.cwd().openFile(runtime.io(), file_path, .{}) catch |err| {
        stderr.print("error: cannot open '{s}': {s}\n", .{ file_path, @errorName(err) }) catch {};
        return null;
    };
    defer file.close(runtime.io());

    var file_reader = file.reader(runtime.io(), &.{});
    return file_reader.interface.allocRemaining(allocator, .limited(10 * 1024 * 1024)) catch |err| {
        stderr.print("error: cannot read '{s}': {s}\n", .{ file_path, @errorName(err) }) catch {};
        return null;
    };
}

fn documentLintFn(path: []const u8) ?*const fn (zghalint.yaml.types.Node, *zghalint.DiagnosticList) void {
    if (isDependabotFile(path)) return &zghalint.rules.dependabot.lintDependabot;
    if (isActionMetadataFile(path)) return &zghalint.rules.action_metadata.lintActionMetadata;
    return null;
}

/// Errors that `lintFile` / `lintDocumentFile` have already reported on
/// stderr; the caller only has to record that the run cannot be trusted.
const LintFileError = error{
    UnreadableFile,
    YamlParseError,
    WorkflowParseError,
};

/// An undefined `*alias` is an error about one line of the file, not about the
/// file as a whole, so it is reported with the position the parser recorded.
fn reportYamlParseError(
    stderr: *std.Io.Writer,
    file_path: []const u8,
    err: anyerror,
    parser: *const zghalint.yaml.Parser,
) void {
    if (parser.failure) |failure| {
        stderr.print("{s}:{d}:{d}: YAML parse error: {s}: '*{s}'\n", .{
            file_path,
            failure.span.start_line,
            failure.span.start_col,
            @errorName(err),
            failure.alias,
        }) catch {};
        return;
    }
    stderr.print("{s}: YAML parse error: {s}\n", .{ file_path, @errorName(err) }) catch {};
}

/// A workflow parse error is about one field of the file, so it is reported
/// with the path the parser recorded and, when the offending node exists in
/// the source, its position. A missing field has no node to point at, so only
/// the path is shown.
fn reportWorkflowParseError(
    stderr: *std.Io.Writer,
    file_path: []const u8,
    err: anyerror,
    failure: ?zghalint.workflow.parser.Failure,
) void {
    const f = failure orelse {
        stderr.print("{s}: workflow parse error: {s}\n", .{ file_path, @errorName(err) }) catch {};
        return;
    };
    if (f.span) |span| {
        stderr.print("{s}:{d}:{d}: workflow parse error: {s}: '{s}'\n", .{
            file_path,
            span.start_line,
            span.start_col,
            @errorName(err),
            f.path,
        }) catch {};
        return;
    }
    stderr.print("{s}: workflow parse error: {s}: '{s}'\n", .{ file_path, @errorName(err), f.path }) catch {};
}

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

/// Non-workflow YAML (Dependabot config, action metadata) has no `Workflow`
/// to build, so these files go straight from the YAML document to a
/// document-level check instead of through the rule engine.
fn lintDocumentFile(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    config: *const Config,
    all_diags: *zghalint.DiagnosticList,
    stderr: *std.Io.Writer,
    lint_fn: *const fn (zghalint.yaml.types.Node, *zghalint.DiagnosticList) void,
) !void {
    const source = readSourceFile(allocator, file_path, stderr) orelse return error.UnreadableFile;
    defer allocator.free(source);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var yaml_parser = zghalint.yaml.Parser.init(arena_alloc, source);

    const yaml_node = yaml_parser.parse() catch |err| {
        reportYamlParseError(stderr, file_path, err, &yaml_parser);
        return error.YamlParseError;
    };

    var diag_list = zghalint.DiagnosticList.init(allocator);
    defer diag_list.deinit();

    lint_fn(yaml_node, &diag_list);

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

    var workflows = std.ArrayList(zghalint.workflow.Workflow).empty;
    defer workflows.deinit(scratch);

    for (files) |file_path| {
        if (config.isIgnored(file_path)) continue;
        if (documentLintFn(file_path) != null) continue;

        const file = std.Io.Dir.cwd().openFile(runtime.io(), file_path, .{}) catch continue;
        defer file.close(runtime.io());

        var file_reader = file.reader(runtime.io(), &.{});
        const source = file_reader.interface.allocRemaining(scratch, .limited(10 * 1024 * 1024)) catch continue;

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

/// 注記を出すだけで終了コードは変えない — 既存の 0/1/2 の意味を動かすと
/// 利用者の CI を壊すため (#304)。
fn reportUnreachableRules(
    stderr: *std.Io.Writer,
    config: *const Config,
    diags: *const zghalint.diagnostics.DiagnosticList,
) void {
    const net_status = zghalint.rules.net_status;
    var skipped: [net_status.rule_count][]const u8 = undefined;
    var skipped_count: usize = 0;
    var partial: [net_status.rule_count][]const u8 = undefined;
    var partial_count: usize = 0;
    for (std.enums.values(net_status.Rule)) |rule| {
        if (!net_status.isUnavailable(rule)) continue;
        // .zghalint.yml で無効にされたルールは元々指摘を出さないので、取得
        // できなかったことを伝えても利用者の判断材料にならない。
        if (!config.isRuleEnabled(rule.id())) continue;
        // 一部のステップだけ取得できたルールは指摘を出している。それを
        // 「skipped」と書くと、同じ実行が出す JSON / terminal の指摘と
        // note が食い違う (#372)。
        if (hasDiagnosticFor(diags, rule.id())) {
            partial[partial_count] = rule.id();
            partial_count += 1;
        } else {
            skipped[skipped_count] = rule.id();
            skipped_count += 1;
        }
    }
    net_status.writeNote(stderr, skipped[0..skipped_count]) catch {};
    net_status.writePartialNote(stderr, partial[0..partial_count]) catch {};
}

fn hasDiagnosticFor(diags: *const zghalint.diagnostics.DiagnosticList, rule_id: []const u8) bool {
    for (diags.items.items) |diag| {
        if (std.mem.eql(u8, diag.rule_id, rule_id)) return true;
    }
    return false;
}

/// A config that exists but cannot be read or parsed is an error, not a
/// silent fallback to defaults: the run would otherwise drop the user's
/// severity overrides and report a clean result.
fn loadConfig(allocator: std.mem.Allocator, config_path: ?[]const u8, stderr: *std.Io.Writer) !Config {
    const path = config_path orelse zghalint.config.defaultConfigPath() orelse return Config.init(allocator);

    const file = std.Io.Dir.cwd().openFile(runtime.io(), path, .{}) catch |err| {
        stderr.print("error: cannot open config '{s}': {s}\n", .{ path, @errorName(err) }) catch {};
        return err;
    };
    defer file.close(runtime.io());

    var file_reader = file.reader(runtime.io(), &.{});
    const source = file_reader.interface.allocRemaining(allocator, .limited(1024 * 1024)) catch |err| {
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

    var unique = std.ArrayList([]const u8).empty;
    errdefer unique.deinit(allocator);

    for (files) |file_path| {
        if (config.isIgnored(file_path)) continue;
        var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const canonical = std.Io.Dir.cwd().realPathFile(runtime.io(), file_path, &path_buf) catch null;
        const key = try allocator.dupe(u8, if (canonical) |len| path_buf[0..len] else file_path);
        const entry = seen.getOrPut(key) catch |err| {
            allocator.free(key);
            return err;
        };
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

    const yaml_node = yaml_parser.parse() catch |err| {
        reportYamlParseError(stderr, file_path, err, &yaml_parser);
        return error.YamlParseError;
    };

    // An empty file is a finding, not an obstacle to linting: it is reported
    // here because the parse below would reject it.
    var empty_diags = zghalint.DiagnosticList.init(allocator);
    defer empty_diags.deinit();
    if (zghalint.rules.syntax.lintEmptyWorkflow(yaml_node, &empty_diags)) {
        appendFiltered(all_diags, &empty_diags, config, file_path);
        return;
    }

    var workflow_failure: ?zghalint.workflow.parser.Failure = null;
    const workflow = zghalint.workflow.parseWorkflowTracked(arena_alloc, yaml_node, &workflow_failure) catch |err| {
        reportWorkflowParseError(stderr, file_path, err, workflow_failure);
        return error.WorkflowParseError;
    };

    zghalint.rules.security.setRepoVisibility(config.repo_visibility);

    const engine = zghalint.rules.Engine.init(&all_rules);
    var diag_list = engine.run(allocator, &workflow);
    defer diag_list.deinit();

    // Strip the broader finding when a stricter one covers the same step
    // (SC008 ⊃ SC005, SEC015 ⊃ SEC018). Guard on the covering rule being
    // enabled; otherwise it would be filtered out below and neither
    // diagnostic would remain.
    zghalint.rules.engine.postProcess(allocator, &workflow, &diag_list, .{
        .drop_sc005 = config.isRuleEnabled("SC008"),
        .drop_sec018 = config.isRuleEnabled("SEC015"),
    });

    appendFiltered(all_diags, &diag_list, config, file_path);
}

const FixOutcome = struct {
    applied: usize = 0,
    /// Fixes dropped because they overlapped one that won. Reported so the
    /// user knows a second `--fix` run still has work to do.
    skipped: usize = 0,
};

fn applyFixesForFile(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    all_diags: *zghalint.DiagnosticList,
    include_unsafe: bool,
) !FixOutcome {
    var file_diags = std.ArrayList(zghalint.Diagnostic).empty;
    defer file_diags.deinit(allocator);

    for (all_diags.items.items) |d| {
        if (d.fix != null) {
            const f = d.file orelse continue;
            if (std.mem.eql(u8, f, file_path)) {
                try file_diags.append(allocator, d);
            }
        }
    }

    if (file_diags.items.len == 0) return .{};

    const fixes = try zghalint.fix.collectFixes(allocator, file_diags.items, include_unsafe);
    defer allocator.free(fixes);

    if (fixes.len == 0) return .{};

    // Refuse to rewrite through a symlink: otherwise `--fix` on a crafted
    // `workflow.yml -> /etc/passwd` would read and then overwrite the link
    // target. `readLink` succeeding means the path itself is a symlink.
    if (try zghalint.util.isSymlink(std.Io.Dir.cwd(), file_path)) return error.RefusingToFixSymlink;

    const file = try std.Io.Dir.cwd().openFile(runtime.io(), file_path, .{});
    defer file.close(runtime.io());
    const stat = try file.stat(runtime.io());
    var file_reader = file.reader(runtime.io(), &.{});
    const source = try file_reader.interface.allocRemaining(allocator, .limited(10 * 1024 * 1024));
    defer allocator.free(source);

    const result = try zghalint.fix.applyFixes(allocator, source, fixes);
    defer result.deinit(allocator);

    if (result.edits_applied == 0) return .{ .skipped = result.fixes_skipped };

    // Atomically replace the file: write a random-named sibling and rename
    // it into place. `rename(2)` replaces the directory entry itself, so if
    // the destination was swapped to a symlink between our check and now,
    // the symlink is replaced — the link target is never written through.
    // rename(2) replaces the inode, so the new file must carry the original
    // permission bits or an executable / group-readable workflow would be
    // reset to the umask default.
    var af = try std.Io.Dir.cwd().createFileAtomic(runtime.io(), file_path, .{
        .replace = true,
        .permissions = stat.permissions,
    });
    defer af.deinit(runtime.io());
    try af.file.writeStreamingAll(runtime.io(), result.content);
    // Creation applies a umask; replacement must preserve the original bits.
    if (builtin.os.tag != .windows) try af.file.setPermissions(runtime.io(), stat.permissions);
    try af.replace(runtime.io());

    return .{ .applied = result.edits_applied, .skipped = result.fixes_skipped };
}

fn hasErrors(diag_list: *zghalint.DiagnosticList) bool {
    for (diag_list.items.items) |diag| {
        if (diag.severity == .@"error") return true;
    }
    return false;
}

/// The repository root, i.e. the nearest ancestor of the linted files that
/// holds a `.git`. Both the PERF001 lockfile probe and DEP004's local action
/// lookups resolve paths against it, so it is computed once.
///
/// Null when the arguments span several repositories: pinning every `uses: ./…`
/// to one of them would make DEP004 report missing manifests for the others.
fn resolveWorkspaceRoot(arena: std.mem.Allocator, files: []const []const u8) ?[]const u8 {
    const hint = if (files.len > 0) files[0] else ".";
    const root = zghalint.workspace.findWorkspaceRoot(arena, hint) catch return null;

    // Files in a directory already checked cannot resolve to another root, so
    // the common case (one directory of workflows) costs a single walk.
    var last_dir = std.Io.Dir.path.dirname(hint) orelse ".";
    for (files) |file| {
        const dir = std.Io.Dir.path.dirname(file) orelse ".";
        if (std.mem.eql(u8, dir, last_dir)) continue;
        last_dir = dir;
        const other = zghalint.workspace.findWorkspaceRoot(arena, file) catch return null;
        if (!std.mem.eql(u8, other, root)) return null;
    }
    return root;
}

/// Errors are swallowed: PERF001 simply emits diagnostics without a fix when
/// probing fails. Config overrides take precedence over probe results.
fn initWorkspaceContext(
    arena: std.mem.Allocator,
    root: []const u8,
    config: *const Config,
) void {
    // The RW rules resolve a local `uses:` against the root, so it is set
    // whether or not the lockfile probe below runs.
    zghalint.workspace.setRepoRoot(root);

    // PERF001 is the sole consumer of the probe, so a disabled rule makes the
    // directory scan pure startup cost.
    if (!config.isRuleEnabled("PERF001")) return;

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

pub fn main(init: std.process.Init) !u8 {
    runtime.init(init);
    const allocator = init.gpa;

    // 64KB: a large workflow set emits megabytes of diagnostics, and a 4KB
    // buffer turned that into thousands of `write` syscalls (0.94s of sys
    // time on a 8.4MB terminal render).
    var stdout_buf: [64 * 1024]u8 = undefined;
    var stdout_bw = std.Io.File.stdout().writerStreaming(init.io, &stdout_buf);
    const stdout = &stdout_bw.interface;

    var stderr_buf: [1024]u8 = undefined;
    var stderr_bw = std.Io.File.stderr().writerStreaming(init.io, &stderr_buf);
    const stderr = &stderr_bw.interface;
    defer stderr.flush() catch {};

    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    var cli_args = parseArgsSlice(allocator, argv[1..], stderr) catch return 2;
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

    // Resolve the repository root (the RW rules read a called workflow
    // relative to it) and probe it for lockfiles so PERF001 can emit concrete
    // `cache: <manager>` fixes for setup-node / setup-python / setup-go.
    var workspace_arena = std.heap.ArenaAllocator.init(allocator);
    defer workspace_arena.deinit();
    const workspace_root = resolveWorkspaceRoot(workspace_arena.allocator(), files);
    if (workspace_root) |root| {
        initWorkspaceContext(workspace_arena.allocator(), root, &config);
        // DEP004 and BP003 read `action.yml` of local actions; both resolve
        // `uses: ./path` against the repository root. Disk only, so this stays
        // active under --quick / --offline.
        zghalint.rules.local_action.init(allocator, root);
    }
    defer zghalint.workspace.clear();
    defer zghalint.rules.local_action.deinit();

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

    // Only a run that can rewrite files has any use for the tag oids, so a
    // plain lint never pays for the extra lookups.
    zghalint.rules.sha_pin.initTagOids(allocator, cli_args.offline, cli_args.fix_mode != .off);
    defer zghalint.rules.sha_pin.deinitTagOids();

    zghalint.rules.net_status.reset();
    defer zghalint.rules.net_status.reset();

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
        const lint_result = if (documentLintFn(file_path)) |lint_fn|
            lintDocumentFile(allocator, file_path, &config, &all_diags, stderr, lint_fn)
        else
            lintFile(allocator, file_path, &config, &all_diags, stderr);
        // lintFile / lintDocumentFile already reported the reason on stderr.
        lint_result catch {
            had_fatal = true;
            unlinted_count += 1;
        };
    }

    if (cli_args.fix_mode != .off) {
        const include_unsafe = cli_args.fix_mode == .all;
        var total_fixed: usize = 0;
        var total_skipped: usize = 0;
        for (files) |file_path| {
            if (config.isIgnored(file_path)) continue;
            const outcome = applyFixesForFile(allocator, file_path, &all_diags, include_unsafe) catch |err| {
                stderr.print("error: failed to apply fixes to '{s}': {s}\n", .{ file_path, @errorName(err) }) catch {};
                had_fatal = true;
                continue;
            };
            total_fixed += outcome.applied;
            total_skipped += outcome.skipped;
        }
        if (total_fixed > 0) {
            stderr.print("Applied {d} fix(es).\n", .{total_fixed}) catch {};
        }
        if (total_skipped > 0) {
            // Name the flag the user actually passed: `--fix` would not apply
            // an unsafe fix that `--fix-unsafe` skipped.
            const flag = if (include_unsafe) "--fix-unsafe" else "--fix";
            stderr.print(
                "{d} fix(es) skipped: they overlap a fix that was applied. Re-run with {s} to apply them.\n",
                .{ total_skipped, flag },
            ) catch {};
        }
    }

    // Errors go out before the report so a CI log shows the cause first.
    stderr.flush() catch {};

    all_diags.sort();

    const use_color = switch (config.color_mode) {
        .always => true,
        .never => false,
        .auto => (try std.Io.Terminal.Mode.detect(
            init.io,
            std.Io.File.stdout(),
            if (init.environ_map.get("NO_COLOR")) |v| v.len > 0 else false,
            if (init.environ_map.get("CLICOLOR_FORCE")) |v| v.len > 0 else false,
        )) != .no_color,
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
    reportUnreachableRules(stderr, &config, &all_diags);
    if (had_fatal) return 2;
    if (hasErrors(&all_diags)) return 1;
    return 0;
}

test {
    _ = zghalint;
}

test "reportUnreachableRules notes marked rules in SC order, skipping disabled ones" {
    zghalint.rules.net_status.reset();
    defer zghalint.rules.net_status.reset();
    zghalint.rules.net_status.markUnavailable(.sc006);
    zghalint.rules.net_status.markUnavailable(.sc005);
    zghalint.rules.net_status.markUnavailable(.sc003);

    var config = zghalint.config.Config.init(std.testing.allocator);
    defer config.deinit();
    try config.rule_overrides.put("SC005", .{ .severity = null, .enabled = false });

    var diags = zghalint.diagnostics.DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();

    var buf: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    reportUnreachableRules(&w, &config, &diags);

    try std.testing.expectEqualStrings(
        "note: SC003, SC006 skipped (github api unreachable; check HTTPS_PROXY / SSL_CERT_FILE)\n",
        w.buffered(),
    );
}

test "reportUnreachableRules calls a rule that still reported partly checked" {
    zghalint.rules.net_status.reset();
    defer zghalint.rules.net_status.reset();
    zghalint.rules.net_status.markUnavailable(.sc005);
    zghalint.rules.net_status.markUnavailable(.sc008);

    var config = zghalint.config.Config.init(std.testing.allocator);
    defer config.deinit();

    var diags = zghalint.diagnostics.DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();
    try diags.append(.{
        .rule_id = "SC005",
        .severity = .info,
        .message = "unresolved sha",
        .span = zghalint.diagnostics.Span.point(1, 1, 0),
    });

    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    reportUnreachableRules(&w, &config, &diags);

    try std.testing.expectEqualStrings(
        "note: SC008 skipped (github api unreachable; check HTTPS_PROXY / SSL_CERT_FILE)\n" ++
            "note: SC005 partly checked (github api unreachable for some steps; check HTTPS_PROXY / SSL_CERT_FILE)\n",
        w.buffered(),
    );
}

test "reportUnreachableRules stays silent when every marked rule is disabled" {
    zghalint.rules.net_status.reset();
    defer zghalint.rules.net_status.reset();
    zghalint.rules.net_status.markUnavailable(.sc003);

    var config = zghalint.config.Config.init(std.testing.allocator);
    defer config.deinit();
    try config.rule_overrides.put("SC003", .{ .severity = null, .enabled = false });

    var diags = zghalint.diagnostics.DiagnosticList.init(std.testing.allocator);
    defer diags.deinit();

    var buf: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    reportUnreachableRules(&w, &config, &diags);

    try std.testing.expectEqualStrings("", w.buffered());
}

test "isDependabotFile matches the file name only" {
    try std.testing.expect(isDependabotFile(".github/dependabot.yml"));
    try std.testing.expect(isDependabotFile(".github/dependabot.yaml"));
    try std.testing.expect(isDependabotFile("some/path/dependabot.yml"));
    try std.testing.expect(isDependabotFile("dependabot.yml"));
    try std.testing.expect(!isDependabotFile(".github/workflows/ci.yml"));
    try std.testing.expect(!isDependabotFile("dependabot.txt"));
    // #349: an ordinary workflow whose name merely ends in `dependabot.yml`.
    try std.testing.expect(!isDependabotFile("automerge-dependabot.yml"));
    try std.testing.expect(!isDependabotFile(".github/workflows/automerge-dependabot.yaml"));
    try std.testing.expect(!isDependabotFile(".github/workflows/dependabot.yml"));
}

test "isActionMetadataFile matches the file name only" {
    try std.testing.expect(isActionMetadataFile("action.yml"));
    try std.testing.expect(isActionMetadataFile("action.yaml"));
    try std.testing.expect(isActionMetadataFile(".github/actions/build/action.yml"));
    try std.testing.expect(!isActionMetadataFile("my-action.yml"));
    try std.testing.expect(!isActionMetadataFile(".github/workflows/action.yml.bak"));
    try std.testing.expect(!isActionMetadataFile(".github/workflows/action.yml"));
}

test "documentLintFn routes non-workflow files" {
    try std.testing.expect(documentLintFn(".github/dependabot.yml") != null);
    try std.testing.expect(documentLintFn(".github/actions/build/action.yml") != null);
    try std.testing.expect(documentLintFn(".github/workflows/ci.yml") == null);
    try std.testing.expect(documentLintFn(".github/workflows/action.yml") == null);
    try std.testing.expect(documentLintFn(".github/workflows/automerge-dependabot.yml") == null);
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
    var buf = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer buf.deinit();
    try printHelp(&buf.writer);
    try std.testing.expect(std.mem.find(u8, buf.written(), "Usage: zghalint") != null);
    try std.testing.expect(std.mem.find(u8, buf.written(), "--config") != null);
    try std.testing.expect(std.mem.find(u8, buf.written(), "--format") != null);
    try std.testing.expect(std.mem.find(u8, buf.written(), "--color") != null);
    try std.testing.expect(std.mem.find(u8, buf.written(), "--quick") != null);
    try std.testing.expect(std.mem.find(u8, buf.written(), "--offline") != null);
    try std.testing.expect(std.mem.find(u8, buf.written(), "--no-cache") != null);
    try std.testing.expect(std.mem.find(u8, buf.written(), "--fix") != null);
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
    try tmp.dir.writeFile(runtime.io(), .{ .sub_path = "a.yml", .data = "" });
    const dir_path = try tmp.dir.realPathFileAlloc(runtime.io(), ".", std.testing.allocator);
    defer std.testing.allocator.free(dir_path);
    const direct = try std.Io.Dir.path.join(std.testing.allocator, &.{ dir_path, "a.yml" });
    defer std.testing.allocator.free(direct);
    const dotted = try std.Io.Dir.path.join(std.testing.allocator, &.{ dir_path, ".", "a.yml" });
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
    try tmp.dir.writeFile(runtime.io(), .{ .sub_path = "a.yml", .data = "" });
    try tmp.dir.symLink(runtime.io(), "a.yml", "b.yml", .{});
    const dir_path = try tmp.dir.realPathFileAlloc(runtime.io(), ".", std.testing.allocator);
    defer std.testing.allocator.free(dir_path);
    const ignored = try std.Io.Dir.path.join(std.testing.allocator, &.{ dir_path, "a.yml" });
    defer std.testing.allocator.free(ignored);
    const link = try std.Io.Dir.path.join(std.testing.allocator, &.{ dir_path, "b.yml" });
    defer std.testing.allocator.free(link);

    var config = Config.init(std.testing.allocator);
    defer config.deinit();
    try config.ignore_patterns.append(std.testing.allocator, try config.strings_arena.allocator().dupe(u8, ignored));

    const files = try dedupeFiles(std.testing.allocator, &.{ ignored, link }, &config);
    defer std.testing.allocator.free(files);
    try std.testing.expectEqual(@as(usize, 1), files.len);
    try std.testing.expectEqualStrings(link, files[0]);
}
