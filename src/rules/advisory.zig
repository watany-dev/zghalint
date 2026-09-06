const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml = @import("../yaml/types.zig");
const engine = @import("engine.zig");
const http_client = @import("http_client.zig");
const json_util = @import("json_util.zig");

const Allocator = std.mem.Allocator;
const DiagnosticList = diagnostics.DiagnosticList;
const spans = @import("spans.zig");
const Step = workflow_types.Step;
const ActionRef = workflow_types.ActionRef;
const isValidGitHubComponent = engine.isValidGitHubComponent;

pub const Advisory = struct {
    ghsa_id: []const u8,
    action_slug: []const u8,
    vulnerable_range: ?[]const u8,
    patched_version: ?[]const u8,
    diagnostic_message: []const u8,
    diagnostic_hint: []const u8,
};

const Semver = struct {
    major: u32,
    minor: u32,
    patch: u32,
};

var advisory_cache: ?[]const Advisory = null;
var advisory_arena: ?std.heap.ArenaAllocator = null;
var is_offline: bool = true;
var fetched: bool = false;

const cache_max_age_s: i64 = 24 * 60 * 60;

/// The HTTP fetch is deferred until the first call to
/// checkKnownVulnerableAction() to avoid blocking startup.
pub fn initAdvisories(backing_allocator: Allocator, offline: bool) void {
    advisory_arena = std.heap.ArenaAllocator.init(backing_allocator);
    is_offline = offline;
}

pub fn deinitAdvisories() void {
    if (advisory_arena) |*arena| {
        arena.deinit();
        advisory_arena = null;
    }
    advisory_cache = null;
    is_offline = true;
    fetched = false;
}

pub fn prefetch() void {
    ensureLoaded();
}

fn ensureLoaded() void {
    if (fetched) return;
    fetched = true;
    const arena = &(advisory_arena orelse return);
    advisory_cache = loadAdvisories(arena.allocator());
}

pub fn checkKnownVulnerableAction(step: *const Step, list: *DiagnosticList) void {
    ensureLoaded();

    const advisories = advisory_cache orelse return;
    const action_ref = step.uses orelse return;
    if (action_ref.is_local or action_ref.is_docker) return;
    const owner = action_ref.owner orelse return;
    const repo = action_ref.repo orelse return;
    if (!isValidGitHubComponent(owner) or !isValidGitHubComponent(repo)) return;

    for (advisories) |adv| {
        if (!slugMatches(adv.action_slug, owner, repo)) continue;

        if (action_ref.ref) |ref| {
            if (!action_ref.is_pinned) {
                if (adv.vulnerable_range) |range| {
                    if (!isVersionVulnerable(ref, range)) continue;
                }
            }
            // SHA ref: can't determine version, always warn if action has advisory
        }

        list.append(.{
            .rule_id = "SC003",
            .severity = .warning,
            .message = adv.diagnostic_message,
            .span = spans.usesSpan(step),
            .fix_hint = adv.diagnostic_hint,
        }) catch return;
        return; // One diagnostic per step
    }
}

const cache_subdir = "zghalint";
const cache_filename = "advisories-v2.tsv";

fn getCacheDir(allocator: Allocator) ?std.fs.Dir {
    // XDG_CACHE_HOME is already a cache root; HOME needs the conventional
    // `.cache` segment appended.
    if (openCacheSubdir(allocator, "XDG_CACHE_HOME", cache_subdir)) |dir| return dir;
    return openCacheSubdir(allocator, "HOME", ".cache/" ++ cache_subdir);
}

fn openCacheSubdir(allocator: Allocator, env_var: []const u8, comptime sub_path: []const u8) ?std.fs.Dir {
    const base = std.process.getEnvVarOwned(allocator, env_var) catch return null;
    defer allocator.free(base);
    var dir = std.fs.openDirAbsolute(base, .{}) catch return null;
    defer dir.close();
    return dir.makeOpenPath(sub_path, .{}) catch null;
}

fn isCacheFresh(dir: std.fs.Dir) bool {
    const stat = dir.statFile(cache_filename) catch return false;
    const now = std.time.timestamp();
    const mtime: i64 = @intCast(@divTrunc(stat.mtime, std.time.ns_per_s));
    return (now - mtime) < cache_max_age_s;
}

fn writeCacheFile(dir: std.fs.Dir, data: []const u8) void {
    const file = dir.createFile(cache_filename, .{}) catch return;
    defer file.close();
    file.writeAll(data) catch {};
}

fn serializeAdvisories(allocator: Allocator, advisories: []const Advisory) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    for (advisories) |adv| {
        try out.writer.print("{s}\t{s}\t{s}\t{s}\t{s}\t{s}\n", .{
            adv.ghsa_id,
            adv.action_slug,
            adv.diagnostic_message,
            adv.diagnostic_hint,
            adv.vulnerable_range orelse "",
            adv.patched_version orelse "",
        });
    }
    return out.toOwnedSlice();
}

fn deserializeAdvisories(allocator: Allocator, data: []const u8) ![]const Advisory {
    var result = std.ArrayList(Advisory){};
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, '\t');
        const ghsa_id = fields.next() orelse continue;
        const action_slug = fields.next() orelse continue;
        const message = fields.next() orelse continue;
        const hint = fields.next() orelse continue;
        const range_str = fields.next() orelse continue;
        const patched_str = fields.next() orelse continue;
        const range: ?[]const u8 = if (range_str.len > 0) range_str else null;
        const patched: ?[]const u8 = if (patched_str.len > 0) patched_str else null;

        result.append(allocator, .{
            .ghsa_id = ghsa_id,
            .action_slug = action_slug,
            .vulnerable_range = range,
            .patched_version = patched,
            .diagnostic_message = message,
            .diagnostic_hint = hint,
        }) catch continue;
    }
    return result.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

fn readCacheFile(allocator: Allocator, dir: std.fs.Dir) ![]const Advisory {
    const file = dir.openFile(cache_filename, .{}) catch return error.CacheMiss;
    defer file.close();
    const body = file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch return error.CacheMiss;
    return deserializeAdvisories(allocator, body);
}

fn loadFromDiskCache(allocator: Allocator, dir: std.fs.Dir) ![]const Advisory {
    if (!isCacheFresh(dir)) return error.CacheStale;
    return readCacheFile(allocator, dir);
}

/// The cache directory is opened once and shared by both read attempts;
/// reopening it per attempt doubled the startup syscalls of a stale-cache run.
fn loadAdvisories(allocator: Allocator) ?[]const Advisory {
    var cache_dir = getCacheDir(allocator);
    defer if (cache_dir) |*d| d.close();

    if (cache_dir) |dir| {
        if (loadFromDiskCache(allocator, dir)) |advisories| return advisories else |_| {}
    }

    if (!is_offline) {
        if (fetchAndParse(allocator)) |advisories| return advisories else |_| {}
    }

    if (cache_dir) |dir| {
        return readCacheFile(allocator, dir) catch null;
    }
    return null;
}

const api_url = "https://api.github.com/advisories?type=reviewed&ecosystem=actions&per_page=100";

fn fetchAndParse(allocator: Allocator) ![]const Advisory {
    var resp = http_client.fetchAuthenticatedJson(allocator, api_url) catch return error.FetchFailed;
    defer resp.deinit();

    if (resp.status != .ok) return error.HttpError;

    const advisories = try parseAdvisories(allocator, resp.body);

    if (serializeAdvisories(allocator, advisories)) |serialized| {
        if (getCacheDir(allocator)) |dir_val| {
            var dir_mut = dir_val;
            writeCacheFile(dir_mut, serialized);
            dir_mut.close();
        }
    } else |_| {}

    return advisories;
}

fn parseAdvisories(allocator: Allocator, body: []const u8) ![]const Advisory {
    const root = std.json.parseFromSliceLeaky(std.json.Value, allocator, body, .{}) catch return error.JsonParseError;

    const items = switch (root) {
        .array => |arr| arr.items,
        else => return error.UnexpectedFormat,
    };

    var result = std.ArrayList(Advisory){};

    for (items) |item| {
        const obj = json_util.asObject(item) orelse continue;
        const ghsa_id = json_util.stringField(obj, "ghsa_id") orelse continue;
        const summary = json_util.stringField(obj, "summary") orelse "";

        const vulns = json_util.arrayField(obj, "vulnerabilities") orelse continue;

        for (vulns) |vuln_item| {
            const vuln = json_util.asObject(vuln_item) orelse continue;
            const pkg = json_util.objField(vuln, "package") orelse continue;
            const ecosystem = json_util.stringField(pkg, "ecosystem") orelse continue;
            if (!std.mem.eql(u8, ecosystem, "actions")) continue;

            const action_name = json_util.stringField(pkg, "name") orelse continue;
            const range = json_util.stringField(vuln, "vulnerable_version_range");
            const patched = getJsonStringFromObj(vuln, "first_patched_version");

            const message = std.fmt.allocPrint(allocator, "action '{s}' has known vulnerability {s}: {s}", .{
                action_name, ghsa_id, summary,
            }) catch continue;

            const hint = if (patched) |p|
                std.fmt.allocPrint(allocator, "update to version {s} or later, see https://github.com/advisories/{s}", .{ p, ghsa_id }) catch continue
            else
                std.fmt.allocPrint(allocator, "check https://github.com/advisories/{s} for remediation", .{ghsa_id}) catch continue;

            result.append(allocator, .{
                .ghsa_id = ghsa_id,
                .action_slug = action_name,
                .vulnerable_range = range,
                .patched_version = patched,
                .diagnostic_message = message,
                .diagnostic_hint = hint,
            }) catch continue;
        }
    }

    return result.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

fn getJsonStringFromObj(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    // first_patched_version can be an object with "identifier" field or a string
    if (json_util.stringField(obj, key)) |s| return s;
    const nested = json_util.objField(obj, key) orelse return null;
    return json_util.stringField(nested, "identifier");
}

fn slugMatches(advisory_slug: []const u8, owner: []const u8, repo: []const u8) bool {
    const slash_pos = std.mem.indexOfScalar(u8, advisory_slug, '/') orelse return false;
    const adv_owner = advisory_slug[0..slash_pos];
    const adv_repo = advisory_slug[slash_pos + 1 ..];
    return std.mem.eql(u8, adv_owner, owner) and std.mem.eql(u8, adv_repo, repo);
}

fn parseSemver(ref: []const u8) ?Semver {
    var s = ref;
    if (s.len > 0 and (s[0] == 'v' or s[0] == 'V')) {
        s = s[1..];
    }
    if (s.len == 0) return null;

    var parts = std.mem.splitScalar(u8, s, '.');
    var out = [_]u32{ 0, 0, 0 };
    for (&out, 0..) |*slot, i| {
        const part = parts.next() orelse break;
        // The patch component stops at the first non-digit so that
        // pre-release tags like "1.2.3-beta" still parse.
        const digits = if (i == 2) part[0..digitPrefixLen(part)] else part;
        if (digits.len == 0) return null;
        slot.* = std.fmt.parseInt(u32, digits, 10) catch return null;
    }

    return .{ .major = out[0], .minor = out[1], .patch = out[2] };
}

fn digitPrefixLen(s: []const u8) usize {
    for (s, 0..) |c, i| {
        if (!std.ascii.isDigit(c)) return i;
    }
    return s.len;
}

fn semverCompare(a: Semver, b: Semver) std.math.Order {
    if (a.major != b.major) return std.math.order(a.major, b.major);
    if (a.minor != b.minor) return std.math.order(a.minor, b.minor);
    return std.math.order(a.patch, b.patch);
}

const Operator = enum { lt, lte, gt, gte };

const Constraint = struct {
    op: Operator,
    version: Semver,
};

fn parseConstraint(s: []const u8) ?Constraint {
    var rest = std.mem.trimLeft(u8, s, " ");

    var op: Operator = undefined;
    if (std.mem.startsWith(u8, rest, "<=")) {
        op = .lte;
        rest = rest[2..];
    } else if (std.mem.startsWith(u8, rest, ">=")) {
        op = .gte;
        rest = rest[2..];
    } else if (std.mem.startsWith(u8, rest, "<")) {
        op = .lt;
        rest = rest[1..];
    } else if (std.mem.startsWith(u8, rest, ">")) {
        op = .gt;
        rest = rest[1..];
    } else {
        return null;
    }

    rest = std.mem.trimLeft(u8, rest, " ");
    const ver = parseSemver(rest) orelse return null;
    return .{ .op = op, .version = ver };
}

fn satisfiesConstraint(ver: Semver, constraint: Constraint) bool {
    const ord = semverCompare(ver, constraint.version);
    return switch (constraint.op) {
        .lt => ord == .lt,
        .lte => ord == .lt or ord == .eq,
        .gt => ord == .gt,
        .gte => ord == .gt or ord == .eq,
    };
}

/// Unparseable refs or ranges are treated as vulnerable (conservative).
pub fn isVersionVulnerable(ref: []const u8, range: []const u8) bool {
    const ver = parseSemver(ref) orelse return true;

    // Split range on comma for AND conditions (e.g., ">= 2.0.0, < 2.3.1")
    var iter = std.mem.splitScalar(u8, range, ',');
    while (iter.next()) |part| {
        const constraint = parseConstraint(part) orelse return true;
        if (!satisfiesConstraint(ver, constraint)) return false;
    }
    return true;
}

const testing = std.testing;

test "parseSemver: v1.2.3" {
    const v = parseSemver("v1.2.3").?;
    try testing.expectEqual(@as(u32, 1), v.major);
    try testing.expectEqual(@as(u32, 2), v.minor);
    try testing.expectEqual(@as(u32, 3), v.patch);
}

test "parseSemver: 1.2.3 without v prefix" {
    const v = parseSemver("1.2.3").?;
    try testing.expectEqual(@as(u32, 1), v.major);
    try testing.expectEqual(@as(u32, 2), v.minor);
    try testing.expectEqual(@as(u32, 3), v.patch);
}

test "parseSemver: v1 major only" {
    const v = parseSemver("v1").?;
    try testing.expectEqual(@as(u32, 1), v.major);
    try testing.expectEqual(@as(u32, 0), v.minor);
    try testing.expectEqual(@as(u32, 0), v.patch);
}

test "parseSemver: v1.2 major.minor" {
    const v = parseSemver("v1.2").?;
    try testing.expectEqual(@as(u32, 1), v.major);
    try testing.expectEqual(@as(u32, 2), v.minor);
    try testing.expectEqual(@as(u32, 0), v.patch);
}

test "parseSemver: pre-release tag 1.2.3-beta" {
    const v = parseSemver("1.2.3-beta").?;
    try testing.expectEqual(@as(u32, 1), v.major);
    try testing.expectEqual(@as(u32, 2), v.minor);
    try testing.expectEqual(@as(u32, 3), v.patch);
}

test "parseSemver: invalid string" {
    try testing.expect(parseSemver("main") == null);
    try testing.expect(parseSemver("") == null);
    try testing.expect(parseSemver("v") == null);
    try testing.expect(parseSemver("abc.def.ghi") == null);
}

test "semverCompare: equal" {
    const a = Semver{ .major = 1, .minor = 2, .patch = 3 };
    const b = Semver{ .major = 1, .minor = 2, .patch = 3 };
    try testing.expect(semverCompare(a, b) == .eq);
}

test "semverCompare: less than" {
    try testing.expect(semverCompare(
        .{ .major = 1, .minor = 0, .patch = 0 },
        .{ .major = 2, .minor = 0, .patch = 0 },
    ) == .lt);
    try testing.expect(semverCompare(
        .{ .major = 1, .minor = 2, .patch = 0 },
        .{ .major = 1, .minor = 3, .patch = 0 },
    ) == .lt);
    try testing.expect(semverCompare(
        .{ .major = 1, .minor = 2, .patch = 3 },
        .{ .major = 1, .minor = 2, .patch = 4 },
    ) == .lt);
}

test "isVersionVulnerable: < 1.0.0" {
    try testing.expect(isVersionVulnerable("v0.9.0", "< 1.0.0"));
    try testing.expect(!isVersionVulnerable("v1.0.0", "< 1.0.0"));
    try testing.expect(!isVersionVulnerable("v1.0.1", "< 1.0.0"));
}

test "isVersionVulnerable: <= 3.0.0" {
    try testing.expect(isVersionVulnerable("v2.9.9", "<= 3.0.0"));
    try testing.expect(isVersionVulnerable("v3.0.0", "<= 3.0.0"));
    try testing.expect(!isVersionVulnerable("v3.0.1", "<= 3.0.0"));
}

test "isVersionVulnerable: range >= 2.0.0, < 2.3.1" {
    try testing.expect(!isVersionVulnerable("v1.9.9", ">= 2.0.0, < 2.3.1"));
    try testing.expect(isVersionVulnerable("v2.0.0", ">= 2.0.0, < 2.3.1"));
    try testing.expect(isVersionVulnerable("v2.3.0", ">= 2.0.0, < 2.3.1"));
    try testing.expect(!isVersionVulnerable("v2.3.1", ">= 2.0.0, < 2.3.1"));
    try testing.expect(!isVersionVulnerable("v3.0.0", ">= 2.0.0, < 2.3.1"));
}

test "isVersionVulnerable: unparseable ref is conservatively vulnerable" {
    try testing.expect(isVersionVulnerable("main", "< 1.0.0"));
}

test "isVersionVulnerable: unparseable range is conservatively vulnerable" {
    try testing.expect(isVersionVulnerable("v1.0.0", "invalid"));
}

test "slugMatches: exact match" {
    try testing.expect(slugMatches("actions/checkout", "actions", "checkout"));
}

test "slugMatches: different repo" {
    try testing.expect(!slugMatches("actions/checkout", "actions", "setup-node"));
}

test "slugMatches: different owner" {
    try testing.expect(!slugMatches("actions/checkout", "other", "checkout"));
}

test "slugMatches: no slash in slug" {
    try testing.expect(!slugMatches("noslash", "no", "slash"));
}

test "parseAdvisories: valid response" {
    const json_input =
        \\[{"ghsa_id":"GHSA-test-1234","summary":"Test vuln","severity":"high",
        \\"vulnerabilities":[{"package":{"ecosystem":"actions","name":"evil/action"},
        \\"vulnerable_version_range":"< 1.0.0","first_patched_version":{"identifier":"1.0.0"}}]}]
    ;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const result = try parseAdvisories(arena.allocator(), json_input);
    try testing.expectEqual(@as(usize, 1), result.len);
    try testing.expectEqualStrings("evil/action", result[0].action_slug);
    try testing.expectEqualStrings("GHSA-test-1234", result[0].ghsa_id);
    try testing.expectEqualStrings("< 1.0.0", result[0].vulnerable_range.?);
    try testing.expectEqualStrings("1.0.0", result[0].patched_version.?);
}

test "parseAdvisories: empty array" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const result = try parseAdvisories(arena.allocator(), "[]");
    try testing.expectEqual(@as(usize, 0), result.len);
}

test "parseAdvisories: malformed JSON" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const result = parseAdvisories(arena.allocator(), "not json");
    try testing.expectError(error.JsonParseError, result);
}

test "parseAdvisories: filters non-actions ecosystem" {
    const json_input =
        \\[{"ghsa_id":"GHSA-npm","summary":"npm vuln","severity":"low",
        \\"vulnerabilities":[{"package":{"ecosystem":"npm","name":"some-package"},
        \\"vulnerable_version_range":"< 2.0"}]}]
    ;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const result = try parseAdvisories(arena.allocator(), json_input);
    try testing.expectEqual(@as(usize, 0), result.len);
}

test "parseAdvisories: multiple vulnerabilities" {
    const json_input =
        \\[{"ghsa_id":"GHSA-a","summary":"Vuln A","severity":"critical",
        \\"vulnerabilities":[
        \\  {"package":{"ecosystem":"actions","name":"owner/action-a"},"vulnerable_version_range":"< 2.0.0"},
        \\  {"package":{"ecosystem":"actions","name":"owner/action-b"},"vulnerable_version_range":"< 3.0.0"}
        \\]}]
    ;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const result = try parseAdvisories(arena.allocator(), json_input);
    try testing.expectEqual(@as(usize, 2), result.len);
    try testing.expectEqualStrings("owner/action-a", result[0].action_slug);
    try testing.expectEqualStrings("owner/action-b", result[1].action_slug);
}

const mock_advisories = [_]Advisory{.{
    .ghsa_id = "GHSA-test-1234",
    .action_slug = "evil/action",
    .vulnerable_range = "< 1.0.0",
    .patched_version = "1.0.0",
    .diagnostic_message = "action 'evil/action' has known vulnerability GHSA-test-1234",
    .diagnostic_hint = "update to version 1.0.0 or later",
}};

const unbounded_advisories = [_]Advisory{blk: {
    var a = mock_advisories[0];
    a.vulnerable_range = null;
    a.patched_version = null;
    break :blk a;
}};

/// Module state is saved and restored so tests stay independent of each other.
fn runWithAdvisories(advisories: []const Advisory, uses_ref: ?[]const u8) DiagnosticList {
    const prev_cache = advisory_cache;
    const prev_offline = is_offline;
    const prev_fetched = fetched;
    defer {
        advisory_cache = prev_cache;
        is_offline = prev_offline;
        fetched = prev_fetched;
    }
    advisory_cache = advisories;
    is_offline = false;
    fetched = true;

    const step = Step{
        .uses = if (uses_ref) |r| ActionRef.parse(r) else null,
        .run = if (uses_ref == null) "echo hello" else null,
    };
    var list = DiagnosticList.init(testing.allocator);
    checkKnownVulnerableAction(&step, &list);
    return list;
}

test "SC003: offline mode produces no diagnostics" {
    const prev_cache = advisory_cache;
    const prev_offline = is_offline;
    const prev_fetched = fetched;
    advisory_cache = null;
    is_offline = true;
    fetched = false;
    defer {
        advisory_cache = prev_cache;
        is_offline = prev_offline;
        fetched = prev_fetched;
    }

    const step = Step{ .uses = ActionRef.parse("actions/checkout@v4") };
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    checkKnownVulnerableAction(&step, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC003: detects known vulnerable action" {
    var list = runWithAdvisories(&mock_advisories, "evil/action@v0.9.0");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expectEqualStrings("SC003", list.get(0).rule_id);
}

test "SC003: safe action not flagged" {
    var list = runWithAdvisories(&mock_advisories, "actions/checkout@v4");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC003: patched version not flagged" {
    var list = runWithAdvisories(&mock_advisories, "evil/action@v1.0.0");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC003: SHA ref with vulnerable action still warns" {
    var list = runWithAdvisories(&mock_advisories, "evil/action@a5ac7e51b41094c92402da3b24376905380afc29");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expectEqualStrings("SC003", list.get(0).rule_id);
}

test "SC003: local action skipped" {
    var list = runWithAdvisories(&mock_advisories, "./local-action");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC003: step without uses skipped" {
    var list = runWithAdvisories(&mock_advisories, null);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC003: advisory without version range always flags" {
    var list = runWithAdvisories(&unbounded_advisories, "evil/action@v99.0.0");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 1), list.len());
}

test "SC003: invalid owner characters rejected" {
    var list = runWithAdvisories(&mock_advisories, "evil?owner/action@v0.9.0");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC003: lazy fetch with deadline exceeded produces no diagnostics" {
    const prev_cache = advisory_cache;
    const prev_offline = is_offline;
    const prev_fetched = fetched;
    const prev_arena = advisory_arena;
    advisory_cache = null;
    is_offline = false;
    fetched = false;
    advisory_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer {
        if (advisory_arena) |*a| a.deinit();
        advisory_cache = prev_cache;
        is_offline = prev_offline;
        fetched = prev_fetched;
        advisory_arena = prev_arena;
    }

    engine.network_deadline_ns = std.time.nanoTimestamp() - 1;
    defer engine.clearNetworkDeadline();

    const step = Step{ .uses = ActionRef.parse("evil/action@v0.9.0") };
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    checkKnownVulnerableAction(&step, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
    try testing.expect(fetched);
}
