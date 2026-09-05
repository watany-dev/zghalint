const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml = @import("../yaml/types.zig");
const engine = @import("engine.zig");
const http_client = @import("http_client.zig");

const Allocator = std.mem.Allocator;
const DiagnosticList = diagnostics.DiagnosticList;
const spans = @import("spans.zig");
const Span = yaml.Span;
const Step = workflow_types.Step;
const ActionRef = workflow_types.ActionRef;
const Rule = engine.Rule;
const isValidGitHubComponent = engine.isValidGitHubComponent;

// ============================================================
// Advisory data types
// ============================================================

pub const Advisory = struct {
    ghsa_id: []const u8,
    action_slug: []const u8,
    summary: []const u8,
    severity: []const u8,
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

// ============================================================
// Module-level advisory cache
// ============================================================

var advisory_cache: ?[]const Advisory = null;
var advisory_arena: ?std.heap.ArenaAllocator = null;
var is_offline: bool = true;
var fetched: bool = false;

// ============================================================
// Public API
// ============================================================

/// Cache validity duration: 24 hours (in seconds).
const cache_max_age_s: i64 = 24 * 60 * 60;

/// Initialize advisory check. The actual HTTP fetch is deferred until the
/// first call to checkKnownVulnerableAction() to avoid blocking startup.
pub fn initAdvisories(backing_allocator: Allocator, offline: bool) void {
    advisory_arena = std.heap.ArenaAllocator.init(backing_allocator);
    is_offline = offline;
}

/// Release advisory memory.
pub fn deinitAdvisories() void {
    if (advisory_arena) |*arena| {
        arena.deinit();
        advisory_arena = null;
    }
    advisory_cache = null;
    is_offline = true;
    fetched = false;
}

/// Eagerly load the advisory database (fresh disk cache -> network fallback).
/// Safe to call multiple times; subsequent calls are no-ops.
pub fn prefetch() void {
    ensureLoaded();
}

/// Load the advisory database once per process. Both the eager `prefetch` and
/// the lazy first rule invocation funnel through here.
fn ensureLoaded() void {
    if (fetched) return;
    fetched = true;
    const arena = &(advisory_arena orelse return);
    advisory_cache = loadAdvisories(arena.allocator());
}

/// Rule check function for SC003.
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

        // Check version if ref is available
        if (action_ref.ref) |ref| {
            if (!action_ref.is_pinned) {
                // Tag ref: try semver comparison
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

// ============================================================
// Disk cache
// ============================================================

const cache_subdir = "zghalint";
const cache_filename = "advisories.json";

fn getCacheDir(allocator: Allocator) ?std.fs.Dir {
    // XDG_CACHE_HOME is already a cache root; HOME needs the conventional
    // `.cache` segment appended.
    if (openCacheSubdir(allocator, "XDG_CACHE_HOME", cache_subdir)) |dir| return dir;
    return openCacheSubdir(allocator, "HOME", ".cache/" ++ cache_subdir);
}

/// `$<env_var>/<sub_path>`, created if missing. Null when the variable is unset
/// or any step of the open fails.
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

/// One tab-separated line per advisory; absent optional fields are empty.
/// `deserializeAdvisories` is the exact inverse.
fn serializeAdvisories(allocator: Allocator, advisories: []const Advisory) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    for (advisories) |adv| {
        try out.writer.print("{s}\t{s}\t{s}\t{s}\t{s}\t{s}\n", .{
            adv.ghsa_id,
            adv.action_slug,
            adv.summary,
            adv.severity,
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
        const summary = fields.next() orelse continue;
        const severity = fields.next() orelse continue;
        const range_str = fields.next() orelse continue;
        const patched_str = fields.next() orelse continue;
        const range: ?[]const u8 = if (range_str.len > 0) range_str else null;
        const patched: ?[]const u8 = if (patched_str.len > 0) patched_str else null;

        const message = std.fmt.allocPrint(allocator, "action '{s}' has known vulnerability {s}: {s}", .{
            action_slug, ghsa_id, summary,
        }) catch continue;
        const hint = if (patched) |p|
            std.fmt.allocPrint(allocator, "update to version {s} or later, see https://github.com/advisories/{s}", .{ p, ghsa_id }) catch continue
        else
            std.fmt.allocPrint(allocator, "check https://github.com/advisories/{s} for remediation", .{ghsa_id}) catch continue;

        result.append(allocator, .{
            .ghsa_id = ghsa_id,
            .action_slug = action_slug,
            .summary = summary,
            .severity = severity,
            .vulnerable_range = range,
            .patched_version = patched,
            .diagnostic_message = message,
            .diagnostic_hint = hint,
        }) catch continue;
    }
    return result.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

fn loadFromDiskCache(allocator: Allocator) ![]const Advisory {
    var dir = getCacheDir(allocator) orelse return error.CacheMiss;
    defer dir.close();
    if (!isCacheFresh(dir)) return error.CacheStale;
    const file = dir.openFile(cache_filename, .{}) catch return error.CacheMiss;
    defer file.close();
    const body = file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch return error.CacheMiss;
    return deserializeAdvisories(allocator, body);
}

fn loadFromDiskCacheIgnoreAge(allocator: Allocator) ![]const Advisory {
    var dir = getCacheDir(allocator) orelse return error.CacheMiss;
    defer dir.close();
    const file = dir.openFile(cache_filename, .{}) catch return error.CacheMiss;
    defer file.close();
    const body = file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch return error.CacheMiss;
    return deserializeAdvisories(allocator, body);
}

fn loadAdvisories(allocator: Allocator) ?[]const Advisory {
    if (is_offline) {
        return loadFromDiskCache(allocator) catch
            loadFromDiskCacheIgnoreAge(allocator) catch
            null;
    }

    return loadFromDiskCache(allocator) catch
        fetchAndParse(allocator) catch
        loadFromDiskCacheIgnoreAge(allocator) catch
        null;
}

// ============================================================
// HTTP fetch
// ============================================================

const api_url = "https://api.github.com/advisories?type=reviewed&ecosystem=actions&per_page=100";

fn fetchAndParse(allocator: Allocator) ![]const Advisory {
    var resp = http_client.fetchAuthenticatedJson(allocator, api_url) catch return error.FetchFailed;
    defer resp.deinit();

    if (resp.status != .ok) return error.HttpError;

    const advisories = try parseAdvisories(allocator, resp.body);

    // Write parsed advisories to disk cache in compact TSV format
    if (serializeAdvisories(allocator, advisories)) |serialized| {
        if (getCacheDir(allocator)) |dir_val| {
            var dir_mut = dir_val;
            writeCacheFile(dir_mut, serialized);
            dir_mut.close();
        }
    } else |_| {}

    return advisories;
}

// ============================================================
// JSON parsing
// ============================================================

fn parseAdvisories(allocator: Allocator, body: []const u8) ![]const Advisory {
    const root = std.json.parseFromSliceLeaky(std.json.Value, allocator, body, .{}) catch return error.JsonParseError;

    const items = switch (root) {
        .array => |arr| arr.items,
        else => return error.UnexpectedFormat,
    };

    var result = std.ArrayList(Advisory){};

    for (items) |item| {
        const obj = switch (item) {
            .object => |o| o,
            else => continue,
        };

        const ghsa_id = getJsonString(obj, "ghsa_id") orelse continue;
        const summary = getJsonString(obj, "summary") orelse "";
        const severity = getJsonString(obj, "severity") orelse "unknown";

        const vulns_val = obj.get("vulnerabilities") orelse continue;
        const vulns = switch (vulns_val) {
            .array => |a| a.items,
            else => continue,
        };

        for (vulns) |vuln_item| {
            const vuln = switch (vuln_item) {
                .object => |o| o,
                else => continue,
            };
            const pkg_val = vuln.get("package") orelse continue;
            const pkg = switch (pkg_val) {
                .object => |o| o,
                else => continue,
            };
            const ecosystem = getJsonString(pkg, "ecosystem") orelse continue;
            if (!std.mem.eql(u8, ecosystem, "actions")) continue;

            const action_name = getJsonString(pkg, "name") orelse continue;
            const range = getJsonString(vuln, "vulnerable_version_range");
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
                .summary = summary,
                .severity = severity,
                .vulnerable_range = range,
                .patched_version = patched,
                .diagnostic_message = message,
                .diagnostic_hint = hint,
            }) catch continue;
        }
    }

    return result.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

fn getJsonString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

fn getJsonStringFromObj(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    // first_patched_version can be an object with "identifier" field or a string
    if (getJsonString(obj, key)) |s| return s;
    const nested = switch (obj.get(key) orelse return null) {
        .object => |o| o,
        else => return null,
    };
    return getJsonString(nested, "identifier");
}

// ============================================================
// Slug matching
// ============================================================

fn slugMatches(advisory_slug: []const u8, owner: []const u8, repo: []const u8) bool {
    const slash_pos = std.mem.indexOfScalar(u8, advisory_slug, '/') orelse return false;
    const adv_owner = advisory_slug[0..slash_pos];
    const adv_repo = advisory_slug[slash_pos + 1 ..];
    return std.mem.eql(u8, adv_owner, owner) and std.mem.eql(u8, adv_repo, repo);
}

// ============================================================
// Semver parsing and comparison
// ============================================================

fn parseSemver(ref: []const u8) ?Semver {
    var s = ref;
    // Strip leading 'v' or 'V'
    if (s.len > 0 and (s[0] == 'v' or s[0] == 'V')) {
        s = s[1..];
    }
    if (s.len == 0) return null;

    // "4", "4.1" and "4.1.2" are all accepted; missing components read as 0.
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

/// Length of the leading run of ASCII digits in `s`.
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

/// Check if a ref version falls within a vulnerable range.
/// Returns true if the version IS vulnerable (or if we can't determine).
pub fn isVersionVulnerable(ref: []const u8, range: []const u8) bool {
    const ver = parseSemver(ref) orelse return true; // Can't parse -> conservatively vulnerable

    // Split range on comma for AND conditions (e.g., ">= 2.0.0, < 2.3.1")
    var iter = std.mem.splitScalar(u8, range, ',');
    while (iter.next()) |part| {
        const constraint = parseConstraint(part) orelse return true; // Can't parse -> conservatively vulnerable
        if (!satisfiesConstraint(ver, constraint)) return false; // One constraint not met -> not in vulnerable range
    }
    return true; // All constraints met -> vulnerable
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;

// --- Semver parsing tests ---

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

// --- Semver comparison tests ---

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

// --- Version vulnerability tests ---

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

// --- Slug matching tests ---

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

// --- JSON parsing tests ---

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
    try testing.expectEqualStrings("high", result[0].severity);
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

// --- Check function tests ---

test "SC003: offline mode produces no diagnostics" {
    // Ensure offline mode
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
    const mock_advisories = [_]Advisory{
        .{
            .ghsa_id = "GHSA-test-1234",
            .action_slug = "evil/action",
            .summary = "RCE vulnerability",
            .severity = "critical",
            .vulnerable_range = "< 1.0.0",
            .patched_version = "1.0.0",
            .diagnostic_message = "action 'evil/action' has known vulnerability GHSA-test-1234",
            .diagnostic_hint = "update to version 1.0.0 or later",
        },
    };

    const prev_cache = advisory_cache;
    const prev_offline = is_offline;
    const prev_fetched = fetched;
    advisory_cache = &mock_advisories;
    is_offline = false;
    fetched = true;
    defer {
        advisory_cache = prev_cache;
        is_offline = prev_offline;
        fetched = prev_fetched;
    }

    const step = Step{ .uses = ActionRef.parse("evil/action@v0.9.0") };
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    checkKnownVulnerableAction(&step, &list);
    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expectEqualStrings("SC003", list.get(0).rule_id);
}

test "SC003: safe action not flagged" {
    const mock_advisories = [_]Advisory{
        .{
            .ghsa_id = "GHSA-test-1234",
            .action_slug = "evil/action",
            .summary = "RCE vulnerability",
            .severity = "critical",
            .vulnerable_range = "< 1.0.0",
            .patched_version = "1.0.0",
            .diagnostic_message = "action 'evil/action' has known vulnerability",
            .diagnostic_hint = "update to version 1.0.0 or later",
        },
    };

    const prev_cache = advisory_cache;
    const prev_offline = is_offline;
    const prev_fetched = fetched;
    advisory_cache = &mock_advisories;
    is_offline = false;
    fetched = true;
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

test "SC003: patched version not flagged" {
    const mock_advisories = [_]Advisory{
        .{
            .ghsa_id = "GHSA-test-1234",
            .action_slug = "evil/action",
            .summary = "RCE vulnerability",
            .severity = "critical",
            .vulnerable_range = "< 1.0.0",
            .patched_version = "1.0.0",
            .diagnostic_message = "action 'evil/action' has known vulnerability",
            .diagnostic_hint = "update to version 1.0.0 or later",
        },
    };

    const prev_cache = advisory_cache;
    const prev_offline = is_offline;
    const prev_fetched = fetched;
    advisory_cache = &mock_advisories;
    is_offline = false;
    fetched = true;
    defer {
        advisory_cache = prev_cache;
        is_offline = prev_offline;
        fetched = prev_fetched;
    }

    const step = Step{ .uses = ActionRef.parse("evil/action@v1.0.0") };
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    checkKnownVulnerableAction(&step, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC003: SHA ref with vulnerable action still warns" {
    const mock_advisories = [_]Advisory{
        .{
            .ghsa_id = "GHSA-test-1234",
            .action_slug = "evil/action",
            .summary = "RCE vulnerability",
            .severity = "critical",
            .vulnerable_range = "< 1.0.0",
            .patched_version = "1.0.0",
            .diagnostic_message = "action 'evil/action' has known vulnerability",
            .diagnostic_hint = "update to version 1.0.0 or later",
        },
    };

    const prev_cache = advisory_cache;
    const prev_offline = is_offline;
    const prev_fetched = fetched;
    advisory_cache = &mock_advisories;
    is_offline = false;
    fetched = true;
    defer {
        advisory_cache = prev_cache;
        is_offline = prev_offline;
        fetched = prev_fetched;
    }

    // SHA ref: can't determine version, is_pinned=true so skip version check -> warn
    const step = Step{ .uses = ActionRef.parse("evil/action@a5ac7e51b41094c92402da3b24376905380afc29") };
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    checkKnownVulnerableAction(&step, &list);
    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expectEqualStrings("SC003", list.get(0).rule_id);
}

test "SC003: local action skipped" {
    const mock_advisories = [_]Advisory{
        .{
            .ghsa_id = "GHSA-test-1234",
            .action_slug = "evil/action",
            .summary = "RCE vulnerability",
            .severity = "critical",
            .vulnerable_range = "< 1.0.0",
            .patched_version = "1.0.0",
            .diagnostic_message = "action 'evil/action' has known vulnerability",
            .diagnostic_hint = "update to version 1.0.0 or later",
        },
    };

    const prev_cache = advisory_cache;
    const prev_offline = is_offline;
    const prev_fetched = fetched;
    advisory_cache = &mock_advisories;
    is_offline = false;
    fetched = true;
    defer {
        advisory_cache = prev_cache;
        is_offline = prev_offline;
        fetched = prev_fetched;
    }

    const step = Step{ .uses = ActionRef.parse("./local-action") };
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    checkKnownVulnerableAction(&step, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC003: step without uses skipped" {
    const mock_advisories = [_]Advisory{
        .{
            .ghsa_id = "GHSA-test-1234",
            .action_slug = "evil/action",
            .summary = "RCE vulnerability",
            .severity = "critical",
            .vulnerable_range = "< 1.0.0",
            .patched_version = "1.0.0",
            .diagnostic_message = "action 'evil/action' has known vulnerability",
            .diagnostic_hint = "update to version 1.0.0 or later",
        },
    };

    const prev_cache = advisory_cache;
    const prev_offline = is_offline;
    const prev_fetched = fetched;
    advisory_cache = &mock_advisories;
    is_offline = false;
    fetched = true;
    defer {
        advisory_cache = prev_cache;
        is_offline = prev_offline;
        fetched = prev_fetched;
    }

    const step = Step{ .run = "echo hello" };
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    checkKnownVulnerableAction(&step, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SC003: advisory without version range always flags" {
    const mock_advisories = [_]Advisory{
        .{
            .ghsa_id = "GHSA-no-range",
            .action_slug = "evil/action",
            .summary = "Some vulnerability",
            .severity = "high",
            .vulnerable_range = null,
            .patched_version = null,
            .diagnostic_message = "action 'evil/action' has known vulnerability",
            .diagnostic_hint = "check advisory for remediation",
        },
    };

    const prev_cache = advisory_cache;
    const prev_offline = is_offline;
    const prev_fetched = fetched;
    advisory_cache = &mock_advisories;
    is_offline = false;
    fetched = true;
    defer {
        advisory_cache = prev_cache;
        is_offline = prev_offline;
        fetched = prev_fetched;
    }

    const step = Step{ .uses = ActionRef.parse("evil/action@v99.0.0") };
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    checkKnownVulnerableAction(&step, &list);
    try testing.expectEqual(@as(usize, 1), list.len());
}

test "SC003: invalid owner characters rejected" {
    const mock_advisories = [_]Advisory{
        .{
            .ghsa_id = "GHSA-test-1234",
            .action_slug = "evil/action",
            .summary = "RCE vulnerability",
            .severity = "critical",
            .vulnerable_range = "< 1.0.0",
            .patched_version = "1.0.0",
            .diagnostic_message = "action 'evil/action' has known vulnerability",
            .diagnostic_hint = "update to version 1.0.0 or later",
        },
    };

    const prev_cache = advisory_cache;
    const prev_offline = is_offline;
    const prev_fetched = fetched;
    advisory_cache = &mock_advisories;
    is_offline = false;
    fetched = true;
    defer {
        advisory_cache = prev_cache;
        is_offline = prev_offline;
        fetched = prev_fetched;
    }

    // URL-unsafe owner should be rejected before any network call
    const step = Step{ .uses = ActionRef.parse("evil?owner/action@v0.9.0") };
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    checkKnownVulnerableAction(&step, &list);
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

    // Set a past deadline so fetchAndParse returns immediately
    engine.network_deadline_ns = std.time.nanoTimestamp() - 1;
    defer engine.clearNetworkDeadline();

    const step = Step{ .uses = ActionRef.parse("evil/action@v0.9.0") };
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    checkKnownVulnerableAction(&step, &list);
    // fetchAndParse should fail due to deadline, cache stays null, no diagnostics
    try testing.expectEqual(@as(usize, 0), list.len());
    // fetched flag should be set even on failure
    try testing.expect(fetched);
}
