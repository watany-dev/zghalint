const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml = @import("../yaml/types.zig");
const engine = @import("engine.zig");

const Allocator = std.mem.Allocator;
const DiagnosticList = diagnostics.DiagnosticList;
const Span = yaml.Span;
const Step = workflow_types.Step;
const ActionRef = workflow_types.ActionRef;
const Rule = engine.Rule;

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

pub const Semver = struct {
    major: u32,
    minor: u32,
    patch: u32,
};

// ============================================================
// Module-level advisory cache
// ============================================================

var advisory_cache: ?[]const Advisory = null;
var advisory_arena: ?std.heap.ArenaAllocator = null;

// ============================================================
// Public API
// ============================================================

/// Fetch advisories from GitHub Security Advisories API.
/// On any error (network, parse, etc.), silently enters offline mode (cache = null).
pub fn initAdvisories(backing_allocator: Allocator) void {
    var arena = std.heap.ArenaAllocator.init(backing_allocator);
    const allocator = arena.allocator();

    const advisories = fetchAndParse(allocator) catch {
        arena.deinit();
        return;
    };

    advisory_arena = arena;
    advisory_cache = advisories;
}

/// Release advisory memory.
pub fn deinitAdvisories() void {
    if (advisory_arena) |*arena| {
        arena.deinit();
        advisory_arena = null;
    }
    advisory_cache = null;
}

/// Rule check function for SC003.
pub fn checkKnownVulnerableAction(step: *const Step, list: *DiagnosticList) void {
    const advisories = advisory_cache orelse return;
    const action_ref = step.uses orelse return;
    if (action_ref.is_local or action_ref.is_docker) return;
    const owner = action_ref.owner orelse return;
    const repo = action_ref.repo orelse return;

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
            .span = Span.point(0, 0, 0),
            .fix_hint = adv.diagnostic_hint,
        }) catch return;
        return; // One diagnostic per step
    }
}

// ============================================================
// HTTP fetch
// ============================================================

const api_url = "https://api.github.com/advisories?type=reviewed&ecosystem=actions&per_page=100";

fn fetchAndParse(allocator: Allocator) ![]const Advisory {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    // Build extra headers
    var headers_buf: [3]std.http.Header = undefined;
    var header_count: usize = 0;

    headers_buf[header_count] = .{ .name = "Accept", .value = "application/vnd.github+json" };
    header_count += 1;
    headers_buf[header_count] = .{ .name = "X-GitHub-Api-Version", .value = "2022-11-28" };
    header_count += 1;

    // Use GITHUB_TOKEN if available for higher rate limits
    const auth_value = blk: {
        const token = std.posix.getenv("GITHUB_TOKEN") orelse break :blk null;
        break :blk std.fmt.allocPrint(allocator, "Bearer {s}", .{token}) catch null;
    };
    if (auth_value) |auth| {
        headers_buf[header_count] = .{ .name = "Authorization", .value = auth };
        header_count += 1;
    }

    const result = client.fetch(.{
        .location = .{ .url = api_url },
        .response_writer = &aw.writer,
        .headers = .{ .user_agent = .{ .override = "zghalint/0.1.0" } },
        .extra_headers = headers_buf[0..header_count],
    }) catch return error.FetchFailed;

    if (result.status != .ok) return error.HttpError;

    var response_list = aw.toArrayList();
    defer response_list.deinit(allocator);

    return parseAdvisories(allocator, response_list.items);
}

// ============================================================
// JSON parsing
// ============================================================

fn parseAdvisories(allocator: Allocator, body: []const u8) ![]const Advisory {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.JsonParseError;
    _ = parsed; // We don't defer deinit because arena owns everything

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
    const val = obj.get(key) orelse return null;
    // first_patched_version can be an object with "identifier" field or a string
    return switch (val) {
        .string => |s| s,
        .object => |o| getJsonString(o, "identifier"),
        else => null,
    };
}

// ============================================================
// Slug matching
// ============================================================

fn slugMatches(advisory_slug: []const u8, owner: []const u8, repo: []const u8) bool {
    const slash_pos = std.mem.indexOf(u8, advisory_slug, "/") orelse return false;
    const adv_owner = advisory_slug[0..slash_pos];
    const adv_repo = advisory_slug[slash_pos + 1 ..];
    return std.mem.eql(u8, adv_owner, owner) and std.mem.eql(u8, adv_repo, repo);
}

// ============================================================
// Semver parsing and comparison
// ============================================================

pub fn parseSemver(ref: []const u8) ?Semver {
    var s = ref;
    // Strip leading 'v' or 'V'
    if (s.len > 0 and (s[0] == 'v' or s[0] == 'V')) {
        s = s[1..];
    }
    if (s.len == 0) return null;

    // Parse major
    const major_end = std.mem.indexOf(u8, s, ".") orelse {
        // Just major version (e.g., "4")
        return .{
            .major = std.fmt.parseInt(u32, s, 10) catch return null,
            .minor = 0,
            .patch = 0,
        };
    };
    const major = std.fmt.parseInt(u32, s[0..major_end], 10) catch return null;
    s = s[major_end + 1 ..];

    // Parse minor
    const minor_end = std.mem.indexOf(u8, s, ".") orelse {
        // major.minor (e.g., "4.1")
        return .{
            .major = major,
            .minor = std.fmt.parseInt(u32, s, 10) catch return null,
            .patch = 0,
        };
    };
    const minor = std.fmt.parseInt(u32, s[0..minor_end], 10) catch return null;
    s = s[minor_end + 1 ..];

    // Parse patch (stop at first non-digit for pre-release tags like "1.2.3-beta")
    var patch_end: usize = 0;
    while (patch_end < s.len and std.ascii.isDigit(s[patch_end])) : (patch_end += 1) {}
    if (patch_end == 0) return null;
    const patch = std.fmt.parseInt(u32, s[0..patch_end], 10) catch return null;

    return .{ .major = major, .minor = minor, .patch = patch };
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
    const ver = parseSemver(ref) orelse return true; // Can't parse → conservatively vulnerable

    // Split range on comma for AND conditions (e.g., ">= 2.0.0, < 2.3.1")
    var iter = std.mem.splitScalar(u8, range, ',');
    while (iter.next()) |part| {
        const constraint = parseConstraint(part) orelse return true; // Can't parse → conservatively vulnerable
        if (!satisfiesConstraint(ver, constraint)) return false; // One constraint not met → not in vulnerable range
    }
    return true; // All constraints met → vulnerable
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
    // Ensure cache is null (offline mode)
    const prev_cache = advisory_cache;
    advisory_cache = null;
    defer advisory_cache = prev_cache;

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
    advisory_cache = &mock_advisories;
    defer advisory_cache = prev_cache;

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
    advisory_cache = &mock_advisories;
    defer advisory_cache = prev_cache;

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
    advisory_cache = &mock_advisories;
    defer advisory_cache = prev_cache;

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
    advisory_cache = &mock_advisories;
    defer advisory_cache = prev_cache;

    // SHA ref: can't determine version, is_pinned=true so skip version check → warn
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
    advisory_cache = &mock_advisories;
    defer advisory_cache = prev_cache;

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
    advisory_cache = &mock_advisories;
    defer advisory_cache = prev_cache;

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
    advisory_cache = &mock_advisories;
    defer advisory_cache = prev_cache;

    const step = Step{ .uses = ActionRef.parse("evil/action@v99.0.0") };
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();
    checkKnownVulnerableAction(&step, &list);
    try testing.expectEqual(@as(usize, 1), list.len());
}
