//! setup-node cache capability shared by PERF001 and SEC016 (#435).
//!
//! Caching is on when `cache:` is an explicit non-false value, or when the
//! resolved action declares `package-manager-cache` and package.json names
//! npm. Capability comes from that input, not from `major >= 5`. A missing
//! metadata match is not treated as enabled (ADR-0009).

const std = @import("std");
const popular_actions = @import("popular_actions.zig");
const sha_pin = @import("sha_pin.zig");
const util = @import("../util.zig");
const workspace = @import("../workspace.zig");
const workflow_types = @import("../workflow/types.zig");

const ActionRef = workflow_types.ActionRef;
const Step = workflow_types.Step;

pub const auto_cache_hint = "setup-node enables npm caching from package.json; set 'package-manager-cache: false' in this release/deploy job, or build from a dedicated cache scope";

const ExplicitCache = enum { on, off, absent };
const AutoCacheGate = enum { off, unknown, allow };

fn isSetupNode(step: *const Step) bool {
    const action = step.uses orelse return false;
    return std.mem.eql(u8, util.actionBaseName(action.raw), "actions/setup-node");
}

pub fn enabled(step: *const Step) bool {
    if (!isSetupNode(step)) return false;
    switch (explicitCache(step)) {
        .on => return true,
        .off => return false,
        .absent => {},
    }
    switch (autoCacheGate(step)) {
        .off, .unknown => return false,
        .allow => {},
    }
    return autoCacheCapable(step) and workspace.current.package_json_npm;
}

pub fn usesAutoCache(step: *const Step) bool {
    return enabled(step) and explicitCache(step) == .absent;
}

fn explicitCache(step: *const Step) ExplicitCache {
    const value = withTrimmed(step, "cache") orelse return .absent;
    if (value.len == 0) return .absent;
    if (isFalse(value)) return .off;
    return .on;
}

fn autoCacheGate(step: *const Step) AutoCacheGate {
    const value = withTrimmed(step, "package-manager-cache") orelse return .allow;
    if (value.len == 0) return .allow;
    if (isFalse(value)) return .off;
    if (std.mem.startsWith(u8, value, "${{")) return .unknown;
    return .allow;
}

fn autoCacheCapable(step: *const Step) bool {
    const action = step.uses orelse return false;
    const meta = resolveMeta(action) orelse return false;
    return popular_actions.hasInput(meta, "package-manager-cache");
}

fn resolveMeta(action: ActionRef) ?popular_actions.ActionMeta {
    if (popular_actions.lookup(action)) |meta| return meta;
    if (!action.is_pinned) return null;
    const owner = action.owner orelse return null;
    const repo = action.repo orelse return null;
    const sha = action.ref orelse return null;
    const tag = sha_pin.lookupTagForOid(owner, repo, sha) orelse return null;
    const major = popular_actions.majorFromRef(tag) orelse return null;
    return popular_actions.lookupByMajor(owner, repo, action.path orelse "", major);
}

fn withTrimmed(step: *const Step, key: []const u8) ?[]const u8 {
    const with_map = step.with orelse return null;
    const raw = with_map.get(key) orelse return null;
    return std.mem.trim(u8, raw, " \t\n\r");
}

fn isFalse(value: []const u8) bool {
    return std.ascii.eqlIgnoreCase(value, "false");
}

const testing = std.testing;

fn nodeStep(ref: []const u8, with: ?workflow_types.StringMap) Step {
    return .{ .uses = ActionRef.parse(ref), .with = with };
}

test "enabled: explicit cache: npm is on without package.json" {
    defer workspace.clear();
    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "cache", "npm");
    const step = nodeStep("actions/setup-node@v4", with);
    try testing.expect(enabled(&step));
    try testing.expect(!usesAutoCache(&step));
}

test "enabled: v5 without package.json is off" {
    defer workspace.clear();
    const step = nodeStep("actions/setup-node@v5", null);
    try testing.expect(!enabled(&step));
}

test "enabled: v5 with package.json npm is auto-cache" {
    workspace.set(.{ .package_json_npm = true });
    defer workspace.clear();
    const step = nodeStep("actions/setup-node@v5", null);
    try testing.expect(enabled(&step));
    try testing.expect(usesAutoCache(&step));
}

test "enabled: v6 with package.json npm is auto-cache" {
    workspace.set(.{ .package_json_npm = true });
    defer workspace.clear();
    const step = nodeStep("actions/setup-node@v6", null);
    try testing.expect(enabled(&step));
}

test "enabled: v4 does not auto-cache even with package.json npm" {
    workspace.set(.{ .package_json_npm = true });
    defer workspace.clear();
    const step = nodeStep("actions/setup-node@v4", null);
    try testing.expect(!enabled(&step));
}

test "enabled: package-manager-cache false disables auto-cache" {
    workspace.set(.{ .package_json_npm = true });
    defer workspace.clear();
    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "package-manager-cache", "false");
    const step = nodeStep("actions/setup-node@v5", with);
    try testing.expect(!enabled(&step));
}

test "enabled: expression package-manager-cache is not treated as on" {
    workspace.set(.{ .package_json_npm = true });
    defer workspace.clear();
    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "package-manager-cache", "${{ inputs.cache }}");
    const step = nodeStep("actions/setup-node@v5", with);
    try testing.expect(!enabled(&step));
}

test "enabled: unresolved SHA is not treated as auto-cache" {
    workspace.set(.{ .package_json_npm = true });
    defer workspace.clear();
    const step = nodeStep("actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020", null);
    try testing.expect(!enabled(&step));
}

test "enabled: SHA that resolves to v5 is auto-cache" {
    workspace.set(.{ .package_json_npm = true });
    defer workspace.clear();
    sha_pin.initTagOids(testing.allocator, false, true);
    defer sha_pin.deinitTagOids();
    const oid = "a5ac7e51b41094c92402da3b24376905380afc29";
    sha_pin.setCachedTagOid("actions", "setup-node", "v5", oid, false);
    const step = nodeStep("actions/setup-node@a5ac7e51b41094c92402da3b24376905380afc29", null);
    try testing.expect(enabled(&step));
}

test "enabled: SHA that resolves to v4 is not auto-cache" {
    workspace.set(.{ .package_json_npm = true });
    defer workspace.clear();
    sha_pin.initTagOids(testing.allocator, false, true);
    defer sha_pin.deinitTagOids();
    const oid = "a5ac7e51b41094c92402da3b24376905380afc29";
    sha_pin.setCachedTagOid("actions", "setup-node", "v4", oid, false);
    const step = nodeStep("actions/setup-node@a5ac7e51b41094c92402da3b24376905380afc29", null);
    try testing.expect(!enabled(&step));
}

test "isSetupNode: other actions are ignored" {
    const step = Step{ .uses = ActionRef.parse("actions/setup-python@v5") };
    try testing.expect(!isSetupNode(&step));
    try testing.expect(!enabled(&step));
}
