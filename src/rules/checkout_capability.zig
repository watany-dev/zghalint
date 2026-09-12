//! Checkout credential store and unsafe-PR-checkout gate, shared by
//! SEC015 / SEC018 / SEC005 / SEC009 (#436).
//!
//! Capability is read from the resolved action's metadata, not from
//! `major >= N` on the `uses:` string. A missing metadata match is not treated
//! as a new error class (ADR-0009).

const std = @import("std");
const popular_actions = @import("popular_actions.zig");
const sha_pin = @import("sha_pin.zig");
const workflow_types = @import("../workflow/types.zig");

const ActionRef = workflow_types.ActionRef;
const Step = workflow_types.Step;

/// How the resolved checkout treats `allow-unsafe-pr-checkout`.
pub const UnsafePrCheckout = enum {
    /// No metadata, or an expression so the runtime flag is unknown.
    unknown,
    /// The action declares the gate and the caller did not set it true.
    blocked,
    /// The action declares the gate and the caller set it true.
    bypassed,
};

pub fn credentialsInRunnerTemp(step: *const Step) bool {
    const meta = resolveMeta(step) orelse return false;
    // persist-credentials moved out of `.git/config` in the v6 snapshot;
    // no dedicated input marks that store, so the resolved table major is
    // the signal. An unresolved SHA does not reach here.
    return meta.major >= 6;
}

pub fn unsafePrCheckout(step: *const Step) UnsafePrCheckout {
    const meta = resolveMeta(step) orelse return .unknown;
    if (!popular_actions.hasInput(meta, "allow-unsafe-pr-checkout")) return .unknown;
    return switch (allowUnsafeFlag(step)) {
        .on => .bypassed,
        .off, .absent => .blocked,
        .unknown => .unknown,
    };
}

pub fn uploadPathReachesRunnerTemp(step: *const Step) bool {
    const with_map = step.with orelse return false;
    var it = with_map.iterator();
    while (it.next()) |entry| {
        if (!std.ascii.eqlIgnoreCase(entry.key_ptr.*, "path")) continue;
        return pathReachesRunnerTemp(entry.value_ptr.*);
    }
    return false;
}

fn pathReachesRunnerTemp(value: []const u8) bool {
    return std.mem.find(u8, value, "RUNNER_TEMP") != null or
        std.mem.find(u8, value, "runner.temp") != null;
}

const AllowUnsafe = enum { on, off, absent, unknown };

fn allowUnsafeFlag(step: *const Step) AllowUnsafe {
    const value = withTrimmed(step, "allow-unsafe-pr-checkout") orelse return .absent;
    if (value.len == 0) return .absent;
    if (std.ascii.eqlIgnoreCase(value, "true")) return .on;
    if (std.ascii.eqlIgnoreCase(value, "false")) return .off;
    if (std.mem.startsWith(u8, value, "${{")) return .unknown;
    return .unknown;
}

fn resolveMeta(step: *const Step) ?popular_actions.ActionMeta {
    const action = step.uses orelse return null;
    if (!isCheckout(action)) return null;
    if (popular_actions.lookup(action)) |meta| return meta;
    if (!action.is_pinned) return null;
    const owner = action.owner orelse return null;
    const repo = action.repo orelse return null;
    const sha = action.ref orelse return null;
    const tag = sha_pin.lookupTagForOid(owner, repo, sha) orelse return null;
    const major = popular_actions.majorFromRef(tag) orelse return null;
    return popular_actions.lookupByMajor(owner, repo, action.path orelse "", major);
}

fn isCheckout(action: ActionRef) bool {
    const owner = action.owner orelse return false;
    const repo = action.repo orelse return false;
    return action.path == null and
        std.ascii.eqlIgnoreCase(owner, "actions") and
        std.ascii.eqlIgnoreCase(repo, "checkout");
}

fn withTrimmed(step: *const Step, key: []const u8) ?[]const u8 {
    const with_map = step.with orelse return null;
    var it = with_map.iterator();
    while (it.next()) |entry| {
        if (!std.ascii.eqlIgnoreCase(entry.key_ptr.*, key)) continue;
        return std.mem.trim(u8, entry.value_ptr.*, " \t\n\r");
    }
    return null;
}

const testing = std.testing;

fn checkoutStep(ref: []const u8, with: ?workflow_types.StringMap) Step {
    return .{ .uses = ActionRef.parse(ref), .with = with };
}

test "credentialsInRunnerTemp: v5 is git config, v6/v7 are runner temp" {
    const v5 = checkoutStep("actions/checkout@v5", null);
    const v6 = checkoutStep("actions/checkout@v6", null);
    const v7 = checkoutStep("actions/checkout@v7", null);
    try testing.expect(!credentialsInRunnerTemp(&v5));
    try testing.expect(credentialsInRunnerTemp(&v6));
    try testing.expect(credentialsInRunnerTemp(&v7));
}

test "credentialsInRunnerTemp: unresolved SHA is not treated as runner temp" {
    const step = checkoutStep("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", null);
    try testing.expect(!credentialsInRunnerTemp(&step));
}

test "credentialsInRunnerTemp: SHA that resolves to v6 is runner temp" {
    sha_pin.initTagOids(testing.allocator, false, true);
    defer sha_pin.deinitTagOids();
    const oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    sha_pin.setCachedTagOid("actions", "checkout", "v6", oid, false);
    const step = checkoutStep("actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", null);
    try testing.expect(credentialsInRunnerTemp(&step));
}

test "unsafePrCheckout: gate without flag is blocked" {
    const step = checkoutStep("actions/checkout@v7", null);
    try testing.expectEqual(UnsafePrCheckout.blocked, unsafePrCheckout(&step));
}

test "unsafePrCheckout: allow-unsafe-pr-checkout true is bypassed" {
    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "allow-unsafe-pr-checkout", "true");
    const step = checkoutStep("actions/checkout@v7", with);
    try testing.expectEqual(UnsafePrCheckout.bypassed, unsafePrCheckout(&step));
}

test "unsafePrCheckout: expression flag is unknown" {
    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "allow-unsafe-pr-checkout", "${{ inputs.allow }}");
    const step = checkoutStep("actions/checkout@v7", with);
    try testing.expectEqual(UnsafePrCheckout.unknown, unsafePrCheckout(&step));
}

test "unsafePrCheckout: unresolved SHA is unknown" {
    const step = checkoutStep("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", null);
    try testing.expectEqual(UnsafePrCheckout.unknown, unsafePrCheckout(&step));
}

test "uploadPathReachesRunnerTemp: workspace paths are not runner temp" {
    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "path", "dist");
    const step = Step{ .uses = ActionRef.parse("actions/upload-artifact@v4"), .with = with };
    try testing.expect(!uploadPathReachesRunnerTemp(&step));
}

test "uploadPathReachesRunnerTemp: runner.temp and RUNNER_TEMP are" {
    var expr_with: workflow_types.StringMap = .empty;
    defer expr_with.deinit(testing.allocator);
    try expr_with.put(testing.allocator, "path", "${{ runner.temp }}/creds");
    const expr_step = Step{ .uses = ActionRef.parse("actions/upload-artifact@v4"), .with = expr_with };
    try testing.expect(uploadPathReachesRunnerTemp(&expr_step));

    var env_with: workflow_types.StringMap = .empty;
    defer env_with.deinit(testing.allocator);
    try env_with.put(testing.allocator, "path", "$RUNNER_TEMP/creds");
    const env_step = Step{ .uses = ActionRef.parse("actions/upload-artifact@v4"), .with = env_with };
    try testing.expect(uploadPathReachesRunnerTemp(&env_step));
}
