const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml = @import("../yaml/types.zig");
const engine = @import("engine.zig");

pub const Diagnostic = diagnostics.Diagnostic;
pub const DiagnosticList = diagnostics.DiagnosticList;
pub const Severity = diagnostics.Severity;
pub const Span = yaml.Span;
pub const Workflow = workflow_types.Workflow;
pub const Job = workflow_types.Job;
pub const Step = workflow_types.Step;
pub const ActionRef = workflow_types.ActionRef;
pub const Permissions = workflow_types.Permissions;
pub const SecretsConfig = workflow_types.SecretsConfig;
pub const EventType = workflow_types.EventType;
pub const Rule = engine.Rule;

// ============================================================
// Dangerous GitHub contexts that can be controlled by users
// ============================================================

const dangerous_contexts = [_][]const u8{
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.head_ref",
    "github.event.commits",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.pages",
    "github.event.workflow_run.head_branch",
};

// ============================================================
// Secret patterns (prefixes that indicate hardcoded secrets)
// ============================================================

const secret_prefixes = [_][]const u8{
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "AKIA",
    "sk-live_",
    "sk-test_",
    "xoxb-",
    "xoxp-",
};

// ============================================================
// SEC001 - Unpinned action references
// ============================================================

fn checkUnpinnedAction(step: *const Step, list: *DiagnosticList) void {
    if (step.uses) |action_ref| {
        if (!action_ref.is_local and !action_ref.is_docker and !action_ref.is_pinned) {
            list.append(.{
                .rule_id = "SEC001",
                .severity = .warning,
                .message = "action reference is not pinned to a SHA",
                .span = Span.point(0, 0, 0),
                .fix_hint = "pin to a full 40-character commit SHA instead of a tag or branch",
            });
        }
    }
}

// ============================================================
// SEC002 - Script injection via untrusted context in run:
// ============================================================

fn checkScriptInjection(step: *const Step, list: *DiagnosticList) void {
    const run_body = step.run orelse return;
    checkDangerousContextInString(run_body, "SEC002", "script injection: untrusted context used in run: block", "assign the context to an environment variable and use the env var instead", list);
}

// ============================================================
// SEC003 - Hardcoded secrets
// ============================================================

fn checkHardcodedSecrets(step: *const Step, list: *DiagnosticList) void {
    // Check run: block
    if (step.run) |run_body| {
        checkStringForSecrets(run_body, list);
    }
    // Check with: values
    if (step.with) |with_map| {
        for (with_map.values()) |val| {
            checkStringForSecrets(val, list);
        }
    }
    // Check env: values
    if (step.env) |env_map| {
        for (env_map.values()) |val| {
            checkStringForSecrets(val, list);
        }
    }
}

fn checkStringForSecrets(s: []const u8, list: *DiagnosticList) void {
    for (secret_prefixes) |prefix| {
        if (containsSecretPrefix(s, prefix)) {
            list.append(.{
                .rule_id = "SEC003",
                .severity = .@"error",
                .message = "potential hardcoded secret detected",
                .span = Span.point(0, 0, 0),
                .fix_hint = "use a GitHub secret (secrets.YOUR_SECRET) instead of hardcoding credentials",
            });
            return; // One diagnostic per string is enough
        }
    }
}

fn containsSecretPrefix(s: []const u8, prefix: []const u8) bool {
    if (s.len < prefix.len) return false;
    var i: usize = 0;
    while (i + prefix.len <= s.len) : (i += 1) {
        if (std.mem.eql(u8, s[i .. i + prefix.len], prefix)) {
            return true;
        }
    }
    return false;
}

// ============================================================
// SEC004 - Excessive permissions (write-all)
// ============================================================

fn checkExcessivePermissions(wf: *const Workflow, list: *DiagnosticList) void {
    if (wf.permissions) |perms| {
        if (perms.write_all) {
            list.append(.{
                .rule_id = "SEC004",
                .severity = .warning,
                .message = "workflow uses 'permissions: write-all' which grants excessive permissions",
                .span = Span.point(0, 0, 0),
                .fix_hint = "specify only the permissions that are needed",
            });
        }
    }
}

fn checkExcessivePermissionsJob(job: *const Job, list: *DiagnosticList) void {
    if (job.permissions) |perms| {
        if (perms.write_all) {
            list.append(.{
                .rule_id = "SEC004",
                .severity = .warning,
                .message = "job uses 'permissions: write-all' which grants excessive permissions",
                .span = Span.point(0, 0, 0),
                .fix_hint = "specify only the permissions that are needed",
            });
        }
    }
}

// ============================================================
// SEC005 - Dangerous pull_request_target + checkout
// ============================================================

fn checkDangerousPRTarget(wf: *const Workflow, list: *DiagnosticList) void {
    // Check if workflow has pull_request_target trigger
    var has_prt = false;
    for (wf.on.events) |event| {
        if (event.event == .pull_request_target) {
            has_prt = true;
            break;
        }
    }
    if (!has_prt) return;

    // Look for checkout actions that check out the PR head
    for (wf.jobs) |*job| {
        for (job.steps) |*step| {
            if (step.uses) |action_ref| {
                if (isCheckoutAction(action_ref)) {
                    // Check if it checks out the PR head ref
                    if (step.with) |with_map| {
                        if (with_map.get("ref")) |ref_val| {
                            if (containsDangerousPRRef(ref_val)) {
                                list.append(.{
                                    .rule_id = "SEC005",
                                    .severity = .@"error",
                                    .message = "dangerous: pull_request_target workflow checks out PR head, allowing arbitrary code execution from forks",
                                    .span = Span.point(0, 0, 0),
                                    .fix_hint = "avoid checking out PR head in pull_request_target workflows, or use a separate unprivileged workflow",
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}

fn isCheckoutAction(ref: ActionRef) bool {
    const owner = ref.owner orelse return false;
    const repo = ref.repo orelse return false;
    return std.mem.eql(u8, owner, "actions") and std.mem.eql(u8, repo, "checkout");
}

fn containsDangerousPRRef(ref_val: []const u8) bool {
    // Look for github.event.pull_request.head.sha or github.event.pull_request.head.ref or github.head_ref
    return std.mem.indexOf(u8, ref_val, "github.event.pull_request.head") != null or
        std.mem.indexOf(u8, ref_val, "github.head_ref") != null;
}

// ============================================================
// SEC006 - Untrusted input in if: conditions
// ============================================================

fn checkUntrustedInCondition(step: *const Step, list: *DiagnosticList) void {
    const cond = step.if_condition orelse return;
    checkConditionForDangerousContext(cond, list);
}

fn checkUntrustedInConditionJob(job: *const Job, list: *DiagnosticList) void {
    const cond = job.if_condition orelse return;
    checkConditionForDangerousContext(cond, list);
}

/// In GitHub Actions, `if:` conditions are implicitly wrapped in `${{ }}`,
/// so they may contain dangerous contexts either directly or inside `${{ }}`.
fn checkConditionForDangerousContext(cond: []const u8, list: *DiagnosticList) void {
    // First check for ${{ expr }} wrapped patterns
    var has_expr = false;
    var pos: usize = 0;
    while (pos + 4 < cond.len) : (pos += 1) {
        if (cond[pos] == '$' and pos + 1 < cond.len and cond[pos + 1] == '{' and pos + 2 < cond.len and cond[pos + 2] == '{') {
            has_expr = true;
            break;
        }
    }
    if (has_expr) {
        checkDangerousContextInString(cond, "SEC006", "untrusted context used in if: condition expression", "validate the input before using it in a condition", list);
    } else {
        // Bare expression (no ${{ }}), check directly
        if (containsDangerousContext(cond)) {
            list.append(.{
                .rule_id = "SEC006",
                .severity = .@"error",
                .message = "untrusted context used in if: condition expression",
                .span = Span.point(0, 0, 0),
                .fix_hint = "validate the input before using it in a condition",
            });
        }
    }
}

// ============================================================
// SEC007 - Missing permissions block
// ============================================================

fn checkMissingPermissions(wf: *const Workflow, list: *DiagnosticList) void {
    if (wf.permissions == null) {
        list.append(.{
            .rule_id = "SEC007",
            .severity = .info,
            .message = "workflow does not define top-level permissions, defaults may be overly broad",
            .span = Span.point(0, 0, 0),
            .fix_hint = "add a top-level 'permissions:' block to restrict GITHUB_TOKEN scope",
        });
    }
}

// ============================================================
// SEC010 - secrets: inherit in reusable workflow calls
// ============================================================

fn checkSecretsInherit(job: *const Job, list: *DiagnosticList) void {
    // Only applies to reusable workflow calls (jobs with uses:)
    if (job.uses == null) return;
    if (job.secrets) |secrets| {
        switch (secrets) {
            .inherit => {
                list.append(.{
                    .rule_id = "SEC010",
                    .severity = .warning,
                    .message = "reusable workflow call uses 'secrets: inherit', which passes all secrets implicitly",
                    .span = Span.point(0, 0, 0),
                    .fix_hint = "explicitly specify only the secrets the called workflow needs instead of using 'inherit'",
                });
            },
            .map => {},
        }
    }
}

// ============================================================
// Shared helpers
// ============================================================

/// Scan a string for ${{ dangerous_context }} patterns
fn checkDangerousContextInString(s: []const u8, rule_id: []const u8, message: []const u8, fix_hint: []const u8, list: *DiagnosticList) void {
    // Find all ${{ ... }} expressions
    var pos: usize = 0;
    while (pos + 4 < s.len) : (pos += 1) {
        if (s[pos] == '$' and pos + 1 < s.len and s[pos + 1] == '{' and pos + 2 < s.len and s[pos + 2] == '{') {
            // Find closing }}
            const expr_start = pos + 3;
            var depth: u32 = 1;
            var j = expr_start;
            while (j + 1 < s.len) : (j += 1) {
                if (s[j] == '}' and s[j + 1] == '}') {
                    depth -= 1;
                    if (depth == 0) break;
                }
            }
            if (depth == 0) {
                const expr = std.mem.trim(u8, s[expr_start..j], " \t\n\r");
                if (containsDangerousContext(expr)) {
                    list.append(.{
                        .rule_id = rule_id,
                        .severity = .@"error",
                        .message = message,
                        .span = Span.point(0, 0, 0),
                        .fix_hint = fix_hint,
                    });
                    return; // One diagnostic per string
                }
                pos = j + 1;
            }
        }
    }
}

fn containsDangerousContext(expr: []const u8) bool {
    for (dangerous_contexts) |ctx| {
        if (stringContainsContext(expr, ctx)) {
            return true;
        }
    }
    return false;
}

/// Check if the expression contains a dangerous context reference.
/// Matches the context string as a substring, ensuring it appears at a word boundary.
fn stringContainsContext(expr: []const u8, ctx: []const u8) bool {
    if (expr.len < ctx.len) return false;
    var i: usize = 0;
    while (i + ctx.len <= expr.len) : (i += 1) {
        if (std.mem.eql(u8, expr[i .. i + ctx.len], ctx)) {
            // Check it's not part of a longer identifier
            const before_ok = i == 0 or !isIdentChar(expr[i - 1]);
            const after_pos = i + ctx.len;
            // Allow trailing .something or [*] for array patterns like github.event.commits[*].message
            const after_ok = after_pos >= expr.len or
                !isIdentChar(expr[after_pos]) or
                expr[after_pos] == '[' or
                expr[after_pos] == '.';
            if (before_ok and after_ok) {
                return true;
            }
        }
    }
    return false;
}

fn isIdentChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

// ============================================================
// Public: All security rules
// ============================================================

pub const security_rules = [_]Rule{
    .{
        .id = "SEC001",
        .name = "unpinned-action",
        .description = "Action references should be pinned to a full SHA",
        .severity = .warning,
        .category = .security,
        .check_step = &checkUnpinnedAction,
    },
    .{
        .id = "SEC002",
        .name = "script-injection",
        .description = "Untrusted GitHub context used in run: block risks script injection",
        .severity = .@"error",
        .category = .security,
        .check_step = &checkScriptInjection,
    },
    .{
        .id = "SEC003",
        .name = "hardcoded-secret",
        .description = "Hardcoded secrets should use GitHub Secrets",
        .severity = .@"error",
        .category = .security,
        .check_step = &checkHardcodedSecrets,
    },
    .{
        .id = "SEC004",
        .name = "excessive-permissions",
        .description = "Avoid write-all permissions, specify only needed scopes",
        .severity = .warning,
        .category = .security,
        .check_workflow = &checkExcessivePermissions,
        .check_job = &checkExcessivePermissionsJob,
    },
    .{
        .id = "SEC005",
        .name = "dangerous-pr-target",
        .description = "pull_request_target with checkout of PR head is dangerous",
        .severity = .@"error",
        .category = .security,
        .check_workflow = &checkDangerousPRTarget,
    },
    .{
        .id = "SEC006",
        .name = "untrusted-input-condition",
        .description = "Untrusted context in if: condition expression",
        .severity = .@"error",
        .category = .security,
        .check_step = &checkUntrustedInCondition,
        .check_job = &checkUntrustedInConditionJob,
    },
    .{
        .id = "SEC007",
        .name = "missing-permissions",
        .description = "Workflow should define top-level permissions",
        .severity = .info,
        .category = .security,
        .check_workflow = &checkMissingPermissions,
    },
    .{
        .id = "SEC010",
        .name = "secrets-inherit",
        .description = "Reusable workflow calls should specify secrets explicitly instead of using inherit",
        .severity = .warning,
        .category = .security,
        .check_job = &checkSecretsInherit,
    },
};

// ============================================================
// Tests
// ============================================================

const testing = std.testing;
const EventConfig = workflow_types.EventConfig;
const Trigger = workflow_types.Trigger;

fn makeEmptyTrigger() Trigger {
    return .{ .events = &.{} };
}

fn makePRTargetTrigger() Trigger {
    const events = &[_]EventConfig{
        .{ .event = .pull_request_target, .name = "pull_request_target" },
    };
    return .{ .events = events };
}

fn hasDiagnostic(list: *const DiagnosticList, rule_id: []const u8) bool {
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, rule_id)) return true;
    }
    return false;
}

fn countDiagnostics(list: *const DiagnosticList, rule_id: []const u8) usize {
    var count: usize = 0;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, rule_id)) count += 1;
    }
    return count;
}

// --- SEC001: Unpinned action ---

test "SEC001: unpinned action tag ref" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC001"));
}

test "SEC001: unpinned action branch ref" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@main") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC001"));
}

test "SEC001: pinned action (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC001"));
}

test "SEC001: local action (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("./my-local-action") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC001"));
}

test "SEC001: docker action (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("docker://alpine:3.8") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC001"));
}

// --- SEC002: Script injection ---

test "SEC002: dangerous context in run block" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo ${{ github.event.issue.title }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC002"));
}

test "SEC002: pull_request body in run block" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo \"${{ github.event.pull_request.body }}\"" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC002"));
}

test "SEC002: head_ref in run block" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "git checkout ${{ github.head_ref }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC002"));
}

test "SEC002: safe context in run (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo ${{ github.sha }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC002"));
}

test "SEC002: no expression in run (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo hello world" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC002"));
}

test "SEC002: commit message in run block" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo ${{ github.event.head_commit.message }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC002"));
}

// --- SEC003: Hardcoded secrets ---

test "SEC003: GitHub PAT in run block" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "curl -H 'Authorization: token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC003"));
}

test "SEC003: AWS key in run block" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC003"));
}

test "SEC003: Slack token in with" {
    const eng = engine.Engine.init(&security_rules);
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("slack-token", "xoxb-1234-5678-abcdef") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("some/action@v1"), .with = with },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC003"));
}

test "SEC003: Stripe key in env" {
    const eng = engine.Engine.init(&security_rules);
    var env = workflow_types.StringMap.init(testing.allocator);
    env.put("STRIPE_KEY", "sk-live_abcdef123456") catch unreachable;
    defer env.deinit();
    const steps = [_]Step{
        .{ .run = "echo test", .env = env },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC003"));
}

test "SEC003: no secret (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo ${{ secrets.MY_TOKEN }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC003"));
}

test "SEC003: sk-test_ pattern detected" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "export KEY=sk-test_abcdefg" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC003"));
}

// --- SEC004: Excessive permissions ---

test "SEC004: write-all at workflow level" {
    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{ .write_all = true } };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC004"));
}

test "SEC004: write-all at job level" {
    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .permissions = Permissions{ .write_all = true } },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC004"));
}

test "SEC004: read-all (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{ .read_all = true } };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC004"));
}

test "SEC004: specific permissions (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{ .contents = .read } };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC004"));
}

// --- SEC005: Dangerous pull_request_target ---

test "SEC005: PR target with checkout of head" {
    const eng = engine.Engine.init(&security_rules);
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("ref", "${{ github.event.pull_request.head.sha }}") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePRTargetTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC005"));
}

test "SEC005: PR target with checkout of head ref" {
    const eng = engine.Engine.init(&security_rules);
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("ref", "${{ github.head_ref }}") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePRTargetTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC005"));
}

test "SEC005: PR target without checkout (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo safe" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePRTargetTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC005"));
}

test "SEC005: PR target checkout without ref (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePRTargetTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC005"));
}

test "SEC005: non-PR-target with checkout (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("ref", "${{ github.event.pull_request.head.sha }}") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC005"));
}

// --- SEC006: Untrusted input in conditions ---

test "SEC006: dangerous context in step if condition" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo test", .if_condition = "contains(github.event.issue.title, 'deploy')" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC006"));
}

test "SEC006: dangerous context in job if condition" {
    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .if_condition = "contains(github.event.comment.body, '/approve')", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC006"));
}

test "SEC006: safe context in condition (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo test", .if_condition = "github.ref == 'refs/heads/main'" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC006"));
}

// --- SEC007: Missing permissions ---

test "SEC007: no permissions defined" {
    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build" },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC007"));
}

test "SEC007: permissions defined (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build" },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{ .contents = .read } };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC007"));
}

test "SEC007: empty permissions block counts as defined" {
    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build" },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC007"));
}

// --- SEC010: secrets: inherit ---

test "SEC010: secrets inherit in reusable workflow call" {
    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "call-workflow", .uses = "octo-org/example/.github/workflows/deploy.yml@main", .secrets = SecretsConfig{ .inherit = {} }, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC010"));
}

test "SEC010: explicit secrets (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    var secrets_map = workflow_types.StringMap.init(testing.allocator);
    secrets_map.put("deploy_key", "${{ secrets.DEPLOY_KEY }}") catch unreachable;
    defer secrets_map.deinit();
    const jobs = [_]Job{
        .{ .id = "call-workflow", .uses = "octo-org/example/.github/workflows/deploy.yml@main", .secrets = SecretsConfig{ .map = secrets_map }, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC010"));
}

test "SEC010: no secrets in reusable workflow call (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "call-workflow", .uses = "octo-org/example/.github/workflows/deploy.yml@main", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC010"));
}

test "SEC010: non-reusable job with no uses (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo hello" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC010"));
}

// --- Helper function tests ---

test "containsDangerousContext recognizes issue title" {
    try testing.expect(containsDangerousContext("github.event.issue.title"));
}

test "containsDangerousContext recognizes PR body" {
    try testing.expect(containsDangerousContext("github.event.pull_request.body"));
}

test "containsDangerousContext rejects safe ref" {
    try testing.expect(!containsDangerousContext("github.sha"));
}

test "containsDangerousContext rejects safe actor" {
    try testing.expect(!containsDangerousContext("github.actor"));
}

test "containsSecretPrefix finds ghp_ token" {
    try testing.expect(containsSecretPrefix("token ghp_abc123def456", "ghp_"));
}

test "containsSecretPrefix finds AKIA key" {
    try testing.expect(containsSecretPrefix("AKIAIOSFODNN7EXAMPLE", "AKIA"));
}

test "containsSecretPrefix no false positive" {
    try testing.expect(!containsSecretPrefix("echo hello world", "ghp_"));
}

test "isCheckoutAction true" {
    try testing.expect(isCheckoutAction(ActionRef.parse("actions/checkout@v4")));
}

test "isCheckoutAction false for other action" {
    try testing.expect(!isCheckoutAction(ActionRef.parse("actions/setup-node@v3")));
}

test "containsDangerousPRRef with head.sha" {
    try testing.expect(containsDangerousPRRef("${{ github.event.pull_request.head.sha }}"));
}

test "containsDangerousPRRef with head_ref" {
    try testing.expect(containsDangerousPRRef("${{ github.head_ref }}"));
}

test "containsDangerousPRRef safe ref" {
    try testing.expect(!containsDangerousPRRef("${{ github.sha }}"));
}

// --- Integration: multiple rules fire on same workflow ---

test "multiple security rules fire together" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") }, // SEC001
        .{ .run = "echo ${{ github.event.issue.body }}" }, // SEC002
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps },
    };
    // No permissions => SEC007
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC001"));
    try testing.expect(hasDiagnostic(&list, "SEC002"));
    try testing.expect(hasDiagnostic(&list, "SEC007"));
}

test "clean workflow passes all security rules" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29") },
        .{ .run = "echo ${{ github.sha }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{ .contents = .read } };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}
