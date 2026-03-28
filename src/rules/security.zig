const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml = @import("../yaml/types.zig");
const engine = @import("engine.zig");
const advisory = @import("advisory.zig");

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
// Actor contexts that are spoofable identity checks
// ============================================================

const actor_contexts = [_][]const u8{
    "github.actor",
    "github.triggering_actor",
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
// Cache-related setup actions (for SEC016 cache poisoning check)
// ============================================================

const cache_setup_actions = [_][]const u8{
    "actions/setup-node",
    "actions/setup-python",
    "actions/setup-java",
    "actions/setup-go",
    "actions/setup-dotnet",
};

/// Keywords that suggest a deploy/release/publish job.
const deploy_keywords = [_][]const u8{
    "deploy",
    "release",
    "publish",
    "prod",
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
// SEC012 - Unredacted secrets via toJSON/fromJSON
// ============================================================

fn checkUnredactedSecrets(step: *const Step, list: *DiagnosticList) void {
    // Check run: block
    if (step.run) |run_body| {
        if (checkStringForUnredactedSecrets(run_body)) {
            emitSEC012(list);
            return;
        }
    }
    // Check with: values
    if (step.with) |with_map| {
        for (with_map.values()) |val| {
            if (checkStringForUnredactedSecrets(val)) {
                emitSEC012(list);
                return;
            }
        }
    }
    // Check env: values
    if (step.env) |env_map| {
        for (env_map.values()) |val| {
            if (checkStringForUnredactedSecrets(val)) {
                emitSEC012(list);
                return;
            }
        }
    }
}

// ============================================================
// SEC013 - Hardcoded container credentials
// ============================================================

fn checkHardcodedContainerCredentials(job: *const Job, list: *DiagnosticList) void {
    if (job.container) |container| {
        checkCredentialsForHardcoded(container.credentials, list);
    }
    for (job.services) |service| {
        checkCredentialsForHardcoded(service.credentials, list);
    }
}

fn checkCredentialsForHardcoded(creds: ?workflow_types.Credentials, list: *DiagnosticList) void {
    const credentials = creds orelse return;
    if (credentials.username) |username| {
        if (!isSecretsExpression(username)) {
            list.append(.{
                .rule_id = "SEC013",
                .severity = .@"error",
                .message = "hardcoded credentials in container configuration",
                .span = Span.point(0, 0, 0),
                .fix_hint = "use ${{ secrets.YOUR_SECRET }} for container credentials instead of plaintext values",
            });
        }
    }
    if (credentials.password) |password| {
        if (!isSecretsExpression(password)) {
            list.append(.{
                .rule_id = "SEC013",
                .severity = .@"error",
                .message = "hardcoded credentials in container configuration",
                .span = Span.point(0, 0, 0),
                .fix_hint = "use ${{ secrets.YOUR_SECRET }} for container credentials instead of plaintext values",
            });
        }
    }
}

fn isSecretsExpression(value: []const u8) bool {
    const trimmed = std.mem.trim(u8, value, " \t\n\r");
    if (trimmed.len < 5) return false;
    if (!std.mem.startsWith(u8, trimmed, "${{")) return false;
    if (!std.mem.endsWith(u8, trimmed, "}}")) return false;
    const inner = std.mem.trim(u8, trimmed[3 .. trimmed.len - 2], " \t");
    return std.mem.startsWith(u8, inner, "secrets.");
}

// ============================================================
// SEC016 - Cache poisoning in release/deploy workflows
// ============================================================

fn checkCachePoisoning(wf: *const Workflow, list: *DiagnosticList) void {
    const has_release_trigger = isReleaseOrDeployTrigger(wf);

    for (wf.jobs) |*job| {
        const job_at_risk = has_release_trigger or isDeployJob(job);
        if (!job_at_risk) continue;

        for (job.steps) |*step| {
            if (isCacheAction(step) or isSetupActionWithCache(step)) {
                list.append(.{
                    .rule_id = "SEC016",
                    .severity = .warning,
                    .message = "cache usage in release/deploy workflow risks cache poisoning from less-privileged workflows",
                    .span = Span.point(0, 0, 0),
                    .fix_hint = "avoid using actions/cache or setup action caching in release/deploy workflows; build from scratch or use a dedicated cache scope",
                });
            }
        }
    }
}

fn emitSEC012(list: *DiagnosticList) void {
    list.append(.{
        .rule_id = "SEC012",
        .severity = .@"error",
        .message = "secret exposed via toJSON()/fromJSON() bypasses masking",
        .span = Span.point(0, 0, 0),
        .fix_hint = "avoid passing secrets through toJSON()/fromJSON(); assign individual secret values to environment variables instead",
    });
}

/// Check if a string contains ${{ ... }} expressions with toJSON(secrets...) or fromJSON(secrets...) patterns.
fn checkStringForUnredactedSecrets(s: []const u8) bool {
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
                const expr = s[expr_start..j];
                if (exprHasSecretJsonCall(expr)) {
                    return true;
                }
                pos = j + 1;
            }
        }
    }
    return false;
}

fn isReleaseOrDeployTrigger(wf: *const Workflow) bool {
    for (wf.on.events) |event| {
        if (event.event == .release) return true;
    }
    return false;
}

fn isDeployJob(job: *const Job) bool {
    if (containsAnyKeyword(job.id)) return true;
    if (job.name) |name| {
        if (containsAnyKeyword(name)) return true;
    }
    return false;
}

fn containsAnyKeyword(s: []const u8) bool {
    for (deploy_keywords) |keyword| {
        if (containsIgnoreCase(s, keyword)) return true;
    }
    return false;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn isCacheAction(step: *const Step) bool {
    const action_ref = step.uses orelse return false;
    const base = actionBaseName(action_ref.raw);
    return std.mem.eql(u8, base, "actions/cache");
}

fn isSetupActionWithCache(step: *const Step) bool {
    const action_ref = step.uses orelse return false;
    const base = actionBaseName(action_ref.raw);
    for (cache_setup_actions) |setup_action| {
        if (std.mem.eql(u8, base, setup_action)) {
            if (step.with) |with_map| {
                if (with_map.get("cache")) |val| {
                    if (val.len > 0) return true;
                }
            }
            return false;
        }
    }
    return false;
}

/// Check if an expression contains toJSON(secrets...) or fromJSON(secrets...).
fn exprHasSecretJsonCall(expr: []const u8) bool {
    const patterns = [_][]const u8{ "toJSON", "tojson", "toJson", "TOJSON", "fromJSON", "fromjson", "fromJson", "FROMJSON" };
    for (patterns) |func_name| {
        var i: usize = 0;
        while (i + func_name.len < expr.len) : (i += 1) {
            if (std.mem.eql(u8, expr[i .. i + func_name.len], func_name)) {
                // Find the opening paren after optional whitespace
                var k = i + func_name.len;
                while (k < expr.len and (expr[k] == ' ' or expr[k] == '\t')) : (k += 1) {}
                if (k < expr.len and expr[k] == '(') {
                    // Check if argument starts with "secrets"
                    var arg_start = k + 1;
                    while (arg_start < expr.len and (expr[arg_start] == ' ' or expr[arg_start] == '\t')) : (arg_start += 1) {}
                    if (arg_start + 7 <= expr.len and std.mem.eql(u8, expr[arg_start .. arg_start + 7], "secrets")) {
                        // Must be followed by ), ., whitespace or end — not part of a longer word
                        const after = arg_start + 7;
                        if (after >= expr.len or expr[after] == ')' or expr[after] == '.' or expr[after] == ' ' or expr[after] == '\t') {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

fn actionBaseName(raw: []const u8) []const u8 {
    return if (std.mem.indexOf(u8, raw, "@")) |pos| raw[0..pos] else raw;
}

// ============================================================
// SEC014 - Spoofable bot actor check in conditions
// ============================================================

fn checkBotConditionStep(step: *const Step, list: *DiagnosticList) void {
    const cond = step.if_condition orelse return;
    checkConditionForBotActorCheck(cond, list);
}

fn checkBotConditionJob(job: *const Job, list: *DiagnosticList) void {
    const cond = job.if_condition orelse return;
    checkConditionForBotActorCheck(cond, list);
}

/// Check if an if-condition compares github.actor / github.triggering_actor
/// against a bot account name (containing "[bot]"). This is spoofable.
fn checkConditionForBotActorCheck(cond: []const u8, list: *DiagnosticList) void {
    // Check for ${{ expr }} wrapped patterns
    var has_expr = false;
    var pos: usize = 0;
    while (pos + 4 < cond.len) : (pos += 1) {
        if (cond[pos] == '$' and pos + 1 < cond.len and cond[pos + 1] == '{' and pos + 2 < cond.len and cond[pos + 2] == '{') {
            has_expr = true;
            break;
        }
    }

    if (has_expr) {
        checkBotActorInString(cond, list);
    } else {
        // Bare expression
        if (containsActorBotCheck(cond)) {
            list.append(.{
                .rule_id = "SEC014",
                .severity = .warning,
                .message = "spoofable bot check: github.actor can be impersonated by creating an account with the same name",
                .span = Span.point(0, 0, 0),
                .fix_hint = "use github.event.sender.type == 'Bot' or GitHub's built-in Dependabot integration features instead",
            });
        }
    }
}

/// Scan a string for ${{ expr }} patterns that contain actor + [bot] checks.
fn checkBotActorInString(s: []const u8, list: *DiagnosticList) void {
    var pos: usize = 0;
    while (pos + 4 < s.len) : (pos += 1) {
        if (s[pos] == '$' and pos + 1 < s.len and s[pos + 1] == '{' and pos + 2 < s.len and s[pos + 2] == '{') {
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
                if (containsActorBotCheck(expr)) {
                    list.append(.{
                        .rule_id = "SEC014",
                        .severity = .warning,
                        .message = "spoofable bot check: github.actor can be impersonated by creating an account with the same name",
                        .span = Span.point(0, 0, 0),
                        .fix_hint = "use github.event.sender.type == 'Bot' or GitHub's built-in Dependabot integration features instead",
                    });
                    return;
                }
                pos = j + 1;
            }
        }
    }
}

/// Returns true if the expression contains both an actor context reference
/// AND a string literal with "[bot]".
fn containsActorBotCheck(expr: []const u8) bool {
    const has_actor = for (actor_contexts) |ctx| {
        if (stringContainsContext(expr, ctx)) break true;
    } else false;
    if (!has_actor) return false;

    return std.mem.indexOf(u8, expr, "[bot]") != null;
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
// SC001 - Unpinned container images (supply chain)
// ============================================================

fn isImagePinned(image: []const u8) bool {
    return std.mem.indexOf(u8, image, "@sha256:") != null;
}

fn checkUnpinnedImages(job: *const Job, list: *DiagnosticList) void {
    if (job.container) |container| {
        if (container.image) |image| {
            if (!isImagePinned(image)) {
                list.append(.{
                    .rule_id = "SC001",
                    .severity = .warning,
                    .message = "container image is not pinned to a SHA256 digest",
                    .span = Span.point(0, 0, 0),
                    .fix_hint = "pin the image using a digest reference, e.g. image@sha256:abc123...",
                });
            }
        }
    }
    for (job.services) |service| {
        if (service.image) |image| {
            if (!isImagePinned(image)) {
                list.append(.{
                    .rule_id = "SC001",
                    .severity = .warning,
                    .message = "service image is not pinned to a SHA256 digest",
                    .span = Span.point(0, 0, 0),
                    .fix_hint = "pin the image using a digest reference, e.g. image@sha256:abc123...",
                });
            }
        }
    }
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
    .{
        .id = "SEC012",
        .name = "unredacted-secrets",
        .description = "Secrets processed via toJSON()/fromJSON() bypass masking and may be exposed in logs",
        .severity = .@"error",
        .category = .security,
        .check_step = &checkUnredactedSecrets,
    },
    .{
        .id = "SEC013",
        .name = "hardcoded-container-credentials",
        .description = "Container credentials should use GitHub Secrets, not plaintext values",
        .severity = .@"error",
        .category = .security,
        .check_job = &checkHardcodedContainerCredentials,
    },
    .{
        .id = "SEC016",
        .name = "cache-poisoning",
        .description = "Cache usage in release/deploy workflows risks cache poisoning attacks",
        .severity = .warning,
        .category = .security,
        .check_workflow = &checkCachePoisoning,
    },
    .{
        .id = "SEC014",
        .name = "bot-conditions",
        .description = "Bot account checks using github.actor are spoofable",
        .severity = .warning,
        .category = .security,
        .check_step = &checkBotConditionStep,
        .check_job = &checkBotConditionJob,
    },
    .{
        .id = "SC001",
        .name = "unpinned-images",
        .description = "Container images should be pinned to a SHA256 digest for supply chain security",
        .severity = .warning,
        .category = .security,
        .check_job = &checkUnpinnedImages,
    },
    .{
        .id = "SC003",
        .name = "known-vulnerable-action",
        .description = "Action has known security advisories (CVE) in GitHub Advisory Database",
        .severity = .warning,
        .category = .dependency,
        .check_step = &advisory.checkKnownVulnerableAction,
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

fn makeReleaseTrigger() Trigger {
    const events = &[_]EventConfig{
        .{ .event = .release, .name = "release" },
    };
    return .{ .events = events };
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

// --- SEC012: Unredacted secrets via toJSON/fromJSON ---

test "SEC012: toJSON(secrets) in run block" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo '${{ toJSON(secrets) }}'" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC012"));
}

test "SEC012: toJSON(secrets.MY_TOKEN) in run block" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo ${{ toJSON(secrets.MY_TOKEN) }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC012"));
}

test "SEC012: fromJSON(secrets.CONFIG) in run block" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo ${{ fromJSON(secrets.CONFIG).api_key }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC012"));
}

test "SEC012: toJSON(secrets) in with value" {
    const eng = engine.Engine.init(&security_rules);
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("data", "${{ toJSON(secrets) }}") catch unreachable;
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
    try testing.expect(hasDiagnostic(&list, "SEC012"));
}

test "SEC012: toJSON(secrets) in env value" {
    const eng = engine.Engine.init(&security_rules);
    var env = workflow_types.StringMap.init(testing.allocator);
    env.put("ALL_SECRETS", "${{ toJSON(secrets) }}") catch unreachable;
    defer env.deinit();
    const steps = [_]Step{
        .{ .run = "echo debug", .env = env },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC012"));
}

test "SEC012: case variant tojson(secrets)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo ${{ tojson(secrets) }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC012"));
}

test "SEC012: toJSON(github) no false positive" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo ${{ toJSON(github) }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC012"));
}

test "SEC012: secrets reference without toJSON (no false positive)" {
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
    try testing.expect(!hasDiagnostic(&list, "SEC012"));
}

test "SEC012: no expression in run (no false positive)" {
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
    try testing.expect(!hasDiagnostic(&list, "SEC012"));
}

test "SEC012: only one diagnostic per step" {
    const eng = engine.Engine.init(&security_rules);
    var env = workflow_types.StringMap.init(testing.allocator);
    env.put("A", "${{ toJSON(secrets) }}") catch unreachable;
    env.put("B", "${{ toJSON(secrets.X) }}") catch unreachable;
    defer env.deinit();
    const steps = [_]Step{
        .{ .run = "echo ${{ toJSON(secrets) }}", .env = env },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 1), countDiagnostics(&list, "SEC012"));
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

// --- SEC014: Bot conditions ---

test "SEC014: github.actor == dependabot[bot] in step condition" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo skip", .if_condition = "github.actor == 'dependabot[bot]'" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC014"));
}

test "SEC014: github.actor != renovate[bot] in step condition" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo test", .if_condition = "github.actor != 'renovate[bot]'" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC014"));
}

test "SEC014: github.actor == github-actions[bot] in job condition" {
    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .if_condition = "github.actor == 'github-actions[bot]'", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC014"));
}

test "SEC014: wrapped in dollar-brace expression" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo skip", .if_condition = "${{ github.actor == 'dependabot[bot]' }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC014"));
}

test "SEC014: github.triggering_actor with bot check" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo skip", .if_condition = "github.triggering_actor == 'dependabot[bot]'" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC014"));
}

test "SEC014: github.actor without bot pattern (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo test", .if_condition = "github.actor == 'octocat'" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC014"));
}

test "SEC014: bot pattern without github.actor (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo test", .if_condition = "contains(github.event.comment.body, 'dependabot[bot]')" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC014"));
}

test "SEC014: safe condition with github.ref (no false positive)" {
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
    try testing.expect(!hasDiagnostic(&list, "SEC014"));
}

test "SEC014: no condition (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo test" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC014"));
}

test "containsActorBotCheck detects actor with bot pattern" {
    try testing.expect(containsActorBotCheck("github.actor == 'dependabot[bot]'"));
}

test "containsActorBotCheck detects triggering_actor with bot" {
    try testing.expect(containsActorBotCheck("github.triggering_actor == 'renovate[bot]'"));
}

test "containsActorBotCheck rejects actor without bot" {
    try testing.expect(!containsActorBotCheck("github.actor == 'octocat'"));
}

test "containsActorBotCheck rejects bot without actor" {
    try testing.expect(!containsActorBotCheck("some_var == 'dependabot[bot]'"));
}

// --- Integration tests ---

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

// --- SEC016: Cache poisoning ---

test "SEC016: release trigger + actions/cache" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/cache@v3") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "Release", .on = makeReleaseTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC016"));
}

test "SEC016: release trigger + setup-node with cache" {
    const eng = engine.Engine.init(&security_rules);
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("cache", "npm") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/setup-node@v4"), .with = with },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "Release", .on = makeReleaseTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC016"));
}

test "SEC016: deploy job name + actions/cache" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/cache@v3") },
    };
    const jobs = [_]Job{
        .{ .id = "deploy-prod", .name = "Deploy to Production", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC016"));
}

test "SEC016: regular CI workflow with cache (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/cache@v3") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .name = "Build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC016"));
}

test "SEC016: release trigger but no cache (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
        .{ .run = "make build" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "Release", .on = makeReleaseTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC016"));
}

test "SEC016: deploy job without cache (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "deploy", .name = "Deploy", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CD", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC016"));
}

test "SEC016: setup-node without cache input in release (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/setup-node@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "Release", .on = makeReleaseTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC016"));
}

test "SEC016: case-insensitive deploy job name" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/cache@v3") },
    };
    const jobs = [_]Job{
        .{ .id = "job1", .name = "DEPLOY to Prod", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CD", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC016"));
}

test "SEC016: publish job id triggers rule" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/cache@v3") },
    };
    const jobs = [_]Job{
        .{ .id = "publish-npm", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC016"));
}

test "SEC016: emits one diagnostic per offending step" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/cache@v3") },
        .{ .uses = ActionRef.parse("actions/cache@v3") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "Release", .on = makeReleaseTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 2), countDiagnostics(&list, "SEC016"));
}

// ============================================================
// SEC013 tests
// ============================================================

test "SEC013: plaintext credentials in container" {
    const eng = engine.Engine.init(&security_rules);
    const container = workflow_types.Container{
        .image = "node:14",
        .credentials = .{ .username = "myuser", .password = "mypassword" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .container = container, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC013"));
    try testing.expectEqual(@as(usize, 2), countDiagnostics(&list, "SEC013"));
}

test "SEC013: plaintext credentials in service" {
    const eng = engine.Engine.init(&security_rules);
    const services = [_]workflow_types.Service{
        .{ .name = "redis", .image = "redis", .credentials = .{ .username = "svcuser", .password = "svcpass" } },
    };
    const jobs = [_]Job{
        .{ .id = "build", .services = &services, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC013"));
    try testing.expectEqual(@as(usize, 2), countDiagnostics(&list, "SEC013"));
}

test "SEC013: plaintext password only" {
    const eng = engine.Engine.init(&security_rules);
    const container = workflow_types.Container{
        .image = "node:14",
        .credentials = .{ .username = "${{ secrets.DOCKER_USER }}", .password = "hardcoded_pass" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .container = container, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC013"));
    try testing.expectEqual(@as(usize, 1), countDiagnostics(&list, "SEC013"));
}

test "SEC013: diagnostics from both container and service" {
    const eng = engine.Engine.init(&security_rules);
    const container = workflow_types.Container{
        .image = "node:14",
        .credentials = .{ .username = "user1", .password = "pass1" },
    };
    const services = [_]workflow_types.Service{
        .{ .name = "db", .image = "postgres", .credentials = .{ .username = "dbuser", .password = "dbpass" } },
    };
    const jobs = [_]Job{
        .{ .id = "build", .container = container, .services = &services, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 4), countDiagnostics(&list, "SEC013"));
}

test "SEC013: secrets expression credentials (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const container = workflow_types.Container{
        .image = "node:14",
        .credentials = .{ .username = "${{ secrets.DOCKER_USER }}", .password = "${{ secrets.DOCKER_PASS }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .container = container, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC013"));
}

test "SEC013: container without credentials (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const container = workflow_types.Container{ .image = "node:14" };
    const jobs = [_]Job{
        .{ .id = "build", .container = container, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC013"));
}

test "SEC013: job without container or services (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{.{ .run = "echo hello" }};
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC013"));
}

test "SEC013: service with secrets credentials (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const services = [_]workflow_types.Service{
        .{ .name = "redis", .image = "redis", .credentials = .{ .username = "${{ secrets.REDIS_USER }}", .password = "${{ secrets.REDIS_PASS }}" } },
    };
    const jobs = [_]Job{
        .{ .id = "build", .services = &services, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC013"));
}

test "isSecretsExpression: valid secrets reference" {
    try testing.expect(isSecretsExpression("${{ secrets.DOCKER_USER }}"));
}

test "isSecretsExpression: with extra whitespace" {
    try testing.expect(isSecretsExpression("${{  secrets.DOCKER_USER  }}"));
}

test "isSecretsExpression: plaintext value" {
    try testing.expect(!isSecretsExpression("myuser"));
}

test "isSecretsExpression: empty string" {
    try testing.expect(!isSecretsExpression(""));
}

test "isSecretsExpression: non-secrets expression" {
    try testing.expect(!isSecretsExpression("${{ github.actor }}"));
}

// ============================================================
// SC001 tests
// ============================================================

test "SC001: unpinned container image with tag" {
    const eng = engine.Engine.init(&security_rules);
    const container = workflow_types.Container{ .image = "node:14" };
    const jobs = [_]Job{
        .{ .id = "build", .container = container, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SC001"));
}

test "SC001: unpinned container image with latest tag" {
    const eng = engine.Engine.init(&security_rules);
    const container = workflow_types.Container{ .image = "redis:latest" };
    const jobs = [_]Job{
        .{ .id = "build", .container = container, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SC001"));
}

test "SC001: unpinned container image without tag" {
    const eng = engine.Engine.init(&security_rules);
    const container = workflow_types.Container{ .image = "redis" };
    const jobs = [_]Job{
        .{ .id = "build", .container = container, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SC001"));
}

test "SC001: unpinned service image" {
    const eng = engine.Engine.init(&security_rules);
    const services = [_]workflow_types.Service{
        .{ .name = "db", .image = "postgres:13" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .services = &services, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SC001"));
}

test "SC001: both container and service unpinned" {
    const eng = engine.Engine.init(&security_rules);
    const container = workflow_types.Container{ .image = "node:14" };
    const services = [_]workflow_types.Service{
        .{ .name = "redis", .image = "redis:6" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .container = container, .services = &services, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(countDiagnostics(&list, "SC001") == 2);
}

test "SC001: pinned container image (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const container = workflow_types.Container{ .image = "node@sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" };
    const jobs = [_]Job{
        .{ .id = "build", .container = container, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SC001"));
}

test "SC001: pinned service image (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const services = [_]workflow_types.Service{
        .{ .name = "redis", .image = "redis@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .services = &services, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SC001"));
}

test "SC001: job without container or services (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{.{ .run = "echo hello" }};
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SC001"));
}

test "SC001: registry with digest is pinned (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const container = workflow_types.Container{ .image = "ghcr.io/owner/image@sha256:a1b2c3d4e5f6" };
    const jobs = [_]Job{
        .{ .id = "build", .container = container, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SC001"));
}

test "isImagePinned: sha256 digest returns true" {
    try testing.expect(isImagePinned("node@sha256:a1b2c3d4e5f6"));
}

test "isImagePinned: tag returns false" {
    try testing.expect(!isImagePinned("node:14"));
}

test "isImagePinned: latest tag returns false" {
    try testing.expect(!isImagePinned("redis:latest"));
}

test "isImagePinned: bare image returns false" {
    try testing.expect(!isImagePinned("redis"));
}

test "isImagePinned: sha256 in name but not digest format" {
    try testing.expect(!isImagePinned("sha256-test:latest"));
}

test "isImagePinned: registry with digest" {
    try testing.expect(isImagePinned("ghcr.io/owner/image@sha256:abc123"));
}
