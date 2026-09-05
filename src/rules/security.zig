const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml = @import("../yaml/types.zig");
const util = @import("../util.zig");
const engine = @import("engine.zig");
const spans = @import("spans.zig");
const fix_builder = @import("../fix/builder.zig");
const advisory = @import("advisory.zig");
const archived = @import("archived.zig");
const stale_refs = @import("stale_refs.zig");
const impostor = @import("impostor.zig");
const refconfusion = @import("refconfusion.zig");
const config_mod = @import("../config.zig");
const compromised_data = @import("data/compromised_actions.zig");

pub const Visibility = config_mod.Visibility;

var sec020_repo_visibility: Visibility = .unknown;

pub fn setRepoVisibility(v: Visibility) void {
    sec020_repo_visibility = v;
}

pub const Diagnostic = diagnostics.Diagnostic;
pub const DiagnosticList = diagnostics.DiagnosticList;
pub const Severity = diagnostics.Severity;
pub const Span = yaml.Span;
pub const Workflow = workflow_types.Workflow;
pub const Job = workflow_types.Job;
pub const Step = workflow_types.Step;
pub const ActionRef = workflow_types.ActionRef;
pub const Permissions = workflow_types.Permissions;
pub const ScalarValueMeta = workflow_types.ScalarValueMeta;
pub const ScalarValueMetaMap = workflow_types.ScalarValueMetaMap;
pub const Fix = diagnostics.Fix;
pub const Edit = diagnostics.Edit;
pub const SecretsConfig = workflow_types.SecretsConfig;
pub const EventType = workflow_types.EventType;
pub const Rule = engine.Rule;
pub const Anchor = spans.Anchor;

// ============================================================
// Diagnostic anchors
//
// Every diagnostic points at the narrowest source location the parser
// preserved: the scalar the finding was read from, falling back to the
// enclosing step or job when a value carries no span of its own.
// ============================================================

fn ifAnchorStep(step: *const Step) Anchor {
    return Anchor.fromMeta(step.if_condition_meta, step.span);
}

fn ifAnchorJob(job: *const Job) Anchor {
    return Anchor.fromMeta(job.if_condition_meta, job.span);
}

fn withAnchor(step: *const Step, key: []const u8) Anchor {
    const meta = if (step.with_meta) |m| m.get(key) else null;
    return Anchor.fromMeta(meta, step.span);
}

fn envAnchor(step: *const Step, key: []const u8) Anchor {
    const meta = if (step.env_meta) |m| m.get(key) else null;
    return Anchor.fromMeta(meta, step.span);
}

/// A `${{ ... }}` expression located inside a scanned string, expressed as an
/// offset and length within that string so an `Anchor` can turn it into a span.
const ExprMatch = struct {
    offset: usize,
    len: usize,
};

// ============================================================
// Dangerous GitHub contexts that can be controlled by users
// ============================================================

/// Untrusted inputs that an attacker can control freely, reported by the
/// injection rules (SEC002 / SEC008) when they are interpolated into a shell
/// script or written to `GITHUB_ENV` / `GITHUB_PATH`.
///
/// Entries are matched as segment prefixes (see `pathMatchesPattern`), so a
/// container path such as `github.event.commits` also covers element accesses
/// like `github.event.commits[0].message` and `github.event.commits.*.author.email`.
const run_dangerous_contexts = [_][]const u8{
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion_comment.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.head_ref",
    // Container prefixes: cover `[0].message`, `.*.author.name`, ...
    "github.event.commits",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.pages",
    "github.event.workflow_run.head_branch",
    // Label names need triage permission to set, so they are a weak injection
    // vector, but they still land verbatim in the shell. Written as a prefix,
    // so `labels.*.name`, `labels[0].name` and a bare `toJSON(labels)` are all
    // covered.
    "github.event.pull_request.labels",
};

/// Untrusted inputs reported by SEC006 inside `if:` conditions.
///
/// An `if:` condition is evaluated by the Actions expression engine and yields
/// a boolean; the value never reaches a shell, so this is not injection. What
/// SEC006 flags is a *gate* an attacker can satisfy on purpose by authoring the
/// text it tests, which is why only free-text fields the attacker writes are
/// listed here.
///
/// Ref-shaped inputs (`github.head_ref`, `...head.ref`, `...head.label`,
/// `...head.repo.default_branch`, `...workflow_run.head_branch`) and label
/// names are deliberately absent: branching on them
/// (`startsWith(github.head_ref, 'release/')`,
/// `contains(github.event.pull_request.labels.*.name, 'deploy')`) is a
/// mainstream routing idiom, and reporting it drowned the real findings (#138).
/// They remain untrusted for SEC002 / SEC008.
const condition_dangerous_contexts = [_][]const u8{
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion_comment.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    // Container prefixes: cover `[0].message`, `.*.author.name`, ...
    "github.event.commits",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.pages",
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
                .span = spans.usesSpan(step),
                .fix_hint = "pin to a full 40-character commit SHA instead of a tag or branch",
            }) catch return;
        }
    }
}

// ============================================================
// SEC002 - Script injection via untrusted context in run:
// ============================================================

const script_injection_fix_hint = "assign the context to an environment variable and use the env var instead";

fn checkScriptInjection(step: *const Step, list: *DiagnosticList) void {
    if (step.run) |run_body| {
        checkContextsInString(run_body, spans.runAnchor(step), &run_dangerous_contexts, "SEC002", .@"error", "script injection: untrusted context used in run: block", script_injection_fix_hint, list);
    }
    checkScriptInputInjection(step, list);
}

/// SEC002 for action inputs executed as code: `actions/github-script` runs `with.script`
/// as JavaScript, so it carries the same injection risk as `run:`.
fn checkScriptInputInjection(step: *const Step, list: *DiagnosticList) void {
    const ref = step.uses orelse return;
    if (!isGithubScriptAction(ref)) return;
    const with_map = step.with orelse return;
    const input = getWithInput(with_map, "script") orelse return;
    checkContextsInString(input.value, withAnchor(step, input.key), &run_dangerous_contexts, "SEC002", .@"error", "script injection: untrusted context used in actions/github-script script: input", script_injection_fix_hint, list);
}

fn isGithubScriptAction(ref: ActionRef) bool {
    const owner = ref.owner orelse return false;
    const repo = ref.repo orelse return false;
    // A nested path is a different action; owner/repo are case-insensitive on GitHub.
    return ref.path == null and
        std.ascii.eqlIgnoreCase(owner, "actions") and
        std.ascii.eqlIgnoreCase(repo, "github-script");
}

/// Look up a `with:` input by name. The runner exposes inputs as `INPUT_<UPPERCASE>`,
/// so input names resolve case-insensitively; the matched key is returned so the
/// diagnostic can anchor on that exact scalar.
fn getWithInput(with_map: workflow_types.StringMap, name: []const u8) ?struct { key: []const u8, value: []const u8 } {
    var it = with_map.iterator();
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, name)) {
            return .{ .key = entry.key_ptr.*, .value = entry.value_ptr.* };
        }
    }
    return null;
}

// ============================================================
// SEC003 - Hardcoded secrets
// ============================================================

fn checkHardcodedSecrets(step: *const Step, list: *DiagnosticList) void {
    // Check run: block
    if (step.run) |run_body| {
        checkStringForSecrets(run_body, spans.runAnchor(step), list);
    }
    // Check with: values
    if (step.with) |with_map| {
        for (with_map.keys(), with_map.values()) |key, val| {
            checkStringForSecrets(val, withAnchor(step, key), list);
        }
    }
    // Check env: values
    if (step.env) |env_map| {
        for (env_map.keys(), env_map.values()) |key, val| {
            checkStringForSecrets(val, envAnchor(step, key), list);
        }
    }
}

fn checkStringForSecrets(s: []const u8, anchor: Anchor, list: *DiagnosticList) void {
    for (secret_prefixes) |prefix| {
        if (std.mem.indexOf(u8, s, prefix)) |offset| {
            list.append(.{
                .rule_id = "SEC003",
                .severity = .@"error",
                .message = "potential hardcoded secret detected",
                .span = anchor.at(s, offset, prefix.len),
                .fix_hint = "use a GitHub secret (secrets.YOUR_SECRET) instead of hardcoding credentials",
            }) catch return;
            return; // One diagnostic per string is enough
        }
    }
}

// ============================================================
// SEC004 - Excessive permissions (write-all)
// ============================================================

const write_all_replacement = "{contents: read}";

fn makeWriteAllFix(list: *DiagnosticList, value_span: Span) ?Fix {
    const edits = fix_builder.replaceScalar(
        list.fixAllocator(),
        value_span,
        .plain,
        write_all_replacement,
    ) orelse return null;
    return .{
        .description = "Replace 'write-all' with minimal permissions",
        .safety = .safe,
        .edits = edits,
    };
}

fn checkExcessivePermissions(wf: *const Workflow, list: *DiagnosticList) void {
    if (wf.permissions) |perms| {
        if (perms.write_all) {
            const span = perms.value_span orelse spans.workflow_head;
            list.append(.{
                .rule_id = "SEC004",
                .severity = .warning,
                .message = "workflow uses 'permissions: write-all' which grants excessive permissions",
                .span = span,
                .fix_hint = "specify only the permissions that are needed",
                .fix = if (perms.value_span) |vs| makeWriteAllFix(list, vs) else null,
            }) catch return;
        }
    }
}

fn checkExcessivePermissionsJob(job: *const Job, list: *DiagnosticList) void {
    if (job.permissions) |perms| {
        if (perms.write_all) {
            const span = perms.value_span orelse job.span;
            list.append(.{
                .rule_id = "SEC004",
                .severity = .warning,
                .message = "job uses 'permissions: write-all' which grants excessive permissions",
                .span = span,
                .fix_hint = "specify only the permissions that are needed",
                .fix = if (perms.value_span) |vs| makeWriteAllFix(list, vs) else null,
            }) catch return;
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
                                    .span = withAnchor(step, "ref").whole(),
                                    .fix_hint = "avoid checking out PR head in pull_request_target workflows, or use a separate unprivileged workflow",
                                }) catch return;
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

/// SEC006 reports a weak gate, not code execution: the expression engine only
/// compares the value. It is a warning so a noisy but non-exploitable condition
/// does not fail a build the way SEC002 / SEC008 do (#138).
const sec006_severity: Severity = .warning;

fn checkUntrustedInCondition(step: *const Step, list: *DiagnosticList) void {
    const cond = step.if_condition orelse return;
    checkConditionForDangerousContext(cond, ifAnchorStep(step), list);
}

fn checkUntrustedInConditionJob(job: *const Job, list: *DiagnosticList) void {
    const cond = job.if_condition orelse return;
    checkConditionForDangerousContext(cond, ifAnchorJob(job), list);
}

/// In GitHub Actions, `if:` conditions are implicitly wrapped in `${{ }}`,
/// so they may contain dangerous contexts either directly or inside `${{ }}`.
fn checkConditionForDangerousContext(cond: []const u8, anchor: Anchor, list: *DiagnosticList) void {
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
        checkContextsInString(cond, anchor, &condition_dangerous_contexts, "SEC006", sec006_severity, "untrusted context used in if: condition expression", "validate the input before using it in a condition", list);
    } else {
        // Bare expression (no ${{ }}), check directly
        if (containsConditionDangerousContext(cond)) {
            list.append(.{
                .rule_id = "SEC006",
                .severity = sec006_severity,
                .message = "untrusted context used in if: condition expression",
                .span = anchor.whole(),
                .fix_hint = "validate the input before using it in a condition",
            }) catch return;
        }
    }
}

// ============================================================
// SEC007 - Missing permissions block
// ============================================================

fn makeMissingPermissionsFix(wf: *const Workflow, list: *DiagnosticList) ?Fix {
    const insert_byte = wf.permissions_insertion_byte orelse return null;
    const edits = fix_builder.insertMappingEntry(
        list.fixAllocator(),
        .{ .byte = insert_byte, .indent = wf.top_level_indent },
        "permissions",
        "{contents: read}",
    ) orelse return null;
    return .{
        .description = "insert top-level permissions: {contents: read}",
        .safety = .unsafe,
        .edits = edits,
    };
}

fn checkMissingPermissions(wf: *const Workflow, list: *DiagnosticList) void {
    if (wf.permissions == null) {
        list.append(.{
            .rule_id = "SEC007",
            .severity = .info,
            .message = "workflow does not define top-level permissions, defaults may be overly broad",
            .span = spans.workflow_head,
            .fix_hint = "add a top-level 'permissions:' block to restrict GITHUB_TOKEN scope",
            .fix = makeMissingPermissionsFix(wf, list),
        }) catch return;
    }
}

// ============================================================
// SEC008 - Dangerous writes to GITHUB_ENV / GITHUB_PATH
// ============================================================

const github_env_targets = [_][]const u8{
    "GITHUB_ENV",
    "GITHUB_PATH",
};

/// Offset of a `>> $GITHUB_ENV` / `>> $GITHUB_PATH` write in `s` (with
/// optional quotes or braces around the variable), or null when there is none.
fn indexOfGithubEnvWrite(s: []const u8) ?usize {
    var i: usize = 0;
    while (i + 1 < s.len) : (i += 1) {
        if (s[i] == '>' and s[i + 1] == '>') {
            var j = i + 2;
            // skip whitespace after >>
            while (j < s.len and (s[j] == ' ' or s[j] == '\t')) : (j += 1) {}
            if (j >= s.len) continue;
            // optional leading quote
            const has_quote = s[j] == '"';
            if (has_quote) j += 1;
            if (j >= s.len) continue;
            // expect '$'
            if (s[j] != '$') continue;
            j += 1;
            if (j >= s.len) continue;
            // optional brace: ${GITHUB_ENV}
            const has_brace = s[j] == '{';
            if (has_brace) j += 1;
            if (j >= s.len) continue;
            for (github_env_targets) |target| {
                if (j + target.len <= s.len and std.mem.eql(u8, s[j .. j + target.len], target)) {
                    var k = j + target.len;
                    if (has_brace) {
                        if (k < s.len and s[k] == '}') {
                            k += 1;
                        } else continue;
                    }
                    if (has_quote) {
                        if (k < s.len and s[k] == '"') {
                            k += 1;
                        } else continue;
                    }
                    // ensure end-of-string or non-identifier char
                    if (k >= s.len or !isIdentChar(s[k])) {
                        return i;
                    }
                }
            }
        }
    }
    return null;
}

fn containsGithubEnvWrite(s: []const u8) bool {
    return indexOfGithubEnvWrite(s) != null;
}

/// Return true if `s` contains any `${{ dangerous_context }}` expression.
/// `s` is always a `run:` body here, so it uses the same list as SEC002.
fn hasDangerousContextExpression(s: []const u8) bool {
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
                if (containsAnyContext(expr, &run_dangerous_contexts)) {
                    return true;
                }
                pos = j + 1;
            }
        }
    }
    return false;
}

fn checkGithubEnvInjection(step: *const Step, list: *DiagnosticList) void {
    const run_body = step.run orelse return;
    const write_offset = indexOfGithubEnvWrite(run_body) orelse return;
    if (!hasDangerousContextExpression(run_body)) return;
    list.append(.{
        .rule_id = "SEC008",
        .severity = .@"error",
        .message = "untrusted input written to GITHUB_ENV/GITHUB_PATH risks environment variable injection",
        .span = spans.runAnchor(step).at(run_body, write_offset, 2),
        .fix_hint = "validate or sanitize the input, or use an intermediate env variable instead of writing directly to GITHUB_ENV/GITHUB_PATH",
    }) catch return;
}

// ============================================================
// SEC009 - workflow_run triggered workflow checking out untrusted ref
// ============================================================

fn checkWorkflowRunUntrustedCheckout(wf: *const Workflow, list: *DiagnosticList) void {
    var has_workflow_run = false;
    for (wf.on.events) |event| {
        if (event.event == .workflow_run) {
            has_workflow_run = true;
            break;
        }
    }
    if (!has_workflow_run) return;

    for (wf.jobs) |*job| {
        for (job.steps) |*step| {
            const action_ref = step.uses orelse continue;
            if (!isCheckoutAction(action_ref)) continue;
            const with_map = step.with orelse continue;
            const ref_val = with_map.get("ref") orelse continue;
            if (!containsDangerousWorkflowRunRef(ref_val)) continue;
            list.append(.{
                .rule_id = "SEC009",
                .severity = .@"error",
                .message = "dangerous: workflow_run job checks out a ref from the triggering workflow, which may allow arbitrary code execution when the triggering workflow is influenced by untrusted code such as forks",
                .span = withAnchor(step, "ref").whole(),
                .fix_hint = "if the triggering workflow may be influenced by untrusted code such as forks, do not check out refs from workflow_run; instead, perform the checkout in a separate pull_request workflow with minimal permissions and pass artifacts forward",
            }) catch return;
        }
    }
}

fn containsDangerousWorkflowRunRef(ref_val: []const u8) bool {
    return std.mem.indexOf(u8, ref_val, "github.event.workflow_run.") != null;
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
                    .span = job.span,
                    .fix_hint = "explicitly specify only the secrets the called workflow needs instead of using 'inherit'",
                }) catch return;
            },
            .map => {},
        }
    }
}

// ============================================================
// SEC011 - Overprovisioned secrets (entire secrets context exposed)
// ============================================================

fn checkOverprovisionedSecrets(step: *const Step, list: *DiagnosticList) void {
    // Check run: block
    if (step.run) |run_body| {
        if (findOverprovisionedSecrets(run_body)) |m| {
            emitSEC011(spans.runAnchor(step).at(run_body, m.offset, m.len), list);
            return;
        }
    }
    // Check with: values
    if (step.with) |with_map| {
        for (with_map.keys(), with_map.values()) |key, val| {
            if (findOverprovisionedSecrets(val)) |m| {
                emitSEC011(withAnchor(step, key).at(val, m.offset, m.len), list);
                return;
            }
        }
    }
    // Check env: values
    if (step.env) |env_map| {
        for (env_map.keys(), env_map.values()) |key, val| {
            if (findOverprovisionedSecrets(val)) |m| {
                emitSEC011(envAnchor(step, key).at(val, m.offset, m.len), list);
                return;
            }
        }
    }
}

fn emitSEC011(span: Span, list: *DiagnosticList) void {
    list.append(.{
        .rule_id = "SEC011",
        .severity = .warning,
        .message = "entire secrets context is exposed; reference only the specific secrets you need",
        .span = span,
        .fix_hint = "replace ${{ secrets }} or toJSON(secrets) with individual references like ${{ secrets.MY_TOKEN }}",
    }) catch return;
}

/// Find the first `${{ ... }}` expression in `s` that references the entire
/// secrets context. Returns its offset and length within `s`.
fn findOverprovisionedSecrets(s: []const u8) ?ExprMatch {
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
                if (exprIsWholeSecretsRef(expr)) {
                    return .{ .offset = pos, .len = j + 2 - pos };
                }
                pos = j + 1;
            }
        }
    }
    return null;
}

/// Check if an expression references the entire secrets context (not an individual secret).
/// Returns true for: "secrets", "toJSON(secrets)", "fromJSON(secrets)" etc.
/// Returns false for: "secrets.TOKEN", "toJSON(secrets.X)", "env.secrets", etc.
fn exprIsWholeSecretsRef(expr: []const u8) bool {
    const trimmed = std.mem.trim(u8, expr, " \t\n\r");
    if (trimmed.len == 0) return false;

    // Check for bare "secrets" reference
    if (std.mem.eql(u8, trimmed, "secrets")) return true;

    // Check for toJSON(secrets) / fromJSON(secrets) patterns
    const patterns = [_][]const u8{ "toJSON", "tojson", "toJson", "TOJSON", "fromJSON", "fromjson", "fromJson", "FROMJSON" };
    for (patterns) |func_name| {
        var i: usize = 0;
        while (i + func_name.len <= trimmed.len) : (i += 1) {
            if (std.mem.eql(u8, trimmed[i .. i + func_name.len], func_name)) {
                // Find the opening paren after optional whitespace
                var k = i + func_name.len;
                while (k < trimmed.len and (trimmed[k] == ' ' or trimmed[k] == '\t')) : (k += 1) {}
                if (k < trimmed.len and trimmed[k] == '(') {
                    // Skip whitespace after '('
                    var arg_start = k + 1;
                    while (arg_start < trimmed.len and (trimmed[arg_start] == ' ' or trimmed[arg_start] == '\t')) : (arg_start += 1) {}
                    if (arg_start + 7 <= trimmed.len and std.mem.eql(u8, trimmed[arg_start .. arg_start + 7], "secrets")) {
                        // Must be followed by ')' or whitespace then ')' — NOT '.' (individual secret)
                        const after = arg_start + 7;
                        if (after >= trimmed.len) return true;
                        if (trimmed[after] == ')') return true;
                        if (trimmed[after] == ' ' or trimmed[after] == '\t') {
                            // Skip whitespace, expect ')'
                            var m = after;
                            while (m < trimmed.len and (trimmed[m] == ' ' or trimmed[m] == '\t')) : (m += 1) {}
                            if (m < trimmed.len and trimmed[m] == ')') return true;
                        }
                        // '.' means individual secret — not a match
                    }
                }
            }
        }
    }
    return false;
}

// ============================================================
// SEC012 - Unredacted secrets via toJSON/fromJSON
// ============================================================

fn checkUnredactedSecrets(step: *const Step, list: *DiagnosticList) void {
    // Check run: block
    if (step.run) |run_body| {
        if (findUnredactedSecrets(run_body)) |m| {
            emitSEC012(spans.runAnchor(step).at(run_body, m.offset, m.len), list);
            return;
        }
    }
    // Check with: values
    if (step.with) |with_map| {
        for (with_map.keys(), with_map.values()) |key, val| {
            if (findUnredactedSecrets(val)) |m| {
                emitSEC012(withAnchor(step, key).at(val, m.offset, m.len), list);
                return;
            }
        }
    }
    // Check env: values
    if (step.env) |env_map| {
        for (env_map.keys(), env_map.values()) |key, val| {
            if (findUnredactedSecrets(val)) |m| {
                emitSEC012(envAnchor(step, key).at(val, m.offset, m.len), list);
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
        checkCredentialsForHardcoded(container.credentials, job.span, list);
    }
    for (job.services) |service| {
        checkCredentialsForHardcoded(service.credentials, job.span, list);
    }
}

/// `credentials:` values carry no span of their own, so findings point at the
/// job that declares the container or service.
fn checkCredentialsForHardcoded(creds: ?workflow_types.Credentials, job_span: Span, list: *DiagnosticList) void {
    const credentials = creds orelse return;
    if (credentials.username) |username| {
        if (!isSecretsExpression(username)) {
            list.append(.{
                .rule_id = "SEC013",
                .severity = .@"error",
                .message = "hardcoded credentials in container configuration",
                .span = job_span,
                .fix_hint = "use ${{ secrets.YOUR_SECRET }} for container credentials instead of plaintext values",
            }) catch return;
        }
    }
    if (credentials.password) |password| {
        if (!isSecretsExpression(password)) {
            list.append(.{
                .rule_id = "SEC013",
                .severity = .@"error",
                .message = "hardcoded credentials in container configuration",
                .span = job_span,
                .fix_hint = "use ${{ secrets.YOUR_SECRET }} for container credentials instead of plaintext values",
            }) catch return;
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
// SEC019 - Secrets used outside env: block
// ============================================================

/// Find the first `${{ secrets.* }}` expression in `s` (excluding
/// secrets.GITHUB_TOKEN). Returns its offset and length within `s`.
fn findSecretsOutsideEnv(s: []const u8) ?ExprMatch {
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
                const inner = std.mem.trim(u8, s[expr_start..j], " \t\n\r");
                if (std.mem.startsWith(u8, inner, "secrets.")) {
                    const secret_name = inner["secrets.".len..];
                    if (!std.mem.eql(u8, secret_name, "GITHUB_TOKEN")) {
                        return .{ .offset = pos, .len = j + 2 - pos };
                    }
                }
                pos = j + 1;
            }
        }
    }
    return null;
}

fn emitSEC019(span: Span, list: *DiagnosticList) void {
    list.append(.{
        .rule_id = "SEC019",
        .severity = .info,
        .message = "secret used directly in run:/with: instead of being bound through env:",
        .span = span,
        .fix_hint = "bind the secret to an env: variable first, then reference the env var in run:/with:",
    }) catch return;
}

fn checkSecretsOutsideEnv(step: *const Step, list: *DiagnosticList) void {
    // Check run: block
    if (step.run) |run_body| {
        if (findSecretsOutsideEnv(run_body)) |m| {
            emitSEC019(spans.runAnchor(step).at(run_body, m.offset, m.len), list);
            return;
        }
    }
    // Check with: values
    if (step.with) |with_map| {
        for (with_map.keys(), with_map.values()) |key, val| {
            if (findSecretsOutsideEnv(val)) |m| {
                emitSEC019(withAnchor(step, key).at(val, m.offset, m.len), list);
                return;
            }
        }
    }
    // NOTE: Do NOT check step.env — that's the correct pattern
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
                    .span = spans.usesSpan(step),
                    .fix_hint = "avoid using actions/cache or setup action caching in release/deploy workflows; build from scratch or use a dedicated cache scope",
                }) catch return;
            }
        }
    }
}

fn emitSEC012(span: Span, list: *DiagnosticList) void {
    list.append(.{
        .rule_id = "SEC012",
        .severity = .@"error",
        .message = "secret exposed via toJSON()/fromJSON() bypasses masking",
        .span = span,
        .fix_hint = "avoid passing secrets through toJSON()/fromJSON(); assign individual secret values to environment variables instead",
    }) catch return;
}

/// Find the first `${{ ... }}` expression in `s` with a toJSON(secrets...) or
/// fromJSON(secrets...) pattern. Returns its offset and length within `s`.
fn findUnredactedSecrets(s: []const u8) ?ExprMatch {
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
                    return .{ .offset = pos, .len = j + 2 - pos };
                }
                pos = j + 1;
            }
        }
    }
    return null;
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
        if (std.ascii.indexOfIgnoreCase(s, keyword) != null) return true;
    }
    return false;
}

fn isCacheAction(step: *const Step) bool {
    const action_ref = step.uses orelse return false;
    const base = util.actionBaseName(action_ref.raw);
    return std.mem.eql(u8, base, "actions/cache");
}

fn isSetupActionWithCache(step: *const Step) bool {
    const action_ref = step.uses orelse return false;
    const base = util.actionBaseName(action_ref.raw);
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

// ============================================================
// SEC014 - Spoofable bot actor check in conditions
// ============================================================

fn checkBotConditionStep(step: *const Step, list: *DiagnosticList) void {
    const cond = step.if_condition orelse return;
    checkConditionForBotActorCheck(cond, ifAnchorStep(step), list);
}

fn checkBotConditionJob(job: *const Job, list: *DiagnosticList) void {
    const cond = job.if_condition orelse return;
    checkConditionForBotActorCheck(cond, ifAnchorJob(job), list);
}

/// Check if an if-condition compares github.actor / github.triggering_actor
/// against a bot account name (containing "[bot]"). This is spoofable.
fn checkConditionForBotActorCheck(cond: []const u8, anchor: Anchor, list: *DiagnosticList) void {
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
        checkBotActorInString(cond, anchor, list);
    } else {
        // Bare expression
        if (containsActorBotCheck(cond)) {
            list.append(.{
                .rule_id = "SEC014",
                .severity = .warning,
                .message = "spoofable bot check: github.actor can be impersonated by creating an account with the same name",
                .span = anchor.whole(),
                .fix_hint = "use github.event.sender.type == 'Bot' or GitHub's built-in Dependabot integration features instead",
            }) catch return;
        }
    }
}

/// Scan a string for ${{ expr }} patterns that contain actor + [bot] checks.
fn checkBotActorInString(s: []const u8, anchor: Anchor, list: *DiagnosticList) void {
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
                    const match = ExprMatch{ .offset = pos, .len = j + 2 - pos };
                    list.append(.{
                        .rule_id = "SEC014",
                        .severity = .warning,
                        .message = "spoofable bot check: github.actor can be impersonated by creating an account with the same name",
                        .span = anchor.at(s, match.offset, match.len),
                        .fix_hint = "use github.event.sender.type == 'Bot' or GitHub's built-in Dependabot integration features instead",
                    }) catch return;
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
    if (!containsAnyContext(expr, &actor_contexts)) return false;

    return std.mem.indexOf(u8, expr, "[bot]") != null;
}

// ============================================================
// SEC015 - Artipacked: credential leak via upload-artifact
// ============================================================

fn isUploadArtifactAction(ref: ActionRef) bool {
    const owner = ref.owner orelse return false;
    const repo = ref.repo orelse return false;
    return std.mem.eql(u8, owner, "actions") and std.mem.eql(u8, repo, "upload-artifact");
}

fn hasPersistCredentialsFalse(step: *const Step) bool {
    const with_map = step.with orelse return false;
    const val = with_map.get("persist-credentials") orelse return false;
    return std.mem.eql(u8, val, "false");
}

fn checkArtipacked(job: *const Job, list: *DiagnosticList) void {
    var has_upload_after = false;
    var i = job.steps.len;
    while (i > 0) {
        i -= 1;
        const step = &job.steps[i];
        if (step.uses) |ref| {
            if (isUploadArtifactAction(ref)) {
                has_upload_after = true;
                continue;
            }

            if (has_upload_after and isCheckoutAction(ref) and !hasPersistCredentialsFalse(step)) {
                var diag = Diagnostic{
                    .rule_id = "SEC015",
                    .severity = .warning,
                    .message = "actions/checkout persists credentials by default; combined with upload-artifact, the GITHUB_TOKEN may leak via uploaded artifacts",
                    .span = spans.usesSpan(step),
                    .fix_hint = "add 'persist-credentials: false' to the checkout step's 'with:' block",
                };

                // Attach autofix when span info is available
                if (step.uses_value_end_byte != null) {
                    diag.fix = buildPersistCredentialsFalseFix(
                        list,
                        step,
                        "add persist-credentials: false to checkout step",
                        .safe,
                    );
                }

                list.append(diag) catch return;
            }
        }
    }
}

fn buildPersistCredentialsFalseFix(
    list: *DiagnosticList,
    step: *const Step,
    description: []const u8,
    safety: diagnostics.FixSafety,
) ?diagnostics.Fix {
    const alloc = list.fixAllocator();
    const col = step.uses_key_col orelse 7;
    if (col == 0) return null;

    // Only generate Fix when persist-credentials is absent.
    // When persist-credentials: true, fall back to fix_hint only.
    const has_persist = if (step.with) |w| w.get("persist-credentials") != null else false;
    if (has_persist) return null;

    // uses_key_col is 1-based; parent aligns at col - 1 spaces, child at col + 1.
    const parent_indent = alloc.alloc(u8, col - 1) catch return null;
    @memset(parent_indent, ' ');
    const child_indent = alloc.alloc(u8, col + 1) catch return null;
    @memset(child_indent, ' ');

    if (step.with == null) {
        // No with: block — insert with: and persist-credentials: false after uses: value
        const insert_at = step.uses_value_end_byte orelse return null;
        const replacement = std.fmt.allocPrint(alloc, "\n{s}with:\n{s}persist-credentials: false", .{ parent_indent, child_indent }) catch return null;
        const edits = alloc.alloc(diagnostics.Edit, 1) catch return null;
        edits[0] = .{ .start_byte = insert_at, .end_byte = insert_at, .replacement = replacement };
        return .{ .description = description, .safety = safety, .edits = edits };
    } else {
        // with: exists — append persist-credentials: false after last entry
        const insert_at = step.with_last_entry_end_byte orelse return null;
        const edits = fix_builder.appendMappingEntry(
            alloc,
            insert_at,
            col + 1,
            "persist-credentials",
            "false",
        ) orelse return null;
        return .{ .description = description, .safety = safety, .edits = edits };
    }
}

// --- SEC018: checkout-persist-credentials ---

const PersistCredentialsState = enum { not_set, explicit_true, explicit_false };

fn classifyPersistCredentials(step: *const Step) PersistCredentialsState {
    const with_map = step.with orelse return .not_set;
    const val = with_map.get("persist-credentials") orelse return .not_set;
    if (std.ascii.eqlIgnoreCase(val, "false")) return .explicit_false;
    if (std.ascii.eqlIgnoreCase(val, "true")) return .explicit_true;
    return .not_set;
}

fn checkCheckoutPersistCredentials(step: *const Step, list: *DiagnosticList) void {
    const ref = step.uses orelse return;
    if (!isCheckoutAction(ref)) return;

    const state = classifyPersistCredentials(step);
    if (state == .explicit_false) return;

    const message_base = "actions/checkout persists GITHUB_TOKEN in .git/config by default; subsequent steps can read the token";
    const message = if (state == .explicit_true)
        message_base ++ " (explicitly set to true)"
    else
        message_base;

    var diag = Diagnostic{
        .rule_id = "SEC018",
        .severity = .warning,
        .message = message,
        .span = spans.usesSpan(step),
        .fix_hint = "add 'with.persist-credentials: false' unless you need git push / gh from later steps",
    };

    if (state == .not_set and step.uses_value_end_byte != null) {
        diag.fix = buildPersistCredentialsFalseFix(
            list,
            step,
            "add persist-credentials: false to checkout step",
            .unsafe,
        );
    }

    list.append(diag) catch return;
}

// ── SC002: Compromised action SHA / tag ──

fn checkCompromisedAction(step: *const Step, list: *DiagnosticList) void {
    const action_ref = step.uses orelse return;
    if (action_ref.is_local or action_ref.is_docker) return;
    const owner = action_ref.owner orelse return;
    const repo = action_ref.repo orelse return;
    const ref = action_ref.ref orelse return;

    for (compromised_data.compromised_actions) |entry| {
        if (!std.mem.eql(u8, owner, entry.owner)) continue;
        if (!std.mem.eql(u8, repo, entry.repo)) continue;

        var hit = false;
        for (entry.shas) |sha| {
            if (std.ascii.eqlIgnoreCase(ref, sha)) {
                hit = true;
                break;
            }
        }
        if (!hit) {
            for (entry.tags) |tag| {
                if (std.mem.eql(u8, ref, tag)) {
                    hit = true;
                    break;
                }
            }
        }
        if (!hit) return;

        const alloc = list.fixAllocator();
        const message = std.fmt.allocPrint(
            alloc,
            "{s}/{s}@{s} is a known compromised action (disclosed {s}, see {s})",
            .{ owner, repo, ref, entry.disclosed, entry.advisory_url },
        ) catch return;

        list.append(.{
            .rule_id = "SC002",
            .severity = .@"error",
            .message = message,
            .span = spans.usesSpan(step),
            .fix_hint = "rollback to a pre-incident SHA or migrate to a trusted fork; do not re-pin to any tag of this action",
        }) catch return;
        return;
    }
}

// ============================================================
// Shared helpers
// ============================================================

/// Scan a string for `${{ dangerous_context }}` patterns.
///
/// Every offending expression is reported separately: a single `run:` block can
/// interpolate several untrusted values, and each one is its own injection
/// point with its own source location.
fn checkContextsInString(s: []const u8, anchor: Anchor, contexts: []const []const u8, rule_id: []const u8, severity: Severity, message: []const u8, fix_hint: []const u8, list: *DiagnosticList) void {
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
                if (containsAnyContext(expr, contexts)) {
                    const match = ExprMatch{ .offset = pos, .len = j + 2 - pos };
                    list.append(.{
                        .rule_id = rule_id,
                        .severity = severity,
                        .message = message,
                        .span = anchor.at(s, match.offset, match.len),
                        .fix_hint = fix_hint,
                    }) catch return;
                }
                pos = j + 1;
            }
        }
    }
}

fn containsConditionDangerousContext(expr: []const u8) bool {
    return containsAnyContext(expr, &condition_dangerous_contexts);
}

// ------------------------------------------------------------
// Context path matching
//
// A context reference is compared segment by segment rather than as a raw
// substring, so that object filters (`github.event.commits.*.message`) and
// index accesses (`github.event.commits[0].message`) are understood instead of
// accidentally matched. Both are normalized to the wildcard segment `*`, which
// matches any single segment on either side of the comparison.
// ------------------------------------------------------------

const max_path_segments = 16;

const wildcard_segment = "*";

/// A context reference split into segments, e.g. `github.event.commits.*.message`
/// becomes `{ "github", "event", "commits", "*", "message" }`.
const ContextPath = struct {
    segments: [max_path_segments][]const u8 = undefined,
    len: usize = 0,
    /// Index just past the last character the reference consumed.
    end: usize = 0,

    fn append(self: *ContextPath, segment: []const u8) void {
        if (self.len >= max_path_segments) return;
        self.segments[self.len] = segment;
        self.len += 1;
    }
};

/// Scan `expr` for context references and report whether any of them is covered
/// by one of `contexts`. Function calls need no special handling: `join(...)` and
/// `toJSON(...)` arguments are themselves references and are visited the same way.
fn containsAnyContext(expr: []const u8, contexts: []const []const u8) bool {
    var i: usize = 0;
    while (i < expr.len) {
        if (expr[i] == '\'') {
            i = skipStringLiteral(expr, i);
            continue;
        }
        const starts_path = isIdentStart(expr[i]) and (i == 0 or !isIdentChar(expr[i - 1]));
        if (!starts_path) {
            i += 1;
            continue;
        }
        // A whole reference is consumed at once, so segments in the middle of
        // `steps.meta.outputs.github.head_ref` are never mistaken for a root.
        const path = parseContextPath(expr, i);
        for (contexts) |ctx| {
            if (pathMatchesPattern(path, ctx)) return true;
        }
        i = if (path.end > i) path.end else i + 1;
    }
    return false;
}

/// Skip a single-quoted expression literal, honouring the `''` escape.
fn skipStringLiteral(expr: []const u8, start: usize) usize {
    var i = start + 1;
    while (i < expr.len) : (i += 1) {
        if (expr[i] != '\'') continue;
        if (i + 1 < expr.len and expr[i + 1] == '\'') {
            i += 1;
            continue;
        }
        return i + 1;
    }
    return expr.len;
}

/// Parse the context reference that begins at `start`.
fn parseContextPath(expr: []const u8, start: usize) ContextPath {
    var path = ContextPath{};
    var i = start;
    while (i < expr.len and isIdentChar(expr[i])) i += 1;
    path.append(expr[start..i]);

    while (i < expr.len) {
        if (expr[i] == '.') {
            const seg_start = i + 1;
            if (seg_start < expr.len and expr[seg_start] == '*') {
                // Object filter: collects the property from every element.
                path.append(wildcard_segment);
                i = seg_start + 1;
                continue;
            }
            var j = seg_start;
            while (j < expr.len and isIdentChar(expr[j])) j += 1;
            if (j == seg_start) break; // A lone '.' is not part of the path.
            path.append(expr[seg_start..j]);
            i = j;
            continue;
        }
        if (expr[i] == '[') {
            // Any index access is treated as a wildcard: the index may itself be
            // an expression, and every element is equally untrusted.
            const close = std.mem.indexOfScalarPos(u8, expr, i + 1, ']') orelse break;
            path.append(wildcard_segment);
            i = close + 1;
            continue;
        }
        break;
    }
    path.end = i;
    return path;
}

/// True when `pattern` covers `path`. The pattern only needs to be a prefix of
/// the reference, because everything below an untrusted node is untrusted too.
fn pathMatchesPattern(path: ContextPath, pattern: []const u8) bool {
    var it = std.mem.splitScalar(u8, pattern, '.');
    var idx: usize = 0;
    while (it.next()) |pat_seg| : (idx += 1) {
        if (idx >= path.len) return false; // Reference is shorter than the pattern.
        if (!segmentMatches(path.segments[idx], pat_seg)) return false;
    }
    return true;
}

fn segmentMatches(ref_seg: []const u8, pat_seg: []const u8) bool {
    if (std.mem.eql(u8, ref_seg, wildcard_segment)) return true;
    if (std.mem.eql(u8, pat_seg, wildcard_segment)) return true;
    // Context names are case-insensitive in GitHub Actions expressions.
    return std.ascii.eqlIgnoreCase(ref_seg, pat_seg);
}

fn isIdentChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

fn isIdentStart(c: u8) bool {
    return std.ascii.isAlphabetic(c) or c == '_';
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
                    // `container.image` is parsed without a span; the job is the
                    // narrowest location available.
                    .span = job.span,
                    .fix_hint = "pin the image using a digest reference, e.g. image@sha256:abc123...",
                }) catch return;
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
                    // `services.<id>.image` is parsed without a span; the job is
                    // the narrowest location available.
                    .span = job.span,
                    .fix_hint = "pin the image using a digest reference, e.g. image@sha256:abc123...",
                }) catch return;
            }
        }
    }
}

// ============================================================
// SEC017 - Insecure workflow commands
// ============================================================

fn buildInsecureCommandsFix(list: *DiagnosticList, meta: ScalarValueMeta) ?Fix {
    const edits = fix_builder.replaceScalar(
        list.fixAllocator(),
        meta.value_span,
        meta.style,
        "false",
    ) orelse return null;

    return .{
        .description = "set ACTIONS_ALLOW_UNSECURE_COMMANDS to false",
        .safety = .safe,
        .edits = edits,
    };
}

fn checkEnvForInsecureCommands(env_map: workflow_types.StringMap, env_meta: ?ScalarValueMetaMap, fallback: Span, list: *DiagnosticList) void {
    if (env_map.get("ACTIONS_ALLOW_UNSECURE_COMMANDS")) |val| {
        if (std.mem.eql(u8, val, "true")) {
            const meta = if (env_meta) |m| m.get("ACTIONS_ALLOW_UNSECURE_COMMANDS") else null;
            var diag = Diagnostic{
                .rule_id = "SEC017",
                .severity = .warning,
                .message = "insecure workflow commands are enabled via ACTIONS_ALLOW_UNSECURE_COMMANDS",
                .span = if (meta) |m| m.value_span else fallback,
                .fix_hint = "remove ACTIONS_ALLOW_UNSECURE_COMMANDS or set it to false; use environment files instead of set-env/add-path",
            };

            if (meta) |m| {
                diag.fix = buildInsecureCommandsFix(list, m);
            }

            list.append(diag) catch return;
        }
    }
}

fn checkInsecureCommandsStep(step: *const Step, list: *DiagnosticList) void {
    if (step.env) |env_map| {
        checkEnvForInsecureCommands(env_map, step.env_meta, step.span, list);
    }
}

fn checkInsecureCommandsJob(job: *const Job, list: *DiagnosticList) void {
    if (job.env) |env_map| {
        checkEnvForInsecureCommands(env_map, job.env_meta, job.span, list);
    }
}

fn checkInsecureCommandsWorkflow(wf: *const Workflow, list: *DiagnosticList) void {
    if (wf.env) |env_map| {
        checkEnvForInsecureCommands(env_map, wf.env_meta, spans.workflow_head, list);
    }
}

// ============================================================
// SEC020 - Self-hosted runner on fork-accessible trigger
// ============================================================

fn hasForkAccessibleTrigger(wf: *const Workflow) bool {
    for (wf.on.events) |event| {
        switch (event.event) {
            .pull_request,
            .pull_request_target,
            .workflow_run,
            .issue_comment,
            => return true,
            else => {},
        }
    }
    return false;
}

fn checkSelfHostedRunnerForkTriggeredWorkflow(wf: *const Workflow, list: *DiagnosticList) void {
    // Private repositories opt out; public and unknown fall through (fail-safe).
    if (sec020_repo_visibility == .private) return;

    if (!hasForkAccessibleTrigger(wf)) return;

    for (wf.jobs) |*job| {
        const runs_on = job.runs_on orelse continue;
        if (std.mem.indexOf(u8, runs_on, "self-hosted") == null) continue;

        list.append(.{
            .rule_id = "SEC020",
            .severity = .warning,
            .message = "self-hosted runner is used on a workflow with fork-accessible triggers; untrusted code may execute on your runner host",
            .span = job.span,
            .fix_hint = "use GitHub-hosted runners for fork-accessible triggers, restrict with `if:` to avoid running on fork PRs, or make the runner ephemeral",
        }) catch return;
    }
}

// ============================================================
// BP007 - Obfuscated command execution
// ============================================================

fn checkObfuscatedExecution(step: *const Step, list: *DiagnosticList) void {
    const run_body = step.run orelse return;
    if (containsBase64PipeExec(run_body) or
        containsEvalVarExpansion(run_body) or
        containsCurlWgetPipeShell(run_body) or
        containsVarAsCommand(run_body))
    {
        list.append(.{
            .rule_id = "BP007",
            .severity = .warning,
            .message = "potentially obfuscated command execution detected",
            .span = spans.runAnchor(step).whole(),
            .fix_hint = "avoid indirect command execution; use explicit, readable commands",
        }) catch return;
    }
}

const exec_targets = [_][]const u8{ "bash", "sh", "zsh", "eval", "source" };
const shell_targets = [_][]const u8{ "bash", "sh", "zsh" };

fn containsBase64PipeExec(s: []const u8) bool {
    const needle = "base64";
    var i: usize = 0;
    while (i + needle.len <= s.len) : (i += 1) {
        if (!std.mem.eql(u8, s[i .. i + needle.len], needle)) continue;
        const before_ok = i == 0 or !isIdentChar(s[i - 1]);
        const after_ok = (i + needle.len >= s.len) or !isIdentChar(s[i + needle.len]);
        if (!before_ok or !after_ok) continue;

        // Scan for decode flag and pipe
        var j = i + needle.len;
        var has_decode = false;
        while (j < s.len and s[j] != '|') : (j += 1) {
            if (s[j] == '-') {
                // Check -d
                if (j + 1 < s.len and s[j + 1] == 'd' and
                    (j + 2 >= s.len or !isIdentChar(s[j + 2])))
                {
                    has_decode = true;
                }
                // Check --decode
                if (j + 1 < s.len and s[j + 1] == '-') {
                    const decode_str = "--decode";
                    if (j + decode_str.len <= s.len and
                        std.mem.eql(u8, s[j .. j + decode_str.len], decode_str) and
                        (j + decode_str.len >= s.len or !isIdentChar(s[j + decode_str.len])))
                    {
                        has_decode = true;
                    }
                }
            }
        }
        if (!has_decode or j >= s.len or s[j] != '|') continue;

        // Skip whitespace after pipe
        var k = j + 1;
        while (k < s.len and (s[k] == ' ' or s[k] == '\t' or s[k] == '\n')) : (k += 1) {}
        // Check for exec target
        for (exec_targets) |target| {
            if (k + target.len <= s.len and
                std.mem.eql(u8, s[k .. k + target.len], target) and
                (k + target.len >= s.len or !isIdentChar(s[k + target.len])))
            {
                return true;
            }
        }
    }
    return false;
}

fn containsEvalVarExpansion(s: []const u8) bool {
    const needle = "eval";
    var i: usize = 0;
    while (i + needle.len <= s.len) : (i += 1) {
        if (!std.mem.eql(u8, s[i .. i + needle.len], needle)) continue;
        const before_ok = i == 0 or !isIdentChar(s[i - 1]);
        if (!before_ok) continue;
        var j = i + needle.len;
        // Must be followed by whitespace
        if (j >= s.len or (s[j] != ' ' and s[j] != '\t')) continue;
        // Skip whitespace
        while (j < s.len and (s[j] == ' ' or s[j] == '\t')) : (j += 1) {}
        if (j >= s.len) continue;
        // Skip optional quote
        if (s[j] == '"' or s[j] == '\'') j += 1;
        if (j >= s.len) continue;
        // Check for $ (variable expansion)
        if (s[j] == '$') {
            // Exclude ${{ (GitHub Actions expression)
            if (j + 2 < s.len and s[j + 1] == '{' and s[j + 2] == '{') continue;
            return true;
        }
    }
    return false;
}

fn containsCurlWgetPipeShell(s: []const u8) bool {
    const downloaders = [_][]const u8{ "curl", "wget" };
    for (downloaders) |downloader| {
        var i: usize = 0;
        while (i + downloader.len <= s.len) : (i += 1) {
            if (!std.mem.eql(u8, s[i .. i + downloader.len], downloader)) continue;
            const before_ok = i == 0 or !isIdentChar(s[i - 1]);
            const after_ok = (i + downloader.len >= s.len) or !isIdentChar(s[i + downloader.len]);
            if (!before_ok or !after_ok) continue;

            // Scan forward for | followed by shell
            var j = i + downloader.len;
            while (j < s.len) : (j += 1) {
                if (s[j] == '|') {
                    // Skip whitespace after pipe
                    var k = j + 1;
                    while (k < s.len and (s[k] == ' ' or s[k] == '\t' or s[k] == '\n')) : (k += 1) {}
                    // Check for shell target
                    for (shell_targets) |shell| {
                        if (k + shell.len <= s.len and
                            std.mem.eql(u8, s[k .. k + shell.len], shell) and
                            (k + shell.len >= s.len or !isIdentChar(s[k + shell.len])))
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

fn isAllUppercase(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (std.ascii.isLower(c)) return false;
    }
    return true;
}

fn containsVarAsCommand(s: []const u8) bool {
    var line_start: usize = 0;
    while (line_start < s.len) {
        // Find end of current line
        var line_end = line_start;
        while (line_end < s.len and s[line_end] != '\n') : (line_end += 1) {}

        // Skip leading whitespace
        var pos = line_start;
        while (pos < line_end and (s[pos] == ' ' or s[pos] == '\t')) : (pos += 1) {}

        if (pos < line_end and s[pos] == '$') {
            // Exclude ${{ (GitHub Actions expression)
            if (pos + 2 < line_end and s[pos + 1] == '{' and s[pos + 2] == '{') {
                // skip
            } else if (pos + 1 < line_end and s[pos + 1] == '(') {
                // $(...) command substitution, skip
            } else if (pos + 1 < line_end and s[pos + 1] == '{') {
                // ${VAR} form
                var k = pos + 2;
                const var_start = k;
                while (k < line_end and (std.ascii.isAlphabetic(s[k]) or s[k] == '_' or std.ascii.isDigit(s[k]))) : (k += 1) {}
                if (k < line_end and s[k] == '}' and k > var_start) {
                    if (isAllUppercase(s[var_start..k])) return true;
                }
            } else if (pos + 1 < line_end and (std.ascii.isAlphabetic(s[pos + 1]) or s[pos + 1] == '_')) {
                // $VAR form
                var k = pos + 1;
                const var_start = k;
                while (k < line_end and (std.ascii.isAlphanumeric(s[k]) or s[k] == '_')) : (k += 1) {}
                if (k > var_start and isAllUppercase(s[var_start..k])) return true;
            }
        }

        line_start = if (line_end < s.len) line_end + 1 else s.len;
    }
    return false;
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
        .description = "Untrusted GitHub context used in run: block or a code-executing action input risks script injection",
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
        .severity = sec006_severity,
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
        .id = "SEC008",
        .name = "github-env-injection",
        .description = "Untrusted input written to GITHUB_ENV/GITHUB_PATH risks environment injection",
        .severity = .@"error",
        .category = .security,
        .check_step = &checkGithubEnvInjection,
    },
    .{
        .id = "SEC009",
        .name = "workflow-run-untrusted-checkout",
        .description = "workflow_run job checks out a ref from the triggering workflow, which may allow arbitrary code execution from forks",
        .severity = .@"error",
        .category = .security,
        .check_workflow = &checkWorkflowRunUntrustedCheckout,
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
        .id = "SEC011",
        .name = "overprovisioned-secrets",
        .description = "Entire secrets context should not be exposed; reference individual secrets instead",
        .severity = .warning,
        .category = .security,
        .check_step = &checkOverprovisionedSecrets,
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
        .id = "SEC015",
        .name = "artipacked",
        .description = "Checkout with persisted credentials followed by upload-artifact can leak GITHUB_TOKEN",
        .severity = .warning,
        .category = .security,
        .check_job = &checkArtipacked,
    },
    .{
        .id = "SEC018",
        .name = "checkout-persist-credentials",
        .description = "actions/checkout persists GITHUB_TOKEN in .git/config by default",
        .severity = .warning,
        .category = .security,
        .check_step = &checkCheckoutPersistCredentials,
    },
    .{
        .id = "SEC019",
        .name = "secrets-outside-env",
        .description = "Secrets should be bound to env: variables instead of used directly in run:/with:",
        .severity = .info,
        .category = .security,
        .check_step = &checkSecretsOutsideEnv,
    },
    .{
        .id = "SEC020",
        .name = "self-hosted-runner-fork-triggered",
        .description = "Self-hosted runners used with fork-accessible triggers allow untrusted code execution",
        .severity = .warning,
        .category = .security,
        .check_workflow = &checkSelfHostedRunnerForkTriggeredWorkflow,
    },
    .{
        .id = "SC002",
        .name = "compromised-action-sha",
        .description = "Action references a SHA or tag of a known-compromised release",
        .severity = .@"error",
        .category = .dependency,
        .check_step = &checkCompromisedAction,
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
        .id = "SEC017",
        .name = "insecure-commands",
        .description = "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables deprecated insecure workflow commands",
        .severity = .warning,
        .category = .security,
        .check_workflow = &checkInsecureCommandsWorkflow,
        .check_job = &checkInsecureCommandsJob,
        .check_step = &checkInsecureCommandsStep,
    },
    .{
        .id = "SC003",
        .name = "known-vulnerable-action",
        .description = "Action has known security advisories (CVE) in GitHub Advisory Database",
        .severity = .warning,
        .category = .dependency,
        .check_step = &advisory.checkKnownVulnerableAction,
    },
    .{
        .id = "SC004",
        .name = "archived-uses",
        .description = "Action references an archived (unmaintained) repository",
        .severity = .warning,
        .category = .dependency,
        .check_step = &archived.checkArchivedAction,
    },
    .{
        .id = "SC005",
        .name = "stale-action-refs",
        .description = "SHA-pinned action does not correspond to any known Git tag",
        .severity = .info,
        .category = .dependency,
        .check_step = &stale_refs.checkStaleActionRef,
    },
    .{
        .id = "SC006",
        .name = "ref-confusion",
        .description = "Action ref matches both a tag and branch, creating exploitable ambiguity",
        .severity = .warning,
        .category = .dependency,
        .check_step = &refconfusion.checkRefConfusion,
    },
    .{
        .id = "SC008",
        .name = "impostor-commit",
        .description = "SHA-pinned action ref is not reachable from any branch or tag of the upstream repo",
        .severity = .warning,
        .category = .dependency,
        .check_step = &impostor.checkImpostorCommit,
    },
    .{
        .id = "BP007",
        .name = "obfuscation",
        .description = "Obfuscated or indirect command execution patterns detected in run: block",
        .severity = .warning,
        .category = .security,
        .check_step = &checkObfuscatedExecution,
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

fn findDiagnostic(list: *const DiagnosticList, rule_id: []const u8) ?Diagnostic {
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, rule_id)) return d;
    }
    return null;
}

fn makeSec017EnvMeta(
    allocator: std.mem.Allocator,
    style: yaml.ScalarStyle,
    span: Span,
) !ScalarValueMetaMap {
    var meta = ScalarValueMetaMap.init(allocator);
    try meta.put("ACTIONS_ALLOW_UNSECURE_COMMANDS", .{
        .value_span = span,
        .style = style,
    });
    return meta;
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

/// Build a single-step workflow with `run: body` (plus optional step `env`) and
/// report whether SEC002 fires for it.
fn sec002Fires(body: []const u8, env: ?workflow_types.StringMap) bool {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = body, .env = env },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    return hasDiagnostic(&list, "SEC002");
}

test "SEC002: untrusted contexts in run block" {
    const bodies = [_][]const u8{
        "echo ${{ github.event.issue.title }}",
        "echo \"${{ github.event.pull_request.body }}\"",
        "git checkout ${{ github.head_ref }}",
        "echo ${{ github.event.head_commit.message }}",
        "echo \"${{ github.event.review_comment.body }}\"",
        "echo \"${{ github.event.discussion.title }}\"",
        "echo \"${{ github.event.discussion.body }}\"",
        "echo \"${{ github.event.discussion_comment.body }}\"",
        "git checkout \"${{ github.event.pull_request.head.ref }}\"",
        "echo \"${{ github.event.pull_request.head.label }}\"",
        "echo \"${{ github.event.pull_request.head.repo.default_branch }}\"",
    };
    for (bodies) |body| {
        try testing.expect(sec002Fires(body, null));
    }
}

test "SEC002: element access under a container context" {
    // `github.event.pages` is stored as a container prefix, so its element
    // accesses are caught without a dedicated entry.
    try testing.expect(sec002Fires("echo \"${{ join(github.event.pages.*.page_name, ' ') }}\"", null));
}

/// Build a single-step workflow whose step is `uses: <ref>` with one `with:`
/// entry (plus optional step `env`) and report whether SEC002 fires for it.
fn sec002UsesFires(uses: []const u8, with_key: []const u8, with_value: []const u8, env: ?workflow_types.StringMap) bool {
    const eng = engine.Engine.init(&security_rules);
    var with = workflow_types.StringMap.init(testing.allocator);
    defer with.deinit();
    with.put(with_key, with_value) catch unreachable;
    const steps = [_]Step{
        .{ .uses = ActionRef.parse(uses), .with = with, .env = env },
    };
    const jobs = [_]Job{
        .{ .id = "handle", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    return hasDiagnostic(&list, "SEC002");
}

test "SEC002: dangerous context in github-script script input" {
    const dangerous = "const title = \"${{ github.event.issue.title }}\";";
    // The action name and the input name both resolve case-insensitively.
    try testing.expect(sec002UsesFires("actions/github-script@v7", "script", dangerous, null));
    try testing.expect(sec002UsesFires("Actions/GitHub-Script@v7", "script", dangerous, null));
    try testing.expect(sec002UsesFires("actions/github-script@v7", "Script", dangerous, null));
}

test "SEC002: script input is not checked outside github-script" {
    const dangerous = "const title = \"${{ github.event.issue.title }}\";";
    // A nested path is a different action, as is an unrelated owner/repo.
    try testing.expect(!sec002UsesFires("actions/github-script/sub@v7", "script", dangerous, null));
    try testing.expect(!sec002UsesFires("some-org/other-action@v1", "script", dangerous, null));
    // Only inputs executed as code are checked.
    try testing.expect(!sec002UsesFires("actions/github-script@v7", "result-encoding", "${{ github.event.issue.title }}", null));
}

test "SEC002: github-script script input via env (no false positive)" {
    var env = workflow_types.StringMap.init(testing.allocator);
    defer env.deinit();
    env.put("TITLE", "${{ github.event.issue.title }}") catch unreachable;
    try testing.expect(!sec002UsesFires("actions/github-script@v7", "script", "const title = process.env.TITLE;", env));
}

test "SEC002: trusted contexts in run block (no false positive)" {
    const bodies = [_][]const u8{
        "echo ${{ github.sha }}",
        "echo hello world",
        "echo \"${{ github.event.pull_request.head.sha }}\"",
        "echo \"${{ github.event.pull_request.number }}\"",
        "echo \"${{ github.event.discussion.number }}\"",
    };
    for (bodies) |body| {
        try testing.expect(!sec002Fires(body, null));
    }
}

test "SEC002: untrusted input passed through env is not reported" {
    var env = workflow_types.StringMap.init(testing.allocator);
    defer env.deinit();
    try env.put("BRANCH", "${{ github.event.pull_request.head.ref }}");
    try testing.expect(!sec002Fires("echo \"Branch $BRANCH\"", env));
}

// --- SEC002: object filter (.*) references ---

fn expectSec002(run: []const u8, expected: bool) !void {
    try testing.expectEqual(expected, sec002Fires(run, null));
}

test "SEC002: object filter inside join()" {
    try expectSec002("echo \"${{ join(github.event.commits.*.message, ' ') }}\"", true);
}

test "SEC002: object filter inside toJSON()" {
    try expectSec002("echo \"${{ toJSON(github.event.commits.*.author.name) }}\"", true);
}

test "SEC002: object filter on pull_request labels" {
    try expectSec002("echo \"${{ github.event.pull_request.labels.*.name }}\"", true);
}

test "SEC002: index access is treated as a wildcard segment" {
    try expectSec002("echo \"${{ github.event.commits[0].message }}\"", true);
}

test "SEC002: object filter over a safe context (no false positive)" {
    try expectSec002("echo \"${{ join(github.event.pull_request.assignees.*.login, ' ') }}\"", false);
}

test "SEC002: dangerous path as a string literal (no false positive)" {
    try expectSec002("echo \"${{ format('github.event.issue.body') }}\"", false);
}

test "SEC002: dangerous name nested under another context (no false positive)" {
    try expectSec002("echo \"${{ steps.meta.outputs.github.head_ref }}\"", false);
}

test "SEC002: bare labels reference without a filter" {
    try expectSec002("echo \"${{ toJSON(github.event.pull_request.labels) }}\"", true);
}

test "SEC002: reference rooted after a function call" {
    try expectSec002("echo \"${{ fromJSON(steps.x.outputs.d).github.head_ref }}\"", true);
}

test "SEC002: context names are case-insensitive" {
    try expectSec002("echo \"${{ GitHub.Event.Issue.Body }}\"", true);
}

test "SEC008: run-only context is reported for GITHUB_ENV writes too" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo \"LABEL=${{ github.event.pull_request.labels.*.name }}\" >> $GITHUB_ENV" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC008"));
}

test "SEC002: labels filter in if: is not reported (SEC006 scope)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "make deploy", .if_condition = "contains(github.event.pull_request.labels.*.name, 'deploy')" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC006"));
}

test "SEC006: object filter over untrusted context in if:" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "make deploy", .if_condition = "contains(github.event.commits.*.message, 'skip')" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC006"));
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

test "SEC004: autofix replaces write-all with minimal permissions" {
    const fix_engine = @import("../fix/engine.zig");
    const source = "permissions: write-all\njobs:";
    // "write-all" starts at byte 13, ends at 22
    const value_span = Span{
        .start_line = 1,
        .start_col = 14,
        .end_line = 1,
        .end_col = 23,
        .start_byte = 13,
        .end_byte = 22,
    };
    const wf = Workflow{
        .name = "CI",
        .on = makeEmptyTrigger(),
        .jobs = &.{},
        .permissions = Permissions{ .write_all = true, .value_span = value_span },
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    checkExcessivePermissions(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(diag.fix != null);
    const fix = diag.fix.?;
    try testing.expectEqual(diagnostics.FixSafety.safe, fix.safety);

    const result = try fix_engine.applyFixes(testing.allocator, source, &.{fix});
    defer result.deinit(testing.allocator);
    try testing.expectEqualStrings("permissions: {contents: read}\njobs:", result.content);
}

test "SEC004: autofix at job level replaces write-all" {
    const fix_engine = @import("../fix/engine.zig");
    const source = "    permissions: write-all\n";
    const value_span = Span{
        .start_line = 1,
        .start_col = 18,
        .end_line = 1,
        .end_col = 27,
        .start_byte = 17,
        .end_byte = 26,
    };
    const jobs = [_]Job{
        .{ .id = "build", .permissions = Permissions{ .write_all = true, .value_span = value_span } },
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    checkExcessivePermissionsJob(&jobs[0], &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const fix = diags.get(0).fix.?;

    const result = try fix_engine.applyFixes(testing.allocator, source, &.{fix});
    defer result.deinit(testing.allocator);
    try testing.expectEqualStrings("    permissions: {contents: read}\n", result.content);
}

test "SEC004: no fix when value_span is null" {
    const wf = Workflow{
        .name = "CI",
        .on = makeEmptyTrigger(),
        .jobs = &.{},
        .permissions = Permissions{ .write_all = true },
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    checkExcessivePermissions(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(diags.get(0).fix == null);
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

// --- SEC009: workflow_run untrusted checkout ---

test "SEC009: workflow_run with checkout of workflow_run head_sha" {
    const eng = engine.Engine.init(&security_rules);
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("ref", "${{ github.event.workflow_run.head_sha }}") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeWorkflowRunTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC009"));
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC009")) {
            try testing.expect(d.severity == .@"error");
            try testing.expect(d.fix_hint != null);
            try testing.expect(d.fix_hint.?.len > 0);
        }
    }
}

test "SEC009: workflow_run with checkout of workflow_run head_branch" {
    const eng = engine.Engine.init(&security_rules);
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("ref", "${{ github.event.workflow_run.head_branch }}") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeWorkflowRunTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC009"));
}

test "SEC009: workflow_run without checkout (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo safe" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeWorkflowRunTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC009"));
}

test "SEC009: workflow_run checkout without ref (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeWorkflowRunTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC009"));
}

test "SEC009: non-workflow_run trigger with workflow_run ref (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("ref", "${{ github.event.workflow_run.head_sha }}") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePRTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC009"));
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

/// The severity SEC006 reports for a step-level `if:` condition, or null when
/// the rule stays quiet.
fn sec006Severity(cond: []const u8) ?Severity {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo test", .if_condition = cond },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC006")) return d.severity;
    }
    return null;
}

test "SEC006: ref-shaped contexts in conditions are not reported" {
    // Routing on a branch name is a mainstream idiom and the value never
    // reaches a shell from an `if:`, so SEC006 stays quiet (#138). The same
    // contexts are still injection vectors inside `run:` — see the SEC002 and
    // SEC008 tests above.
    try testing.expect(sec006Severity("github.head_ref == 'release'") == null);
    try testing.expect(sec006Severity("startsWith(github.event.pull_request.head.ref, 'release/')") == null);
    try testing.expect(sec006Severity("github.event.pull_request.head.label == 'octo:release'") == null);
    try testing.expect(sec006Severity("github.event.workflow_run.head_branch == 'main'") == null);
    // The immutable identity of the same commit stays trusted too.
    try testing.expect(sec006Severity("github.event.pull_request.head.sha == env.EXPECTED") == null);
}

test "SEC006: attacker-authored free text in conditions is a warning" {
    // These gate a decision on text the attacker writes, which is what SEC006
    // is about. It is a weak gate rather than code execution, so it warns
    // instead of failing the build.
    try testing.expectEqual(Severity.warning, sec006Severity("contains(github.event.issue.body, 'ship it')"));
    try testing.expectEqual(Severity.warning, sec006Severity("github.event.pull_request.title == 'release'"));
    try testing.expectEqual(Severity.warning, sec006Severity("contains(github.event.head_commit.message, '[deploy]')"));
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

test "SEC007: autofix generated on single-line on:" {
    const yaml_parser = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    var parser = yaml_parser.Parser.init(alloc, source);
    defer parser.deinit();
    const yaml_ast = try parser.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_ast);

    var list = DiagnosticList.init(alloc);
    checkMissingPermissions(&wf, &list);

    try testing.expectEqual(@as(usize, 1), list.len());
    const diag = list.get(0);
    const fix = diag.fix orelse return error.TestUnexpectedResult;
    try testing.expect(fix.safety == .unsafe);
    try testing.expectEqualStrings("insert top-level permissions: {contents: read}", fix.description);
    try testing.expectEqual(@as(usize, 1), fix.edits.len);
    try testing.expectEqualStrings("permissions: {contents: read}\n", fix.edits[0].replacement);
    try testing.expectEqual(fix.edits[0].start_byte, fix.edits[0].end_byte);
    // Insertion sits at the byte just after the `on: push\n` line.
    const on_line_end = (std.mem.indexOf(u8, source, "on: push\n") orelse unreachable) + "on: push\n".len;
    try testing.expectEqual(on_line_end, fix.edits[0].start_byte);
}

test "SEC007: autofix on multi-line on: block inserts after last child" {
    const yaml_parser = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: CI
        \\on:
        \\  push:
        \\  pull_request:
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    var parser = yaml_parser.Parser.init(alloc, source);
    defer parser.deinit();
    const yaml_ast = try parser.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_ast);

    var list = DiagnosticList.init(alloc);
    checkMissingPermissions(&wf, &list);

    const diag = list.get(0);
    const fix = diag.fix orelse return error.TestUnexpectedResult;
    // Insertion should land at the byte just after `pull_request:\n`,
    // i.e. immediately before `jobs:`.
    const jobs_pos = std.mem.indexOf(u8, source, "jobs:") orelse unreachable;
    try testing.expectEqual(jobs_pos, fix.edits[0].start_byte);
    try testing.expectEqualStrings("permissions: {contents: read}\n", fix.edits[0].replacement);
}

test "SEC007: no fix when permissions_insertion_byte missing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Hand-built Workflow without permissions_insertion_byte set.
    const jobs = [_]Job{.{ .id = "build" }};
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs };

    var list = DiagnosticList.init(alloc);
    checkMissingPermissions(&wf, &list);

    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expect(list.get(0).fix == null);
}

test "SEC007: no diagnostic when permissions already defined (parser path)" {
    const yaml_parser = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: CI
        \\on: push
        \\permissions: read-all
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    var parser = yaml_parser.Parser.init(alloc, source);
    defer parser.deinit();
    const yaml_ast = try parser.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_ast);

    var list = DiagnosticList.init(alloc);
    checkMissingPermissions(&wf, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SEC007: applyFixes inserts permissions block between on: and jobs:" {
    const yaml_parser = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");
    const fix_engine = @import("../fix/engine.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    var parser = yaml_parser.Parser.init(alloc, source);
    defer parser.deinit();
    const yaml_ast = try parser.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_ast);

    var list = DiagnosticList.init(alloc);
    checkMissingPermissions(&wf, &list);
    const fix = list.get(0).fix orelse return error.TestUnexpectedResult;

    const result = try fix_engine.applyFixes(testing.allocator, source, &.{fix});
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), result.edits_applied);
    const perm_pos = std.mem.indexOf(u8, result.content, "permissions: {contents: read}") orelse return error.TestUnexpectedResult;
    const on_pos = std.mem.indexOf(u8, result.content, "on: push") orelse unreachable;
    const jobs_pos = std.mem.indexOf(u8, result.content, "jobs:") orelse unreachable;
    try testing.expect(on_pos < perm_pos);
    try testing.expect(perm_pos < jobs_pos);
}

test "SEC007 + BP005: same-byte insertions produce parseable YAML (golden)" {
    // SEC007 と BP005 はいずれも `on:` 行末の同一 byte を anchor にしたゼロ幅挿入を発行する
    // (src/workflow/parser.zig:59-60)。fix/engine.zig:flattenAndSort の tie-break は
    // (start_byte, end_byte) 昇順 → reverse なので、両 edit が隣接挿入されても
    // 構文上 valid な YAML になる。このテストは順序と再 parse 可能性をピン止めする。
    const yaml_parser = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");
    const fix_engine = @import("../fix/engine.zig");
    const best_practices = @import("best_practices.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    var parser = yaml_parser.Parser.init(alloc, source);
    defer parser.deinit();
    const yaml_ast = try parser.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_ast);

    var list = DiagnosticList.init(alloc);
    checkMissingPermissions(&wf, &list);
    best_practices.checkPushConcurrencyForTest(&wf, &list);

    try testing.expectEqual(@as(usize, 2), list.len());

    const fixes = try fix_engine.collectFixes(testing.allocator, list.items.items, true);
    defer testing.allocator.free(fixes);
    try testing.expectEqual(@as(usize, 2), fixes.len);

    const result = try fix_engine.applyFixes(testing.allocator, source, fixes);
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 2), result.edits_applied);

    // fix/engine.zig のソート安定性に依存する順序をピン止め。
    // SEC007 (permissions, 1 行) が先、BP005 (concurrency, 3 行) が後に並ぶ。
    try testing.expectEqualStrings(
        \\name: CI
        \\on: push
        \\permissions: {contents: read}
        \\concurrency:
        \\  group: ${{ github.workflow }}-${{ github.ref }}
        \\  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ,
        result.content,
    );

    // 再 parse で ParseError が出ないことを確認する。
    var reparse = yaml_parser.Parser.init(alloc, result.content);
    defer reparse.deinit();
    _ = try reparse.parse();
}

// --- SEC008: github-env injection ---

test "SEC008: dangerous context written to GITHUB_ENV" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo \"VAR=${{ github.event.issue.title }}\" >> $GITHUB_ENV" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC008"));
}

test "SEC008: dangerous context written to GITHUB_PATH" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo \"${{ github.head_ref }}\" >> $GITHUB_PATH" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC008"));
}

test "SEC008: quoted GITHUB_ENV target" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo \"X=${{ github.event.comment.body }}\" >> \"$GITHUB_ENV\"" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC008"));
}

test "SEC008: braced GITHUB_ENV target" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo \"X=${{ github.event.pull_request.title }}\" >> ${GITHUB_ENV}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC008"));
}

test "SEC008: safe value to GITHUB_ENV (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo \"VAR=safe\" >> $GITHUB_ENV" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC008"));
}

test "SEC008: dangerous context without env write (no false positive)" {
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
    try testing.expect(!hasDiagnostic(&list, "SEC008"));
}

test "SEC008: no run block (no false positive)" {
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
    try testing.expect(!hasDiagnostic(&list, "SEC008"));
}

test "SEC008: safe context to GITHUB_ENV (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo \"SHA=${{ github.sha }}\" >> $GITHUB_ENV" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC008"));
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

test "containsConditionDangerousContext recognizes issue title" {
    try testing.expect(containsConditionDangerousContext("github.event.issue.title"));
}

test "containsConditionDangerousContext recognizes PR body" {
    try testing.expect(containsConditionDangerousContext("github.event.pull_request.body"));
}

test "containsConditionDangerousContext rejects safe ref" {
    try testing.expect(!containsConditionDangerousContext("github.sha"));
}

test "containsConditionDangerousContext rejects safe actor" {
    try testing.expect(!containsConditionDangerousContext("github.actor"));
}

test "hardcoded secret prefixes are located by offset" {
    try testing.expect(std.mem.indexOf(u8, "token ghp_abc123def456", "ghp_") != null);
}

test "hardcoded secret prefixes match at offset zero" {
    try testing.expect(std.mem.indexOf(u8, "AKIAIOSFODNN7EXAMPLE", "AKIA") != null);
}

test "hardcoded secret prefixes do not match unrelated text" {
    try testing.expect(std.mem.indexOf(u8, "echo hello world", "ghp_") == null);
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
    var checkout_with = workflow_types.StringMap.init(testing.allocator);
    checkout_with.put("persist-credentials", "false") catch unreachable;
    defer checkout_with.deinit();
    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29"),
            .with = checkout_with,
        },
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

// ============================================================
// SEC011 tests
// ============================================================

test "SEC011: bare secrets in run block" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo ${{ secrets }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: bare secrets with extra whitespace" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo ${{  secrets  }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: toJSON(secrets) in run block" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo ${{ toJSON(secrets) }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: tojson(secrets) lowercase" {
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
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: fromJSON(secrets) in run block" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo ${{ fromJSON(secrets) }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: bare secrets in with value" {
    const eng = engine.Engine.init(&security_rules);
    var with_map = workflow_types.StringMap.init(testing.allocator);
    defer with_map.deinit();
    with_map.put("data", "${{ secrets }}") catch unreachable;
    const steps = [_]Step{
        .{ .with = with_map },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: bare secrets in env value" {
    const eng = engine.Engine.init(&security_rules);
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("ALL_SECRETS", "${{ secrets }}") catch unreachable;
    const steps = [_]Step{
        .{ .env = env_map },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: toJSON with whitespace in parens" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo ${{ toJSON( secrets ) }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: individual secret is allowed" {
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
    try testing.expect(!hasDiagnostic(&list, "SEC011"));
}

test "SEC011: toJSON(secrets.TOKEN) is allowed" {
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
    try testing.expect(!hasDiagnostic(&list, "SEC011"));
}

test "SEC011: toJSON(github) is allowed" {
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
    try testing.expect(!hasDiagnostic(&list, "SEC011"));
}

test "SEC011: no expression is allowed" {
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
    try testing.expect(!hasDiagnostic(&list, "SEC011"));
}

test "SEC011: one diagnostic per step" {
    const eng = engine.Engine.init(&security_rules);
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("ALL", "${{ toJSON(secrets) }}") catch unreachable;
    const steps = [_]Step{
        .{ .run = "echo ${{ secrets }}", .env = env_map },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 1), countDiagnostics(&list, "SEC011"));
}

test "exprIsWholeSecretsRef: bare secrets" {
    try testing.expect(exprIsWholeSecretsRef("secrets"));
}

test "exprIsWholeSecretsRef: secrets with dot" {
    try testing.expect(!exprIsWholeSecretsRef("secrets.TOKEN"));
}

test "exprIsWholeSecretsRef: toJSON(secrets)" {
    try testing.expect(exprIsWholeSecretsRef("toJSON(secrets)"));
}

test "exprIsWholeSecretsRef: toJSON(secrets.X)" {
    try testing.expect(!exprIsWholeSecretsRef("toJSON(secrets.X)"));
}

test "exprIsWholeSecretsRef: empty string" {
    try testing.expect(!exprIsWholeSecretsRef(""));
}

// ============================================================
// SEC015 tests - Artipacked
// ============================================================

test "SEC015: checkout + upload-artifact triggers rule" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC015"));
}

test "SEC015: checkout with other with: keys (no persist-credentials) + upload-artifact" {
    const eng = engine.Engine.init(&security_rules);
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("fetch-depth", "0") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC015"));
}

test "SEC015: persist-credentials: true is vulnerable" {
    const eng = engine.Engine.init(&security_rules);
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("persist-credentials", "true") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC015"));
}

test "SEC015: SHA-pinned versions still detected" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29") },
        .{ .uses = ActionRef.parse("actions/upload-artifact@65462800fd760344b1a7b4382951275a0abb4808") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC015"));
}

test "SEC015: multiple checkout steps emit one diagnostic per checkout" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
        .{ .run = "make build" },
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 2), countDiagnostics(&list, "SEC015"));
}

test "SEC015: checkout + persist-credentials: false (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("persist-credentials", "false") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC015"));
}

test "SEC015: checkout only without upload-artifact (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
        .{ .run = "make test" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC015"));
}

test "SEC015: upload-artifact only without checkout (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "make build" },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC015"));
}

test "SEC015: checkout and upload in different jobs (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    const steps1 = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
    };
    const steps2 = [_]Step{
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps1, .permissions = Permissions{} },
        .{ .id = "upload", .steps = &steps2, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC015"));
}

test "SEC015: upload before checkout does not trigger" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC015"));
}

test "SEC015: only checkout before upload triggers in mixed ordering" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/checkout@v4"),
            .uses_key_col = 8,
            .uses_value_end_byte = 50,
        },
        .{ .run = "make build" },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
        .{
            .uses = ActionRef.parse("actions/checkout@v4"),
            .uses_key_col = 8,
            .uses_value_end_byte = 120,
        },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), countDiagnostics(&list, "SEC015"));

    var fix_count: usize = 0;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC015")) {
            try testing.expect(d.fix != null);
            try testing.expectEqual(@as(usize, 50), d.fix.?.edits[0].start_byte);
            fix_count += 1;
        }
    }
    try testing.expectEqual(@as(usize, 1), fix_count);
}

test "SEC015: fix is safe and attached when span info present" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/checkout@v4"),
            .uses_key_col = 8,
            .uses_value_end_byte = 50,
        },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    // Find the SEC015 diagnostic and verify fix
    var found_fix = false;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC015")) {
            try testing.expect(d.fix != null);
            const fix = d.fix.?;
            try testing.expect(fix.safety == .safe);
            try testing.expect(fix.edits.len == 1);
            try testing.expectEqual(@as(usize, 50), fix.edits[0].start_byte);
            try testing.expectEqual(@as(usize, 50), fix.edits[0].end_byte);
            // Verify replacement contains with: and persist-credentials: false
            try testing.expect(std.mem.indexOf(u8, fix.edits[0].replacement, "with:") != null);
            try testing.expect(std.mem.indexOf(u8, fix.edits[0].replacement, "persist-credentials: false") != null);
            found_fix = true;
            break;
        }
    }
    try testing.expect(found_fix);
}

test "SEC015: fix inserts into existing with: block" {
    const eng = engine.Engine.init(&security_rules);
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("fetch-depth", "0") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/checkout@v4"),
            .with = with,
            .uses_key_col = 8,
            .uses_value_end_byte = 50,
            .with_last_entry_end_byte = 80,
        },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC015")) {
            try testing.expect(d.fix != null);
            const fix = d.fix.?;
            try testing.expectEqual(@as(usize, 80), fix.edits[0].start_byte);
            // Should NOT contain "with:" since with already exists
            try testing.expect(std.mem.indexOf(u8, fix.edits[0].replacement, "with:") == null);
            try testing.expect(std.mem.indexOf(u8, fix.edits[0].replacement, "persist-credentials: false") != null);
            break;
        }
    }
}

test "SEC015: persist-credentials: true has no fix (only fix_hint)" {
    const eng = engine.Engine.init(&security_rules);
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("persist-credentials", "true") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/checkout@v4"),
            .with = with,
            .uses_key_col = 8,
            .uses_value_end_byte = 50,
            .with_last_entry_end_byte = 80,
        },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC015")) {
            try testing.expect(d.fix == null);
            try testing.expect(d.fix_hint != null);
            break;
        }
    }
}

test "SEC015: no fix when span info absent (manually constructed step)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC015")) {
            try testing.expect(d.fix == null);
            try testing.expect(d.fix_hint != null);
            break;
        }
    }
}

test "SEC015: isUploadArtifactAction helper" {
    try testing.expect(isUploadArtifactAction(ActionRef.parse("actions/upload-artifact@v4")));
    try testing.expect(isUploadArtifactAction(ActionRef.parse("actions/upload-artifact@65462800fd760344b1a7b4382951275a0abb4808")));
    try testing.expect(!isUploadArtifactAction(ActionRef.parse("actions/checkout@v4")));
    try testing.expect(!isUploadArtifactAction(ActionRef.parse("actions/download-artifact@v4")));
    try testing.expect(!isUploadArtifactAction(ActionRef.parse("./actions/upload-artifact")));
}

test "SEC015: hasPersistCredentialsFalse helper" {
    // No with: map
    const step_no_with = Step{};
    try testing.expect(!hasPersistCredentialsFalse(&step_no_with));

    // with: map without persist-credentials
    var with1 = workflow_types.StringMap.init(testing.allocator);
    with1.put("fetch-depth", "0") catch unreachable;
    defer with1.deinit();
    const step_no_pc = Step{ .with = with1 };
    try testing.expect(!hasPersistCredentialsFalse(&step_no_pc));

    // persist-credentials: false
    var with2 = workflow_types.StringMap.init(testing.allocator);
    with2.put("persist-credentials", "false") catch unreachable;
    defer with2.deinit();
    const step_false = Step{ .with = with2 };
    try testing.expect(hasPersistCredentialsFalse(&step_false));

    // persist-credentials: true
    var with3 = workflow_types.StringMap.init(testing.allocator);
    with3.put("persist-credentials", "true") catch unreachable;
    defer with3.deinit();
    const step_true = Step{ .with = with3 };
    try testing.expect(!hasPersistCredentialsFalse(&step_true));
}

test "SEC015: integration - YAML parse to fix apply" {
    const yaml_parser = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");
    const fix_engine = @import("../fix/engine.zig");

    // Use arena for parser allocations (jobs, steps, etc.)
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\      - run: make build
        \\      - uses: actions/upload-artifact@v4
        \\        with:
        \\          name: dist
        \\          path: ./dist
    ;

    var parser = yaml_parser.Parser.init(alloc, source);
    defer parser.deinit();
    const yaml_ast = try parser.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_ast);

    const eng = engine.Engine.init(&security_rules);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    // Should detect SEC015
    try testing.expect(hasDiagnostic(&list, "SEC015"));

    // Should have a fix attached
    var fix_found = false;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC015")) {
            try testing.expect(d.fix != null);
            const fix = d.fix.?;
            try testing.expect(fix.safety == .safe);
            try testing.expect(fix.edits.len == 1);

            // Apply the fix
            const fixes = [_]diagnostics.Fix{fix};
            const result = try fix_engine.applyFixes(testing.allocator, source, &fixes);
            defer result.deinit(testing.allocator);

            // Verify the output contains persist-credentials: false
            try testing.expect(std.mem.indexOf(u8, result.content, "persist-credentials: false") != null);
            // Verify with: was inserted
            try testing.expect(std.mem.indexOf(u8, result.content, "with:\n") != null);
            try testing.expectEqual(@as(usize, 1), result.edits_applied);

            fix_found = true;
            break;
        }
    }
    try testing.expect(fix_found);
}

test "SEC015: integration ignores checkout after upload-artifact" {
    const yaml_parser = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/upload-artifact@v4
        \\        with:
        \\          name: dist
        \\          path: ./dist
        \\      - uses: actions/checkout@v4
    ;

    var parser = yaml_parser.Parser.init(alloc, source);
    defer parser.deinit();
    const yaml_ast = try parser.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_ast);

    const eng = engine.Engine.init(&security_rules);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SEC015"));
}

// --- SEC018: checkout-persist-credentials ---

test "SEC018: with == null triggers with unsafe fix" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/checkout@v4"),
            .uses_key_col = 8,
            .uses_value_end_byte = 50,
        },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SEC018"));
    const diag = findDiagnostic(&list, "SEC018").?;
    try testing.expect(diag.fix != null);
    try testing.expect(diag.fix.?.safety == .unsafe);
}

test "SEC018: with exists without persist-credentials triggers with fix" {
    const eng = engine.Engine.init(&security_rules);
    var with_map = workflow_types.StringMap.init(testing.allocator);
    with_map.put("fetch-depth", "0") catch unreachable;
    defer with_map.deinit();
    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/checkout@v4"),
            .with = with_map,
            .uses_key_col = 8,
            .uses_value_end_byte = 50,
            .with_last_entry_end_byte = 80,
        },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SEC018"));
    const diag = findDiagnostic(&list, "SEC018").?;
    try testing.expect(diag.fix != null);
    try testing.expect(diag.fix.?.safety == .unsafe);
}

test "SEC018: persist-credentials: true triggers without fix" {
    const eng = engine.Engine.init(&security_rules);
    var with_map = workflow_types.StringMap.init(testing.allocator);
    with_map.put("persist-credentials", "true") catch unreachable;
    defer with_map.deinit();
    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/checkout@v4"),
            .with = with_map,
            .uses_key_col = 8,
            .uses_value_end_byte = 50,
            .with_last_entry_end_byte = 80,
        },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SEC018"));
    const diag = findDiagnostic(&list, "SEC018").?;
    try testing.expect(diag.fix == null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "explicitly set to true") != null);
}

test "SEC018: persist-credentials: false does not trigger" {
    const eng = engine.Engine.init(&security_rules);
    var with_map = workflow_types.StringMap.init(testing.allocator);
    with_map.put("persist-credentials", "false") catch unreachable;
    defer with_map.deinit();
    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/checkout@v4"),
            .with = with_map,
            .uses_key_col = 8,
            .uses_value_end_byte = 50,
            .with_last_entry_end_byte = 80,
        },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SEC018"));
}

test "SEC018: autofix replacement contains with: block when with == null" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/checkout@v4"),
            .uses_key_col = 6,
            .uses_value_end_byte = 50,
        },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    const diag = findDiagnostic(&list, "SEC018").?;
    const fix = diag.fix.?;
    try testing.expectEqual(@as(usize, 1), fix.edits.len);
    try testing.expectEqual(@as(usize, 50), fix.edits[0].start_byte);
    try testing.expectEqual(@as(usize, 50), fix.edits[0].end_byte);
    try testing.expect(std.mem.indexOf(u8, fix.edits[0].replacement, "with:") != null);
    try testing.expect(std.mem.indexOf(u8, fix.edits[0].replacement, "persist-credentials: false") != null);
}

test "SEC018: autofix appends entry when with already exists" {
    const eng = engine.Engine.init(&security_rules);
    var with_map = workflow_types.StringMap.init(testing.allocator);
    with_map.put("fetch-depth", "0") catch unreachable;
    defer with_map.deinit();
    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/checkout@v4"),
            .with = with_map,
            .uses_key_col = 6,
            .uses_value_end_byte = 50,
            .with_last_entry_end_byte = 80,
        },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    const diag = findDiagnostic(&list, "SEC018").?;
    const fix = diag.fix.?;
    try testing.expectEqual(@as(usize, 80), fix.edits[0].start_byte);
    try testing.expect(std.mem.indexOf(u8, fix.edits[0].replacement, "with:") == null);
    try testing.expect(std.mem.indexOf(u8, fix.edits[0].replacement, "persist-credentials: false") != null);
}

test "SEC018: YAML-boolean capitalization variants are classified correctly" {
    const eng = engine.Engine.init(&security_rules);

    var with_false_caps = workflow_types.StringMap.init(testing.allocator);
    with_false_caps.put("persist-credentials", "False") catch unreachable;
    defer with_false_caps.deinit();
    const steps_false = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with_false_caps },
    };
    const jobs_false = [_]Job{.{ .id = "build", .steps = &steps_false, .permissions = Permissions{} }};
    const wf_false = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs_false, .permissions = Permissions{} };
    var list_false = eng.run(testing.allocator, &wf_false);
    defer list_false.deinit();
    try testing.expect(!hasDiagnostic(&list_false, "SEC018"));

    var with_true_caps = workflow_types.StringMap.init(testing.allocator);
    with_true_caps.put("persist-credentials", "TRUE") catch unreachable;
    defer with_true_caps.deinit();
    const steps_true = [_]Step{
        .{
            .uses = ActionRef.parse("actions/checkout@v4"),
            .with = with_true_caps,
            .uses_key_col = 8,
            .uses_value_end_byte = 50,
            .with_last_entry_end_byte = 80,
        },
    };
    const jobs_true = [_]Job{.{ .id = "build", .steps = &steps_true, .permissions = Permissions{} }};
    const wf_true = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs_true, .permissions = Permissions{} };
    var list_true = eng.run(testing.allocator, &wf_true);
    defer list_true.deinit();
    try testing.expect(hasDiagnostic(&list_true, "SEC018"));
    const diag = findDiagnostic(&list_true, "SEC018").?;
    try testing.expect(diag.fix == null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "explicitly set to true") != null);
}

test "SEC018: non-checkout action does not trigger" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/setup-node@v4"),
            .uses_key_col = 8,
            .uses_value_end_byte = 50,
        },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SEC018"));
}

test "SEC018: both SEC015 and SEC018 fire for same checkout + upload-artifact" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/checkout@v4"),
            .uses_key_col = 8,
            .uses_value_end_byte = 50,
        },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SEC015"));
    try testing.expect(hasDiagnostic(&list, "SEC018"));
    const sec015 = findDiagnostic(&list, "SEC015").?;
    const sec018 = findDiagnostic(&list, "SEC018").?;
    try testing.expect(sec015.fix.?.safety == .safe);
    try testing.expect(sec018.fix.?.safety == .unsafe);
}

// --- SEC019: Secrets outside env ---

test "SEC019: secret in run block" {
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
    try testing.expect(hasDiagnostic(&list, "SEC019"));
}

test "SEC019: secret in with value" {
    const eng = engine.Engine.init(&security_rules);
    var with_map = workflow_types.StringMap.init(testing.allocator);
    defer with_map.deinit();
    with_map.put("token", "${{ secrets.DEPLOY_KEY }}") catch unreachable;
    const steps = [_]Step{
        .{ .with = with_map },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC019"));
}

test "SEC019: secret in env value is allowed" {
    const eng = engine.Engine.init(&security_rules);
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("MY_TOKEN", "${{ secrets.MY_TOKEN }}") catch unreachable;
    const steps = [_]Step{
        .{ .env = env_map },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC019"));
}

test "SEC019: GITHUB_TOKEN in with is allowed" {
    const eng = engine.Engine.init(&security_rules);
    var with_map = workflow_types.StringMap.init(testing.allocator);
    defer with_map.deinit();
    with_map.put("token", "${{ secrets.GITHUB_TOKEN }}") catch unreachable;
    const steps = [_]Step{
        .{ .with = with_map },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC019"));
}

test "SEC019: GITHUB_TOKEN in run is allowed" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo ${{ secrets.GITHUB_TOKEN }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC019"));
}

test "SEC019: no secrets usage" {
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
    try testing.expect(!hasDiagnostic(&list, "SEC019"));
}

test "SEC019: secret with whitespace in expression" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo ${{  secrets.MY_TOKEN  }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC019"));
}

test "SEC019: one diagnostic per step" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "${{ secrets.A }} ${{ secrets.B }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 1), countDiagnostics(&list, "SEC019"));
}

// --- SEC017: Insecure commands ---

test "SEC017: ACTIONS_ALLOW_UNSECURE_COMMANDS in step env" {
    const eng = engine.Engine.init(&security_rules);
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("ACTIONS_ALLOW_UNSECURE_COMMANDS", "true") catch unreachable;
    var env_meta = try makeSec017EnvMeta(testing.allocator, .plain, Span{
        .start_line = 1,
        .start_col = 1,
        .end_line = 1,
        .end_col = 5,
        .start_byte = 10,
        .end_byte = 14,
    });
    defer env_meta.deinit();
    const steps = [_]Step{
        .{ .run = "echo test", .env = env_map, .env_meta = env_meta },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    try testing.expect(diag.fix != null);
    try testing.expectEqualStrings("set ACTIONS_ALLOW_UNSECURE_COMMANDS to false", diag.fix.?.description);
    try testing.expectEqual(diagnostics.FixSafety.safe, diag.fix.?.safety);
    try testing.expectEqual(@as(usize, 1), diag.fix.?.edits.len);
    try testing.expectEqual(@as(usize, 10), diag.fix.?.edits[0].start_byte);
    try testing.expectEqual(@as(usize, 14), diag.fix.?.edits[0].end_byte);
    try testing.expectEqualStrings("false", diag.fix.?.edits[0].replacement);
}

test "SEC017: ACTIONS_ALLOW_UNSECURE_COMMANDS in job env" {
    const eng = engine.Engine.init(&security_rules);
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("ACTIONS_ALLOW_UNSECURE_COMMANDS", "true") catch unreachable;
    var env_meta = try makeSec017EnvMeta(testing.allocator, .plain, Span{
        .start_line = 1,
        .start_col = 1,
        .end_line = 1,
        .end_col = 5,
        .start_byte = 20,
        .end_byte = 24,
    });
    defer env_meta.deinit();
    const jobs = [_]Job{
        .{ .id = "build", .env = env_map, .env_meta = env_meta, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    try testing.expect(diag.fix != null);
    try testing.expectEqualStrings("false", diag.fix.?.edits[0].replacement);
    try testing.expectEqual(@as(usize, 20), diag.fix.?.edits[0].start_byte);
}

test "SEC017: ACTIONS_ALLOW_UNSECURE_COMMANDS in workflow env" {
    const eng = engine.Engine.init(&security_rules);
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("ACTIONS_ALLOW_UNSECURE_COMMANDS", "true") catch unreachable;
    var env_meta = try makeSec017EnvMeta(testing.allocator, .plain, Span{
        .start_line = 1,
        .start_col = 1,
        .end_line = 1,
        .end_col = 5,
        .start_byte = 30,
        .end_byte = 34,
    });
    defer env_meta.deinit();
    const wf = Workflow{
        .name = "CI",
        .on = makeEmptyTrigger(),
        .jobs = &.{},
        .permissions = Permissions{},
        .env = env_map,
        .env_meta = env_meta,
    };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    try testing.expect(diag.fix != null);
    try testing.expectEqualStrings("false", diag.fix.?.edits[0].replacement);
    try testing.expectEqual(@as(usize, 30), diag.fix.?.edits[0].start_byte);
}

test "SEC017: fallback without env metadata keeps diagnostic" {
    const eng = engine.Engine.init(&security_rules);
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("ACTIONS_ALLOW_UNSECURE_COMMANDS", "true") catch unreachable;
    const steps = [_]Step{
        .{ .run = "echo test", .env = env_map },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    try testing.expect(diag.fix == null);
    try testing.expect(diag.fix_hint != null);
}

test "SEC017: fix preserves single quoted style" {
    const eng = engine.Engine.init(&security_rules);
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("ACTIONS_ALLOW_UNSECURE_COMMANDS", "true") catch unreachable;
    var env_meta = try makeSec017EnvMeta(testing.allocator, .single_quoted, Span{
        .start_line = 1,
        .start_col = 1,
        .end_line = 1,
        .end_col = 7,
        .start_byte = 40,
        .end_byte = 46,
    });
    defer env_meta.deinit();
    const steps = [_]Step{
        .{ .run = "echo test", .env = env_map, .env_meta = env_meta },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    try testing.expect(diag.fix != null);
    try testing.expectEqualStrings("false", diag.fix.?.edits[0].replacement);
    try testing.expectEqual(@as(usize, 41), diag.fix.?.edits[0].start_byte);
    try testing.expectEqual(@as(usize, 45), diag.fix.?.edits[0].end_byte);
}

test "SEC017: fix preserves double quoted style" {
    const eng = engine.Engine.init(&security_rules);
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("ACTIONS_ALLOW_UNSECURE_COMMANDS", "true") catch unreachable;
    var env_meta = try makeSec017EnvMeta(testing.allocator, .double_quoted, Span{
        .start_line = 1,
        .start_col = 1,
        .end_line = 1,
        .end_col = 7,
        .start_byte = 50,
        .end_byte = 56,
    });
    defer env_meta.deinit();
    const steps = [_]Step{
        .{ .run = "echo test", .env = env_map, .env_meta = env_meta },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    try testing.expect(diag.fix != null);
    try testing.expectEqualStrings("false", diag.fix.?.edits[0].replacement);
    try testing.expectEqual(@as(usize, 51), diag.fix.?.edits[0].start_byte);
    try testing.expectEqual(@as(usize, 55), diag.fix.?.edits[0].end_byte);
}

test "SEC017: literal style gets diagnostic without fix" {
    const eng = engine.Engine.init(&security_rules);
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("ACTIONS_ALLOW_UNSECURE_COMMANDS", "true") catch unreachable;
    var env_meta = try makeSec017EnvMeta(testing.allocator, .literal, Span{
        .start_line = 1,
        .start_col = 1,
        .end_line = 2,
        .end_col = 1,
        .start_byte = 60,
        .end_byte = 70,
    });
    defer env_meta.deinit();
    const steps = [_]Step{
        .{ .run = "echo test", .env = env_map, .env_meta = env_meta },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    try testing.expect(diag.fix == null);
    try testing.expectEqual(@as(usize, 60), diag.span.start_byte);
}

test "SEC017: value is false (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("ACTIONS_ALLOW_UNSECURE_COMMANDS", "false") catch unreachable;
    const steps = [_]Step{
        .{ .run = "echo test", .env = env_map },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC017"));
}

test "SEC017: key absent (no false positive)" {
    const eng = engine.Engine.init(&security_rules);
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("SOME_OTHER_VAR", "true") catch unreachable;
    const steps = [_]Step{
        .{ .run = "echo test", .env = env_map },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC017"));
}

test "SEC017: no env (no false positive)" {
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
    try testing.expect(!hasDiagnostic(&list, "SEC017"));
}

test "SEC017: integration applies fix to workflow env" {
    const yaml_parser = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");
    const fix_engine = @import("../fix/engine.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: CI
        \\on: push
        \\env:
        \\  ACTIONS_ALLOW_UNSECURE_COMMANDS: true
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo test
    ;

    var parser = yaml_parser.Parser.init(alloc, source);
    defer parser.deinit();
    const yaml_ast = try parser.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_ast);

    const eng = engine.Engine.init(&security_rules);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    const fix = diag.fix orelse return error.TestUnexpectedResult;
    const result = try fix_engine.applyFixes(testing.allocator, source, &.{fix});
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), result.edits_applied);
    try testing.expect(std.mem.indexOf(u8, result.content, "ACTIONS_ALLOW_UNSECURE_COMMANDS: false") != null);
}

test "SEC017: integration applies fix to job env and preserves single quote/comment" {
    const yaml_parser = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");
    const fix_engine = @import("../fix/engine.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    env:
        \\      ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true' # deprecated
        \\    steps:
        \\      - run: echo test
    ;

    var parser = yaml_parser.Parser.init(alloc, source);
    defer parser.deinit();
    const yaml_ast = try parser.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_ast);

    const eng = engine.Engine.init(&security_rules);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    const fix = diag.fix orelse return error.TestUnexpectedResult;
    const result = try fix_engine.applyFixes(testing.allocator, source, &.{fix});
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), result.edits_applied);
    try testing.expect(std.mem.indexOf(u8, result.content, "ACTIONS_ALLOW_UNSECURE_COMMANDS: 'false' # deprecated") != null);
}

test "SEC017: integration applies fix to step env and preserves double quote/comment" {
    const yaml_parser = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");
    const fix_engine = @import("../fix/engine.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo test
        \\        env:
        \\          ACTIONS_ALLOW_UNSECURE_COMMANDS: "true" # deprecated
    ;

    var parser = yaml_parser.Parser.init(alloc, source);
    defer parser.deinit();
    const yaml_ast = try parser.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_ast);

    const eng = engine.Engine.init(&security_rules);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    const fix = diag.fix orelse return error.TestUnexpectedResult;
    const result = try fix_engine.applyFixes(testing.allocator, source, &.{fix});
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), result.edits_applied);
    try testing.expect(std.mem.indexOf(u8, result.content, "ACTIONS_ALLOW_UNSECURE_COMMANDS: \"false\" # deprecated") != null);
}

// ============================================================
// BP007 tests
// ============================================================

test "BP007: base64 -d piped to bash" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo payload | base64 -d | bash" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: base64 --decode piped to sh" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "base64 --decode secret.txt | sh" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: eval with variable expansion" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "eval $CMD" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: eval with quoted variable" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "eval \"$SCRIPT\"" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: eval with braced variable" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "eval ${COMMAND}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: curl piped to bash" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "curl -s https://example.com/install.sh | bash" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: wget piped to sh" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "wget -qO- https://example.com/setup.sh | sh" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: variable as command at line start" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "export CMD=\"malicious\"\n$CMD" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on normal command" {
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
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on base64 decode to file" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "base64 -d file.txt > output.bin" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on eval with literal string" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "eval \"echo hello\"" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on curl saving to file" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "curl -o script.sh https://example.com/script.sh" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on wget download" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "wget https://example.com/file.tar.gz" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on echo with variable" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "echo $VARIABLE" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on npm install" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "npm install" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on GitHub Actions expression" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .run = "${{ github.token }}" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

// --- SEC020: Self-hosted runner on fork-accessible trigger ---

fn makePRTrigger() Trigger {
    const events = &[_]EventConfig{
        .{ .event = .pull_request, .name = "pull_request" },
    };
    return .{ .events = events };
}

fn makeIssueCommentTrigger() Trigger {
    const events = &[_]EventConfig{
        .{ .event = .issue_comment, .name = "issue_comment" },
    };
    return .{ .events = events };
}

fn makeWorkflowRunTrigger() Trigger {
    const events = &[_]EventConfig{
        .{ .event = .workflow_run, .name = "workflow_run" },
    };
    return .{ .events = events };
}

fn makePushTrigger() Trigger {
    const events = &[_]EventConfig{
        .{ .event = .push, .name = "push" },
    };
    return .{ .events = events };
}

fn makeWorkflowDispatchTrigger() Trigger {
    const events = &[_]EventConfig{
        .{ .event = .workflow_dispatch, .name = "workflow_dispatch" },
    };
    return .{ .events = events };
}

test "SEC020: self-hosted + pull_request + public -> fires" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePRTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC020"));
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC020")) {
            try testing.expect(d.severity == .warning);
            try testing.expect(d.fix_hint != null and d.fix_hint.?.len > 0);
        }
    }
}

test "SEC020: scalar runs_on with self-hosted prefix -> fires" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .runs_on = "self-hosted-gpu", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePRTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC020"));
}

test "SEC020: self-hosted + pull_request_target -> fires" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePRTargetTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC020"));
}

test "SEC020: self-hosted + issue_comment -> fires" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeIssueCommentTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC020"));
}

test "SEC020: self-hosted + workflow_run -> fires" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeWorkflowRunTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC020"));
}

test "SEC020: multiple jobs, only self-hosted ones fire" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "hosted", .runs_on = "ubuntu-latest", .permissions = Permissions{} },
        .{ .id = "selfa", .runs_on = "self-hosted", .permissions = Permissions{} },
        .{ .id = "selfb", .runs_on = "self-hosted-linux", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePRTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 2), countDiagnostics(&list, "SEC020"));
}

test "SEC020: ubuntu-latest + pull_request -> no fire" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .runs_on = "ubuntu-latest", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePRTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC020"));
}

test "SEC020: self-hosted + push only -> no fire" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePushTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC020"));
}

test "SEC020: self-hosted + workflow_dispatch -> no fire" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeWorkflowDispatchTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC020"));
}

test "SEC020: repo_visibility private -> suppressed" {
    setRepoVisibility(.private);
    defer setRepoVisibility(.unknown);

    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePRTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC020"));
}

test "SEC020: repo_visibility public -> fires" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePRTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC020"));
}

test "SEC020: repo_visibility unknown default -> fires (fail-safe)" {
    setRepoVisibility(.unknown);
    defer setRepoVisibility(.unknown);

    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePRTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC020"));
}

test "SEC020: runs_on null (reusable workflow caller) -> no fire" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "call", .runs_on = null, .uses = "./.github/workflows/reusable.yml", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePRTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC020"));
}

test "SEC020: disabled via config suppresses after engine run" {
    // Engine always produces diagnostics; main.zig filters via Config.isRuleEnabled.
    // Simulate the filter here.
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    var cfg = config_mod.Config.init(testing.allocator);
    defer cfg.deinit();
    try cfg.rule_overrides.put("SEC020", .{ .enabled = false });

    const eng = engine.Engine.init(&security_rules);
    const jobs = [_]Job{
        .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makePRTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    var remaining: usize = 0;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC020")) {
            if (cfg.isRuleEnabled(d.rule_id)) remaining += 1;
        }
    }
    try testing.expectEqual(@as(usize, 0), remaining);
}

// ── SC002: compromised-action-sha ──

test "SC002: compromised SHA fires error" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SC002"));
    const diag = findDiagnostic(&list, "SC002").?;
    try testing.expectEqual(Severity.@"error", diag.severity);
}

test "SC002: compromised tag fires error" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("tj-actions/changed-files@v44") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SC002"));
}

test "SC002: same owner/repo with non-compromised SHA does not fire" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("tj-actions/changed-files@1111111111111111111111111111111111111111") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC002"));
}

test "SC002: same SHA on different owner/repo does not fire" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("other-owner/other-repo@0e58ed8671d6b60d0890c21b07f8835ace038e67") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC002"));
}

test "SC002: local action skipped" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("./local-action") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC002"));
}

test "SC002: docker action skipped" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("docker://alpine:latest") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC002"));
}

test "SC002: uppercase SHA still fires (case-insensitive match)" {
    const eng = engine.Engine.init(&security_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("tj-actions/changed-files@0E58ED8671D6B60D0890C21B07F8835ACE038E67") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SC002"));
}

test "SEC002: each untrusted reference in a run: block is reported at its own position" {
    const yaml_parser = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: |
        \\          echo "${{ github.event.issue.title }}"
        \\          echo "${{ github.event.comment.body }}"
        \\
    ;

    var parser = yaml_parser.Parser.init(alloc, source);
    defer parser.deinit();
    const yaml_ast = try parser.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_ast);

    var list = DiagnosticList.init(alloc);
    checkScriptInjection(&wf.jobs[0].steps[0], &list);

    // Both interpolations are injection points, each at its own line, and the
    // column is the `$` of the expression (10 spaces + `echo "`).
    try testing.expectEqual(@as(usize, 2), list.len());
    try testing.expectEqual(@as(u32, 8), list.get(0).span.start_line);
    try testing.expectEqual(@as(u32, 17), list.get(0).span.start_col);
    try testing.expectEqual(@as(u32, 9), list.get(1).span.start_line);
    try testing.expectEqual(@as(u32, 17), list.get(1).span.start_col);
}

test "SEC001: unpinned action is reported at the uses: value" {
    const yaml_parser = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: CI
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\
    ;

    var parser = yaml_parser.Parser.init(alloc, source);
    defer parser.deinit();
    const yaml_ast = try parser.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_ast);

    var list = DiagnosticList.init(alloc);
    checkUnpinnedAction(&wf.jobs[0].steps[0], &list);

    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expectEqual(@as(u32, 7), list.get(0).span.start_line);
    try testing.expectEqual(@as(u32, 15), list.get(0).span.start_col);
}
