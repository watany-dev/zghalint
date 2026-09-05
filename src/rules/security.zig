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
const permissions = @import("permissions.zig");

pub const Visibility = config_mod.Visibility;

var sec020_repo_visibility: Visibility = .unknown;

pub fn setRepoVisibility(v: Visibility) void {
    sec020_repo_visibility = v;
}

const Diagnostic = diagnostics.Diagnostic;
const DiagnosticList = diagnostics.DiagnosticList;
const Severity = diagnostics.Severity;
const Span = yaml.Span;
const Workflow = workflow_types.Workflow;
const Job = workflow_types.Job;
const Step = workflow_types.Step;
const ActionRef = workflow_types.ActionRef;
const Permissions = workflow_types.Permissions;
const ScalarValueMeta = workflow_types.ScalarValueMeta;
const ScalarValueMetaMap = workflow_types.ScalarValueMetaMap;
const Fix = diagnostics.Fix;
const Edit = diagnostics.Edit;
const SecretsConfig = workflow_types.SecretsConfig;
const EventType = workflow_types.EventType;
const Rule = engine.Rule;
const Anchor = spans.Anchor;

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

/// `env:` is skipped by rules that treat moving the value into `env:` as the fix.
const StepScalars = struct {
    run: bool = true,
    with: bool = true,
    env: bool = true,
};

fn forEachStepScalar(
    step: *const Step,
    which: StepScalars,
    ctx: anytype,
    comptime cb: fn (@TypeOf(ctx), []const u8, Anchor) bool,
) void {
    if (which.run) {
        if (step.run) |run_body| {
            if (cb(ctx, run_body, spans.runAnchor(step))) return;
        }
    }
    if (which.with) {
        if (step.with) |with_map| {
            for (with_map.keys(), with_map.values()) |key, val| {
                if (cb(ctx, val, withAnchor(step, key))) return;
            }
        }
    }
    if (which.env) {
        if (step.env) |env_map| {
            for (env_map.keys(), env_map.values()) |key, val| {
                if (cb(ctx, val, envAnchor(step, key))) return;
            }
        }
    }
}

fn findStepExprSpan(step: *const Step, which: StepScalars, comptime pred: fn ([]const u8) bool) ?Span {
    const Finder = struct {
        found: ?Span = null,

        fn visit(self: *@This(), s: []const u8, anchor: Anchor) bool {
            const m = findExpr(s, pred) orelse return false;
            self.found = anchor.at(s, m.offset, m.len);
            return true;
        }
    };
    var finder: Finder = .{};
    forEachStepScalar(step, which, &finder, Finder.visit);
    return finder.found;
}

const ExprMatch = struct {
    offset: usize,
    len: usize,
};

const ExprSpan = struct {
    inner: []const u8,
    match: ExprMatch,
};

/// An opener with no closing `}}` is skipped and the scan resumes just after
/// it, so a stray `${{` never swallows the rest of the scalar.
const ExprIter = struct {
    s: []const u8,
    pos: usize = 0,

    fn next(self: *ExprIter) ?ExprSpan {
        while (std.mem.indexOfPos(u8, self.s, self.pos, "${{")) |open| {
            const inner_start = open + 3;
            const close = std.mem.indexOfPos(u8, self.s, inner_start, "}}") orelse {
                self.pos = open + 1;
                continue;
            };
            self.pos = close + 2;
            return .{
                .inner = self.s[inner_start..close],
                .match = .{ .offset = open, .len = close + 2 - open },
            };
        }
        return null;
    }
};

fn findExpr(s: []const u8, comptime pred: fn ([]const u8) bool) ?ExprMatch {
    var it: ExprIter = .{ .s = s };
    while (it.next()) |e| {
        if (pred(e.inner)) return e.match;
    }
    return null;
}

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

const actor_contexts = [_][]const u8{
    "github.actor",
    "github.triggering_actor",
};

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

const cache_setup_actions = [_][]const u8{
    "actions/setup-node",
    "actions/setup-python",
    "actions/setup-java",
    "actions/setup-go",
    "actions/setup-dotnet",
};

const deploy_keywords = [_][]const u8{
    "deploy",
    "release",
    "publish",
    "prod",
};

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
    if (!isAction(ref, "actions/github-script")) return;
    const with_map = step.with orelse return;
    const input = getWithInput(with_map, "script") orelse return;
    checkContextsInString(input.value, withAnchor(step, input.key), &run_dangerous_contexts, "SEC002", .@"error", "script injection: untrusted context used in actions/github-script script: input", script_injection_fix_hint, list);
}

/// Match `owner/repo` against a marketplace action reference. A nested path is a
/// different action, and GitHub resolves owner/repo case-insensitively.
fn isAction(ref: ActionRef, comptime owner_repo: []const u8) bool {
    const slash = comptime std.mem.indexOfScalar(u8, owner_repo, '/').?;
    const owner = ref.owner orelse return false;
    const repo = ref.repo orelse return false;
    return ref.path == null and
        std.ascii.eqlIgnoreCase(owner, owner_repo[0..slash]) and
        std.ascii.eqlIgnoreCase(repo, owner_repo[slash + 1 ..]);
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

fn checkHardcodedSecrets(step: *const Step, list: *DiagnosticList) void {
    const scan = struct {
        fn visit(l: *DiagnosticList, s: []const u8, anchor: Anchor) bool {
            checkStringForSecrets(s, anchor, l);
            return false;
        }
    }.visit;
    forEachStepScalar(step, .{}, list, scan);
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

fn checkExcessivePermissions(wf: *const Workflow, list: *DiagnosticList) void {
    checkWriteAll(list, wf.permissions, "workflow", spans.workflow_head);
}

fn checkExcessivePermissionsJob(job: *const Job, list: *DiagnosticList) void {
    checkWriteAll(list, job.permissions, "job", job.span);
}

fn checkWriteAll(list: *DiagnosticList, maybe_perms: ?Permissions, comptime scope: []const u8, fallback: Span) void {
    const perms = maybe_perms orelse return;
    if (!perms.write_all) return;
    list.append(.{
        .rule_id = "SEC004",
        .severity = .warning,
        .message = scope ++ " uses 'permissions: write-all' which grants excessive permissions",
        .span = perms.value_span orelse fallback,
        .fix_hint = "specify only the permissions that are needed",
        .fix = if (perms.value_span) |vs| permissions.makeWriteAllFix(list, vs) else null,
    }) catch return;
}

fn checkDangerousPRTarget(wf: *const Workflow, list: *DiagnosticList) void {
    if (!wf.hasEvent(.pull_request_target)) return;

    for (wf.jobs) |*job| {
        for (job.steps) |*step| {
            if (step.uses) |action_ref| {
                if (isAction(action_ref, "actions/checkout")) {
                    if (step.with) |with_map| {
                        if (with_map.get("ref")) |ref_val| {
                            // github.event.pull_request.head.{sha,ref} and github.head_ref
                            // all name fork-controlled code.
                            if (std.mem.indexOf(u8, ref_val, "github.event.pull_request.head") != null or
                                std.mem.indexOf(u8, ref_val, "github.head_ref") != null)
                            {
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

fn checkConditionForDangerousContext(cond: []const u8, anchor: Anchor, list: *DiagnosticList) void {
    reportConditionContexts(cond, anchor, &condition_dangerous_contexts, "SEC006", sec006_severity, "untrusted context used in if: condition expression", "validate the input before using it in a condition", list);
}

/// In GitHub Actions, `if:` conditions are implicitly wrapped in `${{ }}`,
/// so they may contain dangerous contexts either directly or inside `${{ }}`.
/// Only the explicit form carries per-expression offsets, so a bare condition
/// is anchored to the whole value.
fn reportConditionContexts(cond: []const u8, anchor: Anchor, contexts: []const []const u8, rule_id: []const u8, severity: Severity, message: []const u8, fix_hint: []const u8, list: *DiagnosticList) void {
    const has_expr = std.mem.indexOf(u8, cond, "${{") != null;
    if (has_expr) {
        checkContextsInString(cond, anchor, contexts, rule_id, severity, message, fix_hint, list);
        return;
    }
    if (!containsAnyContext(cond, contexts)) return;
    list.append(.{
        .rule_id = rule_id,
        .severity = severity,
        .message = message,
        .span = anchor.whole(),
        .fix_hint = fix_hint,
    }) catch return;
}

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

const github_env_targets = [_][]const u8{
    "GITHUB_ENV",
    "GITHUB_PATH",
};

fn indexOfGithubEnvWrite(s: []const u8) ?usize {
    var i: usize = 0;
    while (i + 1 < s.len) : (i += 1) {
        if (s[i] == '>' and s[i + 1] == '>') {
            var j = i + 2;
            while (j < s.len and (s[j] == ' ' or s[j] == '\t')) : (j += 1) {}
            if (j >= s.len) continue;
            const has_quote = s[j] == '"';
            if (has_quote) j += 1;
            if (j >= s.len) continue;
            if (s[j] != '$') continue;
            j += 1;
            if (j >= s.len) continue;
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
                    if (k >= s.len or !isIdentChar(s[k])) {
                        return i;
                    }
                }
            }
        }
    }
    return null;
}

/// `s` is always a `run:` body here, so it uses the same list as SEC002.
fn hasDangerousContextExpression(s: []const u8) bool {
    return findExpr(s, isRunDangerousExpr) != null;
}

fn isRunDangerousExpr(inner: []const u8) bool {
    return containsAnyContext(std.mem.trim(u8, inner, " \t\n\r"), &run_dangerous_contexts);
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

fn checkWorkflowRunUntrustedCheckout(wf: *const Workflow, list: *DiagnosticList) void {
    if (!wf.hasEvent(.workflow_run)) return;

    for (wf.jobs) |*job| {
        for (job.steps) |*step| {
            const action_ref = step.uses orelse continue;
            if (!isAction(action_ref, "actions/checkout")) continue;
            const with_map = step.with orelse continue;
            const ref_val = with_map.get("ref") orelse continue;
            if (std.mem.indexOf(u8, ref_val, "github.event.workflow_run.") == null) continue;
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

/// Attributes of the triggering run that a fork decides. A `workflow_run` job
/// runs with the base repository's secrets, so gating it on one of these is a
/// trust decision made from attacker-authored data: a fork only has to name its
/// branch `main`, or word its commit message to match, to walk through the gate
/// (#143). `head_sha` is absent because it names one immutable commit, and the
/// `head_repository` fields are absent because they are the fix, not the bug.
const workflow_run_untrusted_gate_contexts = [_][]const u8{
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author",
    "github.event.workflow_run.head_commit.committer",
    "github.event.workflow_run.display_title",
};

/// Identity checks that make the gate sound: they name the repository the run
/// came from, which a fork cannot forge. `head_repository.fork` is absent on
/// purpose — `fork == true` gates *for* forks, the opposite of a trust check.
const workflow_run_trust_anchors = [_][]const u8{
    "github.event.workflow_run.head_repository.full_name",
    "github.event.workflow_run.head_repository.name",
    "github.event.workflow_run.head_repository.id",
    "github.event.workflow_run.head_repository.owner",
};

fn checkWorkflowRunBranchGate(wf: *const Workflow, list: *DiagnosticList) void {
    if (!wf.hasEvent(.workflow_run)) return;

    for (wf.jobs) |*job| {
        var job_verified = false;
        if (job.if_condition) |cond| {
            job_verified = hasWorkflowRunTrustAnchor(cond);
            if (!job_verified) reportWorkflowRunBranchGate(cond, ifAnchorJob(job), list);
        }

        for (job.steps) |*step| {
            const step_cond = step.if_condition orelse continue;
            // A step only runs when its job's condition already passed, so a
            // trust check on the job covers every step inside it.
            if (job_verified or hasWorkflowRunTrustAnchor(step_cond)) continue;
            reportWorkflowRunBranchGate(step_cond, ifAnchorStep(step), list);
        }
    }
}

fn reportWorkflowRunBranchGate(cond: []const u8, anchor: Anchor, list: *DiagnosticList) void {
    reportConditionContexts(cond, anchor, &workflow_run_untrusted_gate_contexts, "SEC022", .@"error", "workflow_run gate compares an attribute of the triggering run that a fork controls, so a fork can satisfy it and reach this privileged job", "gate on the triggering repository instead — `github.event.workflow_run.head_repository.full_name == github.repository` or `github.event.workflow_run.event == 'push'` — and identify the commit with `head_sha`", list);
}

/// An anchor has to be an *equality* check: `head_repository.full_name !=
/// github.repository` selects the fork runs instead of excluding them, which is
/// the very hole this rule reports.
///
/// `workflow_run.event == 'push'` is an anchor of its own: a fork cannot cause
/// a push run in the base repository, so the branch name there is the base
/// repository's. The compared literal is what makes it one, so a condition that
/// mentions a pull_request event is not treated as verified.
fn hasWorkflowRunTrustAnchor(cond: []const u8) bool {
    if (matchesAnyContext(cond, &workflow_run_trust_anchors, .equality_operand)) return true;
    if (!matchesAnyContext(cond, &[_][]const u8{"github.event.workflow_run.event"}, .equality_operand)) return false;
    return std.mem.indexOf(u8, cond, "pull_request") == null;
}

fn checkSecretsInherit(job: *const Job, list: *DiagnosticList) void {
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

fn checkOverprovisionedSecrets(step: *const Step, list: *DiagnosticList) void {
    const span = findStepExprSpan(step, .{}, exprIsWholeSecretsRef) orelse return;
    list.append(.{
        .rule_id = "SEC011",
        .severity = .warning,
        .message = "entire secrets context is exposed; reference only the specific secrets you need",
        .span = span,
        .fix_hint = "replace ${{ secrets }} or toJSON(secrets) with individual references like ${{ secrets.MY_TOKEN }}",
    }) catch return;
}

fn findOverprovisionedSecrets(s: []const u8) ?ExprMatch {
    return findExpr(s, exprIsWholeSecretsRef);
}

fn exprIsWholeSecretsRef(expr: []const u8) bool {
    const trimmed = std.mem.trim(u8, expr, " \t\n\r");
    if (trimmed.len == 0) return false;
    if (std.mem.eql(u8, trimmed, "secrets")) return true;
    return hasJsonCallArg(trimmed, isWholeSecretsArg);
}

const json_funcs = [_][]const u8{ "toJSON", "fromJSON" };

/// GitHub matches `toJSON` / `fromJSON` case-insensitively and tolerates
/// blanks before the paren, so the scan does too.
fn hasJsonCallArg(expr: []const u8, comptime pred: fn ([]const u8) bool) bool {
    for (json_funcs) |func_name| {
        var i: usize = 0;
        while (std.ascii.indexOfIgnoreCasePos(expr, i, func_name)) |hit| : (i = hit + 1) {
            const paren = std.mem.indexOfNonePos(u8, expr, hit + func_name.len, " \t") orelse continue;
            if (expr[paren] != '(') continue;
            const arg = std.mem.indexOfNonePos(u8, expr, paren + 1, " \t") orelse continue;
            if (pred(expr[arg..])) return true;
        }
    }
    return false;
}

fn afterSecrets(arg: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, arg, "secrets")) return null;
    return arg["secrets".len..];
}

/// `secrets.X` names a single secret and is not over-provisioned.
fn isWholeSecretsArg(arg: []const u8) bool {
    const rest = afterSecrets(arg) orelse return false;
    if (rest.len == 0 or rest[0] == ')') return true;
    if (rest[0] != ' ' and rest[0] != '\t') return false;
    const tail = std.mem.trimLeft(u8, rest, " \t");
    return tail.len > 0 and tail[0] == ')';
}

/// Whole context or a single secret: both bypass masking once serialized.
fn isSecretsArg(arg: []const u8) bool {
    const rest = afterSecrets(arg) orelse return false;
    return rest.len == 0 or rest[0] == ')' or rest[0] == '.' or rest[0] == ' ' or rest[0] == '\t';
}

fn checkUnredactedSecrets(step: *const Step, list: *DiagnosticList) void {
    const span = findStepExprSpan(step, .{}, exprHasSecretJsonCall) orelse return;
    list.append(.{
        .rule_id = "SEC012",
        .severity = .@"error",
        .message = "secret exposed via toJSON()/fromJSON() bypasses masking",
        .span = span,
        .fix_hint = "avoid passing secrets through toJSON()/fromJSON(); assign individual secret values to environment variables instead",
    }) catch return;
}

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

fn findSecretsOutsideEnv(s: []const u8) ?ExprMatch {
    return findExpr(s, exprIsNonTokenSecretRef);
}

/// `secrets.GITHUB_TOKEN` is automatically redacted, so it is exempt.
fn exprIsNonTokenSecretRef(inner: []const u8) bool {
    const trimmed = std.mem.trim(u8, inner, " \t\n\r");
    if (!std.mem.startsWith(u8, trimmed, "secrets.")) return false;
    return !std.mem.eql(u8, trimmed["secrets.".len..], "GITHUB_TOKEN");
}

fn checkSecretsOutsideEnv(step: *const Step, list: *DiagnosticList) void {
    // env: is the recommended binding, so a secret there is not a finding.
    const span = findStepExprSpan(step, .{ .env = false }, exprIsNonTokenSecretRef) orelse return;
    list.append(.{
        .rule_id = "SEC019",
        .severity = .info,
        .message = "secret used directly in run:/with: instead of being bound through env:",
        .span = span,
        .fix_hint = "bind the secret to an env: variable first, then reference the env var in run:/with:",
    }) catch return;
}

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

fn findUnredactedSecrets(s: []const u8) ?ExprMatch {
    return findExpr(s, exprHasSecretJsonCall);
}

fn isReleaseOrDeployTrigger(wf: *const Workflow) bool {
    return wf.hasEvent(.release);
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

fn exprHasSecretJsonCall(expr: []const u8) bool {
    return hasJsonCallArg(expr, isSecretsArg);
}

fn checkBotConditionStep(step: *const Step, list: *DiagnosticList) void {
    const cond = step.if_condition orelse return;
    checkConditionForBotActorCheck(cond, ifAnchorStep(step), list);
}

fn checkBotConditionJob(job: *const Job, list: *DiagnosticList) void {
    const cond = job.if_condition orelse return;
    checkConditionForBotActorCheck(cond, ifAnchorJob(job), list);
}

fn checkConditionForBotActorCheck(cond: []const u8, anchor: Anchor, list: *DiagnosticList) void {
    const has_expr = std.mem.indexOf(u8, cond, "${{") != null;

    if (has_expr) {
        checkBotActorInString(cond, anchor, list);
    } else {
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

fn checkBotActorInString(s: []const u8, anchor: Anchor, list: *DiagnosticList) void {
    const match = findExpr(s, isActorBotExpr) orelse return;
    list.append(.{
        .rule_id = "SEC014",
        .severity = .warning,
        .message = "spoofable bot check: github.actor can be impersonated by creating an account with the same name",
        .span = anchor.at(s, match.offset, match.len),
        .fix_hint = "use github.event.sender.type == 'Bot' or GitHub's built-in Dependabot integration features instead",
    }) catch return;
}

fn isActorBotExpr(inner: []const u8) bool {
    return containsActorBotCheck(std.mem.trim(u8, inner, " \t\n\r"));
}

fn containsActorBotCheck(expr: []const u8) bool {
    if (!containsAnyContext(expr, &actor_contexts)) return false;

    return std.mem.indexOf(u8, expr, "[bot]") != null;
}

fn checkArtipacked(job: *const Job, list: *DiagnosticList) void {
    var has_upload_after = false;
    var i = job.steps.len;
    while (i > 0) {
        i -= 1;
        const step = &job.steps[i];
        if (step.uses) |ref| {
            if (isAction(ref, "actions/upload-artifact")) {
                has_upload_after = true;
                continue;
            }

            if (has_upload_after and isAction(ref, "actions/checkout") and
                classifyPersistCredentials(step) != .explicit_false)
            {
                var diag = Diagnostic{
                    .rule_id = "SEC015",
                    .severity = .warning,
                    .message = "actions/checkout persists credentials by default; combined with upload-artifact, the GITHUB_TOKEN may leak via uploaded artifacts",
                    .span = spans.usesSpan(step),
                    .fix_hint = "add 'persist-credentials: false' to the checkout step's 'with:' block",
                };

                if (step.uses_value_end_byte != null) {
                    diag.fix = buildPersistCredentialsFalseFix(list, step, .safe);
                }

                list.append(diag) catch return;
            }
        }
    }
}

fn buildPersistCredentialsFalseFix(
    list: *DiagnosticList,
    step: *const Step,
    safety: diagnostics.FixSafety,
) ?diagnostics.Fix {
    const alloc = list.fixAllocator();
    const col = step.uses_key_col orelse 7;

    const has_persist = if (step.with) |w| w.get("persist-credentials") != null else false;
    if (has_persist) return null;

    // uses_key_col is 1-based; parent aligns at col - 1 spaces, child at col + 1.
    const edits = if (step.with == null)
        fix_builder.insertWithEntry(alloc, step.uses_value_end_byte orelse return null, col, "persist-credentials", "false")
    else
        fix_builder.appendMappingEntry(alloc, step.with_last_entry_end_byte orelse return null, col + 1, "persist-credentials", "false");

    return .{
        .description = "add persist-credentials: false to checkout step",
        .safety = safety,
        .edits = edits orelse return null,
    };
}

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
    if (!isAction(ref, "actions/checkout")) return;

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
        diag.fix = buildPersistCredentialsFalseFix(list, step, .unsafe);
    }

    list.append(diag) catch return;
}

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

/// Every offending expression is reported separately: a single `run:` block can
/// interpolate several untrusted values, and each one is its own injection
/// point with its own source location.
fn checkContextsInString(s: []const u8, anchor: Anchor, contexts: []const []const u8, rule_id: []const u8, severity: Severity, message: []const u8, fix_hint: []const u8, list: *DiagnosticList) void {
    var it: ExprIter = .{ .s = s };
    while (it.next()) |e| {
        if (!containsAnyContext(std.mem.trim(u8, e.inner, " \t\n\r"), contexts)) continue;
        list.append(.{
            .rule_id = rule_id,
            .severity = severity,
            .message = message,
            .span = anchor.at(s, e.match.offset, e.match.len),
            .fix_hint = fix_hint,
        }) catch return;
    }
}

// A context reference is compared segment by segment rather than as a raw
// substring, so that object filters (`github.event.commits.*.message`) and
// index accesses (`github.event.commits[0].message`) are understood instead of
// accidentally matched. Both are normalized to the wildcard segment `*`, which
// matches any single segment on either side of the comparison.

const max_path_segments = 16;

const wildcard_segment = "*";

const ContextPath = struct {
    segments: [max_path_segments][]const u8 = undefined,
    len: usize = 0,
    end: usize = 0,

    fn append(self: *ContextPath, segment: []const u8) void {
        if (self.len >= max_path_segments) return;
        self.segments[self.len] = segment;
        self.len += 1;
    }
};

/// Function calls need no special handling: `join(...)` and `toJSON(...)`
/// arguments are themselves references and are visited the same way.
fn containsAnyContext(expr: []const u8, contexts: []const []const u8) bool {
    return matchesAnyContext(expr, contexts, .any);
}

/// `.any` accepts a reference wherever it appears; `.equality_operand` accepts
/// it only as an operand of `==`, which is what separates a check that excludes
/// untrusted runs from one that selects them.
const ContextMatch = enum { any, equality_operand };

fn matchesAnyContext(expr: []const u8, contexts: []const []const u8, mode: ContextMatch) bool {
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
            if (!pathMatchesPattern(path, ctx)) continue;
            switch (mode) {
                .any => return true,
                .equality_operand => if (isEqualityOperand(expr, i, path.end)) return true,
            }
        }
        i = if (path.end > i) path.end else i + 1;
    }
    return false;
}

/// `==` may sit on either side of the reference, and `!=` / `>=` / `<=` must
/// not be mistaken for it — hence the character before the `=` pair is checked.
fn isEqualityOperand(expr: []const u8, start: usize, end: usize) bool {
    var after = end;
    while (after < expr.len and (expr[after] == ' ' or expr[after] == '\t')) after += 1;
    if (after + 1 < expr.len and expr[after] == '=' and expr[after + 1] == '=') return true;

    var before = start;
    while (before > 0 and (expr[before - 1] == ' ' or expr[before - 1] == '\t')) before -= 1;
    return before >= 2 and expr[before - 1] == '=' and expr[before - 2] == '=';
}

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

fn parseContextPath(expr: []const u8, start: usize) ContextPath {
    var path = ContextPath{};
    var i = start;
    while (i < expr.len and isIdentChar(expr[i])) i += 1;
    path.append(expr[start..i]);

    while (i < expr.len) {
        if (expr[i] == '.') {
            const seg_start = i + 1;
            if (seg_start < expr.len and expr[seg_start] == '*') {
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

/// The pattern only needs to be a prefix of the reference, because everything
/// below an untrusted node is untrusted too.
fn pathMatchesPattern(path: ContextPath, pattern: []const u8) bool {
    var it = std.mem.splitScalar(u8, pattern, '.');
    var idx: usize = 0;
    while (it.next()) |pat_seg| : (idx += 1) {
        if (idx >= path.len) return false;
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

/// Unlike `isWordAt`, the left side is unchecked: used for flags, whose
/// leading `-` is already a word break.
fn isTokenAt(s: []const u8, i: usize, token: []const u8) bool {
    if (!std.mem.startsWith(u8, s[i..], token)) return false;
    const after = i + token.len;
    return after >= s.len or !isIdentChar(s[after]);
}

fn isWordAt(s: []const u8, i: usize, word: []const u8) bool {
    if (i > 0 and isIdentChar(s[i - 1])) return false;
    return isTokenAt(s, i, word);
}

/// Callers position `i` right after a pipe and whitespace, so the left-hand
/// boundary is implicit.
fn startsAnyWordAt(s: []const u8, i: usize, words: []const []const u8) bool {
    for (words) |word| {
        if (isTokenAt(s, i, word)) return true;
    }
    return false;
}

fn skipBlanks(s: []const u8, i: usize) usize {
    return std.mem.indexOfNonePos(u8, s, i, " \t\n") orelse s.len;
}

fn identRunLen(s: []const u8) usize {
    for (s, 0..) |c, i| {
        if (!isIdentChar(c)) return i;
    }
    return s.len;
}

fn containsBase64PipeExec(s: []const u8) bool {
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (!isWordAt(s, i, "base64")) continue;

        var j = i + "base64".len;
        var has_decode = false;
        while (j < s.len and s[j] != '|') : (j += 1) {
            if (isTokenAt(s, j, "-d") or isTokenAt(s, j, "--decode")) has_decode = true;
        }
        if (!has_decode or j >= s.len) continue;

        if (startsAnyWordAt(s, skipBlanks(s, j + 1), &exec_targets)) return true;
    }
    return false;
}

fn containsEvalVarExpansion(s: []const u8) bool {
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (!isWordAt(s, i, "eval")) continue;

        var j = i + "eval".len;
        if (j >= s.len or (s[j] != ' ' and s[j] != '\t')) continue;
        j = std.mem.indexOfNonePos(u8, s, j, " \t") orelse continue;
        // A quoted argument still expands, so look past the opening quote.
        if (s[j] == '"' or s[j] == '\'') j += 1;
        if (j >= s.len or s[j] != '$') continue;
        // `${{ }}` is a GitHub expression, not a shell expansion.
        if (std.mem.startsWith(u8, s[j..], "${{")) continue;
        return true;
    }
    return false;
}

fn containsCurlWgetPipeShell(s: []const u8) bool {
    const downloaders = [_][]const u8{ "curl", "wget" };
    for (downloaders) |downloader| {
        var i: usize = 0;
        while (i < s.len) : (i += 1) {
            if (!isWordAt(s, i, downloader)) continue;

            var j = i + downloader.len;
            while (std.mem.indexOfScalarPos(u8, s, j, '|')) |pipe| : (j = pipe + 1) {
                if (startsAnyWordAt(s, skipBlanks(s, pipe + 1), &shell_targets)) return true;
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
    var lines = std.mem.splitScalar(u8, s, '\n');
    while (lines.next()) |line| {
        const start = std.mem.indexOfNone(u8, line, " \t") orelse continue;
        const rest = line[start..];
        if (rest.len < 2 or rest[0] != '$') continue;
        // `${{ }}` is a GitHub expression and `$(...)` a command substitution.
        if (std.mem.startsWith(u8, rest, "${{") or rest[1] == '(') continue;

        const name = if (rest[1] == '{') blk: {
            const end = 2 + identRunLen(rest[2..]);
            if (end >= rest.len or rest[end] != '}') break :blk "";
            break :blk rest[2..end];
        } else blk: {
            if (!isIdentStart(rest[1])) break :blk "";
            break :blk rest[1 .. 1 + identRunLen(rest[1..])];
        };
        if (isAllUppercase(name)) return true;
    }
    return false;
}

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
        .id = "SEC022",
        .name = "workflow-run-branch-gate",
        .description = "workflow_run job is gated on an attribute of the triggering run that a fork controls",
        .severity = .@"error",
        .category = .security,
        .check_workflow = &checkWorkflowRunBranchGate,
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

const testing = std.testing;
const test_support = @import("../test_support.zig");
const EventConfig = workflow_types.EventConfig;
const Trigger = workflow_types.Trigger;

const empty_trigger = test_support.empty_trigger;
const release_trigger = test_support.makeTrigger(.release);
const pr_target_trigger = test_support.makeTrigger(.pull_request_target);
const pr_trigger = test_support.makeTrigger(.pull_request);
const issue_comment_trigger = test_support.makeTrigger(.issue_comment);
const workflow_run_trigger = test_support.makeTrigger(.workflow_run);
const push_trigger = test_support.makeTrigger(.push);
const workflow_dispatch_trigger = test_support.makeTrigger(.workflow_dispatch);

const hasDiagnostic = test_support.hasDiagnostic;
const countDiagnostics = test_support.countDiagnostics;
const findDiagnostic = test_support.findDiagnostic;

fn runWorkflow(wf: Workflow) DiagnosticList {
    return engine.Engine.init(&security_rules).run(testing.allocator, &wf);
}

fn runJobOn(on: Trigger, job: Job) DiagnosticList {
    const jobs = [_]Job{job};
    return runWorkflow(.{ .name = "CI", .on = on, .jobs = &jobs, .permissions = Permissions{} });
}

fn runJob(job: Job) DiagnosticList {
    return runJobOn(empty_trigger, job);
}

fn runSteps(steps: []const Step) DiagnosticList {
    return runJob(.{ .id = "build", .steps = steps, .permissions = Permissions{} });
}

fn runStep(step: Step) DiagnosticList {
    const steps = [_]Step{step};
    return runSteps(&steps);
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

test "SEC001: unpinned action tag ref" {
    var list = runStep(.{ .uses = ActionRef.parse("actions/checkout@v4") });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC001"));
}

test "SEC001: unpinned action branch ref" {
    var list = runStep(.{ .uses = ActionRef.parse("actions/checkout@main") });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC001"));
}

test "SEC001: pinned action (no false positive)" {
    var list = runStep(.{ .uses = ActionRef.parse("actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29") });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC001"));
}

test "SEC001: local action (no false positive)" {
    var list = runStep(.{ .uses = ActionRef.parse("./my-local-action") });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC001"));
}

test "SEC001: docker action (no false positive)" {
    var list = runStep(.{ .uses = ActionRef.parse("docker://alpine:3.8") });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC001"));
}

fn sec002Fires(body: []const u8, env: ?workflow_types.StringMap) bool {
    var list = runStep(.{ .run = body, .env = env });
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

fn sec002UsesFires(uses: []const u8, with_key: []const u8, with_value: []const u8, env: ?workflow_types.StringMap) bool {
    var with = workflow_types.StringMap.init(testing.allocator);
    defer with.deinit();
    with.put(with_key, with_value) catch unreachable;
    const steps = [_]Step{
        .{ .uses = ActionRef.parse(uses), .with = with, .env = env },
    };
    var list = runJob(.{ .id = "handle", .steps = &steps, .permissions = Permissions{} });
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

test "SEC002: object filter inside join()" {
    try testing.expectEqual(true, sec002Fires("echo \"${{ join(github.event.commits.*.message, ' ') }}\"", null));
}

test "SEC002: object filter inside toJSON()" {
    try testing.expectEqual(true, sec002Fires("echo \"${{ toJSON(github.event.commits.*.author.name) }}\"", null));
}

test "SEC002: object filter on pull_request labels" {
    try testing.expectEqual(true, sec002Fires("echo \"${{ github.event.pull_request.labels.*.name }}\"", null));
}

test "SEC002: index access is treated as a wildcard segment" {
    try testing.expectEqual(true, sec002Fires("echo \"${{ github.event.commits[0].message }}\"", null));
}

test "SEC002: object filter over a safe context (no false positive)" {
    try testing.expectEqual(false, sec002Fires("echo \"${{ join(github.event.pull_request.assignees.*.login, ' ') }}\"", null));
}

test "SEC002: dangerous path as a string literal (no false positive)" {
    try testing.expectEqual(false, sec002Fires("echo \"${{ format('github.event.issue.body') }}\"", null));
}

test "SEC002: dangerous name nested under another context (no false positive)" {
    try testing.expectEqual(false, sec002Fires("echo \"${{ steps.meta.outputs.github.head_ref }}\"", null));
}

test "SEC002: bare labels reference without a filter" {
    try testing.expectEqual(true, sec002Fires("echo \"${{ toJSON(github.event.pull_request.labels) }}\"", null));
}

test "SEC002: reference rooted after a function call" {
    try testing.expectEqual(true, sec002Fires("echo \"${{ fromJSON(steps.x.outputs.d).github.head_ref }}\"", null));
}

test "SEC002: context names are case-insensitive" {
    try testing.expectEqual(true, sec002Fires("echo \"${{ GitHub.Event.Issue.Body }}\"", null));
}

test "SEC008: run-only context is reported for GITHUB_ENV writes too" {
    var list = runStep(.{ .run = "echo \"LABEL=${{ github.event.pull_request.labels.*.name }}\" >> $GITHUB_ENV" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC008"));
}

test "SEC002: labels filter in if: is not reported (SEC006 scope)" {
    var list = runStep(.{ .run = "make deploy", .if_condition = "contains(github.event.pull_request.labels.*.name, 'deploy')" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC006"));
}

test "SEC006: object filter over untrusted context in if:" {
    var list = runStep(.{ .run = "make deploy", .if_condition = "contains(github.event.commits.*.message, 'skip')" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC006"));
}

test "SEC003: GitHub PAT in run block" {
    var list = runStep(.{ .run = "curl -H 'Authorization: token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC003"));
}

test "SEC003: AWS key in run block" {
    var list = runStep(.{ .run = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC003"));
}

test "SEC003: Slack token in with" {
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("slack-token", "xoxb-1234-5678-abcdef") catch unreachable;
    defer with.deinit();
    var list = runStep(.{ .uses = ActionRef.parse("some/action@v1"), .with = with });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC003"));
}

test "SEC003: Stripe key in env" {
    var env = workflow_types.StringMap.init(testing.allocator);
    env.put("STRIPE_KEY", "sk-live_abcdef123456") catch unreachable;
    defer env.deinit();
    var list = runStep(.{ .run = "echo test", .env = env });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC003"));
}

test "SEC003: no secret (no false positive)" {
    var list = runStep(.{ .run = "echo ${{ secrets.MY_TOKEN }}" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC003"));
}

test "SEC003: sk-test_ pattern detected" {
    var list = runStep(.{ .run = "export KEY=sk-test_abcdefg" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC003"));
}

test "SEC004: write-all at workflow level" {
    const jobs = [_]Job{
        .{ .id = "build", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = empty_trigger, .jobs = &jobs, .permissions = Permissions{ .write_all = true } };
    var list = runWorkflow(wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC004"));
}

test "SEC004: write-all at job level" {
    var list = runJob(.{ .id = "build", .permissions = Permissions{ .write_all = true } });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC004"));
}

test "SEC004: read-all (no false positive)" {
    const jobs = [_]Job{
        .{ .id = "build", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = empty_trigger, .jobs = &jobs, .permissions = Permissions{ .read_all = true } };
    var list = runWorkflow(wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC004"));
}

test "SEC004: specific permissions (no false positive)" {
    const jobs = [_]Job{
        .{ .id = "build", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = empty_trigger, .jobs = &jobs, .permissions = Permissions{ .contents = .read } };
    var list = runWorkflow(wf);
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
        .on = empty_trigger,
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
        .on = empty_trigger,
        .jobs = &.{},
        .permissions = Permissions{ .write_all = true },
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    checkExcessivePermissions(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(diags.get(0).fix == null);
}

test "SEC005: PR target with checkout of head" {
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("ref", "${{ github.event.pull_request.head.sha }}") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
    };
    var list = runJobOn(pr_target_trigger, .{ .id = "build", .steps = &steps, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC005"));
}

test "SEC005: PR target with checkout of head ref" {
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("ref", "${{ github.head_ref }}") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
    };
    var list = runJobOn(pr_target_trigger, .{ .id = "build", .steps = &steps, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC005"));
}

test "SEC005: PR target without checkout (no false positive)" {
    const steps = [_]Step{
        .{ .run = "echo safe" },
    };
    var list = runJobOn(pr_target_trigger, .{ .id = "build", .steps = &steps, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC005"));
}

test "SEC005: PR target checkout without ref (no false positive)" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
    };
    var list = runJobOn(pr_target_trigger, .{ .id = "build", .steps = &steps, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC005"));
}

test "SEC005: non-PR-target with checkout (no false positive)" {
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("ref", "${{ github.event.pull_request.head.sha }}") catch unreachable;
    defer with.deinit();
    var list = runStep(.{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC005"));
}

test "SEC009: workflow_run with checkout of workflow_run head_sha" {
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("ref", "${{ github.event.workflow_run.head_sha }}") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
    };
    var list = runJobOn(workflow_run_trigger, .{ .id = "build", .steps = &steps, .permissions = Permissions{} });
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
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("ref", "${{ github.event.workflow_run.head_branch }}") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
    };
    var list = runJobOn(workflow_run_trigger, .{ .id = "build", .steps = &steps, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC009"));
}

test "SEC009: workflow_run without checkout (no false positive)" {
    const steps = [_]Step{
        .{ .run = "echo safe" },
    };
    var list = runJobOn(workflow_run_trigger, .{ .id = "build", .steps = &steps, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC009"));
}

test "SEC009: workflow_run checkout without ref (no false positive)" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
    };
    var list = runJobOn(workflow_run_trigger, .{ .id = "build", .steps = &steps, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC009"));
}

test "SEC009: non-workflow_run trigger with workflow_run ref (no false positive)" {
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("ref", "${{ github.event.workflow_run.head_sha }}") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
    };
    var list = runJobOn(pr_trigger, .{ .id = "build", .steps = &steps, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC009"));
}

fn sec022JobCondition(cond: []const u8) ?Severity {
    var list = runJobOn(workflow_run_trigger, .{ .id = "deploy", .if_condition = cond, .permissions = Permissions{} });
    defer list.deinit();
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC022")) return d.severity;
    }
    return null;
}

test "SEC022: head_branch gate on a workflow_run job is an error" {
    // #143: `main` is a name a fork gives its own branch, so this gate keeps
    // nobody out of a job that runs with the base repository's secrets.
    try testing.expectEqual(Severity.@"error", sec022JobCondition("github.event.workflow_run.head_branch == 'main'"));
    try testing.expectEqual(Severity.@"error", sec022JobCondition("${{ github.event.workflow_run.head_branch == 'main' }}"));
    try testing.expectEqual(Severity.@"error", sec022JobCondition("github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.head_branch == 'main'"));
}

test "SEC022: other fork-authored attributes of the triggering run" {
    try testing.expectEqual(Severity.@"error", sec022JobCondition("contains(github.event.workflow_run.head_commit.message, '[deploy]')"));
    try testing.expectEqual(Severity.@"error", sec022JobCondition("github.event.workflow_run.head_commit.author.name == 'release-bot'"));
    try testing.expectEqual(Severity.@"error", sec022JobCondition("github.event.workflow_run.display_title == 'release'"));
}

test "SEC022: a gate that verifies the triggering repository is not reported" {
    try testing.expect(sec022JobCondition("github.event.workflow_run.head_repository.full_name == github.repository && github.event.workflow_run.head_branch == 'main'") == null);
    try testing.expect(sec022JobCondition("github.event.workflow_run.event == 'push' && github.event.workflow_run.head_branch == 'main'") == null);
    // The literal is what anchors the event check; comparing it against a
    // fork-reachable event anchors nothing.
    try testing.expectEqual(Severity.@"error", sec022JobCondition("github.event.workflow_run.event == 'pull_request' && github.event.workflow_run.head_branch == 'main'"));
}

test "SEC022: an anchor must exclude untrusted runs, not select them" {
    // `!=` keeps exactly the fork runs #143 is about, so it anchors nothing.
    try testing.expectEqual(Severity.@"error", sec022JobCondition("github.event.workflow_run.head_repository.full_name != github.repository && github.event.workflow_run.head_branch == 'main'"));
    try testing.expectEqual(Severity.@"error", sec022JobCondition("github.event.workflow_run.event != 'push' && github.event.workflow_run.head_branch == 'main'"));
    // `fork == true` is a fork-only gate, so it is not in the anchor table.
    try testing.expectEqual(Severity.@"error", sec022JobCondition("github.event.workflow_run.head_repository.fork == true && github.event.workflow_run.head_branch == 'main'"));
    // The reference may sit on either side of the `==`.
    try testing.expect(sec022JobCondition("github.repository == github.event.workflow_run.head_repository.full_name && github.event.workflow_run.head_branch == 'main'") == null);
}

test "SEC022: immutable and unrelated contexts are not reported" {
    try testing.expect(sec022JobCondition("github.event.workflow_run.head_sha == env.EXPECTED_SHA") == null);
    // `head_commit.id` is that same immutable SHA, and the timestamp comes with it.
    try testing.expect(sec022JobCondition("github.event.workflow_run.head_commit.id == env.EXPECTED_SHA") == null);
    try testing.expect(sec022JobCondition("github.event.workflow_run.head_commit.timestamp == env.EXPECTED") == null);
    try testing.expect(sec022JobCondition("github.event.workflow_run.conclusion == 'success'") == null);
    try testing.expect(sec022JobCondition("github.ref == 'refs/heads/main'") == null);
}

test "SEC022: only workflow_run workflows are reported" {
    var list = runJobOn(push_trigger, .{ .id = "deploy", .if_condition = "github.event.workflow_run.head_branch == 'main'", .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC022"));
}

test "SEC022: step condition inside a workflow_run job" {
    const steps = [_]Step{
        .{ .run = "./deploy.sh", .if_condition = "github.event.workflow_run.head_branch == 'main'" },
    };
    var list = runJobOn(workflow_run_trigger, .{ .id = "deploy", .steps = &steps, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC022"));
}

test "SEC022: a job-level trust check covers its steps" {
    // The step only runs once the job condition passed, so the identity check
    // on the job already guards it.
    const steps = [_]Step{
        .{ .run = "./deploy.sh", .if_condition = "github.event.workflow_run.head_branch == 'main'" },
    };
    var list = runJobOn(workflow_run_trigger, .{
        .id = "deploy",
        .if_condition = "github.event.workflow_run.head_repository.full_name == github.repository",
        .steps = &steps,
        .permissions = Permissions{},
    });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC022"));
}

test "SEC022: reported diagnostic carries a fix hint" {
    var list = runJobOn(workflow_run_trigger, .{ .id = "deploy", .if_condition = "github.event.workflow_run.head_branch == 'main'", .permissions = Permissions{} });
    defer list.deinit();
    const d = findDiagnostic(&list, "SEC022").?;
    try testing.expect(d.fix_hint != null and d.fix_hint.?.len > 0);
}

test "SEC006: dangerous context in step if condition" {
    var list = runStep(.{ .run = "echo test", .if_condition = "contains(github.event.issue.title, 'deploy')" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC006"));
}

test "SEC006: dangerous context in job if condition" {
    var list = runJob(.{ .id = "build", .if_condition = "contains(github.event.comment.body, '/approve')", .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC006"));
}

fn sec006Severity(cond: []const u8) ?Severity {
    var list = runStep(.{ .run = "echo test", .if_condition = cond });
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
    var list = runStep(.{ .run = "echo test", .if_condition = "github.ref == 'refs/heads/main'" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC006"));
}

test "SEC007: no permissions defined" {
    const jobs = [_]Job{
        .{ .id = "build" },
    };
    const wf = Workflow{ .name = "CI", .on = empty_trigger, .jobs = &jobs };
    var list = runWorkflow(wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC007"));
}

test "SEC007: permissions defined (no false positive)" {
    const jobs = [_]Job{
        .{ .id = "build" },
    };
    const wf = Workflow{ .name = "CI", .on = empty_trigger, .jobs = &jobs, .permissions = Permissions{ .contents = .read } };
    var list = runWorkflow(wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC007"));
}

test "SEC007: empty permissions block counts as defined" {
    var list = runJob(.{ .id = "build" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC007"));
}

test "SEC007: autofix generated on single-line on:" {
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

    const wf = try test_support.parseWorkflowSource(alloc, source);

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
    const on_line_end = (std.mem.indexOf(u8, source, "on: push\n") orelse unreachable) + "on: push\n".len;
    try testing.expectEqual(on_line_end, fix.edits[0].start_byte);
}

test "SEC007: autofix on multi-line on: block inserts after last child" {
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

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var list = DiagnosticList.init(alloc);
    checkMissingPermissions(&wf, &list);

    const diag = list.get(0);
    const fix = diag.fix orelse return error.TestUnexpectedResult;
    const jobs_pos = std.mem.indexOf(u8, source, "jobs:") orelse unreachable;
    try testing.expectEqual(jobs_pos, fix.edits[0].start_byte);
    try testing.expectEqualStrings("permissions: {contents: read}\n", fix.edits[0].replacement);
}

test "SEC007: no fix when permissions_insertion_byte missing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const jobs = [_]Job{.{ .id = "build" }};
    const wf = Workflow{ .name = "CI", .on = empty_trigger, .jobs = &jobs };

    var list = DiagnosticList.init(alloc);
    checkMissingPermissions(&wf, &list);

    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expect(list.get(0).fix == null);
}

test "SEC007: no diagnostic when permissions already defined (parser path)" {
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

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var list = DiagnosticList.init(alloc);
    checkMissingPermissions(&wf, &list);
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SEC007: applyFixes inserts permissions block between on: and jobs:" {
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

    const wf = try test_support.parseWorkflowSource(alloc, source);

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
    // (parser が permissions_insertion_byte と concurrency_insertion_byte に同じ end_byte を
    // 入れるため)。fix/engine.zig:flattenAndSort の tie-break は
    // (start_byte, end_byte) 昇順 → reverse なので、両 edit が隣接挿入されても
    // 構文上 valid な YAML になる。このテストは順序と再 parse 可能性をピン止めする。
    const yaml_parser = @import("../yaml/parser.zig");
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

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var list = DiagnosticList.init(alloc);
    checkMissingPermissions(&wf, &list);
    best_practices.checkPushConcurrency(&wf, &list);

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

    var reparse = yaml_parser.Parser.init(alloc, result.content);
    _ = try reparse.parse();
}

test "SEC008: dangerous context written to GITHUB_ENV" {
    var list = runStep(.{ .run = "echo \"VAR=${{ github.event.issue.title }}\" >> $GITHUB_ENV" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC008"));
}

test "SEC008: dangerous context written to GITHUB_PATH" {
    var list = runStep(.{ .run = "echo \"${{ github.head_ref }}\" >> $GITHUB_PATH" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC008"));
}

test "SEC008: quoted GITHUB_ENV target" {
    var list = runStep(.{ .run = "echo \"X=${{ github.event.comment.body }}\" >> \"$GITHUB_ENV\"" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC008"));
}

test "SEC008: braced GITHUB_ENV target" {
    var list = runStep(.{ .run = "echo \"X=${{ github.event.pull_request.title }}\" >> ${GITHUB_ENV}" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC008"));
}

test "SEC008: safe value to GITHUB_ENV (no false positive)" {
    var list = runStep(.{ .run = "echo \"VAR=safe\" >> $GITHUB_ENV" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC008"));
}

test "SEC008: dangerous context without env write (no false positive)" {
    var list = runStep(.{ .run = "echo ${{ github.event.issue.title }}" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC008"));
}

test "SEC008: no run block (no false positive)" {
    var list = runStep(.{ .uses = ActionRef.parse("actions/checkout@v4") });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC008"));
}

test "SEC008: safe context to GITHUB_ENV (no false positive)" {
    var list = runStep(.{ .run = "echo \"SHA=${{ github.sha }}\" >> $GITHUB_ENV" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC008"));
}

test "SEC010: secrets inherit in reusable workflow call" {
    var list = runJob(.{ .id = "call-workflow", .uses = "octo-org/example/.github/workflows/deploy.yml@main", .secrets = SecretsConfig{ .inherit = {} }, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC010"));
}

test "SEC010: explicit secrets (no false positive)" {
    var secrets_map = workflow_types.StringMap.init(testing.allocator);
    secrets_map.put("deploy_key", "${{ secrets.DEPLOY_KEY }}") catch unreachable;
    defer secrets_map.deinit();
    var list = runJob(.{ .id = "call-workflow", .uses = "octo-org/example/.github/workflows/deploy.yml@main", .secrets = SecretsConfig{ .map = secrets_map }, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC010"));
}

test "SEC010: no secrets in reusable workflow call (no false positive)" {
    var list = runJob(.{ .id = "call-workflow", .uses = "octo-org/example/.github/workflows/deploy.yml@main", .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC010"));
}

test "SEC010: non-reusable job with no uses (no false positive)" {
    var list = runStep(.{ .run = "echo hello" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC010"));
}

test "SEC012: toJSON(secrets) in run block" {
    var list = runStep(.{ .run = "echo '${{ toJSON(secrets) }}'" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC012"));
}

test "SEC012: toJSON(secrets.MY_TOKEN) in run block" {
    var list = runStep(.{ .run = "echo ${{ toJSON(secrets.MY_TOKEN) }}" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC012"));
}

test "SEC012: fromJSON(secrets.CONFIG) in run block" {
    var list = runStep(.{ .run = "echo ${{ fromJSON(secrets.CONFIG).api_key }}" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC012"));
}

test "SEC012: toJSON(secrets) in with value" {
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("data", "${{ toJSON(secrets) }}") catch unreachable;
    defer with.deinit();
    var list = runStep(.{ .uses = ActionRef.parse("some/action@v1"), .with = with });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC012"));
}

test "SEC012: toJSON(secrets) in env value" {
    var env = workflow_types.StringMap.init(testing.allocator);
    env.put("ALL_SECRETS", "${{ toJSON(secrets) }}") catch unreachable;
    defer env.deinit();
    var list = runStep(.{ .run = "echo debug", .env = env });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC012"));
}

test "SEC012: case variant tojson(secrets)" {
    var list = runStep(.{ .run = "echo ${{ tojson(secrets) }}" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC012"));
}

test "SEC012: toJSON(github) no false positive" {
    var list = runStep(.{ .run = "echo ${{ toJSON(github) }}" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC012"));
}

test "SEC012: secrets reference without toJSON (no false positive)" {
    var list = runStep(.{ .run = "echo ${{ secrets.MY_TOKEN }}" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC012"));
}

test "SEC012: no expression in run (no false positive)" {
    var list = runStep(.{ .run = "echo hello" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC012"));
}

test "SEC012: only one diagnostic per step" {
    var env = workflow_types.StringMap.init(testing.allocator);
    env.put("A", "${{ toJSON(secrets) }}") catch unreachable;
    env.put("B", "${{ toJSON(secrets.X) }}") catch unreachable;
    defer env.deinit();
    var list = runStep(.{ .run = "echo ${{ toJSON(secrets) }}", .env = env });
    defer list.deinit();
    try testing.expectEqual(@as(usize, 1), countDiagnostics(&list, "SEC012"));
}

test "condition_dangerous_contexts recognizes issue title" {
    try testing.expect(containsAnyContext("github.event.issue.title", &condition_dangerous_contexts));
}

test "condition_dangerous_contexts recognizes PR body" {
    try testing.expect(containsAnyContext("github.event.pull_request.body", &condition_dangerous_contexts));
}

test "condition_dangerous_contexts rejects safe ref" {
    try testing.expect(!containsAnyContext("github.sha", &condition_dangerous_contexts));
}

test "condition_dangerous_contexts rejects safe actor" {
    try testing.expect(!containsAnyContext("github.actor", &condition_dangerous_contexts));
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

test "isAction checkout true" {
    try testing.expect(isAction(ActionRef.parse("actions/checkout@v4"), "actions/checkout"));
}

test "isAction checkout false for other action" {
    try testing.expect(!isAction(ActionRef.parse("actions/setup-node@v3"), "actions/checkout"));
}

test "multiple security rules fire together" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") }, // SEC001
        .{ .run = "echo ${{ github.event.issue.body }}" }, // SEC002
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps },
    };
    const wf = Workflow{ .name = "CI", .on = empty_trigger, .jobs = &jobs };
    var list = runWorkflow(wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC001"));
    try testing.expect(hasDiagnostic(&list, "SEC002"));
    try testing.expect(hasDiagnostic(&list, "SEC007"));
}

test "SEC014: github.actor == dependabot[bot] in step condition" {
    var list = runStep(.{ .run = "echo skip", .if_condition = "github.actor == 'dependabot[bot]'" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC014"));
}

test "SEC014: github.actor != renovate[bot] in step condition" {
    var list = runStep(.{ .run = "echo test", .if_condition = "github.actor != 'renovate[bot]'" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC014"));
}

test "SEC014: github.actor == github-actions[bot] in job condition" {
    var list = runJob(.{ .id = "build", .if_condition = "github.actor == 'github-actions[bot]'", .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC014"));
}

test "SEC014: wrapped in dollar-brace expression" {
    var list = runStep(.{ .run = "echo skip", .if_condition = "${{ github.actor == 'dependabot[bot]' }}" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC014"));
}

test "SEC014: github.triggering_actor with bot check" {
    var list = runStep(.{ .run = "echo skip", .if_condition = "github.triggering_actor == 'dependabot[bot]'" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC014"));
}

test "SEC014: github.actor without bot pattern (no false positive)" {
    var list = runStep(.{ .run = "echo test", .if_condition = "github.actor == 'octocat'" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC014"));
}

test "SEC014: bot pattern without github.actor (no false positive)" {
    var list = runStep(.{ .run = "echo test", .if_condition = "contains(github.event.comment.body, 'dependabot[bot]')" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC014"));
}

test "SEC014: safe condition with github.ref (no false positive)" {
    var list = runStep(.{ .run = "echo test", .if_condition = "github.ref == 'refs/heads/main'" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC014"));
}

test "SEC014: no condition (no false positive)" {
    var list = runStep(.{ .run = "echo test" });
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

test "clean workflow passes all security rules" {
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
    const wf = Workflow{ .name = "CI", .on = empty_trigger, .jobs = &jobs, .permissions = Permissions{ .contents = .read } };
    var list = runWorkflow(wf);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SEC016: release trigger + actions/cache" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/cache@v3") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "Release", .on = release_trigger, .jobs = &jobs, .permissions = Permissions{} };
    var list = runWorkflow(wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC016"));
}

test "SEC016: release trigger + setup-node with cache" {
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("cache", "npm") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/setup-node@v4"), .with = with },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "Release", .on = release_trigger, .jobs = &jobs, .permissions = Permissions{} };
    var list = runWorkflow(wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC016"));
}

test "SEC016: deploy job name + actions/cache" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/cache@v3") },
    };
    var list = runJob(.{ .id = "deploy-prod", .name = "Deploy to Production", .steps = &steps, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC016"));
}

test "SEC016: regular CI workflow with cache (no false positive)" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/cache@v3") },
    };
    var list = runJob(.{ .id = "build", .name = "Build", .steps = &steps, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC016"));
}

test "SEC016: release trigger but no cache (no false positive)" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
        .{ .run = "make build" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "Release", .on = release_trigger, .jobs = &jobs, .permissions = Permissions{} };
    var list = runWorkflow(wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC016"));
}

test "SEC016: deploy job without cache (no false positive)" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "deploy", .name = "Deploy", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CD", .on = empty_trigger, .jobs = &jobs, .permissions = Permissions{} };
    var list = runWorkflow(wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC016"));
}

test "SEC016: setup-node without cache input in release (no false positive)" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/setup-node@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "Release", .on = release_trigger, .jobs = &jobs, .permissions = Permissions{} };
    var list = runWorkflow(wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC016"));
}

test "SEC016: case-insensitive deploy job name" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/cache@v3") },
    };
    const jobs = [_]Job{
        .{ .id = "job1", .name = "DEPLOY to Prod", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CD", .on = empty_trigger, .jobs = &jobs, .permissions = Permissions{} };
    var list = runWorkflow(wf);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC016"));
}

test "SEC016: publish job id triggers rule" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/cache@v3") },
    };
    var list = runJob(.{ .id = "publish-npm", .steps = &steps, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC016"));
}

test "SEC016: emits one diagnostic per offending step" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/cache@v3") },
        .{ .uses = ActionRef.parse("actions/cache@v3") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .steps = &steps, .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "Release", .on = release_trigger, .jobs = &jobs, .permissions = Permissions{} };
    var list = runWorkflow(wf);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 2), countDiagnostics(&list, "SEC016"));
}

test "SEC013: plaintext credentials in container" {
    const container = workflow_types.Container{
        .image = "node:14",
        .credentials = .{ .username = "myuser", .password = "mypassword" },
    };
    var list = runJob(.{ .id = "build", .container = container, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC013"));
    try testing.expectEqual(@as(usize, 2), countDiagnostics(&list, "SEC013"));
}

test "SEC013: plaintext credentials in service" {
    const services = [_]workflow_types.Service{
        .{ .name = "redis", .image = "redis", .credentials = .{ .username = "svcuser", .password = "svcpass" } },
    };
    var list = runJob(.{ .id = "build", .services = &services, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC013"));
    try testing.expectEqual(@as(usize, 2), countDiagnostics(&list, "SEC013"));
}

test "SEC013: plaintext password only" {
    const container = workflow_types.Container{
        .image = "node:14",
        .credentials = .{ .username = "${{ secrets.DOCKER_USER }}", .password = "hardcoded_pass" },
    };
    var list = runJob(.{ .id = "build", .container = container, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC013"));
    try testing.expectEqual(@as(usize, 1), countDiagnostics(&list, "SEC013"));
}

test "SEC013: diagnostics from both container and service" {
    const container = workflow_types.Container{
        .image = "node:14",
        .credentials = .{ .username = "user1", .password = "pass1" },
    };
    const services = [_]workflow_types.Service{
        .{ .name = "db", .image = "postgres", .credentials = .{ .username = "dbuser", .password = "dbpass" } },
    };
    var list = runJob(.{ .id = "build", .container = container, .services = &services, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expectEqual(@as(usize, 4), countDiagnostics(&list, "SEC013"));
}

test "SEC013: secrets expression credentials (no false positive)" {
    const container = workflow_types.Container{
        .image = "node:14",
        .credentials = .{ .username = "${{ secrets.DOCKER_USER }}", .password = "${{ secrets.DOCKER_PASS }}" },
    };
    var list = runJob(.{ .id = "build", .container = container, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC013"));
}

test "SEC013: container without credentials (no false positive)" {
    const container = workflow_types.Container{ .image = "node:14" };
    var list = runJob(.{ .id = "build", .container = container, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC013"));
}

test "SEC013: job without container or services (no false positive)" {
    var list = runStep(.{ .run = "echo hello" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC013"));
}

test "SEC013: service with secrets credentials (no false positive)" {
    const services = [_]workflow_types.Service{
        .{ .name = "redis", .image = "redis", .credentials = .{ .username = "${{ secrets.REDIS_USER }}", .password = "${{ secrets.REDIS_PASS }}" } },
    };
    var list = runJob(.{ .id = "build", .services = &services, .permissions = Permissions{} });
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

test "SC001: unpinned container image with tag" {
    const container = workflow_types.Container{ .image = "node:14" };
    var list = runJob(.{ .id = "build", .container = container, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SC001"));
}

test "SC001: unpinned container image with latest tag" {
    const container = workflow_types.Container{ .image = "redis:latest" };
    var list = runJob(.{ .id = "build", .container = container, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SC001"));
}

test "SC001: unpinned container image without tag" {
    const container = workflow_types.Container{ .image = "redis" };
    var list = runJob(.{ .id = "build", .container = container, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SC001"));
}

test "SC001: unpinned service image" {
    const services = [_]workflow_types.Service{
        .{ .name = "db", .image = "postgres:13" },
    };
    var list = runJob(.{ .id = "build", .services = &services, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SC001"));
}

test "SC001: both container and service unpinned" {
    const container = workflow_types.Container{ .image = "node:14" };
    const services = [_]workflow_types.Service{
        .{ .name = "redis", .image = "redis:6" },
    };
    var list = runJob(.{ .id = "build", .container = container, .services = &services, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(countDiagnostics(&list, "SC001") == 2);
}

test "SC001: pinned container image (no false positive)" {
    const container = workflow_types.Container{ .image = "node@sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" };
    var list = runJob(.{ .id = "build", .container = container, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SC001"));
}

test "SC001: pinned service image (no false positive)" {
    const services = [_]workflow_types.Service{
        .{ .name = "redis", .image = "redis@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1" },
    };
    var list = runJob(.{ .id = "build", .services = &services, .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SC001"));
}

test "SC001: job without container or services (no false positive)" {
    var list = runStep(.{ .run = "echo hello" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SC001"));
}

test "SC001: registry with digest is pinned (no false positive)" {
    const container = workflow_types.Container{ .image = "ghcr.io/owner/image@sha256:a1b2c3d4e5f6" };
    var list = runJob(.{ .id = "build", .container = container, .permissions = Permissions{} });
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

test "SEC011: bare secrets in run block" {
    var list = runStep(.{ .run = "echo ${{ secrets }}" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: bare secrets with extra whitespace" {
    var list = runStep(.{ .run = "echo ${{  secrets  }}" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: toJSON(secrets) in run block" {
    var list = runStep(.{ .run = "echo ${{ toJSON(secrets) }}" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: tojson(secrets) lowercase" {
    var list = runStep(.{ .run = "echo ${{ tojson(secrets) }}" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: fromJSON(secrets) in run block" {
    var list = runStep(.{ .run = "echo ${{ fromJSON(secrets) }}" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: bare secrets in with value" {
    var with_map = workflow_types.StringMap.init(testing.allocator);
    defer with_map.deinit();
    with_map.put("data", "${{ secrets }}") catch unreachable;
    var list = runStep(.{ .with = with_map });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: bare secrets in env value" {
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("ALL_SECRETS", "${{ secrets }}") catch unreachable;
    var list = runStep(.{ .env = env_map });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: toJSON with whitespace in parens" {
    var list = runStep(.{ .run = "echo ${{ toJSON( secrets ) }}" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC011"));
}

test "SEC011: individual secret is allowed" {
    var list = runStep(.{ .run = "echo ${{ secrets.MY_TOKEN }}" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC011"));
}

test "SEC011: toJSON(secrets.TOKEN) is allowed" {
    var list = runStep(.{ .run = "echo ${{ toJSON(secrets.MY_TOKEN) }}" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC011"));
}

test "SEC011: toJSON(github) is allowed" {
    var list = runStep(.{ .run = "echo ${{ toJSON(github) }}" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC011"));
}

test "SEC011: no expression is allowed" {
    var list = runStep(.{ .run = "echo hello world" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC011"));
}

test "SEC011: one diagnostic per step" {
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("ALL", "${{ toJSON(secrets) }}") catch unreachable;
    var list = runStep(.{ .run = "echo ${{ secrets }}", .env = env_map });
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

test "SEC015: checkout + upload-artifact triggers rule" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    var list = runSteps(&steps);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC015"));
}

test "SEC015: checkout with other with: keys (no persist-credentials) + upload-artifact" {
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("fetch-depth", "0") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    var list = runSteps(&steps);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC015"));
}

test "SEC015: persist-credentials: true is vulnerable" {
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("persist-credentials", "true") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    var list = runSteps(&steps);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC015"));
}

test "SEC015: SHA-pinned versions still detected" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29") },
        .{ .uses = ActionRef.parse("actions/upload-artifact@65462800fd760344b1a7b4382951275a0abb4808") },
    };
    var list = runSteps(&steps);
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC015"));
}

test "SEC015: multiple checkout steps emit one diagnostic per checkout" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
        .{ .run = "make build" },
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    var list = runSteps(&steps);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 2), countDiagnostics(&list, "SEC015"));
}

test "SEC015: checkout + persist-credentials: false (no false positive)" {
    var with = workflow_types.StringMap.init(testing.allocator);
    with.put("persist-credentials", "false") catch unreachable;
    defer with.deinit();
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    var list = runSteps(&steps);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC015"));
}

test "SEC015: checkout only without upload-artifact (no false positive)" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
        .{ .run = "make test" },
    };
    var list = runSteps(&steps);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC015"));
}

test "SEC015: upload-artifact only without checkout (no false positive)" {
    const steps = [_]Step{
        .{ .run = "make build" },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    var list = runSteps(&steps);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC015"));
}

test "SEC015: checkout and upload in different jobs (no false positive)" {
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
    const wf = Workflow{ .name = "CI", .on = empty_trigger, .jobs = &jobs, .permissions = Permissions{} };
    var list = runWorkflow(wf);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC015"));
}

test "SEC015: upload before checkout does not trigger" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
    };
    var list = runSteps(&steps);
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC015"));
}

test "SEC015: only checkout before upload triggers in mixed ordering" {
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
    var list = runSteps(&steps);
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
    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/checkout@v4"),
            .uses_key_col = 8,
            .uses_value_end_byte = 50,
        },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    var list = runSteps(&steps);
    defer list.deinit();

    var found_fix = false;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC015")) {
            try testing.expect(d.fix != null);
            const fix = d.fix.?;
            try testing.expect(fix.safety == .safe);
            try testing.expect(fix.edits.len == 1);
            try testing.expectEqual(@as(usize, 50), fix.edits[0].start_byte);
            try testing.expectEqual(@as(usize, 50), fix.edits[0].end_byte);
            try testing.expect(std.mem.indexOf(u8, fix.edits[0].replacement, "with:") != null);
            try testing.expect(std.mem.indexOf(u8, fix.edits[0].replacement, "persist-credentials: false") != null);
            found_fix = true;
            break;
        }
    }
    try testing.expect(found_fix);
}

test "SEC015: fix inserts into existing with: block" {
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
    var list = runSteps(&steps);
    defer list.deinit();

    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC015")) {
            try testing.expect(d.fix != null);
            const fix = d.fix.?;
            try testing.expectEqual(@as(usize, 80), fix.edits[0].start_byte);
            try testing.expect(std.mem.indexOf(u8, fix.edits[0].replacement, "with:") == null);
            try testing.expect(std.mem.indexOf(u8, fix.edits[0].replacement, "persist-credentials: false") != null);
            break;
        }
    }
}

test "SEC015: persist-credentials: true has no fix (only fix_hint)" {
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
    var list = runSteps(&steps);
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
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    var list = runSteps(&steps);
    defer list.deinit();

    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC015")) {
            try testing.expect(d.fix == null);
            try testing.expect(d.fix_hint != null);
            break;
        }
    }
}

test "SEC015: isAction upload-artifact helper" {
    try testing.expect(isAction(ActionRef.parse("actions/upload-artifact@v4"), "actions/upload-artifact"));
    try testing.expect(isAction(ActionRef.parse("actions/upload-artifact@65462800fd760344b1a7b4382951275a0abb4808"), "actions/upload-artifact"));
    try testing.expect(!isAction(ActionRef.parse("actions/checkout@v4"), "actions/upload-artifact"));
    try testing.expect(!isAction(ActionRef.parse("actions/download-artifact@v4"), "actions/upload-artifact"));
    try testing.expect(!isAction(ActionRef.parse("./actions/upload-artifact"), "actions/upload-artifact"));
}

test "classifyPersistCredentials helper" {
    const step_no_with = Step{};
    try testing.expectEqual(PersistCredentialsState.not_set, classifyPersistCredentials(&step_no_with));

    var with1 = workflow_types.StringMap.init(testing.allocator);
    with1.put("fetch-depth", "0") catch unreachable;
    defer with1.deinit();
    const step_no_pc = Step{ .with = with1 };
    try testing.expectEqual(PersistCredentialsState.not_set, classifyPersistCredentials(&step_no_pc));

    var with2 = workflow_types.StringMap.init(testing.allocator);
    with2.put("persist-credentials", "false") catch unreachable;
    defer with2.deinit();
    const step_false = Step{ .with = with2 };
    try testing.expectEqual(PersistCredentialsState.explicit_false, classifyPersistCredentials(&step_false));

    var with3 = workflow_types.StringMap.init(testing.allocator);
    with3.put("persist-credentials", "true") catch unreachable;
    defer with3.deinit();
    const step_true = Step{ .with = with3 };
    try testing.expectEqual(PersistCredentialsState.explicit_true, classifyPersistCredentials(&step_true));
}

test "SEC015: integration - YAML parse to fix apply" {
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
        \\      - uses: actions/checkout@v4
        \\      - run: make build
        \\      - uses: actions/upload-artifact@v4
        \\        with:
        \\          name: dist
        \\          path: ./dist
    ;

    const wf = try test_support.parseWorkflowSource(alloc, source);

    const eng = engine.Engine.init(&security_rules);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SEC015"));

    var fix_found = false;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC015")) {
            try testing.expect(d.fix != null);
            const fix = d.fix.?;
            try testing.expect(fix.safety == .safe);
            try testing.expect(fix.edits.len == 1);

            const fixes = [_]diagnostics.Fix{fix};
            const result = try fix_engine.applyFixes(testing.allocator, source, &fixes);
            defer result.deinit(testing.allocator);

            try testing.expect(std.mem.indexOf(u8, result.content, "persist-credentials: false") != null);
            try testing.expect(std.mem.indexOf(u8, result.content, "with:\n") != null);
            try testing.expectEqual(@as(usize, 1), result.edits_applied);

            fix_found = true;
            break;
        }
    }
    try testing.expect(fix_found);
}

test "SEC015: integration ignores checkout after upload-artifact" {
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

    const wf = try test_support.parseWorkflowSource(alloc, source);

    const eng = engine.Engine.init(&security_rules);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SEC015"));
}

test "SEC018: with == null triggers with unsafe fix" {
    var list = runStep(.{
        .uses = ActionRef.parse("actions/checkout@v4"),
        .uses_key_col = 8,
        .uses_value_end_byte = 50,
    });
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SEC018"));
    const diag = findDiagnostic(&list, "SEC018").?;
    try testing.expect(diag.fix != null);
    try testing.expect(diag.fix.?.safety == .unsafe);
}

test "SEC018: with exists without persist-credentials triggers with fix" {
    var with_map = workflow_types.StringMap.init(testing.allocator);
    with_map.put("fetch-depth", "0") catch unreachable;
    defer with_map.deinit();
    var list = runStep(.{
        .uses = ActionRef.parse("actions/checkout@v4"),
        .with = with_map,
        .uses_key_col = 8,
        .uses_value_end_byte = 50,
        .with_last_entry_end_byte = 80,
    });
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SEC018"));
    const diag = findDiagnostic(&list, "SEC018").?;
    try testing.expect(diag.fix != null);
    try testing.expect(diag.fix.?.safety == .unsafe);
}

test "SEC018: persist-credentials: true triggers without fix" {
    var with_map = workflow_types.StringMap.init(testing.allocator);
    with_map.put("persist-credentials", "true") catch unreachable;
    defer with_map.deinit();
    var list = runStep(.{
        .uses = ActionRef.parse("actions/checkout@v4"),
        .with = with_map,
        .uses_key_col = 8,
        .uses_value_end_byte = 50,
        .with_last_entry_end_byte = 80,
    });
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SEC018"));
    const diag = findDiagnostic(&list, "SEC018").?;
    try testing.expect(diag.fix == null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "explicitly set to true") != null);
}

test "SEC018: persist-credentials: false does not trigger" {
    var with_map = workflow_types.StringMap.init(testing.allocator);
    with_map.put("persist-credentials", "false") catch unreachable;
    defer with_map.deinit();
    var list = runStep(.{
        .uses = ActionRef.parse("actions/checkout@v4"),
        .with = with_map,
        .uses_key_col = 8,
        .uses_value_end_byte = 50,
        .with_last_entry_end_byte = 80,
    });
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SEC018"));
}

test "SEC018: autofix replacement contains with: block when with == null" {
    var list = runStep(.{
        .uses = ActionRef.parse("actions/checkout@v4"),
        .uses_key_col = 6,
        .uses_value_end_byte = 50,
    });
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
    var with_map = workflow_types.StringMap.init(testing.allocator);
    with_map.put("fetch-depth", "0") catch unreachable;
    defer with_map.deinit();
    var list = runStep(.{
        .uses = ActionRef.parse("actions/checkout@v4"),
        .with = with_map,
        .uses_key_col = 6,
        .uses_value_end_byte = 50,
        .with_last_entry_end_byte = 80,
    });
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
    const wf_false = Workflow{ .name = "CI", .on = empty_trigger, .jobs = &jobs_false, .permissions = Permissions{} };
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
    const wf_true = Workflow{ .name = "CI", .on = empty_trigger, .jobs = &jobs_true, .permissions = Permissions{} };
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
    const wf = Workflow{ .name = "CI", .on = empty_trigger, .jobs = &jobs, .permissions = Permissions{} };
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SEC018"));
}

test "SEC018: both SEC015 and SEC018 fire for same checkout + upload-artifact" {
    const steps = [_]Step{
        .{
            .uses = ActionRef.parse("actions/checkout@v4"),
            .uses_key_col = 8,
            .uses_value_end_byte = 50,
        },
        .{ .uses = ActionRef.parse("actions/upload-artifact@v4") },
    };
    var list = runSteps(&steps);
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SEC015"));
    try testing.expect(hasDiagnostic(&list, "SEC018"));
    const sec015 = findDiagnostic(&list, "SEC015").?;
    const sec018 = findDiagnostic(&list, "SEC018").?;
    try testing.expect(sec015.fix.?.safety == .safe);
    try testing.expect(sec018.fix.?.safety == .unsafe);
}

test "SEC019: secret in run block" {
    var list = runStep(.{ .run = "echo ${{ secrets.MY_TOKEN }}" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC019"));
}

test "SEC019: secret in with value" {
    var with_map = workflow_types.StringMap.init(testing.allocator);
    defer with_map.deinit();
    with_map.put("token", "${{ secrets.DEPLOY_KEY }}") catch unreachable;
    var list = runStep(.{ .with = with_map });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC019"));
}

test "SEC019: secret in env value is allowed" {
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("MY_TOKEN", "${{ secrets.MY_TOKEN }}") catch unreachable;
    var list = runStep(.{ .env = env_map });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC019"));
}

test "SEC019: GITHUB_TOKEN in with is allowed" {
    var with_map = workflow_types.StringMap.init(testing.allocator);
    defer with_map.deinit();
    with_map.put("token", "${{ secrets.GITHUB_TOKEN }}") catch unreachable;
    var list = runStep(.{ .with = with_map });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC019"));
}

test "SEC019: GITHUB_TOKEN in run is allowed" {
    var list = runStep(.{ .run = "echo ${{ secrets.GITHUB_TOKEN }}" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC019"));
}

test "SEC019: no secrets usage" {
    var list = runStep(.{ .run = "echo hello" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC019"));
}

test "SEC019: secret with whitespace in expression" {
    var list = runStep(.{ .run = "echo ${{  secrets.MY_TOKEN  }}" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC019"));
}

test "SEC019: one diagnostic per step" {
    var list = runStep(.{ .run = "${{ secrets.A }} ${{ secrets.B }}" });
    defer list.deinit();
    try testing.expectEqual(@as(usize, 1), countDiagnostics(&list, "SEC019"));
}

test "SEC017: ACTIONS_ALLOW_UNSECURE_COMMANDS in step env" {
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
    var list = runStep(.{ .run = "echo test", .env = env_map, .env_meta = env_meta });
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
    var list = runJob(.{ .id = "build", .env = env_map, .env_meta = env_meta, .permissions = Permissions{} });
    defer list.deinit();
    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    try testing.expect(diag.fix != null);
    try testing.expectEqualStrings("false", diag.fix.?.edits[0].replacement);
    try testing.expectEqual(@as(usize, 20), diag.fix.?.edits[0].start_byte);
}

test "SEC017: ACTIONS_ALLOW_UNSECURE_COMMANDS in workflow env" {
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
        .on = empty_trigger,
        .jobs = &.{},
        .permissions = Permissions{},
        .env = env_map,
        .env_meta = env_meta,
    };
    var list = runWorkflow(wf);
    defer list.deinit();
    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    try testing.expect(diag.fix != null);
    try testing.expectEqualStrings("false", diag.fix.?.edits[0].replacement);
    try testing.expectEqual(@as(usize, 30), diag.fix.?.edits[0].start_byte);
}

test "SEC017: fallback without env metadata keeps diagnostic" {
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("ACTIONS_ALLOW_UNSECURE_COMMANDS", "true") catch unreachable;
    var list = runStep(.{ .run = "echo test", .env = env_map });
    defer list.deinit();

    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    try testing.expect(diag.fix == null);
    try testing.expect(diag.fix_hint != null);
}

test "SEC017: fix preserves single quoted style" {
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
    var list = runStep(.{ .run = "echo test", .env = env_map, .env_meta = env_meta });
    defer list.deinit();

    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    try testing.expect(diag.fix != null);
    try testing.expectEqualStrings("false", diag.fix.?.edits[0].replacement);
    try testing.expectEqual(@as(usize, 41), diag.fix.?.edits[0].start_byte);
    try testing.expectEqual(@as(usize, 45), diag.fix.?.edits[0].end_byte);
}

test "SEC017: fix preserves double quoted style" {
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
    var list = runStep(.{ .run = "echo test", .env = env_map, .env_meta = env_meta });
    defer list.deinit();

    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    try testing.expect(diag.fix != null);
    try testing.expectEqualStrings("false", diag.fix.?.edits[0].replacement);
    try testing.expectEqual(@as(usize, 51), diag.fix.?.edits[0].start_byte);
    try testing.expectEqual(@as(usize, 55), diag.fix.?.edits[0].end_byte);
}

test "SEC017: literal style gets diagnostic without fix" {
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
    var list = runStep(.{ .run = "echo test", .env = env_map, .env_meta = env_meta });
    defer list.deinit();

    const diag = findDiagnostic(&list, "SEC017") orelse return error.TestUnexpectedResult;
    try testing.expect(diag.fix == null);
    try testing.expectEqual(@as(usize, 60), diag.span.start_byte);
}

test "SEC017: value is false (no false positive)" {
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("ACTIONS_ALLOW_UNSECURE_COMMANDS", "false") catch unreachable;
    var list = runStep(.{ .run = "echo test", .env = env_map });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC017"));
}

test "SEC017: key absent (no false positive)" {
    var env_map = workflow_types.StringMap.init(testing.allocator);
    defer env_map.deinit();
    env_map.put("SOME_OTHER_VAR", "true") catch unreachable;
    var list = runStep(.{ .run = "echo test", .env = env_map });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC017"));
}

test "SEC017: no env (no false positive)" {
    var list = runStep(.{ .run = "echo test" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC017"));
}

test "SEC017: integration applies fix to workflow env" {
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

    const wf = try test_support.parseWorkflowSource(alloc, source);

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

    const wf = try test_support.parseWorkflowSource(alloc, source);

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

    const wf = try test_support.parseWorkflowSource(alloc, source);

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

test "BP007: base64 -d piped to bash" {
    var list = runStep(.{ .run = "echo payload | base64 -d | bash" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: base64 --decode piped to sh" {
    var list = runStep(.{ .run = "base64 --decode secret.txt | sh" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: eval with variable expansion" {
    var list = runStep(.{ .run = "eval $CMD" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: eval with quoted variable" {
    var list = runStep(.{ .run = "eval \"$SCRIPT\"" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: eval with braced variable" {
    var list = runStep(.{ .run = "eval ${COMMAND}" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: curl piped to bash" {
    var list = runStep(.{ .run = "curl -s https://example.com/install.sh | bash" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: wget piped to sh" {
    var list = runStep(.{ .run = "wget -qO- https://example.com/setup.sh | sh" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: variable as command at line start" {
    var list = runStep(.{ .run = "export CMD=\"malicious\"\n$CMD" });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on normal command" {
    var list = runStep(.{ .run = "echo hello world" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on base64 decode to file" {
    var list = runStep(.{ .run = "base64 -d file.txt > output.bin" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on eval with literal string" {
    var list = runStep(.{ .run = "eval \"echo hello\"" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on curl saving to file" {
    var list = runStep(.{ .run = "curl -o script.sh https://example.com/script.sh" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on wget download" {
    var list = runStep(.{ .run = "wget https://example.com/file.tar.gz" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on echo with variable" {
    var list = runStep(.{ .run = "echo $VARIABLE" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on npm install" {
    var list = runStep(.{ .run = "npm install" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

test "BP007: no false positive on GitHub Actions expression" {
    var list = runStep(.{ .run = "${{ github.token }}" });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "BP007"));
}

test "SEC020: self-hosted + pull_request + public -> fires" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    var list = runJobOn(pr_trigger, .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} });
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

    var list = runJobOn(pr_trigger, .{ .id = "build", .runs_on = "self-hosted-gpu", .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC020"));
}

test "SEC020: self-hosted + pull_request_target -> fires" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    var list = runJobOn(pr_target_trigger, .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC020"));
}

test "SEC020: self-hosted + issue_comment -> fires" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    var list = runJobOn(issue_comment_trigger, .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC020"));
}

test "SEC020: self-hosted + workflow_run -> fires" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    var list = runJobOn(workflow_run_trigger, .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC020"));
}

test "SEC020: multiple jobs, only self-hosted ones fire" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    const jobs = [_]Job{
        .{ .id = "hosted", .runs_on = "ubuntu-latest", .permissions = Permissions{} },
        .{ .id = "selfa", .runs_on = "self-hosted", .permissions = Permissions{} },
        .{ .id = "selfb", .runs_on = "self-hosted-linux", .permissions = Permissions{} },
    };
    const wf = Workflow{ .name = "CI", .on = pr_trigger, .jobs = &jobs, .permissions = Permissions{} };
    var list = runWorkflow(wf);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 2), countDiagnostics(&list, "SEC020"));
}

test "SEC020: ubuntu-latest + pull_request -> no fire" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    var list = runJobOn(pr_trigger, .{ .id = "build", .runs_on = "ubuntu-latest", .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC020"));
}

test "SEC020: self-hosted + push only -> no fire" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    var list = runJobOn(push_trigger, .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC020"));
}

test "SEC020: self-hosted + workflow_dispatch -> no fire" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    var list = runJobOn(workflow_dispatch_trigger, .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC020"));
}

test "SEC020: repo_visibility private -> suppressed" {
    setRepoVisibility(.private);
    defer setRepoVisibility(.unknown);

    var list = runJobOn(pr_trigger, .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(!hasDiagnostic(&list, "SEC020"));
}

test "SEC020: repo_visibility public -> fires" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    var list = runJobOn(pr_trigger, .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC020"));
}

test "SEC020: repo_visibility unknown default -> fires (fail-safe)" {
    setRepoVisibility(.unknown);
    defer setRepoVisibility(.unknown);

    var list = runJobOn(pr_trigger, .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} });
    defer list.deinit();
    try testing.expect(hasDiagnostic(&list, "SEC020"));
}

test "SEC020: runs_on null (reusable workflow caller) -> no fire" {
    setRepoVisibility(.public);
    defer setRepoVisibility(.unknown);

    var list = runJobOn(pr_trigger, .{ .id = "call", .runs_on = null, .uses = "./.github/workflows/reusable.yml", .permissions = Permissions{} });
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

    var list = runJobOn(pr_trigger, .{ .id = "build", .runs_on = "self-hosted", .permissions = Permissions{} });
    defer list.deinit();

    var remaining: usize = 0;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC020")) {
            if (cfg.isRuleEnabled(d.rule_id)) remaining += 1;
        }
    }
    try testing.expectEqual(@as(usize, 0), remaining);
}

test "SC002: compromised SHA fires error" {
    var list = runStep(.{ .uses = ActionRef.parse("tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67") });
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SC002"));
    const diag = findDiagnostic(&list, "SC002").?;
    try testing.expectEqual(Severity.@"error", diag.severity);
}

test "SC002: compromised tag fires error" {
    var list = runStep(.{ .uses = ActionRef.parse("tj-actions/changed-files@v44") });
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SC002"));
}

test "SC002: same owner/repo with non-compromised SHA does not fire" {
    var list = runStep(.{ .uses = ActionRef.parse("tj-actions/changed-files@1111111111111111111111111111111111111111") });
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC002"));
}

test "SC002: same SHA on different owner/repo does not fire" {
    var list = runStep(.{ .uses = ActionRef.parse("other-owner/other-repo@0e58ed8671d6b60d0890c21b07f8835ace038e67") });
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC002"));
}

test "SC002: local action skipped" {
    var list = runStep(.{ .uses = ActionRef.parse("./local-action") });
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC002"));
}

test "SC002: docker action skipped" {
    var list = runStep(.{ .uses = ActionRef.parse("docker://alpine:latest") });
    defer list.deinit();

    try testing.expect(!hasDiagnostic(&list, "SC002"));
}

test "SC002: uppercase SHA still fires (case-insensitive match)" {
    var list = runStep(.{ .uses = ActionRef.parse("tj-actions/changed-files@0E58ED8671D6B60D0890C21B07F8835ACE038E67") });
    defer list.deinit();

    try testing.expect(hasDiagnostic(&list, "SC002"));
}

test "SEC002: each untrusted reference in a run: block is reported at its own position" {
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

    const wf = try test_support.parseWorkflowSource(alloc, source);

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

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var list = DiagnosticList.init(alloc);
    checkUnpinnedAction(&wf.jobs[0].steps[0], &list);

    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expectEqual(@as(u32, 7), list.get(0).span.start_line);
    try testing.expectEqual(@as(u32, 15), list.get(0).span.start_col);
}
