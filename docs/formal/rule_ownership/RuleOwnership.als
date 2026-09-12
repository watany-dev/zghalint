/*
 * Ownership of "attacker-controlled checkout input" findings between
 * SEC005 (pull_request_target), SEC009 (workflow_run) and SEC021
 * (dispatch / issue-family triggers), modelled from src/rules/security.zig.
 *
 * Declared specification (docs/rules/SEC005, SEC009, SEC021; issue #138):
 *   S1  every checkout whose `ref` or `repository` is controlled by the actor
 *       who fired a privileged trigger is reported by exactly one rule
 *   S2  SEC021 defers `ref` findings to SEC005 / SEC009 ("owned by the
 *       neighbour rule") so that a step is never reported twice
 *
 * Code-derived specification:
 *   C1  SEC005 = hasEvent(pull_request_target) and `ref` mentions a PR-head
 *       context; SEC009 = hasEvent(workflow_run) and `ref` mentions
 *       github.event.workflow_run.*  (both inspect `ref` only)
 *   C2  SEC021 = some SEC021 trigger present and the value mentions a SEC021
 *       context (github.event.inputs, client_payload, issue/comment text,
 *       bare `inputs` unless workflow_call is declared); it inspects `ref`
 *       and `repository`, one finding per step, and skips `ref` when
 *       ownedByNeighbourRule holds
 *   C3  ownedByNeighbourRule(wf, ref) =
 *         (PRT in events and ref mentions PR-head)
 *       or (workflow_run in events and ref mentions workflow_run.*)
 *
 * Run:  java -jar alloy.jar exec -c '*' -t text -o - RuleOwnership.als
 */
module RuleOwnership

abstract sig Event {}
one sig PullRequestTarget, WorkflowRun, WorkflowDispatch, RepositoryDispatch,
        Issues, IssueComment, Discussion, DiscussionComment, WorkflowCall, Push
        extends Event {}

-- Where a checkout input's value can come from.
abstract sig Source {}
one sig PRHead,          -- github.head_ref, github.event.pull_request.head.*, refs/pull/N/...
        WorkflowRunRef,  -- github.event.workflow_run.*
        DispatchInputs,  -- github.event.inputs.*
        BareInputs,      -- inputs.*
        ClientPayload,   -- github.event.client_payload.*
        IssueText,       -- github.event.issue / comment / discussion text
        Trusted          -- literals, github.sha, ...
        extends Source {}

sig Workflow {
  events: set Event,
  checkouts: set Step
}

sig Step {
  ref: set Source,
  repository: set Source
}

fact stepsBelongToOneWorkflow {
  all s: Step | one w: Workflow | s in w.checkouts
}

-- Which trigger hands the *actor who fired it* control over a source, with a
-- privileged GITHUB_TOKEN (the threat model of the three rules).
fun controlledBy: Source -> Event {
  (PRHead -> PullRequestTarget)
  + (WorkflowRunRef -> WorkflowRun)
  + (DispatchInputs -> WorkflowDispatch)
  + (BareInputs -> WorkflowDispatch)
  + (ClientPayload -> RepositoryDispatch)
  + (IssueText -> (Issues + IssueComment + Discussion + DiscussionComment))
}

pred dangerousValue[w: Workflow, v: set Source] {
  some src: v | some (src.controlledBy & w.events)
}

pred dangerousStep[w: Workflow, s: Step] {
  dangerousValue[w, s.ref] or dangerousValue[w, s.repository]
}

-- ---------------------------------------------------------------------------
-- The rules, as implemented.
-- ---------------------------------------------------------------------------
pred sec005[w: Workflow, s: Step] {
  PullRequestTarget in w.events and PRHead in s.ref
}

pred sec009[w: Workflow, s: Step] {
  WorkflowRun in w.events and WorkflowRunRef in s.ref
}

fun sec021Triggers: set Event {
  WorkflowDispatch + RepositoryDispatch + Issues + IssueComment + Discussion + DiscussionComment
}

fun sec021Contexts[w: Workflow]: set Source {
  (DispatchInputs + ClientPayload + IssueText)
  + (WorkflowCall in w.events implies none else BareInputs)
}

pred ownedByNeighbourRule[w: Workflow, v: set Source] {
     (PullRequestTarget in w.events and PRHead in v)
  or (WorkflowRun in w.events and WorkflowRunRef in v)
}

pred sec021Value[w: Workflow, v: set Source] {
  some (w.events & sec021Triggers) and some (v & sec021Contexts[w])
}

pred sec021[w: Workflow, s: Step] {
     (sec021Value[w, s.ref] and not ownedByNeighbourRule[w, s.ref])
  or sec021Value[w, s.repository]
}

pred reported[w: Workflow, s: Step] {
  sec005[w, s] or sec009[w, s] or sec021[w, s]
}

-- ---------------------------------------------------------------------------
-- Properties
-- ---------------------------------------------------------------------------

-- S1 (coverage): every dangerous checkout is reported by some rule.
assert Coverage {
  all w: Workflow, s: w.checkouts | dangerousStep[w, s] implies reported[w, s]
}

-- S1 (uniqueness): `ref` of a step is reported by at most one rule.
assert RefReportedOnce {
  all w: Workflow, s: w.checkouts |
    not (sec005[w, s] and sec009[w, s])
}

-- S2: whenever SEC021 checkouts back from a `ref`, the neighbour actually reports it.
assert DeferralIsSafe {
  all w: Workflow, s: w.checkouts |
    (sec021Value[w, s.ref] and ownedByNeighbourRule[w, s.ref])
      implies (sec005[w, s] or sec009[w, s])
}

-- No rule fires on a value nobody untrusted controls (no false positive in
-- this abstraction).
assert NoSpuriousReport {
  all w: Workflow, s: w.checkouts | reported[w, s] implies dangerousStep[w, s]
}

check Coverage for 3 but 1 Workflow, 1 Step
check RefReportedOnce for 3 but 1 Workflow, 1 Step
check DeferralIsSafe for 3 but 1 Workflow, 1 Step
check NoSpuriousReport for 3 but 1 Workflow, 1 Step

-- Named gap probes (SAT = the gap exists).
pred GapRepositoryFromPRHead {
  some w: Workflow, s: w.checkouts |
    dangerousStep[w, s] and not reported[w, s]
    and PRHead in s.repository and s.ref in Trusted
}
pred GapRepositoryFromWorkflowRun {
  some w: Workflow, s: w.checkouts |
    dangerousStep[w, s] and not reported[w, s]
    and WorkflowRunRef in s.repository and s.ref in Trusted
}
pred GapBareInputsWithWorkflowCall {
  some w: Workflow, s: w.checkouts |
    dangerousStep[w, s] and not reported[w, s]
    and BareInputs in s.ref and WorkflowCall in w.events
    and s.repository in Trusted
}
-- Any gap other than the three above?
pred GapOther {
  some w: Workflow, s: w.checkouts |
    dangerousStep[w, s] and not reported[w, s]
    and not (PRHead in s.repository)
    and not (WorkflowRunRef in s.repository)
    and not (BareInputs in s.ref and WorkflowCall in w.events)
}

run GapRepositoryFromPRHead for 3 but 1 Workflow, 1 Step
run GapRepositoryFromWorkflowRun for 3 but 1 Workflow, 1 Step
run GapBareInputsWithWorkflowCall for 3 but 1 Workflow, 1 Step
run GapOther for 3 but 1 Workflow, 1 Step
