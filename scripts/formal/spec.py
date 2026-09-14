"""The trust model of GitHub Actions, written down independently of zghalint.

This is the *specification* side of the check in ``model.py``. Nothing here is
derived from ``src/``; every relation is transcribed from GitHub's own
documentation (webhook payloads, "Security hardening for GitHub Actions",
`github.head_ref` availability) and from the untrusted-input lists that
actionlint and zizmor publish. When the two sides disagree the model produces
a counterexample and ``confirm.py`` checks it against the real binary.

Vocabulary
----------
* trigger    — an ``on:`` event name.
* context    — a ``${{ }}`` path. ``.*`` stands for an element of a sequence.
* Author     — who writes the value: ``EXTERNAL`` (any GitHub account, e.g. a
               fork or a drive-by commenter), ``DISPATCHER`` (whoever started
               a dispatched / called run; write access or a caller workflow),
               ``COLLABORATOR`` (write access to the base repository).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Author(Enum):
    EXTERNAL = "external"
    DISPATCHER = "dispatcher"
    COLLABORATOR = "collaborator"


@dataclass(frozen=True)
class Context:
    path: str
    author: Author
    #: Names a commit / ref / repository, i.e. *which code* a checkout fetches.
    ref_shaped: bool = False
    #: Free text a human types (title, body, message, description ...).
    free_text: bool = False
    #: ``ref_shaped``, but only a shell command accepts it as the handle
    #: (``git clone <url>``, ``gh run download <id>``); ``actions/checkout``
    #: has no ``with:`` key for it.
    fetch_only: bool = False


TRIGGERS = [
    "push",
    "pull_request",
    "pull_request_target",
    "pull_request_review",
    "pull_request_review_comment",
    "issues",
    "issue_comment",
    "discussion",
    "discussion_comment",
    "commit_comment",
    "workflow_run",
    "workflow_dispatch",
    "workflow_call",
    "repository_dispatch",
    "schedule",
    "release",
    "gollum",
    "merge_group",
    "fork",
    "watch",
]

#: A run of this trigger gets the base repository's secrets and a
#: ``GITHUB_TOKEN`` that can write (unless ``permissions:`` says otherwise).
#: ``pull_request`` from a fork gets neither, which is the whole point of
#: ``pull_request_target`` existing.
PRIVILEGED = set(TRIGGERS) - {"pull_request"}

#: An account without write access can cause a run of this trigger
#: (by opening a PR / issue / discussion, commenting, forking, starring, ...).
#: ``workflow_run`` inherits it from the upstream ``pull_request`` run.
EXTERNALLY_TRIGGERABLE = {
    "pull_request",
    "pull_request_target",
    "pull_request_review",
    "pull_request_review_comment",
    "issues",
    "issue_comment",
    "discussion",
    "discussion_comment",
    "commit_comment",
    "workflow_run",
    "fork",
    "watch",
}

#: The payload names code that lives in a fork, so a job of this trigger can
#: be talked into checking out (and on a self-hosted runner: executing)
#: a fork's code. ``issue_comment`` qualifies through ``refs/pull/<n>/merge``.
CARRIES_FORK_CODE = {
    "pull_request",
    "pull_request_target",
    "pull_request_review",
    "pull_request_review_comment",
    "issue_comment",
    "workflow_run",
}


E, D, C = Author.EXTERNAL, Author.DISPATCHER, Author.COLLABORATOR


def _ctx(
    path: str, author: Author, *, ref: bool = False, text: bool = False, fetch_only: bool = False
) -> Context:
    return Context(path, author, ref_shaped=ref, free_text=text, fetch_only=fetch_only)


_PR_FIELDS = [
    _ctx("github.event.pull_request.title", E, text=True),
    _ctx("github.event.pull_request.body", E, text=True),
    _ctx("github.event.pull_request.head.ref", E, ref=True, text=True),
    _ctx("github.event.pull_request.head.label", E, ref=True, text=True),
    _ctx("github.event.pull_request.head.sha", E, ref=True),
    _ctx("github.event.pull_request.head.repo.full_name", E, ref=True),
    # `git clone <url>` fetches the fork itself.
    _ctx("github.event.pull_request.head.repo.clone_url", E, ref=True, fetch_only=True),
    _ctx("github.event.pull_request.head.repo.default_branch", E, ref=True, text=True),
    _ctx("github.event.pull_request.head.repo.description", E, text=True),
    _ctx("github.event.pull_request.head.repo.homepage", E, text=True),
    # The merge of the PR head into base: it *contains* the fork's code.
    _ctx("github.event.pull_request.merge_commit_sha", E, ref=True),
    _ctx("github.event.pull_request.number", E, ref=True),
    _ctx("github.event.number", E, ref=True),
    # Labels need triage permission; listed because zghalint lists them and
    # the model must not contradict the implementation on purpose.
    _ctx("github.event.pull_request.labels.*.name", C, text=True),
]

_ISSUE_FIELDS = [
    _ctx("github.event.issue.title", E, text=True),
    _ctx("github.event.issue.body", E, text=True),
    _ctx("github.event.issue.labels.*.name", C, text=True),
]

# `refs/pull/${{ github.event.issue.number }}/merge` is the ChatOps idiom
# that checks out whichever PR the commenter chose. Only `issue_comment`
# fires on a PR; under `issues` the number never names a pull request.
_ISSUE_NUMBER = _ctx("github.event.issue.number", E, ref=True)

_COMMIT_FIELDS = [
    _ctx("github.event.commits.*.message", E, text=True),
    _ctx("github.event.commits.*.author.name", E, text=True),
    _ctx("github.event.commits.*.author.email", E, text=True),
    _ctx("github.event.head_commit.message", E, text=True),
    _ctx("github.event.head_commit.author.name", E, text=True),
    _ctx("github.event.head_commit.author.email", E, text=True),
    _ctx("github.event.head_commit.committer.name", E, text=True),
    _ctx("github.event.head_commit.committer.email", E, text=True),
]

_WORKFLOW_RUN_FIELDS = [
    # The upstream run was the fork's `pull_request` run: its artifacts are
    # whatever the fork's code produced, so the run id picks attacker output
    # the same way a SHA picks attacker code (artifact poisoning).
    _ctx("github.event.workflow_run.id", E, ref=True, fetch_only=True),
    _ctx("github.event.workflow_run.head_branch", E, ref=True, text=True),
    _ctx("github.event.workflow_run.head_sha", E, ref=True),
    _ctx("github.event.workflow_run.head_commit.message", E, text=True),
    _ctx("github.event.workflow_run.head_commit.author.name", E, text=True),
    _ctx("github.event.workflow_run.head_commit.author.email", E, text=True),
    _ctx("github.event.workflow_run.head_commit.committer.name", E, text=True),
    _ctx("github.event.workflow_run.head_commit.committer.email", E, text=True),
    _ctx("github.event.workflow_run.head_repository.description", E, text=True),
    _ctx("github.event.workflow_run.head_repository.full_name", E, ref=True),
    _ctx("github.event.workflow_run.pull_requests.*.head.ref", E, ref=True, text=True),
    _ctx("github.event.workflow_run.display_title", E, text=True),
]

_DISCUSSION_FIELDS = [
    _ctx("github.event.discussion.title", E, text=True),
    _ctx("github.event.discussion.body", E, text=True),
]

_COMMENT = _ctx("github.event.comment.body", E, text=True)
_REVIEW = _ctx("github.event.review.body", E, text=True)
_HEAD_REF = _ctx("github.head_ref", E, ref=True, text=True)
_INPUTS = _ctx("inputs.*", D, ref=True, text=True)
_EVENT_INPUTS = _ctx("github.event.inputs.*", D, ref=True, text=True)
_CLIENT_PAYLOAD = _ctx("github.event.client_payload.*", D, ref=True, text=True)
_PAGES = [
    _ctx("github.event.pages.*.page_name", E, text=True),
    _ctx("github.event.pages.*.title", E, text=True),
]
_RELEASE = [
    _ctx("github.event.release.name", C, text=True),
    _ctx("github.event.release.body", C, text=True),
    _ctx("github.event.release.tag_name", C, ref=True, text=True),
]

#: ``AVAILABLE[t]`` = the contexts the payload of trigger ``t`` fills.
#: ``github.head_ref`` exists only for the two ``pull_request*`` events.
AVAILABLE: dict[str, list[Context]] = {
    "push": _COMMIT_FIELDS,
    "pull_request": _PR_FIELDS + [_HEAD_REF],
    "pull_request_target": _PR_FIELDS + [_HEAD_REF],
    "pull_request_review": _PR_FIELDS + [_REVIEW],
    "pull_request_review_comment": _PR_FIELDS + [_COMMENT],
    "issues": _ISSUE_FIELDS,
    # A comment on a PR also arrives as issue_comment; the payload carries
    # the issue, not the pull request object.
    "issue_comment": _ISSUE_FIELDS + [_ISSUE_NUMBER, _COMMENT],
    "discussion": _DISCUSSION_FIELDS,
    "discussion_comment": _DISCUSSION_FIELDS + [_COMMENT],
    "commit_comment": [_COMMENT],
    "workflow_run": _WORKFLOW_RUN_FIELDS,
    "workflow_dispatch": [_INPUTS, _EVENT_INPUTS],
    "workflow_call": [_INPUTS],
    "repository_dispatch": [_CLIENT_PAYLOAD],
    "schedule": [],
    "release": _RELEASE,
    "gollum": _PAGES,
    "merge_group": [],
    "fork": [],
    "watch": [],
}

CONTEXTS: list[Context] = sorted({c for cs in AVAILABLE.values() for c in cs}, key=lambda c: c.path)
# Two Context objects with one path would give Z3 one symbol with two
# different attribute sets; whichever wins would silently shape the model.
assert len({c.path for c in CONTEXTS}) == len(CONTEXTS), "duplicate context path"


def concrete(path: str) -> str:
    """Turn a spec path into a reference a workflow can contain: sequences get
    an index, open-ended roots get a member name."""
    if path.endswith(".*"):
        return path[:-2] + ".foo"
    return path.replace(".*.", "[0].")


#: Numbers that only become a ref through the `refs/pull/<n>/merge` spelling.
_NUMBER_CONTEXTS = {
    "github.event.issue.number",
    "github.event.pull_request.number",
    "github.event.number",
}

#: Names a repository rather than a ref.
_REPOSITORY_CONTEXTS = {
    "github.event.pull_request.head.repo.full_name",
    "github.event.workflow_run.head_repository.full_name",
}


def checkout_with(path: str) -> str:
    """The `with:` line under `actions/checkout` through which `path` picks
    the code. This is the string the marker rules (SEC005 / SEC009) scan, so
    the model and the generated workflow must agree on it."""
    expr = "${{ " + concrete(path) + " }}"
    if path in _NUMBER_CONTEXTS:
        return f"ref: refs/pull/{expr}/merge"
    if path in _REPOSITORY_CONTEXTS:
        return f"repository: {expr}"
    return f"ref: {expr}"


def fetch_command(path: str) -> str:
    """The shell command through which `path` picks the code when the job
    fetches it itself instead of through `actions/checkout`: the ChatOps
    `gh pr checkout <n>`, `git clone` of the fork, `gh run download` of the
    upstream run's artifact, or a plain `git fetch` of the ref / SHA."""
    expr = "${{ " + concrete(path) + " }}"
    if path in _NUMBER_CONTEXTS:
        return f"gh pr checkout {expr}"
    if path in _REPOSITORY_CONTEXTS:
        return f"git clone https://github.com/{expr} src"
    if path == "github.event.pull_request.head.repo.clone_url":
        return f"git clone {expr} src"
    if path == "github.event.workflow_run.id":
        return f"gh run download {expr} -n build"
    return f"git fetch origin {expr} && git checkout FETCH_HEAD"


SINKS = [
    # Interpolated into a shell script → command injection.
    "run",
    # Written to $GITHUB_ENV / $GITHUB_PATH → env / PATH injection for later steps.
    "github_env",
    # `actions/checkout` `with.ref` / `with.repository` → attacker picks the code.
    "checkout_ref",
    # `if:` gate that attacker-authored text can satisfy on purpose.
    "condition",
    # `git checkout` / `git clone` / `gh pr checkout` / `gh run download`
    # inside `run:` → attacker picks the code, without `actions/checkout`
    # being involved. A SHA or number carries no shell metacharacters, so
    # this is not injection (P1); the fetched code runs in the next step.
    "run_fetch",
    # `with.run-id` of an artifact download in a `workflow_run` job → the
    # upstream (fork) run's artifact is unpacked and used (artifact poisoning).
    "artifact_run_id",
    # An action input the action executes as code (`actions/github-script`
    # `with.script` and the like, see CODE_EXECUTING_INPUTS) → same as `run:`.
    "action_script",
]

#: How a value reaches a sink. ``direct`` is `${{ ctx }}` at the sink itself;
#: the rest are one hop of indirection the runner (or an action) performs.
FLOWS = [
    "direct",
    # `env: {X: ${{ ctx }}}` then `${{ env.X }}` at the sink (not `$X`, which is safe).
    "env_context",
    # `echo "k=${{ ctx }}" >> $GITHUB_OUTPUT` then `${{ steps.id.outputs.k }}`.
    "step_output",
    # job `outputs: {k: ${{ steps.id.outputs.k }}}` then `${{ needs.job.outputs.k }}`.
    "job_output",
    # `uses: ./local` with `with: {k: ${{ ctx }}}`, then `${{ inputs.k }}`
    # in a `run:` of that composite action's `runs.steps`.
    "action_input",
    # An action computes an output from the attacker's payload (the file
    # names of the PR head, the branch name, a comment it looked up) and the
    # workflow interpolates `${{ steps.id.outputs.k }}`; see ACTION_OUTPUTS.
    "action_output",
]


@dataclass(frozen=True)
class CodeInput:
    """An action input that the action executes, so `${{ }}` inside it is
    script injection exactly as in `run:`. From zizmor's template-injection
    audit and each action's own README."""

    action: str
    input: str
    #: What the input is fed to.
    runtime: str

    @property
    def key(self) -> str:
        return f"{self.action}#{self.input}"


CODE_EXECUTING_INPUTS = [
    CodeInput("actions/github-script", "script", "node (JavaScript)"),
    CodeInput("azure/cli", "inlineScript", "bash / pwsh with the Azure CLI"),
    CodeInput("azure/powershell", "inlineScript", "pwsh with the Az module"),
    CodeInput("nick-fields/retry", "command", "the runner shell"),
    CodeInput("addnab/docker-run-action", "run", "a shell inside the container"),
    CodeInput("appleboy/ssh-action", "script", "a shell on the SSH host"),
    CodeInput("jannekem/run-python-script-action", "script", "python"),
]


@dataclass(frozen=True)
class ActionOutput:
    """A step output an action derives from attacker-authored content. The
    value never appears as a `${{ github.* }}` context in the workflow, so
    a taint table keyed by context path cannot see it; the action itself is
    the source. `source` names the payload field the output is a function
    of and `trigger` a privileged trigger under which that field is the
    attacker's."""

    action: str
    output: str
    source: str
    trigger: str

    @property
    def key(self) -> str:
        return f"{self.action}#{self.output}"


_PR_HEAD_SHA = "github.event.pull_request.head.sha"

ACTION_OUTPUTS = [
    # File names in the PR head; CVE-2023-51664 was this in the action itself.
    ActionOutput(
        "tj-actions/changed-files", "all_changed_files", _PR_HEAD_SHA, "pull_request_target"
    ),
    ActionOutput(
        "step-security/changed-files", "all_changed_files", _PR_HEAD_SHA, "pull_request_target"
    ),
    ActionOutput("jitterbit/get-changed-files", "all", _PR_HEAD_SHA, "pull_request_target"),
    # The PR head branch name, i.e. `github.head_ref` by another route.
    ActionOutput(
        "tj-actions/branch-names", "head_ref_branch", "github.head_ref", "pull_request_target"
    ),
    # The body of a comment the action looked up.
    ActionOutput(
        "peter-evans/find-comment", "comment-body", "github.event.comment.body", "issue_comment"
    ),
]

for _ao in ACTION_OUTPUTS:
    assert _ao.source in {c.path for c in AVAILABLE[_ao.trigger]}, _ao
    assert _ao.trigger in PRIVILEGED, _ao

#: Action sort of the model: the union of both tables plus ``NO_ACTION`` for
#: the properties that are not about an action.
NO_ACTION = "-"
ACTIONS = [NO_ACTION] + [ci.key for ci in CODE_EXECUTING_INPUTS] + [ao.key for ao in ACTION_OUTPUTS]
assert len(set(ACTIONS)) == len(ACTIONS), "duplicate action key"
