"""The implementation side: zghalint's context tables, read out of the source.

``model.py`` compares ``spec.py`` against *these* relations, so they are
extracted from ``src/rules/security.zig`` at run time rather than copied by
hand. A rule change that edits a table changes the model on the next run; a
table the extractor no longer finds is an error, not a silent empty set.

Only the shape of each table is assumed (``const NAME = [_][]const u8{ ... };``
and friends). The matching semantics — segment-prefix matching for context
tables, substring matching for the ``refs/pull/`` style markers — are mirrored
in ``matches_prefix`` / ``matches_marker`` from ``pathMatchesPattern`` and
``containsAnyMarker``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SECURITY_ZIG = PROJECT_ROOT / "src" / "rules" / "security.zig"

_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
_LINE_COMMENT = re.compile(r"//[^\n]*")


def _block(source: str, start: str, end: str = "};") -> str:
    begin = source.find(start)
    if begin < 0:
        raise LookupError(f"{start!r} not found; the extractor is out of date")
    stop = source.find(end, begin)
    if stop < 0:
        raise LookupError(f"unterminated block starting at {start!r}")
    return _LINE_COMMENT.sub("", source[begin:stop])


def _nonempty(found, what: str):
    if not found:
        raise LookupError(f"{what} extracted nothing; the extractor is out of date")
    return found


def _string_table(source: str, name: str) -> list[str]:
    return _nonempty(_STRING.findall(_block(source, f"const {name} = [_][]const u8{{")), name)


def _probe_string_table(source: str, name: str) -> list[str]:
    """A table for a rule that does not exist yet. Absent is *not* an error:
    the witnesses an empty probe leaves are the open issues. Once the rule
    lands under this name the probe becomes a real table; if it lands under
    another name, `confirm.py` shows the witness as `covered` while
    `model.py` still lists it — the cue to rename the probe."""
    try:
        return _STRING.findall(_block(source, f"const {name} = [_][]const u8{{"))
    except LookupError:
        return []


def _code_executing_inputs(source: str) -> dict[str, list[str]]:
    """`code_executing_inputs`: action → the `with:` keys it executes as code."""
    body = _block(source, "const code_executing_inputs = [_]CodeExecutingInput{")
    entries = re.findall(r'\.action\s*=\s*"([^"]+)"\s*,\s*\.input\s*=\s*"([^"]+)"', body)
    found: dict[str, list[str]] = {}
    for action, input_name in entries:
        found.setdefault(action, []).append(input_name)
    return _nonempty(found, "code_executing_inputs")


def _sec025_actions(source: str) -> list[str]:
    """Probe: actions SEC025 names. Absent is empty, not an error."""
    if not re.search(r'\.id = "SEC025"', source):
        return []
    found = re.findall(r'isAction\(ref, "([^"]+)"\)', source)
    return [name for name in found if name.endswith("create-github-app-token")]


def _marker_fn(source: str, name: str) -> list[str]:
    return _nonempty(
        _STRING.findall(_block(source, f"fn {name}(value: []const u8) bool {{", "});")), name
    )


def _switch_true_arms(source: str, name: str) -> list[str]:
    body = _block(source, f"fn {name}(wf: *const Workflow) bool {{", "=> return true")
    return _nonempty(re.findall(r"\.(\w+),", body[body.index("switch") :]), name)


def _event_type_table(source: str, name: str) -> list[str]:
    return _nonempty(re.findall(r"\.(\w+)", _block(source, f"const {name} = [_]EventType{{")), name)


def _trigger_table(source: str, name: str) -> dict[str, list[str]]:
    body = _block(source, f"const {name} = [_]TriggerContexts{{")
    entries = re.findall(r"\.event\s*=\s*\.(\w+),\s*\.contexts\s*=\s*&\.\{([^}]*)\}", body)
    return _nonempty({event: _STRING.findall(contexts) for event, contexts in entries}, name)


def _merge_trigger_tables(*tables: dict[str, list[str]]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for table in tables:
        for event, contexts in table.items():
            merged.setdefault(event, []).extend(contexts)
    return merged


@dataclass(frozen=True)
class Impl:
    #: SEC002 (`run:` / github-script) and SEC008 ($GITHUB_ENV): segment-prefix table.
    run_dangerous: list[str]
    #: Bare `inputs.*`, added to the taint table when `workflow_dispatch` /
    #: `workflow_call` is declared (`runTaintContexts`).
    bare_inputs: list[str]
    #: Payload roots a dispatching caller fills, keyed by trigger. Shared by
    #: SEC002 / SEC008 (`runTaintContexts`) and SEC021 (`trigger_context_table`).
    dispatch_payload: dict[str, list[str]]
    #: SEC006: `if:` conditions.
    condition_dangerous: list[str]
    #: SEC022: `if:` gates of a `workflow_run` job.
    workflow_run_gate: list[str]
    #: SEC005 markers (substring), active when a privileged PR-head trigger
    #: is declared (`privileged_pr_head_events`).
    pr_head_markers: list[str]
    #: SEC005: triggers that run privileged while carrying `pull_request.head`.
    privileged_pr_head: list[str]
    #: SEC009 markers (substring), active when `workflow_run` is declared.
    workflow_run_markers: list[str]
    #: SEC021: contexts owned per declared trigger (segment-prefix).
    trigger_contexts: dict[str, list[str]]
    #: SEC020: triggers a fork can reach.
    fork_accessible_triggers: list[str]
    #: SEC002 on action inputs executed as code: action → inputs
    #: (`checkScriptInputInjection`).
    code_executing_inputs: dict[str, list[str]]
    #: Flows SEC002 follows (see spec.FLOWS). `checkScriptInjection` walks
    #: `env:` keys, step outputs, and job outputs as well as the direct use
    #: (#314). Job outputs are a fixed-point, so a re-export through a second
    #: job is `job_output_2hop` (#564). Also: outputs of actions that echo
    #: attacker content (`action_output`, #535), and a local composite
    #: action's interpolated `inputs.*` (`action_input`, #536).
    followed_flows: list[str] = field(
        default_factory=lambda: [
            "direct",
            "step_output",
            "env_context",
            "job_output",
            "job_output_2hop",
            "action_output",
            "action_input",
        ]
    )
    #: Probes (`_probe_string_table`): rules the specification asks for that
    #: have no table yet. Names are placeholders to rename when the rule lands.
    #: Contexts a `git` / `gh` fetch inside `run:` may not take (spec sink `run_fetch`).
    shell_fetch_contexts: list[str] = field(default_factory=list)
    #: Contexts an artifact download's `run-id` may not take (spec sink `artifact_run_id`).
    artifact_run_id_contexts: list[str] = field(default_factory=list)
    #: Actions whose outputs SEC002 treats as attacker text (spec.ACTION_OUTPUTS).
    untrusted_output_actions: list[str] = field(default_factory=list)
    #: Actions SEC025 flags when `permission-*` is missing. Empty until the
    #: rule lands (B1 #552).
    github_app_token_actions: list[str] = field(default_factory=list)


def load() -> Impl:
    sec = SECURITY_ZIG.read_text()
    dispatch_payload = _trigger_table(sec, "dispatch_payload_table")
    attacker_text = _trigger_table(sec, "attacker_text_table")
    return Impl(
        run_dangerous=_string_table(sec, "run_dangerous_contexts"),
        bare_inputs=_string_table(sec, "bare_inputs_contexts"),
        dispatch_payload=dispatch_payload,
        condition_dangerous=_string_table(sec, "condition_dangerous_contexts"),
        workflow_run_gate=_string_table(sec, "workflow_run_untrusted_gate_contexts"),
        pr_head_markers=_marker_fn(sec, "isPRHeadValue"),
        privileged_pr_head=_event_type_table(sec, "privileged_pr_head_events"),
        workflow_run_markers=_marker_fn(sec, "isWorkflowRunValue"),
        trigger_contexts=_merge_trigger_tables(dispatch_payload, attacker_text),
        fork_accessible_triggers=_switch_true_arms(sec, "hasForkAccessibleTrigger"),
        code_executing_inputs=_code_executing_inputs(sec),
        shell_fetch_contexts=_probe_string_table(sec, "shell_fetch_contexts"),
        artifact_run_id_contexts=_probe_string_table(sec, "artifact_run_id_contexts"),
        untrusted_output_actions=_probe_string_table(sec, "untrusted_output_actions"),
        github_app_token_actions=_sec025_actions(sec),
    )


def matches_prefix(path: str, pattern: str) -> bool:
    """`pathMatchesPattern`: every pattern segment matches the path segment at
    the same index; `*` matches anything; the pattern may be shorter."""
    path_segs = path.split(".")
    pat_segs = pattern.split(".")
    if len(pat_segs) > len(path_segs):
        return False
    return all(
        p == "*" or s == "*" or p.lower() == s.lower()
        for s, p in zip(path_segs, pat_segs, strict=False)
    )


def matches_any_prefix(path: str, table: list[str]) -> bool:
    return any(matches_prefix(path, pattern) for pattern in table)


def matches_marker(value: str, markers: list[str]) -> bool:
    """`containsAnyMarker`: plain substring search on the `with:` value."""
    return any(marker in value for marker in markers)


def matches_action(name: str, table: list[str]) -> bool:
    """`isAction`: `owner/repo` compared case-insensitively."""
    return name.lower() in {entry.lower() for entry in table}


if __name__ == "__main__":
    import json
    from dataclasses import asdict

    print(json.dumps(asdict(load()), indent=2))
