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


def _marker_fn(source: str, name: str) -> list[str]:
    return _nonempty(_STRING.findall(_block(source, f"fn {name}(value: []const u8) bool {{", "});")), name)


def _switch_true_arms(source: str, name: str) -> list[str]:
    body = _block(source, f"fn {name}(wf: *const Workflow) bool {{", "=> return true")
    return _nonempty(re.findall(r"\.(\w+),", body[body.index("switch") :]), name)


def _trigger_table(source: str) -> dict[str, list[str]]:
    body = _block(source, "const trigger_context_table = [_]TriggerContexts{")
    entries = re.findall(r"\.event\s*=\s*\.(\w+),\s*\.contexts\s*=\s*&\.\{([^}]*)\}", body)
    return _nonempty({event: _STRING.findall(contexts) for event, contexts in entries}, "trigger_context_table")


@dataclass(frozen=True)
class Impl:
    #: SEC002 (`run:` / github-script) and SEC008 ($GITHUB_ENV): segment-prefix table.
    run_dangerous: list[str]
    #: SEC002 only, and only when `workflow_dispatch` / `workflow_call` is declared.
    dispatched_inputs: list[str]
    #: SEC006: `if:` conditions.
    condition_dangerous: list[str]
    #: SEC022: `if:` gates of a `workflow_run` job.
    workflow_run_gate: list[str]
    #: SEC005 markers (substring), active when `pull_request_target` is declared.
    pr_head_markers: list[str]
    #: SEC009 markers (substring), active when `workflow_run` is declared.
    workflow_run_markers: list[str]
    #: SEC021: contexts owned per declared trigger (segment-prefix).
    trigger_contexts: dict[str, list[str]]
    #: SEC020: triggers a fork can reach.
    fork_accessible_triggers: list[str]
    #: Flows SEC002 follows (see spec.FLOWS). Fixed by construction of
    #: `checkScriptInjection`: direct use, and a step output written on the
    #: same line as the tainted expression.
    followed_flows: list[str] = field(default_factory=lambda: ["direct", "step_output"])


def load() -> Impl:
    sec = SECURITY_ZIG.read_text()
    return Impl(
        run_dangerous=_string_table(sec, "run_dangerous_contexts"),
        dispatched_inputs=_string_table(sec, "dispatched_inputs_contexts"),
        condition_dangerous=_string_table(sec, "condition_dangerous_contexts"),
        workflow_run_gate=_string_table(sec, "workflow_run_untrusted_gate_contexts"),
        pr_head_markers=_marker_fn(sec, "isPRHeadValue"),
        workflow_run_markers=_marker_fn(sec, "isWorkflowRunValue"),
        trigger_contexts=_trigger_table(sec),
        fork_accessible_triggers=_switch_true_arms(sec, "hasForkAccessibleTrigger"),
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
        for s, p in zip(path_segs, pat_segs)
    )


def matches_any_prefix(path: str, table: list[str]) -> bool:
    return any(matches_prefix(path, pattern) for pattern in table)


def matches_marker(value: str, markers: list[str]) -> bool:
    """`containsAnyMarker`: plain substring search on the `with:` value."""
    return any(marker in value for marker in markers)


if __name__ == "__main__":
    import json
    from dataclasses import asdict

    print(json.dumps(asdict(load()), indent=2))
