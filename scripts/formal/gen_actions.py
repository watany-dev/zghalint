"""Build spec.CODE_EXECUTING_INPUTS from popular_actions.zig.

The popular snapshot is data, not a rule table, so the specification may
read it. Actions zizmor names that the snapshot does not carry stay here
as extras — still not copied from security.zig.
"""

from __future__ import annotations

import re
from pathlib import Path

FORMAL_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = FORMAL_DIR.parents[1]
POPULAR_ACTIONS = PROJECT_ROOT / "src" / "rules" / "data" / "popular_actions.zig"

CODE_INPUT_NAMES = frozenset({"script", "inlineScript", "command"})

# zizmor template-injection audit; not in popular_actions.zig.
_EXTRA = [
    ("azure/cli", "inlineScript", "bash / pwsh with the Azure CLI"),
    ("azure/powershell", "inlineScript", "pwsh with the Az module"),
    ("nick-fields/retry", "command", "the runner shell"),
    ("addnab/docker-run-action", "run", "a shell inside the container"),
    ("appleboy/ssh-action", "script", "a shell on the SSH host"),
    ("jannekem/run-python-script-action", "script", "python"),
]


def _runtime_of(using: str) -> str:
    if using.startswith("node"):
        return f"{using} (JavaScript)"
    return using


def popular_code_inputs(source: str) -> list[tuple[str, str, str]]:
    """(owner/repo, input, runtime) for code-executing inputs in the snapshot."""
    owner = repo = using = None
    found: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in source.splitlines():
        stripped = line.strip()
        if m := re.search(r'\.owner = "([^"]+)"', stripped):
            owner, repo, using = m.group(1), None, None
            continue
        if m := re.search(r'\.repo = "([^"]+)"', stripped):
            repo = m.group(1)
            continue
        if m := re.search(r'\.using = "([^"]+)"', stripped):
            using = m.group(1)
            continue
        if owner is None or repo is None or using is None:
            continue
        if m := re.search(r'\.name = "([^"]+)"', stripped):
            name = m.group(1)
            if name not in CODE_INPUT_NAMES:
                continue
            key = (f"{owner}/{repo}", name)
            if key in seen:
                continue
            seen.add(key)
            found.append((key[0], name, _runtime_of(using)))
    return found


def load_code_executing_rows() -> list[tuple[str, str, str]]:
    popular = popular_code_inputs(POPULAR_ACTIONS.read_text())
    seen = {(a, i) for a, i, _ in popular}
    rows = list(popular)
    for action, input_name, runtime in _EXTRA:
        if (action, input_name) in seen:
            continue
        rows.append((action, input_name, runtime))
    rows.sort(key=lambda r: (r[0], r[1]))
    return rows
