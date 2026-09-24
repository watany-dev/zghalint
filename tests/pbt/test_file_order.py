"""Lint results must not depend on the order of file arguments."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, given, settings

from tests.pbt.conftest import run_zghalint
from tests.pbt.strategies import workflow_yaml

PBT_SETTINGS = settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def _diag_keys(stdout: str) -> list[tuple[str, int, int, str]]:
    data = json.loads(stdout)
    return sorted(
        (Path(d["file"]).name, d["line"], d["column"], d["rule_id"]) for d in data["diagnostics"]
    )


@given(left=workflow_yaml(), right=workflow_yaml())
@PBT_SETTINGS
def test_file_argument_order_does_not_change_diagnostics(zghalint_bin, left, right):
    """Linting A then B yields the same findings as B then A."""
    with tempfile.TemporaryDirectory() as tmp:
        a = Path(tmp) / "a.yml"
        b = Path(tmp) / "b.yml"
        a.write_text(left)
        b.write_text(right)
        first = run_zghalint(zghalint_bin, "--format", "json", "--color", "never", str(a), str(b))
        second = run_zghalint(zghalint_bin, "--format", "json", "--color", "never", str(b), str(a))
        assert first.returncode == second.returncode
        assert _diag_keys(first.stdout) == _diag_keys(second.stdout), (
            f"file order changed diagnostics\nA then B: {_diag_keys(first.stdout)}\n"
            f"B then A: {_diag_keys(second.stdout)}"
        )
