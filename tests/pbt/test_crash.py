"""Crash resistance: zghalint must never signal-terminate on any input."""
from __future__ import annotations

import os
import tempfile

from hypothesis import given, settings, HealthCheck

from tests.pbt.conftest import run_zghalint
from tests.pbt.strategies import (
    random_bytes,
    random_text,
    yaml_like_text,
    expression_text,
)

# Subprocess-based tests: disable deadline, moderate example count.
PBT_SETTINGS = settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

# Exit codes 0 (ok), 1 (lint errors), 2 (operational error) are all valid.
# Only signal termination (negative) indicates a crash.
VALID_EXIT_CODES = {0, 1, 2}


def _assert_no_crash(result, context: str = "") -> None:
    assert result.returncode in VALID_EXIT_CODES, (
        f"Crash detected ({context}): "
        f"returncode={result.returncode}, "
        f"stderr={result.stderr[:500]}"
    )


def _write_and_lint(binary, data: bytes | str, suffix: str = ".yml"):
    mode = "wb" if isinstance(data, bytes) else "w"
    with tempfile.NamedTemporaryFile(suffix=suffix, mode=mode, delete=False) as f:
        f.write(data)
        path = f.name
    try:
        return run_zghalint(binary, path)
    finally:
        os.unlink(path)


@given(data=random_bytes)
@PBT_SETTINGS
def test_no_crash_on_arbitrary_bytes(zghalint_bin, data):
    """Arbitrary byte sequences must not crash the linter."""
    result = _write_and_lint(zghalint_bin, data)
    _assert_no_crash(result, "arbitrary bytes")


@given(data=random_text)
@PBT_SETTINGS
def test_no_crash_on_random_text(zghalint_bin, data):
    """Random UTF-8 text must not crash the linter."""
    result = _write_and_lint(zghalint_bin, data)
    _assert_no_crash(result, "random text")


@given(data=yaml_like_text)
@PBT_SETTINGS
def test_no_crash_on_yaml_like_input(zghalint_bin, data):
    """YAML-like structural fragments must not crash the linter."""
    result = _write_and_lint(zghalint_bin, data)
    _assert_no_crash(result, "yaml-like text")


@given(expr=expression_text)
@PBT_SETTINGS
def test_no_crash_on_expression_in_workflow(zghalint_bin, expr):
    """Arbitrary strings inside ${{ }} must not crash the linter."""
    safe_expr = expr.replace("\\", "\\\\").replace('"', '\\"')
    workflow = (
        "name: test\n"
        "on: push\n"
        "jobs:\n"
        "  j:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f'      - run: echo "${{{{ {safe_expr} }}}}"\n'
    )
    result = _write_and_lint(zghalint_bin, workflow)
    _assert_no_crash(result, f"expression: {safe_expr[:80]}")
