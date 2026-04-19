"""Auto-fix idempotency: applying --fix and re-linting must reduce fixable diagnostics."""
from __future__ import annotations

import os
import tempfile

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from tests.pbt.conftest import run_zghalint, write_temp_workflow
from tests.pbt.strategies import (
    dependabot_with_dep001,
    workflow_with_bp005,
    workflow_with_perm002,
    workflow_yaml,
)

PBT_SETTINGS = settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def _count_diagnostics_json(binary, path: str) -> tuple[int, set[str]]:
    """Lint a file with JSON output and return (count, set_of_rule_ids)."""
    import json
    result = run_zghalint(binary, "--format", "json", "--color", "never", path)
    if not result.stdout.strip():
        return 0, set()
    data = json.loads(result.stdout)
    rule_ids = {d["rule_id"] for d in data["diagnostics"]}
    return len(data["diagnostics"]), rule_ids


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_fix_reduces_diagnostics(zghalint_bin, content):
    """After --fix, re-linting must not show more diagnostics than before."""
    # Write to a temp file (we need it to survive --fix rewriting)
    path = write_temp_workflow(content)
    try:
        # 1) Baseline lint
        count_before, _ = _count_diagnostics_json(zghalint_bin, path)

        # 2) Apply safe fixes (this rewrites the file in place)
        run_zghalint(zghalint_bin, "--fix", path)

        # 3) Re-lint the fixed file
        count_after, _ = _count_diagnostics_json(zghalint_bin, path)

        assert count_after <= count_before, (
            f"--fix increased diagnostics: {count_before} → {count_after}"
        )
    finally:
        os.unlink(path)


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_double_fix_is_idempotent(zghalint_bin, content):
    """Applying --fix twice must produce the same file content as applying once."""
    path = write_temp_workflow(content)
    try:
        # First fix
        run_zghalint(zghalint_bin, "--fix", path)
        with open(path) as f:
            after_first = f.read()

        # Second fix
        run_zghalint(zghalint_bin, "--fix", path)
        with open(path) as f:
            after_second = f.read()

        assert after_first == after_second, (
            "Double --fix produced different content.\n"
            f"After 1st fix:\n{after_first[:500]}\n\n"
            f"After 2nd fix:\n{after_second[:500]}"
        )
    finally:
        os.unlink(path)


@pytest.mark.xfail(
    reason="Known bug: fix/engine.zig segfaults on some generated workflows",
    strict=False,
)
@given(content=workflow_yaml())
@PBT_SETTINGS
def test_fix_does_not_crash(zghalint_bin, content):
    """--fix must never crash (signal-terminate)."""
    path = write_temp_workflow(content)
    try:
        result = run_zghalint(zghalint_bin, "--fix", path)
        assert result.returncode >= 0, (
            f"--fix signal-terminated: returncode={result.returncode}, "
            f"stderr={result.stderr[:300]}"
        )
    finally:
        os.unlink(path)


# ============================================================
# Phase 2 unsafe-fix coverage: BP005 / PERM002 / DEP001
# ============================================================


def _write_temp_dependabot(content: str) -> str:
    """Write dependabot content to a temp file whose name ends in 'dependabot.yml'.

    zghalint dispatches to the dependabot ruleset only when the filename ends
    with 'dependabot.yml' or 'dependabot.yaml' (see src/main.zig:isDependabotFile).
    """
    dir_path = tempfile.mkdtemp()
    path = os.path.join(dir_path, "dependabot.yml")
    with open(path, "w") as f:
        f.write(content)
    return path


def _cleanup_dependabot(path: str) -> None:
    os.unlink(path)
    os.rmdir(os.path.dirname(path))


@given(content=st.one_of(
    workflow_with_bp005(),
    workflow_with_perm002(),
))
@PBT_SETTINGS
def test_unsafe_fix_reduces_diagnostics_workflow(zghalint_bin, content):
    """After --fix-unsafe, re-linting a workflow must not show more diagnostics."""
    path = write_temp_workflow(content)
    try:
        count_before, _ = _count_diagnostics_json(zghalint_bin, path)
        run_zghalint(zghalint_bin, "--fix-unsafe", path)
        count_after, _ = _count_diagnostics_json(zghalint_bin, path)

        assert count_after <= count_before, (
            f"--fix-unsafe increased diagnostics: {count_before} → {count_after}"
        )
    finally:
        os.unlink(path)


@given(content=dependabot_with_dep001())
@PBT_SETTINGS
def test_unsafe_fix_reduces_diagnostics_dependabot(zghalint_bin, content):
    """After --fix-unsafe, re-linting a dependabot file must not show more diagnostics."""
    path = _write_temp_dependabot(content)
    try:
        count_before, _ = _count_diagnostics_json(zghalint_bin, path)
        run_zghalint(zghalint_bin, "--fix-unsafe", path)
        count_after, _ = _count_diagnostics_json(zghalint_bin, path)

        assert count_after <= count_before, (
            f"--fix-unsafe increased diagnostics: {count_before} → {count_after}"
        )
    finally:
        _cleanup_dependabot(path)


@given(content=st.one_of(
    workflow_with_bp005(),
    workflow_with_perm002(),
))
@PBT_SETTINGS
def test_double_unsafe_fix_is_idempotent_workflow(zghalint_bin, content):
    """Applying --fix-unsafe twice must produce the same file content as applying once."""
    path = write_temp_workflow(content)
    try:
        run_zghalint(zghalint_bin, "--fix-unsafe", path)
        with open(path) as f:
            after_first = f.read()

        run_zghalint(zghalint_bin, "--fix-unsafe", path)
        with open(path) as f:
            after_second = f.read()

        assert after_first == after_second, (
            "Double --fix-unsafe produced different content.\n"
            f"After 1st fix:\n{after_first[:500]}\n\n"
            f"After 2nd fix:\n{after_second[:500]}"
        )
    finally:
        os.unlink(path)


@given(content=dependabot_with_dep001())
@PBT_SETTINGS
def test_double_unsafe_fix_is_idempotent_dependabot(zghalint_bin, content):
    """Applying --fix-unsafe twice on a dependabot file must be idempotent."""
    path = _write_temp_dependabot(content)
    try:
        run_zghalint(zghalint_bin, "--fix-unsafe", path)
        with open(path) as f:
            after_first = f.read()

        run_zghalint(zghalint_bin, "--fix-unsafe", path)
        with open(path) as f:
            after_second = f.read()

        assert after_first == after_second, (
            "Double --fix-unsafe on dependabot produced different content.\n"
            f"After 1st fix:\n{after_first[:500]}\n\n"
            f"After 2nd fix:\n{after_second[:500]}"
        )
    finally:
        _cleanup_dependabot(path)


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_fixed_file_is_still_parseable(zghalint_bin, content):
    """After --fix, the output file must still be lint-able (no crash)."""
    path = write_temp_workflow(content)
    try:
        run_zghalint(zghalint_bin, "--fix", path)
        # Re-lint should not crash
        result = run_zghalint(zghalint_bin, "--format", "json", "--color", "never", path)
        assert result.returncode >= 0, (
            f"Re-lint after --fix signal-terminated: returncode={result.returncode}"
        )
    finally:
        os.unlink(path)
