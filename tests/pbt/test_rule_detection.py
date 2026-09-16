"""PERM / BP / PERF detection guarantees: known-bad patterns must always be caught."""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings

from tests.pbt.conftest import lint_workflow_json
from tests.pbt.strategies import (
    workflow_with_bp004,
    workflow_with_bp005,
    workflow_with_perf001_setup_go,
    workflow_with_perm001_individual_write,
    workflow_with_perm002,
)

PBT_SETTINGS = settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def _rule_ids(data: dict) -> set[str]:
    return {d["rule_id"] for d in data["diagnostics"]}


@given(content=workflow_with_perm001_individual_write())
@PBT_SETTINGS
def test_perm001_always_detected(zghalint_bin, content):
    """PERM001 must fire when a privilege-escalating scope is set to write."""
    ids = _rule_ids(lint_workflow_json(zghalint_bin, content))
    assert "PERM001" in ids, f"PERM001 not detected.\nWorkflow:\n{content}\nDetected: {ids}"


@given(content=workflow_with_perm002())
@PBT_SETTINGS
def test_perm002_always_detected(zghalint_bin, content):
    """PERM002 must fire when a job using a third-party action omits permissions."""
    ids = _rule_ids(lint_workflow_json(zghalint_bin, content))
    assert "PERM002" in ids, f"PERM002 not detected.\nWorkflow:\n{content}\nDetected: {ids}"


@given(content=workflow_with_bp004())
@PBT_SETTINGS
def test_bp004_always_detected(zghalint_bin, content):
    """BP004 must fire for a Windows `run:` step without `shell:`."""
    ids = _rule_ids(lint_workflow_json(zghalint_bin, content))
    assert "BP004" in ids, f"BP004 not detected.\nWorkflow:\n{content}\nDetected: {ids}"


@given(content=workflow_with_bp005())
@PBT_SETTINGS
def test_bp005_always_detected(zghalint_bin, content):
    """BP005 must fire for a push workflow without concurrency."""
    ids = _rule_ids(lint_workflow_json(zghalint_bin, content))
    assert "BP005" in ids, f"BP005 not detected.\nWorkflow:\n{content}\nDetected: {ids}"


@given(content=workflow_with_perf001_setup_go())
@PBT_SETTINGS
def test_perf001_always_detected(zghalint_bin, content):
    """PERF001 must fire for setup-go without cache."""
    ids = _rule_ids(lint_workflow_json(zghalint_bin, content))
    assert "PERF001" in ids, f"PERF001 not detected.\nWorkflow:\n{content}\nDetected: {ids}"
