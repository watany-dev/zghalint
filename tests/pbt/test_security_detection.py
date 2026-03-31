"""Security rule detection guarantees: known-bad patterns must always be caught."""
from __future__ import annotations

from hypothesis import given, settings, HealthCheck

from tests.pbt.conftest import lint_workflow_json
from tests.pbt.strategies import (
    workflow_with_script_injection,
    workflow_with_unpinned_action,
    workflow_with_hardcoded_secret,
)

PBT_SETTINGS = settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def _rule_ids(data: dict) -> set[str]:
    """Extract the set of rule_ids from JSON lint output."""
    return {d["rule_id"] for d in data["diagnostics"]}


@given(content=workflow_with_script_injection())
@PBT_SETTINGS
def test_script_injection_always_detected(zghalint_bin, content):
    """SEC002 must fire for any workflow containing ${{ <dangerous_context> }} in run:."""
    data = lint_workflow_json(zghalint_bin, content)
    ids = _rule_ids(data)
    assert "SEC002" in ids, (
        f"SEC002 not detected.\n"
        f"Workflow:\n{content}\n"
        f"Detected rules: {ids}"
    )


@given(content=workflow_with_unpinned_action())
@PBT_SETTINGS
def test_unpinned_action_always_detected(zghalint_bin, content):
    """SEC001 must fire for any workflow using a tag-based action reference."""
    data = lint_workflow_json(zghalint_bin, content)
    ids = _rule_ids(data)
    assert "SEC001" in ids, (
        f"SEC001 not detected.\n"
        f"Workflow:\n{content}\n"
        f"Detected rules: {ids}"
    )


@given(content=workflow_with_hardcoded_secret())
@PBT_SETTINGS
def test_hardcoded_secret_always_detected(zghalint_bin, content):
    """SEC003 must fire for any workflow containing a known secret prefix."""
    data = lint_workflow_json(zghalint_bin, content)
    ids = _rule_ids(data)
    assert "SEC003" in ids, (
        f"SEC003 not detected.\n"
        f"Workflow:\n{content}\n"
        f"Detected rules: {ids}"
    )


@given(content=workflow_with_script_injection())
@PBT_SETTINGS
def test_script_injection_severity_is_error(zghalint_bin, content):
    """SEC002 must always be reported at error severity."""
    data = lint_workflow_json(zghalint_bin, content)
    sec002 = [d for d in data["diagnostics"] if d["rule_id"] == "SEC002"]
    assert sec002, "SEC002 not found"
    for d in sec002:
        assert d["severity"] == "error", (
            f"SEC002 severity is {d['severity']}, expected error"
        )


@given(content=workflow_with_hardcoded_secret())
@PBT_SETTINGS
def test_hardcoded_secret_severity_is_error(zghalint_bin, content):
    """SEC003 must always be reported at error severity."""
    data = lint_workflow_json(zghalint_bin, content)
    sec003 = [d for d in data["diagnostics"] if d["rule_id"] == "SEC003"]
    assert sec003, "SEC003 not found"
    for d in sec003:
        assert d["severity"] == "error", (
            f"SEC003 severity is {d['severity']}, expected error"
        )
