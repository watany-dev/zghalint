"""Plain scalar round-trip: block-context values must survive flow indicators.

Regression coverage for issue #131 — `,` `[` `]` `{` `}` are YAML indicators
only inside a flow collection.  In block context they belong to the value, so
truncating there silently drops the rest of a `run:` / `if:` expression and the
rules never see it.
"""
from __future__ import annotations

from hypothesis import given, settings, HealthCheck

from tests.pbt.conftest import lint_workflow_json
from tests.pbt.strategies import (
    workflow_with_plain_scalar_run,
    workflow_with_plain_scalar_if,
)

PBT_SETTINGS = settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def _rule_ids(data: dict) -> set[str]:
    return {d["rule_id"] for d in data["diagnostics"]}


@given(content=workflow_with_plain_scalar_run())
@PBT_SETTINGS
def test_plain_run_scalar_read_to_end_of_line(zghalint_bin, content):
    """SEC002 must fire even when flow indicators precede the expression."""
    data = lint_workflow_json(zghalint_bin, content)
    ids = _rule_ids(data)
    assert "SEC002" in ids, (
        f"SEC002 not detected — plain scalar was truncated.\n"
        f"Workflow:\n{content}\n"
        f"Detected rules: {ids}"
    )


@given(content=workflow_with_plain_scalar_if())
@PBT_SETTINGS
def test_plain_if_scalar_keeps_commas(zghalint_bin, content):
    """A comma-separated `if:` call must parse: SEC006 fires, EXPR001 does not."""
    data = lint_workflow_json(zghalint_bin, content)
    ids = _rule_ids(data)
    assert "SEC006" in ids, (
        f"SEC006 not detected — if: condition was truncated.\n"
        f"Workflow:\n{content}\n"
        f"Detected rules: {ids}"
    )
    assert "EXPR001" not in ids, (
        f"EXPR001 false positive from a truncated if: condition.\n"
        f"Workflow:\n{content}"
    )
