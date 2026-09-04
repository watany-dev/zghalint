"""Monotonicity: more issues in the input → diagnostic count does not decrease.
Also: disabling rules via config never increases diagnostic count."""
from __future__ import annotations

import os

from hypothesis import given, settings, HealthCheck, assume

from tests.pbt.conftest import (
    lint_workflow_json,
    write_temp_workflow,
    write_temp_config,
    run_zghalint,
)
from tests.pbt.strategies import (
    workflow_yaml,
    workflow_pair_monotonic,
)

PBT_SETTINGS = settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


@given(pair=workflow_pair_monotonic())
@PBT_SETTINGS
def test_adding_issues_does_not_decrease_diagnostics(zghalint_bin, pair):
    """Appending jobs with known issues must yield >= base diagnostic count."""
    base_content, extended_content = pair

    base_data = lint_workflow_json(zghalint_bin, base_content)
    extended_data = lint_workflow_json(zghalint_bin, extended_content)

    base_count = len(base_data["diagnostics"])
    extended_count = len(extended_data["diagnostics"])

    assert extended_count >= base_count, (
        f"Monotonicity violated: base={base_count}, extended={extended_count}\n"
        f"Base:\n{base_content}\n\n"
        f"Extended:\n{extended_content}"
    )


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_disabling_rule_does_not_increase_diagnostics(zghalint_bin, content):
    """Disabling any single rule via config must not increase total diagnostics."""
    # Run without config
    baseline = lint_workflow_json(zghalint_bin, content)
    baseline_count = len(baseline["diagnostics"])

    # Skip if no diagnostics (nothing to disable)
    assume(baseline_count > 0)

    # Pick a rule to disable
    rule_to_disable = baseline["diagnostics"][0]["rule_id"]

    # Run with config that disables that rule
    config_path = write_temp_config({rule_to_disable: {"enabled": False}})
    wf_path = write_temp_workflow(content)
    try:
        result = run_zghalint(
            zghalint_bin,
            "--format", "json", "--color", "never",
            "--config", config_path,
            wf_path,
        )
        import json
        data = json.loads(result.stdout)
        reduced_count = len(data["diagnostics"])

        assert reduced_count <= baseline_count, (
            f"Disabling {rule_to_disable} increased diagnostics: "
            f"{baseline_count} → {reduced_count}"
        )
        # The disabled rule should not appear
        disabled_ids = {d["rule_id"] for d in data["diagnostics"]}
        assert rule_to_disable not in disabled_ids, (
            f"Rule {rule_to_disable} still appears after disabling"
        )
    finally:
        os.unlink(config_path)
        os.unlink(wf_path)


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_disabling_all_rules_yields_zero_diagnostics(zghalint_bin, content):
    """Disabling every reported rule must result in zero diagnostics."""
    baseline = lint_workflow_json(zghalint_bin, content)

    # Collect all rule IDs
    rule_ids = {d["rule_id"] for d in baseline["diagnostics"]}
    if not rule_ids:
        return  # Already zero

    # Disable all of them
    overrides = {rid: {"enabled": False} for rid in rule_ids}
    config_path = write_temp_config(overrides)
    wf_path = write_temp_workflow(content)
    try:
        result = run_zghalint(
            zghalint_bin,
            "--format", "json", "--color", "never",
            "--config", config_path,
            wf_path,
        )
        import json
        data = json.loads(result.stdout)
        remaining = [d["rule_id"] for d in data["diagnostics"]]
        remaining_in_disabled = [r for r in remaining if r in rule_ids]
        assert len(remaining_in_disabled) == 0, (
            f"Disabled rules still report: {remaining_in_disabled}"
        )
    finally:
        os.unlink(config_path)
        os.unlink(wf_path)
