"""Output consistency: JSON/SARIF structural validity, cross-format agreement,
summary arithmetic, span validity, and sort stability."""
from __future__ import annotations

import json

from hypothesis import given, settings, HealthCheck, assume

from tests.pbt.conftest import (
    lint_workflow,
    lint_workflow_json,
    lint_workflow_sarif,
)
from tests.pbt.strategies import workflow_yaml

PBT_SETTINGS = settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


# ============================================================
# JSON structural validity
# ============================================================


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_json_output_is_valid_json(zghalint_bin, content):
    """--format json must always produce parseable JSON."""
    result = lint_workflow(zghalint_bin, content, "--format", "json", "--color", "never")
    # Should not signal-terminate
    assert result.returncode >= 0
    if result.stdout.strip():
        data = json.loads(result.stdout)
        assert "diagnostics" in data
        assert "summary" in data


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_json_summary_arithmetic(zghalint_bin, content):
    """summary.total == errors + warnings + infos + hints == len(diagnostics)."""
    data = lint_workflow_json(zghalint_bin, content)
    s = data["summary"]

    assert s["total"] == s["errors"] + s["warnings"] + s["infos"] + s["hints"], (
        f"Summary arithmetic mismatch: {s}"
    )
    assert s["total"] == len(data["diagnostics"]), (
        f"total ({s['total']}) != len(diagnostics) ({len(data['diagnostics'])})"
    )


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_json_severity_counts_match(zghalint_bin, content):
    """Per-severity counts in summary must match actual diagnostic severities."""
    data = lint_workflow_json(zghalint_bin, content)
    s = data["summary"]

    actual = {"error": 0, "warning": 0, "info": 0, "hint": 0}
    for d in data["diagnostics"]:
        actual[d["severity"]] += 1

    assert actual["error"] == s["errors"]
    assert actual["warning"] == s["warnings"]
    assert actual["info"] == s["infos"]
    assert actual["hint"] == s["hints"]


# ============================================================
# SARIF structural validity
# ============================================================


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_sarif_output_is_valid_sarif(zghalint_bin, content):
    """--format sarif must produce valid SARIF 2.1.0 with required fields."""
    data = lint_workflow_sarif(zghalint_bin, content)

    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert "runs" in data
    assert len(data["runs"]) == 1

    run = data["runs"][0]
    assert "tool" in run
    assert "driver" in run["tool"]
    assert "name" in run["tool"]["driver"]
    assert run["tool"]["driver"]["name"] == "zghalint"
    assert "rules" in run["tool"]["driver"]
    assert "results" in run


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_sarif_results_have_valid_structure(zghalint_bin, content):
    """Every SARIF result must have ruleId, level, message, locations."""
    data = lint_workflow_sarif(zghalint_bin, content)
    for result in data["runs"][0]["results"]:
        assert "ruleId" in result
        assert "level" in result
        assert result["level"] in {"error", "warning", "note"}
        assert "message" in result
        assert "text" in result["message"]
        assert "locations" in result
        assert len(result["locations"]) >= 1

        loc = result["locations"][0]
        phys = loc["physicalLocation"]
        assert "artifactLocation" in phys
        assert "region" in phys


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_sarif_rule_ids_in_driver_rules(zghalint_bin, content):
    """Every ruleId referenced in results must exist in tool.driver.rules."""
    data = lint_workflow_sarif(zghalint_bin, content)
    run = data["runs"][0]
    known_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for result in run["results"]:
        assert result["ruleId"] in known_ids, (
            f"ruleId '{result['ruleId']}' not in driver.rules"
        )


# ============================================================
# Cross-format consistency
# ============================================================


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_json_sarif_diagnostic_count_matches(zghalint_bin, content):
    """JSON and SARIF must report the same number of diagnostics."""
    json_data = lint_workflow_json(zghalint_bin, content)
    sarif_data = lint_workflow_sarif(zghalint_bin, content)

    json_count = len(json_data["diagnostics"])
    sarif_count = len(sarif_data["runs"][0]["results"])
    assert json_count == sarif_count, (
        f"JSON reports {json_count} diagnostics, SARIF reports {sarif_count}"
    )


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_json_sarif_rule_ids_match(zghalint_bin, content):
    """JSON and SARIF must report the same multiset of rule_ids."""
    json_data = lint_workflow_json(zghalint_bin, content)
    sarif_data = lint_workflow_sarif(zghalint_bin, content)

    json_ids = sorted(d["rule_id"] for d in json_data["diagnostics"])
    sarif_ids = sorted(r["ruleId"] for r in sarif_data["runs"][0]["results"])
    assert json_ids == sarif_ids, (
        f"Rule IDs differ: JSON={json_ids} SARIF={sarif_ids}"
    )


# ============================================================
# Span validity
# ============================================================


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_json_span_values_are_positive(zghalint_bin, content):
    """All line/column values in JSON diagnostics must be >= 0."""
    data = lint_workflow_json(zghalint_bin, content)
    for d in data["diagnostics"]:
        assert d["line"] >= 0, f"line < 0 in {d}"
        assert d["column"] >= 0, f"column < 0 in {d}"
        assert d["end_line"] >= 0, f"end_line < 0 in {d}"
        assert d["end_column"] >= 0, f"end_column < 0 in {d}"


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_sarif_region_values_are_positive(zghalint_bin, content):
    """SARIF region startLine/startColumn must be >= 0."""
    data = lint_workflow_sarif(zghalint_bin, content)
    for result in data["runs"][0]["results"]:
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 0, f"startLine < 0: {region}"
        assert region["startColumn"] >= 0, f"startColumn < 0: {region}"


# ============================================================
# Sort stability
# ============================================================


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_json_diagnostics_are_sorted(zghalint_bin, content):
    """Diagnostics in JSON output must be sorted by (file, line, column)."""
    data = lint_workflow_json(zghalint_bin, content)
    diags = data["diagnostics"]
    if len(diags) < 2:
        return

    for i in range(len(diags) - 1):
        a, b = diags[i], diags[i + 1]
        key_a = (a["file"], a["line"], a["column"])
        key_b = (b["file"], b["line"], b["column"])
        assert key_a <= key_b, (
            f"Diagnostics not sorted: {key_a} > {key_b}"
        )
