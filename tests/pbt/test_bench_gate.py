"""Unit tests for `scripts/bench_gate.py`.

The gate decides whether the weekly bench workflow goes red, so the line
between "regression" and "new case" is worth pinning down: a case the
baseline has never seen must not fail the run, and a detection the baseline
recorded must.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "bench_gate.py"


def load_mod():
    spec = importlib.util.spec_from_file_location("bench_gate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = load_mod()


def report(case: str, **score) -> dict:
    base = {
        "expected": 1,
        "detected": 1,
        "line_expected": 1,
        "line_matched": 1,
        "forbidden": 0,
        "violations": 0,
    }
    base.update(score)
    errors = {"zghalint": base.pop("error")} if "error" in base else {}
    return {"cases": [{"case": case, "scores": {"zghalint": base}, "errors": errors}]}


def test_summarize_keeps_only_the_zghalint_column():
    raw = {
        "cases": [
            {
                "case": "a/x.yml",
                "scores": {
                    "zghalint": {
                        "expected": 2,
                        "detected": 1,
                        "line_expected": 2,
                        "line_matched": 1,
                        "forbidden": 0,
                        "violations": 0,
                    },
                    "zizmor": {
                        "expected": 9,
                        "detected": 9,
                        "line_expected": 9,
                        "line_matched": 9,
                        "forbidden": 0,
                        "violations": 0,
                    },
                },
                "errors": {"zizmor": "exit 3"},
            }
        ]
    }
    assert gate.summarize(raw) == {
        "a/x.yml": {
            "expected": 2,
            "detected": 1,
            "line_expected": 2,
            "line_matched": 1,
            "violations": 0,
        }
    }


def test_fewer_detections_is_a_regression():
    baseline = gate.summarize(report("a/x.yml"))
    current = gate.summarize(report("a/x.yml", detected=0))
    cmp = gate.compare(current, baseline)
    assert cmp.failed
    assert cmp.regressions[0][0] == "a/x.yml"


def test_a_case_missing_from_the_baseline_never_fails():
    cmp = gate.compare(gate.summarize(report("new/x.yml", expected=2, detected=0)), {})
    assert not cmp.failed
    assert [name for name, _ in cmp.new_findings] == ["new/x.yml"]


def test_new_false_positive_and_new_error_are_regressions():
    baseline = gate.summarize(report("a/x.yml"))
    fp = gate.compare(gate.summarize(report("a/x.yml", violations=1)), baseline)
    crash = gate.compare(gate.summarize(report("a/x.yml", error="exit 134")), baseline)
    assert fp.failed and crash.failed


def test_recovering_from_a_baseline_error_is_an_improvement():
    baseline = gate.summarize(report("a/x.yml", error="exit 134"))
    cmp = gate.compare(gate.summarize(report("a/x.yml")), baseline)
    assert not cmp.failed
    assert cmp.improvements == [("a/x.yml", "実行エラーが解消")]


def test_line_accuracy_drop_warns_without_failing():
    baseline = gate.summarize(report("a/x.yml"))
    cmp = gate.compare(gate.summarize(report("a/x.yml", line_matched=0)), baseline)
    assert not cmp.failed
    assert cmp.warnings[0][0] == "a/x.yml"


def test_a_case_dropped_from_the_run_is_listed_not_failed():
    baseline = gate.summarize(report("gone/x.yml"))
    cmp = gate.compare({}, baseline)
    assert not cmp.failed
    assert cmp.removed_cases == ["gone/x.yml"]


def test_checked_in_baseline_matches_the_current_case_set():
    """`bench/baseline.json` must not drift from `bench/cases/`."""
    baseline = json.loads((PROJECT_ROOT / "bench" / "baseline.json").read_text(encoding="utf-8"))
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    import bench

    cases_dir = PROJECT_ROOT / "bench" / "cases"
    discovered = {case.name for case in bench.discover_cases(cases_dir, [])}
    # Adding a case without `--update` would otherwise leave it unscored by
    # the gate forever; removing one would leave a stale entry behind.
    assert set(baseline["cases"]) == discovered


def test_render_markdown_reports_the_regression_rows():
    baseline = gate.summarize(report("a/x.yml"))
    current = gate.summarize(report("a/x.yml", detected=0))
    text = gate.render_markdown(current, baseline, gate.compare(current, baseline))
    assert "recall 低下" in text
    assert "`a/x.yml`" in text
