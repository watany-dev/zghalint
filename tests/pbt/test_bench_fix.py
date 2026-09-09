"""Unit tests for `scripts/bench_fix.py` helpers.

The `--fix` harness talks to three binaries; these tests cover the scoring
predicates so a comment-line comparison bug cannot silently swallow a
rewrite that dropped a header.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "bench_fix.py"


def load_mod():
    spec = importlib.util.spec_from_file_location("bench_fix", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fix = load_mod()


def test_new_idents_are_sorted_additions():
    assert fix.new_idents({"BP001", "SEC002"}, {"BP001", "SYN002", "SEC002"}) == ["SYN002"]
    assert fix.new_idents({"BP001"}, {"BP001"}) == []


def test_lost_comments_ignore_kept_and_moved_identical_lines():
    before = "# keep\nname: t\n# gone\n"
    after = "name: t\n# keep\n"
    assert fix.lost_comments(before, after) == ["# gone"]


def test_lost_comments_does_not_flag_identical_comment_still_present():
    before = "# bench:expect x\nname: t\n"
    after = "# bench:expect x\nname: t\ntimeout-minutes: 30\n"
    assert fix.lost_comments(before, after) == []


def test_yaml_error_accepts_empty_and_multi_document():
    assert fix.yaml_error("") is None
    assert fix.yaml_error("a: 1\n---\nb: 2\n") is None
    assert fix.yaml_error(":\n  -") is not None


def test_changed_paths_reports_only_rewritten_files():
    before = {"a.yml": b"a", "b.yml": b"b"}
    after = {"a.yml": b"a\n", "b.yml": b"b"}
    assert fix.changed_paths(before, after) == ["a.yml"]


def test_fix_allow_moves_an_expected_increase_out_of_problems():
    """`bench:fix-allow` is what keeps an intentional rewrite from going red."""
    result = fix.FlagResult(flag="--fix-unsafe")
    assert result.problems == []
    result.new_zizmor = ["dangerous-triggers"]
    assert result.problems == ["zizmor +dangerous-triggers"]
    result.new_zizmor = []
    result.allowed = [("zizmor", "dangerous-triggers", "G22")]
    assert result.problems == []


def load_bench():
    import sys

    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    import bench

    return bench


def test_duplicate_fix_allow_for_one_flag_and_tool_is_rejected():
    """Two lines used to silently overwrite each other, dropping allowances."""
    bench = load_bench()
    case = bench.Case(path=PROJECT_ROOT / "x.yml", name="x.yml")
    bench._apply_fix_allow(case, "--fix zizmor=a 理由")
    try:
        bench._apply_fix_allow(case, "--fix zizmor=b 別の理由")
    except bench.CaseError:
        pass
    else:
        raise AssertionError("expected CaseError")
    assert case.fix_allows[("--fix", "zizmor")][0] == ["a"]
