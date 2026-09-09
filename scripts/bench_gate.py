#!/usr/bin/env python3
"""Compare a bench run against the recorded zghalint baseline (issue #270).

`scripts/bench.py --json` scores three linters, but only zghalint's column is
ours to defend: actionlint's and zizmor's numbers move with their own releases
and with whether shellcheck is on the runner. So the gate reads just that
column and answers one question per case — did zghalint get worse than the
last recorded run?

    python3 scripts/bench_gate.py --json out.json            # gate, Markdown on stdout
    python3 scripts/bench_gate.py --json out.json -o gate.md
    python3 scripts/bench_gate.py --json out.json --update   # rewrite the baseline

Exit 1 marks a regression: a case detecting fewer expected findings than the
baseline, a new `bench:forbid` violation, or an execution error (crash, hang,
unparsable output, exit code 2) where the baseline had none. A case the
baseline has never seen cannot regress — its misses are reported as new FN
candidates for the parity doc, and do not fail the run.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASELINE = REPO_ROOT / "bench" / "baseline.json"

TOOL = "zghalint"


def summarize(report: dict) -> dict[str, dict]:
    """The zghalint column of a `bench.py --json` report, keyed by case."""
    cases = {}
    for case in report.get("cases", []):
        score = case.get("scores", {}).get(TOOL)
        error = case.get("errors", {}).get(TOOL)
        entry: dict[str, object] = {
            "expected": score["expected"] if score else 0,
            "detected": score["detected"] if score else 0,
            "line_expected": score["line_expected"] if score else 0,
            "line_matched": score["line_matched"] if score else 0,
            "violations": score["violations"] if score else 0,
        }
        if error is not None:
            entry["error"] = error
        cases[case["case"]] = entry
    return cases


@dataclass
class Comparison:
    """What changed between the baseline and this run, from zghalint's side."""

    regressions: list[tuple[str, str]] = field(default_factory=list)
    improvements: list[tuple[str, str]] = field(default_factory=list)
    new_findings: list[tuple[str, str]] = field(default_factory=list)
    removed_cases: list[str] = field(default_factory=list)
    warnings: list[tuple[str, str]] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return bool(self.regressions)


def compare(current: dict[str, dict], baseline: dict[str, dict]) -> Comparison:
    cmp = Comparison()
    for name, now in sorted(current.items()):
        before = baseline.get(name)
        if before is None:
            # A case added since the baseline. Its misses are FN candidates,
            # not regressions -- nothing has gotten worse.
            missed = now["expected"] - now["detected"]
            note = f"新規ケース (期待 {now['expected']} 件"
            note += f", FN {missed} 件)" if missed else ")"
            if now.get("error"):
                note += f" / 実行エラー: {now['error']}"
            cmp.new_findings.append((name, note))
            continue
        if now["detected"] < before["detected"]:
            cmp.regressions.append(
                (
                    name,
                    f"recall 低下: {before['detected']} → {now['detected']}"
                    f" / 期待 {now['expected']}",
                )
            )
        elif now["detected"] > before["detected"]:
            cmp.improvements.append(
                (name, f"recall 改善: {before['detected']} → {now['detected']}")
            )
        if now["violations"] > before["violations"]:
            cmp.regressions.append(
                (name, f"FP 増加: {before['violations']} → {now['violations']} 件")
            )
        elif now["violations"] < before["violations"]:
            cmp.improvements.append(
                (name, f"FP 減少: {before['violations']} → {now['violations']} 件")
            )
        if now.get("error") and not before.get("error"):
            cmp.regressions.append((name, f"実行エラー: {now['error']}"))
        elif before.get("error") and not now.get("error"):
            cmp.improvements.append((name, "実行エラーが解消"))
        if now["line_matched"] < before["line_matched"]:
            cmp.warnings.append(
                (name, f"位置一致の低下: {before['line_matched']} → {now['line_matched']}")
            )
        # `expected` shrinking means the case header changed, not the linter.
        if now["expected"] < before["expected"]:
            cmp.warnings.append(
                (name, f"期待値が減った: {before['expected']} → {now['expected']} (ケース側の変更)")
            )
    cmp.removed_cases = sorted(set(baseline) - set(current))
    return cmp


def totals(cases: dict[str, dict]) -> tuple[int, int, int, int, int]:
    expected = sum(c["expected"] for c in cases.values())
    detected = sum(c["detected"] for c in cases.values())
    line_expected = sum(c["line_expected"] for c in cases.values())
    line_matched = sum(c["line_matched"] for c in cases.values())
    violations = sum(c["violations"] for c in cases.values())
    return expected, detected, line_expected, line_matched, violations


def _pct(part: int, whole: int) -> str:
    return "–" if whole == 0 else f"{part * 100 // whole}% ({part}/{whole})"


def render_markdown(current: dict[str, dict], baseline: dict[str, dict], cmp: Comparison) -> str:
    exp, det, lexp, lmat, viol = totals(current)
    bexp, bdet, blexp, blmat, bviol = totals(baseline)
    out = [
        "# bench ゲート (zghalint)",
        "",
        "| 指標 | baseline | 今回 |",
        "|---|---|---|",
        f"| ケース数 | {len(baseline)} | {len(current)} |",
        f"| recall | {_pct(bdet, bexp)} | {_pct(det, exp)} |",
        f"| 位置一致 | {_pct(blmat, blexp)} | {_pct(lmat, lexp)} |",
        f"| FP (`bench:forbid` 違反) | {bviol} | {viol} |",
        "",
    ]

    def section(title: str, rows: list[tuple[str, str]], empty: str) -> None:
        out.append(f"## {title}")
        out.append("")
        if rows:
            out.append("| case | 内容 |")
            out.append("|---|---|")
            out.extend(f"| `{name}` | {note} |" for name, note in rows)
        else:
            out.append(empty)
        out.append("")

    section("回帰 (ワークフローを失敗させる)", cmp.regressions, "なし。")
    section("新規ケース (FN 候補。失敗させない)", cmp.new_findings, "なし。")
    section("改善", cmp.improvements, "なし。")
    section("注意", cmp.warnings, "なし。")

    out.append("## baseline から消えたケース")
    out.append("")
    out.append(
        ", ".join(f"`{name}`" for name in cmp.removed_cases) if cmp.removed_cases else "なし。"
    )
    out.append("")
    if cmp.new_findings or cmp.improvements or cmp.removed_cases:
        out.append(
            "baseline を更新するには "
            "`python3 scripts/bench_gate.py --json <報告> --update` を実行し、"
            "`bench/baseline.json` の差分をコミットする。"
        )
        out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--json", type=Path, required=True, metavar="PATH", help="`bench.py --json` の出力"
    )
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE, help="比較する baseline")
    parser.add_argument("-o", "--out", type=Path, help="Markdown の書き出し先")
    parser.add_argument(
        "--update", action="store_true", help="比較せず baseline を今回の結果で置き換える"
    )
    args = parser.parse_args(argv)

    if not args.json.is_file():
        print(f"no such report: {args.json}", file=sys.stderr)
        return 2
    current = summarize(json.loads(args.json.read_text(encoding="utf-8")))

    if args.update:
        args.baseline.write_text(
            json.dumps({"cases": current}, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {args.baseline} ({len(current)} cases)")
        return 0

    if not args.baseline.is_file():
        print(
            f"no baseline at {args.baseline}; create it with --update once the run looks right",
            file=sys.stderr,
        )
        return 2
    baseline = json.loads(args.baseline.read_text(encoding="utf-8")).get("cases", {})

    cmp = compare(current, baseline)
    report = render_markdown(current, baseline, cmp)
    if args.out:
        args.out.write_text(report, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(report)
    for name, note in cmp.regressions:
        print(f"::error::bench regression in {name}: {note}", file=sys.stderr)
    return 1 if cmp.failed else 0


if __name__ == "__main__":
    sys.exit(main())
