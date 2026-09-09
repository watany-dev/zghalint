"""Autofix cross-check behind `scripts/bench.py --fix`.

Issue #269: apply `--fix` / `--fix-unsafe` to a copy of every bench case and
ask whether the rewrite is still a valid workflow, still lintable, idempotent,
and free of findings the other two tools did not already report.

    python3 scripts/bench.py --fix
    python3 scripts/bench.py --fix --case 'd-*'

The five checks, per case and per flag:

1. apply zghalint `--fix` (then, separately, `--fix-unsafe`) to a copy
2. re-run zghalint: no crash, and no *new* rule IDs
3. actionlint / zizmor: no finding IDs that were absent before the rewrite
4. a second apply is a no-op (byte-identical)
5. PyYAML still parses anything that parsed before; comment lines are kept
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# ============================================================
# Pure helpers (unit-tested without the binary)
# ============================================================

COMMENT_LINE = re.compile(r"^\s*#")


def comment_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if COMMENT_LINE.match(line)]


def lost_comments(before: str, after: str) -> list[str]:
    """Comment lines present before the rewrite and missing afterwards.

    Autofix inserts keys; it must not delete a comment. Comparing the exact
    set (not a prefix / substring) keeps a moved-but-kept comment from
    firing, and a deleted one from hiding.
    """
    after_set = set(comment_lines(after))
    return [line for line in comment_lines(before) if line not in after_set]


def yaml_error(text: str) -> str | None:
    """None when PyYAML can load *text*; otherwise a short reason.

    Workflows may contain multiple documents (`---`); `safe_load_all`
    accepts that, `safe_load` does not. An empty file is a valid YAML stream.
    """
    try:
        list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        return str(exc).splitlines()[0][:160]
    return None


def new_idents(before: set[str], after: set[str]) -> list[str]:
    return sorted(after - before)


def snapshot_tree(root: Path) -> dict[str, bytes]:
    """Every file under *root* except the empty `.git` marker `stage()` adds."""
    out: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if ".git" in path.parts:
            continue
        out[path.relative_to(root).as_posix()] = path.read_bytes()
    return out


def restore_tree(root: Path, snap: dict[str, bytes]) -> None:
    for rel, data in snap.items():
        (root / rel).write_bytes(data)


def changed_paths(before: dict[str, bytes], after: dict[str, bytes]) -> list[str]:
    return sorted(rel for rel, data in after.items() if before.get(rel) != data)


def idents_from_run(run) -> set[str]:
    if run is None or run.error is not None:
        return set()
    return {f.ident for f in run.findings}


def added_idents(before_runs: dict, after_runs: dict, tool: str) -> list[str]:
    before_run = before_runs.get(tool)
    if before_run is None or before_run.error is not None:
        return []
    return new_idents(idents_from_run(before_run), idents_from_run(after_runs.get(tool)))


# ============================================================
# Per-case / per-flag run
# ============================================================


@dataclass
class FlagResult:
    flag: str
    rewritten: list[str] = field(default_factory=list)
    error: str | None = None
    new_zghalint: list[str] = field(default_factory=list)
    new_actionlint: list[str] = field(default_factory=list)
    new_zizmor: list[str] = field(default_factory=list)
    not_idempotent: bool = False
    yaml_broken: list[tuple[str, str]] = field(default_factory=list)
    comments_lost: list[tuple[str, str]] = field(default_factory=list)
    skipped_overlaps: int = 0
    #: (tool, ID, reason) the case declared with `bench:fix-allow`.
    allowed: list[tuple[str, str, str]] = field(default_factory=list)

    @property
    def problems(self) -> list[str]:
        out: list[str] = []
        if self.error:
            out.append(self.error)
        if self.new_zghalint:
            out.append("zghalint +" + ",".join(self.new_zghalint))
        if self.new_actionlint:
            out.append("actionlint +" + ",".join(self.new_actionlint))
        if self.new_zizmor:
            out.append("zizmor +" + ",".join(self.new_zizmor))
        if self.not_idempotent:
            out.append("not idempotent")
        if self.yaml_broken:
            out.append("yaml broken")
        if self.comments_lost:
            out.append("comments dropped")
        return out


@dataclass
class CaseFixResult:
    name: str
    flags: list[FlagResult]


SKIPPED_RE = re.compile(r"(\d+) fix(?:es)? skipped")

FIX_TOOLS = ("zghalint", "actionlint", "zizmor")


def _apply(binary: Path, staged, flag: str, run_cmd) -> tuple[int, str]:
    argv = [str(binary), "--offline", "--color", "never", flag, staged.rel]
    proc, error = run_cmd(argv, staged.root)
    if proc is None:
        return 2, error or "apply failed"
    stderr = proc.stderr or ""
    return proc.returncode, stderr


def check_flag(
    *,
    binary: Path,
    case,
    staged,
    available: dict[str, bool],
    flag: str,
    run_case,
    run_cmd,
) -> FlagResult:
    result = FlagResult(flag=flag)
    before_snap = snapshot_tree(staged.root)
    before_text = {rel: data.decode("utf-8", errors="replace") for rel, data in before_snap.items()}
    before_yaml_ok = {rel: yaml_error(text) is None for rel, text in before_text.items()}

    before_runs = run_case(case, staged, binary, available)

    code, stderr = _apply(binary, staged, flag, run_cmd)
    if "could not run" in (stderr or "") or code == 2 and "timed out" in (stderr or ""):
        result.error = stderr
        restore_tree(staged.root, before_snap)
        return result
    skipped = SKIPPED_RE.search(stderr)
    result.skipped_overlaps = int(skipped.group(1)) if skipped else 0

    after_snap = snapshot_tree(staged.root)
    result.rewritten = changed_paths(before_snap, after_snap)

    after_text = {rel: data.decode("utf-8", errors="replace") for rel, data in after_snap.items()}
    for rel in result.rewritten:
        if not before_yaml_ok.get(rel, False):
            continue
        err = yaml_error(after_text[rel])
        if err is not None:
            result.yaml_broken.append((rel, err))
        for line in lost_comments(before_text[rel], after_text[rel]):
            result.comments_lost.append((rel, line))

    after_runs = run_case(case, staged, binary, available)
    zg = after_runs.get("zghalint")
    before_zg = before_runs.get("zghalint")
    if (
        zg is not None
        and zg.error is not None
        and (result.rewritten or before_zg is None or before_zg.error is None)
    ):
        result.error = f"re-lint: {zg.error}"
        restore_tree(staged.root, before_snap)
        return result

    added = {tool: added_idents(before_runs, after_runs, tool) for tool in FIX_TOOLS}
    for tool, ids in added.items():
        allowed_ids, reason = case.fix_allows.get((flag, tool), ([], ""))
        result.allowed.extend((tool, i, reason) for i in ids if i in allowed_ids)
        added[tool] = [i for i in ids if i not in allowed_ids]
    result.new_zghalint = added["zghalint"]
    result.new_actionlint = added["actionlint"]
    result.new_zizmor = added["zizmor"]

    if result.rewritten:
        _apply(binary, staged, flag, run_cmd)
        second = snapshot_tree(staged.root)
        result.not_idempotent = second != after_snap

    restore_tree(staged.root, before_snap)
    return result


def run_fix(
    *,
    zghalint: Path,
    cases: list,
    available: dict[str, bool],
    tmp: Path,
    stage,
    run_case,
    run_cmd,
) -> list[CaseFixResult]:
    results: list[CaseFixResult] = []
    for case in cases:
        staged = stage(case, tmp)
        flags = [
            check_flag(
                binary=zghalint,
                case=case,
                staged=staged,
                available=available,
                flag=flag,
                run_case=run_case,
                run_cmd=run_cmd,
            )
            for flag in ("--fix", "--fix-unsafe")
        ]
        results.append(CaseFixResult(name=case.name, flags=flags))
    return results


# ============================================================
# Reporting
# ============================================================


def render_markdown(results: list[CaseFixResult], available: dict[str, bool]) -> str:
    out = ["# bench autofix 交差検証", ""]
    out.append(f"ケース {len(results)} 件。`--fix` と `--fix-unsafe` を別コピーへ適用する。")
    out.append("")
    missing = [t for t, ok in available.items() if not ok]
    if missing:
        out.append(f"> 未インストールのため比較対象外: {', '.join(missing)}")
        out.append("")

    rewritten = 0
    problem_rows: list[tuple[str, str, str]] = []
    allowed_rows: list[tuple[str, str, str, str, str]] = []
    for case in results:
        for flag in case.flags:
            if flag.rewritten:
                rewritten += 1
            problems = flag.problems
            if problems:
                problem_rows.append((case.name, flag.flag, "; ".join(problems)))
            allowed_rows.extend(
                (case.name, flag.flag, tool, ident, reason) for tool, ident, reason in flag.allowed
            )

    out.append("## 集計")
    out.append("")
    out.append("| 項目 | 件数 |")
    out.append("|---|---|")
    out.append(f"| ケース | {len(results)} |")
    out.append(f"| 書き換えが起きた適用 (フラグ単位) | {rewritten} |")
    out.append(f"| 問題あり | {len(problem_rows)} |")
    out.append(f"| 許容した増加 (`bench:fix-allow`) | {len(allowed_rows)} |")
    out.append("")

    out.append("## 問題")
    out.append("")
    if problem_rows:
        out.append("| case | flag | 内容 |")
        out.append("|---|---|---|")
        for name, flag, detail in problem_rows:
            out.append(f"| `{name}` | `{flag}` | {detail} |")
    else:
        out.append("なし。")
    out.append("")

    out.append("## 許容した増加 (`bench:fix-allow`)")
    out.append("")
    if allowed_rows:
        out.append("| case | flag | tool | ID | 理由 |")
        out.append("|---|---|---|---|---|")
        for name, flag, tool, ident, reason in allowed_rows:
            out.append(f"| `{name}` | `{flag}` | {tool} | `{ident}` | {reason} |")
    else:
        out.append("なし。")
    out.append("")

    out.append("## ケース別")
    out.append("")
    out.append("| case | `--fix` | `--fix-unsafe` |")
    out.append("|---|---|---|")
    for case in results:
        cells = []
        for flag in case.flags:
            if flag.problems:
                cells.append("**" + "; ".join(flag.problems) + "**")
            elif flag.rewritten:
                cells.append(f"ok ({len(flag.rewritten)} file)")
            else:
                cells.append("unchanged")
        out.append(f"| `{case.name}` | " + " | ".join(cells) + " |")
    out.append("")
    return "\n".join(out)


def as_json(results: list[CaseFixResult]) -> dict:
    return {
        "cases": [
            {
                "case": case.name,
                "flags": [
                    {
                        "flag": f.flag,
                        "rewritten": f.rewritten,
                        "error": f.error,
                        "new_zghalint": f.new_zghalint,
                        "new_actionlint": f.new_actionlint,
                        "new_zizmor": f.new_zizmor,
                        "not_idempotent": f.not_idempotent,
                        "yaml_broken": [{"file": p, "error": e} for p, e in f.yaml_broken],
                        "comments_lost": [{"file": p, "line": line} for p, line in f.comments_lost],
                        "skipped_overlaps": f.skipped_overlaps,
                        "allowed": [{"tool": t, "id": i, "reason": r} for t, i, r in f.allowed],
                    }
                    for f in case.flags
                ],
            }
            for case in results
        ]
    }
