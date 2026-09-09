"""Startup / allocation / RSS measurements behind `scripts/bench.py --alloc`.

Unlike `--perf`, this is zghalint-only: it splits process startup from lint
work, records allocator counts from a `-Dalloc-stats` binary, and (when
strace is installed) shows which syscalls dominate.

    zig build -Doptimize=ReleaseFast -Dalloc-stats
    python3 scripts/bench.py --alloc

The instrumented binary prints one `alloc-stats: {...}` JSON line on stderr.
Wall time still comes from an in-process loop (or hyperfine); peak RSS from
GNU time, same caveat as `bench_perf.py`. A binary built without
`-Dalloc-stats` still yields wall / RSS / syscalls; the alloc columns are
blank.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import bench_perf

REPO_ROOT = Path(__file__).resolve().parent.parent
TIMEOUT_SEC = 120
TINY_WORKFLOW = """\
name: alloc tiny
on: push
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - run: echo ok
"""


@dataclass
class AllocStats:
    allocs: int | None = None
    frees: int | None = None
    remaps: int | None = None
    bytes: int | None = None
    peak: int | None = None
    current: int | None = None
    small: int | None = None
    medium: int | None = None
    large: int | None = None
    elapsed_ns: int | None = None
    rss_kb: int | None = None
    phases: dict[str, dict[str, int]] = field(default_factory=dict)


@dataclass
class SyscallRow:
    name: str
    calls: int
    seconds: float
    errors: int = 0


@dataclass
class Row:
    name: str
    description: str
    files: int
    lines: int
    wall: bench_perf.Measurement
    stats: AllocStats | None
    syscalls: list[SyscallRow]
    binary_bytes: int | None = None


def parse_alloc_stats_line(stderr: str) -> AllocStats | None:
    """Pick the `alloc-stats:` JSON line out of mixed stderr."""
    for raw in stderr.splitlines():
        line = raw.strip()
        if not line.startswith("alloc-stats:"):
            continue
        payload = line[len("alloc-stats:") :].strip()
        data = json.loads(payload)
        phases = {}
        for name, sample in (data.get("phases") or {}).items():
            phases[name] = {
                "ns": int(sample.get("ns", 0)),
                "allocs": int(sample.get("allocs", 0)),
                "bytes": int(sample.get("bytes", 0)),
            }
        return AllocStats(
            allocs=data.get("allocs"),
            frees=data.get("frees"),
            remaps=data.get("remaps"),
            bytes=data.get("bytes"),
            peak=data.get("peak"),
            current=data.get("current"),
            small=data.get("small"),
            medium=data.get("medium"),
            large=data.get("large"),
            elapsed_ns=data.get("elapsed_ns"),
            rss_kb=data.get("rss_kb"),
            phases=phases,
        )
    return None


def parse_strace_c(text: str) -> list[SyscallRow]:
    """Parse `strace -c` summary. Ignores the header/total rows."""
    rows: list[SyscallRow] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("%") or stripped.startswith("-"):
            continue
        parts = stripped.split()
        if parts[-1] == "total" or not parts[-1].isidentifier():
            continue
        try:
            seconds = float(parts[1])
            if len(parts) >= 6 and parts[4].isdigit():
                calls = int(parts[3])
                errors = int(parts[4])
                name = parts[5]
            else:
                calls = int(parts[3])
                errors = 0
                name = parts[4]
        except (IndexError, ValueError):
            continue
        rows.append(SyscallRow(name=name, calls=calls, seconds=seconds, errors=errors))
    rows.sort(key=lambda r: r.calls, reverse=True)
    return rows


def _zghalint_cmd(zghalint: Path, extra: list[str]) -> bench_perf.Command:
    env = dict(os.environ)
    return bench_perf.Command(
        "zghalint",
        "offline",
        [str(zghalint), "--format", "json", "--color", "never", "--offline", *extra],
        env,
    )


def _capture_stats(cmd: bench_perf.Command, cwd: Path) -> AllocStats | None:
    try:
        proc = subprocess.run(
            cmd.argv,
            cwd=str(cwd),
            env=cmd.env,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SEC,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_alloc_stats_line(proc.stderr or "")


def _capture_strace(cmd: bench_perf.Command, cwd: Path) -> list[SyscallRow]:
    strace = shutil.which("strace")
    if strace is None:
        return []
    with tempfile.NamedTemporaryFile("r", suffix=".strace") as out:
        try:
            subprocess.run(
                [strace, "-c", "-o", out.name, *cmd.argv],
                cwd=str(cwd),
                env=cmd.env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=TIMEOUT_SEC,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        return parse_strace_c(out.read())


def _measure_row(
    name: str,
    description: str,
    cmd: bench_perf.Command,
    cwd: Path,
    files: int,
    lines: int,
    runs: int,
    warmup: int,
    hyperfine: bool,
    rss_tool: str | None,
    binary_bytes: int | None,
) -> Row:
    print(f"  {name}", file=sys.stderr)
    wall = bench_perf.measure(cmd, cwd, runs, warmup, hyperfine, rss_tool)
    stats = _capture_stats(cmd, cwd)
    syscalls = _capture_strace(cmd, cwd)
    return Row(name, description, files, lines, wall, stats, syscalls, binary_bytes)


def tiny_scenario(tmp: Path) -> bench_perf.Scenario:
    root = tmp / "tiny"
    root.mkdir()
    (root / "tiny.yml").write_text(TINY_WORKFLOW, encoding="utf-8")
    files = ["tiny.yml"]
    return bench_perf.Scenario(
        "tiny",
        "単一小ファイル (起動と lint の差分)",
        root,
        files,
        bench_perf._line_count(root, files),
    )


def _tile_cases(cases: bench_perf.Scenario, tmp: Path, count: int) -> bench_perf.Scenario:
    """Repeat `cases` files into a flat directory so many-file allocs are visible
    when `bench/corpus/` has not been fetched."""
    root = tmp / "many-files"
    root.mkdir()
    files: list[str] = []
    sources = [cases.cwd / rel for rel in cases.files]
    for i in range(count):
        src = sources[i % len(sources)]
        name = f"{i:04d}-{src.name}"
        shutil.copyfile(src, root / name)
        files.append(name)
    return bench_perf.Scenario(
        "many-files",
        f"多数小ファイル (cases を {count} 件に反復; corpus 未取得)",
        root,
        files,
        bench_perf._line_count(root, files),
    )


@dataclass
class AllocReport:
    rows: list[Row]
    skipped: dict[str, str]
    environment: dict[str, str]


def run_alloc(
    zghalint: Path, cases_dir: Path, corpus_dir: Path, runs: int, warmup: int, tmp: Path
) -> AllocReport:
    hyperfine = shutil.which("hyperfine") is not None
    rss_tool = bench_perf.gnu_time()
    binary_bytes = zghalint.stat().st_size if zghalint.is_file() else None
    rows: list[Row] = []
    skipped: dict[str, str] = {}

    version_cmd = bench_perf.Command(
        "zghalint", "version", [str(zghalint), "--version"], dict(os.environ)
    )
    rows.append(
        _measure_row(
            "version",
            "`--version`（lint なしの起動下限）",
            version_cmd,
            REPO_ROOT,
            0,
            0,
            runs,
            warmup,
            hyperfine,
            rss_tool,
            binary_bytes,
        )
    )

    tiny = tiny_scenario(tmp)
    rows.append(
        _measure_row(
            tiny.name,
            tiny.description,
            _zghalint_cmd(zghalint, tiny.files),
            tiny.cwd,
            len(tiny.files),
            tiny.lines,
            runs,
            warmup,
            hyperfine,
            rss_tool,
            binary_bytes,
        )
    )

    cases = bench_perf.cases_scenario(cases_dir)
    rows.append(
        _measure_row(
            cases.name,
            cases.description,
            _zghalint_cmd(zghalint, cases.files),
            cases.cwd,
            len(cases.files),
            cases.lines,
            runs,
            warmup,
            hyperfine,
            rss_tool,
            binary_bytes,
        )
    )

    huge = bench_perf.huge_scenario(tmp)
    rows.append(
        _measure_row(
            huge.name,
            huge.description,
            _zghalint_cmd(zghalint, huge.files),
            huge.cwd,
            len(huge.files),
            huge.lines,
            runs,
            warmup,
            hyperfine,
            rss_tool,
            binary_bytes,
        )
    )

    many = bench_perf.many_small_scenario(corpus_dir, tmp)
    if many.unavailable is not None:
        tiled = _tile_cases(cases, tmp, 200)
        rows.append(
            _measure_row(
                tiled.name,
                tiled.description,
                _zghalint_cmd(zghalint, tiled.files),
                tiled.cwd,
                len(tiled.files),
                tiled.lines,
                runs,
                warmup,
                hyperfine,
                rss_tool,
                binary_bytes,
            )
        )
        skipped[many.name] = many.unavailable
    else:
        rows.append(
            _measure_row(
                many.name,
                many.description,
                _zghalint_cmd(zghalint, many.files),
                many.cwd,
                len(many.files),
                many.lines,
                runs,
                warmup,
                hyperfine,
                rss_tool,
                binary_bytes,
            )
        )

    environment = {
        "date": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "platform": platform.platform(),
        "cpu": f"{os.cpu_count()} logical CPUs",
        "runs": f"{runs} (warmup {warmup})",
        "timer": (
            bench_perf._version(["hyperfine", "--version"]) if hyperfine else "in-process loop"
        ),
        "rss": f"GNU time `{rss_tool} -f %M`" if rss_tool else "未計測 (GNU time が無い)",
        "strace": bench_perf._version(["strace", "-V"]).splitlines()[0],
        "zghalint": f"`{zghalint}` {bench_perf._version([str(zghalint), '--version'])}",
        "binary": f"{binary_bytes} bytes" if binary_bytes is not None else "不明",
        "alloc-stats": (
            "stderr に alloc-stats 行あり"
            if any(r.stats is not None for r in rows)
            else "未計測 (`zig build -Doptimize=ReleaseFast -Dalloc-stats` で作る)"
        ),
    }
    return AllocReport(rows, skipped, environment)


def _ms(ns: int | None) -> str:
    if ns is None:
        return "–"
    return f"{ns / 1_000_000:.2f} ms"


def _num(value: int | None) -> str:
    if value is None:
        return "–"
    return f"{value:,}"


def _bytes(value: int | None) -> str:
    if value is None:
        return "–"
    if value < 1024:
        return f"{value} B"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KiB"
    return f"{value / (1024 * 1024):.2f} MiB"


def _utilization(stats: AllocStats | None, rss_kb: int | None) -> str:
    """Live peak heap vs process RSS. Sub-100% is code, stacks, allocator cache."""
    if stats is None or stats.peak is None or not rss_kb:
        return "–"
    rss_bytes = rss_kb * 1024
    if rss_bytes == 0:
        return "–"
    return f"{100.0 * stats.peak / rss_bytes:.0f}%"


def render_markdown(report: AllocReport) -> str:
    out = ["# bench 起動 / アロケーション / メモリ", ""]
    out.append("| 項目 | 値 |")
    out.append("|---|---|")
    for key, value in report.environment.items():
        out.append(f"| {key} | {value} |")
    out.append("")

    out.append("## シナリオ")
    out.append("")
    out.append("| シナリオ | 内容 | ファイル数 | 総行数 |")
    out.append("|---|---|---|---|")
    for row in report.rows:
        out.append(f"| `{row.name}` | {row.description} | {row.files:,} | {row.lines:,} |")
    out.append("")

    out.append("## 起動と wall time")
    out.append("")
    out.append("| シナリオ | mean ± σ | min | max | 最大 RSS | exit |")
    out.append("|---|---|---|---|---|---|")
    for row in report.rows:
        cells = bench_perf._cell(row.wall)
        out.append(f"| `{row.name}` | " + " | ".join(cells) + " |")
    out.append("")
    out.append(
        "`version` が起動下限。`tiny` との差が「1 ファイルを lint するコスト」、"
        "`cases` との差が「ファイル数に比例するコスト」。"
    )
    out.append("")

    out.append("## アロケーション")
    out.append("")
    out.append(
        "| シナリオ | allocs | frees | remaps | 累計 bytes | peak heap | "
        "≤64 B | ≤4 KiB | >4 KiB | peak/RSS |"
    )
    out.append("|---|---|---|---|---|---|---|---|---|---|")
    for row in report.rows:
        s = row.stats
        rss_kb = row.wall.max_rss_kb
        if rss_kb is None and s is not None:
            rss_kb = s.rss_kb
        if s is None:
            out.append(f"| `{row.name}` | – | – | – | – | – | – | – | – | – |")
            continue
        out.append(
            f"| `{row.name}` | {_num(s.allocs)} | {_num(s.frees)} | {_num(s.remaps)} | "
            f"{_bytes(s.bytes)} | {_bytes(s.peak)} | {_num(s.small)} | {_num(s.medium)} | "
            f"{_num(s.large)} | {_utilization(s, rss_kb)} |"
        )
    out.append("")
    out.append(
        "peak heap は CountingAllocator が見た `current` の最大。最大 RSS は GNU time の "
        "VmHWM。peak/RSS が低いのはバイナリとアロケータが抱えているキャッシュで、"
        "ライブなワークフロー AST ではない。"
    )
    out.append("")

    out.append("## フェーズ (アロケーション)")
    out.append("")
    out.append("| シナリオ | フェーズ | 時間 | allocs | bytes |")
    out.append("|---|---|---|---|---|")
    for row in report.rows:
        if row.stats is None or not row.stats.phases:
            continue
        for phase, sample in row.stats.phases.items():
            out.append(
                f"| `{row.name}` | `{phase}` | {_ms(sample['ns'])} | "
                f"{_num(sample['allocs'])} | {_bytes(sample['bytes'])} |"
            )
    out.append("")

    out.append("## システムコール (`strace -c`)")
    out.append("")
    out.append("| シナリオ | syscall | calls | 時間 | errors |")
    out.append("|---|---|---|---|---|")
    any_sys = False
    for row in report.rows:
        for sc in row.syscalls[:8]:
            any_sys = True
            out.append(
                f"| `{row.name}` | `{sc.name}` | {sc.calls:,} | {sc.seconds * 1000:.2f} ms | "
                f"{sc.errors} |"
            )
    if not any_sys:
        out.append("| – | strace 未インストール | – | – | – |")
    out.append("")

    out.append("## 計測できなかったシナリオ")
    out.append("")
    if report.skipped:
        out.append("| シナリオ | 理由 |")
        out.append("|---|---|")
        for name, reason in report.skipped.items():
            out.append(f"| `{name}` | {reason} |")
    else:
        out.append("なし。")
    out.append("")
    return "\n".join(out)


def as_json(report: AllocReport) -> dict:
    return {
        "environment": report.environment,
        "rows": [
            {
                "name": r.name,
                "description": r.description,
                "files": r.files,
                "lines": r.lines,
                "binary_bytes": r.binary_bytes,
                "wall": vars(r.wall),
                "stats": None if r.stats is None else dict(vars(r.stats)),
                "syscalls": [vars(s) for s in r.syscalls],
            }
            for r in report.rows
        ],
        "skipped": report.skipped,
    }
