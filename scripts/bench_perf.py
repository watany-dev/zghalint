"""Wall-clock and peak-RSS measurements behind `scripts/bench.py --perf`.

Four scenarios, each run through zghalint, actionlint and zizmor on the same
machine and the same files:

    cases       every workflow-shaped file under `bench/cases/` in one call
    huge        one synthetic ~10,000-line workflow
    many-small  `bench/corpus/` (see `scripts/fetch-corpus.py`) tiled to
                1000 files in one call
    network     the `cases` set again, zghalint with the prefetch cache cold
                (`--no-cache`) and warm, zizmor `--offline` and online

Wall time comes from `hyperfine --warmup N` when it is installed, otherwise
from an in-process loop with the same warmup; peak RSS is the `ru_maxrss` of
one extra run, the same number `/usr/bin/time -v` prints as "Maximum resident
set size". The network scenario is only reported when the network actually
answers: an environment that blocks `api.github.com` would otherwise post the
cost of a failed connection as if it were a fetch.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import platform
import shlex
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CORPUS_DIR = REPO_ROOT / "bench" / "corpus"

TOOLS = ("zghalint", "actionlint", "zizmor")

#: Per-invocation ceiling, generous because the network variants wait on
#: GitHub. A run past it is recorded as an error, never as a slow mean.
TIMEOUT_SEC = 300

#: Target sizes of the synthetic scenarios.
HUGE_LINES = 10_000
MANY_SMALL_FILES = 1000


# ============================================================
# Scenario files
# ============================================================


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    #: Directory the tools run from; relative paths keep the argv short.
    cwd: Path
    #: Paths relative to `cwd`.
    files: list[str]
    #: Total line count of `files`, taken while the staged copies still exist.
    lines: int = 0
    #: Set for a scenario that cannot be built (no corpus fetched).
    unavailable: str | None = None


def _line_count(cwd: Path, files: list[str]) -> int:
    return sum((cwd / f).read_text(encoding="utf-8", errors="replace").count("\n") for f in files)


def workflow_files(cases_dir: Path) -> list[Path]:
    """Every case file that all three tools read as a workflow.

    `*.action.yml` and `*.dependabot.yml` are only recognised under their
    staged names (see `bench.py`); passed as-is they cost each tool a
    different failure path, which is not what this scenario measures.
    """
    return sorted(
        p
        for p in cases_dir.rglob("*")
        if p.is_file()
        and p.suffix in (".yml", ".yaml")
        and not p.name.endswith((".action.yml", ".action.yaml"))
        and not p.name.endswith((".dependabot.yml", ".dependabot.yaml"))
    )


def cases_scenario(cases_dir: Path) -> Scenario:
    files = [p.relative_to(REPO_ROOT).as_posix() for p in workflow_files(cases_dir)]
    return Scenario("cases", "ベンチケース一括", REPO_ROOT, files, _line_count(REPO_ROOT, files))


def render_huge_workflow(target_lines: int) -> str:
    """A valid, lint-heavy workflow of about *target_lines* lines.

    Each job references the previous one (`needs:` plus a `needs.*.outputs`
    lookup) and mixes pinned and floating `uses:`, expressions in `run:` and
    `if:`, a matrix and per-step env, so the parser, the expression checker
    and the rules all get a full workload rather than a wall of comments.
    """
    out = [
        "name: perf huge",
        "on:",
        "  push:",
        "    branches: [main]",
        "  pull_request:",
        "  workflow_dispatch:",
        "    inputs:",
        "      level:",
        "        description: verbosity",
        "        default: info",
        "permissions:",
        "  contents: read",
        "concurrency:",
        "  group: ${{ github.workflow }}-${{ github.ref }}",
        "  cancel-in-progress: true",
        "env:",
        "  CI: 'true'",
        "jobs:",
    ]
    index = 0
    while len(out) < target_lines:
        prev = f"job{index - 1}" if index else None
        out.extend(_huge_job(index, prev))
        index += 1
    out.append("")
    return "\n".join(out)


def _huge_job(index: int, prev: str | None) -> list[str]:
    lines = [
        f"  job{index}:",
        f"    name: Job {index}",
        "    runs-on: ${{ matrix.os }}",
        "    timeout-minutes: 30",
    ]
    if prev is not None:
        lines += [f"    needs: [{prev}]", f"    if: needs.{prev}.outputs.status == 'ok'"]
    lines += [
        "    strategy:",
        "      fail-fast: true",
        "      matrix:",
        "        os: [ubuntu-latest, macos-15]",
        "        node: [20, 22]",
        "    outputs:",
        "      status: ${{ steps.finish.outputs.status }}",
        "    steps:",
        "      - name: Checkout",
        "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
        "        with:",
        "          persist-credentials: false",
        "      - name: Set up Node",
        "        uses: actions/setup-node@v4",
        "        with:",
        "          node-version: ${{ matrix.node }}",
        "          cache: npm",
        f"      - name: Build {index}",
        "        env:",
        "          LEVEL: ${{ inputs.level || 'info' }}",
        f"          SEED: {index}",
        "        run: |",
        '          echo "building on ${{ matrix.os }} with node ${{ matrix.node }}"',
        '          npm ci --loglevel "$LEVEL"',
        '          npm run build -- --seed "$SEED"',
        "      - name: Test",
        "        if: github.event_name == 'pull_request' && !cancelled()",
        "        run: npm test",
        "      - name: Upload",
        "        if: matrix.os == 'ubuntu-latest' && matrix.node == 22",
        "        uses: actions/upload-artifact@v4",
        "        with:",
        f"          name: build-{index}-${{{{ github.sha }}}}",
        "          path: dist/",
        "      - name: Finish",
        "        id: finish",
        '        run: echo "status=ok" >> "$GITHUB_OUTPUT"',
    ]
    return lines


def huge_scenario(tmp: Path) -> Scenario:
    root = tmp / "huge"
    root.mkdir()
    (root / "huge.yml").write_text(render_huge_workflow(HUGE_LINES), encoding="utf-8")
    files = ["huge.yml"]
    return Scenario(
        "huge", f"単一巨大ファイル (約 {HUGE_LINES:,} 行)", root, files, _line_count(root, files)
    )


def corpus_files(corpus_dir: Path) -> list[Path]:
    return sorted(p for p in corpus_dir.rglob("*") if p.is_file() and p.suffix in (".yml", ".yaml"))


def many_small_scenario(corpus_dir: Path, tmp: Path) -> Scenario:
    """The corpus tiled to `MANY_SMALL_FILES` files in one flat directory.

    Tiling repeats files when the corpus is smaller than the target, which
    keeps the file count (the thing this scenario varies) fixed across corpus
    refreshes.
    """
    description = f"多数小ファイル (実コーパス {MANY_SMALL_FILES:,} 件)"
    sources = corpus_files(corpus_dir) if corpus_dir.is_dir() else []
    if not sources:
        return Scenario(
            "many-small",
            description,
            tmp,
            [],
            unavailable=f"{corpus_dir} が空: `python3 scripts/fetch-corpus.py` で取得する",
        )
    root = tmp / "many-small"
    root.mkdir()
    files = []
    for i in range(MANY_SMALL_FILES):
        src = sources[i % len(sources)]
        name = f"{i:04d}-{src.parent.name}-{src.name}"
        shutil.copyfile(src, root / name)
        files.append(name)
    return Scenario(
        "many-small",
        f"{description} — 元 {len(sources)} 件を反復",
        root,
        files,
        _line_count(root, files),
    )


# ============================================================
# Commands and measurement
# ============================================================


@dataclass(frozen=True)
class Command:
    tool: str
    #: Cache / connectivity condition the row was measured under.
    condition: str
    argv: list[str]
    env: dict[str, str]
    #: Run once before measuring, e.g. to populate a cache for a warm row.
    prepare: list[str] | None = None


def tool_commands(zghalint: Path, files: list[str]) -> list[Command]:
    env = dict(os.environ)
    return [
        Command(
            "zghalint",
            "offline",
            [str(zghalint), "--format", "json", "--color", "never", "--offline", *files],
            env,
        ),
        Command("actionlint", "offline", ["actionlint", "-no-color", *files], env),
        Command(
            "zizmor",
            "offline",
            ["zizmor", "--format", "json", "--offline", "--no-progress", *files],
            env,
        ),
    ]


def network_commands(zghalint: Path, files: list[str], cache_home: Path) -> list[Command]:
    """Cold / warm pairs. The cache lives under a private `XDG_CACHE_HOME` so
    the user's real cache neither seeds the cold rows nor is refilled by them."""
    env = dict(os.environ, XDG_CACHE_HOME=str(cache_home))
    zg = [str(zghalint), "--format", "json", "--color", "never"]
    zz = ["zizmor", "--format", "json", "--no-progress"]
    return [
        Command("zghalint", "cold (--no-cache)", [*zg, "--no-cache", *files], env),
        Command("zghalint", "warm (disk cache)", [*zg, *files], env, prepare=[*zg, *files]),
        Command("zizmor", "--offline", [*zz, "--offline", *files], env),
        Command("zizmor", "online", [*zz, *files], env),
    ]


@dataclass
class Measurement:
    runs: int = 0
    mean: float | None = None
    stddev: float | None = None
    min: float | None = None
    max: float | None = None
    max_rss_kb: int | None = None
    exit_code: int | None = None
    #: Set when the command could not be measured at all.
    error: str | None = None


def _run_once(cmd: Command, cwd: Path) -> tuple[float, int, int, str]:
    """One run: (wall seconds, exit code, peak RSS in KiB, last stderr line).

    `os.wait4` returns the rusage of exactly the process it reaps — the number
    `/usr/bin/time -v` prints as "Maximum resident set size" — where a shared
    `RUSAGE_CHILDREN` reading would be the maximum over hyperfine and git too.
    stderr goes to a file so the read cannot deadlock against `wait4`.
    """
    with tempfile.TemporaryFile() as stderr:
        start = time.perf_counter()
        proc = subprocess.Popen(
            cmd.argv, cwd=str(cwd), env=cmd.env, stdout=subprocess.DEVNULL, stderr=stderr
        )
        killer = threading.Timer(TIMEOUT_SEC, proc.kill)
        killer.start()
        try:
            _, status, rusage = os.wait4(proc.pid, 0)
        finally:
            killer.cancel()
        wall = time.perf_counter() - start
        # Popen still believes the child is running; tell it otherwise so its
        # finaliser does not wait on an already reaped pid.
        proc.returncode = os.waitstatus_to_exitcode(status)
        if proc.returncode == -signal.SIGKILL:
            raise subprocess.TimeoutExpired(cmd.argv, TIMEOUT_SEC)
        stderr.seek(0)
        tail = stderr.read().decode("utf-8", "replace").strip().splitlines()
    return wall, proc.returncode, rusage.ru_maxrss, tail[-1][:160] if tail else ""


def measure(cmd: Command, cwd: Path, runs: int, warmup: int, hyperfine: bool) -> Measurement:
    if shutil.which(cmd.argv[0]) is None and not Path(cmd.argv[0]).is_file():
        return Measurement(error=f"{cmd.argv[0]} が見つからない")
    if cmd.prepare is not None:
        subprocess.run(
            cmd.prepare, cwd=str(cwd), env=cmd.env, capture_output=True, timeout=TIMEOUT_SEC
        )
    try:
        if hyperfine:
            result = _measure_hyperfine(cmd, cwd, runs, warmup)
        else:
            result = _measure_loop(cmd, cwd, runs, warmup)
        if result.error is None and result.max_rss_kb is None:
            _, exit_code, result.max_rss_kb, _ = _run_once(cmd, cwd)
            if result.exit_code is None:
                result.exit_code = exit_code
    except subprocess.TimeoutExpired:
        return Measurement(error=f"{TIMEOUT_SEC}s でタイムアウト")
    except OSError as exc:
        return Measurement(error=f"起動できない: {exc}")
    return result


def _measure_hyperfine(cmd: Command, cwd: Path, runs: int, warmup: int) -> Measurement:
    export = cwd / f".hyperfine-{cmd.tool}.json"
    argv = [
        "hyperfine",
        "--shell=none",
        "--style",
        "none",
        "--ignore-failure",
        "--warmup",
        str(warmup),
        "--runs",
        str(runs),
        "--export-json",
        str(export),
        shlex.join(cmd.argv),
    ]
    proc = subprocess.run(
        argv,
        cwd=str(cwd),
        env=cmd.env,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SEC * (runs + warmup),
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout).strip().splitlines()
        return Measurement(error=f"hyperfine exit {proc.returncode}: {tail[-1] if tail else ''}")
    data = json.loads(export.read_text(encoding="utf-8"))["results"][0]
    export.unlink()
    codes = data.get("exit_codes") or [None]
    return Measurement(
        runs=len(data["times"]),
        mean=data["mean"],
        stddev=data.get("stddev"),
        min=data["min"],
        max=data["max"],
        exit_code=codes[-1],
    )


def _measure_loop(cmd: Command, cwd: Path, runs: int, warmup: int) -> Measurement:
    for _ in range(warmup):
        _run_once(cmd, cwd)
    times = []
    rss = []
    exit_code = None
    for _ in range(runs):
        wall, exit_code, max_rss, _ = _run_once(cmd, cwd)
        times.append(wall)
        rss.append(max_rss)
    return Measurement(
        runs=len(times),
        mean=statistics.fmean(times),
        stddev=statistics.stdev(times) if len(times) > 1 else None,
        min=min(times),
        max=max(times),
        max_rss_kb=max(rss),
        exit_code=exit_code,
    )


# ============================================================
# Network availability
# ============================================================


def network_unavailable(
    zghalint: Path, cwd: Path, files: list[str], cache_home: Path
) -> str | None:
    """Reason the network rows cannot be trusted, or None when they can.

    zghalint reports a failed prefetch only by leaving the cache empty (it
    degrades to offline rules rather than failing the lint), so the probe is
    "did a cold run write a cache entry". zizmor aborts the whole run instead,
    which its exit status 1 and `fatal:` line make visible.
    """
    env = dict(os.environ, XDG_CACHE_HOME=str(cache_home))
    probe = files[: min(len(files), 20)]
    subprocess.run(
        [str(zghalint), "--format", "json", "--color", "never", "--no-cache", *probe],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        timeout=TIMEOUT_SEC,
    )
    if not any(cache_home.rglob("*.json")):
        return "zghalint のコールド実行でキャッシュが書かれない (api.github.com に到達できない)"
    proc = subprocess.run(
        ["zizmor", "--format", "json", "--no-progress", *probe],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SEC,
    )
    if proc.returncode == 1:
        tail = proc.stderr.strip().splitlines()
        return f"zizmor のオンライン実行が失敗: {tail[-1][:160] if tail else 'exit 1'}"
    return None


# ============================================================
# Orchestration and report
# ============================================================


@dataclass
class Row:
    scenario: str
    tool: str
    condition: str
    result: Measurement


@dataclass
class PerfReport:
    scenarios: list[Scenario]
    rows: list[Row]
    skipped: dict[str, str]
    environment: dict[str, str]


def run_perf(
    zghalint: Path, cases_dir: Path, corpus_dir: Path, runs: int, warmup: int, tmp: Path
) -> PerfReport:
    hyperfine = shutil.which("hyperfine") is not None
    scenarios = [
        cases_scenario(cases_dir),
        huge_scenario(tmp),
        many_small_scenario(corpus_dir, tmp),
    ]
    rows: list[Row] = []
    skipped: dict[str, str] = {}

    for scenario in scenarios:
        if scenario.unavailable is not None:
            skipped[scenario.name] = scenario.unavailable
            continue
        for cmd in tool_commands(zghalint, scenario.files):
            print(f"  {scenario.name}: {cmd.tool}", file=sys.stderr)
            rows.append(
                Row(
                    scenario.name,
                    cmd.tool,
                    cmd.condition,
                    measure(cmd, scenario.cwd, runs, warmup, hyperfine),
                )
            )

    cases = scenarios[0]
    cache_home = tmp / "xdg-cache"
    cache_home.mkdir()
    reason = network_unavailable(zghalint, cases.cwd, cases.files, cache_home)
    if reason is not None:
        skipped["network"] = reason
    else:
        for cmd in network_commands(zghalint, cases.files, cache_home):
            print(f"  network: {cmd.tool} {cmd.condition}", file=sys.stderr)
            rows.append(
                Row(
                    "network",
                    cmd.tool,
                    cmd.condition,
                    measure(cmd, cases.cwd, runs, warmup, hyperfine),
                )
            )

    environment = {
        "date": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "platform": platform.platform(),
        "cpu": f"{os.cpu_count()} logical CPUs",
        "runs": f"{runs} (warmup {warmup})",
        "timer": _version(["hyperfine", "--version"]) if hyperfine else "in-process loop",
        "zghalint": f"`{zghalint}` {_version([str(zghalint), '--version'])}",
        "actionlint": _version(["actionlint", "-version"]).splitlines()[0],
        "zizmor": _version(["zizmor", "--version"]),
    }
    return PerfReport(scenarios, rows, skipped, environment)


def _version(argv: list[str]) -> str:
    if shutil.which(argv[0]) is None and not Path(argv[0]).is_file():
        return "未インストール"
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except OSError as exc:
        return f"不明 ({exc})"
    return (proc.stdout or proc.stderr).strip() or "不明"


def _seconds(value: float | None) -> str:
    if value is None:
        return "–"
    return f"{value * 1000:.1f} ms" if value < 1 else f"{value:.3f} s"


def _cell(m: Measurement) -> tuple[str, str, str, str, str]:
    if m.error is not None:
        return (f"**error**: {m.error}", "–", "–", "–", "–")
    mean = _seconds(m.mean)
    if m.stddev is not None:
        mean += f" ± {_seconds(m.stddev)}"
    rss = f"{m.max_rss_kb / 1024:.1f} MiB" if m.max_rss_kb is not None else "–"
    return (mean, _seconds(m.min), _seconds(m.max), rss, str(m.exit_code))


def render_markdown(report: PerfReport) -> str:
    out = ["# bench 性能", ""]
    out.append("| 項目 | 値 |")
    out.append("|---|---|")
    for key, value in report.environment.items():
        out.append(f"| {key} | {value} |")
    out.append("")

    out.append("## シナリオ")
    out.append("")
    out.append("| シナリオ | 内容 | ファイル数 | 総行数 |")
    out.append("|---|---|---|---|")
    for s in report.scenarios:
        if s.unavailable is not None:
            out.append(f"| `{s.name}` | {s.description} | – | – |")
        else:
            out.append(f"| `{s.name}` | {s.description} | {len(s.files):,} | {s.lines:,} |")
    cases = report.scenarios[0]
    out.append(
        f"| `network` | コールド / ウォーム比較 (`cases` と同じ {len(cases.files)} ファイル) "
        f"| {len(cases.files):,} | {cases.lines:,} |"
    )
    out.append("")

    out.append("## 結果")
    out.append("")
    out.append("| シナリオ | tool | 条件 | mean ± σ | min | max | 最大 RSS | exit |")
    out.append("|---|---|---|---|---|---|---|---|")
    for row in report.rows:
        cells = _cell(row.result)
        out.append(
            f"| `{row.scenario}` | {row.tool} | {row.condition} | " + " | ".join(cells) + " |"
        )
    out.append("")
    out.append(
        "exit は最後の計測実行の終了コード。指摘ありで非ゼロになるのは 3 ツールとも正常 "
        "(zghalint 1、actionlint 1、zizmor 10〜14)。zghalint の 2 は「一部ファイルを lint "
        "できなかった」で、`cases` にはパースを拒否する堅牢性ケースが含まれる。"
    )
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


def as_json(report: PerfReport) -> dict:
    return {
        "environment": report.environment,
        "scenarios": [
            {
                "name": s.name,
                "description": s.description,
                "files": len(s.files),
                "lines": s.lines if s.unavailable is None else None,
                "unavailable": s.unavailable,
            }
            for s in report.scenarios
        ],
        "rows": [
            {
                "scenario": r.scenario,
                "tool": r.tool,
                "condition": r.condition,
                **vars(r.result),
            }
            for r in report.rows
        ],
        "skipped": report.skipped,
    }
