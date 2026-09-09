"""Unit tests for `scripts/bench_alloc.py` parsing and report wiring."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "bench_alloc.py"


def load_mod():
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("bench_alloc", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


alloc = load_mod()


def test_parse_alloc_stats_line_ignores_other_stderr():
    stderr = (
        "error: cannot open 'missing.yml': FileNotFound\n"
        'alloc-stats: {"allocs":12,"frees":10,"remaps":1,"bytes":4096,'
        '"peak":2048,"current":0,"small":8,"medium":3,"large":1,'
        '"elapsed_ns":1234567,"rss_kb":1800,'
        '"phases":{"args":{"ns":1000,"allocs":4,"bytes":128}}}\n'
    )
    stats = alloc.parse_alloc_stats_line(stderr)
    assert stats is not None
    assert stats.allocs == 12
    assert stats.peak == 2048
    assert stats.phases["args"]["allocs"] == 4


def test_parse_alloc_stats_line_missing():
    assert alloc.parse_alloc_stats_line("no stats here\n") is None


def test_parse_strace_c_reads_calls_and_optional_errors():
    text = """\
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 50.00    0.001000        1000        10           mmap
 25.00    0.000500          50        20         3 openat
 25.00    0.000500          25        20           newfstatat
------ ----------- ----------- --------- --------- ----------------
100.00    0.002000                    50         3 total
"""
    rows = alloc.parse_strace_c(text)
    by_name = {r.name: r for r in rows}
    assert set(by_name) == {"mmap", "openat", "newfstatat"}
    assert by_name["openat"].calls == 20
    assert by_name["openat"].errors == 3
    assert by_name["mmap"].errors == 0
    assert rows[0].name in {"openat", "newfstatat"}


def test_tile_cases_repeats_until_count(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.yml").write_text("name: a\n", encoding="utf-8")
    (src / "b.yml").write_text("name: b\n", encoding="utf-8")
    cases = alloc.bench_perf.Scenario("cases", "x", src, ["a.yml", "b.yml"], 2)
    tiled = alloc._tile_cases(cases, tmp_path, 5)
    assert tiled.name == "many-files"
    assert len(tiled.files) == 5
    assert (tiled.cwd / tiled.files[0]).read_text(encoding="utf-8") == "name: a\n"
    assert (tiled.cwd / tiled.files[2]).read_text(encoding="utf-8") == "name: a\n"


def test_render_markdown_includes_version_and_alloc_columns():
    report = alloc.AllocReport(
        rows=[
            alloc.Row(
                "version",
                "startup floor",
                0,
                0,
                alloc.bench_perf.Measurement(
                    runs=3, mean=0.001, min=0.001, max=0.002, max_rss_kb=1800, exit_code=0
                ),
                alloc.AllocStats(allocs=5, frees=5, remaps=0, bytes=64, peak=64, current=0),
                [],
                binary_bytes=1024,
            )
        ],
        skipped={},
        environment={"zghalint": "test"},
    )
    text = alloc.render_markdown(report)
    assert "| `version` |" in text
    assert "allocs" in text
    assert "peak/RSS" in text
