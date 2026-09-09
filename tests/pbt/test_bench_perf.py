"""Unit tests for `scripts/bench_perf.py` rival-tool wiring.

The weekly `--perf` job is how we claim to be faster than other GitHub
Actions linters, so the argv and the `.github/workflows/` staging layout
are worth pinning down without running hyperfine.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "bench_perf.py"


def load_mod():
    spec = importlib.util.spec_from_file_location("bench_perf", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


perf = load_mod()


def test_file_tool_commands_include_action_validator():
    cmds = perf.file_tool_commands(Path("/tmp/zghalint"), ["a.yml", "b.yml"])
    by_tool = {c.tool: c for c in cmds}
    assert set(by_tool) == {"zghalint", "actionlint", "zizmor", "action-validator"}
    assert by_tool["action-validator"].argv == ["action-validator", "a.yml", "b.yml"]
    assert "--offline" in by_tool["zghalint"].argv
    assert "--offline" in by_tool["zizmor"].argv


def test_repo_tool_commands_stay_offline_and_scan_the_repo():
    cmds = perf.repo_tool_commands()
    by_tool = {c.tool: c for c in cmds}
    assert set(by_tool) == {"ghalint", "octoscan", "poutine"}
    assert by_tool["ghalint"].argv == ["ghalint", "--log-color", "never", "run"]
    assert by_tool["octoscan"].argv[:3] == ["octoscan", "scan", "."]
    assert "--disable-version-check" in by_tool["poutine"].argv
    assert by_tool["poutine"].argv[:3] == ["poutine", "analyze_local", "."]
    for cmd in cmds:
        assert cmd.condition == "offline (repo)"


def test_stage_github_workflows_flattens_and_disambiguates(tmp_path: Path):
    src = tmp_path / "src"
    (src / "one").mkdir(parents=True)
    (src / "two").mkdir()
    (src / "one" / "ci.yml").write_text("a\n", encoding="utf-8")
    (src / "two" / "ci.yml").write_text("b\n", encoding="utf-8")
    dest = tmp_path / "repo"
    perf.stage_github_workflows(src, ["one/ci.yml", "two/ci.yml"], dest)
    workflows = dest / ".github" / "workflows"
    names = sorted(p.name for p in workflows.iterdir())
    assert names == ["0000-ci.yml", "0001-ci.yml"]
    assert (workflows / "0000-ci.yml").read_text(encoding="utf-8") == "a\n"
    assert (workflows / "0001-ci.yml").read_text(encoding="utf-8") == "b\n"
    assert (dest / ".git").is_dir()


def test_render_markdown_lists_rival_rows():
    report = perf.PerfReport(
        scenarios=[perf.Scenario("cases", "ベンチケース一括", Path("."), ["a.yml"], lines=3)],
        rows=[
            perf.Row(
                "cases",
                "ghalint",
                "offline (repo)",
                perf.Measurement(runs=1, mean=0.01, min=0.01, max=0.01, exit_code=1),
            )
        ],
        skipped={},
        environment={"ghalint": "1.5.6"},
    )
    text = perf.render_markdown(report)
    assert "| `cases` | ghalint | offline (repo) |" in text
    assert ".github/workflows/" in text
