"""Unit tests for `scripts/fetch-corpus.py` path-preserving copy.

Flattening workflows made every `uses: ./` unresolvable and let the
repository-root walk escape into zghalint itself (PR #306 / #554).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "fetch-corpus.py"


def load_mod():
    spec = importlib.util.spec_from_file_location("fetch_corpus", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fetch = load_mod()


def test_copy_repo_keeps_workflow_and_action_paths(tmp_path: Path):
    checkout = tmp_path / "src"
    workflows = checkout / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("name: ci\n", encoding="utf-8")
    (checkout / "merge" / "action.yml").parent.mkdir()
    (checkout / "merge" / "action.yml").write_text("name: merge\n", encoding="utf-8")
    (checkout / ".git" / "config").parent.mkdir()
    (checkout / ".git" / "config").write_text("gitdir\n", encoding="utf-8")

    target = tmp_path / "out" / "acme__tool"
    names = fetch.copy_repo(checkout, target)

    assert names == ["ci.yml"]
    assert (target / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8") == "name: ci\n"
    assert (target / "merge" / "action.yml").read_text(encoding="utf-8") == "name: merge\n"
    assert (target / ".git").is_dir()
    assert not (target / ".git" / "config").exists()


def test_copy_repo_empty_without_workflows(tmp_path: Path):
    checkout = tmp_path / "src"
    checkout.mkdir()
    (checkout / "action.yml").write_text("name: root\n", encoding="utf-8")
    assert fetch.copy_repo(checkout, tmp_path / "out") == []
