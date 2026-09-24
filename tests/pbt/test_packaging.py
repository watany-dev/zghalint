"""Checks for the packaging files users copy into aqua and pre-commit.

These files are not generated on tag push, so a broken asset template or a
hook that invokes a flag zghalint does not have would only show up after
someone tried to install. The assertions are the shape the README tells
them to paste.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
AQUA = ROOT / "packaging" / "aqua-registry.yaml"
PRECOMMIT = ROOT / ".pre-commit-hooks.yaml"


def test_aqua_registry_reads_release_checksums_and_renames_go_triples():
    data = yaml.safe_load(AQUA.read_text(encoding="utf-8"))
    packages = data["packages"]
    assert len(packages) == 1
    pkg = packages[0]
    assert pkg["type"] == "github_release"
    assert pkg["repo_owner"] == "watany-dev"
    assert pkg["repo_name"] == "zghalint"
    assert pkg["description"][-1] not in ".!"

    override = pkg["version_overrides"][-1]
    assert override["version_constraint"] == "true"
    assert override["asset"] == "zghalint-{{.OS}}-{{.Arch}}.{{.Format}}"
    assert " {{" not in override["asset"]
    assert override["format"] == "tar.gz"
    assert override["replacements"] == {
        "darwin": "macos",
        "amd64": "x86_64",
        "arm64": "aarch64",
    }
    assert override["checksum"] == {
        "type": "github_release",
        "asset": "SHA256SUMS",
        "algorithm": "sha256",
    }
    assert override["files"] == [
        {"name": "zghalint", "src": "zghalint-{{.OS}}-{{.Arch}}/zghalint"},
    ]
    windows = next(item for item in override["overrides"] if item.get("goos") == "windows")
    assert windows["format"] == "zip"
    assert "windows/amd64" in override["supported_envs"]
    assert "windows/arm64" not in override["supported_envs"]


def test_pre_commit_hook_uses_the_offline_system_binary():
    hooks = yaml.safe_load(PRECOMMIT.read_text(encoding="utf-8"))
    assert len(hooks) == 1
    hook = hooks[0]
    assert hook["id"] == "zghalint"
    assert hook["language"] == "system"
    assert hook["entry"] == "zghalint --offline --"
    assert hook["types"] == ["yaml"]
    assert r"\.github/workflows/" in hook["files"]
    assert "action\\.ya?ml" in hook["files"]
