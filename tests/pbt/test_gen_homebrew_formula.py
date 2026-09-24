"""Checks for scripts/gen-homebrew-formula.sh.

The generator only runs on tag push, so a missing archive entry or an empty
checksum used to surface only mid-release. These are the same assertions the
lint job used to inline in ci.yml.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from pathlib import Path

import pytest

GENERATOR = Path(__file__).resolve().parents[2] / "scripts" / "gen-homebrew-formula.sh"

TARGETS = ("linux-aarch64", "linux-x86_64", "macos-aarch64", "macos-x86_64")

if platform.system() == "Windows":
    pytest.skip("gen-homebrew-formula.sh targets POSIX shells", allow_module_level=True)


def write_sums(path: Path) -> None:
    path.write_text(
        "".join(f"{'0' * 64}  zghalint-{target}.tar.gz\n" for target in TARGETS), encoding="utf-8"
    )


def generate(sums: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(GENERATOR), "v9.9.9", str(sums)],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_formula_lists_every_release_archive(tmp_path: Path):
    sums = tmp_path / "SHA256SUMS"
    write_sums(sums)

    result = generate(sums)
    assert result.returncode == 0, result.stderr
    for target in TARGETS:
        assert f"zghalint-{target}.tar.gz" in result.stdout


def test_generated_formula_is_valid_ruby(tmp_path: Path):
    ruby = shutil.which("ruby")
    assert ruby is not None, "ruby is required to syntax-check the generated formula"

    sums = tmp_path / "SHA256SUMS"
    write_sums(sums)
    result = generate(sums)
    assert result.returncode == 0, result.stderr

    formula = tmp_path / "zghalint.rb"
    formula.write_text(result.stdout, encoding="utf-8")
    syntax = subprocess.run([ruby, "-c", str(formula)], capture_output=True, text=True, timeout=30)
    assert syntax.returncode == 0, syntax.stderr


def test_rejects_a_checksum_file_with_no_entries(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.write_text("", encoding="utf-8")

    result = generate(empty)
    assert result.returncode != 0
