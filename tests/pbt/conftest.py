"""PBT fixtures: zghalint binary build and execution helper."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class LintResult:
    returncode: int
    stdout: str
    stderr: str


@pytest.fixture(scope="session")
def zghalint_bin() -> Path:
    """Build once per session and return the binary path."""
    binary = PROJECT_ROOT / "zig-out" / "bin" / "zghalint"
    if not binary.exists():
        zig = shutil.which("zig")
        if zig is None:
            pytest.skip("zig not found in PATH")
        result = subprocess.run(
            [zig, "build"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            pytest.fail(f"zig build failed:\n{result.stderr}")
    assert binary.exists(), f"Binary not found: {binary}"
    return binary


def run_zghalint(binary: Path, *args: str, timeout: int = 10) -> LintResult:
    """Run zghalint as a subprocess with a timeout."""
    result = subprocess.run(
        [str(binary), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return LintResult(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )
