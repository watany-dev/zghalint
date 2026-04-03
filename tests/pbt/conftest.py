"""PBT fixtures: zghalint binary build and execution helpers."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
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
    """Build once per session (ReleaseSafe for PBT speed) and return the binary path."""
    binary = PROJECT_ROOT / "zig-out" / "bin" / "zghalint"
    zig = shutil.which("zig")
    if zig is None:
        pytest.skip("zig not found in PATH")
    # Build ReleaseSafe for fast PBT execution (Debug GPA is too slow
    # and emits non-deterministic memory-address leak warnings to stderr).
    result = subprocess.run(
        [zig, "build", "-Doptimize=ReleaseSafe"],
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
        [str(binary), "--quick", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return LintResult(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


# ============================================================
# Higher-level helpers
# ============================================================


def write_temp_workflow(content: str, suffix: str = ".yml") -> str:
    """Write content to a temp file and return its path.

    Caller must delete the file when done.
    """
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


def lint_workflow(binary: Path, content: str, *extra_args: str) -> LintResult:
    """Write *content* to a temp .yml, lint it, clean up, return result."""
    path = write_temp_workflow(content)
    try:
        return run_zghalint(binary, *extra_args, path)
    finally:
        os.unlink(path)


def lint_workflow_json(binary: Path, content: str) -> dict:
    """Lint and parse the JSON output.  Raises on non-JSON output."""
    result = lint_workflow(binary, content, "--format", "json", "--color", "never")
    return json.loads(result.stdout)


def lint_workflow_sarif(binary: Path, content: str) -> dict:
    """Lint and parse the SARIF output.  Raises on non-SARIF output."""
    result = lint_workflow(binary, content, "--format", "sarif", "--color", "never")
    return json.loads(result.stdout)


def write_temp_config(rules_overrides: dict[str, dict]) -> str:
    """Write a .zghalint.yml config to a temp file and return its path.

    ``rules_overrides`` maps rule_id → {enabled: bool, severity: str, ...}.
    Caller must delete the file.
    """
    lines = ["rules:"]
    for rule_id, overrides in rules_overrides.items():
        lines.append(f"  {rule_id}:")
        for k, v in overrides.items():
            if isinstance(v, bool):
                lines.append(f"    {k}: {'true' if v else 'false'}")
            else:
                lines.append(f"    {k}: {v}")
    fd, path = tempfile.mkstemp(suffix=".yml")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path
