"""Determinism: identical inputs must always produce identical outputs."""
from __future__ import annotations

import os

from hypothesis import given, settings, HealthCheck

from tests.pbt.conftest import run_zghalint, write_temp_workflow
from tests.pbt.strategies import workflow_yaml, yaml_like_text

PBT_SETTINGS = settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_deterministic_terminal_output(zghalint_bin, content):
    """Linting the same file twice must yield identical terminal output."""
    path = write_temp_workflow(content)
    try:
        r1 = run_zghalint(zghalint_bin, "--color", "never", path)
        r2 = run_zghalint(zghalint_bin, "--color", "never", path)
        assert r1.returncode == r2.returncode, (
            f"Return codes differ: {r1.returncode} vs {r2.returncode}"
        )
        assert r1.stdout == r2.stdout, "stdout differs between runs"
    finally:
        os.unlink(path)


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_deterministic_json_output(zghalint_bin, content):
    """JSON output must be bit-for-bit identical across runs on the same file."""
    path = write_temp_workflow(content)
    try:
        r1 = run_zghalint(zghalint_bin, "--format", "json", "--color", "never", path)
        r2 = run_zghalint(zghalint_bin, "--format", "json", "--color", "never", path)
        assert r1.returncode == r2.returncode
        assert r1.stdout == r2.stdout, "JSON output differs between runs"
    finally:
        os.unlink(path)


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_deterministic_sarif_output(zghalint_bin, content):
    """SARIF output must be bit-for-bit identical across runs on the same file."""
    path = write_temp_workflow(content)
    try:
        r1 = run_zghalint(zghalint_bin, "--format", "sarif", "--color", "never", path)
        r2 = run_zghalint(zghalint_bin, "--format", "sarif", "--color", "never", path)
        assert r1.returncode == r2.returncode
        assert r1.stdout == r2.stdout, "SARIF output differs between runs"
    finally:
        os.unlink(path)


@given(content=yaml_like_text)
@PBT_SETTINGS
def test_deterministic_on_malformed_yaml(zghalint_bin, content):
    """Even malformed YAML must produce deterministic results."""
    path = write_temp_workflow(content)
    try:
        r1 = run_zghalint(zghalint_bin, "--format", "json", "--color", "never", path)
        r2 = run_zghalint(zghalint_bin, "--format", "json", "--color", "never", path)
        assert r1.returncode == r2.returncode
        assert r1.stdout == r2.stdout
    finally:
        os.unlink(path)
