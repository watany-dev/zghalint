"""YAML round-trip: parse(s) == parse(emit(parse(s))) for documents that parse."""

from __future__ import annotations

import os

from hypothesis import HealthCheck, given, settings

from tests.pbt.conftest import run_zghalint, write_temp_workflow
from tests.pbt.strategies import workflow_yaml, yaml_like_text

PBT_SETTINGS = settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def _assert_roundtrip(zghalint_bin, content: str) -> None:
    path = write_temp_workflow(content)
    try:
        result = run_zghalint(zghalint_bin, "--check-yaml-roundtrip", path)
        assert result.returncode != 2, (
            f"zghalint could not read the temp file\nstderr:\n{result.stderr}\nWorkflow:\n{content}"
        )
        assert result.returncode == 0, (
            f"round-trip failed (exit {result.returncode})\n"
            f"stderr:\n{result.stderr}\nWorkflow:\n{content}"
        )
    finally:
        os.unlink(path)


@given(content=workflow_yaml())
@PBT_SETTINGS
def test_generated_workflow_roundtrips(zghalint_bin, content):
    """A structurally valid workflow must survive parse → emit → parse."""
    _assert_roundtrip(zghalint_bin, content)


@given(content=yaml_like_text)
@PBT_SETTINGS
def test_yaml_like_text_roundtrips_or_rejects(zghalint_bin, content):
    """Unparseable input is skipped; anything that parses must round-trip."""
    _assert_roundtrip(zghalint_bin, content)
