"""Unit tests for `scripts/gen-advisories.py`."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "gen-advisories.py"


def load_generator():
    spec = importlib.util.spec_from_file_location("gen_advisories", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = load_generator()


def test_rows_from_advisories_skips_non_actions_and_sanitizes():
    payload = json.loads(
        """
        [
          {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "summary": "one\\ttwo\\nthree",
            "vulnerabilities": [
              {
                "package": {"ecosystem": "actions", "name": "owner/repo"},
                "vulnerable_version_range": "< 1.0.0",
                "first_patched_version": "1.0.0"
              },
              {
                "package": {"ecosystem": "npm", "name": "left-pad"},
                "vulnerable_version_range": "< 2.0.0",
                "first_patched_version": "2.0.0"
              }
            ]
          }
        ]
        """
    )
    rows = gen.rows_from_advisories(payload)
    assert len(rows) == 1
    ghsa, slug, message, hint, range_s, patched = rows[0]
    assert ghsa == "GHSA-aaaa-bbbb-cccc"
    assert slug == "owner/repo"
    assert "\t" not in message and "\n" not in message
    assert "one two three" in message
    assert range_s == "< 1.0.0"
    assert patched == "1.0.0"
    assert "1.0.0" in hint


def test_render_zig_is_a_tsv_block():
    text = gen.render_zig(
        [("GHSA-x", "o/r", "msg", "hint", "< 1", "1")],
        "2026-09-16",
    )
    assert 'pub const generated_at = "2026-09-16";' in text
    assert "GHSA-x\\to/r\\tmsg\\thint\\t< 1\\t1" in text
