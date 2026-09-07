"""Unit tests for `scripts/gen-popular-actions.py`.

The generated table is committed, so a broken escape or a malformed entry
fails `zig fmt` at generation time. What it does *not* catch is a misread
`required:` or `default:`: the table stays well-formed and the linter simply
starts asking for an input nobody has to pass. These tests cover that.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "gen-popular-actions.py"


def load_generator():
    spec = importlib.util.spec_from_file_location("gen_popular_actions", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # The dataclass decorator resolves annotations through sys.modules.
    import sys

    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gen = load_generator()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, True),
        (False, False),
        ("true", True),
        ("True", True),
        ("  true  ", True),
        ("false", False),
        # A quoted "false" is a string, and `bool("false")` would be True.
        ('"false"', False),
        (None, False),
        (1, False),
    ],
)
def test_is_true_reads_required_like_the_runner(value, expected):
    assert gen.is_true(value) is expected


def test_a_default_makes_a_required_input_optional():
    doc = {
        "runs": {"using": "node20"},
        "inputs": {
            "must": {"required": True},
            "has-default": {"required": True, "default": "x"},
            "plain": {},
        },
    }
    meta = collect_from(doc)
    assert [(i.name, i.required) for i in meta.inputs] == [
        ("must", True),
        ("has-default", False),
        ("plain", False),
    ]


def test_deprecation_message_is_carried_through():
    doc = {
        "runs": {"using": "node20"},
        "inputs": {"old": {"deprecationMessage": "use `new` instead"}},
    }
    assert collect_from(doc).inputs[0].deprecation == "use `new` instead"


@pytest.mark.parametrize(
    "doc",
    [
        "not a mapping",
        {"inputs": {"a": {}}},
        {"runs": {"main": "index.js"}},
        {"runs": "composite"},
        {"runs": {"using": "node20"}, "inputs": ["a", "b"]},
    ],
)
def test_a_manifest_that_cannot_be_read_stops_the_run(doc):
    with pytest.raises(SystemExit):
        collect_from(doc)


def collect_from(doc, path=""):
    """Run `collect` against `doc` instead of a real checkout."""
    original = gen.read_manifest_yaml
    gen.read_manifest_yaml = lambda _checkout, _path: doc
    try:
        return gen.collect("owner", "repo", path, "v1", Path("."))
    finally:
        gen.read_manifest_yaml = original


@pytest.mark.parametrize("ref", ["v4", "v4.2.2", "v12.0.1"])
def test_major_of_accepts_a_version_tag(ref):
    assert gen.major_of(ref) == int(ref[1:].split(".")[0])


@pytest.mark.parametrize("ref", ["4", "V4", "main", "v4-beta", "4.x-maintenance", "v"])
def test_major_of_rejects_anything_else(ref):
    with pytest.raises(SystemExit):
        gen.major_of(ref)


def test_parse_manifest_skips_comments_and_blank_lines():
    text = "\n".join(
        [
            "# a comment",
            "",
            "actions/checkout@v4",
            "actions/cache/restore@v4  # trailing comment",
            "   ",
        ]
    )
    assert gen.parse_manifest(text) == [
        ("actions", "checkout", "", "v4"),
        ("actions", "cache", "restore", "v4"),
    ]


def test_parse_manifest_rejects_a_line_it_cannot_read():
    with pytest.raises(SystemExit):
        gen.parse_manifest("actions/checkout\n")


def test_zig_string_escapes_what_zig_cannot_take_literally():
    assert gen.zig_string('a"b\\c\nd\te') == '"a\\"b\\\\c\\nd\\te"'


def test_the_committed_table_is_what_render_produces_for_its_header():
    generated = (PROJECT_ROOT / "src" / "rules" / "data" / "popular_actions.zig").read_text()
    assert generated.startswith(gen.HEADER)
