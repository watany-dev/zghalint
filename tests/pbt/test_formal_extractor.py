"""The formal-methods extractor must still find the tables in security.zig.

``scripts/formal/impl.py`` is the only reader of those table names. A rename
that the extractor does not follow used to pass CI because nothing called
``load()`` (#307). This test is that call: no z3, no binary.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "formal" / "impl.py"


def load_extractor():
    spec = importlib.util.spec_from_file_location("formal_impl", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


impl = load_extractor()


def test_extractor_loads_current_tables():
    tables = impl.load()
    assert tables.run_dangerous
    assert tables.bare_inputs == ["inputs"]
    assert "workflow_dispatch" in tables.dispatch_payload
    assert "repository_dispatch" in tables.dispatch_payload
    assert "github.event.inputs" in tables.dispatch_payload["workflow_dispatch"]
    assert "github.event.client_payload" in tables.dispatch_payload["repository_dispatch"]
    assert "issue_comment" in tables.trigger_contexts
    assert "github.event.issue.number" in tables.trigger_contexts["issue_comment"]
    assert "pull_request_review" in tables.privileged_pr_head
    assert "pull_request_review_comment" in tables.privileged_pr_head
    assert "env_context" in tables.followed_flows
    assert "job_output" in tables.followed_flows
