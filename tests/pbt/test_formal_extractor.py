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
    assert "job_output_2hop" in tables.followed_flows
    assert "action_output" in tables.followed_flows
    assert "action_input" in tables.followed_flows
    assert tables.code_executing_inputs["actions/github-script"] == ["script"]
    assert tables.code_executing_inputs["azure/cli"] == ["inlineScript"]
    assert "nick-fields/retry" in tables.code_executing_inputs
    assert "github.event.pull_request.head" in tables.shell_fetch_contexts
    assert "github.event.workflow_run.id" in tables.shell_fetch_contexts
    assert "github.event.workflow_run.id" in tables.artifact_run_id_contexts
    assert "tj-actions/changed-files" in tables.untrusted_output_actions
    assert "peter-evans/find-comment" in tables.untrusted_output_actions


def test_probe_tables_are_lists():
    # Probes for rules that do not exist yet: absent is an empty list, never
    # an error. Once a rule lands with the probe's name the list fills.
    tables = impl.load()
    assert isinstance(tables.shell_fetch_contexts, list)
    assert isinstance(tables.artifact_run_id_contexts, list)
    assert isinstance(tables.untrusted_output_actions, list)
    assert isinstance(tables.github_app_token_actions, list)


def test_probe_of_missing_table_is_empty():
    assert impl._probe_string_table("const other = [_][]const u8{};", "missing") == []
    assert impl._probe_string_table('const t = [_][]const u8{ "a", "b" };', "t") == ["a", "b"]


def test_code_executing_inputs_come_from_popular_actions():
    import importlib.util

    gen_path = PROJECT_ROOT / "scripts" / "formal" / "gen_actions.py"
    spec = importlib.util.spec_from_file_location("formal_gen_actions", gen_path)
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    rows = gen.load_code_executing_rows()
    keys = {(action, input_name) for action, input_name, _ in rows}
    assert ("actions/github-script", "script") in keys
    assert ("azure/cli", "inlineScript") in keys
    assert ("nick-fields/retry", "command") in keys

    formal_dir = str(PROJECT_ROOT / "scripts" / "formal")
    sys.path.insert(0, formal_dir)
    try:
        import spec as formal_spec

        spec_keys = {(ci.action, ci.input) for ci in formal_spec.CODE_EXECUTING_INPUTS}
        assert spec_keys == keys
        assert "actions/create-github-app-token#token" in formal_spec.ACTIONS
        assert "job_output_2hop" in formal_spec.FLOWS
        assert "app_token" in formal_spec.SINKS
    finally:
        sys.path.remove(formal_dir)
