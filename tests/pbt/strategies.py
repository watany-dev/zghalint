"""Hypothesis custom strategies for zghalint PBT."""
from __future__ import annotations

from hypothesis import strategies as st

# ============================================================
# Low-level strategies (crash resistance)
# ============================================================

# Arbitrary byte sequences (0-1KB)
random_bytes = st.binary(min_size=0, max_size=1024)

# Random UTF-8 text (including newlines)
random_text = st.text(min_size=0, max_size=500)

# YAML structural fragments mixed with random text
_yaml_fragments = [
    "name: CI",
    "on: push",
    "on: [push, pull_request]",
    "jobs:",
    "  build:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    '      - run: echo "hello"',
    "    env:",
    "      KEY: value",
    "- item",
    "key: value",
    "# comment",
    "${{ github.event.issue.title }}",
    "'single quoted'",
    '"double quoted"',
    "null",
    "true",
    "42",
    "|",
    ">",
    "---",
    "...",
    "    ",
    "",
]

yaml_like_text = st.lists(
    st.sampled_from(_yaml_fragments) | st.text(max_size=50),
    min_size=1,
    max_size=20,
).map("\n".join)

# Text without newlines (for embedding inside a YAML run: line)
expression_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",),
        blacklist_characters="\n\r",
    ),
    min_size=0,
    max_size=200,
)

# ============================================================
# High-level strategies (structurally valid workflows)
# ============================================================

_triggers = ["push", "pull_request", "pull_request_target",
             "workflow_dispatch", "release", "issues", "issue_comment"]

_runners = ["ubuntu-latest", "ubuntu-22.04", "macos-latest", "windows-latest"]

_pinned_actions = [
    "actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29",
    "actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8",
    "actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94d9d67",
]

_unpinned_actions = [
    "actions/checkout@v4",
    "actions/setup-node@v3",
    "actions/cache@v3",
    "actions/upload-artifact@v4",
]

_safe_commands = [
    'echo "hello"',
    "npm test",
    "npm install",
    "pip install -r requirements.txt",
    "make build",
    "cargo test",
    "ls -la",
]

# Contexts that SEC002 detects as dangerous
_dangerous_contexts = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.head_ref",
    "github.event.head_commit.message",
]

# Prefixes that SEC003 detects as hardcoded secrets
_secret_values = [
    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12",
    "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12",
    "AKIAIOSFODNN7EXAMPLE",
    "xoxb-1234-5678-abcdefgh",
]


@st.composite
def workflow_yaml(draw: st.DrawFn) -> str:
    """Generate a structurally valid GitHub Actions workflow YAML.

    The generated workflow always parses successfully, but may contain
    lint issues (unpinned actions, missing timeouts, etc.).
    """
    name = draw(st.sampled_from(["CI", "Build", "Test", "Deploy", "Lint"]))
    trigger = draw(st.sampled_from(_triggers))
    num_jobs = draw(st.integers(min_value=1, max_value=3))

    jobs_lines: list[str] = []
    for i in range(num_jobs):
        job_id = f"job{i}"
        runner = draw(st.sampled_from(_runners))
        has_timeout = draw(st.booleans())

        lines = [f"  {job_id}:", f"    runs-on: {runner}"]
        if has_timeout:
            timeout = draw(st.integers(min_value=1, max_value=360))
            lines.append(f"    timeout-minutes: {timeout}")

        num_steps = draw(st.integers(min_value=1, max_value=4))
        step_lines: list[str] = []
        for _ in range(num_steps):
            kind = draw(st.sampled_from(["pinned", "unpinned", "run"]))
            if kind == "pinned":
                action = draw(st.sampled_from(_pinned_actions))
                step_lines.append(f"      - uses: {action}")
            elif kind == "unpinned":
                action = draw(st.sampled_from(_unpinned_actions))
                step_lines.append(f"      - uses: {action}")
            else:
                cmd = draw(st.sampled_from(_safe_commands))
                step_lines.append(f"      - run: {cmd}")

        lines.append("    steps:")
        lines.extend(step_lines)
        jobs_lines.extend(lines)

    return f"name: {name}\non: {trigger}\njobs:\n" + "\n".join(jobs_lines) + "\n"


@st.composite
def workflow_with_script_injection(draw: st.DrawFn) -> str:
    """Generate a workflow guaranteed to trigger SEC002 (script injection)."""
    context = draw(st.sampled_from(_dangerous_contexts))
    trigger = draw(st.sampled_from(["pull_request", "issues", "issue_comment", "push"]))
    # Use literal block scalar (|) to preserve ${{ }} verbatim through YAML parsing
    return (
        "name: CI\n"
        f"on: {trigger}\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        f"          echo ${{{{ {context} }}}}\n"
    )


@st.composite
def workflow_with_unpinned_action(draw: st.DrawFn) -> str:
    """Generate a workflow guaranteed to trigger SEC001 (unpinned action)."""
    action = draw(st.sampled_from(_unpinned_actions))
    return (
        "name: CI\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: {action}\n"
    )


@st.composite
def workflow_with_hardcoded_secret(draw: st.DrawFn) -> str:
    """Generate a workflow guaranteed to trigger SEC003 (hardcoded secret)."""
    secret = draw(st.sampled_from(_secret_values))
    return (
        "name: CI\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - run: curl {secret}\n"
    )


@st.composite
def workflow_with_bp005(draw: st.DrawFn) -> str:
    """Generate a workflow guaranteed to trigger BP005 (push without concurrency).

    The workflow always includes a push trigger and never defines
    concurrency, so BP005 fires. Other rules may fire as well.
    """
    runner = draw(st.sampled_from(_runners))
    return (
        "name: CI\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        f"    runs-on: {runner}\n"
        "    steps:\n"
        "      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29\n"
    )


@st.composite
def workflow_with_perm002(draw: st.DrawFn) -> str:
    """Generate a workflow guaranteed to trigger PERM002 (missing job perms).

    The job uses a third-party action and omits job-level permissions, so
    PERM002 fires.
    """
    runner = draw(st.sampled_from(_runners))
    action = draw(st.sampled_from([
        "some-org/some-action@a5ac7e51b41094c92402da3b24376905380afc29",
        "another-org/tool@a5ac7e51b41094c92402da3b24376905380afc29",
    ]))
    return (
        "name: CI\n"
        "on: push\n"
        "concurrency:\n"
        "  group: ci-${{ github.ref }}\n"
        "  cancel-in-progress: true\n"
        "jobs:\n"
        "  build:\n"
        f"    runs-on: {runner}\n"
        "    timeout-minutes: 10\n"
        "    steps:\n"
        f"      - uses: {action}\n"
    )


@st.composite
def dependabot_with_dep001(draw: st.DrawFn) -> str:
    """Generate a dependabot config guaranteed to trigger DEP001 (missing cooldown)."""
    ecosystem = draw(st.sampled_from(["npm", "pip", "docker", "github-actions"]))
    interval = draw(st.sampled_from(["daily", "weekly", "monthly"]))
    return (
        "version: 2\n"
        "updates:\n"
        f"  - package-ecosystem: \"{ecosystem}\"\n"
        "    directory: \"/\"\n"
        "    schedule:\n"
        f"      interval: \"{interval}\"\n"
    )


@st.composite
def workflow_pair_monotonic(draw: st.DrawFn) -> tuple[str, str]:
    """Generate (base, extended) where extended has strictly more issue-bearing steps.

    Both are valid workflows.  The extended workflow appends extra jobs
    with known issues, so the diagnostic count should be >= the base count.
    """
    base = draw(workflow_yaml())

    # Create additional jobs with known issues
    num_extra = draw(st.integers(min_value=1, max_value=3))
    extra_jobs: list[str] = []
    for i in range(num_extra):
        job_id = f"  extra{i}:"
        action = draw(st.sampled_from(_unpinned_actions))
        extra_jobs.extend([
            job_id,
            "    runs-on: ubuntu-latest",
            "    steps:",
            f"      - uses: {action}",
        ])

    extended = base.rstrip("\n") + "\n" + "\n".join(extra_jobs) + "\n"
    return base, extended
