#!/usr/bin/env python3
"""Score zghalint, actionlint and zizmor against the same bench cases.

Each case under `bench/cases/` declares, in a leading comment header, which
findings it expects in **tool-neutral** terms (`template-injection`) plus the
ID each tool uses for them. Running all three over one case therefore yields a
comparable row: recall, precision, line accuracy, and the findings only one
tool reports.

    python3 scripts/bench.py                 # matrix on stdout
    python3 scripts/bench.py -o bench/out.md # ...or into a file
    python3 scripts/bench.py --case a-*      # only matching cases
    python3 scripts/bench.py --json out.json # machine-readable scores too
    python3 scripts/bench.py --perf          # wall time / RSS instead (bench_perf.py)

A missing external tool is reported as unavailable rather than scored, so the
harness stays usable with only zghalint installed.

See `bench/README.md` for the header format.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import bench_perf

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CASES_DIR = REPO_ROOT / "bench" / "cases"
DEFAULT_ZGHALINT = REPO_ROOT / "zig-out" / "bin" / "zghalint"

TOOLS = ("zghalint", "actionlint", "zizmor")
PERSONAS = ("regular", "pedantic", "auditor")

#: Timeout per tool invocation. A tool that exceeds it is scored as a
#: robustness failure, never as "no findings".
TIMEOUT_SEC = 60


# ============================================================
# Neutral kind → per-tool IDs
# ============================================================

#: Mappings shared by every case, so a case header only has to carry the ones
#: it invents. `None` means "this tool is not expected to report it" and feeds
#: the unique-win column; a `~` suffix narrows an ID by message substring,
#: which actionlint needs because its `kind` field is coarse (`expression`
#: covers both untrusted interpolation and a malformed `${{ }}`).
DEFAULT_KIND_MAP: dict[str, dict[str, list[str] | None]] = {
    "template-injection": {
        "zghalint": ["SEC002"],
        "zizmor": ["template-injection"],
        "actionlint": ["expression~potentially untrusted"],
    },
    #: zizmor reports the trigger itself; zghalint only reports the unsafe
    #: checkout under it (`untrusted-checkout`), so the two are separate kinds.
    "dangerous-trigger": {
        "zghalint": None,
        "zizmor": ["dangerous-triggers"],
        "actionlint": None,
    },
    "untrusted-checkout": {
        "zghalint": ["SEC005", "SEC009", "SEC021"],
        "zizmor": None,
        "actionlint": None,
    },
    "bot-condition": {
        "zghalint": ["SEC014"],
        "zizmor": ["bot-conditions"],
        "actionlint": None,
    },
    "self-hosted-runner": {
        "zghalint": ["SEC020"],
        "zizmor": ["self-hosted-runner"],
        "actionlint": None,
    },
    "unsound-contains": {
        "zghalint": ["EXPR006"],
        "zizmor": ["unsound-contains"],
        "actionlint": None,
    },
    "unpinned-action": {
        "zghalint": ["SEC001"],
        "zizmor": ["unpinned-uses"],
        "actionlint": None,
    },
    "artipacked": {
        "zghalint": ["SEC015", "SEC018"],
        "zizmor": ["artipacked"],
        "actionlint": None,
    },
    # zghalint has no equivalent: SEC019 (secret outside env:) fires on the same
    # step but says nothing about OIDC being available instead of a token.
    "use-trusted-publishing": {
        "zghalint": None,
        "zizmor": ["use-trusted-publishing"],
        "actionlint": None,
    },
    "excessive-permissions": {
        "zghalint": ["SEC004", "SEC007"],
        "zizmor": ["excessive-permissions"],
        "actionlint": None,
    },
    "missing-timeout": {
        "zghalint": ["BP001"],
        "zizmor": None,
        "actionlint": None,
    },
    "unnamed-step": {
        "zghalint": ["BP002"],
        "zizmor": None,
        "actionlint": None,
    },
    "missing-cache": {
        "zghalint": ["PERF001"],
        "zizmor": None,
        "actionlint": None,
    },
    "unpinned-image": {
        "zghalint": ["SC001"],
        "zizmor": ["unpinned-images"],
        "actionlint": None,
    },
    "compromised-action": {
        "zghalint": ["SC002"],
        "zizmor": None,
        "actionlint": None,
    },
    #: A SHA pin whose trailing `# vX.Y.Z` comment names a different release.
    #: No tool audits this today; the case documents the shared blind spot.
    "sha-comment-mismatch": {
        "zghalint": None,
        "zizmor": None,
        "actionlint": None,
    },
    "known-vulnerable": {
        "zghalint": ["SC003"],
        "zizmor": ["known-vulnerable-actions"],
        "actionlint": None,
    },
    "impostor-commit": {
        "zghalint": ["SC008"],
        "zizmor": ["impostor-commit"],
        "actionlint": None,
    },
    "obfuscated-uses": {
        "zghalint": ["DEP003"],
        "zizmor": ["obfuscation"],
        "actionlint": None,
    },
    "dependabot-cooldown": {
        "zghalint": ["DEP001"],
        "zizmor": ["dependabot-cooldown"],
        "actionlint": None,
    },
    "dependabot-execution": {
        "zghalint": ["DEP002"],
        "zizmor": ["dependabot-execution"],
        "actionlint": None,
    },
    "secrets-inherit": {
        "zghalint": ["SEC010"],
        "zizmor": ["secrets-inherit"],
        "actionlint": None,
    },
    "overprovisioned-secrets": {
        "zghalint": ["SEC011", "SEC012"],
        "zizmor": ["overprovisioned-secrets"],
        "actionlint": None,
    },
    "hardcoded-container-credentials": {
        "zghalint": ["SEC013"],
        "zizmor": None,
        "actionlint": None,
    },
    "insecure-commands": {
        "zghalint": ["SEC017"],
        "zizmor": ["insecure-commands"],
        "actionlint": None,
    },
    "github-env-injection": {
        "zghalint": ["SEC008"],
        "zizmor": ["github-env"],
        "actionlint": None,
    },
    "secrets-outside-env": {
        "zghalint": ["SEC019"],
        "zizmor": None,
        "actionlint": None,
    },
    "untrusted-input-condition": {
        "zghalint": ["SEC006"],
        "zizmor": None,
        "actionlint": None,
    },
    "branch-gate": {
        "zghalint": ["SEC022"],
        "zizmor": None,
        "actionlint": None,
    },
    "expression-syntax": {
        "zghalint": ["EXPR001", "EXPR002", "EXPR003"],
        "zizmor": None,
        "actionlint": ["expression!~potentially untrusted"],
    },
    "unknown-runner-label": {
        "zghalint": ["RUNNER002"],
        "zizmor": None,
        "actionlint": ["runner-label"],
    },
    # ---- E: expressions and types -------------------------------------
    #: actionlint folds every static expression error into `expression`, so
    #: the narrow zghalint IDs below all map onto that one kind.
    "undefined-step-reference": {
        "zghalint": ["EXPR010"],
        "zizmor": None,
        "actionlint": ["expression"],
    },
    "undeclared-matrix-key": {
        "zghalint": ["EXPR011"],
        "zizmor": None,
        "actionlint": ["expression"],
    },
    "needs-context": {
        "zghalint": ["EXPR012"],
        "zizmor": None,
        "actionlint": ["expression"],
    },
    "unsound-condition": {
        "zghalint": ["EXPR007"],
        "zizmor": None,
        "actionlint": ["if-cond", "syntax-check"],
    },
    "incomparable-types": {
        "zghalint": ["EXPR017"],
        "zizmor": None,
        "actionlint": ["expression"],
    },
    "argument-type": {
        "zghalint": ["EXPR018"],
        "zizmor": None,
        "actionlint": ["expression"],
    },
    "function-availability": {
        "zghalint": ["EXPR016"],
        "zizmor": None,
        "actionlint": ["expression"],
    },
    "context-availability": {
        "zghalint": ["EXPR015"],
        "zizmor": None,
        "actionlint": ["expression"],
    },
    "fromjson-literal": {
        "zghalint": ["EXPR009"],
        "zizmor": None,
        "actionlint": ["expression"],
    },
    "format-placeholders": {
        "zghalint": ["EXPR008"],
        "zizmor": None,
        "actionlint": ["expression"],
    },
    #: `env.<name>` that no `env:` block defines. Neither tool audits it; the
    #: case records the shared blind spot.
    "undefined-env": {
        "zghalint": None,
        "zizmor": None,
        "actionlint": None,
    },
    # ---- F: syntax and schema ------------------------------------------
    "unknown-key": {
        "zghalint": ["SYN001"],
        "zizmor": None,
        "actionlint": ["syntax-check"],
    },
    "duplicate-key": {
        "zghalint": ["SYN002"],
        "zizmor": None,
        "actionlint": ["syntax-check"],
    },
    "mapping-value-type": {
        "zghalint": ["SYN004"],
        "zizmor": None,
        "actionlint": ["syntax-check"],
    },
    "invalid-id-naming": {
        "zghalint": ["SYN006"],
        "zizmor": None,
        "actionlint": ["id"],
    },
    "invalid-env-var-name": {
        "zghalint": ["SYN007"],
        "zizmor": None,
        "actionlint": ["env-var"],
    },
    "unknown-event": {
        "zghalint": ["SYN009"],
        "zizmor": None,
        "actionlint": ["events"],
    },
    "invalid-activity-type": {
        "zghalint": ["SYN010"],
        "zizmor": None,
        "actionlint": ["events"],
    },
    "exclusive-event-filters": {
        "zghalint": ["SYN012"],
        "zizmor": None,
        "actionlint": ["events"],
    },
    "invalid-filter-glob": {
        "zghalint": ["SYN013"],
        "zizmor": None,
        "actionlint": ["glob"],
    },
    "invalid-cron": {
        "zghalint": ["SYN014"],
        "zizmor": None,
        "actionlint": ["events"],
    },
    "cron-too-frequent": {
        "zghalint": ["SYN015"],
        "zizmor": None,
        "actionlint": ["events"],
    },
    #: actionlint has no `timezone` key in its schedule schema at all, so it
    #: rejects the mapping outright instead of validating the zone name.
    "invalid-timezone": {
        "zghalint": ["SYN016"],
        "zizmor": None,
        "actionlint": None,
    },
    "workflow-dispatch-inputs": {
        "zghalint": ["SYN017"],
        "zizmor": None,
        "actionlint": ["events"],
    },
    "matrix-include-exclude": {
        "zghalint": ["SYN019"],
        "zizmor": None,
        "actionlint": ["matrix"],
    },
    #: `needs:` naming a job the workflow does not define, and a cycle in the
    #: job graph. actionlint reports both; zghalint has no rule for either.
    "needs-unknown-job": {
        "zghalint": None,
        "zizmor": None,
        "actionlint": ["job-needs~does not exist"],
    },
    "needs-cycle": {
        "zghalint": None,
        "zizmor": None,
        "actionlint": ["job-needs~cyclic"],
    },
    "runner-label-conflict": {
        "zghalint": ["RUNNER003"],
        "zizmor": None,
        "actionlint": ["runner-label"],
    },
    "deprecated-runner": {
        "zghalint": ["RUNNER001"],
        "zizmor": None,
        "actionlint": ["runner-label"],
    },
    "unknown-shell": {
        "zghalint": ["BP004"],
        "zizmor": None,
        "actionlint": ["shell-name"],
    },
    # ---- G: reusable workflows and composite actions --------------------
    "workflow-call-required-inputs": {
        "zghalint": ["RW002"],
        "zizmor": None,
        "actionlint": ["workflow-call"],
    },
    "workflow-call-input-values": {
        "zghalint": ["RW003"],
        "zizmor": None,
        "actionlint": ["workflow-call"],
    },
    "workflow-call-secrets": {
        "zghalint": ["RW004"],
        "zizmor": None,
        "actionlint": ["workflow-call"],
    },
    "workflow-call-outputs": {
        "zghalint": ["RW005"],
        "zizmor": None,
        "actionlint": ["workflow-call"],
    },
    "local-action-inputs": {
        "zghalint": ["DEP004"],
        "zizmor": None,
        "actionlint": ["action"],
    },
    "retired-action-runtime": {
        "zghalint": ["ACT002", "BP003"],
        "zizmor": None,
        "actionlint": ["action"],
    },
    "unknown-action-runtime": {
        "zghalint": ["ACT002"],
        "zizmor": None,
        "actionlint": ["action"],
    },
    # ---- H: best practices and performance ------------------------------
    "deprecated-workflow-command": {
        "zghalint": ["BP008"],
        "zizmor": None,
        "actionlint": ["deprecated-commands"],
    },
    "deprecated-action-version": {
        "zghalint": ["BP003"],
        "zizmor": None,
        "actionlint": ["action"],
    },
    "redundant-checkout": {
        "zghalint": ["PERF002"],
        "zizmor": None,
        "actionlint": None,
    },
    "fail-fast-disabled": {
        "zghalint": ["PERF003"],
        "zizmor": None,
        "actionlint": None,
    },
    "push-without-concurrency": {
        "zghalint": ["BP005"],
        "zizmor": None,
        "actionlint": None,
    },
    #: No zghalint rule flags a workflow file with no content at all; the
    #: case records the gap against actionlint's `workflow is empty`.
    "empty-workflow": {
        "zghalint": None,
        "zizmor": None,
        "actionlint": ["syntax-check~empty"],
    },
    #: PERM001 is broader than zizmor's `excessive-permissions`: it warns on
    #: any write scope, including the one the job demonstrably needs.
    "broad-write-permission": {
        "zghalint": ["PERM001"],
        "zizmor": ["excessive-permissions"],
        "actionlint": None,
    },
    "cache-poisoning": {
        "zghalint": ["SEC016"],
        "zizmor": ["cache-poisoning"],
        "actionlint": None,
    },
}


@dataclass(frozen=True)
class IdSpec:
    """One tool-side ID, optionally narrowed by a message substring.

    `ID~text` keeps only findings whose message contains *text*; `ID!~text`
    keeps only the ones that do not. Both exist for actionlint, whose `kind`
    field is coarse enough that a single `expression` covers untrusted
    interpolation and a malformed `${{ }}` alike.
    """

    ident: str
    substring: str | None = None
    negated: bool = False

    @classmethod
    def parse(cls, token: str) -> IdSpec:
        for separator, negated in (("!~", True), ("~", False)):
            ident, sep, substring = token.partition(separator)
            if sep:
                return cls(ident.strip(), substring.strip().lower(), negated)
        return cls(token.strip())

    def matches(self, finding: Finding) -> bool:
        if finding.ident != self.ident:
            return False
        if self.substring is None:
            return True
        return (self.substring in finding.message.lower()) != self.negated

    def __str__(self) -> str:
        if self.substring is None:
            return self.ident
        return f"{self.ident}{'!~' if self.negated else '~'}{self.substring}"


# ============================================================
# Case parsing
# ============================================================


class CaseError(Exception):
    """A case header that cannot be scored as written."""


@dataclass
class Expectation:
    kind: str
    line: int | None
    #: tool → IDs, or None for "not expected from this tool".
    mapping: dict[str, list[IdSpec] | None]


@dataclass
class Case:
    path: Path
    name: str
    expects: list[Expectation] = field(default_factory=list)
    forbids: list[Expectation] = field(default_factory=list)
    #: (tool, kind or None for the whole case) → reason.
    skips: dict[tuple[str, str | None], str] = field(default_factory=dict)
    persona: str = "regular"
    #: Set for a multi-file case: the directory staged as a miniature repo
    #: root, with `path` the entry file inside it. `None` for a lone file.
    tree: Path | None = None

    def is_action(self) -> bool:
        name = self.path.name
        return name.endswith((".action.yml", ".action.yaml")) or self.path.stem == "action"

    def is_dependabot(self) -> bool:
        name = self.path.name
        if name.endswith((".dependabot.yml", ".dependabot.yaml")):
            return True
        return self.path.stem == "dependabot"

    def staged_name(self) -> str:
        """The filename the case must carry for the tools to recognise it."""
        if self.is_action():
            return "action.yml"
        if self.is_dependabot():
            return "dependabot.yml"
        return self.path.name

    def skip_reason(self, tool: str, kind: str | None = None) -> str | None:
        reason = self.skips.get((tool, None))
        if reason is not None or kind is None:
            return reason
        return self.skips.get((tool, kind))


DIRECTIVE_RE = re.compile(r"^#\s*bench:(expect|forbid|skip|persona)\s+(.*)$")
TARGET_RE = re.compile(r"^(?P<kind>[A-Za-z0-9][A-Za-z0-9._-]*)(?:@(?P<line>\d+))?$")


def parse_case(path: Path, root: Path) -> Case:
    """Read the leading `# bench:` header of *path*.

    Parsing stops at the first line that is not a comment or blank, so the
    header cannot pick up directives from a case body that quotes them.
    `utf-8-sig` because a robustness case may carry a BOM, which would
    otherwise hide the first directive behind an invisible character.
    """
    case = Case(path=path, name=path.relative_to(root).as_posix())
    text = path.read_text(encoding="utf-8-sig")
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        if not stripped.startswith("#"):
            break
        match = DIRECTIVE_RE.match(stripped)
        if match is None:
            continue
        directive, rest = match.group(1), match.group(2).strip()
        try:
            _apply_directive(case, directive, rest)
        except CaseError as exc:
            raise CaseError(f"{case.name}:{lineno}: {exc}") from None
    if not (case.expects or case.forbids):
        raise CaseError(f"{case.name}: no `bench:expect` or `bench:forbid` directive")
    return case


def _apply_directive(case: Case, directive: str, rest: str) -> None:
    if directive == "persona":
        persona = rest.split()[0] if rest.split() else ""
        if persona not in PERSONAS:
            raise CaseError(f"unknown persona {persona!r} (expected one of {', '.join(PERSONAS)})")
        case.persona = persona
        return

    if directive == "skip":
        fields = rest.split(None, 1)
        if len(fields) < 2:
            raise CaseError("`bench:skip` needs a target and a reason")
        target, reason = fields[0], fields[1].strip()
        tool, _, kind = target.partition(":")
        if tool != "all" and tool not in TOOLS:
            raise CaseError(f"unknown skip target {tool!r}")
        tools = TOOLS if tool == "all" else (tool,)
        for name in tools:
            case.skips[(name, kind or None)] = reason
        return

    expectation = _parse_expectation(rest)
    (case.expects if directive == "expect" else case.forbids).append(expectation)


def _parse_expectation(rest: str) -> Expectation:
    tokens = rest.split()
    if not tokens:
        raise CaseError("missing finding kind")
    target = TARGET_RE.match(tokens[0])
    if target is None:
        raise CaseError(f"malformed kind {tokens[0]!r} (expected `kind` or `kind@<line>`)")
    kind = target.group("kind")
    line = int(target.group("line")) if target.group("line") else None

    mapping: dict[str, list[IdSpec] | None] = dict(_default_mapping(kind))
    for token in tokens[1:]:
        tool, sep, ids = token.partition("=")
        if not sep:
            raise CaseError(f"malformed mapping {token!r} (expected `tool=ID` or `tool=-`)")
        if tool not in TOOLS:
            raise CaseError(f"unknown tool {tool!r} in {token!r}")
        mapping[tool] = None if ids == "-" else [IdSpec.parse(i) for i in ids.split(",") if i]

    missing = [t for t in TOOLS if t not in mapping]
    if missing:
        raise CaseError(
            f"{kind!r} has no mapping for {', '.join(missing)}; write `{missing[0]}=<ID>` "
            f"(or `{missing[0]}=-`) on the directive, or add {kind!r} to DEFAULT_KIND_MAP"
        )
    return Expectation(kind=kind, line=line, mapping=mapping)


def _default_mapping(kind: str) -> dict[str, list[IdSpec] | None]:
    defaults = DEFAULT_KIND_MAP.get(kind, {})
    return {
        tool: None if ids is None else [IdSpec.parse(i) for i in ids]
        for tool, ids in defaults.items()
    }


def discover_cases(root: Path, patterns: list[str]) -> list[Case]:
    """Collect cases under *root*.

    `<category>/<name>.yml` is a case on its own. `<category>/<name>/` is a
    multi-file case: one file in it carries the `bench:` header and is the
    entry the tools are pointed at, the rest are the companions it references
    (a called workflow, a local action) and are not scored on their own.
    """
    cases = []
    for category in sorted(p for p in root.iterdir() if p.is_dir()):
        for path in sorted(category.iterdir()):
            if path.is_dir():
                cases.append(parse_tree_case(path, root))
            elif path.suffix in (".yml", ".yaml"):
                cases.append(parse_case(path, root))
    if patterns:
        cases = [c for c in cases if any(fnmatch.fnmatch(c.name, p) for p in patterns)]
    return cases


def parse_tree_case(tree: Path, root: Path) -> Case:
    entries = [
        path
        for path in sorted(set(tree.rglob("*.yml")) | set(tree.rglob("*.yaml")))
        if _has_header(path)
    ]
    if len(entries) != 1:
        found = ", ".join(p.relative_to(tree).as_posix() for p in entries) or "none"
        raise CaseError(
            f"{tree.relative_to(root).as_posix()}: a multi-file case needs exactly one file "
            f"with a `bench:` header (the entry the tools are run on); found: {found}"
        )
    case = parse_case(entries[0], root)
    case.tree = tree
    case.name = tree.relative_to(root).as_posix()
    return case


def _has_header(path: Path) -> bool:
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        if not stripped.startswith("#"):
            return False
        if DIRECTIVE_RE.match(stripped):
            return True
    return False


# ============================================================
# Tool execution
# ============================================================


@dataclass(frozen=True)
class Finding:
    ident: str
    line: int
    message: str


@dataclass
class ToolRun:
    findings: list[Finding] = field(default_factory=list)
    returncode: int = 0
    #: Set when the tool crashed, timed out, or emitted unparseable output.
    error: str | None = None


def _run(argv: list[str], cwd: Path) -> tuple[subprocess.CompletedProcess[str] | None, str | None]:
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=TIMEOUT_SEC, cwd=str(cwd)
        )
    except subprocess.TimeoutExpired:
        return None, f"timed out after {TIMEOUT_SEC}s"
    except OSError as exc:
        return None, f"could not run {argv[0]}: {exc}"
    return proc, None


def run_zghalint(binary: Path, staged: Staged) -> ToolRun:
    proc, error = _run(
        [str(binary), "--format", "json", "--color", "never", "--offline", staged.rel],
        cwd=staged.root,
    )
    if proc is None:
        return ToolRun(error=error)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return ToolRun(returncode=proc.returncode, error=_stderr_summary(proc))
    if proc.returncode == 2:
        # Exit 2 is "the file could not be linted at all": the JSON is valid
        # but empty, so without this a refused file would score as clean.
        return ToolRun(returncode=proc.returncode, error=_stderr_summary(proc))
    findings = [
        Finding(ident=d["rule_id"], line=int(d["line"]), message=d.get("message", ""))
        for d in payload.get("diagnostics", [])
    ]
    return ToolRun(findings=findings, returncode=proc.returncode)


def run_actionlint(staged: Staged) -> ToolRun:
    proc, error = _run(
        ["actionlint", "-no-color", "-format", "{{json .}}", staged.rel], cwd=staged.root
    )
    if proc is None:
        return ToolRun(error=error)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return ToolRun(returncode=proc.returncode, error=_stderr_summary(proc))
    findings = [
        Finding(ident=d.get("kind", "?"), line=int(d.get("line", 0)), message=d.get("message", ""))
        for d in payload
    ]
    return ToolRun(findings=findings, returncode=proc.returncode)


def run_zizmor(staged: Staged, persona: str) -> ToolRun:
    proc, error = _run(
        [
            "zizmor",
            "--format",
            "json",
            "--offline",
            "--no-progress",
            "--persona",
            persona,
            staged.rel,
        ],
        cwd=staged.root,
    )
    if proc is None:
        return ToolRun(error=error)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return ToolRun(returncode=proc.returncode, error=_stderr_summary(proc))
    findings = []
    for item in payload:
        message = str(item.get("desc", ""))
        for line in _zizmor_lines(item):
            findings.append(Finding(ident=item.get("ident", "?"), line=line, message=message))
    return ToolRun(findings=findings, returncode=proc.returncode)


def _zizmor_lines(item: dict) -> list[int]:
    """Primary location rows, 1-based (zizmor reports `row` 0-based)."""
    locations = item.get("locations", [])
    primary = [loc for loc in locations if loc.get("symbolic", {}).get("kind") == "Primary"]
    rows = []
    for loc in primary or locations:
        point = loc.get("concrete", {}).get("location", {}).get("start_point", {})
        if "row" in point:
            rows.append(int(point["row"]) + 1)
    return rows or [0]


def _stderr_summary(proc: subprocess.CompletedProcess[str]) -> str:
    text = (proc.stderr or proc.stdout or "").strip().splitlines()
    head = text[-1] if text else "no output"
    return f"exit {proc.returncode}: {head[:160]}"


def run_case(case: Case, staged: Staged, zghalint: Path, available: dict[str, bool]) -> dict:
    runs: dict[str, ToolRun] = {}
    for tool in TOOLS:
        if not available[tool] or case.skip_reason(tool) is not None:
            continue
        # actionlint only reads workflow files; a composite action is out of
        # its scope by design, not a miss.
        if tool == "actionlint" and case.is_action():
            case.skips[(tool, None)] = "actionlint は composite action を読まない"
            continue
        # actionlint はワークフローしか読まない。zizmor は dependabot 設定も監査する。
        if tool == "actionlint" and case.is_dependabot():
            case.skips[(tool, None)] = "actionlint は dependabot.yml を読まない"
            continue
        if tool == "zghalint":
            runs[tool] = run_zghalint(zghalint, staged)
        elif tool == "actionlint":
            runs[tool] = run_actionlint(staged)
        else:
            runs[tool] = run_zizmor(staged, case.persona)
    return runs


@dataclass(frozen=True)
class Staged:
    """Where a case was materialised: the directory to run the tools from,
    and the entry file's path relative to it."""

    root: Path
    rel: str


def stage(case: Case, tmp: Path) -> Staged:
    """Copy the case under the filename and layout its tools expect.

    Both zizmor and zghalint key off the filename: a composite action is only
    recognised as `action.yml`, and a Dependabot config only as
    `dependabot.yml`. A `<name>.action.yml` / `<name>.dependabot.yml` case is
    therefore materialised under that name in its own directory (line numbers
    are unchanged).

    A multi-file case is copied whole, so `uses: ./.github/workflows/x.yml`
    and `uses: ./tool` resolve against the staged tree the way they would in a
    real repository. An empty `.git` marker is added because actionlint locates
    the project root by it, and skips every local `uses:` check without one.
    """
    target_dir = tmp / case.name.replace("/", "__")
    if case.tree is not None:
        shutil.copytree(case.tree, target_dir)
        (target_dir / ".git").mkdir(exist_ok=True)
        return Staged(root=target_dir, rel=case.path.relative_to(case.tree).as_posix())
    target_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(case.path, target_dir / case.staged_name())
    return Staged(root=target_dir, rel=case.staged_name())


# ============================================================
# Scoring
# ============================================================


@dataclass
class Score:
    expected: int = 0
    detected: int = 0
    line_expected: int = 0
    line_matched: int = 0
    forbidden: int = 0
    violations: int = 0

    def add(self, other: Score) -> None:
        self.expected += other.expected
        self.detected += other.detected
        self.line_expected += other.line_expected
        self.line_matched += other.line_matched
        self.forbidden += other.forbidden
        self.violations += other.violations

    @property
    def recall(self) -> float | None:
        return self.detected / self.expected if self.expected else None

    @property
    def precision(self) -> float | None:
        total = self.detected + self.violations
        return self.detected / total if total else None

    @property
    def line_accuracy(self) -> float | None:
        return self.line_matched / self.line_expected if self.line_expected else None


@dataclass
class CaseResult:
    case: Case
    runs: dict[str, ToolRun]
    scores: dict[str, Score] = field(default_factory=dict)
    #: (tool, kind) pairs the tool was expected to report and did not.
    misses: list[tuple[str, str, int | None]] = field(default_factory=list)
    #: (tool, kind, line) the tool reported despite a `forbid`.
    false_positives: list[tuple[str, str, int]] = field(default_factory=list)
    #: Kinds zghalint alone reported.
    unique_wins: list[str] = field(default_factory=list)


def _match(run: ToolRun, specs: list[IdSpec]) -> list[Finding]:
    return [f for f in run.findings if any(spec.matches(f) for spec in specs)]


def score_case(case: Case, runs: dict[str, ToolRun]) -> CaseResult:
    result = CaseResult(case=case, runs=runs)
    for tool in TOOLS:
        result.scores[tool] = Score()

    for expectation in case.expects:
        detected_by: list[str] = []
        for tool, specs in expectation.mapping.items():
            run = runs.get(tool)
            if run is None or run.error is not None or specs is None:
                # `-` mappings are the unique-win baseline, not a miss.
                continue
            if case.skip_reason(tool, expectation.kind) is not None:
                continue
            score = result.scores[tool]
            score.expected += 1
            hits = _match(run, specs)
            if hits:
                score.detected += 1
                detected_by.append(tool)
            else:
                result.misses.append((tool, expectation.kind, expectation.line))
            if expectation.line is not None:
                score.line_expected += 1
                if any(h.line == expectation.line for h in hits):
                    score.line_matched += 1
        if detected_by == ["zghalint"]:
            result.unique_wins.append(expectation.kind)

    for forbidden in case.forbids:
        for tool, specs in forbidden.mapping.items():
            run = runs.get(tool)
            if run is None or run.error is not None or specs is None:
                continue
            if case.skip_reason(tool, forbidden.kind) is not None:
                continue
            score = result.scores[tool]
            score.forbidden += 1
            for hit in _match(run, specs):
                score.violations += 1
                result.false_positives.append((tool, forbidden.kind, hit.line))

    return result


# ============================================================
# Reporting
# ============================================================


def _pct(value: float | None) -> str:
    return "–" if value is None else f"{value * 100:.0f}%"


def _cell(case: Case, tool: str, result: CaseResult) -> str:
    run = result.runs.get(tool)
    if run is None:
        reason = case.skip_reason(tool)
        return f"skip ({reason})" if reason else "n/a"
    if run.error is not None:
        return f"**error**: {run.error}"
    score = result.scores[tool]
    parts = [f"{score.detected}/{score.expected}"]
    if score.line_expected:
        parts.append(f"line {score.line_matched}/{score.line_expected}")
    if score.violations:
        parts.append(f"FP {score.violations}")
    return " · ".join(parts)


def render_markdown(
    results: list[CaseResult], available: dict[str, bool], persona_note: str
) -> str:
    out: list[str] = ["# bench 行列", ""]
    out.append(f"ケース {len(results)} 件 / {persona_note}")
    out.append("")

    unavailable = [t for t in TOOLS if not available[t]]
    if unavailable:
        out.append(f"> 未インストールのため採点対象外: {', '.join(unavailable)}")
        out.append("")

    out.append("## ケース別")
    out.append("")
    out.append("| case | expect | " + " | ".join(TOOLS) + " |")
    out.append("|---|---|" + "---|" * len(TOOLS))
    for result in results:
        cells = [_cell(result.case, tool, result) for tool in TOOLS]
        out.append(
            f"| `{result.case.name}` | {len(result.case.expects)} | " + " | ".join(cells) + " |"
        )
    out.append("")

    totals = {tool: Score() for tool in TOOLS}
    unique_wins = 0
    for result in results:
        for tool in TOOLS:
            if tool in result.runs and result.runs[tool].error is None:
                totals[tool].add(result.scores[tool])
        unique_wins += len(result.unique_wins)

    out.append("## 集計")
    out.append("")
    out.append("| tool | recall | precision | 位置一致 | unique-win |")
    out.append("|---|---|---|---|---|")
    for tool in TOOLS:
        score = totals[tool]
        win = str(unique_wins) if tool == "zghalint" else "–"
        out.append(
            f"| {tool} | {_pct(score.recall)} ({score.detected}/{score.expected}) "
            f"| {_pct(score.precision)} | {_pct(score.line_accuracy)} "
            f"({score.line_matched}/{score.line_expected}) | {win} |"
        )
    out.append("")

    misses = [(r.case.name, *m) for r in results for m in r.misses]
    out.append("## FN (期待したが出なかった指摘)")
    out.append("")
    if misses:
        out.append("| case | tool | kind | 期待行 |")
        out.append("|---|---|---|---|")
        for name, tool, kind, line in misses:
            out.append(f"| `{name}` | {tool} | `{kind}` | {line if line else '–'} |")
    else:
        out.append("なし。")
    out.append("")

    fps = [(r.case.name, *f) for r in results for f in r.false_positives]
    out.append("## FP (`bench:forbid` に反した指摘)")
    out.append("")
    if fps:
        out.append("| case | tool | kind | 行 |")
        out.append("|---|---|---|---|")
        for name, tool, kind, line in fps:
            out.append(f"| `{name}` | {tool} | `{kind}` | {line} |")
    else:
        out.append("なし。")
    out.append("")

    skips = [
        (r.case.name, tool, kind, reason)
        for r in results
        for (tool, kind), reason in sorted(r.case.skips.items(), key=lambda kv: kv[0])
    ]
    out.append("## skip (スコア除外)")
    out.append("")
    if skips:
        out.append("| case | tool | kind | 理由 |")
        out.append("|---|---|---|---|")
        for name, tool, kind, reason in skips:
            out.append(f"| `{name}` | {tool} | {f'`{kind}`' if kind else '(全体)'} | {reason} |")
    else:
        out.append("なし。")
    out.append("")

    errors = [
        (r.case.name, tool, run.error)
        for r in results
        for tool, run in r.runs.items()
        if run.error is not None
    ]
    out.append("## 実行エラー")
    out.append("")
    if errors:
        out.append("| case | tool | 内容 |")
        out.append("|---|---|---|")
        for name, tool, error in errors:
            out.append(f"| `{name}` | {tool} | {error} |")
    else:
        out.append("なし。")
    out.append("")
    return "\n".join(out)


def as_json(results: list[CaseResult]) -> dict:
    return {
        "cases": [
            {
                "case": r.case.name,
                "persona": r.case.persona,
                "scores": {
                    tool: {
                        "expected": r.scores[tool].expected,
                        "detected": r.scores[tool].detected,
                        "line_expected": r.scores[tool].line_expected,
                        "line_matched": r.scores[tool].line_matched,
                        "forbidden": r.scores[tool].forbidden,
                        "violations": r.scores[tool].violations,
                    }
                    for tool in TOOLS
                    if tool in r.runs and r.runs[tool].error is None
                },
                "misses": [{"tool": t, "kind": k, "line": ln} for t, k, ln in r.misses],
                "false_positives": [
                    {"tool": t, "kind": k, "line": ln} for t, k, ln in r.false_positives
                ],
                "unique_wins": r.unique_wins,
                "errors": {t: run.error for t, run in r.runs.items() if run.error is not None},
                "skips": {
                    f"{tool}:{kind or ''}": reason for (tool, kind), reason in r.case.skips.items()
                },
            }
            for r in results
        ]
    }


def render_kind_table() -> str:
    """The `DEFAULT_KIND_MAP` as Markdown, so the docs never restate it."""
    out = ["| kind | zghalint | actionlint | zizmor |", "|---|---|---|---|"]

    def cell(ids: list[str] | None) -> str:
        return "–" if ids is None else ", ".join(f"`{i}`" for i in ids)

    for kind, mapping in DEFAULT_KIND_MAP.items():
        row = (cell(mapping[tool]) for tool in ("zghalint", "actionlint", "zizmor"))
        out.append(f"| `{kind}` | " + " | ".join(row) + " |")
    return "\n".join(out)


# ============================================================
# Entry point
# ============================================================


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cases-dir", type=Path, default=DEFAULT_CASES_DIR, help="bench case root")
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        metavar="GLOB",
        help="only cases whose path under --cases-dir matches (repeatable)",
    )
    parser.add_argument(
        "--zghalint", type=Path, default=DEFAULT_ZGHALINT, help="zghalint binary to score"
    )
    parser.add_argument("-o", "--out", type=Path, help="write the Markdown matrix here")
    parser.add_argument("--json", type=Path, help="also write the raw scores as JSON")
    parser.add_argument(
        "--fail-on-fp",
        action="store_true",
        help="exit non-zero when zghalint violates a `bench:forbid`",
    )
    parser.add_argument(
        "--kinds",
        action="store_true",
        help="print the neutral kind -> per-tool ID table and exit",
    )
    perf = parser.add_argument_group("performance (--perf)")
    perf.add_argument(
        "--perf",
        action="store_true",
        help="measure wall time and peak RSS instead of scoring findings",
    )
    perf.add_argument(
        "--corpus-dir",
        type=Path,
        default=bench_perf.DEFAULT_CORPUS_DIR,
        help="real-world workflows from scripts/fetch-corpus.py",
    )
    perf.add_argument("--runs", type=int, default=10, help="measured runs per command")
    perf.add_argument("--warmup", type=int, default=3, help="unmeasured runs before them")
    args = parser.parse_args(argv)

    if args.kinds:
        print(render_kind_table())
        return 0

    if args.perf:
        return main_perf(args)

    if not args.cases_dir.is_dir():
        print(f"no such case directory: {args.cases_dir}", file=sys.stderr)
        return 2

    try:
        cases = discover_cases(args.cases_dir, args.case)
    except CaseError as exc:
        print(f"bench case error: {exc}", file=sys.stderr)
        return 2
    if not cases:
        print("no cases matched", file=sys.stderr)
        return 2

    available = {
        "zghalint": args.zghalint.is_file(),
        "actionlint": shutil.which("actionlint") is not None,
        "zizmor": shutil.which("zizmor") is not None,
    }
    if not available["zghalint"]:
        print(
            f"zghalint binary not found at {args.zghalint}; run `zig build` first", file=sys.stderr
        )

    results = []
    with tempfile.TemporaryDirectory(prefix="zghalint-bench-") as tmp:
        for case in cases:
            staged = stage(case, Path(tmp))
            runs = run_case(case, staged, args.zghalint, available)
            results.append(score_case(case, runs))

    personas = sorted({c.persona for c in cases})
    report = render_markdown(results, available, f"zizmor persona: {', '.join(personas)}")
    if args.out:
        args.out.write_text(report, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(report)
    if args.json:
        args.json.write_text(json.dumps(as_json(results), indent=2, ensure_ascii=False) + "\n")

    if args.fail_on_fp and any(
        tool == "zghalint" for r in results for tool, _, _ in r.false_positives
    ):
        return 1
    return 0


def main_perf(args: argparse.Namespace) -> int:
    if not args.zghalint.is_file():
        print(
            f"zghalint binary not found at {args.zghalint}; "
            "run `zig build -Doptimize=ReleaseFast` first",
            file=sys.stderr,
        )
        return 2
    if not args.cases_dir.is_dir():
        print(f"no such case directory: {args.cases_dir}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="zghalint-perf-") as tmp:
        report = bench_perf.run_perf(
            args.zghalint, args.cases_dir, args.corpus_dir, args.runs, args.warmup, Path(tmp)
        )
    text = bench_perf.render_markdown(report)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)
    if args.json:
        args.json.write_text(
            json.dumps(bench_perf.as_json(report), indent=2, ensure_ascii=False) + "\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
