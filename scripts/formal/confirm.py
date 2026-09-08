#!/usr/bin/env python3
"""Run every witness of ``model.py`` through the real binary.

A witness is a (trigger, context, sink, flow) tuple the model calls unsafe
and uncovered. This script writes the smallest workflow that realises the
tuple, lints it with ``zig-out/bin/zghalint --quick --format json`` and
reports:

* ``CONFIRMED``   — none of the rules the specification expects fired.
* ``covered``     — one of them did fire after all (the model's picture of
                    the implementation is too coarse there; fix the model).

Every rule that did fire on the file is listed alongside, so a gap another
rule happens to catch is visible as such.

Usage:
    zig build
    python3 scripts/formal/confirm.py [--json] [--keep DIR]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

import model
import impl

BINARY = impl.PROJECT_ROOT / "zig-out" / "bin" / "zghalint"

#: Contexts that are numbers a `refs/pull/<n>/merge` spelling turns into a ref.
NUMBER_CONTEXTS = {
    "github.event.issue.number",
    "github.event.pull_request.number",
    "github.event.number",
}

#: Contexts that name a repository rather than a ref.
REPOSITORY_CONTEXTS = {
    "github.event.pull_request.head.repo.full_name",
    "github.event.workflow_run.head_repository.full_name",
}


def concrete(path: str) -> str:
    """Turn a spec path into a reference a workflow can contain: sequences get
    an index, open-ended roots get a member name."""
    if path.endswith(".*"):
        return path[:-2] + ".foo"
    return path.replace(".*.", "[0].")


def on_block(trigger: str) -> str:
    if trigger == "workflow_dispatch":
        return "on:\n  workflow_dispatch:\n    inputs:\n      foo:\n        type: string\n"
    if trigger == "workflow_call":
        return "on:\n  workflow_call:\n    inputs:\n      foo:\n        type: string\n"
    if trigger == "workflow_run":
        return "on:\n  workflow_run:\n    workflows: [ci]\n    types: [completed]\n"
    return f"on: {trigger}\n"


def checkout_input(path: str) -> str:
    expr = "${{ " + concrete(path) + " }}"
    if path in NUMBER_CONTEXTS:
        return f"ref: refs/pull/{expr}/merge"
    if path in REPOSITORY_CONTEXTS:
        return f"repository: {expr}"
    return f"ref: {expr}"


def workflow_for(w: model.Witness) -> str:
    expr = "${{ " + concrete(w.context) + " }}"
    head = on_block(w.trigger) + "jobs:\n"
    runs_on = "self-hosted" if w.property.startswith("P7") else "ubuntu-latest"

    if w.sink == "checkout_ref":
        return head + (
            "  j:\n"
            f"    runs-on: {runs_on}\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            f"          {checkout_input(w.context)}\n"
        )
    if w.sink == "condition":
        return head + (
            "  j:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            f"      - if: contains({concrete(w.context)}, 'deploy')\n"
            "        run: ./deploy.sh\n"
        )
    if w.sink == "github_env":
        return head + (
            "  j:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            f'      - run: echo "TITLE={expr}" >> "$GITHUB_ENV"\n'
        )
    # run: sink, one workflow per flow.
    if w.flow == "env_context":
        return head + (
            "  j:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - env:\n"
            f'          TITLE: "{expr}"\n'
            '        run: echo "${{ env.TITLE }}"\n'
        )
    # The capturing step binds the value through `env:` and expands `$TITLE`,
    # which is the safe spelling: only the later `${{ }}` re-injects it, so
    # a diagnostic can only come from following the flow.
    capture = (
        "      - id: s\n"
        "        env:\n"
        f'          TITLE: "{expr}"\n'
        '        run: echo "title=$TITLE" >> "$GITHUB_OUTPUT"\n'
    )
    if w.flow == "job_output":
        return head + (
            "  a:\n"
            "    runs-on: ubuntu-latest\n"
            "    outputs:\n"
            "      title: ${{ steps.s.outputs.title }}\n"
            "    steps:\n"
            + capture
            + "  b:\n"
            "    needs: a\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            '      - run: echo "${{ needs.a.outputs.title }}"\n'
        )
    if w.flow == "step_output":
        return head + (
            "  j:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            + capture
            + '      - run: echo "${{ steps.s.outputs.title }}"\n'
        )
    return head + (
        "  j:\n"
        f"    runs-on: {runs_on}\n"
        "    steps:\n"
        f'      - run: echo "{expr}"\n'
    )


@dataclass(frozen=True)
class Outcome:
    witness: model.Witness
    confirmed: bool
    #: SEC* rule IDs the binary reported on the file.
    security_rules: list[str]
    workflow: str


def lint(path: Path) -> list[str]:
    proc = subprocess.run(
        [str(BINARY), "--quick", "--format", "json", str(path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode not in (0, 1) or not proc.stdout:
        raise RuntimeError(f"zghalint failed on {path}: {proc.stderr}")
    return sorted({d["rule_id"] for d in json.loads(proc.stdout)["diagnostics"]})


def confirm(witnesses: list[model.Witness], keep: Path | None) -> list[Outcome]:
    outcomes: list[Outcome] = []
    with tempfile.TemporaryDirectory() as tmp:
        base = keep or Path(tmp)
        base.mkdir(parents=True, exist_ok=True)
        for i, w in enumerate(witnesses):
            text = workflow_for(w)
            path = base / f"{i:03}-{w.trigger}-{w.sink}-{w.flow}.yml"
            path.write_text(text)
            rules = lint(path)
            expected = set(w.expected_rule.split("/"))
            outcomes.append(
                Outcome(
                    witness=w,
                    confirmed=not (expected & set(rules)),
                    security_rules=[r for r in rules if r.startswith("SEC")],
                    workflow=text,
                )
            )
    return outcomes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--json", action="store_true", help="emit outcomes as JSON")
    parser.add_argument("--keep", type=Path, help="directory to keep the generated workflows in")
    args = parser.parse_args(argv)

    if not BINARY.exists():
        print(f"{BINARY} not found; run `zig build` first", file=sys.stderr)
        return 2

    witnesses = sorted(model.Model(impl.load()).check(), key=model._sort_key)
    outcomes = confirm(witnesses, args.keep)

    if args.json:
        json.dump([asdict(o) for o in outcomes], sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    current = None
    confirmed = 0
    for o in outcomes:
        w = o.witness
        if w.property != current:
            current = w.property
            print(f"\n== {w.property}  (expected {w.expected_rule})")
        status = "CONFIRMED" if o.confirmed else "covered  "
        confirmed += o.confirmed
        flow = "" if w.flow == "direct" else f" via {w.flow}"
        fired = ",".join(o.security_rules) or "-"
        print(f"  {status} {w.trigger:28} {w.context}{flow:18}  fired: {fired}")
    print(f"\n{confirmed}/{len(outcomes)} witnesses confirmed against {BINARY.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
