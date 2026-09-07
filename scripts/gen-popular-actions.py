#!/usr/bin/env python3
"""Generate `src/rules/data/popular_actions.zig` from real `action.yml` files.

The alternative to generating this table would be to copy another linter's
snapshot, which inherits that project's staleness. Here the input is the list
in `scripts/popular-actions.txt`, and the data is read from the actions
themselves, so a refresh is `python3 scripts/gen-popular-actions.py`.

Each manifest line is `owner/repo[/path]@ref`. The repository is cloned
shallowly at `ref`, `action.yml` (or `action.yaml`) is parsed, and the inputs
plus `runs.using` are emitted as Zig source.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "scripts" / "popular-actions.txt"
OUTPUT = REPO_ROOT / "src" / "rules" / "data" / "popular_actions.zig"

ENTRY_RE = re.compile(r"^(?P<owner>[^/@\s]+)/(?P<repo>[^/@\s]+)(?P<path>(?:/[^@\s]+)?)@(?P<ref>\S+)$")


@dataclass
class Input:
    name: str
    required: bool = False
    has_default: bool = False
    deprecation: str | None = None


@dataclass
class ActionMeta:
    owner: str
    repo: str
    path: str
    major: int
    using: str
    inputs: list[Input] = field(default_factory=list)


def parse_manifest(text: str) -> list[tuple[str, str, str, str]]:
    entries = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = ENTRY_RE.match(line)
        if m is None:
            raise SystemExit(f"malformed manifest entry: {raw!r}")
        entries.append(
            (m["owner"], m["repo"], m["path"].lstrip("/"), m["ref"]),
        )
    return entries


def major_of(ref: str) -> int:
    m = re.match(r"^v?(\d+)", ref)
    if m is None:
        raise SystemExit(f"cannot derive a major version from ref {ref!r}")
    return int(m.group(1))


def clone(owner: str, repo: str, ref: str, into: pathlib.Path) -> pathlib.Path:
    """Shallow-clone `owner/repo` at `ref`; reuse the checkout across paths.

    Every ref in the manifest is a moving major tag, so a cached checkout is
    refetched rather than reused as-is: otherwise `--cache-dir` would quietly
    regenerate the table from whatever the tag pointed at last time.
    """
    dest = into / f"{owner}__{repo}__{ref}"
    if dest.exists():
        subprocess.run(
            ["git", "-C", str(dest), "fetch", "--quiet", "--depth", "1", "origin", f"tags/{ref}"],
            check=True,
        )
        subprocess.run(["git", "-C", str(dest), "reset", "--quiet", "--hard", "FETCH_HEAD"], check=True)
        return dest
    subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--single-branch",
            "--branch",
            ref,
            f"https://github.com/{owner}/{repo}",
            str(dest),
        ],
        check=True,
    )
    return dest


def read_manifest_yaml(checkout: pathlib.Path, path: str) -> dict:
    directory = checkout / path if path else checkout
    for name in ("action.yml", "action.yaml"):
        candidate = directory / name
        if candidate.is_file():
            return yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
    raise SystemExit(f"no action manifest under {directory}")


def is_true(value: object) -> bool:
    """`required:` as the runner reads it. A quoted `"false"` is not true."""
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() == "true"


def collect(owner: str, repo: str, path: str, ref: str, checkout: pathlib.Path) -> ActionMeta:
    doc = read_manifest_yaml(checkout, path)
    runs = doc.get("runs") or {}
    using = str(runs.get("using", "")) if isinstance(runs, dict) else ""

    inputs = []
    declared = doc.get("inputs") or {}
    # An entry that silently ends up with no inputs would make DEP005 reject
    # every `with:` key the action actually accepts.
    if not isinstance(declared, dict):
        raise SystemExit(f"{owner}/{repo}@{ref}: `inputs:` is not a mapping")
    for name, spec in declared.items():
        spec = spec if isinstance(spec, dict) else {}
        inputs.append(
            Input(
                name=str(name),
                required=is_true(spec.get("required")),
                has_default="default" in spec,
                deprecation=spec.get("deprecationMessage"),
            )
        )

    return ActionMeta(
        owner=owner,
        repo=repo,
        path=path,
        major=major_of(ref),
        using=using,
        inputs=inputs,
    )


def zig_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{escaped}"'


def render(metas: list[ActionMeta]) -> str:
    out = [
        "//! Metadata of widely used actions: what `with:` keys they accept and",
        "//! which runtime they declare. DEP005, DEP006 and BP003 read this table.",
        "//!",
        "//! GENERATED FILE — do not edit by hand. Regenerate with",
        "//! `python3 scripts/gen-popular-actions.py` after changing",
        "//! `scripts/popular-actions.txt`; see docs/maintenance.md.",
        "",
        "pub const Input = struct {",
        "    name: []const u8,",
        "    /// `required: true` without a `default:`. An input with a default is",
        "    /// satisfied whether or not the caller passes it.",
        "    required: bool = false,",
        "    /// The action's own `deprecationMessage:`, reported verbatim by DEP006.",
        "    deprecation: ?[]const u8 = null,",
        "};",
        "",
        "pub const ActionMeta = struct {",
        "    owner: []const u8,",
        "    repo: []const u8,",
        "    /// Sub-directory for an action that does not sit at the repository",
        "    /// root, such as `actions/cache/restore`. Empty for the root action.",
        "    path: []const u8 = \"\",",
        "    /// The major version this entry describes; `uses: owner/repo@v4`",
        "    /// matches the entry with `major == 4`.",
        "    major: u16,",
        "    /// `runs.using` as declared by the action.",
        "    using: []const u8,",
        "    inputs: []const Input,",
        "};",
        "",
        "pub const popular_actions = [_]ActionMeta{",
    ]

    for meta in metas:
        out.append("    .{")
        out.append(f"        .owner = {zig_string(meta.owner)},")
        out.append(f"        .repo = {zig_string(meta.repo)},")
        if meta.path:
            out.append(f"        .path = {zig_string(meta.path)},")
        out.append(f"        .major = {meta.major},")
        out.append(f"        .using = {zig_string(meta.using)},")
        if not meta.inputs:
            out.append("        .inputs = &.{},")
        else:
            out.append("        .inputs = &.{")
            for inp in meta.inputs:
                fields = [f".name = {zig_string(inp.name)}"]
                if inp.required and not inp.has_default:
                    fields.append(".required = true")
                if inp.deprecation:
                    fields.append(f".deprecation = {zig_string(str(inp.deprecation))}")
                out.append("            .{ " + ", ".join(fields) + " },")
            out.append("        },")
        out.append("    },")

    out.append("};")
    out.append("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cache-dir",
        type=pathlib.Path,
        help="reuse checkouts across runs instead of cloning into a temp dir",
    )
    args = parser.parse_args()

    entries = parse_manifest(MANIFEST.read_text(encoding="utf-8"))

    workdir = args.cache_dir or pathlib.Path(tempfile.mkdtemp(prefix="popular-actions-"))
    workdir.mkdir(parents=True, exist_ok=True)

    metas = []
    try:
        for owner, repo, path, ref in entries:
            print(f"fetching {owner}/{repo}{'/' + path if path else ''}@{ref}", file=sys.stderr)
            checkout = clone(owner, repo, ref, workdir)
            metas.append(collect(owner, repo, path, ref, checkout))
    finally:
        if args.cache_dir is None:
            shutil.rmtree(workdir, ignore_errors=True)

    OUTPUT.write_text(render(metas), encoding="utf-8")
    subprocess.run(["zig", "fmt", str(OUTPUT)], check=True)
    print(f"wrote {OUTPUT} ({len(metas)} actions)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
