#!/usr/bin/env python3
"""Fetch real-world workflow files into `bench/corpus/` for the perf bench.

`scripts/bench.py --perf` needs a corpus of workflows that were written by
people rather than for the bench. The repositories in
`scripts/popular-actions.txt` are a ready-made sample (every one of them ships
its own CI), so each is cloned sparsely and copied under
`bench/corpus/<owner>__<repo>/` **keeping the repository's own shape** —
`.github/workflows/` plus the action definitions a workflow can reference with
`uses: ./`. Flattening the workflows instead would make every local `uses:`
unresolvable, and the ancestor search for the repository root would escape into
this repository and match zghalint's own `action.yml`.

The corpus is not committed: the files keep their upstream licences, so
`bench/corpus/` is ignored by git and `manifest.json` records where and when
each file came from instead.

    python3 scripts/fetch-corpus.py                 # every repo in the manifest
    python3 scripts/fetch-corpus.py --repo o/r      # add repositories
    python3 scripts/fetch-corpus.py --limit 5       # a quick smoke run
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "scripts" / "popular-actions.txt"
DEFAULT_OUT = REPO_ROOT / "bench" / "corpus"

#: `owner/repo` at the head of a manifest entry; the `/path@ref` tail names a
#: sub-action or tag, and the corpus wants the repository's own workflows.
REPO_RE = re.compile(r"^(?P<owner>[^/@\s]+)/(?P<repo>[^/@\s]+)")


def repos_from_manifest(text: str) -> list[str]:
    """Unique `owner/repo` names in manifest order."""
    seen: dict[str, None] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = REPO_RE.match(line)
        if match is None:
            raise SystemExit(f"malformed manifest entry: {raw!r}")
        seen[f"{match['owner']}/{match['repo']}"] = None
    return list(seen)


#: Sparse-checkout patterns (gitignore syntax, `--no-cone`): the workflows to
#: lint, plus every action definition a workflow's `uses: ./...` can point at.
#: The action patterns carry no leading slash on purpose — they match at any
#: depth, because repositories keep sub-actions in directories of their own
#: (`merge/action.yml`, `.github/actions/setup/action.yml`).
SPARSE_PATTERNS = (
    "/.github/workflows/*",
    "action.yml",
    "action.yaml",
)


def clone_workflows(repo: str, into: Path) -> tuple[str, Path]:
    """Shallow, blob-less sparse checkout of `SPARSE_PATTERNS` at HEAD.

    Returns the checked-out commit and the checkout directory.
    """
    dest = into / repo.replace("/", "__")
    subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--filter=blob:none",
            "--sparse",
            "--no-checkout",
            f"https://github.com/{repo}",
            str(dest),
        ],
        check=True,
    )
    git = ["git", "-C", str(dest)]
    subprocess.run([*git, "sparse-checkout", "set", "--no-cone", *SPARSE_PATTERNS], check=True)
    subprocess.run([*git, "checkout", "--quiet"], check=True)
    commit = subprocess.run(
        [*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    return commit, dest


def copy_repo(checkout: Path, target: Path) -> list[str]:
    """Copy the sparse checkout to `target`, keeping its paths.

    Returns the workflow file names (relative to `.github/workflows/`).
    """
    workflows = checkout / ".github" / "workflows"
    if not workflows.is_dir():
        return []
    names = []
    target.mkdir(parents=True, exist_ok=True)
    (target / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    for path in sorted(workflows.iterdir()):
        if path.is_file() and path.suffix in (".yml", ".yaml"):
            shutil.copyfile(path, target / ".github" / "workflows" / path.name)
            names.append(path.name)
    # Action definitions keep their own paths: `uses: ./merge/` resolves
    # against the repository root, so only the original directory makes it
    # resolvable.
    for source in sorted(checkout.rglob("action.y*ml")):
        relative = source.relative_to(checkout)
        if ".git" in relative.parts or not source.is_file():
            continue
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    # zghalint and actionlint both find the repository root by walking up to a
    # `.git`; without one here the walk leaves the corpus and lands on this
    # repository, so every local `uses:` would resolve against zghalint's own
    # files.
    (target / ".git").mkdir(exist_ok=True)
    return names


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="corpus directory")
    parser.add_argument(
        "--repo",
        action="append",
        default=[],
        metavar="OWNER/REPO",
        help="fetch this repository in addition to the manifest (repeatable)",
    )
    parser.add_argument("--limit", type=int, help="only the first N manifest repositories")
    args = parser.parse_args(argv)

    repos = repos_from_manifest(MANIFEST.read_text(encoding="utf-8"))
    if args.limit is not None:
        repos = repos[: args.limit]
    for extra in args.repo:
        if extra not in repos:
            repos.append(extra)

    # Start from a clean directory: a repository dropped from the manifest
    # must not linger and skew the file count.
    if args.out.exists():
        shutil.rmtree(args.out)
    args.out.mkdir(parents=True)

    entries = []
    workdir = Path(tempfile.mkdtemp(prefix="zghalint-corpus-"))
    try:
        for repo in repos:
            print(f"fetching {repo}", file=sys.stderr)
            try:
                commit, checkout = clone_workflows(repo, workdir)
            except subprocess.CalledProcessError as exc:
                print(f"  skipped: git exited {exc.returncode}", file=sys.stderr)
                continue
            files = copy_repo(checkout, args.out / repo.replace("/", "__"))
            entries.append({"repo": repo, "commit": commit, "files": files})
            print(f"  {len(files)} workflow file(s) at {commit[:12]}", file=sys.stderr)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    manifest = {
        "fetched_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "source": MANIFEST.relative_to(REPO_ROOT).as_posix(),
        "repos": entries,
    }
    (args.out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    total = sum(len(e["files"]) for e in entries)
    print(f"wrote {args.out} ({len(entries)} repos, {total} files)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
