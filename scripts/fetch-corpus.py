#!/usr/bin/env python3
"""Fetch real-world workflow files into `bench/corpus/` for the perf bench.

`scripts/bench.py --perf` needs a corpus of workflows that were written by
people rather than for the bench. The repositories in
`scripts/popular-actions.txt` are a ready-made sample (every one of them ships
its own CI), so each is cloned sparsely — the `.github/workflows/` directory
only — and its workflow files are copied under `bench/corpus/<owner>__<repo>/`.

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


def clone_workflows(repo: str, into: Path) -> tuple[str, Path]:
    """Shallow, blob-less sparse checkout of `.github/workflows/` at HEAD.

    Returns the checked-out commit and the workflows directory (which may not
    exist for a repository without workflows).
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
    subprocess.run(
        [*git, "sparse-checkout", "set", "--no-cone", "/.github/workflows/*"], check=True
    )
    subprocess.run([*git, "checkout", "--quiet"], check=True)
    commit = subprocess.run(
        [*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    return commit, dest / ".github" / "workflows"


def copy_workflows(workflows: Path, target: Path) -> list[str]:
    if not workflows.is_dir():
        return []
    target.mkdir(parents=True, exist_ok=True)
    names = []
    for path in sorted(workflows.iterdir()):
        if path.is_file() and path.suffix in (".yml", ".yaml"):
            shutil.copyfile(path, target / path.name)
            names.append(path.name)
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
                commit, workflows = clone_workflows(repo, workdir)
            except subprocess.CalledProcessError as exc:
                print(f"  skipped: git exited {exc.returncode}", file=sys.stderr)
                continue
            files = copy_workflows(workflows, args.out / repo.replace("/", "__"))
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
