#!/usr/bin/env python3
"""Generate `src/rules/data/advisories.zig` from GitHub Security Advisories.

SC003 fetches this set at runtime. The generated file is the offline /
cache-miss snapshot so `--offline` still has the last release's table.
Regenerate before a release: `python3 scripts/gen-advisories.py`.
See docs/maintenance.md.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = REPO_ROOT / "src" / "rules" / "data" / "advisories.zig"
API = "https://api.github.com/advisories?type=reviewed&ecosystem=actions&per_page=100"


def sanitize(field: str) -> str:
    return field.replace("\t", " ").replace("\n", " ").replace("\r", " ")


def patched_version(vuln: dict) -> str:
    raw = vuln.get("first_patched_version")
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        ident = raw.get("identifier")
        return ident if isinstance(ident, str) else ""
    return ""


def rows_from_advisories(items: list[dict]) -> list[tuple[str, str, str, str, str, str]]:
    rows = []
    for item in items:
        ghsa_id = item.get("ghsa_id")
        if not isinstance(ghsa_id, str) or not ghsa_id:
            continue
        summary = item.get("summary") if isinstance(item.get("summary"), str) else ""
        for vuln in item.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            pkg = vuln.get("package") or {}
            if not isinstance(pkg, dict):
                continue
            if pkg.get("ecosystem") != "actions":
                continue
            name = pkg.get("name")
            if not isinstance(name, str) or "/" not in name:
                continue
            range_s = vuln.get("vulnerable_version_range")
            range_s = range_s if isinstance(range_s, str) else ""
            patched = patched_version(vuln)
            message = f"action '{name}' has known vulnerability {ghsa_id}: {summary}"
            if patched:
                hint = (
                    f"update to version {patched} or later, "
                    f"see https://github.com/advisories/{ghsa_id}"
                )
            else:
                hint = f"check https://github.com/advisories/{ghsa_id} for remediation"
            rows.append(
                (
                    sanitize(ghsa_id),
                    sanitize(name),
                    sanitize(message),
                    sanitize(hint),
                    sanitize(range_s),
                    sanitize(patched),
                )
            )
    rows.sort(key=lambda r: (r[0], r[1]))
    return rows


def next_link(headers: str) -> str | None:
    # Link: <url>; rel="next", <url>; rel="last"
    for part in headers.split(","):
        if 'rel="next"' not in part:
            continue
        m = re.search(r"<([^>]+)>", part)
        if m:
            return m.group(1)
    return None


def fetch_all(token: str | None) -> list[dict]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "zghalint-gen-advisories",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    items: list[dict] = []
    url: str | None = API
    while url:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read().decode())
            if not isinstance(body, list):
                raise SystemExit(f"unexpected payload from {url}")
            items.extend(body)
            url = next_link(resp.headers.get("Link") or "")
    return items


def zig_escape(field: str) -> str:
    return field.replace("\\", "\\\\").replace('"', '\\"')


def render_zig(rows: list[tuple[str, str, str, str, str, str]], generated_at: str) -> str:
    # Zig line strings reject tab bytes; a quoted string can hold `\t` / `\n`.
    lines = ["\\t".join(zig_escape(field) for field in row) for row in rows]
    body = "\\n".join(lines)
    return f"""//! Snapshot of GitHub Security Advisories for the `actions` ecosystem.
//!
//! GENERATED FILE — do not edit by hand. Regenerate with
//! `python3 scripts/gen-advisories.py`; see docs/maintenance.md.
//! Last generated: {generated_at}

pub const generated_at = "{generated_at}";

/// TSV used as the last-resort table when the network and the on-disk cache
/// are both unavailable. Same columns as `advisory.serializeAdvisories`.
pub const tsv = "{body}\\n";
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input-json",
        type=Path,
        help="use a saved GitHub API payload instead of fetching",
    )
    args = parser.parse_args()

    if args.input_json:
        items = json.loads(args.input_json.read_text())
        if not isinstance(items, list):
            raise SystemExit("--input-json must be a JSON array")
    else:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        items = fetch_all(token)

    rows = rows_from_advisories(items)
    if not rows:
        raise SystemExit("no actions advisories parsed")
    generated_at = dt.date.today().isoformat()
    OUTPUT.write_text(render_zig(rows, generated_at))
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)} ({len(rows)} advisories)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
