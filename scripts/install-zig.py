#!/usr/bin/env python3
"""Install a Zig toolchain from ziglang.org for CI.

`mlugg/setup-zig` still declares `runs.using: node20`, which GitHub removes
from hosted runners on 2026-09-23. Workflows call this script through
`.github/actions/setup-zig` instead. When `--version` / `INPUT_VERSION` is
empty, the version is `minimum_zig_version` in `build.zig.zon` — the same
source `mlugg/setup-zig` used when `version:` was omitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import ssl
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

DEFAULT_INDEX_URL = "https://ziglang.org/download/index.json"
USER_AGENT = "zghalint-ci"
FETCH_ATTEMPTS = 3


def die(message: str, code: int = 1) -> None:
    print(f"install-zig: {message}", file=sys.stderr)
    raise SystemExit(code)


def repo_root() -> Path:
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        return Path(workspace)
    return Path(__file__).resolve().parent.parent


def read_zon_version(zon: Path) -> str:
    match = re.search(
        r'\.minimum_zig_version\s*=\s*"([^"]+)"',
        zon.read_text(encoding="utf-8"),
    )
    if match:
        return match.group(1)
    die(f"could not read .minimum_zig_version from {zon}")
    raise AssertionError


def runner_triple() -> str:
    os_name = os.environ.get("RUNNER_OS") or platform.system()
    arch = os.environ.get("RUNNER_ARCH") or platform.machine()

    os_map = {
        "Linux": "linux",
        "macOS": "macos",
        "Darwin": "macos",
        "Windows": "windows",
    }
    arch_map = {
        "X64": "x86_64",
        "x64": "x86_64",
        "AMD64": "x86_64",
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "ARM64": "aarch64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }
    zig_os = os_map.get(os_name)
    zig_arch = arch_map.get(arch)
    if zig_os is None or zig_arch is None:
        die(f"unsupported runner {os_name}/{arch}")
    return f"{zig_arch}-{zig_os}"


def urlopen(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    kwargs: dict = {"timeout": 60}
    if not url.startswith("file:"):
        kwargs["context"] = ssl.create_default_context()
    last_error: Exception | None = None
    for _ in range(FETCH_ATTEMPTS):
        try:
            return urllib.request.urlopen(request, **kwargs)
        except urllib.error.URLError as err:
            last_error = err
    die(f"failed to fetch {url}: {last_error}")
    raise AssertionError


def fetch_bytes(url: str) -> bytes:
    with urlopen(url) as response:
        return response.read()


def index_url() -> str:
    return os.environ.get("ZIG_INDEX_URL", DEFAULT_INDEX_URL)


def load_json(url: str) -> dict:
    with urlopen(url) as response:
        return json.load(response)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_archive(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    if archive.suffix == ".zip" or archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
        return
    with tarfile.open(archive) as tf:
        kwargs = {}
        if sys.version_info >= (3, 12):
            kwargs["filter"] = "data"
        tf.extractall(dest, **kwargs)


def find_zig_dir(dest: Path) -> Path:
    for name in ("zig", "zig.exe"):
        matches = [p for p in dest.rglob(name) if p.is_file()]
        if matches:
            return matches[0].parent
    die(f"extracted archive under {dest} contains no zig binary")
    raise AssertionError


def write_github_path(bin_dir: Path) -> None:
    github_path = os.environ.get("GITHUB_PATH")
    if not github_path:
        return
    with open(github_path, "a", encoding="utf-8") as handle:
        handle.write(f"{bin_dir}\n")


def resolve_version(explicit: str | None) -> str:
    if explicit:
        return explicit
    env_version = os.environ.get("INPUT_VERSION", "").strip()
    if env_version:
        return env_version
    zon = repo_root() / "build.zig.zon"
    if not zon.is_file():
        die(f"{zon} is missing; pass --version")
    return read_zon_version(zon)


def install(version: str, prefix: Path) -> Path:
    triple = runner_triple()
    source = index_url()
    index = load_json(source)
    release = index.get(version)
    if not isinstance(release, dict):
        die(f"zig {version} is not in {source}")
    artifact = release.get(triple)
    if not isinstance(artifact, dict):
        die(f"no {triple} tarball for zig {version}")
    tarball_url = artifact.get("tarball")
    expected = artifact.get("shasum")
    if not tarball_url or not expected:
        die(f"{triple} entry for zig {version} is missing tarball/shasum")

    prefix.mkdir(parents=True, exist_ok=True)
    archive_name = tarball_url.rsplit("/", 1)[-1]
    archive = prefix / archive_name
    archive.write_bytes(fetch_bytes(tarball_url))
    actual = sha256_file(archive)
    if actual != expected:
        die(f"checksum mismatch for {archive_name}: expected {expected}, got {actual}")

    extract_dir = prefix / "pkg"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_archive(archive, extract_dir)
    bin_dir = find_zig_dir(extract_dir)
    zig = bin_dir / ("zig.exe" if os.name == "nt" else "zig")
    if not os.access(zig, os.X_OK):
        zig.chmod(zig.stat().st_mode | 0o111)
    write_github_path(bin_dir)
    print(f"installed zig {version} ({triple}) at {zig}")
    return zig


def default_prefix() -> Path:
    root = os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()
    return Path(root) / "zig"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=None, help="Zig version (default: build.zig.zon)")
    parser.add_argument("--prefix", default=None, help="Install directory")
    args = parser.parse_args()
    version = resolve_version(args.version)
    prefix = Path(args.prefix) if args.prefix else default_prefix()
    install(version, prefix)


if __name__ == "__main__":
    main()
