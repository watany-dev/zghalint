"""Offline checks for scripts/install-zig.py against a staged fake index.

This is the installer `.github/actions/setup-zig` runs. Tests point
`ZIG_INDEX_URL` at a `file://` index so they stay offline and can provoke a
checksum mismatch without hitting ziglang.org.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = PROJECT_ROOT / "scripts" / "install-zig.py"

if platform.system() == "Windows":
    pytest.skip("install-zig.py is exercised on POSIX in PBT", allow_module_level=True)

_OS = {"Linux": "linux", "Darwin": "macos"}.get(platform.system())
_ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}.get(
    platform.machine()
)
if _OS is None or _ARCH is None:
    pytest.skip("no zig tarball triple for this platform", allow_module_level=True)

TRIPLE = f"{_ARCH}-{_OS}"
VERSION = "0.16.0"


def _stage_tarball(root: Path) -> tuple[Path, str]:
    payload = root / "zig-bin" / "zig"
    payload.parent.mkdir()
    payload.write_text("#!/bin/sh\necho 0.16.0\n", encoding="utf-8")
    payload.chmod(payload.stat().st_mode | stat.S_IXUSR)

    archive = root / f"zig-{TRIPLE}-{VERSION}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(payload, arcname=f"zig-{TRIPLE}-{VERSION}/zig")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    return archive, digest


def _write_index(root: Path, archive: Path, digest: str) -> Path:
    index = {
        VERSION: {
            TRIPLE: {
                "tarball": archive.as_uri(),
                "shasum": digest,
            }
        }
    }
    path = root / "index.json"
    path.write_text(json.dumps(index), encoding="utf-8")
    return path


def _run(index: Path, prefix: Path, *args: str, extra_env: dict[str, str] | None = None):
    env = dict(os.environ)
    env["ZIG_INDEX_URL"] = index.as_uri()
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["python3", str(INSTALLER), "--prefix", str(prefix), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


def test_installs_from_zon_when_version_omitted(tmp_path: Path) -> None:
    archive, digest = _stage_tarball(tmp_path)
    index = _write_index(tmp_path, archive, digest)
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (workspace / "build.zig.zon").write_text(
        '.{ .name = .zghalint, .minimum_zig_version = "0.16.0", }\n',
        encoding="utf-8",
    )
    prefix = tmp_path / "prefix"
    result = _run(index, prefix, extra_env={"GITHUB_WORKSPACE": str(workspace)})
    assert result.returncode == 0, result.stderr
    zig = prefix / "pkg" / f"zig-{TRIPLE}-{VERSION}" / "zig"
    assert zig.is_file()
    assert os.access(zig, os.X_OK)


def test_writes_github_path(tmp_path: Path) -> None:
    archive, digest = _stage_tarball(tmp_path)
    index = _write_index(tmp_path, archive, digest)
    prefix = tmp_path / "prefix"
    github_path = tmp_path / "github_path"
    github_path.write_text("", encoding="utf-8")
    result = _run(
        index,
        prefix,
        "--version",
        VERSION,
        extra_env={"GITHUB_PATH": str(github_path)},
    )
    assert result.returncode == 0, result.stderr
    written = github_path.read_text(encoding="utf-8").strip()
    assert written.endswith(f"zig-{TRIPLE}-{VERSION}")
    assert Path(written, "zig").is_file()


def test_rejects_checksum_mismatch(tmp_path: Path) -> None:
    archive, _digest = _stage_tarball(tmp_path)
    index = _write_index(tmp_path, archive, hashlib.sha256(b"other").hexdigest())
    prefix = tmp_path / "prefix"
    result = _run(index, prefix, "--version", VERSION)
    assert result.returncode != 0
    assert "checksum mismatch" in result.stderr
