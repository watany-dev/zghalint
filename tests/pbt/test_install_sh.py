"""End-to-end checks for install.sh against a locally staged fake release.

The installer is what `curl ... | sh` runs on a user's machine, so its download,
checksum verification and placement are exercised here rather than only at
release time. `ZGHALINT_BASE_URL` points the script at a directory of `file://`
URLs holding archives built by this test, which keeps the run offline and lets
the failure paths (a tampered archive, a missing checksum entry) be provoked.
"""

from __future__ import annotations

import hashlib
import os
import platform
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = PROJECT_ROOT / "install.sh"

FAKE_VERSION = "v9.9.9"

if platform.system() == "Windows":
    pytest.skip("install.sh targets POSIX shells", allow_module_level=True)

_OS = {"Linux": "linux", "Darwin": "macos"}.get(platform.system())
_ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}.get(
    platform.machine()
)
if _OS is None or _ARCH is None:
    pytest.skip("no release target for this platform", allow_module_level=True)

TARGET = f"{_OS}-{_ARCH}"
ARCHIVE = f"zghalint-{TARGET}.tar.gz"


def stage_release(root: Path, *, corrupt: bool = False, sums_name: str | None = None) -> Path:
    """Write an archive and a SHA256SUMS beside it, and return the directory.

    The payload is a shell script standing in for the binary: install.sh runs
    `--version` on what it installed, so the stand-in has to answer.
    """
    release = root / "release"
    release.mkdir()

    payload = root / f"zghalint-{TARGET}" / "zghalint"
    payload.parent.mkdir()
    payload.write_text(f'#!/bin/sh\necho "zghalint {FAKE_VERSION}"\n', encoding="utf-8")
    payload.chmod(payload.stat().st_mode | stat.S_IXUSR)

    archive = release / ARCHIVE
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(payload, arcname=f"zghalint-{TARGET}/zghalint")

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if corrupt:
        # Publish a checksum for content that is not what will be downloaded.
        digest = hashlib.sha256(b"something else").hexdigest()

    name = sums_name if sums_name is not None else ARCHIVE
    (release / "SHA256SUMS").write_text(f"{digest}  {name}\n", encoding="utf-8")
    return release


def run_installer(release: Path, prefix: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["ZGHALINT_BASE_URL"] = release.as_uri()
    return subprocess.run(
        ["sh", str(INSTALLER), "--version", FAKE_VERSION, "--prefix", str(prefix), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


def test_installs_the_verified_binary(tmp_path: Path):
    release = stage_release(tmp_path)
    prefix = tmp_path / "prefix"

    result = run_installer(release, prefix)

    assert result.returncode == 0, result.stderr
    installed = prefix / "bin" / "zghalint"
    assert installed.is_file()
    assert os.access(installed, os.X_OK)
    reported = subprocess.run([str(installed), "--version"], capture_output=True, text=True)
    assert reported.stdout.strip() == f"zghalint {FAKE_VERSION}"


def test_replaces_an_existing_install(tmp_path: Path):
    release = stage_release(tmp_path)
    prefix = tmp_path / "prefix"
    (prefix / "bin").mkdir(parents=True)
    (prefix / "bin" / "zghalint").write_text("old\n", encoding="utf-8")

    result = run_installer(release, prefix)

    assert result.returncode == 0, result.stderr
    assert (prefix / "bin" / "zghalint").read_text(encoding="utf-8") != "old\n"
    # The staging name used for the atomic replace must not survive.
    assert [p.name for p in (prefix / "bin").iterdir()] == ["zghalint"]


def test_rejects_a_checksum_mismatch(tmp_path: Path):
    release = stage_release(tmp_path, corrupt=True)
    prefix = tmp_path / "prefix"

    result = run_installer(release, prefix)

    assert result.returncode != 0
    assert "checksum mismatch" in result.stderr
    assert not (prefix / "bin" / "zghalint").exists()


def test_rejects_a_checksum_file_without_the_archive(tmp_path: Path):
    release = stage_release(tmp_path, sums_name="zghalint-other-target.tar.gz")
    prefix = tmp_path / "prefix"

    result = run_installer(release, prefix)

    assert result.returncode != 0
    assert "no entry for" in result.stderr
    assert not (prefix / "bin" / "zghalint").exists()


def test_rejects_a_version_that_is_not_a_release_tag(tmp_path: Path):
    release = stage_release(tmp_path)
    env = dict(os.environ)
    env["ZGHALINT_BASE_URL"] = release.as_uri()

    result = subprocess.run(
        ["sh", str(INSTALLER), "--version", "main"],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )

    assert result.returncode != 0
    assert "release tag" in result.stderr


def test_help_exits_zero():
    result = subprocess.run(
        ["sh", str(INSTALLER), "--help"], capture_output=True, text=True, timeout=120
    )

    assert result.returncode == 0
    assert "--prefix" in result.stdout
