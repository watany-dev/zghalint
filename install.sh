#!/bin/sh
# Install a released zghalint binary.
#
#   curl -fsSL https://raw.githubusercontent.com/watany-dev/zghalint/main/install.sh | sh
#
# The download and verification mirror the composite action's; keep the two in
# step (action.yml). Written for POSIX sh so `| sh` and `| bash` behave the same.
set -eu

REPO=watany-dev/zghalint

# The release this copy of the installer points at. The installer is fetched
# from a ref and run before any binary exists, so it cannot read the version at
# run time the way `--version` does; `scripts/check-version-sync.sh` keeps this
# in step with `build.zig.zon` instead. See docs/maintenance.md.
DEFAULT_VERSION=v0.0.1-rc.2

usage() {
  cat <<'EOF'
Install zghalint, a fast GitHub Actions workflow linter.

Usage:
  install.sh [--version <tag>] [--prefix <dir>]

Options:
  --version <tag>  Release tag to install (for example v1.2.3). Defaults to the
                   release this installer was published with.
  --prefix <dir>   Install into <dir>/bin. Defaults to /usr/local when that is
                   writable, otherwise $HOME/.local.
  -h, --help       Show this help.

Environment:
  ZGHALINT_VERSION   Same as --version.
  PREFIX             Same as --prefix.
  ZGHALINT_BASE_URL  Directory URL holding the release archives and SHA256SUMS.
                     Defaults to this release's GitHub download URL; set it to
                     install from a mirror.

When piping this script, pass options after `-s --`:
  curl -fsSL <url> | sh -s -- --prefix "$HOME/.local"
EOF
}

die() {
  printf 'install.sh: %s\n' "$1" >&2
  exit 1
}

have() {
  command -v "$1" >/dev/null 2>&1
}

version=${ZGHALINT_VERSION:-$DEFAULT_VERSION}
prefix=${PREFIX:-}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || die "--version needs a release tag"
      version=$2
      shift 2
      ;;
    --prefix)
      [ "$#" -ge 2 ] || die "--prefix needs a directory"
      prefix=$2
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown option: $1"
      ;;
  esac
done

# Releases are tagged `v<semver>`. Rejecting anything else keeps a typo from
# being pasted into the download URL as a path.
case "$version" in
  v[0-9]*) ;;
  *) die "version must be a release tag such as v1.2.3, got: $version" ;;
esac

if have curl; then
  download() { curl -fsSL -o "$2" "$1"; }
elif have wget; then
  download() { wget -qO "$2" "$1"; }
else
  die "curl or wget is required"
fi

os=$(uname -s)
case "$os" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  MINGW* | MSYS* | CYGWIN*)
    die "Windows is not supported by this installer; download zghalint-windows-x86_64.zip from https://github.com/$REPO/releases, or use the GitHub Action"
    ;;
  *) die "unsupported operating system: $os" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) die "unsupported architecture: $arch" ;;
esac

# /usr/local/bin is the conventional destination but is root-owned on most
# systems. Falling back to ~/.local/bin keeps the common `curl | sh` working
# without asking for a password or invoking sudo on the user's behalf.
if [ -z "$prefix" ]; then
  if [ -w /usr/local/bin ]; then
    prefix=/usr/local
  else
    prefix=$HOME/.local
  fi
fi
bindir=$prefix/bin

target="$os-$arch"
archive="zghalint-$target.tar.gz"
base_url=${ZGHALINT_BASE_URL:-"https://github.com/$REPO/releases/download/$version"}

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t zghalint)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

printf 'Downloading zghalint %s (%s)\n' "$version" "$target"
download "$base_url/$archive" "$tmp/$archive" ||
  die "could not download $base_url/$archive"
download "$base_url/SHA256SUMS" "$tmp/SHA256SUMS" ||
  die "could not download $base_url/SHA256SUMS"

# Linux ships sha256sum, macOS ships shasum; those are the two platforms this
# script installs for, and action.yml checks with the same pair.
if have sha256sum; then
  actual_sum=$(sha256sum "$tmp/$archive" | cut -d' ' -f1)
elif have shasum; then
  actual_sum=$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)
else
  die "no SHA-256 tool found; install coreutils or shasum"
fi

# `sha256sum -c` is not portable enough to rely on (BSD and macOS ship a
# different checker), so the one relevant line is compared directly. A
# `*`-prefixed name is what a checksum file written in binary mode carries.
expected_sum=$(awk -v name="$archive" '$2 == name || $2 == "*" name { print $1 }' "$tmp/SHA256SUMS")
[ -n "$expected_sum" ] || die "SHA256SUMS has no entry for $archive"
[ "$actual_sum" = "$expected_sum" ] ||
  die "checksum mismatch for $archive: expected $expected_sum, got $actual_sum"

tar -xzf "$tmp/$archive" -C "$tmp"
binary="$tmp/zghalint-$target/zghalint"
[ -f "$binary" ] || die "archive does not contain zghalint-$target/zghalint"

mkdir -p "$bindir" || die "could not create $bindir"
chmod 0755 "$binary"

# Copying onto a running binary fails with ETXTBSY; renaming within the
# destination directory replaces it atomically instead.
staged="$bindir/.zghalint.$$"
if ! cp "$binary" "$staged" 2>/dev/null; then
  rm -f "$staged"
  die "could not write to $bindir; rerun with --prefix \"\$HOME/.local\""
fi
mv -f "$staged" "$bindir/zghalint"

printf 'Installed %s to %s\n' "$("$bindir/zghalint" --version)" "$bindir/zghalint"

# The `$PATH` in the advice below is literal text for the user to paste, not
# this shell's value.
# shellcheck disable=SC2016
case ":${PATH:-}:" in
  *":$bindir:"*) ;;
  *) printf 'note: %s is not on PATH; add it with: export PATH="%s:%s"\n' "$bindir" "$bindir" '$PATH' >&2 ;;
esac
