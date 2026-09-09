#!/usr/bin/env bash
# Install the extra GitHub Actions linters compared by `scripts/bench.py --perf`.
# actionlint and zizmor stay pinned in ci.yml / .github/lint-requirements.txt.
#
# Linux x86_64 only — the weekly bench runner is ubuntu-latest. Pins live here
# so bench.yml and a local install share one checksum.
#
# Usage: [sudo] PREFIX=/usr/local scripts/install-perf-rivals.sh
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
DEST="${PREFIX}/bin"

os=$(uname -s)
arch=$(uname -m)
if [ "$os" != Linux ] || [ "$arch" != x86_64 ]; then
  echo "install-perf-rivals.sh: only Linux x86_64 is pinned (got ${os} ${arch})" >&2
  exit 1
fi

GHALINT_VERSION=1.5.6
GHALINT_SHA256=98ee0e3330de7286f470d1e89c03ff7ce70d7a5998ba0f15969c400447be579c
OCTOSCAN_VERSION=0.1.7
OCTOSCAN_SHA256=6435e9cc0e6346741367cbb1803e5b545d8e7031d188c733a0b30f768ab6ebe2
POUTINE_VERSION=1.1.6
POUTINE_SHA256=abde716599a65608b023a69ed9316e5f083a7bca48612151c2720835883757ea
ACTION_VALIDATOR_VERSION=0.9.0
ACTION_VALIDATOR_SHA256=9f42f94fca5b8d04c13bccfbb331104b37a9250650d89ae58dc888d46206f9b9

workdir=$(mktemp -d)
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT

mkdir -p "$DEST"

fetch() {
  local url=$1 dest=$2 sha=$3
  curl -fsSL -o "$dest" "$url"
  echo "${sha}  ${dest}" | sha256sum -c -
}

fetch \
  "https://github.com/suzuki-shunsuke/ghalint/releases/download/v${GHALINT_VERSION}/ghalint_${GHALINT_VERSION}_linux_amd64.tar.gz" \
  "$workdir/ghalint.tar.gz" \
  "$GHALINT_SHA256"
tar -xzf "$workdir/ghalint.tar.gz" -C "$workdir" ghalint
install -m 0755 "$workdir/ghalint" "$DEST/ghalint"

fetch \
  "https://github.com/synacktiv/octoscan/releases/download/v${OCTOSCAN_VERSION}/octoscan" \
  "$workdir/octoscan" \
  "$OCTOSCAN_SHA256"
install -m 0755 "$workdir/octoscan" "$DEST/octoscan"

fetch \
  "https://github.com/boostsecurityio/poutine/releases/download/v${POUTINE_VERSION}/poutine_Linux_x86_64.tar.gz" \
  "$workdir/poutine.tar.gz" \
  "$POUTINE_SHA256"
tar -xzf "$workdir/poutine.tar.gz" -C "$workdir" poutine
install -m 0755 "$workdir/poutine" "$DEST/poutine"

fetch \
  "https://github.com/mpalmer/action-validator/releases/download/v${ACTION_VALIDATOR_VERSION}/action-validator_linux_amd64" \
  "$workdir/action-validator" \
  "$ACTION_VALIDATOR_SHA256"
install -m 0755 "$workdir/action-validator" "$DEST/action-validator"
