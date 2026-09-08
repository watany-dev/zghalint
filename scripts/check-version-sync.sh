#!/bin/bash
# Verify that every place the release version is written out agrees.
#
# The authoritative value is `.version` in build.zig.zon; `build.zig` feeds it
# to `--version`. The copies below cannot be derived at build time — the action
# runs before any binary exists, and the README is prose — so they are checked
# instead. See docs/maintenance.md.
#
# Usage: check-version-sync.sh [expected-version]
#
# With an argument (the release tag, with or without a leading `v`), the
# authoritative value must also match it. Without one, only the copies are
# compared against build.zig.zon.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0
fail() {
  echo "::error::$1" >&2
  status=1
}

ZON_VERSION=$(sed -n 's/^[[:space:]]*\.version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' build.zig.zon | head -1)
if [ -z "$ZON_VERSION" ]; then
  fail "could not read .version from build.zig.zon"
  exit 1
fi

if [ "$#" -ge 1 ]; then
  EXPECTED=${1#v}
  if [ "$ZON_VERSION" != "$EXPECTED" ]; then
    fail "expected version $EXPECTED but build.zig.zon has $ZON_VERSION"
  fi
fi

# action.yml's fallback is what a consumer who pinned a SHA (as SEC001 asks)
# downloads, so a stale value here breaks exactly the recommended usage.
ACTION_VERSION=$(sed -n 's/^[[:space:]]*FALLBACK_VERSION=v\(.*\)$/\1/p' action.yml | head -1)
if [ -z "$ACTION_VERSION" ]; then
  fail "could not read FALLBACK_VERSION from action.yml"
elif [ "$ACTION_VERSION" != "$ZON_VERSION" ]; then
  fail "action.yml FALLBACK_VERSION is v$ACTION_VERSION but build.zig.zon has $ZON_VERSION"
fi

# The README is copy-pasted by readers, so a stale version there sends them to
# a release that may not exist. Every `vX.Y.Z` in it is a zghalint release —
# the Zig version is written without a leading `v` — so they are all compared.
while IFS=: read -r line ref; do
  [ -n "$ref" ] || continue
  if [ "${ref#v}" != "$ZON_VERSION" ]; then
    fail "README.md:$line says $ref but build.zig.zon has $ZON_VERSION"
  fi
done <<<"$(grep -nEo 'v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?' README.md)"

if [ "$status" -eq 0 ]; then
  echo "version OK: $ZON_VERSION"
fi
exit "$status"
