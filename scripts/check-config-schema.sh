#!/bin/bash
# Verify docs/schema/zghalint.schema.json matches src/config.zig key tables.
#
# The authoritative names are `schema_*_keys` (and the related enums) in
# src/config.zig / src/workspace.zig; scripts/gen-config-schema.py builds the
# JSON Schema from them (#560).
set -euo pipefail

cd "$(dirname "$0")/.."

generated=$(mktemp)
trap 'rm -f "$generated"' EXIT
python3 scripts/gen-config-schema.py >"$generated"

if ! diff -u docs/schema/zghalint.schema.json "$generated"; then
  echo "::error::docs/schema/zghalint.schema.json is stale; run python3 scripts/gen-config-schema.py > docs/schema/zghalint.schema.json" >&2
  exit 1
fi

echo "config schema OK"
