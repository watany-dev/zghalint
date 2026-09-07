#!/bin/bash
# Run shellcheck over the shell scripts embedded in a composite action.
#
# actionlint runs shellcheck on `run:` blocks in `.github/workflows/`, but it
# does not read `action.yml`. That left the composite action — the code every
# consumer of `watany-dev/zghalint@<tag>` executes — with a
# `# shellcheck disable=SC2086` directive and no shellcheck to honour it.
#
# Each `run:` block is written to a scratch file padded with leading blank
# lines, so the line numbers shellcheck reports match the ones in action.yml.
set -euo pipefail

ACTION_FILE="${1:-action.yml}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

python3 - "$ACTION_FILE" "$WORKDIR" <<'PY'
import pathlib
import sys

import yaml

action_file, workdir = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
root = yaml.compose(action_file.read_text(encoding="utf-8"))


def get(mapping, key):
    """Value node for `key`, or None. Works on a composed (node) tree."""
    if not isinstance(mapping, yaml.MappingNode):
        return None
    for key_node, value_node in mapping.value:
        if key_node.value == key:
            return value_node
    return None


runs = get(root, "runs")
steps = get(runs, "steps") if runs is not None else None
if steps is None:
    sys.exit(0)

default_shell = get(runs, "shell")
for index, step in enumerate(steps.value):
    run = get(step, "run")
    if run is None:
        continue
    shell_node = get(step, "shell") or default_shell
    shell = shell_node.value if shell_node is not None else "bash"
    if shell not in ("bash", "sh"):
        # pwsh / python steps are not shell scripts.
        continue

    # start_mark.line is 0-based and points at the `|` / `>` indicator for a
    # block scalar, whose content starts on the next line; a plain scalar
    # starts on the mark's own line. Padding with that many newlines aligns
    # the scratch file with action.yml.
    first_line = run.start_mark.line + (1 if run.style in ("|", ">") else 0)
    padding = "\n" * first_line
    out = workdir / f"step{index}.{shell}"
    out.write_text(f"{padding}{run.value}", encoding="utf-8")
PY

shopt -s nullglob
scripts=("$WORKDIR"/*.bash "$WORKDIR"/*.sh)
if [ ${#scripts[@]} -eq 0 ]; then
  echo "shellcheck-action: no shell run: blocks found in $ACTION_FILE"
  exit 0
fi

status=0
for script in "${scripts[@]}"; do
  case "$script" in
    *.bash) shell="bash" ;;
    *) shell="sh" ;;
  esac
  # Report findings against the original path so the output is clickable and
  # GitHub's annotations land on the right file.
  if ! shellcheck --shell="$shell" --format=gcc "$script" |
    sed "s|^$script|$ACTION_FILE|"; then
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo "shellcheck-action: findings in $ACTION_FILE (lines match the file; columns are relative to the run: block body)" >&2
fi
exit "$status"
