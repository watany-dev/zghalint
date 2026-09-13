# zghalint

[![CI](https://github.com/watany-dev/zghalint/actions/workflows/ci.yml/badge.svg)](https://github.com/watany-dev/zghalint/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A comprehensive, fast GitHub Actions workflow linter written in Zig.
Zero external dependencies — even the YAML parser is built from scratch.

## Features

- **Security** — Script injection, unpinned actions, hardcoded secrets, environment injection, dangerous triggers
- **Supply Chain** — Known vulnerable actions (CVE), archived repos, unpinned images, ref confusion
- **Performance** — Missing caching, redundant checkout, fail-fast detection
- **Best Practices** — Timeouts, naming, deprecated actions, concurrency, obfuscation detection
- **Expression Validation** — `${{ }}` syntax, context access, function calls, argument validation
- **Permissions** — Overly broad scopes, missing job-level permissions
- **Dependencies** — Dependabot configuration validation
- **Action Metadata** — `action.yml` required keys, `runs.using` runtimes, input/output definitions
- **Multiple Output Formats** — Terminal (colored), JSON, SARIF 2.1.0 (GitHub Code Scanning)

## Installation

### Install script

```bash
curl -fsSL https://raw.githubusercontent.com/watany-dev/zghalint/main/install.sh | sh
```

Detects the platform, downloads the matching release archive, verifies it
against the release's `SHA256SUMS`, and installs the binary into `<prefix>/bin`.
The prefix is `/usr/local` when `/usr/local/bin` is writable and `$HOME/.local`
otherwise. Linux and macOS only; on Windows use the release archive or the
GitHub Action.

Options are passed after `-s --`:

```bash
curl -fsSL https://raw.githubusercontent.com/watany-dev/zghalint/main/install.sh \
  | sh -s -- --version v0.0.1 --prefix "$HOME/.local"
```

`--version` takes a release tag and defaults to the release the script was
published with; `--prefix` chooses the install directory. To read the script
before running it, download it first and run `sh install.sh`.

### Homebrew

```bash
brew install watany-dev/tap/zghalint
```

The tap is updated by the release workflow. Prereleases (`-rc.`) are not
published to it, so `brew` installs the newest stable release.

### Build from source

Requires **Zig 0.16.0** or later (the authoritative value is `minimum_zig_version` in `build.zig.zon`; see [docs/maintenance.md](docs/maintenance.md)).

```bash
git clone https://github.com/watany-dev/zghalint.git
cd zghalint
zig build -Doptimize=ReleaseFast
```

The binary will be at `./zig-out/bin/zghalint`.

### Download release binary

Pre-built binaries for Linux, macOS, and Windows (x86_64 / aarch64) are available on the [Releases](https://github.com/watany-dev/zghalint/releases) page.
The current release is `v0.0.1`.
Tags follow `v<semver>`, with prereleases as `v<semver>-rc.<N>`; see [docs/maintenance.md](docs/maintenance.md) for the release procedure.

#### Verifying a release artifact

Every release archive is published with a `SHA256SUMS` file and a
[SLSA build provenance attestation](https://slsa.dev/), so a download can be
checked against both the published checksum and the workflow that produced it.

```bash
TAG=v0.0.1
ARCHIVE=zghalint-linux-x86_64.tar.gz
BASE=https://github.com/watany-dev/zghalint/releases/download/$TAG

curl -fSL -O "$BASE/$ARCHIVE"
curl -fSL -O "$BASE/SHA256SUMS"

# 1. Checksum published with the release
sha256sum --ignore-missing -c SHA256SUMS

# 2. Provenance: the archive was built by this repository's release workflow
gh attestation verify "$ARCHIVE" --repo watany-dev/zghalint
```

`gh attestation verify` requires GitHub CLI 2.49 or later. It prints the
workflow (`.github/workflows/release.yml`) and the commit the artifact was
built from; a mismatch or a missing attestation means the archive did not come
from this repository's release pipeline.

### Use as a GitHub Action

```yaml
- uses: watany-dev/zghalint@v0.0.1
  with:
    paths: ".github/workflows/*.yml"
```

With auto-fix enabled:

```yaml
- uses: watany-dev/zghalint@v0.0.1
  with:
    paths: ".github/workflows/*.yml"
    fix: safe
```

The action downloads the release archive for the ref it was referenced by, so
pinning to a full commit SHA — what zghalint's own `SEC001` asks of every
action — works too: a ref that is not a release tag (a SHA, a branch, a moving
major tag) resolves to the release its commit belongs to. Pin a commit that is
part of a release; a commit made after a version bump but before its tag has no
archive to download yet.

```yaml
- uses: watany-dev/zghalint@<full-sha> # v0.0.1
  with:
    paths: ".github/workflows/*.yml"
```

Pass `version` to download a specific release regardless of the ref:

```yaml
- uses: watany-dev/zghalint@<full-sha> # v0.0.1
  with:
    version: v0.0.1
    paths: ".github/workflows/*.yml"
```

## Usage

### Basic

```bash
# Lint all workflow files
zghalint .github/workflows/*.yml

# Lint a specific file
zghalint .github/workflows/ci.yml

# Lint the default targets of the current repository
zghalint
```

With no file arguments zghalint reads `.github/workflows/*.yml`,
`.github/dependabot.yml`, the repository's own `action.yml` / `action.yaml`,
and `.github/actions/*/action.yml`. Action metadata kept anywhere else is
linted by passing its path explicitly.

### With configuration file

```bash
zghalint --config .zghalint.yml .github/workflows/*.yml
```

### Output formats

```bash
# Terminal output with colors (default)
zghalint .github/workflows/*.yml

# JSON output
zghalint --format json .github/workflows/*.yml

# SARIF output for GitHub Code Scanning
zghalint --format sarif .github/workflows/*.yml > results.sarif
```

### Offline mode and cache control

```bash
# Disable all network requests and use only local data/cache
zghalint --quick .github/workflows/*.yml

# Bypass the on-disk prefetch cache and refetch from GitHub
zghalint --no-cache .github/workflows/*.yml
```

Network-dependent rules (SC003-SC006) share a single HTTP client and,
when `GITHUB_TOKEN` is set, batch repository lookups into a single
GraphQL POST. Results are cached per-repo under
`$XDG_CACHE_HOME/zghalint/repos/` with a 24-hour TTL; `--no-cache`
forces a refresh.

### Example output

```
.github/workflows/ci.yml:15:7: warning [SEC001]: action reference is not pinned to a SHA
  hint: pin to a full 40-character commit SHA instead of a tag or branch
.github/workflows/ci.yml:8:1: warning [BP001]: Job is missing 'timeout-minutes'. Default timeout is 6 hours, which is usually too long.
  hint: Add 'timeout-minutes' to the job (e.g., timeout-minutes: 30).
```

## Rules

zghalint includes **108 rules** across 11 categories. See [docs/rules.md](docs/rules.md) for the complete rule reference with detailed descriptions.

### Security (23 rules)

Script injection, unpinned actions, hardcoded secrets, environment injection, secrets management, container credentials, cache poisoning, self-hosted runners on fork-accessible triggers, fork-controlled `workflow_run` gates, publishing with a long-lived API token instead of OIDC, and more.

### Supply Chain (8 rules)

Unpinned container images, compromised action SHAs, known CVEs, archived repositories, stale SHA refs, ref confusion attacks, typosquat action names, impostor commits.

### Performance (3 rules)

Missing caching, redundant checkout, fail-fast disabled.

### Best Practices (7 rules)

Missing timeouts, step naming, deprecated actions, cross-platform shell, concurrency, obfuscation detection, deprecated workflow commands.

### Permissions (3 rules)

Overly broad scopes, missing job-level permissions, unknown scope names and
invalid permission levels.

### Expression Validation (13 rules)

`${{ }}` syntax errors, unknown contexts/properties/functions, argument count validation, unsound conditions, `steps.<id>` resolution, unsynchronized background outputs.

### Dependencies (3 rules)

Dependabot cooldown configuration, insecure external code execution settings,
`uses:` reference format for actions and reusable workflow calls.

### Runner (3 rules)

Deprecated or retired `runs-on:` label detection, unknown `runs-on:` label
detection (typos such as `ubunut-latest`), and conflicting label sets that no
single runner can satisfy (`runs-on: [ubuntu-latest, windows-latest]`).

### Action Metadata (4 rules)

Required keys in `action.yml` / `action.yaml`, supported and deprecated
`runs.using` runtimes, unknown metadata keys, and the shape of `inputs` /
`outputs` definitions.

### Syntax (21 rules)

Empty workflow sections, unknown keys, duplicate keys, mapping value types, duplicate job/step IDs, job/step ID naming, duplicated job IDs in `needs`, unknown `on:` event names, invalid `types:` activity types, event filters the event does not offer, mutually exclusive event filters specified together, invalid filter globs, cron syntax and frequency, `schedule` timezone names, `cache-mode` values, YAML merge key `<<`, `workflow_dispatch` input definitions, duplicate `strategy.matrix` values, `strategy.matrix` `include` / `exclude` consistency, workflow files with no content at all.

## Configuration

Create a `.zghalint.yml` file in your project root to customize behavior:

```yaml
# Override rule severity or disable rules
rules:
  SEC001:
    severity: error        # Upgrade from warning to error
  BP002:
    enabled: false         # Disable missing-step-name rule
  SEC007:
    severity: warning      # Upgrade from info to warning
  # PERF001 picks a cache manager from lockfiles it detects in the
  # workspace (package-lock.json / yarn.lock / pnpm-lock.yaml /
  # Pipfile.lock / poetry.lock / requirements.txt / go.sum). Override
  # the probe result when multiple lockfiles coexist or none are checked in.
  # It also flags oven-sh/setup-bun without actions/cache, and
  # astral-sh/setup-uv with `enable-cache: false` (no autofix for either).
  PERF001:
    node_cache_manager: pnpm     # one of: npm, yarn, pnpm
    python_cache_manager: poetry # one of: pip, pipenv, poetry

# RUNNER002 knows the GitHub-hosted runner labels but not your self-hosted
# fleet. List the labels it should accept as known.
runner:
  labels:
    - ubuntu-nvidia
    - build-box

# Ignore specific files
ignore:
  - ".github/workflows/legacy-*.yml"
  - ".github/workflows/experimental.yml"

# Output settings
output:
  format: terminal         # terminal, json, sarif
  color: auto              # auto, always, never

# Repository visibility (used by SEC020)
#   public  — fire SEC020 on self-hosted runners with fork-accessible triggers
#   private — suppress SEC020 (fork PRs cannot reach private repos)
#   unknown — fail-safe, treated as public (default when unset)
repo_visibility: unknown
```

## CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--config <path>` | Load rule overrides from a `.zghalint.yml` file | None |
| `--format <fmt>` | Output format: `terminal`, `json`, `sarif` | `terminal` |
| `--color <mode>` | Color control: `auto`, `always`, `never` | `auto` |
| `--quick` | Disable network requests and use only local data/cache (`--offline` is also accepted) | Off |
| `--no-cache` | Bypass the on-disk prefetch cache and refetch from the network | Off |
| `--fix` | Apply safe auto-fixes and rewrite files in place | |
| `--fix-unsafe` | Apply all auto-fixes, including unsafe ones | |
| `-h`, `--help` | Show help message | |
| `-v`, `--version` | Show version | |

## Development

```bash
zig build                           # Build the CLI executable
zig build run -- [workflow files]   # Run with arguments
zig build test                      # Run all unit tests
zig build test --summary all        # With detailed summary
zig fmt --check src/ build.zig      # Check formatting
zig fmt src/ build.zig              # Auto-format
zig build fuzz                      # Fuzz targets over their seed corpus
```

The parsers that consume untrusted input (the YAML tokenizer, the YAML parser
and the `${{ }}` expression parser) have fuzz targets in `src/fuzz_test.zig`.
`zig build fuzz` replays their seed corpus as ordinary regression tests;
`zig build fuzz --fuzz --webui=127.0.0.1` starts continuous, coverage-guided
fuzzing and runs until interrupted. See
[docs/design/pbt-strategy.md](docs/design/pbt-strategy.md) §6-4 for the corpus
and regression policy.

## Contributing

Issue templates are provided for bug reports, false positives / false
negatives, and new rules. Before opening a pull request, run the checks the CI
runs:

```bash
zig build && zig fmt --check src/ build.zig && zig build test --summary all
```

User-visible changes go in [CHANGELOG.md](CHANGELOG.md) under `## [Unreleased]`,
and a new or changed rule needs its row in [docs/rules.md](docs/rules.md) — a
test fails the build if the two drift apart.

## Security

Do not open a public issue for a vulnerability in zghalint itself — including a
workflow it fails to flag. See [SECURITY.md](SECURITY.md) for the private
reporting path.

## License

[Apache License 2.0](LICENSE)
