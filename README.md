# zghalint

[![CI](https://github.com/watany-dev/zghalint/actions/workflows/ci.yml/badge.svg)](https://github.com/watany-dev/zghalint/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A comprehensive, fast GitHub Actions workflow linter written in Zig.
Zero external dependencies — even the YAML parser is built from scratch.

## Features

- **Security** — Script injection, unpinned actions, hardcoded secrets, dangerous triggers
- **Performance** — Missing caching, redundant checkout detection
- **Best Practices** — Timeouts, naming, deprecated actions, concurrency
- **Expression Validation** — `${{ }}` syntax, context access, function calls
- **Permissions** — Overly broad scopes, missing job-level permissions
- **Multiple Output Formats** — Terminal (colored), JSON, SARIF 2.1.0 (GitHub Code Scanning)

## Installation

### Build from source

Requires **Zig 0.15.2** or later.

```bash
git clone https://github.com/watany-dev/zghalint.git
cd zghalint
zig build -Doptimize=ReleaseFast
```

The binary will be at `./zig-out/bin/zghalint`.

### Download release binary

Pre-built binaries for Linux, macOS, and Windows (x86_64 / aarch64) are available on the [Releases](https://github.com/watany-dev/zghalint/releases) page.

### Use as a GitHub Action

```yaml
- uses: watany-dev/zghalint@v0.1.0
  with:
    files: ".github/workflows/*.yml"
```

## Usage

### Basic

```bash
# Lint all workflow files
zghalint .github/workflows/*.yml

# Lint a specific file
zghalint .github/workflows/ci.yml
```

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

### Example output

```
.github/workflows/ci.yml:15:7: warning [SEC001]: action reference is not pinned to a SHA
  hint: pin to a full 40-character commit SHA instead of a tag or branch
.github/workflows/ci.yml:8:1: warning [BP001]: Job is missing 'timeout-minutes'. Default timeout is 6 hours, which is usually too long.
  hint: Add 'timeout-minutes' to the job (e.g., timeout-minutes: 30).
```

## Rules

| ID | Name | Category | Severity | Description |
|----|------|----------|----------|-------------|
| SEC001 | unpinned-action | security | warning | Action references should be pinned to a full SHA |
| SEC002 | script-injection | security | error | Untrusted GitHub context used in `run:` block risks script injection |
| SEC003 | hardcoded-secret | security | error | Hardcoded secrets should use GitHub Secrets |
| SEC004 | excessive-permissions | security | warning | Avoid write-all permissions, specify only needed scopes |
| SEC005 | dangerous-pr-target | security | error | `pull_request_target` with checkout of PR head is dangerous |
| SEC006 | untrusted-input-condition | security | error | Untrusted context in `if:` condition expression |
| SEC007 | missing-permissions | security | info | Workflow should define top-level permissions |
| PERF001 | cache-not-used | performance | warning | Job uses a language setup action without caching enabled |
| PERF002 | redundant-checkout | performance | warning | Multiple `actions/checkout` without path in the same job |
| BP001 | missing-timeout | best_practice | warning | Job is missing `timeout-minutes` (default 6 hours is too long) |
| BP002 | missing-step-name | best_practice | info | Step is missing a `name` field |
| BP003 | deprecated-action-version | best_practice | warning | Using a known deprecated action version |
| BP004 | cross-platform-shell | best_practice | warning | Run step without `shell` in a Windows-targeting job |
| BP005 | push-without-concurrency | best_practice | info | Push trigger without concurrency setting |
| PERM001 | broad-permissions | permissions | warning | Overly broad permission scope detected |
| PERM002 | missing-job-permissions | permissions | warning | Job with third-party actions lacks explicit permissions |
| EXPR | expression-validator | expression | error | Validates `${{ }}` expression syntax and context access |

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

# Ignore specific files
ignore:
  - ".github/workflows/legacy-*.yml"
  - ".github/workflows/experimental.yml"

# Output settings
output:
  format: terminal         # terminal, json, sarif
  color: auto              # auto, always, never
```

## CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--config <path>` | Load rule overrides from a `.zghalint.yml` file | None |
| `--format <fmt>` | Output format: `terminal`, `json`, `sarif` | `terminal` |
| `--color <mode>` | Color control: `auto`, `always`, `never` | `auto` |
| `-h`, `--help` | Show help message | |
| `-v`, `--version` | Show version | |

## Development

```bash
zig build                           # Build executable and library
zig build run -- [workflow files]   # Run with arguments
zig build test                      # Run all unit tests
zig build test --summary all        # With detailed summary
zig fmt --check src/ build.zig      # Check formatting
zig fmt src/ build.zig              # Auto-format
```

## License

[Apache License 2.0](LICENSE)
