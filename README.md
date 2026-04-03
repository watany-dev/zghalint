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
The first public tag is `v0.0.1-rc.1`, published as a prerelease while the installation flow and CLI contract are still being validated.

### Use as a GitHub Action

```yaml
- uses: watany-dev/zghalint@v0.0.1-rc.1
  with:
    paths: ".github/workflows/*.yml"
```

With auto-fix enabled:

```yaml
- uses: watany-dev/zghalint@v0.0.1-rc.1
  with:
    paths: ".github/workflows/*.yml"
    fix: safe
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

zghalint includes **38 rules** across 7 categories. See [docs/rules.md](docs/rules.md) for the complete rule reference with detailed descriptions.

### Security (17 rules)

Script injection, unpinned actions, hardcoded secrets, environment injection, secrets management, container credentials, cache poisoning, and more.

### Supply Chain (5 rules)

Unpinned container images, known CVEs, archived repositories, stale SHA refs, ref confusion attacks.

### Performance (3 rules)

Missing caching, redundant checkout, fail-fast disabled.

### Best Practices (6 rules)

Missing timeouts, step naming, deprecated actions, cross-platform shell, concurrency, obfuscation detection.

### Permissions (2 rules)

Overly broad scopes, missing job-level permissions.

### Expression Validation (7 rules)

`${{ }}` syntax errors, unknown contexts/properties/functions, argument count validation, unsound conditions.

### Dependencies (2 rules)

Dependabot cooldown configuration, insecure external code execution settings.

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
| `--fix` | Apply safe auto-fixes and rewrite files in place | |
| `--fix-unsafe` | Apply all auto-fixes, including unsafe ones | |
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
