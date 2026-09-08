# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Rule changes are tracked here with particular care: adding a rule, raising a
severity, or widening what an existing rule matches will change the result of a
CI run that was previously green, so those land under **Changed** or **Added**
with the affected rule IDs named. See [docs/rules.md](docs/rules.md) for what
each ID means.

## [Unreleased]

Nothing released yet. `v0.0.1-rc.1` is the first planned tag; the CLI contract
(flag names, exit codes, output shapes) is not yet stable, and rule IDs may
still be renumbered before 1.0.

### Changed

- EXPR006 no longer warns when `contains()` tests array membership (object
  filters such as `labels.*.name`, `fromJSON` arrays, typed arrays). Those are
  exact element checks, not substring matching (#333).

### Added

- GitHub Actions workflow linting across ten categories: security (`SEC*`),
  supply chain (`SC*`), performance (`PERF*`), best practices (`BP*`),
  permissions (`PERM*`), expression validation (`EXPR*`), dependencies
  (`DEP*`), runners (`RUNNER*`), syntax (`SYN*`) and reusable workflows
  (`RW*`).
- Output formats: colored terminal, JSON, and SARIF 2.1.0 for GitHub Code
  Scanning.
- Auto-fix via `--fix` and `--fix-unsafe`.
- Configuration through `.zghalint.yml`: per-rule severity overrides,
  enable/disable, ignore patterns, and output defaults.
- `--quick` / `--offline` and `--no-cache` for controlling the GitHub API
  lookups the `SC*` rules perform.
- A composite action (`watany-dev/zghalint@<tag>`) that downloads the release
  binary and verifies it against the published `SHA256SUMS`.
- Prebuilt binaries for Linux, macOS and Windows on x86_64 and aarch64.
- SLSA build provenance attestations on every release archive, verifiable with
  `gh attestation verify` (see the README).
- Fuzz targets (`zig build fuzz`) for the YAML tokenizer, the YAML parser and
  the `${{ }}` expression parser.
