# AGENTS.md

## Project Overview

zghalint is a comprehensive, fast GitHub Actions workflow linter written in Zig. It analyzes `.yml`/`.yaml` workflow files to detect security vulnerabilities, performance issues, best practices violations, expression syntax errors, and permission model problems.

## Build & Development

```bash
zig build                           # Build executable and library
zig build run -- [workflow files]   # Run with arguments
zig build test                      # Run all unit tests
zig build test --summary all        # With detailed summary
zig fmt --check src/ build.zig      # Check formatting
zig fmt src/ build.zig              # Auto-format
```

### Prerequisites

- Zig 0.15.2 or later

### Completion Requirements

Before considering a task complete, run all of the following checks:

```bash
zig build && zig fmt --check src/ build.zig && zig build test --summary all
```

1. `zig build` must succeed
2. `zig fmt --check src/ build.zig` must pass
3. `zig build test --summary all` must pass

Do not skip these checks.

## Architecture

- `src/main.zig` - CLI entry point and argument parsing
- `src/lib.zig` - Library public API and test orchestration
- `src/config.zig` - Configuration parsing and rule overrides (`.zghalint.yml`)
- `src/diagnostics.zig` - Diagnostic types, severity, categories
- `src/rules/` - Linting rule implementations
  - `engine.zig` - Rule execution framework
  - `security.zig` - Security checks
  - `expressions.zig` - `${{ }}` expression validation
  - `performance.zig` - Performance optimization rules
  - `best_practices.zig` - Best practice checks
  - `permissions.zig` - Permission model validation
- `src/workflow/` - Workflow data structures and parsing
  - `types.zig` - Workflow, Job, Step, Trigger types
  - `parser.zig` - Workflow structure parser
  - `validator.zig` - Workflow validation logic
- `src/yaml/` - YAML parsing implemented in-house
  - `tokenizer.zig` - YAML tokenization
  - `parser.zig` - YAML AST parsing
  - `types.zig` - YAML node and span types
- `src/output/` - Output formatters
  - `terminal.zig` - Colored terminal output
  - `json.zig` - JSON output format
  - `sarif.zig` - SARIF 2.1.0 output format

## CLI Options

- `--config <path>` - Load rule overrides from `.zghalint.yml`
- `--format <fmt>` - Output format (`terminal`, `json`, `sarif`; default: `terminal`)
- `--color <mode>` - Color control (`auto`, `always`, `never`; default: `auto`)
- `--fix` - Apply safe auto-fixes and rewrite files in place
- `--fix-unsafe` - Apply all auto-fixes, including unsafe ones
- `-h`, `--help` - Show help
- `-v`, `--version` - Show version

## Project Principles

### Goal

Provide fast static analysis for GitHub Actions workflow files and detect security, performance, and best-practice issues.

### Technical Direction

- Zero dependencies: no external libraries, including the YAML parser
- Safety first: prefer Zig's safety features and explicit types
- Performance conscious: favor low-overhead parsing and execution
- Cross-platform: support Linux, macOS, and Windows on x86_64 and aarch64
- Test quality: keep unit coverage strong with inline tests where practical

## Engineering Approach

### TDD Cycle

Implement changes with the following loop:

1. Red: write a failing test
2. Green: add the minimum implementation to pass
3. Refactor: improve the code without changing behavior

### Tidy First

Separate structural cleanup from behavioral changes where practical.

- Prefer small preparatory refactors over broad rewrites
- Use guard clauses to reduce nesting
- Remove dead code when encountered
- Normalize similar code paths
- Extract helpers when they clarify intent
- Add short explanatory comments only when code is not self-evident

### Iteration Size

Split work into the smallest meaningful increment and finish each increment completely before moving on.

## Codex Skills

Codex-specific skills for this repository live under `.agents/skills/`.
