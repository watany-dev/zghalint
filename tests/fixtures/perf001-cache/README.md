# PERF001 cache autofix fixtures

Input / expected pairs for PERF001 setup-node / setup-python / setup-go
autofix. Each subdirectory represents a scenario:

| Directory | Workspace context | Expected behavior |
|---|---|---|
| `setup-node-npm/` | `workspace.current.node_cache = .npm` | fix inserts `cache: npm` |
| `setup-node-pnpm/` | `node_cache = .pnpm` | fix inserts `cache: pnpm` |
| `setup-python-poetry/` | `python_cache = .poetry` | fix inserts `cache: poetry` |
| `setup-go-gosum/` | `go_sum_present = true` | fix inserts `cache: true` |
| `setup-node-ambiguous/` | `ambiguous_node_lockfiles = [...]` | fix suppressed, diagnostic only |
| `setup-bun-lock/` | `bun_lockfile_present = true` | diagnostic only (no autofix for bun) |
| `setup-uv-disabled/` | empty | diagnostic only when `enable-cache: false` is explicit |

Each directory contains:

- `input.yml` — workflow source fed to the linter
- `expected.yml` — expected content after `--fix-unsafe` (omitted for
  ambiguous case, where fix should be null)

These fixtures are consumed by the Zig inline test
`PERF001: fixture harness applies expected fix` in
`src/rules/performance.zig`. The harness reads each file at runtime via
`std.fs.cwd()` (tests run with `cwd = repo root` under both
`zig build test` and the local wrapper), so the fixtures stay outside the
Zig package path without needing `--embed-dir` plumbing.
