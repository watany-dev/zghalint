# E2E fixtures

Real workflow files fed through the production pipeline — YAML tokenizer →
YAML parser → workflow parser → rule engine — by the Zig test
`E2E: fixtures produce the declared diagnostics` in `src/e2e_test.zig`.

Rule-level inline tests build `Workflow` / `Job` / `Step` values by hand, so a
parser-layer defect can silence a rule while every one of those tests stays
green (see #131: plain scalars were truncated and SEC002 stopped firing on
unquoted `run:`). These fixtures close that gap.

## Declaring expectations

Each fixture declares its own expectations in the leading comment block:

```yaml
# zghalint:expect SEC002@19 EXPR001
# zghalint:forbid SEC001
```

- `expect` — the rule must fire at least once. `@<line>` optionally pins the
  1-based start line of the diagnostic.
- `forbid` — the rule must not fire at all (false-positive guard).

Directives accumulate across lines, and parsing stops at the first
non-comment line. A fixture with neither directive fails the test.

## Fixtures

| File | Purpose |
|---|---|
| `sec002-run-plain-scalar.yml` | #131 repro: `${{ }}` in an unquoted `run:` |
| `sec002-run-quoted-scalar.yml` | Same injection in a single-quoted scalar |
| `sec002-run-block-scalar.yml` | Same injection in a `run: \|` block scalar |
| `security-misc.yml` | SEC003 / SEC005 / SEC006 / SEC007 / SEC008 / SC002 |
| `sec006-condition-scope.yml` | #138 repro: ref/label routing in `if:` must not fire SEC006 |
| `supply-chain.yml` | Unpinned actions and container images, `write-all` |
| `expressions.yml` | `${{ }}` syntax and unknown-context errors |
| `syntax.yml` | Schema, type, and duplicate-ID violations |
| `best-practices.yml` | Timeouts, step names, concurrency, retired runners |
| `clean.yml` | A well-formed workflow: nothing may fire |

Network-backed rules (SC003–SC006, SC008) stay offline in tests, so fixtures
only exercise local analysis.

Fixtures are read at runtime via `std.fs.cwd()` (tests run with
`cwd = repo root`), so adding a `.yml` file here is enough to add a case.
