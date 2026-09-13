# E2E fixtures (action metadata)

Real `action.yml` documents fed through the production pipeline — YAML
tokenizer → YAML parser → `lintActionMetadata` — by the Zig test
`E2E: action metadata fixtures produce the declared diagnostics` in
`src/e2e_test.zig`.

Action metadata is not a workflow, so these files stop at the YAML document
instead of continuing into the workflow parser and rule engine. That is the
same path the CLI takes for a file named `action.yml` / `action.yaml`; the
file names here differ only so each fixture can say what it covers.

## Declaring expectations

Identical to `tests/fixtures/e2e/README.md`:

```yaml
# zghalint:expect ACT001@4 ACT002
# zghalint:forbid ACT003
```

- `expect` — the rule must fire at least once. `@<line>` optionally pins the
  1-based start line of the diagnostic.
- `forbid` — the rule must not fire at all (false-positive guard).

Directives accumulate across lines, and parsing stops at the first
non-comment line. A fixture with neither directive fails the test.

A sibling `<fixture>.yml.fixed` file pins what `--fix` makes of the fixture,
and `<fixture>.yml.fixed-unsafe` what `--fix-unsafe` makes of it, the same as
for the workflow fixtures.

## Fixtures

| File | Purpose |
|---|---|
| `act001-missing-keys.yml` | ACT001: no `name`, and a node action without `main` |
| `act001-composite-steps-fix.yml` | ACT001: `--fix-unsafe` inserts a placeholder `steps:` item under a composite `runs:` |
| `act002-deprecated-and-unknown-using.yml` | ACT002: `node16`, a runtime GitHub has stopped |
| `act002-node20-using.yml` | #437: `node20` is warning, not unknown |
| `act002-unknown-using.yml` | ACT002: a `using` value that is not a runtime, with a suggestion |
| `act003-unknown-keys.yml` | ACT003: misspelled document key and input key |
| `act004-invalid-definitions.yml` | ACT004: non-boolean `required`, `value` outside a composite action |
| `act005-composite-steps.yml` | ACT005: an unavailable context and a misspelled `inputs.<name>` in a composite step |
| `clean-composite.yml` | A well-formed composite action: nothing may fire |

Fixtures are read at runtime via `std.fs.cwd()` (tests run with
`cwd = repo root`), so adding a `.yml` file here is enough to add a case.
