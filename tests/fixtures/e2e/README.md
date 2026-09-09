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

## Pinning `--fix`

A fixture may also declare what `--fix` makes of it: put the expected result in
a sibling `<fixture>.yml.fixed` file and the harness applies the safe fixes and
compares. A `<fixture>.yml.fixed-unsafe` sibling does the same for
`--fix-unsafe`, which is the only way to pin a rule whose fix is `unsafe`. The
`expect` directives pin *where* a rule fires; these files pin *what* its fix
rewrites, which is the half a wrong byte range would otherwise get wrong
silently. Fixtures without such a sibling are unaffected.

## Invariants checked on every fixture

Two checks run on all fixtures, with no directive needed:

- **Span ordering** — no diagnostic may end before it starts (#367).
- **Fix convergence** — `--fix` and `--fix-unsafe` must reach a fixed point:
  re-running them on their own output leaves the file alone. A fix whose
  rewrite is not read back the way it was meant re-fires forever (#369, #370).

## Fixtures

| File | Purpose |
|---|---|
| `sec002-run-plain-scalar.yml` | #131 repro: `${{ }}` in an unquoted `run:` |
| `sec002-run-quoted-scalar.yml` | Same injection in a single-quoted scalar |
| `sec002-run-block-scalar.yml` | Same injection in a `run: \|` block scalar |
| `sec002-env-binding.yml` | #327: `--fix-unsafe` binds the tainted expression to the step's `env:` per shell |
| `sec019-secret-env-binding.yml` | #327: the same binding for a secret in `run:`, with a `with:`-only step left alone |
| `sec002-repeated-on-event.yml` | #366 repro: `on:` naming the same event three times must not overflow the taint table |
| `sec002-taint-one-hop.yml` | #314 repro: `env.<KEY>` and `needs.<job>.outputs.*` carry taint one hop |
| `security-misc.yml` | SEC003 / SEC005 / SEC006 / SEC007 / SEC008 / SC002 |
| `sc007-typosquat.yml` | #135: `actions/chekout` fires SC007; `myorg/chekout` and exact `actions/checkout` do not |
| `sec006-condition-scope.yml` | #138 repro: ref/label routing in `if:` must not fire SEC006 |
| `sec005-pr-target-head-repository.yml` | #218 repro: `pull_request_target` checkout of the PR head repository |
| `sec021-untrusted-checkout-ref.yml` | #134 repro: checkout ref from an `issue_comment` body |
| `sec021-workflow-call-dispatch-inputs.yml` | #219 repro: `workflow_call` must not silence `inputs.*` on the dispatch path |
| `sec022-workflow-run-branch-gate.yml` | #143 repro: `head_branch` gate on a `workflow_run` job |
| `sec022-workflow-run-anchor-paths.yml` | #220 repro: an anchor joined with `\|\|` or under `!` |
| `supply-chain.yml` | Unpinned actions and container images, `write-all` |
| `expressions.yml` | `${{ }}` syntax and unknown-context errors |
| `expr010-step-refs.yml` | EXPR010: unknown / misspelled / forward `steps.<id>` references |
| `expr011-matrix-context.yml` | EXPR011: undeclared / misspelled `matrix.<key>` and jobs without a matrix |
| `expr013-inputs-context.yml` | EXPR013: undeclared / misspelled `inputs.<name>` against the declared triggers |
| `expr014-secrets-context.yml` | EXPR014: `secrets.<name>` against a declared `workflow_call.secrets` set |
| `expr015-expr016-availability.yml` | EXPR015/EXPR016: contexts and special functions against the key they appear under |
| `expr017-github-event-overlay.yml` | #124: the curated `github.event` overlay widens EXPR017 without new EXPR003s |
| `expr006-array-contains.yml` | #333 FP guard: `contains(labels.*.name, 'x')` is array membership |
| `syn009-privileged-trigger-fix.yml` | #346: `--fix` leaves a `pull_request_target` typo; `--fix-unsafe` rewrites it |
| `syn001-sibling-rename.yml` | #347: `--fix` leaves `runs-onn` when `runs-on` is already a sibling |
| `syn001-sec007-permissions-collision.yml` | #348: `--fix-unsafe` keeps the SYN001 rename of `prmissions` and drops the SEC007 insert |
| `syntax.yml` | Schema, type, and duplicate-ID violations |
| `syn010-syn011-event-config.yml` | #66/#67: invalid `types:` values and filters the event does not offer |
| `syn014-syn015-cron.yml` | #70/#71: invalid `schedule` cron syntax and sub-5-minute intervals |
| `syn016-schedule-timezone.yml` | #72: `schedule` `timezone` names outside the IANA database |
| `syn017-workflow-dispatch-inputs.yml` | #73: `workflow_dispatch` input type, `options`, and `default` mismatches |
| `syn018-duplicate-matrix-value.yml` | #74: repeated values and `include` entries in `strategy.matrix` |
| `perm001-scope-placement.yml` | #285 FP guard: a metadata scope at `write` on the job that needs it |
| `perm001-workflow-level-grant.yml` | #285: the same scopes at workflow level, plus `contents: write` |
| `perm002-workflow-level-read.yml` | #334 FP guard: workflow-level `contents: read` covers jobs |
| `perm003-invalid-permissions.yml` | Unknown `permissions:` scopes and invalid levels |
| `runner002-unknown-label.yml` | #76: unknown/typo'd `runs-on` labels vs. hosted, larger and self-hosted ones |
| `dep005-dep006-action-inputs.yml` | #97/#98/#99: `with:` against the embedded action metadata, and a retired remote runtime |
| `dep004-checkout-path.yml` | #305 FP guard: a local action under an `actions/checkout` `path:` only exists on the runner |
| `best-practices.yml` | Timeouts, step names, concurrency, retired runners |
| `bp004-shell-names.yml` | BP004: unknown shell names and OS-unavailable shells |
| `bp004-shell-after-quoted-continuation.yml` | #173 repro: line numbers after a `\` line continuation in a double-quoted scalar |
| `bp008-workflow-commands.yml` | #326: every deprecated workflow command rewritten by `--fix`, with a piped line left alone |
| `rw001-input-type-fix.yml` | #326: `--fix-unsafe` infers a `workflow_call` input `type:` from its `default:` |
| `clean.yml` | A well-formed workflow: nothing may fire |
| `rename-fix-schema.yml` | #323: every did-you-mean rename on schema keys and values, with its `--fix` result pinned |
| `rename-fix-contexts.yml` | #323: the same for the `needs` / `inputs` / `secrets` expression contexts |
| `merge-key-job-span.yml` | #367 repro: a job built from `<<:` must report a forward span |
| `on-block-nested-sequence-insert.yml` | #368 repro: the SEC007 insertion lands after the `on:` block, not inside a nested sequence item |
| `expr010-rename-invalid-id.yml` | #369 repro: a step id that is not a path identifier gets no rename fix |
| `sec018-with-not-a-block-mapping.yml` | #370 repro: `with:` that is not a block mapping gets no persist-credentials fix |

Network-backed rules (SC003–SC006, SC008) stay offline in tests, so fixtures
only exercise local analysis.

Fixtures are read at runtime via `std.fs.cwd()` (tests run with
`cwd = repo root`), so adding a `.yml` file here is enough to add a case. The
repository root is also the local-action root for the run, so a `uses: ./x`
that does not exist here resolves as missing, the same as under the CLI.
