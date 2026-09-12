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

### Fixed

- SEC002 no longer treats a whole boolean-returning builtin call such as
  `startsWith(...)`, `endsWith(...)`, or `contains(...)` as script injection.
  String-valued expressions in the same script remain diagnosed and fixed
  independently (#419).

### Added

- EXPR002 / EXPR003 / EXPR004 offer safe rename fixes for a unique nearby
  context, strict-object property, or function name from the expression
  catalog, when the source token can be located (#410).
- SEC014 offers an unsafe fix for a whole `if:` condition comparing
  `github.actor` or `github.triggering_actor` to a bot name with `==` / `!=`.
  It preserves YAML quotes and expression wrappers, replacing the comparison
  with `github.event.sender.type` and the generic `Bot` type (#413).
- SYN012 offers an unsafe fix that removes the later conflicting branch, tag,
  or path filter while keeping the earlier one (#412). Guarded flow-mapping
  deletion spans are shared with SYN011; uncertain or anchored ranges are skipped.
- ACT001 safely inserts `shell: bash` for composite `run:` steps with a missing
  shell when the insertion position is known (#411).

- SYN023 reports an unknown `cache-mode` at workflow or job level. The
  documented values are `none` / `read` / `write` / `write-only` (#428).
- `background` / `wait` / `wait-all` / `cancel` / `parallel` are accepted
  step keys. Nested `parallel:` steps are walked by existing SEC / SC / BP /
  EXPR rules. SYN024 reports `wait` / `cancel` targeting a missing step id
  (#432).
- EXPR019 warns when `steps.<id>.outputs` reads a background step that has
  not been waited on yet. A missing `wait` with no output reference is not
  reported. No autofix (#433).
- SEC016 and PERF001 share a `cache-mode` capability model (`can_restore` /
  `can_save`). `cache-mode: none` silences PERF001 and SEC016. `cache-mode:
  read` does not silence SEC016 (#434).
- SEC024 warns when `cache-mode: write` or `write-only` is declared on a
  low-trust trigger (`pull_request_target`, `issue_comment`, `workflow_run`),
  which overrides GitHub's restore-only default. No autofix (#434).

### Changed

- `cache-mode` is a known workflow and job key, so it no longer fires SYN001
  (#428).
- `permissions.vulnerability-alerts` is a known scope. `read` and `none` are
  accepted; `write` is PERM003 (#428).
- `job.workflow_ref` / `job.workflow_sha` / `job.workflow_repository` /
  `job.workflow_file_path` are known job-context properties and no longer
  fire EXPR003. They are not the same as `github.workflow_ref` /
  `github.workflow_sha` (#428).
- EXPR005 rejects `case()` calls with an even number of arguments. `case()` is
  pairs of `(condition, result)` plus a fallback, so the count must be odd and
  at least 3 (#429).
- RUNNER001 treats `macos-13` as retired (removed 2025-12-04). `macos-11` /
  `macos-12` / `macos-13` now rewrite to `macos-15`, a current catalog entry
  (#430). Deprecated and retired replacements are checked at compile time so
  they cannot point at another retired label.
- CI and bench now pin actionlint 1.7.12 and zizmor 1.30.1, the versions used
  as the comparison baseline (#431).

## [0.0.1] - 2026-09-10

First public release. Preceded by prereleases `v0.0.1-rc.1` and `v0.0.1-rc.2`.
The CLI contract (flag names, exit codes, output shapes) is not yet stable, and
rule IDs may still be renumbered before 1.0.

### Changed

- SEC022 now flags `github.event.workflow_run.head_repository.description` as
  an attacker-authored `if:` gate, the same class as `display_title` (#307,
  leftover from #313). Identity fields of `head_repository` (`full_name`,
  `id`, `owner`) remain the recommended fix and are not reported.
- When SEC015 (artipacked) fires on a checkout, SEC018 on the same step is
  suppressed so the more specific artifact-leakage message is the one shown
  (#335). Disabling SEC015 restores SEC018. The identical-insertion guard in
  the fix engine (#300) remains as a backstop.
- BP002 no longer reports `uses:`-only steps. The action name is already the
  GitHub Actions UI label, so requiring `name:` there drowned out higher
  severity findings (#337). Unnamed `run:` steps are unchanged.
- EXPR006 no longer warns when `contains()` tests array membership (object
  filters such as `labels.*.name`, `fromJSON` arrays, typed arrays). Those are
  exact element checks, not substring matching (#333).
- PERM002 no longer warns when the workflow already declares `permissions:`
  with no write scope. `write-all` or any `: write` at workflow level still
  asks each job to narrow the grant (#334).
- SEC003 now anchors its diagnostic at the earliest secret-looking token in a
  string. Previously a string holding two patterns reported the one that came
  first in the internal prefix list; the number of findings is unchanged.
- SEC013 no longer treats a `${{ }}` expression as a hardcoded container
  credential. `username: ${{ github.actor }}` with
  `password: ${{ secrets.GITHUB_TOKEN }}` is the documented GHCR login.
- BP007 no longer treats `$NAME = ...` at the start of a line as a command.
  That is PowerShell assignment (`$PACK_OUTPUT = npm pack`); `$CMD == ...`
  is still a command.
- SC* GitHub API lookups now fail fast after a transport failure (connection
  refused, network unreachable) and bound each remaining request to the
  leftover deadline, instead of hanging until the overall timeout (#402).
  Once the network is unreachable, the REST fallback is skipped.

### Fixed

- EXPR001 accepts numeric context indices and mixed dot/bracket paths such as
  `github.event.workflow_run.pull_requests[0].number` (#424).
- DEP003 accepts scoped local action paths such as `./tools/@scope/tool` and
  `$/tools/@scope/tool`, while still rejecting `tool@v1` ref suffixes (#425).

- A `steps:` holding a mapping instead of a sequence no longer aborts the
  workflow parse and silences every diagnostic in the file. It now reports
  SYN004 and parsing continues, the same treatment `services:` and
  `credentials:` already had. A file that was previously silent can now report.
- Insertion auto-fixes (SEC007, BP005, SEC015, PERF001) no longer place a line
  at a column the surrounding mapping does not use. `Workflow.top_level_indent`
  was declared but never assigned, so a workflow whose root mapping is indented
  had `permissions:` inserted at column 0, ending the mapping and dropping
  `jobs:` out of the document. `with:` additions took their column from `uses:`
  rather than from the existing children, so a repeated `--fix-unsafe` appended
  `persist-credentials: false` once per run.
- Insertion auto-fixes emit no fix at all, rather than a broken rewrite, when
  the anchor would land inside a quoted or block scalar, on a line the parser
  dropped, or in a mapping that starts on its key's own line (`on: push:`).
  The diagnostics themselves are unchanged.
- An empty `permissions:` or `concurrency:` no longer aborts the workflow parse
  and silences every diagnostic in the file. Both sections now report SYN003
  and parsing continues, so a `--fix` rename that produces one of them (for
  example `ermissons:` to `permissions:`) keeps the file lintable (#364).
  `permissions: {}` stays the meaningful deny-all form and is not reported.
- A workflow whose `on:` block repeats an event no longer writes past the taint
  table's fixed buffer. YAML duplicate keys parse, so three
  `workflow_dispatch:` keys appended the same contexts three times: a panic in
  Debug and an out-of-bounds store, up to SIGSEGV, in ReleaseFast (#366). The
  table now holds each context once. SYN002 still reports the duplicate keys.
- SYN009 no longer applies `--fix` when the suggestion is `pull_request_target`
  or `workflow_run`. Those triggers run with the default branch's secrets, so
  turning a name that never fired into one of them requires `--fix-unsafe`
  (#346).
- SYN001 no longer attaches a rename when the suggested key already exists as a
  sibling (case-insensitive). That rewrite used to produce SYN002 (#347).
- `--fix-unsafe` no longer inserts a mapping key that a rename in the same
  mapping already produces, so SYN001 rewriting `prmissions:` and SEC007
  inserting `permissions:` cannot leave a duplicate (#348).
- HTTP client now honors `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` and
  `SSL_CERT_FILE`, so SC003 / SC004 / SC005 / SC008 no longer skip on every
  run behind a required proxy (#336).
- SEC021 no longer treats `github.event.issue.number` as a ChatOps checkout
  taint under `on: issues`. That event does not fire on pull requests; the
  `refs/pull/<n>/merge` pattern is `issue_comment` only (#308).

### Added

- SYN021 (`undefined-needs-job`, error) and SYN022 (`needs-cycle`, error):
  validate the job dependency graph (#281). SYN021 reports a `needs:` entry
  naming no job in the workflow, with a `--fix` rename when a single job ID
  sits within edit distance 2; SYN022 reports a cycle in that graph, a job
  needing itself included. Both configurations fail the run before any step
  executes, and neither needs network access.
- `install.sh`: a `curl -fsSL .../install.sh | sh` installer. It resolves the
  platform, downloads the matching release archive, verifies it against the
  release's `SHA256SUMS`, and places the binary in `<prefix>/bin` (`/usr/local`
  when writable, otherwise `$HOME/.local`). `--version`, `--prefix` and
  `ZGHALINT_BASE_URL` are supported; Linux and macOS only. The release workflow
  installs the published artifacts through it as part of the smoke job.
- Homebrew tap: releases now update `Formula/zghalint.rb` in
  `watany-dev/homebrew-tap`, so `brew install watany-dev/tap/zghalint` works.
  The formula is generated from the release's published `SHA256SUMS`;
  prereleases (`-rc.`) are not published to the tap.
- SYN020 (`empty-workflow`, error): report a workflow file with no content at
  all — comments and whitespace only, or an empty mapping (#284). Such a file
  was previously rejected as unlintable (exit code 2); it is now an ordinary
  diagnostic (exit code 1), so a workflow that was emptied out but never
  deleted is visible in the report.
- SEC023 (`use-trusted-publishing`, info): report a publish step that passes a
  long-lived API token where the registry supports OIDC trusted publishing —
  `pypa/gh-action-pypi-publish` with `password:`, `rubygems/release-gem` with
  `setup-trusted-publisher: false`, and an `npm publish` whose step `env:` binds
  `NODE_AUTH_TOKEN` to a secret (#286). No autofix: removing the token also
  needs a publisher configured on the registry side.
- SC007 (`typosquat-action`): warn when an `actions/*` reference is 1–2 edits
  away from a well-known official action such as `actions/checkout`.
- Auto-fixes for rules that previously only carried a hint: BP008 under
  `--fix`, and ACT001 / RW001 / SEC002 / SEC008 / SEC019 under `--fix-unsafe`.
  The `SEC*` ones bind the offending `${{ ... }}` to the step's `env:` and read
  it back as a shell variable (#322).
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
