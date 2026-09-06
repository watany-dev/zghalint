# Rules Reference

zghalint includes **63 rules** across 9 categories to help you write secure, efficient, and maintainable GitHub Actions workflows.

## Severity Levels

| Level | Description |
|-------|-------------|
| error | Must fix — likely a security vulnerability or broken workflow |
| warning | Should fix — potential issue or bad practice |
| info | Consider fixing — suggestion for improvement |

---

## Security Rules (SEC)

Detect security vulnerabilities in workflow definitions.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SEC001 | unpinned-action | warning | Action references should be pinned to a full SHA |
| SEC002 | script-injection | error | Untrusted GitHub context used in `run:` block or a code-executing action input (`actions/github-script`'s `with.script`) risks script injection |
| SEC003 | hardcoded-secret | error | Hardcoded secrets should use GitHub Secrets |
| SEC004 | excessive-permissions | warning | Avoid write-all permissions, specify only needed scopes |
| SEC005 | dangerous-pr-target | error | `pull_request_target` with checkout of PR head is dangerous |
| SEC006 | untrusted-input-condition | warning | Attacker-authored text used as a gate in an `if:` condition expression |
| SEC007 | missing-permissions | info | Workflow should define top-level permissions |
| SEC008 | github-env-injection | error | Untrusted input written to `GITHUB_ENV`/`GITHUB_PATH` risks environment injection |
| SEC009 | workflow-run-untrusted-checkout | error | `workflow_run` job checks out a ref from the triggering workflow, which may allow arbitrary code execution from forks |
| SEC010 | secrets-inherit | warning | Reusable workflow calls should specify secrets explicitly instead of using `inherit` |
| SEC011 | overprovisioned-secrets | warning | Entire secrets context should not be exposed; reference individual secrets instead |
| SEC012 | unredacted-secrets | error | Secrets processed via `toJSON()`/`fromJSON()` bypass masking and may be exposed in logs |
| SEC013 | hardcoded-container-credentials | error | Container credentials should use GitHub Secrets, not plaintext values |
| SEC014 | bot-conditions | warning | Bot account checks using `github.actor` are spoofable |
| SEC015 | artipacked | warning | Checkout with persisted credentials followed by `upload-artifact` can leak `GITHUB_TOKEN` |
| SEC016 | cache-poisoning | warning | Cache usage in release/deploy workflows risks cache poisoning attacks |
| SEC017 | insecure-commands | warning | `ACTIONS_ALLOW_UNSECURE_COMMANDS` re-enables deprecated insecure workflow commands |
| SEC018 | checkout-persist-credentials | warning | `actions/checkout` persists `GITHUB_TOKEN` in `.git/config` by default |
| SEC019 | secrets-outside-env | info | Secrets should be bound to `env:` variables instead of used directly in `run:`/`with:` |
| SEC020 | self-hosted-runner-fork-triggered | warning | Self-hosted runners used with fork-accessible triggers allow untrusted code execution |
| SEC021 | untrusted-checkout-ref | error | `actions/checkout` resolves its ref/repository from untrusted context on dispatch, issue, comment or discussion triggers |
| SEC022 | workflow-run-branch-gate | error | `workflow_run` job is gated on an attribute of the triggering run that a fork controls |

### SEC002 / SEC008 vs. SEC006

SEC002 and SEC008 report **injection** — an untrusted value reaches a shell —
while SEC006 reports a **weak gate**: an `if:` condition only yields a boolean,
but an attacker who authors the text being tested decides whether the branch is
taken. The two rules therefore keep separate context lists, and SEC006 warns
instead of erroring.

SEC006 does not report ref-shaped inputs (`github.head_ref`,
`github.event.pull_request.head.ref` / `.head.label` /
`.head.repo.default_branch`, `github.event.workflow_run.head_branch`) or label
names, because branching on them — `if: startsWith(github.head_ref, 'release/')`
— is a common routing idiom. They stay untrusted for SEC002 and SEC008.

### SEC021 vs. SEC005 / SEC009

All three report the same shape — `actions/checkout` fed a ref the attacker
picks — split by trigger. SEC005 owns `pull_request_target`, SEC009 owns
`workflow_run`, and SEC021 covers what is left: `workflow_dispatch`,
`repository_dispatch`, `issues`, `issue_comment`, `discussion` and
`discussion_comment`.

A workflow can declare several of those triggers at once, so ownership is
decided per value rather than per workflow: SEC021 stays quiet on exactly the
`with.ref` values SEC005 or SEC009 already reports, and no other. Skipping the
whole workflow would hide a `ref` fed from a comment body just because
`pull_request_target` also appears in `on:`, and would hide `with.repository`
entirely, since neither of the other two rules looks at it.

SEC021 reads the dispatch payloads (`github.event.inputs.*`,
`github.event.client_payload.*`) and the free text of an issue, comment or
discussion. The bare `inputs.*` shorthand counts too, except in a workflow that
also declares `workflow_call`: there it names what a caller passes, and
analysing callers is out of scope.

### SEC022 vs. SEC006

`github.event.workflow_run.head_branch` is one of those ref-shaped inputs, so
SEC006 stays quiet on it — but in a `workflow_run` workflow the same comparison
is not routing. That workflow runs with the base repository's secrets, and a
fork picks its own branch names, so `if: github.event.workflow_run.head_branch
== 'main'` is a gate the attacker walks through. SEC022 covers exactly that
case: `on: workflow_run` only, and only for the attributes the fork authors
(`head_branch`, `head_commit.message` / `.author` / `.committer`,
`display_title`). A condition that also verifies the triggering repository —
`github.event.workflow_run.head_repository.full_name == github.repository`, or
`github.event.workflow_run.event == 'push'` — is sound, and is not reported.
The anchor must be an equality check: `head_repository.full_name !=
github.repository` selects the fork runs rather than excluding them, and
`head_repository.fork == true` is a fork-only gate, so neither counts. Values
that name one immutable commit — `head_sha`, `head_commit.id` — are never
reported. A trust check on the job covers the steps inside it.

## Supply Chain Security Rules (SC)

Detect supply chain risks in action and container image references.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SC001 | unpinned-images | warning | Container images should be pinned to a SHA256 digest for supply chain security |
| SC002 | compromised-action-sha | error | Action references a SHA or tag of a known-compromised release |
| SC003 | known-vulnerable-action | warning | Action has known security advisories (CVE) in GitHub Advisory Database |
| SC004 | archived-uses | warning | Action references an archived (unmaintained) repository |
| SC005 | stale-action-refs | info | SHA-pinned action does not correspond to any known Git tag |
| SC006 | ref-confusion | warning | Action ref matches both a tag and branch, creating exploitable ambiguity |
| SC008 | impostor-commit | warning | SHA-pinned action ref is not reachable from any branch or tag of the upstream repo |

## Performance Rules (PERF)

Detect CI performance issues and resource waste.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PERF001 | cache-not-used | warning | Job uses a language setup action (`actions/setup-node`, `actions/setup-python`, `actions/setup-go`, `oven-sh/setup-bun`, `astral-sh/setup-uv`) without caching enabled |
| PERF002 | redundant-checkout | warning | Multiple `actions/checkout` without `path` in the same job |
| PERF003 | fail-fast-disabled | warning | Strategy has `fail-fast` disabled, wasting CI resources on failures |

## Best Practices Rules (BP)

Enforce workflow best practices for maintainability and reliability.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| BP001 | missing-timeout | warning | Job is missing `timeout-minutes` (default 6 hours is too long) |
| BP002 | missing-step-name | info | Step is missing a `name` field |
| BP003 | deprecated-action-version | warning | Using a known deprecated action version |
| BP004 | cross-platform-shell | warning / error | Invalid or OS-unavailable `shell` name (error), or a run step without `shell` in a Windows-targeting job (warning) |
| BP005 | push-without-concurrency | info | Push trigger without concurrency setting |
| BP007 | obfuscation | warning | Obfuscated or indirect command execution patterns detected in `run:` block |
| BP008 | deprecated-workflow-command | error | Deprecated workflow command (`::set-output`, `::save-state`, `::set-env`, `::add-path`) used in `run:` |

## Permissions Rules (PERM)

Validate the principle of least privilege in workflow permissions.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PERM001 | broad-permissions | warning | Overly broad permission scope detected |
| PERM002 | missing-job-permissions | warning | Job with third-party actions lacks explicit permissions |
| PERM003 | invalid-permissions | error | Unknown permission scope or invalid permission level |

## Expression Validation Rules (EXPR)

Validate `${{ }}` expression syntax, context access, and function calls.

式は静的型検査エンジン（`src/rules/expr_type.zig` / `expr_catalog.zig` /
`expr_check.zig`）で評価される。設計は `docs/adr/0009-expr-static-typecheck.md`
と `docs/design/expr-static-typecheck-design.md` を参照。
`github.event` はイベントごとのスキーマを持たない緩いオブジェクトとして扱われ、
未知のキーは報告しない（ADR D3）。

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| EXPR001 | invalid-syntax | error | Empty expression or syntax error in `${{ }}` |
| EXPR002 | unknown-context | error | Unknown context reference (e.g. `${{ foo.bar }}`) |
| EXPR003 | unknown-property | warning | Unknown context property at any depth (e.g. `${{ github.unknown }}`, `${{ job.container.i }}`) |
| EXPR004 | unknown-function | error | Unknown function name |
| EXPR005 | wrong-argument-count | error | Function called with wrong number of arguments |
| EXPR006 | unsound-contains | warning | `contains()` uses substring matching which may match unintended values |
| EXPR007 | unsound-condition | warning | Bare literal as operand in logical operator is always truthy |
| EXPR009 | fromjson-literal | error | `fromJSON()` string literal argument must be valid JSON |
| EXPR017 | incomparable-types | warning | Comparison between values whose types can never be equal (e.g. `${{ github.event == 1 }}`) |

## Dependency Rules (DEP)

Validate Dependabot configuration files (`dependabot.yml`) and the format of
action / reusable workflow references.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| DEP001 | dependabot-cooldown | info | Dependabot updates should configure a cooldown period to avoid excessive PRs |
| DEP002 | dependabot-execution | warning | `insecure-external-code-execution: allow` is a supply chain attack risk |
| DEP003 | uses-format | error | `uses:` is not a supported action reference (step) or reusable workflow call (job) |

### DEP003 で受理される形式

ステップの `uses:`:

- `{owner}/{repo}@{ref}` / `{owner}/{repo}/{path}@{ref}` — `@ref` は必須
- `./{path}` — ローカルアクション（`@ref` を付けられない）
- `docker://{image}`

ジョブの `uses:`（再利用可能ワークフロー呼び出し）:

- `{owner}/{repo}/.github/workflows/{file}.yml@{ref}`
- `./.github/workflows/{file}.yml` — `@ref` を付けられない

`uses:` の値が `${{ }}` を含む場合は実行時にしか決まらないため報告しない。

## Runner Rules (RUNNER)

Validate GitHub-hosted runner labels in `runs-on:`.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| RUNNER001 | deprecated-runner | error/warning | `runs-on` label is retired (error) or scheduled for retirement (warning) by GitHub |

## Syntax Rules (SYN)

Validate the structural correctness of the workflow definition itself.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SYN001 | unknown-key | error | Mapping contains a key that is not defined in the GitHub Actions workflow schema |
| SYN002 | duplicate-key | error | The same mapping key appears more than once (case-insensitive) |
| SYN003 | empty-section | error | Required workflow sections must not be empty mappings or sequences |
| SYN004 | mapping-value-type | error | Mapping value does not match the expected type for its key (e.g. string where a number or bool is required) |
| SYN005 | duplicate-id | error | Job IDs and step IDs must be unique within a workflow or job (case-insensitive) |
| SYN006 | invalid-id-naming | error | Job ID and step ID must start with a letter or `_` and contain only alphanumeric characters, `-`, or `_` |
| SYN007 | invalid-env-var-name | error | `env:` key is empty or contains `&`, `=`, or a space, which the runner cannot accept as an environment variable name |
| SYN008 | duplicate-needs | warning | The same job ID is listed more than once in `needs` |
| SYN012 | exclusive-event-filters | error | `branches`/`branches-ignore`, `tags`/`tags-ignore` or `paths`/`paths-ignore` specified together for the same event |

### SYN002 duplicate-key

GitHub Actions resolves mapping keys case-insensitively. A second key that
differs only in letter case silently overrides the first definition.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo first
    STEPS:                  # error: key "STEPS" duplicates "steps"
      - run: echo second
```

Keys that are distinct even when lowercased (for example `FOO` and
`foo_bar` under `env:`) are not reported.

Job IDs under the top-level `jobs:` mapping are outside the scope of this
rule: duplicates there are reported by SYN005, which also validates `needs`
references. This avoids two diagnostics at the same position for a single
problem.

### SYN003 empty-section

A section that is present but empty (`{}`, `[]`, or a key with no value) is
reported as an error. GitHub Actions rejects these at runtime.

```yaml
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    strategy: {}            # error: "strategy" section should not be empty
    steps:
      - uses: actions/checkout@v4
        with:               # error: "with" section should not be empty
```

The same check applies to `on`, `jobs`, `steps`, `with`, `env`, `strategy`,
`matrix`, `defaults`, `container`, `services`, `outputs`, `inputs`, and
`secrets`. `permissions: {}` is excluded because an empty permissions block
is the documented way to strip all `GITHUB_TOKEN` scopes.

`secrets: inherit` and a scalar `container:` image are not empty mappings
and are not reported.

### SYN007 invalid-env-var-name

Environment variable names are validated wherever `env:` may appear —
workflow, job, step, `container:`, and `services.<id>:`. A name that is empty
or contains `&`, `=`, or a space cannot be written to the runner's
environment file:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      FOO=BAR: 1          # error: '=' is not allowed
      "A B": 2            # error: spaces are not allowed
      FOO&BAR: 3          # error: '&' is not allowed
      MY_VAR: 4           # ok
```

A key whose name contains a `${{ }}` expression is skipped: the literal text
is substituted before the runner sees it, so it says nothing about the name
that finally reaches the environment file.

### SYN012 exclusive-event-filters

GitHub Actions rejects a workflow that specifies both halves of a filter pair
for the same event. Only one of each pair may appear:

```yaml
on:
  push:
    branches: [main]
    branches-ignore: [wip/**]   # error: cannot use both "branches" and "branches-ignore"
    paths: ['src/**']
    paths-ignore: ['docs/**']   # error: cannot use both "paths" and "paths-ignore"
```

Filters from different pairs may coexist, and each event is checked
independently:

```yaml
on:
  push:
    branches: [main]
    paths-ignore: ['docs/**']   # ok: different pairs
```

To exclude patterns while keeping the positive filter, use a negated pattern
under the positive key (`branches: [main, '!wip/**']`).

---

## Configuring Rules

You can override rule severity or disable rules in `.zghalint.yml`:

```yaml
rules:
  SEC001:
    severity: error        # Upgrade from warning to error
  BP002:
    enabled: false         # Disable a rule
  SEC007:
    severity: warning      # Upgrade from info to warning
```

See the [README](../README.md#configuration) for full configuration options.
