# Rules Reference

zghalint includes **77 rules** across 9 categories to help you write secure, efficient, and maintainable GitHub Actions workflows.

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

All three read both `with.ref` and `with.repository`: pointing `repository` at
the PR head repository checks out the fork's code without `ref` being touched
at all (#218). A step whose `ref` and `repository` are fed from the same
payload is one mistake, so it is reported once.

A workflow can declare several of those triggers at once, so ownership is
decided per value rather than per workflow: SEC021 stays quiet on exactly the
values SEC005 or SEC009 already reports, and no other. Skipping the whole
workflow would hide a `ref` fed from a comment body just because
`pull_request_target` also appears in `on:`.

SEC021 reads the dispatch payloads (`github.event.inputs.*`,
`github.event.client_payload.*`) and the free text of an issue, comment or
discussion. The bare `inputs.*` shorthand counts too, unless every way into the
workflow fills it from a caller — a `workflow_call` workflow with no
`workflow_dispatch`, or one whose `workflow_dispatch` declares no inputs of its
own. Analysing callers is out of scope. A `workflow_call` declared beside a
`workflow_dispatch` that has inputs keeps the shorthand untrusted: the same
`inputs.ref` is still what a dispatching user types, so three lines of
`workflow_call:` must not silence the rule (#219).

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
The condition is parsed, and the anchor only counts where it is
guaranteed to have held: joined with `||` it leaves the branch gate reachable
on its own, so it anchors nothing. Negation is read through — `!(fork == true
|| head_branch == 'main')` excludes exactly the fork runs and is sound, while
`!(head_repository.full_name == github.repository)` asserts the opposite of the
check it is written as. Read with that polarity, the anchor must assert
identity: `head_repository.full_name != github.repository` selects the fork
runs rather than excluding them, and `head_repository.fork == true` is a
fork-only gate (`fork == false`, `fork != true` and `!fork` are the sound
spellings). The anchor is matched segment for segment, so only the fields that
name the repository count — `head_repository.name` is not one of them, because
a fork inherits the name of the repository it came from, and neither is
`head_repository.owner.type`, which is `User` for every fork. A condition that
does not parse anchors nothing. Values that name one immutable commit — `head_sha`,
`head_commit.id` — are never reported. A trust check on the job covers the
steps inside it.

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
| EXPR001 | invalid-syntax | error | Empty expression, syntax error, or nesting deeper than 256 levels in `${{ }}` |
| EXPR002 | unknown-context | error | Unknown context reference (e.g. `${{ foo.bar }}`) |
| EXPR003 | unknown-property | warning | Unknown context property at any depth (e.g. `${{ github.unknown }}`, `${{ job.container.i }}`) |
| EXPR004 | unknown-function | error | Unknown function name |
| EXPR005 | wrong-argument-count | error | Function called with wrong number of arguments |
| EXPR006 | unsound-contains | warning | `contains()` uses substring matching which may match unintended values |
| EXPR007 | unsound-condition | warning | Bare literal in logical operator, constant `if:` condition, or text mixed with `${{ }}` |
| EXPR008 | format-placeholders | error/warning | `format()` placeholder indices must match provided arguments |
| EXPR009 | fromjson-literal | error | `fromJSON()` string literal argument must be valid JSON |
| EXPR010 | undefined-step-reference | error | `steps.<id>` must name a step defined earlier in the same job, and only `outputs` / `conclusion` / `outcome` exist below it |
| EXPR011 | matrix-context | error | `matrix.<key>` must name a key declared in the job's `strategy.matrix` (including keys added by `include:`), and a job without `strategy.matrix` has no `matrix` context |
| EXPR012 | needs-context | error | `needs.<job>` references a job outside this job's `needs:`, an unknown property, or an output the referenced job does not declare |
| EXPR013 | inputs-context | error | `inputs.<name>` must name an input declared by `workflow_dispatch.inputs` or `workflow_call.inputs`, and a workflow with neither trigger has no `inputs` context |
| EXPR014 | secrets-context | error | `secrets.<name>` must name a secret declared under `on.workflow_call.secrets` (only checked when that section exists; `GITHUB_TOKEN` is always valid) |
| EXPR017 | incomparable-types | warning | Comparison between values whose types can never be equal (e.g. `${{ github.event == 1 }}`, `${{ github.event.issue == 'bug' }}`) |
| EXPR018 | argument-type | warning | An object or array passed where a builtin function takes a string (e.g. `${{ startsWith(github.event, 'a') }}`), or interpolated into a string where it renders as `Object` / `Array` / nothing |

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
| RUNNER002 | unknown-runner | error | `runs-on` label is not a known GitHub-hosted runner (typos leave the job queued forever) |
| RUNNER003 | runner-label-conflict | error | `runs-on` の複数ラベルが異なる OS を指しており、条件を満たすランナーが存在しない |

RUNNER002 は「GitHub ホストランナーのつもりで書かれた未知のラベル」だけを報告する。
セルフホストのフリートは列挙しようがないため、以下は報告しない:

- 既知ラベルに接尾辞が付いたもの（`ubuntu-latest-4-cores` などの larger runner）
- `self-hosted` / `linux` / `x64` などの慣用ラベル
- 既知ラベルから遠く、`ubuntu-` / `windows-` / `macos-` でも始まらない独自ラベル（`gpu-box` など）
- 展開できない式（`fromJSON`、他コンテキスト参照、文字列連結）を含む `runs-on`

既知ラベルと編集距離 2 以内で候補が一意に定まる場合のみ `did you mean ...?` を
提示し、`--fix-unsafe` で置換する。独自ラベルは `.zghalint.yml` の
`runner.labels` に列挙すれば既知として扱われる。

`runs-on: ${{ matrix.os }}` のように値が `${{ matrix.<key> }}` 単体の式である
場合は、`strategy.matrix.<key>`（`include` 由来の値を含む）を展開して各値を
判定する。診断と autofix は matrix の値側を指す。`exclude` の値は組み合わせを
除外するだけなのでランナーを名乗らず、報告の対象外とする（`--fix-unsafe` は
軸の値を直す際に、同じラベルを名指しする `exclude` の値も併せて書き換える）。

RUNNER001 / RUNNER002 は `runs-on: [self-hosted, linux, x64]` のような配列指定と
ランナーグループ（`runs-on: {group:, labels:}`）にも対応し、ラベルごとに検査する。
ただし `self-hosted` を含む集合では、残りのラベルはフリート運用者が付けた名前と
みなして RUNNER002 を報告しない。

RUNNER003 は同一ランナーが同時に満たせないラベルの併記を報告する。ジョブは
すべてのラベルを備えた 1 台のランナーで実行されるため、`ubuntu-latest` と
`windows-latest` のように OS が異なるラベルを並べると永久に queued のままになる。
OS の判定に使うのは既知ラベルだけで、`self-hosted` / `x64` や自前フリートの独自
ラベル（Linux マシンに付けた `macos-m1` など）は判定に使わない。`${{ }}` を含む
ラベルがあるジョブは matrix 展開が必要なため報告しない。

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
| SYN009 | unknown-event | error | `on:` names an event GitHub Actions does not support, so the workflow never triggers |
| SYN010 | invalid-activity-type | error | `types:` names an activity type the event does not define, so the workflow never triggers |
| SYN011 | unavailable-event-filter | error | Event filter is not available for the event it is written under, or is not a filter name at all |
| SYN012 | exclusive-event-filters | error | `branches`/`branches-ignore`, `tags`/`tags-ignore` or `paths`/`paths-ignore` specified together for the same event |
| SYN013 | invalid-filter-glob | error | Event filter value (`branches`, `tags`, `paths`, or their `-ignore` forms) uses invalid GitHub Actions glob syntax |
| SYN014 | invalid-cron | error | `schedule` cron expression is not valid POSIX 5-field cron syntax |
| SYN015 | cron-too-frequent | error | scheduled workflow runs more often than GitHub Actions allows (once every 5 minutes) |
| SYN016 | invalid-timezone | error | `schedule` `timezone` is not a name in the IANA time zone database |
| SYN017 | workflow-dispatch-inputs | error | `workflow_dispatch` input declares an invalid `type`, misuses `options`, or has a `default` that does not fit |
| SYN018 | duplicate-matrix-value | warning | The same value appears more than once in a `strategy.matrix` axis |
| SYN019 | matrix-include-exclude | warning | `strategy.matrix` `include` / `exclude` names a key or value the matrix never produces |

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

### SYN009 unknown-event

An event name GitHub does not know is not rejected at parse time: the workflow
is accepted and then never runs. A typo therefore looks exactly like a workflow
nobody triggered, so every `on:` key is checked against the list of supported
triggers.

```yaml
on:
  pull_reqeust:        # error: unknown Webhook event "pull_reqeust". did you mean "pull_request"?
    types: [opened]
  push_tag:            # error: unknown Webhook event "push_tag"
```

The check covers all three `on:` forms (`on: push`, `on: [push, fork]`, and the
mapping form) and is case-sensitive, since GitHub matches trigger names exactly.
Valid triggers, webhook or not, pass:

```yaml
on:
  push:
  discussion_comment:
    types: [created]
  merge_group:
  workflow_dispatch:
```

A name containing a `${{ }}` expression is skipped, since the literal text says
nothing about the name GitHub finally sees.

### SYN010 invalid-activity-type

`types:` narrows an event to a list of activity types. A name that is not one of
them silently drops the event: nothing rejects the workflow, it simply stops
firing for the activity the author meant.

```yaml
on:
  issues:
    types: [open, closed]    # error: invalid activity type "open" for "issues" event. did you mean "opened"?
  pull_request:
    types: [synchronised]    # error: invalid activity type "synchronised" for "pull_request" event. did you mean "synchronize"?
  push:
    types: [opened]          # error: "types" is not available for "push" event
```

The `push` case is the same bug from the other side: an event with no activity
types at all ignores `types:` entirely, so the filter the author wrote never
applies.

Two events are exempt from the value check. `repository_dispatch` types are
chosen by whoever POSTs the dispatch, and `image_version` has no documented
closed set, so `types:` is accepted there without judging the names. A value
containing a `${{ }}` expression is skipped for the same reason as in SYN009.

```yaml
on:
  issues:
    types: [opened, reopened]
  pull_request:
    types: [opened, synchronize, ready_for_review]
  repository_dispatch:
    types: [deploy-please]
```

### SYN011 unavailable-event-filter

`branches`, `tags`, `paths` and their `-ignore` forms only exist for some
events. Written under an event that does not read them they are not an error to
GitHub — the workflow just runs on *every* occurrence of the event, which is the
opposite of the intent.

```yaml
on:
  issues:
    branches: [main]     # error: "branches" filter is not available for "issues" event
  pull_request:
    tags: [v*]           # error: "tags" filter is not available for "pull_request" event
  push:
    brancehs: [main]     # error: unknown filter "brancehs" for "push" event. did you mean "branches"?
```

The available sets follow GitHub: `push` takes all six; `pull_request` and
`pull_request_target` run on a branch so they take the four branch and path
filters but not `tags`/`tags-ignore`; `workflow_run` takes only `branches` and
`branches-ignore`; every other event takes none.

The same check covers the non-filter keys an event accepts, so a misspelled
`inputs` under `workflow_dispatch` is reported too. An event name SYN009 already
flagged is left alone rather than reported twice.

```yaml
on:
  push:
    branches: [main]
    paths: ['src/**']
  pull_request:
    branches-ignore: [wip/**]
  workflow_run:
    workflows: [CI]
    types: [completed]
    branches: [main]
```

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

### SYN013 invalid-filter-glob

Filter values under `branches`, `tags`, `paths`, and their `-ignore` forms must
use GitHub Actions glob syntax. Invalid patterns are rejected at workflow
parse time on GitHub.

```yaml
on:
  push:
    branches:
      - 'v[1.*'          # error: unclosed [
    paths:
      - '+foo'           # error: + must follow a literal character
      - './src/**'       # error: paths cannot start with ./
```

Valid examples:

```yaml
on:
  push:
    branches: [main, releases/**, v[0-9].*]
    paths: [src/**/*.zig, '!src/vendor/**']
```

### SYN018 duplicate-matrix-value

A value repeated in a `strategy.matrix` axis adds no combination the earlier one
does not already cover, so a mistyped axis looks exactly like the matrix the
author intended.

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, ubuntu-latest, macos-latest]   # warning: duplicate value "ubuntu-latest"
    node: [18, 20, 18]                                 # warning: duplicate value "18"
```

`include` and `exclude` are checked the same way. Their entries are mappings, so
they are compared structurally: quoting style and key order do not hide a
duplicate.

```yaml
strategy:
  matrix:
    include:
      - os: ubuntu-latest
        node: 18
      - node: 18            # warning: duplicate entry in matrix "include"
        os: ubuntu-latest
```

A matrix built from an expression (`matrix: ${{ fromJSON(...) }}`) has no
literal values to compare and is skipped.

---

### SYN016 invalid-timezone

`on.schedule[*].timezone` is resolved against the IANA time zone database.
An abbreviation or a misspelled name is not silently ignored — the schedule
never fires. Names are case-sensitive.

```yaml
on:
  schedule:
    - cron: '0 0 * * *'
      timezone: 'Asia/Tokio'   # error: did you mean "Asia/Tokyo"?
    - cron: '0 9 * * *'
      timezone: 'JST'          # error: not an IANA time zone name
```

Valid examples:

```yaml
on:
  schedule:
    - cron: '0 0 * * *'
      timezone: 'Asia/Tokyo'
    - cron: '0 0 * * *'
      timezone: 'UTC'
```

A `timezone` built from a `${{ }}` expression is not checked.

---

### SYN017 workflow-dispatch-inputs

`workflow_dispatch` inputs have a small type system that GitHub enforces when
the run form is rendered:

- `type:` must be `string`, `boolean`, `number`, `choice`, or `environment`
- `type: choice` requires a non-empty `options:` list, and `options:` is
  meaningless for any other type
- `default:` must be one of the `options:` for a choice, a bool for `boolean`,
  and a number for `number`

```yaml
on:
  workflow_dispatch:
    inputs:
      env:
        type: choice
        default: staging       # error: not included in "options"
        options: [dev, prod]
      verbose:
        type: boolean
        default: "yes"         # error: not a valid "boolean" value
      level:
        type: enum             # error: invalid input type
      target:
        type: choice           # error: "options" is required
```

Valid examples:

```yaml
on:
  workflow_dispatch:
    inputs:
      env:
        type: choice
        default: dev
        options: [dev, staging, prod]
      verbose:
        type: boolean
        default: false
```

An input with no `type:` defaults to `string` and is not reported. Reusable
workflow inputs use a different type system and are checked by RW001.

---

### SYN019 matrix-include-exclude

`exclude` removes combinations the matrix already produces. An entry naming an
axis the matrix does not declare, or a value the axis never takes, removes
nothing — the combination the author meant to drop still runs.

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, macos-latest]
    node: [18, 20]
    exclude:
      - os: windows-latest   # warning: "windows-latest" does not exist in "os" axis
        node: 18
      - oss: ubuntu-latest   # warning: unknown key "oss" in "exclude". did you mean "os"?
        node: 20
```

`include` is allowed to add keys the matrix does not declare, so a new key is
left alone. Only a key one edit away from an existing axis is reported, and not
even then when some entry sets both the key and that axis — a key used beside
the axis it resembles is a deliberate addition, not a typo.

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, macos-latest]
    node: [18, 20]
    exclude:
      - os: macos-latest     # valid: the matrix produces this combination
        node: 18
    include:
      - os: ubuntu-latest
        node: 20
        experimental: true   # valid: 'include' may add a new key
      - os: macos-latest
        nodes: 22            # warning: unknown key "nodes" in "include". did you mean "node"?
```

`exclude` is matched against the axes only. GitHub applies `exclude` to the base
matrix and merges `include` afterwards, so a combination that only `include`
contributes is never removed and naming it in `exclude` is reported as well. An
axis built from an expression (`os: ${{ fromJSON(...) }}`) carries no values to
compare against, so the value check is skipped for it. Plain `1.10` and `1.1`,
or `True` and `true`, are the same YAML value and do not count as a mismatch;
quoted scalars are strings, so `"3.10"` and `"3.1"` stay distinct.

## Action Metadata Rules (ACT)

Validate action metadata files (`action.yml` / `action.yaml`) — the manifest of
a composite, JavaScript, or Docker action. これらはワークフローではないため、
ワークフロー用のルールは一切適用されず、ACT ルールだけが走る。

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| ACT001 | action-missing-required-key | error | `name` / `runs`、および `runs.using` が要求するキー（node は `main`、docker は `image`、composite は `steps`）が無い |
| ACT002 | action-invalid-runs-using | error/warning | `runs.using` が未対応のランタイム（error）、または GitHub が廃止予定のランタイム（warning） |
| ACT003 | action-unknown-key | error | メタデータ・`runs`・各 input / output 定義に、仕様にないキーがある |
| ACT004 | action-invalid-definition | error | 値の形が仕様と違う（ドキュメントや `runs` がマッピングでない、`required` が真偽値でない、composite 以外の `value` など） |

### 検査対象になるファイル

引数を省略した場合、既定で以下を読む:

- リポジトリ直下の `action.yml` / `action.yaml`
- `.github/actions/<name>/action.yml` / `action.yaml`

GitHub 自身が案内しているのはこの 2 つの配置なので既定はここまでとし、それ以外の
場所に置いたメタデータはパスを直接渡す。判定はファイル名そのもので行うため、
`my-action.yml` はワークフロー扱いのままになる。逆に `.github/workflows/` 配下の
ファイルは名前が `action.yml` でもワークフローなので、ACT ルールは適用しない。

### ACT002 が受理する `using`

`node20` / `node24` / `docker` / `composite` の 4 つ。`node12` / `node16` は
GitHub が実行を停止するランタイムなので warning として報告し、それ以外の未知の値は
error として報告する（編集距離 2 以内で候補が一意に定まるときは
`did you mean ...?` を添える）。

### 個々の定義に対する検査

- `inputs.<name>` に置けるのは `description` / `required` / `default` /
  `deprecationMessage`、`outputs.<name>` に置けるのは `description` /
  `value`。未知のキーは ACT003、値の型が違うものは ACT004。
- `main:` のように値を書かずにキーだけ置いた場合、ランナーには値が届かないので
  ACT001（キーが無い）として扱う。
- `required:` は YAML 1.2 core schema の真偽値（`true` / `True` / `TRUE` と
  その否定形）だけを受理する。`yes` / `on` は文字列なので ACT004 として報告する。
- `value:` は composite action だけが持つ。JavaScript / Docker action は実行時に
  出力を書き出すため、`value:` があれば ACT004 として報告する。`using` の値が
  解決できない場合は出力側の判定を行わない。
- composite の `runs.steps` はシーケンスであることだけを確認する。既存の step
  ルールや式検証を steps に適用するのは #254。

---

---

## Reusable Workflow Rules (RW)

Validate the `on.workflow_call` interface a reusable workflow exposes to its
callers, and the calls made against it.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| RW001 | workflow-call-inputs | error | `workflow_call` input is missing `type`, declares a type outside `string`/`number`/`boolean`, has a `default` that does not match its type, or is both `required` and defaulted |
| RW002 | workflow-call-required-inputs | error | A job calling a local reusable workflow does not pass one of its `required` inputs |
| RW003 | workflow-call-input-values | error | A job calling a local reusable workflow passes an input it does not declare, or a value that does not match the declared type |
| RW004 | workflow-call-secrets | error | A job calling a local reusable workflow omits one of its `required` secrets, or passes a secret it does not declare |

### RW001 workflow-call-inputs

`workflow_call` inputs use a different type system from `workflow_dispatch`
inputs (which are checked by [SYN017](#syn017-workflow-dispatch-inputs)):
`type` is **required**, and `choice` / `environment` are not available.

```yaml
on:
  workflow_call:
    inputs:
      environment:        # missing `type`
        required: true
      mode:
        type: choice      # not a workflow_call type
        options: [a, b]
      retries:
        type: number
        default: three    # default is not a number
      target:
        type: string
        required: true
        default: main     # required and defaulted at the same time
```

A caller that omits a `required` input fails at dispatch time, and a `default`
on a required input is never applied — so declaring both is always a mistake in
one direction or the other. Fix by giving every input an explicit `type` of
`string`, `number` or `boolean`, matching the `default` to it, and dropping
either `required: true` or `default`.

### RW002 workflow-call-required-inputs

A job that calls a reusable workflow must pass every input the called workflow
declares `required: true`. A missing one fails the run at dispatch time, before
any step executes.

```yaml
# .github/workflows/reusable.yml
on:
  workflow_call:
    inputs:
      version:
        type: string
        required: true
```

```yaml
# .github/workflows/ci.yml
jobs:
  build:
    uses: ./.github/workflows/reusable.yml   # `version` is never passed
```

Fix by adding the input under the job's `with:`.

Only a **local** call (`./path/to/workflow.yml`) is checked: a call into another
repository names a file zghalint cannot read, so it is left alone. The called
file is read one level deep and never followed further, so workflows that call
each other cannot loop. An input that is both `required` and defaulted is
reported on the definition side by [RW001](#rw001-workflow-call-inputs) and is
not demanded of the caller.

### RW003 workflow-call-input-values

The `with:` of a reusable workflow call may only name inputs the called
workflow declares, and each value must fit the input's declared `type`.

```yaml
# .github/workflows/reusable.yml
on:
  workflow_call:
    inputs:
      version:
        type: string
      retries:
        type: number
```

```yaml
# .github/workflows/ci.yml
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    with:
      verison: '1.0'    # unknown input — did you mean `version`?
      retries: three    # not a number
```

Quoting is not consulted: `retries: '3'` is accepted, the way the runner
coerces the value. A value built by an expression (`${{ … }}`) is only known at
run time and is never type-checked, and an input whose `type:` is missing or
invalid is reported on the definition side by
[RW001](#rw001-workflow-call-inputs) instead.

Like [RW002](#rw002-workflow-call-required-inputs), only a **local** call is
checked.

### RW004 workflow-call-secrets

The `secrets:` of a reusable workflow call is checked against the secrets the
called workflow declares, in both directions: every `required: true` secret must
be passed, and no name may be passed that is not declared.

```yaml
# .github/workflows/reusable.yml
on:
  workflow_call:
    secrets:
      npm_token:
        required: true
      slack_webhook:
        required: false
```

```yaml
# .github/workflows/ci.yml
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    secrets:
      slack_webhook: ${{ secrets.SLACK }}
      aws_key: ${{ secrets.AWS }}   # not declared by the called workflow
      # required secret `npm_token` is never passed
```

`secrets: inherit` hands the caller's whole secret set over, so a job that uses
it is not checked at all. Neither is a call whose target declares no
`workflow_call.secrets`: without a declaration there is no closed set to check
against. Like [RW002](#rw002-workflow-call-required-inputs), only a **local**
call is checked.

This is the caller-side counterpart of EXPR014, which checks `secrets.<name>`
uses inside the called workflow against the same declaration.

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
