# Rules Reference

zghalint includes **91 rules** across 11 categories to help you write secure, efficient, and maintainable GitHub Actions workflows.

## Severity Levels

| Level | Description |
|-------|-------------|
| error | Must fix — likely a security vulnerability or broken workflow |
| warning | Should fix — potential issue or bad practice |
| info | Consider fixing — suggestion for improvement |

## did you mean ...? と `--fix`

キー名・イベント名・識別子のタイプミスを検出するルールは、既知の名前と編集距離
2 以内で候補が一意に定まるときに `did you mean "..."?` を添える。この候補は
そのまま safe な autofix でもあり、`--fix` はタイプミスした綴りだけを置き換える
（引用符は保持する）。候補が定まらない場合は診断のみで、autofix は付かない。

対象は SYN001 / SYN009 / SYN010 / SYN016 / SYN019、EXPR010–EXPR014、
PERM003、ACT002 / ACT003 / ACT005、DEP004 / DEP005、RW003 / RW004。

---

## Security Rules (SEC)

Detect security vulnerabilities in workflow definitions.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SEC001 | unpinned-action | warning | Action references should be pinned to a full SHA |
| SEC002 | script-injection | error | Untrusted GitHub context used in `run:` block or a code-executing action input (`actions/github-script`'s `with.script`) risks script injection（`--fix-unsafe` で式を step の `env:` に束縛してシェル変数として読む） |
| SEC003 | hardcoded-secret | error | Hardcoded secrets should use GitHub Secrets |
| SEC004 | excessive-permissions | warning | Avoid write-all permissions, specify only needed scopes |
| SEC005 | dangerous-pr-target | error | `pull_request_target` with checkout of PR head is dangerous |
| SEC006 | untrusted-input-condition | warning | Attacker-authored text used as a gate in an `if:` condition expression |
| SEC007 | missing-permissions | info | Workflow should define top-level permissions |
| SEC008 | github-env-injection | error | Untrusted input written to `GITHUB_ENV`/`GITHUB_PATH` risks environment injection（`--fix-unsafe` で式を step の `env:` に束縛してシェル変数として読む） |
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
| SEC019 | secrets-outside-env | info | Secrets should be bound to `env:` variables instead of used directly in `run:`/`with:`（`--fix-unsafe` で `run:` 中の参照を step の `env:` に束縛する） |
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

### SEC002 taint sources

Besides the fixed `github.event.*` table, two taint sources cannot be decided
from a step alone and need the whole workflow. SEC008 is workflow-scoped for the
same reason and reads the same table, so a value that is injection in a `run:`
block is injection when it is written to `$GITHUB_ENV` too.

- The dispatch payloads — `inputs.*` / `github.event.inputs.*` under
  `workflow_dispatch` or `workflow_call`, and `github.event.client_payload.*`
  under `repository_dispatch`. The values are typed by the dispatching actor,
  passed by the caller, or forwarded verbatim by whatever posted the dispatch,
  and none of them can be validated on the callee side. Each root is untrusted
  only under the trigger that fills it (#224), and the pairing is the same table
  SEC021 reads, so the two rules cannot disagree about what a caller controls.
- `steps.<id>.outputs.*` — untrusted when step `<id>` wrote an untrusted value
  to `$GITHUB_OUTPUT`. Binding the value to `env:` is what makes the *capturing*
  step safe; it does nothing for whoever expands the output, so only the later
  step that expands it is reported.

Taint then travels one hop further, through the two indirections that otherwise
look like the recommended fix:

- `env.<KEY>` — an `env:` entry bound to an untrusted value taints the
  expression spelling of that key for the scope that declares it (workflow, job
  or step). `$KEY` stays quiet: the shell reads the value out of the
  environment, while `${{ env.KEY }}` is spliced into the script before the
  shell ever starts, which is the injection the `env:` binding was meant to
  remove.
- `needs.<job>.outputs.<name>` — untrusted when `<job>` binds that output to a
  tainted `steps.<id>.outputs.*` (or to an untrusted context directly). The set
  of exporting jobs is closed by iteration, so a chain of jobs is followed
  whatever order they are declared in.

The fixed table covers every payload field an attacker authors, not only the
obvious ones: alongside issue / PR / comment free text and commit messages it
lists the head repository's `description` and `homepage` (the fork owner types
them in its settings) and the `committer.name` / `.email` of a commit, which
whoever authored the commit fills in. SEC006 gets the same free-text additions;
they are not ref-shaped, so the #138 exclusion does not apply to them.

Expanding the event as a whole — `toJSON(github.event)` — is a taint source too.
The root matches only as a whole reference, so server-generated fields such as
`github.event.number` stay out of scope.

### Refs SEC005 and SEC009 recognize

SEC005 covers the triggers that run with the base repository's privileges while
carrying the fork's `pull_request.head` in the payload: `pull_request_target`,
`pull_request_review` and `pull_request_review_comment`. Anyone who can see a
pull request can post a review on it, so the last two share the
`pull_request_target` threat model; the finding names the trigger it found.

SEC005 reports a checkout whose `ref` / `repository` names the PR head:
`github.event.pull_request.head.*`, `github.head_ref`, a literal `refs/pull/`,
`github.event.pull_request.number` / `github.event.number` used to build one,
and `github.event.pull_request.merge_commit_sha` — the test merge of the head
into the base carries the fork's changes just as `refs/pull/<n>/merge` does.

SEC009 reports `github.event.workflow_run.head_*`, `.display_title` and
`.pull_requests[*].*`. The last one keeps SEC009 in step with SEC002, which
already treats `pull_requests.*.head.ref` as untrusted; GitHub empties the
array for fork-triggered runs, so the reachable case is a branch name a
same-repository PR author picks.

### Fork guards

SEC005 and SEC009 stay quiet when the job — or the step itself — is gated on an
`if:` that keeps the run to code the base repository controls: an equality
check against the head repository's `full_name` / `id` / `owner.*`, or the
`fork` flag asserted false. The gate has to hold on every path, so `||` around
it, `fork == true`, and a comparison between two attributes of the same head
anchor nothing and the rule still reports.

SEC022 uses the same analysis on `github.event.workflow_run.head_repository`,
plus `workflow_run.event` compared against an event a fork cannot cause. SEC021
has no such gate: the triggers it owns (`workflow_dispatch`, `issue_comment`,
`discussion`, ...) carry no fork identity to test.

### SEC021 vs. SEC005 / SEC009

All three report the same shape — `actions/checkout` fed a ref the attacker
picks — split by trigger. SEC005 owns the privileged PR-head triggers above,
SEC009 owns
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
`github.event.client_payload.*`), the free text of an issue, comment or
discussion, and `github.event.issue.number`. The last one is the ChatOps shape:
anyone may comment `/test` on any pull request, so
`ref: refs/pull/${{ github.event.issue.number }}/merge` lets the commenter pick
which fork's code the job runs with the base repository's secrets (#308). The
`issues` event does not fire on pull requests, so the same number is not a
checkout taint there. The bare `inputs.*` shorthand counts too, unless every way into the
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

### Triggers SEC020 treats as fork-accessible

`pull_request`, `pull_request_target`, `pull_request_review`,
`pull_request_review_comment`, `workflow_run` and `issue_comment`. The two
review events belong in that list for the same reason as
`pull_request_target`: anyone who can see the pull request can post a review,
and the run that reacts to it carries the fork's code onto the runner.

## Supply Chain Security Rules (SC)

Detect supply chain risks in action and container image references.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SC001 | unpinned-images | warning | Container images (`container.image`, `services.*.image`, `uses: docker://...`) should be pinned to a SHA256 digest for supply chain security |
| SC002 | compromised-action-sha | error | Action references a SHA or tag of a known-compromised release |
| SC003 | known-vulnerable-action | warning | Action has known security advisories (CVE) in GitHub Advisory Database |
| SC004 | archived-uses | warning | Action references an archived (unmaintained) repository |
| SC005 | stale-action-refs | info | SHA-pinned action does not correspond to any known Git tag |
| SC006 | ref-confusion | warning | Action ref matches both a tag and branch, creating exploitable ambiguity |
| SC007 | typosquat-action | warning | Action name is similar to a well-known `actions/*` action (possible typosquat) |
| SC008 | impostor-commit | warning | SHA-pinned action ref is not reachable from any branch or tag of the upstream repo |

### SC007 typosquat-action

`uses: actions/chekout@v4` のように、公式 `actions/*` のよく知られたリポジトリ名
から編集距離 1 または 2 の参照を warning する。完全一致（`actions/checkout`）と、
`myorg/chekout` のような別 owner の fork は対象外。候補の置き換えは作者の意図を
先取りするため、autofix は付けない。

### SEC001 / SC006 の SHA ピン止め autofix

prefetch（`src/rules/prefetch.zig`）がタグの指すコミットを取得できた場合、
SEC001 と SC006 は `uses: owner/repo@v4` を
`uses: owner/repo@<40桁 SHA> # v4` に書き換える fix を添える。末尾のコメントは
装飾ではなく、ピン止め後も人間がバージョンを読めるようにするためであり、
Dependabot / Renovate がバージョンを読み取る位置でもある。annotated tag は
GraphQL 側で dereference 済みなので、書き込まれる oid は常にコミットを指す。

- **SEC001 は `safe`**: 書き換え先はそのタグが解決していたコミットそのもので、
  実行されるコードは変わらない。
- **SC006 は `unsafe`**: 同名のタグとブランチが両方ある状態が指摘の本体なので、
  タグ側に決め打つことは作者の意図を先取りする。`--fix-unsafe` でのみ適用する。

コミットが分からない場合（`--quick` / `--offline`、トークン無し、ref がタグでは
なくブランチ）は fix を付けず、指摘だけを出す。取得結果に名前が見つからないこと
は「タグが存在しない」証拠にはならないため、取りこぼしは常に「fix 無し」側に倒す。

fix を付けない条件はほかに 2 つある:

- **同名のタグとブランチが両方ある**: SEC001 の `safe` fix は付けない。どちらを
  指しているかの判断は SC006 の `unsafe` fix の仕事である。
- **`uses:` の値が行末にない**: `- {uses: actions/checkout@v4}` のような flow
  形式では、末尾に付ける `# v4` が閉じ括弧ごとコメントアウトしてしまう。

タグ oid の取得は `--fix` / `--fix-unsafe` を指定した実行でのみ行う。通常の lint
は書き換えないので、余分な問い合わせを負わない。

## Performance Rules (PERF)

Detect CI performance issues and resource waste.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PERF001 | cache-not-used | warning | Job uses a language setup action (`actions/setup-node`, `actions/setup-python`, `actions/setup-go`, `oven-sh/setup-bun`, `astral-sh/setup-uv`) without caching enabled |
| PERF002 | redundant-checkout | warning | Multiple `actions/checkout` without `path` in the same job (`--fix-unsafe` で 2 つ目のステップを削除) |
| PERF003 | fail-fast-disabled | warning | Strategy has `fail-fast` disabled, wasting CI resources on failures |

## Best Practices Rules (BP)

Enforce workflow best practices for maintainability and reliability.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| BP001 | missing-timeout | warning | Job is missing `timeout-minutes` (default 6 hours is too long)。`uses:` ジョブ（reusable workflow 呼び出し）は GitHub Actions が `timeout-minutes` を受け付けないため対象外 |
| BP002 | missing-step-name | info | Step is missing a `name` field |
| BP003 | deprecated-action-version | warning / error | Using a known deprecated action version (warning), or an action declaring a retired `runs.using` runtime (error) |
| BP004 | cross-platform-shell | warning / error | Invalid or OS-unavailable `shell` name (error), or a run step without `shell` in a Windows-targeting job (warning) |
| BP005 | push-without-concurrency | info | Push trigger without concurrency setting |
| BP007 | obfuscation | warning | Obfuscated or indirect command execution patterns detected in `run:` block |
| BP008 | deprecated-workflow-command | error | Deprecated workflow command (`::set-output`, `::save-state`, `::set-env`, `::add-path`) used in `run:` (`--fix` で `$GITHUB_*` への追記に書き換え) |

### BP003 の 2 つの判定

- **バージョン表**: `actions/checkout` など置き換え先が判明しているアクションを
  固定表と突き合わせ、`warning` で報告する。置き換え先が分かっているので
  `--fix` で `@vN` を書き換えられる。
- **ランタイム判定**: アクションの `runs.using` が GitHub の廃止済みランタイム
  （`node12` / `node16`）なら `error` で報告する。ローカルアクション
  （`uses: ./{path}`）は `action.yml` を読み、リモートアクションは DEP005 の
  埋め込みメタデータ（`src/rules/data/popular_actions.zig`）を引く。

両方が該当する場合はランタイム判定を優先する（廃止済みランタイムは警告で済む
「古いだけのバージョン」と違って実行そのものが失敗するため）。autofix は失われ
ない: バージョン表が置き換え先を知っていれば、ランタイム判定の報告に同じ `@vN`
書き換えが付く。ローカルアクションの場合は呼び出し側では直せない（アクション
自身の `action.yml` を `using: node24` へ移行する必要がある）ため autofix は
付かない。

固定リストに無いアクションでも、データセットに載っていれば廃止済みランタイムを
検出できる（例: `actions/checkout@v2` は `node12`）。データセットに無いアクション
は判定しない。

## Permissions Rules (PERM)

Validate the principle of least privilege in workflow permissions.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PERM001 | broad-permissions | warning | Overly broad permission scope detected |
| PERM002 | missing-job-permissions | warning | Job with third-party actions lacks explicit permissions |
| PERM003 | invalid-permissions | error | Unknown permission scope or invalid permission level |

PERM002 stays quiet when the workflow already declares `permissions:` with no
write scope (`contents: read`, `read-all`, `{}`). The token is already
minimized for every job. `write-all` or any `: write` at workflow level still
warns, because those jobs should narrow the grant (#334).

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
| EXPR015 | context-availability | error | A context used under a workflow key that does not provide it (e.g. `secrets` in `runs-on:`, `steps` in a job-level `if:`) |
| EXPR016 | function-availability | error | `success()` / `failure()` / `always()` / `cancelled()` outside an `if:`, or `hashFiles()` under a key that does not provide it |
| EXPR017 | incomparable-types | warning | Comparison between values whose types can never be equal (e.g. `${{ github.event == 1 }}`, `${{ github.event.issue == 'bug' }}`) |
| EXPR018 | argument-type | warning | An object or array passed where a builtin function takes a string (e.g. `${{ startsWith(github.event, 'a') }}`), or interpolated into a string where it renders as `Object` / `Array` / nothing |

EXPR006 is substring matching, so it fires only when the first argument is a
string. Array membership — `contains(github.event.pull_request.labels.*.name, 'label')`,
`fromJSON('[...]')`, or a `TypeEnv` array — is exact and is not reported (#333).

## Dependency Rules (DEP)

Validate Dependabot configuration files (`dependabot.yml`) and the format of
action / reusable workflow references.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| DEP001 | dependabot-cooldown | info | Dependabot updates should configure a cooldown period to avoid excessive PRs |
| DEP002 | dependabot-execution | warning | `insecure-external-code-execution: allow` is a supply chain attack risk |
| DEP003 | uses-format | error | `uses:` is not a supported action reference (step) or reusable workflow call (job) |
| DEP004 | local-action-inputs | error | `with:` does not match the `inputs:` declared by the referenced local action, or the action has no `action.yml` |
| DEP005 | action-inputs | error | `with:` does not match the `inputs:` declared by a widely used action (unknown input, or a missing required input) |
| DEP006 | deprecated-action-input | warning | The action declares the used input as deprecated (`deprecationMessage:`) |

### DEP003 で受理される形式

ステップの `uses:`:

- `{owner}/{repo}@{ref}` / `{owner}/{repo}/{path}@{ref}` — `@ref` は必須
- `./{path}` — ローカルアクション（`@ref` を付けられない）
- `docker://{image}`

ジョブの `uses:`（再利用可能ワークフロー呼び出し）:

- `{owner}/{repo}/.github/workflows/{file}.yml@{ref}`
- `./.github/workflows/{file}.yml` — `@ref` を付けられない

`uses:` の値が `${{ }}` を含む場合は実行時にしか決まらないため報告しない。

### DEP004 のスコープ

`uses: ./{path}` が指すディレクトリの `action.yml` / `action.yaml` を読み、
呼び出し側の `with:` と突き合わせる。パスはリポジトリルート（`.git` を持つ
ディレクトリ）からの相対として解決する。報告するのは 3 種類:

- 参照先に `action.yml` も `action.yaml` も存在しない
- `with:` のキーがアクションの `inputs:` に無い（編集距離 2 以内で候補が一意に
  定まる場合は `did you mean ...?` を添える）
- `required: true` かつ `default:` を持たない入力が渡されていない

`runs.using: docker` のアクションでは `args:` / `entrypoint:` は入力ではなく
Dockerfile の上書きなので報告しない。DEP003 が既に弾く形式の参照（`../` 始まり、
`@ref` 付きなど）は二重報告を避けるため対象外。

同一ジョブ内で、当該ステップより前にある `actions/checkout` の `path:` が指す
ディレクトリ以下への参照も対象外とする（#305）。

```yaml
- uses: actions/checkout@v4
  with:
    path: action-under-test
- uses: ./action-under-test   # 実行時に作られるので報告しない
```

アクション自身をテストするワークフローの定番の書き方で、ディレクトリは実行時に
できるためリポジトリ側には存在しない。`path:` が `${{ }}` を含む場合も実行時に
しか解決できないため同様に対象外。

ディスクだけを読むので `--quick` / `--offline` でも動作する。

### DEP005 / DEP006 のスコープ

広く使われているアクションのメタデータ（`inputs:` と `runs.using`）を
`src/rules/data/popular_actions.zig` に埋め込み、呼び出し側の `with:` と
突き合わせる。DEP004 のローカルアクション版と同じ判定を、リモートアクションに
対して埋め込みデータで行うもの。

- **DEP005**: `with:` のキーがアクションの `inputs:` に無い（候補が一意なら
  `did you mean ...?` を添える）、または `required: true` かつ `default:` を
  持たない入力が渡されていない。
- **DEP006**: アクションが `deprecationMessage:` を設定している入力を使って
  いる。メッセージはアクション側の文言をそのまま表示する。

判定するのはデータセットに載っているアクションだけで、載っていないアクションは
一切検証しない。誤検出を避けるための線引きであり、次の参照も対象外になる:

- SHA ピン止め（`@11bd7190...`）— タグへの逆引きにはネットワークが要る（SC005 の
  領域）。推測すると使っていないバージョンの入力を報告しかねない。
- ブランチ参照やバージョンでないタグ（`@main`、`@v4-beta`、`@4.x-maintenance`）
  — データはメジャーバージョン単位で持っているため対応付けられない。バージョンと
  見なすのは先頭が `v` で、続きが数字を `.` で連ねた形（`v4`、`v4.2.2`）だけ。

データは各アクションの `action.yml` から生成する。対象一覧は
`scripts/popular-actions.txt`、生成は `scripts/gen-popular-actions.py`
（更新手順は `docs/maintenance.md`）。埋め込みデータなので `--quick` /
`--offline` でも動作する。

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
| SYN008 | duplicate-needs | warning | The same job ID is listed more than once in `needs` (`--fix` で重複を削除) |
| SYN009 | unknown-event | error | `on:` names an event GitHub Actions does not support, so the workflow never triggers |
| SYN010 | invalid-activity-type | error | `types:` names an activity type the event does not define, so the workflow never triggers |
| SYN011 | unavailable-event-filter | error | Event filter is not available for the event it is written under, or is not a filter name at all (`--fix` で綴りを修正、候補が無ければ `--fix-unsafe` でキーを削除) |
| SYN012 | exclusive-event-filters | error | `branches`/`branches-ignore`, `tags`/`tags-ignore` or `paths`/`paths-ignore` specified together for the same event |
| SYN013 | invalid-filter-glob | error | Event filter value (`branches`, `tags`, `paths`, or their `-ignore` forms) uses invalid GitHub Actions glob syntax |
| SYN014 | invalid-cron | error | `schedule` cron expression is not valid POSIX 5-field cron syntax |
| SYN015 | cron-too-frequent | error | scheduled workflow runs more often than GitHub Actions allows (once every 5 minutes) |
| SYN016 | invalid-timezone | error | `schedule` `timezone` is not a name in the IANA time zone database |
| SYN017 | workflow-dispatch-inputs | error | `workflow_dispatch` input declares an invalid `type`, misuses `options`, or has a `default` that does not fit |
| SYN018 | duplicate-matrix-value | warning | The same value appears more than once in a `strategy.matrix` axis (`--fix` で重複を削除) |
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

綴り間違いで候補が 1 つに絞れる場合は `--fix` が正しい綴りに書き換える。候補が
無い場合のみ `--fix-unsafe` がそのキーの行ごと削除する。フィルタが消えると
ワークフローの起動条件が広がるため、削除は unsafe 扱いとする。

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

`--fix` は繰り返された値を軸から取り除く。同じ値が 3 回以上書かれている場合も
1 回の実行でまとめて 1 つに減らす。

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
| ACT001 | action-missing-required-key | error | `name` / `runs`、および `runs.using` が要求するキー（node は `main`、docker は `image`、composite は `steps`）が無い（`--fix-unsafe` で仮の値を挿入） |
| ACT002 | action-invalid-runs-using | error/warning | `runs.using` が未対応のランタイム（error）、または GitHub が廃止予定のランタイム（warning） |
| ACT003 | action-unknown-key | error | メタデータ・`runs`・各 input / output 定義に、仕様にないキーがある |
| ACT004 | action-invalid-definition | error | 値の形が仕様と違う（ドキュメントや `runs` がマッピングでない、`required` が真偽値でない、composite 以外の `value` など） |
| ACT005 | action-invalid-context | error | composite の step の式が、action 内では使えない context（`matrix` / `needs` / `secrets` / `strategy`）か、その action が宣言していない `inputs.<name>` を参照している |

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
### composite の `runs.steps`

composite action の step は、ワークフローの step と同じ実体なので、ワークフロー
側で既に持っているルールをそのまま適用する。適用するのは、ワークフローもジョブも
無い状態で正しく判定できる step 単位のルールに限る:

- `uses:` 系: SEC001（SHA ピン止め）、DEP003（`uses:` の形式）、DEP004（ローカル
  action の入力）、DEP005 / DEP006（widely used action の入力）、SC002（改竄された
  リリース）、SC007（`actions/*` への typosquat）、BP003（廃止されたバージョン）
- `run:` 系: SEC002（スクリプトインジェクション）、SEC008（`GITHUB_ENV` 汚染）、
  SEC017、BP007、BP008
- その他: SEC003、SEC006、SEC014、SEC018

適用しないものにも理由がある。ワークフロー / ジョブ単位のルール（SEC004、BP001 など）
は判定対象が無い。`secrets` を見るルール（SEC011 / SEC012 / SEC019）は composite に
`secrets` context が無いため、ACT005 が代わりに報告する。ネットワークを使うルール
（SC003-SC006、SC008）はメタデータのリントでは prefetch が走らないため常に無反応に
なる。BP002（step の `name`）はワークフローのログ表示のための規約で、action 側が
決めることではない。

さらに composite 固有の判定として:

- `run:` を持つ step には `shell:` が必須。既定のシェルも `defaults.run` も無く、
  GitHub は実行時にエラーにするため、ACT001（必須キーが無い）として報告する。
  `shell:` の値そのものの妥当性は BP004 と同じ表で判定する。
- 式検証（EXPR 系）は composite 用の context で行う。`inputs.<name>` はその action
  自身の `inputs:` を指すため、宣言されていない名前は ACT005 として報告する
  （`inputs:` の形が壊れている場合は判定しない）。`matrix` / `needs` / `secrets` /
  `strategy` は composite action では解決できないので、参照していれば ACT005。
  `steps.<id>` はその step より前に現れた step の `id` に対して解決する。

---

---

## Reusable Workflow Rules (RW)

Validate the `on.workflow_call` interface a reusable workflow exposes to its
callers, and the calls made against it.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| RW001 | workflow-call-inputs | error | `workflow_call` input is missing `type`, declares a type outside `string`/`number`/`boolean`, has a `default` that does not match its type, or is both `required` and defaulted (`--fix-unsafe` で `default:` から `type:` を推論して挿入) |
| RW002 | workflow-call-required-inputs | error | A job calling a local reusable workflow does not pass one of its `required` inputs |
| RW003 | workflow-call-input-values | error | A job calling a local reusable workflow passes an input it does not declare, or a value that does not match the declared type |
| RW004 | workflow-call-secrets | error | A job calling a local reusable workflow omits one of its `required` secrets, or passes a secret it does not declare |
| RW005 | workflow-call-outputs | error | A `workflow_call` output reads a job or job output that does not exist, or a caller reads an output the called local workflow does not declare |

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

### RW005 workflow-call-outputs

The outputs of a reusable workflow are checked from both sides.

In the reusable workflow, `on.workflow_call.outputs.<name>.value` may only read
`jobs.<id>.outputs.<x>`, and both names must exist:

```yaml
# .github/workflows/reusable.yml
on:
  workflow_call:
    outputs:
      version:
        value: ${{ jobs.build.outputs.version }}
      bad:
        value: ${{ jobs.nonexistent.outputs.x }}   # no such job
jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      version: ${{ steps.v.outputs.version }}
    steps:
      - id: v
        run: echo "version=1" >> "$GITHUB_OUTPUT"
```

In the caller, `needs.<job>.outputs.<name>` on a job that calls a local
reusable workflow must name an output that workflow declares:

```yaml
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
  use:
    needs: [call]
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ needs.call.outputs.ver }}"   # not declared by the called workflow
```

EXPR012 checks the same references against a plain
job's `outputs:`; it hands a job with a `uses:` over to this rule because the
declaration lives in another file. A job whose outputs come from a further
reusable workflow is not resolved on the definition side, and, like
[RW002](#rw002-workflow-call-required-inputs), only a **local** call is checked.

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
