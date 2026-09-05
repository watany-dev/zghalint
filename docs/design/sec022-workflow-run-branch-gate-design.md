# SEC022 workflow-run-branch-gate 検知設計書

判断の単一情報源は `docs/adr/0010-sec022-workflow-run-branch-gate.md`。本書は実装の形を記述する。

## 目的

`on: workflow_run` のワークフローで、fork が値を決められるトリガー元属性を `if:` の信頼ゲートに使っている箇所を検出する（#143）。

## スコープ

- workflow-level の `on:` に `workflow_run` を含むワークフローのみ
- job の `if:` と step の `if:` の両方
- 検査対象コンテキスト（prefix マッチ）:
  - `github.event.workflow_run.head_branch`
  - `github.event.workflow_run.head_commit`（`.message` / `.author.*` を含む）
  - `github.event.workflow_run.display_title`

## 非スコープ

- `head_sha` / `head_repository.*` / `conclusion` などの属性
- `run:` 内での同コンテキスト利用（SEC002 / SEC008 の担当）
- checkout の `with.ref`（SEC009 の担当）
- 別 step / 別 job で行われる検証の追跡
- autofix（ADR D6）

## 実装

`src/rules/security.zig`:

- `workflow_run_untrusted_gate_contexts` — 報告対象のコンテキスト表
- `workflow_run_trust_anchors` — `github.event.workflow_run.head_repository`
- `hasWorkflowRunTrustAnchor(cond)` — anchor 判定。`head_repository.*` を含めば true。`workflow_run.event` を含む場合は、条件文字列に `pull_request` が現れないときのみ true
- `checkWorkflowRunBranchGate(wf, list)` — `wf.hasEvent(.workflow_run)` で早期 return。job 条件を先に判定し、anchor を持つ job の step はスキップする
- `reportConditionContexts` — SEC006 と共有する報告ヘルパー。`${{ }}` を含む条件は式単位、含まない条件は値全体に span を張る

## 診断

- ID: `SEC022` / name: `workflow-run-branch-gate` / severity: `error` / category: `security`
- message: workflow_run gate compares an attribute of the triggering run that a fork controls, so a fork can satisfy it and reach this privileged job
- fix_hint: `head_repository.full_name == github.repository` または `workflow_run.event == 'push'` でゲートし、コミットは `head_sha` で特定する

## テスト

- inline（`src/rules/security.zig`）: head_branch / head_commit / display_title の発火、`${{ }}` 形と裸の条件、head_repository anchor と `event == 'push'` anchor の抑制、`event == 'pull_request'` は抑制しない、head_sha / conclusion の無報告、非 workflow_run トリガーの無報告、step 条件の発火、job anchor による step 抑制、fix_hint の存在
- E2E: `tests/fixtures/e2e/sec022-workflow-run-branch-gate.yml`（発火 job と検証済み job を 1 ファイルに同居）
