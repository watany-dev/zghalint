# SEC021 untrusted-checkout-ref 検知設計書

## 目的

`actions/checkout` の `with.ref` / `with.repository` に **untrusted context**（`github.event.issue.title`, `github.event.inputs.*`, `github.event.discussion.*` など）が流れると、attacker が任意コードを checkout できる。SEC005 (`pull_request_target`) と SEC009 (`workflow_run`) は狭いトリガー範囲をカバーしているが、`workflow_dispatch` / `repository_dispatch` / `issues` / `issue_comment` / `discussion` / `discussion_comment` 経由は未カバー。

`SEC021` はこれら残りのトリガー群に対して checkout ref への untrusted 代入を検知する。SEC005 / SEC009 と**重複発火させない**。

本設計書の判断は `docs/adr/0004-security-gap-fill-sec018-sec021-sc002-sc007.md` の D6 を単一情報源とする。行番号は本ドキュメント記述時点（commit `f427b0a`）のもの。

## スコープ

- workflow-level の `on:` に次のいずれかのトリガーを含むワークフロー:
  - `workflow_dispatch`
  - `repository_dispatch`
  - `issues`
  - `issue_comment`
  - `discussion`
  - `discussion_comment`
- 各 job の step が `actions/checkout@*` であり、`with.ref` または `with.repository` が設定されている場合
- 値文字列に untrusted context が含まれるかを検査（`${{ github.event.issue.title }}` など）

## 非スコープ

- SEC005 対象の `pull_request_target` トリガー（発火したら SEC021 は skip）
- SEC009 対象の `workflow_run` トリガー（発火したら SEC021 は skip）
- reusable workflow 呼び出し元への伝播解析
- composite action 内部の checkout
- autofix（ADR D4 の通り提供しない。機械的置換は意図保存不可能）

## 現状整理

| 既存資産 | 位置 | 備考 |
|---|---|---|
| `checkDangerousPRTarget` (SEC005) | `src/rules/security.zig:237-271` | `pull_request_target` + dangerous ref 検知 |
| `checkWorkflowRunUntrustedCheckout` (SEC009) | `src/rules/security.zig:457-487` | `workflow_run` + dangerous ref 検知 |
| `containsDangerousPRRef` | `src/rules/security.zig:279-282` | `github.event.pull_request.head` / `github.head_ref` を検知 |
| `containsDangerousWorkflowRunRef` | `src/rules/security.zig:485-486` | `github.event.workflow_run.*` を検知 |
| `dangerous_contexts` 配列 | `src/rules/security.zig:43-57` | 汎用の untrusted context リスト（run: injection 用） |
| `containsDangerousContext` | `src/rules/security.zig:1119-1126` | 汎用検知ヘルパ |
| `stringContainsContext` | `src/rules/security.zig:1130-1149` | 単語境界チェック付き検知 |
| `EventType` enum | `src/workflow/types.zig:118-156` | `workflow_dispatch`, `repository_dispatch`, `issues`, `issue_comment`, `workflow_run`, `pull_request_target`, ... |
| `Trigger.events` | `src/workflow/types.zig:169-171` | `[]const EventConfig` |

ADR 文言の「`containsUntrustedContext` ヘルパ」は**現在リポジトリに存在しない**。本設計書では既存の `containsDangerousContext` / `dangerous_contexts` を再利用する方針を採る。

**DiagnosticList に dedup 機構はない**（`src/diagnostics.zig:75-138` 確認済）。重複抑制はルール側で早期 return する責務。

## 設計方針

### 1. ルールレベルは workflow レベル

SEC005 / SEC009 と同様に `check_workflow = &checkUntrustedCheckoutRef` とする。理由:

- トリガー判定を 1 回だけ済ませたい（各 step check で個別に `wf.on.events` を走査するのは無駄）
- SEC005 / SEC009 との重複抑制ロジックを同じ層に置きたい

### 2. 重複抑制は早期 return で行う

```zig
fn checkUntrustedCheckoutRef(wf: *const Workflow, list: *DiagnosticList) void {
    if (hasPRTargetTrigger(wf)) return;       // SEC005 の領域
    if (hasWorkflowRunTrigger(wf)) return;    // SEC009 の領域
    if (!hasUntrustedRefTrigger(wf)) return;  // SEC021 対象トリガー不在
    // ... step 走査
}
```

3 ヘルパの共通化方針:

- `hasPRTargetTrigger` / `hasWorkflowRunTrigger` は現在 SEC005 / SEC009 内にインライン展開されている。**SEC021 実装と同じコミットで `src/rules/security.zig` 内のファイルスコープ helper に抽出する**（Tidy First）
- `hasUntrustedRefTrigger` は本 PR で新設
- 3 者は `for (wf.on.events) |event| switch (event.event) { ... }` の単純パターン

### 3. `hasUntrustedRefTrigger` 実装

```zig
fn hasUntrustedRefTrigger(wf: *const Workflow) bool {
    for (wf.on.events) |event| {
        switch (event.event) {
            .workflow_dispatch,
            .repository_dispatch,
            .issues,
            .issue_comment,
            => return true,
            else => {},
        }
    }
    return false;
}
```

`discussion` / `discussion_comment` については **`EventType` enum に該当 variant が存在するかを実装時に確認**する。存在しなければ `.other` で受けるか、`EventType` 拡張を別 PR で行う（SEC021 本実装では一旦 `workflow_dispatch` / `repository_dispatch` / `issues` / `issue_comment` の 4 種に絞る）。

### 4. untrusted context の検査

既存の `containsDangerousContext` をそのまま使う。`dangerous_contexts` 配列（`src/rules/security.zig:43-57`）に以下が含まれることを実装時に確認:

- `github.event.issue.title` / `github.event.issue.body`
- `github.event.comment.body`
- `github.event.inputs.*`（`workflow_dispatch` / `repository_dispatch`）
- `github.event.client_payload.*`（`repository_dispatch`）
- `github.event.discussion.*` / `github.event.discussion_comment.*`
- `github.event.pull_request.head.*` / `github.head_ref`（既存）

**不足している context があれば `dangerous_contexts` に追記する。これは Tidy First の「Dead Code / One Pile」に該当し、本 PR の最初のコミットとして別途分離する**。

### 5. 検査対象は `ref` と `repository` の 2 キー

```zig
fn checkStepCheckoutRefs(step: *const Step, list: *DiagnosticList) void {
    const ref = step.uses orelse return;
    if (!isCheckoutAction(ref)) return;
    const with_map = step.with orelse return;

    for ([_][]const u8{ "ref", "repository" }) |key| {
        if (with_map.get(key)) |val| {
            if (containsDangerousContext(val)) {
                list.append(.{
                    .rule_id = "SEC021",
                    .severity = .@"error",
                    .message = "actions/checkout ref/repository references untrusted context (indirect injection)",
                    .category = .security,
                    .span = step.span,
                    .fix_hint = "pin to a trusted ref/repository or validate the input before use",
                }) catch return;
                return; // 同一 step で 2 重発火させない
            }
        }
    }
}
```

呼び出し側 (`checkUntrustedCheckoutRef`) が `wf.jobs` と `job.steps` を 2 重 for ループで走査し、各 step を `checkStepCheckoutRefs` に渡す。

### 6. 診断フィールド

- `id = "SEC021"`
- `severity = .@"error"`（ADR D2、SEC005 / SEC009 と同級）
- `category = .security`
- `span = step.span`（step 全体の span。将来 `with.ref` value span を Step に伝播させる設計が入ったら差し替え）
- autofix なし、`fix_hint` のみ

### 7. ルール登録

`src/rules/security.zig:1472` の `security_rules` 配列に追加（SEC020 の直後）:

```zig
.{
    .id = "SEC021",
    .name = "untrusted-checkout-ref",
    .description = "actions/checkout ref/repository uses untrusted context from dispatch/issues/comments triggers",
    .severity = .@"error",
    .category = .security,
    .check_workflow = &checkUntrustedCheckoutRef,
},
```

## 安全性評価

- 発火条件は 4 トリガー × checkout step × untrusted context の 3 重マッチのみ。false positive は構造的に少ない
- SEC005 / SEC009 との重複は冒頭 2 行の early return で完全排除
- autofix なしのため、ユーザのワークフローを誤って壊すリスクはゼロ

## 実装差分

### 変更対象

- `src/rules/security.zig`
  - `hasPRTargetTrigger` / `hasWorkflowRunTrigger` ヘルパを SEC005 / SEC009 から抽出（Tidy First）
  - `hasUntrustedRefTrigger` を新設
  - `dangerous_contexts` 配列に不足 context（`inputs.*`, `client_payload.*`, `discussion.*` など）があれば追記
  - `checkUntrustedCheckoutRef` / `checkStepCheckoutRefs` を新設
  - `security_rules` 配列に `SEC021` エントリ追加
  - SEC021 のインラインテスト追加

### 変更しないもの

- `src/workflow/types.zig`（既存の `EventType` / `Trigger` で十分。`discussion` 系が不足していたら別 PR で拡張）
- `src/workflow/parser.zig`
- `src/fix/*`
- `src/lib.zig`

## テスト設計

### ケース一覧

1. **workflow_dispatch + checkout ref に inputs** → SEC021 発火
2. **issue_comment + checkout ref に issue.body** → SEC021 発火
3. **workflow_dispatch + checkout ref に固定値** → 発火せず
4. **pull_request_target + checkout ref に head_ref** → SEC005 発火、SEC021 は発火せず（重複抑制）
5. **workflow_run + checkout ref に workflow_run.head_branch** → SEC009 発火、SEC021 は発火せず
6. **push トリガーのみ** → 発火せず（対象トリガー外）
7. **repository_dispatch + checkout repository に client_payload** → SEC021 発火

### テストヘルパ

既存の `hasDiagnostic`, `findDiagnostic`, `countDiagnostics` を使う。`makeEmptyTrigger` をベースにして各トリガーをセットするヘルパ `makeDispatchTrigger` / `makeIssueCommentTrigger` を必要に応じて新設する。

### CI 必須 3 点

```bash
zig build && zig fmt --check src/ build.zig && zig build test --summary all
```

## 実装手順

1. **Tidy 1**: `dangerous_contexts` 配列に不足 context を追記（既存 SEC 系テストが通ることを確認）
2. **Tidy 2**: `hasPRTargetTrigger` / `hasWorkflowRunTrigger` を SEC005 / SEC009 から抽出（既存テストが通ることを確認）
3. **Red**: SEC021 の failing test（ケース 1, 3, 4）を追加
4. **Green**: `hasUntrustedRefTrigger`, `checkUntrustedCheckoutRef`, `checkStepCheckoutRefs` を実装、`security_rules` に登録
5. **Red→Green**: ケース 2, 5, 6, 7 を順次追加し、必要ならロジックを補強
6. **Refactor**: 3 ヘルパの命名統一、コメント整理
7. `zig build && zig fmt --check src/ build.zig && zig build test --summary all` を通す
8. `docs/rules.md` に SEC021 行を追加

## 参考

- `docs/adr/0004-security-gap-fill-sec018-sec021-sc002-sc007.md` — 判断の単一情報源（特に D2 / D3 / D6）
- `docs/design/sec009-workflow-run-untrusted-checkout-design.md` — 同級ルールの設計書テンプレート
- `src/rules/security.zig:237-282` — SEC005 実装 + `containsDangerousPRRef`
- `src/rules/security.zig:457-487` — SEC009 実装 + `containsDangerousWorkflowRunRef`
- `src/rules/security.zig:43-57` — `dangerous_contexts` 配列
- `src/rules/security.zig:1119-1149` — `containsDangerousContext` / `stringContainsContext`
- `src/rules/security.zig:1472` — `security_rules` 配列
- `src/workflow/types.zig:118-171` — `EventType`, `Trigger`, `EventConfig`
- `src/workflow/types.zig:185-234` — `ActionRef.parse`
