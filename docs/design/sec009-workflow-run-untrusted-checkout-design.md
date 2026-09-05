# SEC009 workflow_run-untrusted-checkout 設計書

## 目的

`workflow_run` トリガーで起動される workflow が、トリガー元 workflow の
head SHA / head branch を `actions/checkout` の `ref:` に指定して fork 由来の
コードを checkout する構成は、実質 RCE につながる。`workflow_run` ジョブは
デフォルトで base リポジトリのデフォルトブランチ文脈・secrets フルアクセス・
`GITHUB_TOKEN` write 権限多数で実行されるため、fork の untrusted ref を
build/test に回した時点で外部コントリビュータが base 側の secrets と書込み
トークンを握ることと等価となる。

GitHub Security Lab は 2022 年の "Keeping your GitHub Actions and workflows
secure Part 2: Untrusted input" で本クラスを明示的に警告しており、tj-actions
系の実攻撃観測例も存在する。しかし zghalint の既存 SEC ルールでは
`SEC005 dangerous-pr-target` が `pull_request_target` を対象にしているのみで、
`workflow_run` クラスタはカバーされていない。

本設計書は、SEC005 と同構造で `workflow_run` + `actions/checkout` の
untrusted ref を検出する新ルール `SEC009` を追加する方針を定義する。

関連資料:
- `docs/adr/0004-sec009-workflow-run-untrusted-checkout.md`（決定記録）
- `docs/design/sec020-self-hosted-runner-fork-triggered-design.md`（設計書フォーマットの基準）
- `src/rules/security.zig:237-283`（SEC005 の先行実装）

## スコープ

- Workflow の `on:` に `workflow_run` が含まれる
- 任意の job の step で `uses` が `actions/checkout` である
- その step の `with.ref` が存在し、値に部分文字列 `github.event.workflow_run.` を含む
- severity = `error`, category = `security`
- 修正提案は `fix_hint` のみ
- 診断粒度は該当 step 単位で 1 件

## 非スコープ

- `run:` 内の `gh pr checkout` / `git fetch origin pull/<N>/head` 等の検出
  （SEC002 script-injection の管轄）
- `permissions:` 考慮による severity 可変化
- `head_repository.full_name` 同時指定の有無による発火条件差分（FP より FN を嫌う方針）
- `${{ matrix.* }}` / `${{ inputs.* }}` / 再利用 workflow 経由の ref 伝搬
- autofix（`--fix` / `--fix-unsafe`）の提供
- `repo_visibility` によるゲート（SEC020 と異なり public / private 問わず原理的にリスク）
- `Span` 精度の向上（`with.ref` span は parser が保持していないため 0 span へフォールバック）

## 現状整理

本ルール実装に関連する既存コードの制約は以下の通り。

- `EventType.workflow_run` は `src/workflow/types.zig:113` で既に定義済み。
  parser は `src/workflow/parser.zig` の `EventType` マップで `workflow_run` を認識する
- `Step.with` は `StringMap`（`src/workflow/types.zig`）で、`with_map.get("ref")`
  で `[]const u8` を取り出せる
- `Job.steps` は配列走査可能
- `Rule.check_workflow` は `*const Workflow, *DiagnosticList` を受け取るため
  workflow 全体を参照できる（`src/rules/engine.zig:14-23`）
- `isCheckoutAction(ActionRef) bool` は `src/rules/security.zig:273-277` に存在し
  `owner == "actions"` かつ `repo == "checkout"` を判定する
- SEC005 `checkDangerousPRTarget` は `src/rules/security.zig:237-271` に存在し、
  本ルールはその構造をそのまま踏襲できる
- `DiagnosticList.append` と `Span.point(0, 0, 0)` は SEC005 で先行使用されている
- `security_rules` 配列は `src/rules/security.zig` 内で定義され、`main.zig` の
  `all_rules` に自動結合される（新規エントリ追加のみで組み込み完了）

これらの制約上、SEC009 は SEC005 と全く同じ骨格で実装でき、追加インフラは不要である。

## 設計方針

### 1. 検出ロジックは `check_workflow` で実装する

trigger 判定と job/step 走査を一体に行うため、`Rule.check_workflow` を使用する。

```zig
fn checkWorkflowRunUntrustedCheckout(wf: *const Workflow, list: *DiagnosticList) void {
    var has_workflow_run = false;
    for (wf.on.events) |event| {
        if (event.event == .workflow_run) {
            has_workflow_run = true;
            break;
        }
    }
    if (!has_workflow_run) return;

    for (wf.jobs) |*job| {
        for (job.steps) |*step| {
            const action_ref = step.uses orelse continue;
            if (!isCheckoutAction(action_ref)) continue;
            const with_map = step.with orelse continue;
            const ref_val = with_map.get("ref") orelse continue;
            if (!containsDangerousWorkflowRunRef(ref_val)) continue;
            list.append(.{
                .rule_id = "SEC009",
                .severity = .@"error",
                .message = "dangerous: workflow_run job checks out a ref from the triggering workflow, allowing arbitrary code execution from forks",
                .span = Span.point(0, 0, 0),
                .fix_hint = "do not check out untrusted refs in workflow_run; perform the checkout in a separate pull_request workflow with minimal permissions and pass artifacts forward",
            }) catch return;
        }
    }
}
```

SEC005 と異なり、step ごとに guard clause 連鎖で早期 continue する形式
（CLAUDE.md "Guard Clauses" tidying の適用）を採用する。SEC005 の深いネスト
より読みやすく、将来同型ルールを増やす際にも揃えやすい。

### 2. Dangerous ref 判定は単一アンカーで行う

```zig
fn containsDangerousWorkflowRunRef(ref_val: []const u8) bool {
    return std.mem.indexOf(u8, ref_val, "github.event.workflow_run.") != null;
}
```

untrusted sub-field（`head_sha` / `head_branch` / `head_commit.*` /
`pull_requests[*].head.*`）をすべて prefix `github.event.workflow_run.` で
一括捕捉する。安全 sub-field（`conclusion` / `run_number` / `status` 等）は
通常 `ref:` 値には書かれないため、prefix 一致で false positive は実運用で
ゼロに近い。ADR D4 参照。

### 3. Rule エントリの配置

SEC008 の Rule エントリ（`src/rules/security.zig:1496-1502`）の直後に挿入する。

```zig
.{
    .id = "SEC009",
    .name = "workflow-run-untrusted-checkout",
    .description = "workflow_run job checks out a ref from the triggering workflow, allowing arbitrary code execution from forks",
    .severity = .@"error",
    .category = .security,
    .check_workflow = &checkWorkflowRunUntrustedCheckout,
},
```

`check_job` と `check_step` は暗黙 `null`。

### 4. fix_hint のみ提供、autofix は出さない

修正方針は「別 workflow への分離 + artifact 経由のデータ受け渡し」という
再設計レベルであり、機械化できる単一解が存在しない。SEC005 と同じく
`fix_hint` のみ提供する（ADR D6）。

## 安全性評価

本ルールは診断のみで破壊的変更を伴わないため、失敗モードは誤検知／見逃しに帰着する。

**False positive 軽減**:
- 対象を `actions/checkout` の `with.ref` に限定し、`run:` 内パターンは SEC002 に委譲
- `github.event.workflow_run.` prefix は事実上 untrusted sub-field にしか使われない
- 誤発火したユーザは `.zghalint.yml` で `rules.SEC009.enabled: false` または severity 下げ

**残存する false negative**:
- `run:` 内の `gh pr checkout` / `git fetch` による untrusted checkout（SEC002 カバー範囲）
- 動的 matrix / reusable workflow 経由で間接的に untrusted ref を渡すケース
- `workflow_run` 以外の trigger で fork の head を checkout するケース（例: `repository_dispatch`）

これらは明示的な非スコープとして設計書に記載する。

`fix_hint` は構造的代替案（pull_request workflow 分離 + artifact 受け渡し）を
案内するのみで、ユーザの具体的環境構成を仮定した破壊的提案を含まない。

## 実装差分

### 変更対象

- `src/rules/security.zig`
- `docs/rules.md`
- `README.md`
- `docs/design/sec009-workflow-run-untrusted-checkout-design.md`（本ファイル新規）
- `docs/adr/0004-sec009-workflow-run-untrusted-checkout.md`（新規）

### 変更内容

1. `src/rules/security.zig` の SEC005 実装近傍に `checkWorkflowRunUntrustedCheckout`
   と `containsDangerousWorkflowRunRef` を追加
2. `security_rules` 配列（SEC008 の次）に SEC009 エントリを追加
3. ファイル末尾の test ブロックに 5 テスト追加（`makeWorkflowRunTrigger` ヘルパを同梱）
4. `docs/rules.md` の SEC テーブルに SEC009 行を追加、冒頭 "43 rules" → "44 rules"
5. `README.md:114` の "43 rules" → "44 rules"

### 変更しないもの

- `src/rules/engine.zig`（`Rule` 構造体・`Engine` API 変更なし）
- `src/workflow/types.zig` / `src/workflow/parser.zig`（`workflow_run` は既対応）
- `src/main.zig`（`security_rules` 経由で自動結合）
- `src/config.zig`（ID ベース override は汎用）
- `src/yaml/*`

## テスト設計

`src/rules/security.zig` 末尾のインラインテストブロック（SEC005 テスト群の直後）に
5 件追加する。`makeWorkflowRunTrigger()` を `makePRTargetTrigger` と並べて定義する。

### Positive

| # | ケース |
|---|---|
| 1 | `on: workflow_run` + `actions/checkout@v4` with `ref: ${{ github.event.workflow_run.head_sha }}` → 発火 |
| 2 | `on: workflow_run` + `actions/checkout@v4` with `ref: ${{ github.event.workflow_run.head_branch }}` → 発火 |

### Negative

| # | ケース |
|---|---|
| 3 | `on: workflow_run` + 他 step のみ（checkout なし） → 発火しない |
| 4 | `on: workflow_run` + `actions/checkout@v4` で `with.ref` なし → 発火しない |
| 5 | `on: workflow_run` 以外の trigger（例: `pull_request`） + `actions/checkout@v4` with `ref: ${{ github.event.workflow_run.head_sha }}` → 発火しない |

診断検証項目:
- `rule_id == "SEC009"`
- `severity == .@"error"`
- `fix_hint` が非空

## 実装手順

1. ADR `docs/adr/0002-...` を先に記述（決定の固定）
2. 本設計書を記述
3. テスト 5 件を `src/rules/security.zig` に追加（Red）
4. `containsDangerousWorkflowRunRef` と `checkWorkflowRunUntrustedCheckout` を実装
5. `security_rules` 配列に SEC009 エントリを追加（Green）
6. `docs/rules.md` と `README.md` のカウント + SEC 表を更新
7. `zig build && zig fmt --check src/ build.zig && zig build test --summary all`
8. `claude/grill-me-rules-gKpf3` ブランチへコミット＆push

## ソースコードとの差分メモ

- SEC005 と SEC009 で「trigger 判定 + checkout step 走査 + with.ref 検査」の構造が
  重複する。現時点ではヘルパ抽出のコストが利得を上回るため行わない。3 つ目の同型
  ルールが必要になった時点で `iterateCheckoutSteps(wf, predicate, handler)` 形の
  共通化を検討する
- `Job.runs_on_span` / `Step.with_span` が parser に無いため `Span.point(0, 0, 0)`
  へフォールバックする制約は SEC005 / SEC020 と共通。pinpoint 精度向上は parser /
  types 横断変更となるため別 PR で対応する
- 既知の parser 制約（SEC005 にも同様に影響）: 非クォート形式の
  `ref: ${{ github.event.workflow_run.head_sha }}` は YAML tokenizer が `$` 以降を
  切り詰め、`with_map.get("ref")` が `"$"` を返すため本ルールも発火しない。
  実運用では多くのユーザがクォート付き（`ref: "${{ ... }}"`）で書いており、
  その形式では正しく発火する。非クォート `${{ }}` scalar を正しくパースする
  tokenizer 修正は本 PR 非スコープで、全ルール横断の YAML 修正として別 PR で扱う
