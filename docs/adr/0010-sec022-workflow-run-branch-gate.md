# 0010. SEC022 workflow_run branch gate

- Status: Accepted
- Date: 2026-09-05
- Deciders: issue #143（#138 の SEC006 スコープ縮小で生じた検出漏れ。issue 記載の選択肢 1 / 2 から決定）

## Context

#138 で SEC006 は `if:` 専用の untrusted context テーブル（`condition_dangerous_contexts`）を持ち、ref 形状の入力（`github.head_ref`, `...head.ref`, `...head.label`, `...head.repo.default_branch`, `github.event.workflow_run.head_branch`）とラベル名を報告対象から外した。ブランチ名でのルーティングは一般的なイディオムであり、`if:` の値はシェルに到達しないため、この判断自体は維持する。

しかし `on: workflow_run` のワークフローだけは事情が異なる。このワークフローは base リポジトリの secrets を持つ privileged コンテキストで動くのに、`head_branch` は fork 側が自由に名付けられる。

```yaml
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  deploy:
    if: github.event.workflow_run.head_branch == 'main'   # fork が main という名前のブランチを作れば通過
```

現状これを報告するルールは無い。SEC006 は #138 以降このコンテキストを見ず、SEC009（`checkWorkflowRunUntrustedCheckout`）は `step.uses` が checkout であることと `with.ref` しか見ておらず `if:` を検査しない。

## Decisions

### D1. 選択肢 2（専用ルール）を採用する

issue の選択肢 1（`condition_dangerous_contexts` に `head_branch` を戻す）は実装が最小だが、`workflow_run` 以外のワークフローでも発火し、#138 で取り除いたノイズを部分的に戻す。専用ルールなら `on: workflow_run` に限定でき、修正ヒントも具体的に出せる。

### D2. Rule ID は SEC022、name は `workflow-run-branch-gate`

SEC021 は `docs/design/sec021-untrusted-checkout-ref-design.md` / ADR 0006 で untrusted-checkout-ref に予約済み（未実装）。番号の再利用は設計文書との対応を壊すため、次番の SEC022 を採る。

### D3. Severity は error

SEC006 が warning なのは「weak gate だが実行には至らない」ためだった。SEC022 が対象にするのは privileged コンテキストのゲート突破であり、突破すれば base の secrets に到達する。SEC005（dangerous-pr-target）/ SEC009（workflow-run-untrusted-checkout）と同クラスの exploit 直結として error とする。誤検出は D4 / D5 のスコープ限定で抑える。

### D4. 対象コンテキストは fork が著者となる可変属性のみ

- 報告する: `github.event.workflow_run.head_branch` / `head_commit.*` / `display_title`
- 報告しない: `head_sha`（不変の 1 コミットを指す）、`head_repository.*`（これは修正手段そのもの）、`conclusion` / `name` など base 側が決める属性

issue 本文の「`head_branch` / `head_sha` 以外の可変な属性」という記述は、`head_sha` を信頼の根拠として残す意図として読み、`head_branch` は報告対象に含めた（issue の再現例そのものが `head_branch` であるため）。

### D5. trust anchor を含む条件は報告しない

同じ `if:` が次のいずれかを含む場合、ゲートは成立しているので報告しない。

- `github.event.workflow_run.head_repository.*` — トリガー元リポジトリの同一性検査。fork には偽装できない
- `github.event.workflow_run.event`（ただし条件文字列に `pull_request` を含まない場合のみ）— fork は base リポジトリの push run を起こせないため `event == 'push'` は有効な anchor。比較する literal が anchor の本体なので、`event == 'pull_request'` は anchor と見なさない

job の `if:` が anchor を持つ場合、その job の step は job 条件を通過して初めて走るので step 条件も報告しない。

### D6. autofix は提供しない

安全な修正は「どの identity を信頼するか」の宣言であり、機械的に補える情報ではない。fix_hint で `head_repository.full_name == github.repository` / `event == 'push'` / `head_sha` を提示するに留める。

## Consequences

- #143 の再現パターンが error として検出される
- `on: workflow_run` 以外のワークフローでの `head_branch` 比較は引き続き無報告（#138 の判断を維持）
- anchor 判定は同一 `if:` 文字列（と job → step の包含関係）に閉じており、別 step での検証は追跡しない。将来必要になれば D5 を拡張する
