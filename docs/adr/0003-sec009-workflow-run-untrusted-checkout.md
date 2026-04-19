# 0002. SEC009 workflow_run-untrusted-checkout

- Status: Accepted
- Date: 2026-04-19
- Deciders: grill-me セッション（2026-04-19）

## Context

zghalint は 43 ルールを実装済みだが、`workflow_run` トリガー起動の workflow が
トリガー元 workflow の head SHA / head branch を `actions/checkout` で取得する攻撃面
（tj-actions 系と同系統の pwn_request パターン）が未カバーである。
`SEC005 dangerous-pr-target` は `pull_request_target` のみを対象にしており、
`workflow_run` クラスタはその盲点として残っている。

`workflow_run` ジョブはデフォルトで以下の権限で実行される。

1. base repo のデフォルトブランチ文脈（workflow 定義はデフォルトブランチから読まれる）
2. secrets フルアクセス
3. `GITHUB_TOKEN` の write 権限多数

この状態で fork の untrusted ref を checkout してビルド/テストを回すと、
外部コントリビュータが base リポジトリの secrets と書き込み権限を握ることと等価であり、
実質 RCE となる。GitHub Security Lab が 2022 年に "Keeping your GitHub Actions
and workflows secure Part 2: Untrusted input" で明示的に警告した攻撃面である。

本 ADR は grill-me セッションで確定した決定事項とその根拠を記録する。
詳細設計は `docs/design/sec009-workflow-run-untrusted-checkout-design.md` に分離する。

## Decisions

### D1. Rule ID は SEC009 を使用する

- 現行 SEC 系の採番は SEC001-020 のうち SEC009 / SEC018 が欠番。SEC020 まで埋まった状態で
  SEC021 を新設するか、欠番を埋めるかの二択となる
- 今回は欠番のうち若い SEC009 を充填する。SEC020 実装以降 SEC009 / SEC018 を使用した履歴は
  git log -S 検索でゼロ（2026-04-19 時点）であり、revert / 再利用の混同リスクは無視できる
- 代償: 将来参照時に「SEC009 は workflow_run-untrusted-checkout」という対応関係を
  確認するコストが 1 回発生するが、`docs/rules.md` と本 ADR で明文化することで緩和する

### D2. 検出ロジックは SEC005 と同構造で `check_workflow` に実装する

- 判定条件が「workflow の `on:` を見つつ各 job の steps を走査する」ため、
  `check_step` / `check_job` では workflow 全体を参照できず不足する
- SEC005 `checkDangerousPRTarget`（`src/rules/security.zig:237-271`）と同じく
  `check_workflow` フックを採用する
- workflow の trigger 判定は 1 度だけ行い、以後 job / step をループする

### D3. 検出対象は `actions/checkout` の `with.ref` のみに絞る

- 対象: `isCheckoutAction(uses)` が true の step で `step.with.get("ref")` が
  `github.event.workflow_run.` を部分一致で含むケース
- `run:` 内の `gh pr checkout` / `git fetch` 類は SEC002 script-injection の管轄に委譲し、
  本ルールでは拾わない
- 根拠: スコープを狭く取ることで false positive を最小化する。run: 内パターンまで含めると
  SEC002 と境界が曖昧化し、同一問題に重複診断が出る

### D4. Dangerous ref 判定は単一アンカー `github.event.workflow_run.` の部分一致とする

- untrusted sub-field は `head_sha` / `head_branch` / `head_commit.*` /
  `pull_requests[*].head.*` の 4 系統存在するが、個別列挙でなく共通 prefix で判定する
- 根拠:
  - 安全な sub-field（`conclusion` / `run_number` / `status` 等）は通常 `ref:` に
    書かれないため、prefix 一致の誤検知は実運用でゼロに近い
  - 列挙方式は今後 GitHub が `head_*` 系のフィールドを追加した場合に更新漏れが起きる。
    prefix 方式なら自動的にカバーされる
  - 実装コードが 1 行の `std.mem.indexOf` 呼び出しに収まり保守性が高い
- 代償: 安全 sub-field を `ref:` に使うユーザが false positive を受ける可能性がある。
  その場合は `.zghalint.yml` で SEC009.enabled を false にするか、severity 下げで対処

### D5. Severity は error

- SEC005 も同じく `error`。`workflow_run` が secrets + write token フルで動く既定環境
  を考えると攻撃成功時の被害は `pull_request_target` と等価以上
- zizmor `dangerous-triggers` / poutine `pwn_request` も high / HIGH 評価
- 代償: 正当な "build in pull_request → deploy in workflow_run" パターンを
  組む少数の大規模 repo でノイズが増える。当該ユーザは `.zghalint.yml` で
  severity downgrade または disable で対処可能

### D6. Autofix は提供せず `fix_hint` のみ

- workflow 構造そのものを再設計しない限り安全に書き換えられない。`ref:` 行を
  削除するだけでは動かないし、代替 ref を機械が選べない
- SEC005 と同じく `fix_hint` で「pull_request で checkout する unprivileged
  workflow に分離せよ」と案内するに留める

### D7. Config 依存なし、ネットワーク I/O なし

- SEC020 のような `repo_visibility` 依存は不要。`workflow_run` + checkout の
  組み合わせは public / private いずれでも原理的にリスクがあり（private でも
  外部コラボレータ権限制御と組み合わさる）、visibility で発火を絞る理由がない
- GitHub API 呼び出しは不要。完全静的解析で完結する。`--quick` / `--offline`
  フラグの影響は受けない

### D8. 診断粒度は step 単位、span は `Span.point(0, 0, 0)`

- SEC005 と同じく step.with.ref に span が無いため 0 span にフォールバック
- 1 job に複数 checkout step がある場合は step ごとに 1 診断
- pinpoint 精度向上（with.ref span 追加）は parser / types 横断変更のため別 PR

### D9. テストは SEC005 パリティの 5 件

- (a) head_sha 検出 / (b) head_branch 検出 / (c) checkout なし no-FP /
  (d) ref なし no-FP / (e) 他 trigger no-FP
- SEC020 は config 分岐を含めて 14 件だが、本ルールは config 依存がないため
  5 件で網羅できる。将来 config 依存が増えた時点で追加する

## Consequences

- `workflow_run` ベースの build/test split パターンで false positive が出る可能性。
  `.zghalint.yml` で個別 disable / severity 下げが可能
- SEC 系の ID 採番が SEC009 → ... → SEC020 と非単調になるが、`docs/rules.md` と
  本 ADR の存在で混乱は避けられる
- SEC005 と SEC009 で「trigger 判定 + checkout step 走査 + with.ref 検査」の構造が
  重複する。1 ルール分なら許容範囲だが、3 つ目の同型ルールが増える際は
  ヘルパ抽出を検討する（本 PR スコープ外）

## 参考

- GitHub Security Lab: "Keeping your GitHub Actions and workflows secure Part 2:
  Untrusted input"（https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/）
- zizmor `dangerous-triggers` 相当のカバレッジ対称性
- poutine `pwn_request` ルール
