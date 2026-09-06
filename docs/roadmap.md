# 実施ロードマップ（2026-09-06 時点）

オープンな PR / issue を main（`0ccf6d0`）の実装状況と突き合わせ、以後の実施順序を示す。
経緯や前版との差分は git log と PR #130 の履歴に残しているため、本書には現在形の内容だけを書く。

## 1. 現状サマリ

| 項目 | 状態 |
|---|---|
| ルール数（`docs/rules.md`） | 62 |
| `src/**/*.zig` | 29,818 行 |
| ユニットテスト | 1161 件（`zig build test` 緑） |
| #55 actionlint parity | 54 sub-issue 中 **20 close 済み（37%）** |
| 型検査エンジン | T0〜T3 実装済み。T4（overlay 接続）は #129、引数型検査は #162 |
| E2E テスト | `src/e2e_test.zig` が `tests/fixtures/e2e/*.yml` の `# zghalint:expect RULE@line` / `forbid` コメントを読んで検証 |
| ADR | `docs/adr/0001`〜`0010`（最新は 0010 SEC022） |
| PBT（`tests/pbt/`） | xfail 0 件 |
| オープン PR | #130（本ロードマップ）のみ |
| オープン issue | 43 件。内訳は #55 本体 1、parity sub-issue 34、それ以外 8（#124 #134 #135 #158 #159 #160 #161 #162） |
| 既知バグ | なし。#143（`workflow_run` 信頼ゲート）は SEC022 で、#136（SYN002 / SYN005 二重報告）は SYN002 の `jobs:` 除外で解消済み。いずれも main のバイナリで確認 |

## 2. 直近で解決した検出漏れ

### 2.1 SEC022 — `workflow_run` の信頼ゲート（#143）

`on: workflow_run` は base リポジトリの secrets を持つ privileged コンテキストで走るのに、
`head_branch` は fork 側が自由に名付けられる。`if: github.event.workflow_run.head_branch == 'main'`
のようなゲートは信頼の根拠にならない。#138 で SEC006 が ref 形状のコンテキストを条件から外して以降、
このパターンを報告するルールが無かった。

SEC022 `workflow-run-branch-gate` として実装済み（PR #165、ADR-0010）。設計上の要点:

- 検出対象は `on: workflow_run` のジョブ / ステップの `if:` に限定する
- `head_repository.*` か `workflow_run.event == 'push'` が**等値比較のオペランド**として現れる条件は
  trust anchor とみなして抑制する。`!=` は fork 側を選ぶ比較なので anchor に数えない
- job 条件に anchor があれば配下の step は抑制する
- SEC006 の `condition_dangerous_contexts` は変更していない。責務境界は `docs/rules.md` の
  「SEC022 vs. SEC006」節に記載

### 2.2 オープン PR

#130（本ロードマップ、docs のみ）だけ。#143 の下準備だった PR #151（`findAnyContext` 抽出）は
main が `reportConditionContexts` に集約する別方向へ進んだため、移植すべき差分なしとして close 済み。

## 3. ロードマップ

原則:

- 1 issue = 1 PR = 1 ルール。TDD（Red → Green → Refactor）、完了時に `docs/rules.md` へ行追加
- 同一ファイル（`types.zig` / `parser.zig` / `security.zig`）を触る issue は直列にし、rebase 地獄を避ける
- 誤検出ゼロを優先。不確かなものは検出しない（ADR-0009 の方針を全ルールに適用）
- 新ルールは `src/rules/registry.zig` へ登録し、`tests/fixtures/e2e/` に `# zghalint:expect RULE@line` つきの fixture を 1 本足す

### Phase 1: 依存なし・小粒

`types.zig` を触らず、既存の走査ループにチェックを足すだけで済むもの。

| 順 | issue | 内容 | 触る主なファイル |
|---|---|---|---|
| 1 | #85 | EXPR009 fromJSON リテラルの JSON 妥当性 | `expressions.zig`。JSON 妥当性チェッカは `src/rules/json_util.zig` に置く |
| 2 | #84 | EXPR008 format() のプレースホルダ整合 | `expressions.zig` |
| 3 | #83 | EXPR007 拡張: 定数条件 / `${{ }}` 外の文字 | `expressions.zig` |
| 4 | #158 | EXPR007 autofix: bare number_literal | `expressions.zig` の `buildExpr007Fix`。#83 と同じ関数群なので直後に処理する |
| 5 | #104 | RW001 workflow_call inputs type | `parser.zig` の `parseInputDefs`（単一ファイルで完結する RW 唯一の項目） |
| 6 | #160 | SC008 `compareRest` を `rest_fallback.zig` へ移す | Tidy First の構造的変更のみ。挙動不変 |
| 7 | #161 | EXPR004 / 型検査の関数名 lookup を case-insensitive にするか決める | オーナーの判断が要る。case-insensitive にするなら `expr_catalog.zig` の比較を ASCII case-insensitive にするだけ |

### Phase 2: トリガー `on:` 群

`ScheduleEntry` / `EventConfig` の拡張を伴うため直列。イベント名テーブルと cron パーサを先に作り、後続で再利用する。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #70 | SYN014 CRON 構文 | cron パーサを `workflow/cron.zig` に新設。自己完結でテストしやすく、Phase 2 の入口に向く |
| 2 | #71 | SYN015 5 分未満 | #70 のパーサ。#70 と同一 PR に載せてよい |
| 3 | #69 | SYN013 glob 構文 | なし。独立して着手可 |
| 4 | #65 | SYN009 webhook イベント名（+ `util.didYouMean` で候補提示） | イベント名 / activity type の埋め込みテーブルを新設 |
| 5 | #66 | SYN010 `types` 値 | #65 のテーブル |
| 6 | #67 | SYN011 イベントで使えないフィルタ | #65 のテーブル。SYN012 で `EventFilter` の key span は記録済み |
| 7 | #72 | SYN016 timezone | `ScheduleEntry.timezone` 追加 + IANA 名テーブル（`scripts/` で生成、`src/rules/data/` に置く） |
| 8 | #73 | SYN017 workflow_dispatch inputs | #129 の `github.event.inputs` overlay と同時に実装 |

### Phase 3: job / step / matrix

`Strategy` 型の拡張（matrix 軸・include / exclude の保持）が起点。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #74 | SYN018 matrix 値重複 | `Strategy` に matrix 構造を追加 |
| 2 | #75 | SYN019 include / exclude 整合 | #74 |
| 3 | #76 | RUNNER002 未知ラベル | RUNNER001 のラベルデータを既知ラベル一覧に拡張。`.zghalint.yml` に self-hosted ラベル許可設定が要る |
| 4 | #77 | RUNNER003 ラベル衝突 | #76 |

### Phase 4: contextual typing（エンジン T4 = #129）

各 issue で「存在検証」を実装し、最後に `TypeEnv` overlay へ接続する（ADR-0009 の二重メンテ期間を短くするため Phase 4 内で一気に片付ける）。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #86 | EXPR010 `steps.<id>` | なし |
| 2 | #88 | EXPR012 `needs.<job>.outputs` | なし |
| 3 | #89 | EXPR013 `inputs.<name>` | #73（SYN017 の inputs 構造） |
| 4 | #87 | EXPR011 `matrix.<key>` | #74（matrix 構造） |
| 5 | #90 | EXPR014 `secrets.<name>` | #104（workflow_call secrets の定義） |
| 6 | #129 | T4: 上記を `expr_check.zig` の overlay に接続し、存在検証をエンジン側に寄せる | #86〜#90 |
| 7 | #162 | EXPR018 関数の引数型と補間値（object / array / null）の型検査 | #129。loose object（overlay 未接続の context）は診断しない |
| 8 | #91 | EXPR015 キーごとの context 利用可否 | 式を検証する箇所に「どのキーか」を渡す配線が必要 |
| 9 | #92 | EXPR016 特殊関数の利用可否 | #91 の配線 |
| 10 | #124 | curated scalar overlay（`github.event.issue.number: number` 等） | EXPR017 の到達範囲拡大 |

### Phase 5: action.yml / reusable workflow（複数ファイル横断）

「他ファイルを読む」仕組みが共通基盤。`action.yml` ローダーと `workflow_call` ローダーを 1 つのモジュールにまとめる。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #100 | 基盤: action.yml をリント対象化 + メタデータ構文 | `main.zig` の対象判定拡張、`workflow/action_meta.zig` 新設 |
| 2 | #96 | DEP004 ローカルアクション inputs | #100 のローダー |
| 3 | #99 | BP003 拡張 node12 / node16 | ローカルは #100、リモートは `prefetch.zig` 経由で `action.yml` を取得（オフライン時はスキップ） |
| 4 | #105 | RW002 required inputs 欠落 | ローカル reusable workflow ローダー（#100 と同モジュール） |
| 5 | #106 | RW003 未定義 inputs / 型不整合 | #105 |
| 6 | #107 | RW004 secrets | #105 |
| 7 | #108 | RW005 outputs 実在 | #105 + #88 |
| 8 | #97 | DEP005 popular actions inputs | 埋め込みデータセット（`scripts/` で生成）。バイナリサイズを計測してから採否を決める |
| 9 | #98 | DEP006 非推奨 inputs | #97 のデータセット |

### 並行トラック

| 項目 | 位置づけ |
|---|---|
| #134 SEC021 untrusted checkout ref | #55 の対象外。ADR-0006 と `docs/design/sec021-untrusted-checkout-ref-design.md` で設計済み・未実装。SEC022（§2.1）と同じ `security.zig` の `workflow_run` 周辺（`checkWorkflowRunUntrustedCheckout` / `reportConditionContexts`）を触るので、記憶が新しいうちに着手する |
| #135 SC007 typosquat 検出 | `docs/design/sc007-typosquat-design.md` で設計済み。`src/rules/data/trusted_actions.zig` を追加しオフラインで完結するので、他と完全に並列可 |
| #159 rule engine の arena 提供 | `expressions.zig` の `getArenaAllocator` が `page_allocator` を返して意図的にリークしている。`engine.zig` がルール実行単位の arena を配り、`impostor.zig` の同名関数と意味を揃える。`engine.zig` の `Rule` シグネチャに触るので、ルール追加が集中する Phase 2〜4 の**前**に済ませると衝突が少ない |
| #64 YAML anchor / alias / merge key | パーサ基盤。GitHub Actions が anchor をサポートしたため実用価値あり。`yaml/parser.zig` の整理を Tidy First で先に行い、PBT にラウンドトリップ / 循環参照テストを追加する |
| `docs/design/pbt-strategy.md` #3〜#5 | xfail は解消済み。新ルールが増えるたびに detection PBT を横展開する |

## 4. 直近の着手順（上位 10 件）

| 順 | issue | 理由 |
|---|---|---|
| 1 | #134 | SEC022 の直後で `security.zig` の `workflow_run` 経路が頭に入っている。設計済み |
| 2 | #135 | 設計済み・オフライン完結・他と非競合。並列で流せる |
| 3 | #159 | エンジンの arena。ルール追加が本格化する前に `Rule` シグネチャを固める |
| 4 | #85 → #84 → #83 → #158 | `expressions.zig` の小粒 4 件。同一ファイルなので直列にまとめて処理 |
| 5 | #70 + #71 | cron パーサを 1 本書けば 2 件。自己完結でテストしやすい |
| 6 | #69 | glob パーサ。#70 と独立なので並列可 |
| 7 | #65 | イベント名テーブルを作る。これが入ると #66 / #67 が同じ表の上に乗り 3 件まとまる |
| 8 | #104 | RW001。単一ファイルで完結し、Phase 4 の #90 と Phase 5 の RW 群の前提になる |
| 9 | #160 + #161 | 隙間で処理する tidy と判断事項。#161 はオーナーの決定待ち |
| 10 | #129 | 最大の山。#86〜#89 の 4 件が一気に解ける。5〜8 で足場を固めてから着手し、続けて #162 |

## 5. 進め方の注意

- #134 は SEC022 と同じ `security.zig` の `workflow_run` 経路を触るので、他の `security.zig` 変更とは直列にする。それ以外の Phase 1 は並列に走らせられる
- Phase 2 以降は `types.zig` の拡張を伴うため、同 Phase 内は直列にする
- エージェント PR は CI 緑でもマージ前に main へ rebase する
- ルールを追加・変更したら `tests/fixtures/e2e/` に fixture を足し、`# zghalint:expect RULE@line` で行まで含めてアサートする（インラインテストだけでは `Step` 構造体を直接組み立ててパーサを通らない経路が残る）
- 新ルールのテストは自前でワークフローを組み立てず、`src/test_support.zig` の `parseWorkflowSource` / `runStep` / `runJob` / `runWorkflow` を使う
- 実装が終わったら `/wrapup`（`.claude/skills/wrapup`）で正しさ・過剰設計・コメントの 3 点を見てからコミットする。コメントは「コードから復元できない why」だけ残す（`/cleanup-comments` の基準）
- 各 Phase 完了時に `docs/rules.md` のルール数と #55 の進捗を確認する
- `zig build` は build.zig 一本で、`scripts/setup-zig.sh` の wrapper は `-fllvm` 注入のみ。**古い wrapper が `/usr/local/bin/zig` に残っていると `no module named 'build_options'` でビルドが落ちる**。main を取り込んだら `bash scripts/setup-zig.sh` を流し直す
