# 実施ロードマップ（2026-09-07 時点）

オープンな PR / issue を main（`015f8b5`）の実装状況と突き合わせ、以後の実施順序を示す。
経緯や前版との差分は git log と PR #130 / #207 の履歴に残しているため、本書には現在形の内容だけを書く。

## 1. 現状サマリ

| 項目 | 状態 |
|---|---|
| ルール数 | `docs/rules.md` の表は 87 行で `registry.all_rules` と一致。`src/docs_sync_test.zig`（#242）が ID の欠落・余剰を両方向でテストするようになり、RW001 の欠落も解消した。残る不一致は**見出しの「77 rules」だけ**（同期テストは ID 集合のみを見て本文の数字は見ない） |
| `src/**/*.zig` | 42,552 行 |
| ユニットテスト | 1530 件（`zig build test` 緑） |
| #55 actionlint parity | 54 sub-issue 中 **42 close 済み（77%）** |
| 型検査エンジン | T0〜T3 実装済み。T4（overlay 接続）は #129 で、PR #256 が実装中。引数型検査は #162 |
| E2E テスト | `src/e2e_test.zig` が `tests/fixtures/e2e/*.yml`（38 本）と `tests/fixtures/e2e-action/*.yml`（6 本）の `# zghalint:expect RULE@line` / `forbid` コメントを読んで検証 |
| PBT（`tests/pbt/`） | 42 個の `@given`、xfail 0 件。依存は固定済み（#235） |
| ファズ | `src/fuzz_test.zig` が YAML パーサと式パーサのターゲットを持ち、CI で回る（#241） |
| ADR | `docs/adr/0001`〜`0013`（0012 は RUNNER002 matrix 展開、0013 は RUNNER003） |
| オープン PR | #207（本ロードマップ）、#217（形式仕様とモデル検査）、#256（#129 の overlay 接続）、#249 / #252（Dependabot） |
| オープン issue | 21 件。内訳は #55 本体 1、#55 の sub-issue 14、parity ラベルだが sub でないもの 2（#162 #254）、形式検証由来のバグ 4（#221〜#224）、その他 2（#135 #159） |
| バージョン定義 | Zig の版は `build.zig.zon` の `minimum_zig_version` 一箇所が真。参照側の一覧と更新手順は `docs/maintenance.md`（#236） |
| 既知バグ | 形式検証由来の security 3 件（#218 / #219 / #220）は修正済みで close 済み。残る反例は #221 / #222（prefetch キャッシュ）、#223（`--fix` の原子性）、#224（二重報告）の 4 件 |

Phase 1（トリガー `on:` 群）と Phase 2（job / step / matrix）は完了済み。
Phase 3（contextual typing）も存在検証 4 本（#86 #87 #89 #90）が着地し、残るのは
overlay 接続（#129 = PR #256）と、その先の #162 / #91 / #92 だけになった。
Phase 4 も基盤の #100（action.yml メタデータ = ACT001〜ACT004）が入り、後続の複数ファイル横断ルールが着手可能になっている。
実装済みだったルール系 issue（#72 #73 #75 #86 #100 #124 #210 #218 #219 #220）は本回で close 済み。

リポジトリ運用・CI 基盤トラックは完了した。CI は fmt / build / test に加えて
クロスコンパイル・3 OS スモーク・自リポジトリの dogfooding・外部静的解析（actionlint / zizmor / shellcheck / ruff）・
ファズ・coverage を回し、release は provenance attestation とバイナリスモークを持つ。
該当 issue（#230 #234〜#244）12 件も本回で close 済みで、この track に残作業はない。

## 2. ロードマップ

原則:

- 1 issue = 1 PR = 1 ルール。TDD（Red → Green → Refactor）、完了時に `docs/rules.md` へ行追加
- 同一ファイル（`types.zig` / `parser.zig` / `security.zig`）を触る issue は直列にし、rebase 地獄を避ける
- 誤検出ゼロを優先。不確かなものは検出しない（ADR-0009 の方針を全ルールに適用）
- 新ルールは `src/rules/registry.zig` へ登録し、`tests/fixtures/e2e/` に `# zghalint:expect RULE@line` つきの fixture を 1 本足す。`docs/rules.md` の行を忘れると `src/docs_sync_test.zig` が落ちる

### Phase 1: トリガー `on:` 群 — 完了

SYN009（イベント名）/ SYN010（activity type）/ SYN011（イベント別フィルタ）は
`src/workflow/events.zig` の表に、SYN016 の IANA タイムゾーンは `src/workflow/timezones.zig` に、
SYN017 の `workflow_dispatch` inputs は `workflow/parser.zig` + `rules/syntax.zig` に入った。
cron（#70 / #71）と glob（#69）は `src/workflow/cron.zig` / `src/rules/glob.zig` として実装済み。
`events.zig` / `timezones.zig` の表は後続 Phase から再利用する。

### Phase 2: job / step / matrix — 完了

`Strategy` の matrix 構造は SYN018（#74）で `src/workflow/parser.zig` + `src/rules/syntax.zig` に入り、
SYN019（#75）の include / exclude 整合、RUNNER002 の matrix 展開（#210、ADR-0012）、
RUNNER003 のラベル衝突（#77、ADR-0013）が続けて着地した。
ラベル表は `src/rules/runner.zig` にあり、self-hosted のフリート表記は RUNNER002 / RUNNER003 とも対象外にしてある。
この matrix 構造は Phase 3 の EXPR011 がそのまま使っている。

### Phase 3: contextual typing（エンジン T4 = #129）— 残り 4 件

存在検証は 4 本とも実装済み。式の走査は `src/rules/expr_scan.zig` に切り出され、
各 context ルールは同じ形（`<context>_context.zig`）で並んでいる。

| ルール | issue | 実装 | 状態 |
|---|---|---|---|
| EXPR010 `steps.<id>` | #86 | `src/rules/steps_ref.zig` | 完了（close 済み） |
| EXPR011 `matrix.<key>` | #87 | `src/rules/matrix_context.zig` | 完了 |
| EXPR012 `needs.<job>` | — | `src/rules/needs_context.zig` | 完了 |
| EXPR013 `inputs.<name>` | #89 | `src/rules/inputs_context.zig` | 完了 |
| EXPR014 `secrets.<name>` | #90 | `src/rules/secrets_context.zig` | 完了 |
| EXPR017 curated `github.event` overlay | #124 | `src/rules/expr_catalog.zig` | 完了（close 済み） |

残りの着手順:

| 順 | issue | 内容 | 依存 |
|---|---|---|---|
| 1 | #129 | T4: 存在検証 5 本を `expr_check.zig` の `TypeEnv` overlay に接続し、エンジン側へ寄せる | **PR #256 で実装中**。ADR-0009 の二重メンテ期間を閉じる |
| 2 | #162 | EXPR018 関数の引数型と補間値（object / array / null）の型検査 | #129。loose object（overlay 未接続の context）は診断しない |
| 3 | #91 | EXPR015 キーごとの context 利用可否 | 式を検証する箇所に「どのキーか」を渡す配線が必要 |
| 4 | #92 | EXPR016 特殊関数の利用可否 | #91 の配線 |

### Phase 4: action.yml / reusable workflow（複数ファイル横断）

基盤の #100 が着地した。`src/rules/action_metadata.zig` が ACT001〜ACT004（必須キー / `runs.using` /
未知キー / 定義の型）を見て、`tests/fixtures/e2e-action/` が fixture を持つ。
残りは「他ファイルを読む」ローダーが共通基盤で、`action.yml` ローダーと `workflow_call` ローダーを 1 つのモジュールにまとめる。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #254 | composite の `runs.steps` に既存の step ルールと式検証を適用する | #100。今のメタデータ検証は steps の中身を見ていない |
| 2 | #96 | DEP004 ローカルアクション inputs | #100 のローダー。`uses` 形式の検証は DEP003（`src/rules/uses.zig`）を再利用 |
| 3 | #99 | BP003 拡張 node12 / node16 | ローカルは #100、リモートは `prefetch.zig` 経由で `action.yml` を取得（オフライン時はスキップ） |
| 4 | #105 | RW002 required inputs 欠落 | ローカル reusable workflow ローダー（#100 と同モジュール）+ `reusable_workflow.zig` |
| 5 | #106 | RW003 未定義 inputs / 型不整合 | #105 |
| 6 | #107 | RW004 secrets | #105 |
| 7 | #108 | RW005 outputs 実在 | #105 + #88 |
| 8 | #97 | DEP005 popular actions inputs | 埋め込みデータセット（`scripts/` で生成）。バイナリサイズを計測してから採否を決める |
| 9 | #98 | DEP006 非推奨 inputs | #97 のデータセット |

### 並行トラック

| 項目 | 位置づけ |
|---|---|
| #135 SC007 typosquat 検出 | `docs/design/sc007-typosquat-design.md` で設計済み。`src/rules/data/trusted_actions.zig` を追加しオフラインで完結するので、他と完全に並列可 |
| #159 rule engine の arena 提供 | `expressions.zig` の `getArenaAllocator` が `page_allocator` を返して意図的にリークしている。`engine.zig` がルール実行単位の arena を配り、`impostor.zig` の同名関数と意味を揃える。`engine.zig` の `Rule` シグネチャに触るので、ルール追加が続く Phase 3〜4 の**前**に済ませると衝突が少ない |
| 形式検証由来の残バグ #221〜#224 | security 3 件（#218 / #219 / #220）は修正済み。残りは #221 / #222 が prefetch キャッシュ（ウォームランが成立しない・RateLimited の劣化）、#223 が `--fix` の原子性、#224 が二重報告。いずれも `src/rules/` の外なのでルール実装と並行できる |
| PR #217 形式仕様 | Alloy（ルール所有権）と TLA+（prefetch / autofix）の仕様と反例。#218〜#224 の出所。マージすれば以後の反例追加が同じ場所に載る |
| リポジトリ運用・CI 基盤（旧 #230 #234〜#244） | 12 件すべて実装済み・close 済み（Dependabot / PBT 依存固定 / Zig 版一元化 / coverage / concurrency / 外部静的解析 / ファズ / 自リポジトリ dogfooding / action.yml スモーク / メタファイル / release provenance / タグ整合 / `docs/rules.md` 同期テスト）。track として終了 |
| #64 YAML anchor / alias / merge key | パーサ基盤。GitHub Actions が anchor をサポートしたため実用価値あり。`yaml/parser.zig` の整理を Tidy First で先に行い、PBT にラウンドトリップ / 循環参照テストを追加する |

## 3. 直近の着手順（上位 5 件）

| 順 | 対象 | 理由 |
|---|---|---|
| 1 | #129（PR #256） | Phase 3 の締め。存在検証 5 本を overlay に寄せ、ADR-0009 の二重メンテを終わらせる。#162 の前提でもある |
| 2 | `docs/rules.md` の見出し修正 | 表は 87 行で registry と同期済みなのに、見出しが「77 rules」のまま。#242 の同期テストは ID 集合しか見ないので本文の数字は守られない |
| 3 | #159 | エンジンの arena。Phase 4 でルール追加が再び集中する前に `Rule` シグネチャを固める |
| 4 | #254 | composite の `runs.steps` を既存ルールに通す。#100 の基盤がそのまま使え、Phase 4 の他ルールより依存が浅い |
| 5 | #221 / #222 | prefetch キャッシュ。ウォームランが成立しないのは実利用のレイテンシに直結する |

#129 → #162 → #91 → #92 で Phase 3 を閉じ、Phase 4 は #254 → #96 → #105 の順で
ローダー基盤を育てる。#135 / #64 / #221〜#224 は競合しないので並行で流す。

## 4. 進め方の注意

- Phase 4 は `types.zig` の拡張を伴うため、同 Phase 内は直列にする
- エージェント PR は CI 緑でもマージ前に main へ rebase する
- ルールを追加・変更したら `tests/fixtures/e2e/`（ワークフロー）または `tests/fixtures/e2e-action/`（action.yml）に fixture を足し、`# zghalint:expect RULE@line` で行まで含めてアサートする
- `docs/rules.md` への行追加は任意ではない。`src/docs_sync_test.zig` が registry との ID 差分でビルドを落とす
- 新ルールのテストは `Step` / `Job` を手で組まず、`src/test_support.zig` の `parseWorkflowSource`（YAML から `Workflow` を起こす）と `lintAndFix`（リント + autofix を 1 度に検証）を使う。`runStep` / `runJob` / `runWorkflow` は `security.zig` にあるファイル内ヘルパーなので、他ファイルからは呼べない
- 式を走査するルールは `src/rules/expr_scan.zig` を使う。`${{ }}` の切り出しを各ルールで書き直さない
- autofix を伴うルールは、フロースタイル（`{}` / `[]`）とブロックスカラー（`|` / `>`）の入力を必ずテストに含める（#171 / #172 はどちらもこの 2 形式の抜けだった）。`tests/pbt/strategies.py` に両形式の strategy があるので PBT 側にも足す
- CRLF のワークフローも入力になる（Windows CI で顕在化した）。行末を跨ぐ処理を書いたら `\r` を落とす経路を確認する
- 深い再帰を持つパーサには上限を入れる（YAML は `max_parse_depth = 256`、式は `max_expr_depth = 256`）。新しい再帰下降を書いたら同じガードを必ず付ける
- 実装が終わったら `/wrapup`（`.claude/skills/wrapup`）で正しさ・過剰設計・コメントの 3 点を見てからコミットする。コメントは「コードから復元できない why」だけ残す（`/cleanup-comments` の基準）
- 各 Phase 完了時に `docs/rules.md` のルール数と #55 の進捗を確認する
- Zig の版を上げるときは `build.zig.zon` の `minimum_zig_version` だけを触る。CI / release / `scripts/setup-zig.sh` はそこから読むので、他所に版を書かない（`docs/maintenance.md`）
- `zig build` は build.zig 一本で、`scripts/setup-zig.sh` の wrapper は `-fllvm` 注入のみ。**古い wrapper が `/usr/local/bin/zig` に残っていると `no module named 'build_options'` でビルドが落ちる**。main を取り込んだら `bash scripts/setup-zig.sh` を流し直す
