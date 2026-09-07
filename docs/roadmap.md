# 実施ロードマップ（2026-09-07 時点）

オープンな PR / issue を main（`5fc66a7`）の実装状況と突き合わせ、以後の実施順序を示す。
経緯や前版との差分は git log と PR #130 / #207 の履歴に残しているため、本書には現在形の内容だけを書く。

## 1. 現状サマリ

| 項目 | 状態 |
|---|---|
| ルール数 | 表は 79 行、見出しは 77 のまま。**不一致**（SYN019 / RUNNER003 の行追加時に見出しを更新し忘れ）。RW001 が表に無い件と併せて #242 が同期テストを起票済み |
| `src/**/*.zig` | 39,635 行 |
| ユニットテスト | 1444 件（`zig build test` 緑） |
| #55 actionlint parity | 54 sub-issue 中 **34 close 済み（63%）** |
| 型検査エンジン | T0〜T3 実装済み。T4（overlay 接続）は #129、引数型検査は #162 |
| E2E テスト | `src/e2e_test.zig` が `tests/fixtures/e2e/*.yml`（33 本）の `# zghalint:expect RULE@line` / `forbid` コメントを読んで検証 |
| PBT（`tests/pbt/`） | 42 個の `@given`、xfail 0 件。#170 / #171 / #172 の回帰 strategy を収録済み |
| ADR | `docs/adr/0001`〜`0013`（0012 は RUNNER002 matrix 展開、0013 は RUNNER003） |
| オープン PR | #207（本ロードマップ）、#217（形式仕様とモデル検査）、#246（CI 基盤 / #234〜#239） |
| オープン issue | 50 件。内訳は #55 本体 1、#55 の sub-issue 20、形式検証由来のバグ残 4（#221〜#224）、リポジトリ運用・CI 基盤 17（#228〜#244）、その他 8 |
| 実装済みだが未 close の issue | **#72 / #73 / #75 / #86 / #210 / #218 / #219 / #220**（いずれも main に実装が入っているのに issue が open のまま。棚卸しの最大のノイズ源） |
| 既知バグ | 形式検証由来の security 3 件（#218 / #219 / #220）は **修正済み**（issue は未 close）。未修正は #221〜#224 と #229（BP007 誤検知）/ #232（release.yml のランナー不一致） |

Phase 1（トリガー `on:` 群）と Phase 2（job / step / matrix）はどちらも完了した。
形式検証が出した security 3 件（#218 / #219 / #220）も修正済みで、残る反例は #221〜#224 の 4 件。
主線は **Phase 3（contextual typing）** に移り、#87 / #89 は依存が解けて即着手できる状態にある。

一方で、リポジトリ運用・CI 基盤の issue が 17 件（#228〜#244）新たに起票された。
ルール実装とはファイルが重ならない（`.github/` と `docs/` 中心）ので並行トラックとして扱うが、
#228（自リポジトリの dogfooding）と #242（`docs/rules.md` と `registry.all_rules` の同期テスト）は
本書の棚卸しコストを直接下げるので優先度を上げる。

## 2. ロードマップ

原則:

- 1 issue = 1 PR = 1 ルール。TDD（Red → Green → Refactor）、完了時に `docs/rules.md` へ行追加
- 同一ファイル（`types.zig` / `parser.zig` / `security.zig`）を触る issue は直列にし、rebase 地獄を避ける
- 誤検出ゼロを優先。不確かなものは検出しない（ADR-0009 の方針を全ルールに適用）
- 新ルールは `src/rules/registry.zig` へ登録し、`tests/fixtures/e2e/` に `# zghalint:expect RULE@line` つきの fixture を 1 本足す

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
この matrix 構造は Phase 3 の EXPR011（#87）がそのまま使う。

### Phase 3: contextual typing（エンジン T4 = #129）

EXPR010（`src/rules/steps_ref.zig`）と EXPR012（`src/rules/needs_context.zig`）は実装済み。
残りの存在検証を同じ形で足し、最後に `TypeEnv` overlay へ接続する（ADR-0009 の二重メンテ期間を短くするため Phase 3 内で一気に片付ける）。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #89 | EXPR013 `inputs.<name>` | SYN017（#73）で入った `workflow_dispatch` inputs 構造を使う |
| 2 | #87 | EXPR011 `matrix.<key>` | Phase 2 で入った matrix 構造を使う（着手可能） |
| 3 | #90 | EXPR014 `secrets.<name>` | RW001（#104）で入った `workflow_call` の定義構造を使う |
| 4 | #129 | T4: 存在検証（`steps_ref.zig` / `needs_context.zig` + #87 #89 #90）を `expr_check.zig` の overlay に接続し、エンジン側に寄せる | #87 / #89 / #90 |
| 5 | #162 | EXPR018 関数の引数型と補間値（object / array / null）の型検査 | #129。loose object（overlay 未接続の context）は診断しない |
| 6 | #91 | EXPR015 キーごとの context 利用可否 | 式を検証する箇所に「どのキーか」を渡す配線が必要 |
| 7 | #92 | EXPR016 特殊関数の利用可否 | #91 の配線 |
| 8 | #124 | curated scalar overlay（`github.event.issue.number: number` 等） | EXPR017 の到達範囲拡大 |

### Phase 4: action.yml / reusable workflow（複数ファイル横断）

「他ファイルを読む」仕組みが共通基盤。`action.yml` ローダーと `workflow_call` ローダーを 1 つのモジュールにまとめる。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #100 | 基盤: action.yml をリント対象化 + メタデータ構文 | `main.zig` の対象判定拡張、`workflow/action_meta.zig` 新設 |
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
| #159 rule engine の arena 提供 | `expressions.zig` の `getArenaAllocator`（:1009）が `page_allocator` を返して意図的にリークしている。`engine.zig` がルール実行単位の arena を配り、`impostor.zig` の同名関数と意味を揃える。`engine.zig` の `Rule` シグネチャに触るので、ルール追加が集中する Phase 1〜3 の**前**に済ませると衝突が少ない |
| 形式検証由来の残バグ #221〜#224 | security 3 件（#218 / #219 / #220）は修正済み。残りは #221 / #222 が prefetch キャッシュ（ウォームランが成立しない・RateLimited の劣化）、#223 が `--fix` の原子性、#224 が二重報告。いずれも `src/rules/` の外なのでルール実装と並行できる |
| その他のバグ #229 / #232 | #229 は BP007 が行継続（`\`）の続き行を誤検知する。#232 は `release.yml` の macOS ランナーが `macos-latest` のままで `ci.yml` と不一致 |
| リポジトリ運用・CI 基盤 #228〜#244（17 件） | `.github/` と `docs/` 中心でルール実装とファイルが重ならない。#246 が #234〜#239 をまとめて対応中。**#228（自リポジトリを zghalint で lint する dogfooding）と #242（`docs/rules.md` と `registry.all_rules` の同期テスト）を先に通す** — 本書の棚卸しで毎回手で数えている数字が自動で守られる |
| #64 YAML anchor / alias / merge key | パーサ基盤。GitHub Actions が anchor をサポートしたため実用価値あり。`yaml/parser.zig` の整理を Tidy First で先に行い、PBT にラウンドトリップ / 循環参照テストを追加する。#172 / #173 の修正が入って同ファイルが落ち着いたので、着手可能になった |

## 3. 直近の着手順（上位 6 件）

| 順 | 対象 | 理由 |
|---|---|---|
| 1 | 実装済み issue の close（#72 #73 #75 #86 #210 #218 #219 #220） | コードは main にあるのに 8 件が open のまま。棚卸しのたびに実装状況を手で突き合わせる原因になっており、コスト 0 で解消できる |
| 2 | #242 | `docs/rules.md` と `registry.all_rules` の同期テスト。表 79 行・見出し 77・RW001 欠落という現状の不一致がそのまま再発防止になる |
| 3 | #159 | エンジンの arena。Phase 3 でルール追加が集中する前に `Rule` シグネチャを固める |
| 4 | #87 | Phase 2 の matrix 構造が入ったので即着手できる。#129 の overlay 材料も揃う |
| 5 | #89 | SYN017 の inputs 構造を使う。#87 と同じ contextual typing の形なので連続して書ける |
| 6 | #228 | 自リポジトリの dogfooding。#229 / #232 のような自前ワークフローの不備を CI で拾えるようになる |

#90 → #129 → #162 と Phase 3 を進め、#135 / #64 / #221〜#224 は競合しないので並行で流す。
Phase 1・Phase 2 が終わったので、以後は contextual typing（Phase 3）が主線、
リポジトリ運用・CI 基盤（#228〜#244）が並行トラックという二本立てになる。

## 4. 進め方の注意

- Phase 1 以降は `types.zig` の拡張を伴うため、同 Phase 内は直列にする
- エージェント PR は CI 緑でもマージ前に main へ rebase する
- ルールを追加・変更したら `tests/fixtures/e2e/` に fixture を足し、`# zghalint:expect RULE@line` で行まで含めてアサートする（インラインテストだけでは `Step` 構造体を直接組み立ててパーサを通らない経路が残る）
- 新ルールのテストは `Step` / `Job` を手で組まず、`src/test_support.zig` の `parseWorkflowSource`（YAML から `Workflow` を起こす）と `lintAndFix`（リント + autofix を 1 度に検証）を使う。`runStep` / `runJob` / `runWorkflow` は `security.zig` にあるファイル内ヘルパーなので、他ファイルからは呼べない
- autofix を伴うルールは、フロースタイル（`{}` / `[]`）とブロックスカラー（`|` / `>`）の入力を必ずテストに含める（#171 / #172 はどちらもこの 2 形式の抜けだった）。`tests/pbt/strategies.py` に両形式の strategy があるので PBT 側にも足す
- 深い再帰を持つパーサには上限を入れる（YAML は `max_parse_depth = 256`、式は `max_expr_depth = 256`）。新しい再帰下降を書いたら同じガードを必ず付ける
- 実装が終わったら `/wrapup`（`.claude/skills/wrapup`）で正しさ・過剰設計・コメントの 3 点を見てからコミットする。コメントは「コードから復元できない why」だけ残す（`/cleanup-comments` の基準）
- 各 Phase 完了時に `docs/rules.md` のルール数と #55 の進捗を確認する
- `zig build` は build.zig 一本で、`scripts/setup-zig.sh` の wrapper は `-fllvm` 注入のみ。**古い wrapper が `/usr/local/bin/zig` に残っていると `no module named 'build_options'` でビルドが落ちる**。main を取り込んだら `bash scripts/setup-zig.sh` を流し直す
