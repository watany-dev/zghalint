# 実施ロードマップ（2026-09-06 時点）

オープンな PR / issue を main（`a5dbf5f`）の実装状況と突き合わせ、以後の実施順序を示す。
経緯や前版との差分は git log と PR #130 の履歴に残しているため、本書には現在形の内容だけを書く。

## 1. 現状サマリ

| 項目 | 状態 |
|---|---|
| ルール数 | 68（`docs/rules.md` の表の行数。本文の見出しが `63 rules` のまま止まっているので要修正） |
| `src/**/*.zig` | 33,728 行 |
| ユニットテスト | 1310 件（`zig build test` 緑） |
| #55 actionlint parity | 54 sub-issue 中 **26 close 済み（48%）** |
| 型検査エンジン | T0〜T3 実装済み。T4（overlay 接続）は #129、引数型検査は #162 |
| E2E テスト | `src/e2e_test.zig` が `tests/fixtures/e2e/*.yml`（19 本）の `# zghalint:expect RULE@line` / `forbid` コメントを読んで検証 |
| PBT（`tests/pbt/`） | 42 個の `@given`、xfail 0 件。#170 / #171 / #172 の回帰 strategy を収録済み |
| ADR | `docs/adr/0001`〜`0010` |
| オープン PR | #130（本ロードマップ）、#190（#170〜#173 の修正計画書。実装が先に入ったため扱いの判断が要る） |
| オープン issue | 42 件。内訳は 実装済み未 close 8、#55 本体 1、parity ラベル 28、それ以外 5（#124 #135 #159 #191 #192） |
| 既知バグ | **なし**。#170〜#173 はすべて main で修正済み（§2 で再現確認済み） |

## 2. 実装済みだが未 close の issue（8 件）

main に実装が入っているのに issue が開いたままのもの。棚卸しして close する。
バグ 4 件は今回、main のバイナリで修正済みであることを実地確認した。

| issue | 実装 | 確認方法・確認箇所 |
|---|---|---|
| #170 式パーサのスタックオーバーフロー | PR #205 | `expressions.zig` に `max_expr_depth = 256` と `ExprParser.depth`。`${{ }}` を 20,000 段ネストさせても SIGSEGV せず exit 1。`tests/pbt/test_crash.py` の `deeply_nested_expression` で回帰 |
| #172 ブロックスカラー直後の autofix 挿入位置 | PR #205 | `yaml/parser.zig` の `blockEntryFullSpan` がブロックスカラーを分岐。`runs-on: \|` に対する `--fix-unsafe` が `permissions:` / `timeout-minutes:` を正しい位置に入れる |
| #171 フロースタイル `with:` の破壊 | PR #205 | `workflow/parser.zig:744` で `with_last_entry_end_byte` をブロックマッピング + インラインスカラーの場合だけ設定。`with: {fetch-depth: 0}` に `--fix-unsafe` しても書き換えない |
| #173 行継続エスケープ以降の行番号ずれ | PR #205 | `yaml/tokenizer.zig` の `consumeNewline` 抽出。fixture `bp004-shell-after-quoted-continuation.yml` が行 18 をアサート |
| #134 SEC021 untrusted checkout ref | PR #174 | `security.zig:1670` に `.id = "SEC021"`、fixture `sec021-untrusted-checkout-ref.yml` |
| #104 RW001 workflow_call inputs type | PR #178 | `src/rules/reusable_workflow.zig`（新設）、fixture `rw001-workflow-call-inputs.yml` |
| #160 SC008 `compareRest` の移設 | PR #178 | `rest_fallback.zig:244` に `pub fn compareRest`。`impostor_compare.zig` から消えている |
| #161 関数名 lookup の case-insensitive 化 | PR #178 | `expr_type.zig:66` が `std.ascii.eqlIgnoreCase` で引く。actionlint 互換の方向で決着 |

PR #190 は #170〜#173 の修正計画書だが、計画より先に PR #205 で実装が入った。
内容を設計記録として残すなら実装後の形に直し、残さないなら close する。

## 3. パフォーマンス: 出力層の残り 2 件

#182〜#202 の 21 件はすでに main へ入り、残っているのは出力層の 2 件だけである。
どちらも診断件数に比例して効くため、大きなワークフロー群を回す CI で体感差が出る。

### 3.1 #192 terminal 出力が JSON の 2 倍遅い

`src/output/terminal.zig` の `writeSanitized` が ASCII の通常文字も 1 バイトずつ `writeByte` する。
安全な連続区間をまとめて `writeAll` する形に変えれば、サニタイズが必要なバイトだけ個別処理で済む。
出力層だけで 130M Ir（1.108s vs JSON の 0.575s）。

### 3.2 #191 JSON 出力の Stringify コスト

`src/output/json.zig` が診断ごとに `std.json.Stringify` を回し、`encodeJsonString` と memcpy で 16% を消費する。
stdout バッファも 4KB のまま。バッファ拡大とエスケープ不要文字列の高速パスが要る。

## 4. ロードマップ

原則:

- 1 issue = 1 PR = 1 ルール。TDD（Red → Green → Refactor）、完了時に `docs/rules.md` へ行追加
- 同一ファイル（`types.zig` / `parser.zig` / `security.zig`）を触る issue は直列にし、rebase 地獄を避ける
- 誤検出ゼロを優先。不確かなものは検出しない（ADR-0009 の方針を全ルールに適用）
- 新ルールは `src/rules/registry.zig` へ登録し、`tests/fixtures/e2e/` に `# zghalint:expect RULE@line` つきの fixture を 1 本足す

### Phase 1: 棚卸しと出力層 perf

| 順 | 対象 | 内容 |
|---|---|---|
| 1 | #170 / #171 / #172 / #173 / #134 / #104 / #160 / #161 | §2 の 8 件を close。PR #190 の扱いも同時に決める |
| 2 | `docs/rules.md` | 見出しのルール数を 63 → 68 に直す |
| 3 | #192 | `writeSanitized` を区間まとめ書きにする |
| 4 | #191 | JSON 出力の Stringify とバッファ |

#191 / #192 はどちらも `src/output/` 配下なので直列にする。

### Phase 2: トリガー `on:` 群

`ScheduleEntry` / `EventConfig` の拡張を伴うため直列。イベント名テーブルを先に作り、後続で再利用する。
cron（#70 / #71）と glob（#69）は `src/workflow/cron.zig` / `src/rules/glob.zig` として実装済み。

| 順 | issue | ルール | 状態・依存 |
|---|---|---|---|
| 1 | #65 | SYN009 webhook イベント名（+ `util.didYouMean` で候補提示） | イベント名 / activity type の埋め込みテーブルを新設 |
| 2 | #66 | SYN010 `types` 値 | #65 のテーブル |
| 3 | #67 | SYN011 イベントで使えないフィルタ | #65 のテーブル。SYN012 で `EventFilter` の key span は記録済み |
| 4 | #72 | SYN016 timezone | `ScheduleEntry.timezone` 追加 + IANA 名テーブル（`scripts/` で生成、`src/rules/data/` に置く）。cron パーサは `workflow/cron.zig` を再利用 |
| 5 | #73 | SYN017 workflow_dispatch inputs | #129 の `github.event.inputs` overlay と同時に実装 |

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
| 5 | #90 | EXPR014 `secrets.<name>` | RW001（#104）で入った `workflow_call` の定義構造を使う |
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
| #159 rule engine の arena 提供 | `expressions.zig` の `getArenaAllocator`（:1009）が `page_allocator` を返して意図的にリークしている。`engine.zig` がルール実行単位の arena を配り、`impostor.zig` の同名関数と意味を揃える。`engine.zig` の `Rule` シグネチャに触るので、ルール追加が集中する Phase 2〜4 の**前**に済ませると衝突が少ない |
| #64 YAML anchor / alias / merge key | パーサ基盤。GitHub Actions が anchor をサポートしたため実用価値あり。`yaml/parser.zig` の整理を Tidy First で先に行い、PBT にラウンドトリップ / 循環参照テストを追加する。#172 / #173 の修正が入って同ファイルが落ち着いたので、着手可能になった |

## 5. 直近の着手順（上位 10 件）

| 順 | 対象 | 理由 |
|---|---|---|
| 1 | #170 / #171 / #172 / #173 / #134 / #104 / #160 / #161 の close | 実装済み・未 close が 8 件。open issue 42 件のうち 2 割が実態と乖離しており、優先度判断を歪める |
| 2 | PR #190 | 実装後に残った計画書。close か設計記録化かを決める |
| 3 | `docs/rules.md` の見出し修正 | ルール数 63 → 68。表と本文が食い違っている |
| 4 | #192 | 残る perf 2 件のうち効果が大きい方（terminal が JSON の 2 倍） |
| 5 | #191 | #192 と同じ `src/output/` なので直後に処理する |
| 6 | #65 | イベント名テーブルを作る。これが入ると #66 / #67 が同じ表の上に乗り 3 件まとまる |
| 7 | #159 | エンジンの arena。ルール追加が本格化する前に `Rule` シグネチャを固める |
| 8 | #135 | 設計済み・オフライン完結・他と非競合。並列で流せる |
| 9 | #64 | `yaml/` が落ち着いた今が着手時期。Phase 3 以降の matrix / anchor 併用ワークフローに効く |
| 10 | #129 | 最大の山。#86〜#89 の 4 件が一気に解ける。6〜9 で足場を固めてから着手し、続けて #162 |

## 6. 進め方の注意

- Phase 2 以降は `types.zig` の拡張を伴うため、同 Phase 内は直列にする
- エージェント PR は CI 緑でもマージ前に main へ rebase する
- ルールを追加・変更したら `tests/fixtures/e2e/` に fixture を足し、`# zghalint:expect RULE@line` で行まで含めてアサートする（インラインテストだけでは `Step` 構造体を直接組み立ててパーサを通らない経路が残る）
- 新ルールのテストは自前でワークフローを組み立てず、`src/test_support.zig` の `parseWorkflowSource` / `runStep` / `runJob` / `runWorkflow` を使う
- autofix を伴うルールは、フロースタイル（`{}` / `[]`）とブロックスカラー（`|` / `>`）の入力を必ずテストに含める（#171 / #172 はどちらもこの 2 形式の抜けだった）。`tests/pbt/strategies.py` に両形式の strategy があるので PBT 側にも足す
- 深い再帰を持つパーサには上限を入れる（YAML は `max_parse_depth = 256`、式は `max_expr_depth = 256`）。新しい再帰下降を書いたら同じガードを必ず付ける
- 実装が終わったら `/wrapup`（`.claude/skills/wrapup`）で正しさ・過剰設計・コメントの 3 点を見てからコミットする。コメントは「コードから復元できない why」だけ残す（`/cleanup-comments` の基準）
- 各 Phase 完了時に `docs/rules.md` のルール数と #55 の進捗を確認する
- `zig build` は build.zig 一本で、`scripts/setup-zig.sh` の wrapper は `-fllvm` 注入のみ。**古い wrapper が `/usr/local/bin/zig` に残っていると `no module named 'build_options'` でビルドが落ちる**。main を取り込んだら `bash scripts/setup-zig.sh` を流し直す
