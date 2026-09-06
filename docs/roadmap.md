# 実施ロードマップ（2026-09-06 時点）

オープンな PR / issue を main（`5d3552b`）の実装状況と突き合わせ、以後の実施順序を示す。
経緯や前版との差分は git log と PR #130 の履歴に残しているため、本書には現在形の内容だけを書く。

## 1. 現状サマリ

| 項目 | 状態 |
|---|---|
| ルール数（`docs/rules.md`） | 65 |
| `src/**/*.zig` | 31,064 行 |
| ユニットテスト | 1207 件（`zig build test` 緑） |
| #55 actionlint parity | 54 sub-issue 中 **23 close 済み（42%）** |
| 型検査エンジン | T0〜T3 実装済み。T4（overlay 接続）は #129、引数型検査は #162 |
| E2E テスト | `src/e2e_test.zig` が `tests/fixtures/e2e/*.yml`（16 本）の `# zghalint:expect RULE@line` / `forbid` コメントを読んで検証 |
| ADR | `docs/adr/0001`〜`0010` |
| PBT（`tests/pbt/`） | xfail 0 件 |
| オープン PR | #130（本ロードマップ）、#180 draft（SYN014 / SYN015）、#181 draft（SYN013） |
| オープン issue | 43 件。内訳は バグ 4（#170〜#173）、#55 本体 1、parity ラベル 33、それ以外 5（#124 #134 #135 #159 #160） |
| 既知バグ | **4 件（#170〜#173）**。すべて main のバイナリで再現を確認済み。§2 参照 |

## 2. 最優先: バグ 4 件

ファジングと autofix の実地確認で判明した未修正バグ。新ルールの追加よりこちらが先である。
いずれもユーザーのファイルを壊すか、プロセスを落とすか、CI アノテーションの位置をずらす。

### 2.1 #170 式パーサのスタックオーバーフロー（クラッシュ）

`${{ }}` の中で括弧や関数呼び出しを深くネストすると、再帰下降パーサに深度上限が無いため
SIGSEGV で落ちる（20,000 段で再現、しきい値は概ね 17,000 段前後でスタックサイズ依存）。
YAML ブロックパーサ側は `max_parse_depth = 256`（`src/yaml/parser.zig`）で守られているが、
`src/rules/expressions.zig` の `parseOr → parseAnd → parseComparison → parseBinary → parseUnary → parsePrimary`
と `parseFunctionCall` の相互再帰にはカウンタが無い。

修正は `ExprParser` に `depth` を持たせ、YAML 側と同じく上限超過で `ParseError` を返す。
実運用の式は浅いので上限は 128〜256 で足りる。**4 件のうち唯一プロセスが落ちるので最優先。**

### 2.2 #172 ブロックスカラー直後の autofix 挿入位置がずれる

`runs-on: |` のように値がブロックスカラーだと、`blockEntryFullSpan`（`src/yaml/parser.zig`）の
スカラー分岐が「スカラーはキーと同じ行で終わる」前提で次の `\n` まで走査し、次の兄弟キー行
（例 `    steps:`）を span に飲み込む。その `end_byte` をアンカーにする autofix
（トップレベル / ジョブレベルの `permissions:` `concurrency:`）が `steps:` とステップリストの
間に挿入され、YAML が壊れる。

根が YAML パーサ側にあり `workflow/parser.zig` の 4 つの `*_insertion_byte` すべてに波及するため、
バグ 4 件の中では #170 の次に重い。修正はブロックスカラー（literal / folded）をプレーンスカラーと
分岐し、次行の走査を行わないようにする。

### 2.3 #171 フロースタイル `with:` を SEC018 autofix が破壊

`with: {a: b}` のようなフローマッピングに `persist-credentials: false` を追記すると
`x: {\n          persist-credentials: falsea: b}` となり、元の値と連結して意味が変わる。
`fix/builder.zig` の `appendMappingEntry` がブロックマッピング末尾への追記専用なのに、
フロー / ブロックを区別しないアンカー（`step.with_last_entry_end_byte`）で呼ばれている。
しかもフローマッピングのパースが緩く、書き換え後も SEC018 は消えない（fix が無効なうえ副作用だけ残る）。

同型のリスクは PERF の cache 追記（`src/rules/performance.zig`）にもある。
`Step` に `with_is_flow` を持たせ、フロー時は append 系 fix を一律スキップするのが安全。

### 2.4 #173 行継続エスケープ以降で行番号が 1 ずれる

ダブルクォートスカラー内の `\` + 改行を `scanQuotedScalar`（`src/yaml/tokenizer.zig`）が
`self.line` を増やさずに消費するため、それ以降の全診断が 1 行手前を指す。
4 件の中では影響が限定的だが修正は最も小さい（エスケープ対象が `\n` かを判定して行カウンタを進めるだけ）。

## 3. 実装済みだが未 close の issue

main に実装が入っているのに issue が開いたままのもの。着手前に確認して close する。

| issue | 実装 | 確認箇所 |
|---|---|---|
| #134 SEC021 untrusted checkout ref | PR #174 | `security.zig` に `.id = "SEC021"` / `untrusted-checkout-ref`、fixture `tests/fixtures/e2e/sec021-untrusted-checkout-ref.yml` |
| #104 RW001 workflow_call inputs type | PR #178 | `src/rules/reusable_workflow.zig`（新設）、fixture `rw001-workflow-call-inputs.yml` |
| #160 SC008 `compareRest` の移設 | PR #178 | `rest_fallback.zig` に `pub fn compareRest`。`impostor_compare.zig` から消えている |
| #161 関数名 lookup の case-insensitive 化 | PR #178 | `expr_type.zig` が `std.ascii.eqlIgnoreCase` で引く。actionlint 互換の方向で決着 |

## 4. ロードマップ

原則:

- 1 issue = 1 PR = 1 ルール。TDD（Red → Green → Refactor）、完了時に `docs/rules.md` へ行追加
- 同一ファイル（`types.zig` / `parser.zig` / `security.zig`）を触る issue は直列にし、rebase 地獄を避ける
- 誤検出ゼロを優先。不確かなものは検出しない（ADR-0009 の方針を全ルールに適用）
- 新ルールは `src/rules/registry.zig` へ登録し、`tests/fixtures/e2e/` に `# zghalint:expect RULE@line` つきの fixture を 1 本足す

### Phase 1: バグ修正

| 順 | issue | 内容 | 触る主なファイル |
|---|---|---|---|
| 1 | #170 | 式パーサに再帰深度上限 | `rules/expressions.zig` |
| 2 | #172 | `blockEntryFullSpan` のブロックスカラー分岐 | `yaml/parser.zig`。`workflow/parser.zig` の insertion byte 全体に効く |
| 3 | #171 | フロースタイル `with:` で append 系 fix をスキップ | `workflow/types.zig` / `workflow/parser.zig` / `rules/security.zig` / `rules/performance.zig` |
| 4 | #173 | `scanQuotedScalar` の行カウンタ | `yaml/tokenizer.zig` |

#172 と #173 はどちらも `yaml/` 配下なので直列にする。#170 と #171 は独立。

### Phase 2: トリガー `on:` 群

`ScheduleEntry` / `EventConfig` の拡張を伴うため直列。イベント名テーブルと cron パーサを先に作り、後続で再利用する。

| 順 | issue | ルール | 状態・依存 |
|---|---|---|---|
| 1 | #70 / #71 | SYN014 CRON 構文 / SYN015 5 分未満 | **PR #180 が draft で存在**。cron パーサを 1 本書けば 2 件 |
| 2 | #69 | SYN013 glob 構文 | **PR #181 が draft で存在**。独立して着手可 |
| 3 | #65 | SYN009 webhook イベント名（+ `util.didYouMean` で候補提示） | イベント名 / activity type の埋め込みテーブルを新設 |
| 4 | #66 | SYN010 `types` 値 | #65 のテーブル |
| 5 | #67 | SYN011 イベントで使えないフィルタ | #65 のテーブル。SYN012 で `EventFilter` の key span は記録済み |
| 6 | #72 | SYN016 timezone | `ScheduleEntry.timezone` 追加 + IANA 名テーブル（`scripts/` で生成、`src/rules/data/` に置く） |
| 7 | #73 | SYN017 workflow_dispatch inputs | #129 の `github.event.inputs` overlay と同時に実装 |

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
| #159 rule engine の arena 提供 | `expressions.zig` の `getArenaAllocator` が `page_allocator` を返して意図的にリークしている。`engine.zig` がルール実行単位の arena を配り、`impostor.zig` の同名関数と意味を揃える。`engine.zig` の `Rule` シグネチャに触るので、ルール追加が集中する Phase 2〜4 の**前**に済ませると衝突が少ない |
| #64 YAML anchor / alias / merge key | パーサ基盤。GitHub Actions が anchor をサポートしたため実用価値あり。`yaml/parser.zig` の整理を Tidy First で先に行い、PBT にラウンドトリップ / 循環参照テストを追加する。Phase 1 の #172 / #173 で同ファイルを触るのでその後に回す |
| ファジングのリポジトリ内取り込み | #170 は 240,000 件規模のインプロセスファジングで見つかったが、ハーネスがリポジトリに無い。`docs/design/pbt-strategy.md` の枠組みに乗せて `zig build fuzz` 相当を用意すれば、同種のクラッシュを回帰として押さえられる |

## 5. 直近の着手順（上位 10 件）

| 順 | issue | 理由 |
|---|---|---|
| 1 | #170 | 唯一プロセスが落ちる。修正は深度カウンタの追加のみで小さい |
| 2 | #172 | autofix がユーザーの YAML を壊す。根が `yaml/parser.zig` にあり insertion byte 全体に効く |
| 3 | #171 | 同じく autofix の破壊。#172 と原因は別（フロー / ブロックの区別）なので並列可 |
| 4 | #173 | 行番号ずれ。修正が最小で、#172 と同じ `yaml/` なので直後に処理する |
| 5 | #134 / #104 / #160 / #161 | 実装済み・未 close（§3）。棚卸しして close する |
| 6 | PR #180 / #181 | #70 / #71 / #69 の draft PR。main へ rebase して CI を通し、レビューして取り込む |
| 7 | #65 | イベント名テーブルを作る。これが入ると #66 / #67 が同じ表の上に乗り 3 件まとまる |
| 8 | #159 | エンジンの arena。ルール追加が本格化する前に `Rule` シグネチャを固める |
| 9 | #135 | 設計済み・オフライン完結・他と非競合。並列で流せる |
| 10 | #129 | 最大の山。#86〜#89 の 4 件が一気に解ける。7〜9 で足場を固めてから着手し、続けて #162 |

## 6. 進め方の注意

- Phase 1 のバグ 4 件を新ルールより先に片付ける。特に #171 / #172 は `--fix` がユーザーのファイルを壊すので、修正まで autofix の広報は控える
- Phase 2 以降は `types.zig` の拡張を伴うため、同 Phase 内は直列にする
- エージェント PR は CI 緑でもマージ前に main へ rebase する
- ルールを追加・変更したら `tests/fixtures/e2e/` に fixture を足し、`# zghalint:expect RULE@line` で行まで含めてアサートする（インラインテストだけでは `Step` 構造体を直接組み立ててパーサを通らない経路が残る）
- 新ルールのテストは自前でワークフローを組み立てず、`src/test_support.zig` の `parseWorkflowSource` / `runStep` / `runJob` / `runWorkflow` を使う
- autofix を伴うルールは、フロースタイル（`{}` / `[]`）とブロックスカラー（`|` / `>`）の入力を必ずテストに含める（#171 / #172 はどちらもこの 2 形式の抜け）
- 実装が終わったら `/wrapup`（`.claude/skills/wrapup`）で正しさ・過剰設計・コメントの 3 点を見てからコミットする。コメントは「コードから復元できない why」だけ残す（`/cleanup-comments` の基準）
- 各 Phase 完了時に `docs/rules.md` のルール数と #55 の進捗を確認する
- `zig build` は build.zig 一本で、`scripts/setup-zig.sh` の wrapper は `-fllvm` 注入のみ。**古い wrapper が `/usr/local/bin/zig` に残っていると `no module named 'build_options'` でビルドが落ちる**。main を取り込んだら `bash scripts/setup-zig.sh` を流し直す
