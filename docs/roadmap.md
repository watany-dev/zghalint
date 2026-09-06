# 実施ロードマップ（2026-09-06 時点）

オープンな PR / issue を main（`82fad14`）の実装状況と突き合わせ、以後の実施順序を示す。
経緯や前版との差分は git log と PR #130 / #207 の履歴に残しているため、本書には現在形の内容だけを書く。

## 1. 現状サマリ

| 項目 | 状態 |
|---|---|
| ルール数 | 69（`docs/rules.md` の表・見出しとも 69 で一致。PR #209 の SYN009 で +1） |
| `src/**/*.zig` | 34,174 行 |
| ユニットテスト | 1323 件（`zig build test` 緑） |
| #55 actionlint parity | 54 sub-issue 中 **28 close 済み（52%）**。#65 が PR #209 で close |
| 型検査エンジン | T0〜T3 実装済み。T4（overlay 接続）は #129、引数型検査は #162 |
| E2E テスト | `src/e2e_test.zig` が `tests/fixtures/e2e/*.yml`（20 本）の `# zghalint:expect RULE@line` / `forbid` コメントを読んで検証 |
| PBT（`tests/pbt/`） | 42 個の `@given`、xfail 0 件。#170 / #171 / #172 の回帰 strategy を収録済み |
| ADR | `docs/adr/0001`〜`0010` |
| オープン PR | #207（本ロードマップ）のみ |
| オープン issue | 32 件。内訳は #55 本体 1、#55 の sub-issue 26、それ以外 5（#124 #135 #159 #162 #210） |
| 実装済みだが未 close の issue | **なし** |
| 既知バグ | **なし**。#170〜#173 は PR #205 で修正済み |

棚卸しの積み残しはなく、出力層の perf 2 件（#192 terminal、#191 JSON）も PR #206 で main に入った。
残っているのは #55 parity の sub-issue 26 件と、それ以外の 5 件（#124 #135 #159 #162 #210）だけである。
#124 と #162 は型検査エンジンに、#210 は matrix 展開に依存するのでそれぞれ Phase 3 / Phase 2 に置き、
#135 / #159 / #64 を並行トラックとして扱う。

## 2. ロードマップ

原則:

- 1 issue = 1 PR = 1 ルール。TDD（Red → Green → Refactor）、完了時に `docs/rules.md` へ行追加
- 同一ファイル（`types.zig` / `parser.zig` / `security.zig`）を触る issue は直列にし、rebase 地獄を避ける
- 誤検出ゼロを優先。不確かなものは検出しない（ADR-0009 の方針を全ルールに適用）
- 新ルールは `src/rules/registry.zig` へ登録し、`tests/fixtures/e2e/` に `# zghalint:expect RULE@line` つきの fixture を 1 本足す

### Phase 1: トリガー `on:` 群

`ScheduleEntry` / `EventConfig` の拡張を伴うため直列。イベント名テーブルは #65（PR #209）で
`src/workflow/events.zig` に入り、`trigger_names` / `isKnown` として後続から再利用できる。
cron（#70 / #71）と glob（#69）は `src/workflow/cron.zig` / `src/rules/glob.zig` として実装済み。

| 順 | issue | ルール | 状態・依存 |
|---|---|---|---|
| 1 | #66 | SYN010 `types` 値 | `events.zig` はイベント名だけを持つので、イベント → activity type の表を同ファイルに追加する。候補提示は `util.didYouMean` を SYN009 と同じ形で使う |
| 2 | #67 | SYN011 イベントで使えないフィルタ | イベント → 許可フィルタ（`branches` / `paths` / `tags` 等）の表を `events.zig` に追加。SYN012 で `EventFilter` の key span は記録済み |
| 3 | #72 | SYN016 timezone | `ScheduleEntry.timezone` 追加 + IANA 名テーブル（`scripts/` で生成、`src/rules/data/` に置く）。cron パーサは `workflow/cron.zig` を再利用 |
| 4 | #73 | SYN017 workflow_dispatch inputs | #129 の `github.event.inputs` overlay と同時に実装 |

### Phase 2: job / step / matrix

`Strategy` 型の拡張（matrix 軸・include / exclude の保持）が起点。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #74 | SYN018 matrix 値重複 | `Strategy` に matrix 構造を追加 |
| 2 | #75 | SYN019 include / exclude 整合 | #74 |
| 3 | #76 | RUNNER002 未知ラベル | RUNNER001 のラベルデータを既知ラベル一覧に拡張。`.zghalint.yml` に self-hosted ラベル許可設定が要る |
| 4 | #210 | RUNNER002 第二段階: `runs-on: ${{ matrix.<key> }}` を matrix 展開して検証 | #76 + #74（matrix 構造）。展開できない式は従来どおりスキップし、span は matrix 値側に向ける |
| 5 | #77 | RUNNER003 ラベル衝突 | #76 |

### Phase 3: contextual typing（エンジン T4 = #129）

各 issue で「存在検証」を実装し、最後に `TypeEnv` overlay へ接続する（ADR-0009 の二重メンテ期間を短くするため Phase 3 内で一気に片付ける）。

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
| #64 YAML anchor / alias / merge key | パーサ基盤。GitHub Actions が anchor をサポートしたため実用価値あり。`yaml/parser.zig` の整理を Tidy First で先に行い、PBT にラウンドトリップ / 循環参照テストを追加する。#172 / #173 の修正が入って同ファイルが落ち着いたので、着手可能になった |

## 3. 直近の着手順（上位 6 件）

| 順 | 対象 | 理由 |
|---|---|---|
| 1 | #66 | `events.zig` が入った直後の続き。activity type の表を同ファイルに足す |
| 2 | #67 | #66 と同じファイル・同じ形。連続で入れると `events.zig` を 1 度で固められる |
| 3 | #159 | エンジンの arena。ルール追加が本格化する前に `Rule` シグネチャを固める |
| 4 | #135 | 設計済み・オフライン完結・他と非競合。並列で流せる |
| 5 | #64 | `yaml/` が落ち着いた今が着手時期。Phase 2 以降の matrix / anchor 併用ワークフローに効く |
| 6 | #129 | 最大の山。#86〜#89 の 4 件が一気に解ける。1〜5 で足場を固めてから着手する |

#162 は #129 の overlay が入った直後に続ける。棚卸しと perf が片付いたため、以後はルール実装（#55 parity）が主線になる。

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
