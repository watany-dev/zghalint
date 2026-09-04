# 実施ロードマップ（2026-09-04 時点）

オープンな PR 7 件・issue 46 件（親 #55 + sub-issue 45 件）を、main の実装状況と突き合わせて
棚卸しした結果と、以後の実施順序を示す。

## 1. 現状サマリ

| 項目 | 状態 |
|---|---|
| ルール数（`docs/rules.md`） | 56（SYN001/002/004/005/006/008/012、EXPR017 を含む） |
| #55 actionlint parity | 53 sub-issue 中 10 完了（#56 #57 #59 #60 #61 #63 #68 #80 #81 #82） |
| 型検査エンジン | T0〜T3 実装済み（#116）。T4（overlay 接続）が未着手 |
| PBT（`tests/pbt/`） | xfail 3 件が残存（config override 2 件、`--fix` クラッシュ 1 件） |

## 2. 閉じてよい PR / issue

### PR

| PR | 判定 | 理由 |
|---|---|---|
| #8 `fix: resolve memory leak in lintFile()` | **close** | base が削除済みの `dev` ブランチ。3 月時点の 18 コミット混在で `dirty`。lintFile は以後大きく書き換わっており再利用不可 |
| #115 `docs: 式の静的型検査エンジンの設計` | **close（superseded）** | 同内容の `docs/adr/0006-expr-static-typecheck.md` と `docs/design/expr-static-typecheck-design.md` は #116 で main に入っている |
| #11 `add property-based fuzz tests` | **close** | main と競合。PBT は Python/Hypothesis（`tests/pbt/`、CI の Property-Based Tests ジョブ）で採用済みで、`docs/design/pbt-strategy.md` が基準文書。`std.testing.fuzz` を入れるなら別途小さな PR で再提案 |
| #6 `perf: add benchmarks, optimize checkCyclicNeeds` | **close** | main と競合。`engine.run` の sort 削除は挙動変更で、ベンチ対象のワークフロー規模（50 job）は実運用で稀。必要になったら bench のみ再作成 |
| #25 `fix(fix/engine): drop edits with invalid byte ranges` | **close → 再移植** | 内容は今も有効（`main.loadConfig` が `source` を解放した後も `Config` がその slice を保持する use-after-free と、`Edit` 値域検証の欠如は main に残っている）。ただしブランチが競合するため、main から新規ブランチで作り直す。ロードマップ Phase 0 の P0 |
| #121 `feat(SYN003)` | **残す（rebase 必須）** | CI は緑だが SYN001/004/005 マージ後の main と競合。rebase して取り込めば #58 が閉じる |

### issue

| issue | 判定 | 理由 |
|---|---|---|
| #94 基盤: 式の静的型検査エンジンの設計（ADR） | **close（completed）** | ADR-0006 と設計書、エンジン本体（T0〜T3）が main にある。残る T4 は #86〜#90 側で扱う |
| #93 EXPR017 比較演算子の型不整合 | **close（completed）** | EXPR017 は #116 で実装済み（`docs/rules.md` 掲載）。ADR D3 で「`github.event` 配下は any」と決めたため、`github.event.issue.number == 'foo'` は仕様上検出しない。到達範囲拡大は ADR の follow-up（curated scalar overlay）として別 issue を切る |

上記以外の sub-issue は全て未実装で、閉じる対象はない。

## 3. ロードマップ

原則:

- 1 issue = 1 PR = 1 ルール。TDD（Red → Green → Refactor）、完了時に `docs/rules.md` へ行追加
- 同一ファイル（`types.zig` / `parser.zig`）を触る issue は直列にし、rebase 地獄を避ける
- 誤検出ゼロを優先。不確かなものは検出しない（ADR-0006 の方針を全ルールに適用）

### Phase 0: 整理（〜1 週間）

| 順 | 作業 | 備考 |
|---|---|---|
| 1 | §2 の PR / issue を閉じる | |
| 2 | #121 を rebase してマージ → #58 close | SYN 系で残る最後の「基盤なし」issue |
| 3 | #25 を main から再移植 | `Config.strings_arena` + `isValidEdit` + xfail 3 件解除。`docs/design/pbt-strategy.md` §4 と `docs/codebase-improvements.md` を同時更新 |
| 4 | #55 本文の進捗表を更新、Phase ごとの milestone を作る | |

### Phase 1: 依存なし・小粒ルール（A / C / D / E / F の単独項目）

`types.zig` を触らず、既存の走査ループにチェックを足すだけで済むもの。セキュリティ価値の高い SEC002 拡張を先頭に置く。

| 順 | issue | ルール | 触る主なファイル |
|---|---|---|---|
| 1 | #101 | SEC002 untrusted inputs 拡充 | `security.zig` の `dangerous_contexts`（現在 13 件 → actionlint の 18 件） |
| 2 | #103 | SEC002 github-script の `script:` | `security.zig` |
| 3 | #102 | SEC002 object filter `.*` | `security.zig`（式エンジンの walk が `foo.*` を扱えるので流用） |
| 4 | #62 | SYN007 env 変数名 | `syntax.zig` |
| 5 | #79 | PERM003 permissions スコープ / レベル | `permissions.zig` / `parser.zig` の `parsePermissions` |
| 6 | #95 | DEP003 `uses` フォーマット | `types.zig` の `ActionRef.parse` 近傍 |
| 7 | #78 | BP004 拡張 shell 名 | `best_practices.zig` |
| 8 | #85 | EXPR009 fromJSON リテラル | `expressions.zig`（JSON 妥当性チェッカを `util.zig` に切り出す） |
| 9 | #84 | EXPR008 format() 整合 | `expressions.zig` |
| 10 | #83 | EXPR007 拡張 定数条件 / `${{ }}` 外の文字 | `expressions.zig` |
| 11 | #104 | RW001 workflow_call inputs type | `parser.zig` の `parseInputDefs`（単一ファイルで完結する RW 唯一の項目） |

### Phase 2: トリガー `on:` 群（B）

`ScheduleEntry` / `EventConfig` の拡張を伴うため直列。イベント名テーブルと cron パーサを先に作り、後続で再利用する。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #65 | SYN009 webhook イベント名（+ 近似候補提案） | イベント名 / activity type の埋め込みテーブルを新設 |
| 2 | #66 | SYN010 `types` 値 | #65 のテーブル |
| 3 | #67 | SYN011 イベントで使えないフィルタ | SYN012 で `EventFilter` の key span は記録済み |
| 4 | #69 | SYN013 glob 構文 | なし |
| 5 | #70 | SYN014 CRON 構文 | cron パーサを `util.zig` か `workflow/cron.zig` に新設 |
| 6 | #71 | SYN015 5 分未満 | #70 のパーサ |
| 7 | #72 | SYN016 timezone | `ScheduleEntry.timezone` 追加 + IANA 名テーブル（`scripts/` で生成、`src/rules/data/` に置く） |
| 8 | #73 | SYN017 workflow_dispatch inputs | ADR-0006 の `github.event.inputs` overlay と同時に実装 |

### Phase 3: job / step / matrix（C）

`Strategy` 型の拡張（matrix 軸・include / exclude の保持）が起点。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #74 | SYN018 matrix 値重複 | `Strategy` に matrix 構造を追加 |
| 2 | #75 | SYN019 include / exclude 整合 | #74 |
| 3 | #76 | RUNNER002 未知ラベル | RUNNER001 のラベルデータを既知ラベル一覧に拡張。`.zghalint.yml` に self-hosted ラベル許可設定が要る |
| 4 | #77 | RUNNER003 ラベル衝突 | #76 |

### Phase 4: contextual typing（D、エンジン T4）

各 issue で「存在検証」を実装し、最後に `TypeEnv` overlay へ接続する（ADR-0006 の二重メンテ期間を短くするため Phase 4 内で一気に片付ける）。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #86 | EXPR010 `steps.<id>` | なし |
| 2 | #88 | EXPR012 `needs.<job>.outputs` | なし |
| 3 | #89 | EXPR013 `inputs.<name>` | #73（SYN017 の inputs 構造） |
| 4 | #87 | EXPR011 `matrix.<key>` | #74（matrix 構造） |
| 5 | #90 | EXPR014 `secrets.<name>` | #104（workflow_call secrets の定義） |
| 6 | — | T4: 上記を `expr_check.zig` の overlay に接続し、存在検証をエンジン側に寄せる | #86〜#90 |
| 7 | #91 | EXPR015 キーごとの context 利用可否 | 式を検証する箇所に「どのキーか」を渡す配線が必要 |
| 8 | #92 | EXPR016 特殊関数の利用可否 | #91 の配線 |
| 9 | — | ADR-0006 follow-up: curated scalar overlay（`github.event.issue.number: number` 等） | EXPR017 の到達範囲拡大。#93 close 時に新 issue を切る |

### Phase 5: action.yml / reusable workflow（E / G、複数ファイル横断）

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
| #64 YAML anchor / alias / merge key | パーサ基盤。GitHub Actions が anchor をサポートしたため実用価値あり。全ルールに影響するので Phase 1 完了後、Phase 2 と並行して着手。`docs/codebase-improvements.md` §7 の yaml/parser 整理を Tidy First で先に行い、PBT にラウンドトリップ / 循環参照テストを追加する |
| `docs/codebase-improvements.md` 優先度 1〜8 | 各 Phase で該当ファイルを触る前に Tidy First で消化する（例: Phase 1 の SEC002 拡張前に「`${{ }}` 式スキャンのイテレータヘルパー」を入れる） |
| `docs/design/pbt-strategy.md` #3〜#5 | Phase 0 の xfail 解除後、新ルールが増えるたびに detection PBT を横展開する |
| SEC021 / SC007（ADR-0004 で設計済み・未実装） | #55 の対象外。issue が無いので、着手するなら issue を起票してから Phase 1 の末尾に入れる |

## 4. 進め方の注意

- Phase 1 は互いに独立なので並列に走らせられる。Phase 2 以降は `types.zig` の拡張を伴うため、同 Phase 内は直列にする
- Cursor / Claude のエージェント PR は CI 緑でもマージ前に main へ rebase する（#121 と同じ競合を繰り返さない）
- 各 Phase 完了時に `docs/rules.md` のルール数と #55 の進捗表を更新する
