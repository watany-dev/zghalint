# v0.0.3 実施ロードマップ（2026-09-15 時点）

v0.0.2（main `4974885`、PR #542）を起点に、次のリリース v0.0.3 で何をどの順に入れるかを示す。
0.0.1 / 0.0.2 で何を入れたかは `CHANGELOG.md` に、着手順の履歴は git log と PR #207 / #395 に残しているため、本書には現在形の内容だけを書く。

## 1. 現状サマリ

| 項目 | 状態 |
|---|---|
| バージョン | v0.0.2（`build.zig.zon` の `.version = "0.0.2"`、2026-09-15 タグ）。`## [Unreleased]` は空 |
| ルール数 | `docs/rules.md` の表は 110 ID（SEC 24 / SC 8 / PERF 3 / BP 8 / PERM 3 / EXPR 19 / DEP 6 / RUNNER 3 / SYN 26 / RW 5 / ACT 5）で `registry.documented_rule_ids` と一致し、`src/docs_sync_test.zig` が両方向で検査する。残る不一致は `docs/rules.md` と `README.md` の見出しが **「108 rules」のまま**なことだけ（同期テストは ID 集合だけを見て本文の数字は見ない） |
| `src/**/*.zig` | 71,461 行 |
| ユニットテスト | 2,382 件（`zig build test` 緑。本体 2,362 + fuzz ドライバ 20） |
| E2E テスト | `tests/fixtures/e2e/` 155 本 + `tests/fixtures/e2e-action/` 10 本。`.fixed` / `.fixed-unsafe` の兄弟ファイルで autofix 結果を固定するものが 39 本、`ga*.yml.meta.yml` サイドカー（GA0 #427 の仕様追従）が 27 本 |
| bench | `bench/cases/` 147 ファイル。actionlint 1.7.12 / zizmor 1.30.1 との三者比較で parity gap は G1〜G39 まで起票済み。**未対応は G29 の 1 件だけ**（B1 #552。`actions/create-github-app-token` の `permission-*` 未指定。zizmor の `github-app` 相当。bench ケース `d-permissions-secrets/github-app-token-unscoped.yml` は用意済み）。G38 / G39（#424 / #425）は修正済みだが `docs/design/external-linter-parity.md` への追記が PR #426（draft、conflict）で止まっている（B2 #553）。週次 `.github/workflows/bench.yml` が `scripts/bench_gate.py` で baseline との回帰を見る |
| 形式手法 | `scripts/formal/`（Z3 有界モデル検査）で F1〜F7 と G1〜G5（P8〜P12）を確認済み。表の抜けは意図的除外を除き 0。残る限界は伝播 1 hop と、`CODE_EXECUTING_INPUTS` / `ACTION_OUTPUTS` の action 表が手書きで非網羅なこと（`docs/design/formal-rule-model.md` §9） |
| PBT / ファズ | `tests/pbt/` に 42 個の `@given`、xfail 0。`docs/design/pbt-strategy.md` §5 の未了項目は #3（PERM / BP / PERF の検出 PBT）、#4（YAML round-trip）、#5（生成器の拡張）、#7（新しい不変量）、#8（advisory / archived）、#10（terminal formatter）。`src/fuzz_test.zig` は YAML と式のターゲットを CI で回す |
| ADR | `docs/adr/0001`〜`0018`（0015 は BP003 の behind-current-major、0016 はネットワークの fail-fast と request budget、0017 は SC001 の image digest pin、0018 はランタイム廃止の切替時期） |
| オープン PR | #426（G38 / G39 の bench 追記、draft）、#395（旧ロードマップの同期。本書で置き換える）、#306（bench 再実行記録）、#217（Alloy / TLA+ 仕様。Z3 モデル #307 で代替済み）。いずれも main から遅れており、rebase して取り込むか close する |
| オープン issue | v0.0.3 軸の umbrella 4 本（N0 #544 / B0 #545 / C0 #546 / D0 #547）とその子。0.0.2 から残るのは **#409（AF6）** だけで、子の AF7〜AF14（#410〜#417）は全部 close 済みなので B3（#554）で umbrella も close する。GA0 #427 / PT0 #449 / G0 #531 / AF0 #322 / F0 #307 / bench #262 / 性能 #527 の各 umbrella は close 済み |
| 外部期限 | GitHub は **2026-09-23 に node20 ランタイムを廃止**する。N1〜N4（#548〜#551）で追従済み——`local_action.zig` の `retired_runtimes` が node20 を持ち、`action_metadata.zig` の `supported_using` からは外れ、BP003 は error、ACT002 は「もう動かない」を出す。次の世代交代（node24）の手順は [ADR 0018](adr/0018-runtime-retirement.md) |

0.0.2 は仕様追従（GA1〜GA14）・脆弱性クラス（G1〜G5）・autofix 拡張（AF7〜AF14）・
ponytail 監査（PT0）を一括で入れた大きめのリリースだった。
0.0.2 の追跡 issue は全て close 済みで、v0.0.3 は「積み残し」ではなく新しい軸（#544〜#566）を立てるところから始まる。

## 2. v0.0.3 ロードマップ

### 原則

- 進め方は 0.0.2 と同じ。umbrella issue + 子 issue、**1 issue = 1 PR = 1 ルール（または 1 機能）**、PR は `/wrapup` を通す
- v0.0.3 の主軸は 3 本。**(A) node20 廃止への追従**、**(B) parity 残件と滞留 PR の清算**、**(C) 利用者向けの CLI / 設定の穴埋め**。
  (D) 品質トラック（形式手法 / PBT / データ表の更新）は並行で回す
- ルールを足す・severity を上げる・一致範囲を広げる変更は、緑だった CI を赤くする。0.0.2 と同じく `CHANGELOG.md` の **Changed** / **Added** に対象 ID を必ず書く
- リリース時期は node20 の期限で決める。**(A) は 2026-09-23 までに main へ入れ**、(B) と (C) の P0 が揃った時点（目安 2026-09 末）で v0.0.3 を切る。(C) の P1 以降は間に合わなければ v0.0.4 へ送る
- 0.0.2 と同様に、新しい axis は `docs/design/` に設計文書を 1 本置いてから子 issue を切る

### (A) node20 廃止への追従 — umbrella **N0** (#544、P0、期限 09-23)

| 子 | issue | 内容 |
|---|---|---|
| N1 | #548 | 2026-09-23 以降の状態に合わせて `local_action.zig` の `ending_runtimes` から node20 を `retired_runtimes` へ移し、`action_metadata.zig` の `supported_using` から外す。ACT002 / BP003 / ACT003 の期待値と `docs/rules.md` の説明を「廃止済み」に書き換え、E2E fixture（`tests/fixtures/e2e-action/`）と bench ケースの期待 severity を更新する。CHANGELOG は **Changed** に ACT002 / BP003 を明記 |
| N2 | #549 | `scripts/gen-popular-actions.py` で `src/rules/data/popular_actions.zig` を再生成し、主要 action の node24 移行状況を反映する。再生成しないと N1 の後で DEP005 / DEP006 / BP003 が「人気 action がまだ node20」と誤って言う。再生成の実行日を `docs/maintenance.md` に記録する |
| N3 | #550 | ランタイム廃止の扱い方を ADR 0018 として残す。日付でビルド時に自動切替はしない（同じバイナリが日によって結果を変えると再現性が壊れる）、廃止はリリースで切り替える、次の廃止（node24）が告知されたら同じ手順を踏む、の 3 点 |
| N4 | #551 | 自リポジトリの dogfood（`.github/workflows/ci.yml` の lint ジョブ）と `bench/baseline.json` を N1 の結果で更新し、`scripts/bench_gate.py` が回帰と誤認しないことを確認する |

N1 は `types.zig` / `parser.zig` を触らないので他の作業と並行できる。N2 は N1 と同じ PR にまとめてよい。

### (B) parity 残件と滞留 PR の清算 — umbrella **B0** (#545、P0)

| 子 | issue | 内容 |
|---|---|---|
| B1 | #552 | **G29**: `actions/create-github-app-token` を `permission-*` 入力なしで使う step を検出する新ルール **SEC025**（zizmor `github-app` 相当）。app token は既定で app の全権限を持つため、`permissions:` の最小化と同じ理由で warning。`owner` / `repositories` の絞り込みだけでは不十分な点も併せて見る。fixture は `tests/fixtures/e2e/`、bench ケースは既存の `github-app-token-unscoped.yml` を採点に載せる。autofix は付けない（どの permission が要るかは静的に決まらない） |
| B2 | #553 | G38 / G39 を `docs/design/external-linter-parity.md` に追記し、§5 のチェックリストを更新する。PR #426 を main に rebase して取り込む（コードは #424 / #425 で着地済みなので文書だけ） |
| B3 | #554 | 滞留 PR の整理: #395 は本書で置換して close、#306 は記録として価値がある数値だけを parity 文書 §4 に移して close、#217 は Z3 モデル（`docs/design/formal-rule-model.md`）で代替済みなので close。#409 は子が全部済んでいるので close |
| B4 | #555 | 週次 bench の継続ループ。`bench.yml` が FN / FP を出したら G40 以降で起票し、parity 文書 §4.1 の手順で節を足す。`doghooding` スキルの対象を 1 リポジトリ追加して D8 として回す |

### (C) 利用者向けの CLI / 設定の穴埋め — umbrella **C0** (#546)

0.0.2 までは検出精度に注力し、利用側の道具立ては `.zghalint.yml` の severity / enabled / ignore と 3 形式の出力で止まっている。
actionlint / zizmor と並べて使われるために足りないものを優先度順に並べる。設計文書は `docs/design/cli-ergonomics.md` を 1 本置く。

| 子 | issue | 優先度 | 内容 |
|---|---|---|---|
| C1 | #556 | P0 | **ルール単位のパス除外**。`.zghalint.yml` の `rules.<ID>` に `exclude: ["**/release.yml"]` を足し、「このルールだけこのファイルでは見ない」を書けるようにする。`config.zig` と `ignore` の glob 実装だけで済み、パーサを触らない |
| C2 | #557 | P0 | **`--fail-on <severity>`**。終了コードを error / warning / info のどこで 1 にするか選ぶ。既定は現状（error で 1）を維持し、CHANGELOG には **Added** で書く。`--format sarif` との組み合わせでも終了コードだけが変わる |
| C3 | #558 | P0 | **インライン抑制コメント** `# zghalint-disable-next-line SEC001,SEC002` / `# zghalint-disable-line`（zizmor の `# zizmor: ignore[...]` と同じ位置づけ）。YAML トークナイザがコメントの行番号を保持する必要があり、`src/yaml/tokenizer.zig` を触るので**他の tokenizer / parser 変更と直列にする**。抑制された件数は `--format json` に `suppressed` として出す |
| C4 | #559 | P1 | **`--stdin`**（`-` でも可）。エディタや pre-commit から内容を渡せるようにする。ファイル名は `--stdin-filename` で受け、`ignore` パターンの評価に使う |
| C5 | #560 | P1 | **`.zghalint.yml` の JSON Schema** を `docs/schema/zghalint.schema.json` に置き、未知のキーを warning で報告する（現状は黙って無視する）。schema は `config.zig` の構造体からスクリプトで生成し、`scripts/check-version-sync.sh` と同じ流儀でずれを CI が検出する |
| C6 | #561 | P2 | **`--format github`**（`::error file=,line=,col=::` の workflow command）。Code Scanning を使わないリポジトリで PR 上に注釈を出す最短経路。`src/output/` に 1 ファイル足すだけで済む |

C1 / C2 / C4 / C6 は互いに独立で並行できる。C3 だけがパーサ変更を伴う。

### (D) 品質トラック — 並行（P1〜P2）— umbrella **D0** (#547)

| 子 | issue | 優先度 | 内容 |
|---|---|---|---|
| D-doc | #562 | P0 | `docs/rules.md` と `README.md` の見出しを 110 に直し、`src/docs_sync_test.zig` に「見出しの数字 = `documented_rule_ids.len`」の検査を足す。B1 で 111 になるので先に入れる |
| D-data | #563 | P1 | 埋め込みデータ表の更新手順を `docs/maintenance.md` に一本化する。対象は `advisory.zig` の advisory 表（現在 21 件、手書き）、`src/rules/data/compromised_actions.zig`、`trusted_actions.zig`、`runner.zig` の GitHub-hosted ラベル。advisory は `scripts/gen-advisories.py` で GHSA から生成できる形にし、更新日をファイル先頭に残す。リリース前に必ず流す |
| D-formal | #564 | P1 | `scripts/formal/model.py` の伝播を 2 hop（`outputs` → `needs.*.outputs` → 別 job の `run`）に広げ、`CODE_EXECUTING_INPUTS` / `ACTION_OUTPUTS` を `popular_actions.zig` から生成して網羅性を上げる。B1 の SEC025 もモデルに載せる。反例が出たら G0 の流儀で子 issue にする |
| D-pbt | #565 | P1 | `docs/design/pbt-strategy.md` §5 の #3（PERM / BP / PERF の検出 PBT）、#4（YAML round-trip 不変量。C3 でトークナイザを触るので同時に）、#7 のうち「ファイル順序に依存しない」「severity override の単調性」を入れる。#5 / #8 / #10 は v0.0.4 へ |
| D-fuzz | #566 | P2 | `src/fuzz_test.zig` に `.zghalint.yml` のパーサと式評価（`expressions.zig` の型検査）のターゲットを足す。C3 / C5 で入力面が増えるため |

### v0.0.3 のスコープ外

- 複数 CI（GitLab CI / CircleCI）対応。PR #320 は close 済みで、GitHub Actions 専用のまま
- LSP / エディタ拡張。C4 の `--stdin` までで、サーバ実装は持たない
- 外部プラグイン・カスタムルール。ゼロ依存・単一バイナリの方針を優先する
- 性能。#527 で回収済みで、bench の `--perf` 表（actionlint 比 wall time 15〜60 倍・RSS 6〜23 倍の差）を維持する以上のことはしない

## 3. 直近の着手順

1. **清掃（B3 #554 + D-doc #562）**: #409 を close、#395 / #217 / #306 を close、#426 を rebase して取り込む（B2 #553）。`docs/rules.md` / `README.md` の見出しを 110 に直し、同期テストに数字の検査を足す
2. **N1 #548 + N2 #549 + N4 #551**: node20 の廃止追従を 1 PR で入れ、`bench/baseline.json` を更新する。**09-23 までに main へ**。N3（#550）の ADR は同 PR に含める
3. **B1 #552（SEC025）**: G29 を潰す。着地したら parity 文書 §5 の全項目が [x] になる
4. **C1 #556 + C2 #557**: `config.zig` と `main.zig` だけで閉じる 2 本を並行で。ここまでで v0.0.3 の P0 が揃う
5. **C3 #558（インライン抑制）**: tokenizer を触るので単独で。D-pbt（#565）の #4（YAML round-trip）を同じ PR か直後に入れて、コメント保持の回帰を PBT で押さえる
6. **リリース v0.0.3**: `build.zig.zon` の `.version` を 0.0.3 に、CHANGELOG の `[Unreleased]` を `[0.0.3]` に切り、`docs/maintenance.md` のタグ手順で `v0.0.3` を打つ。D-data（#563）の更新をリリース直前に流す
7. **C4 #559 / C5 #560 / C6 #561 と D-formal #564 / D-fuzz #566**: 6 に間に合ったものは 0.0.3 に、残りは v0.0.4 の最初の項目にする

## 4. 進め方の注意

- `types.zig` / `parser.zig` / `security.zig` / `tokenizer.zig` を触る変更は直列にする（Phase 4 で `types.zig` の拡張が重なった際の教訓。C3 #558 が今回の該当）
- エージェント PR は CI 緑でもマージ前に main へ rebase する
- ルールを追加・変更したら `tests/fixtures/e2e/`（ワークフロー）または `tests/fixtures/e2e-action/`（action.yml）に fixture を足し、`# zghalint:expect RULE@line` で行まで含めてアサートする。GitHub の仕様に根拠がある挙動は `ga*.yml.meta.yml` サイドカーで出典を残す
- `docs/rules.md` への行追加は任意ではない。`src/docs_sync_test.zig` が registry との ID 差分でビルドを落とす
- 新ルールのテストは `Step` / `Job` を手で組まず、`src/test_support.zig` の `parseWorkflowSource`（YAML から `Workflow` を起こす）と `lintAndFix`（リント + autofix を 1 度に検証）を使う。`runStep` / `runJob` / `runWorkflow` は `security.zig` にあるファイル内ヘルパーなので、他ファイルからは呼べない
- 式を走査するルールは `src/rules/expr_scan.zig` を使う。`${{ }}` の切り出しを各ルールで書き直さない
- autofix を伴うルールは、フロースタイル（`{}` / `[]`）とブロックスカラー（`|` / `>`）の入力を必ずテストに含める（#171 / #172 はどちらもこの 2 形式の抜けだった）。`tests/pbt/strategies.py` に両形式の strategy があるので PBT 側にも足す
- CRLF のワークフローも入力になる（Windows CI で顕在化した）。行末を跨ぐ処理を書いたら `\r` を落とす経路を確認する
- 深い再帰を持つパーサには上限を入れる（YAML は `max_parse_depth = 256`、式は `max_expr_depth = 256`）。新しい再帰下降を書いたら同じガードを必ず付ける
- 実装が終わったら `/wrapup`（`.claude/skills/wrapup`）で正しさ・過剰設計・コメントの 3 点を見てからコミットする。コメントは「コードから復元できない why」だけ残す（`/cleanup-comments` の基準）
- ルールを増やしたら `docs/rules.md` のルール数と bench の採点（`scripts/bench.py` → `scripts/bench_gate.py`）を確認し、baseline を更新するなら同じ PR で `--update` を流す
- ネットワークを使うルール（SC003〜SC006）に手を入れたら `--quick` / `--offline` の経路と `disk_cache.zig` の TTL も見る（ADR 0016）
- Zig の版を上げるときは `build.zig.zon` の `minimum_zig_version` だけを触る。CI / release / `scripts/setup-zig.sh` はそこから読むので、他所に版を書かない（`docs/maintenance.md`）
- `zig build` は build.zig 一本で、`scripts/setup-zig.sh` の wrapper は `-fllvm` 注入のみ。**古い wrapper が `/usr/local/bin/zig` に残っていると `no module named 'build_options'` でビルドが落ちる**。main を取り込んだら `bash scripts/setup-zig.sh` を流し直す
