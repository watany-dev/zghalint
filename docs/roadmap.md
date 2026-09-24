# v0.0.4 実施ロードマップ（2026-09-24 時点）

v0.0.3（main `8318855`、PR #592、2026-09-24 タグ）を起点に、次のリリース v0.0.4 で何をどの順に入れるかを示す。
0.0.1〜0.0.3 で何を入れたかは `CHANGELOG.md` に、着手順の履歴は git log と PR #207 / #395 / #543 に残しているため、本書には現在形の内容だけを書く。

## 1. 現状サマリ

| 項目 | 状態 |
|---|---|
| バージョン | v0.0.3（`build.zig.zon` の `.version = "0.0.3"`、2026-09-24 タグ）。`## [Unreleased]` は空 |
| ルール数 | 111 ID（SEC 25 / SC 8 / PERF 3 / BP 8 / PERM 3 / EXPR 19 / DEP 6 / RUNNER 3 / SYN 26 / RW 5 / ACT 5）。`src/docs_sync_test.zig` が `docs/rules.md` の表と `registry.documented_rule_ids` を両方向で、`docs/rules.md` / `README.md` の見出しの数字を `documented_rule_ids.len` と突き合わせる |
| `src/**/*.zig` | 73,880 行 |
| ユニットテスト | 2,429 件（`zig build test` 緑。本体 2,395 + fuzz ドライバ 34） |
| E2E テスト | `tests/fixtures/e2e/` のワークフロー 134 本（`ga*.yml.meta.yml` サイドカー 27 本を除く）+ `tests/fixtures/e2e-action/` 10 本。`.fixed` / `.fixed-unsafe` の兄弟ファイルが 43 本 |
| bench | `bench/cases/` 149 ファイル。actionlint 1.7.12 / zizmor 1.30.1 との三者比較で parity gap G1〜G39 は全て対応済み（G29 は SEC025 #552）。`docs/design/external-linter-parity.md` §5 のチェックリストは全項目 [x]。週次 `.github/workflows/bench.yml` が `scripts/bench_gate.py` で baseline との回帰を見て、FN / FP は G40 以降で起票する（#555） |
| 形式手法 | `scripts/formal/`（Z3 有界モデル検査）で F1〜F7、G1〜G5（P8〜P12）、SEC025（P13）を確認済み。job `outputs:` の伝播は 2 hop、`CODE_EXECUTING_INPUTS` は `popular_actions.zig` から生成（#564）。残る限界は 3 hop 以上と composite action 内の `outputs`、`ACTION_OUTPUTS` が手書きなこと（`docs/design/formal-rule-model.md` §9） |
| PBT / ファズ | `tests/pbt/` に 51 個の `@given`。`docs/design/pbt-strategy.md` §5 の未了は #5（生成器の拡張）、#7 (b)（`--quick` と通常モードの整合）、#8（advisory / archived 等の検出 PBT）、#10（terminal formatter）。`src/fuzz_test.zig` は YAML / 式 / `.zghalint.yml` / 式の型検査 / YAML parse-emit-parse の 6 ターゲット |
| 埋め込みデータ表 | 更新手順は `docs/maintenance.md` に一本化済み（#563）。SC003 の advisory スナップショットは `scripts/gen-advisories.py` で生成し、v0.0.3 直前に更新した（#592）。popular actions は 2026-09-15 の再生成が最新 |
| 配布 | リリース資産（`install.sh` / GitHub Action / Homebrew tap）に加え、pre-commit hook、in-repo aqua registry、mise / Code Scanning の手順（#569、[ADR 0019](adr/0019-distribution-channels.md)）。リポジトリの About と Marketplace 掲載は UI 作業で、`docs/maintenance.md`「配布経路」の手順が残っている |
| ADR | `docs/adr/0001`〜`0019`（0018 はランタイム廃止の切替時期、0019 は配布チャネル） |
| オープン PR / issue | なし（v0.0.3 の umbrella N0 #544 / B0 #545 / C0 #546 / D0 #547 と子 #548〜#566 は全て close） |

0.0.3 は node20 廃止への追従（N0）、parity 残件の清算（B0）、利用者向け CLI / 設定（C0: ルール単位除外・`--fail-on`・インライン抑制・`--stdin`・JSON Schema・`--format github`）、
品質トラック（D0）を入れた。v0.0.3 の P1 / P2 まで含めて全ての子が 0.0.3 に間に合ったため、v0.0.4 に持ち越す issue は無い。

## 2. v0.0.4 ロードマップ

### 原則

- 進め方は 0.0.3 と同じ。umbrella issue + 子 issue、**1 issue = 1 PR = 1 ルール（または 1 機能）**、PR は `/wrapup` を通す
- ルールを足す・severity を上げる・一致範囲を広げる変更は、緑だった CI を赤くする。`CHANGELOG.md` の **Changed** / **Added** に対象 ID を必ず書く
- 新しい axis は `docs/design/` に設計文書を 1 本置いてから子 issue を切る
- 軸と umbrella はまだ切っていない。下の持ち越し候補から選び、umbrella を立てた時点で本節に issue 番号を書く

### 持ち越し候補

各設計文書が「v0.0.4 へ」と送った項目と、v0.0.3 のリリース作業で任意扱いにした項目。

| 出典 | 内容 |
|---|---|
| `pbt-strategy.md` §5 #5 | 生成戦略の拡充（matrix / reusable workflow / `if` 条件式 / multiline run / 巨大 jobs）。既存 PBT 全体の実効カバーを底上げする |
| `pbt-strategy.md` §5 #7 (b) | `--quick` と通常モードの整合性。ネットワークルール以外の診断が一致することを不変条件にする |
| `pbt-strategy.md` §5 #8 / #10 | advisory / archived / dependabot / refconfusion / stale_refs の検出 PBT（外部依存の扱いを要調査）と terminal formatter の property test |
| `formal-rule-model.md` §9 | 伝播 3 hop 以上と composite action 内の `outputs`、`ACTION_OUTPUTS` の生成。反例が出たら G0 の流儀で子 issue にする |
| `docs/maintenance.md` | popular actions の再生成（`scripts/gen-popular-actions.py`）。新しい major が出ていれば流す |
| `docs/maintenance.md`「配布経路」 | リポジトリ About と GitHub Marketplace への掲載（UI 作業）。掲載後に README へ Marketplace バッジを足す |
| bench | 週次 bench の継続。FN / FP が出たら G40 以降で起票する |

### v0.0.4 のスコープ外

- 複数 CI（GitLab CI / CircleCI）対応。GitHub Actions 専用のまま
- LSP / エディタ拡張。`--stdin`（#559）までで、サーバ実装は持たない
- 外部プラグイン・カスタムルール。ゼロ依存・単一バイナリの方針を優先する

## 3. 進め方の注意

- `types.zig` / `parser.zig` / `security.zig` / `tokenizer.zig` を触る変更は直列にする（Phase 4 で `types.zig` の拡張が重なった際の教訓。v0.0.3 では C3 #558 が該当した）
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
