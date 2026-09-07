# 外部リンター統合と parity 整理

最終更新: 2026-09-07

## 1. 目的

CI に外部静的解析ツールを導入し (issue #240)、

1. zghalint 自身のリポジトリ資産 (`action.yml` / `.github/workflows/` / `tests/pbt/`)
   を第三者ツールで検証する
2. 「外部ツールが指摘できて zghalint が指摘できないもの」を parity gap として
   継続的に洗い出す

の 2 点を満たす。本書は 2 の棚卸し結果と、ルール化の判断を記録する基準ドキュメントである。

## 2. 導入ツールと担当範囲

| ツール | 版 | 対象 | CI での実行 |
| --- | --- | --- | --- |
| shellcheck | runner 同梱 | `scripts/*.sh`, `action.yml` の埋め込みスクリプト | `lint` ジョブ |
| actionlint | 1.7.7 (SHA256 検証) | `.github/workflows/**` (`run:` は shellcheck へ委譲) | `lint` ジョブ |
| zizmor | 1.30.0 | `.github/workflows/**`, `action.yml` | `lint` ジョブ |
| ruff | 0.15.8 | `tests/pbt/` (check + format) | `lint` ジョブ |

### 2.1 `action.yml` を shellcheck にかける仕組み

actionlint は workflow ファイルしか読まないため、composite action の `run:` は
どのツールでも検査されていなかった。`action.yml` には
`# shellcheck disable=SC2086` ディレクティブがあるにもかかわらず、
shellcheck が一度も走っていないという状態だった。

`scripts/shellcheck-action.sh` がこれを埋める。PyYAML の `yaml.compose()` で
`run:` スカラーのノード位置を取得し、**元ファイルと同じ行番号になるよう改行で
パディングした一時ファイル**を作って shellcheck にかける。ブロックスカラー
(`|` / `>`) では `start_mark.line` が指示子の行を指し本文は次行から始まるため、
その分を補正している (列番号のみブロック本文相対のまま)。

これにより `# shellcheck disable=SC2086` が初めて実際に機能するようになった。

## 3. 導入時に修正した指摘

| ツール | 指摘 | 対応 |
| --- | --- | --- |
| actionlint (SC2046) | `ci.yml` `make -j$(nproc)` | クォート |
| actionlint (SC2046) | `ci.yml` kcov の `$(find ...)` 引数 | クォート |
| zizmor `cache-poisoning` (high) ×2 | `release.yml` の `mlugg/setup-zig` が既定でキャッシュを有効化 | 両ステップに `use-cache: false` |
| ruff check | 未使用 import (`hypothesis.assume`) ほか 8 件 | 自動修正 |
| ruff format | `tests/pbt/` 9 ファイル | 整形 |

修正後、4 ツールすべてがグリーン (zizmor は regular persona で
`No findings to report (14 suppressed)`)。

## 4. parity 整理

### 4.1 zghalint が拾えていないもの (gap)

#### G1. SEC016 が「暗黙にキャッシュする setup 系 action」を認識しない  — 要ルール改善

`release.yml` の `mlugg/setup-zig` に対し zizmor は `cache-poisoning` (high) を
2 件出したが、zghalint の SEC016 は 0 件だった (`use-cache: false` を外した状態で確認済み)。

SEC016 の現行実装 (`src/rules/security.zig`) は

- `actions/cache` の明示利用
- `cache:` 入力を与えた `setup-*` 系 action

しか見ていない。`mlugg/setup-zig`、`astral-sh/setup-uv` のように
**入力を書かなくても既定でキャッシュを有効にする** action がリリース系
ワークフローに現れると検出できない。既知の「既定でキャッシュする action」
リストを SEC016 に持たせるのが対応方針。

#### G2. `action.yml` (composite action) を解析できない — 要スコープ拡張

```
$ zghalint --offline action.yml
action.yml: workflow parse error: MissingField
```

zizmor は composite action を監査対象に含むが、zghalint のパーサは
workflow スキーマ (`on:` / `jobs:`) 前提で composite action を扱えない。
自リポジトリの `action.yml` が誰も静的解析していなかった直接の原因であり、
利用者側の composite action も同様に素通りする。

#### G3. `run:` のシェルレベル解析がない — 意図的な非対応 (現状)

actionlint は `run:` ブロックを shellcheck に流し SC2046 等を検出するが、
zghalint はシェル構文を解析しない (BP007 / BP008 のようなパターン照合のみ)。
shellcheck 相当の実装はスコープ外とし、CI で actionlint を併走させる形で担保する。

#### G4. `permissions` に説明コメントがない — 採用しない

zizmor pedantic の `undocumented-permissions` (1 件)。スタイル規約寄りであり、
YAML コメントの有無を強制するルールは zghalint の診断カテゴリに馴染まないため
採用しない。

#### G5 (#273). 汚染源が `github.event.*` に限られている — 対応済み

`bench/cases/a-script-injection/` で発覚した SEC002 の FN 4 件。zizmor は
いずれも `template-injection` として検出する。

| ケース | 汚染源 |
|---|---|
| `dispatch-inputs.yml` | `workflow_dispatch` の `inputs.*` |
| `workflow-call-inputs.yml` | `workflow_call` の `inputs.*` |
| `tojson-event.yml` | `toJSON(github.event)` (フィールド指定なしの丸ごと展開) |
| `step-output-indirect.yml` | 汚染値を書いた `steps.<id>.outputs.*` の再展開 |

SEC002 をステップ単位からワークフロー単位のルールへ移し、上の 4 つを汚染源に
加えた。`inputs.*` はトリガを、`steps.<id>.outputs.*` は同一ジョブの前段
ステップを見ないと判定できないため、ステップだけを見るルールでは足りない。
`github.event` の根は「まるごと参照したときだけ」の一致にしてあり、
`github.event.number` のようなサーバ生成フィールドは汚染源にしていない。
ステップ出力の汚染は「汚染値を持ったまま `$GITHUB_OUTPUT` へ書いた」ステップの
出力に限り、指摘は展開する後段だけに出る。詳細は `docs/rules.md` の
「SEC002 taint sources」。

#### G6 (#274). `runs-on` が配列のとき SEC020 が発火しない — 対応済み

`bench/cases/b-trigger-checkout/self-hosted-fork-trigger.yml`。
`runs-on: self-hosted` (スカラー) では発火するが
`runs-on: [self-hosted, linux]` では発火しない。配列要素の走査漏れ。

パーサは既にスカラー・配列・ランナーグループ (`{group:, labels:}`) の 3 形を
`runs_on_labels` へ正規化していたので、SEC020 をその走査 (`runner.runsOnLabels`)
に載せ替えた。ラベル 1 件ごとの部分一致は据え置き — 自前プールに
`self-hosted-gpu` のような名前を付ける運用が多いため。

#### G7 (#275). `docker://` 形式の `uses:` を SC001 が見ていない — 対応済み

`bench/cases/c-supply-chain/docker-uses-no-digest.yml`。
`uses: docker://alpine:3.19` はコンテナイメージのタグ参照だが、SC001 は
`container.image` / `services.*.image` しか見ていない。zizmor は pedantic
persona の `unpinned-images` で検出する。

SC001 にステップの走査を足し、`ActionRef.is_docker` が立つ `uses:` を
`container.image` と同じ基準 (`@sha256:` 固定) で見るようにした。
`uses:` のマーケットプレース形は SEC001 の担当なので重複はしない。

#### G8 (#276). SEC005 がフォーク判定のガードを見ない (FP) — 要ルール改善

`bench/cases/b-trigger-checkout/pr-target-guarded.yml`。
`if: github.event.pull_request.head.repo.full_name == github.repository` で
フォーク由来の実行を除外しているジョブでも SEC005 が発火する。SEC022 は
同種のガード解析を持っているので、その判定を SEC005 と共有させたい。

### 4.2 zghalint が拾えていて外部ツールが拾わないもの

- `PERF001` — `ci.yml` の `actions/setup-python` にキャッシュ設定がない
  (actionlint / zizmor いずれも指摘なし)
- `BP002` ×7 — `name` のないステップ

### 4.3 意図的に一致させないもの

- zizmor pedantic の `template-injection` 11 件はすべて `matrix.*` の展開。
  zghalint の SEC002 は untrusted context (`github.event.*` など) に限定して
  誤検出を避ける設計であり、pedantic persona との差分は仕様どおり。
- zizmor `concurrency-limits` 2 件は zghalint の `BP005` が同じ 2 ファイルを
  指摘済み (parity 達成)。
- `bench/cases/c-supply-chain/sha-comment-mismatch.yml` (SHA 固定だが末尾の
  `# vX.Y.Z` コメントが別リリースを名乗る) は 3 ツールとも無反応。共通の
  盲点としてケースだけ残し、当面は検出しない。

### 4.4 ルール間の相互作用メモ

PERF001 (キャッシュを足せ) と SEC016 (リリース系でのキャッシュは危険) は
逆方向の圧力を持つ。現状は PERF001 が release/deploy ワークフローを
対象外にしていないため、G1 の対応時に両ルールの適用条件を併せて確認すること。

## 5. 次アクション

- [ ] G1: SEC016 に「既定でキャッシュする setup action」リストを追加する
- [ ] G2: composite action (`action.yml`) の解析サポートを設計する
- [ ] §4.4: PERF001 と SEC016 の適用条件の整合を確認する
- [x] G5 (#273): SEC002 の汚染源に `inputs.*` と `toJSON(github.event)` を加える
- [x] G6 (#274): SEC020 を `runs-on` の配列形に対応させる
- [x] G7 (#275): SC001 を `uses: docker://...` に対応させる
- [ ] G8 (#276): SEC022 のフォークガード解析を SEC005 と共有する
