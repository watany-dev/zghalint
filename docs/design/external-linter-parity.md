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

#### G2. `action.yml` (composite action) を解析できない — 対応済み

当時のパーサは workflow スキーマ (`on:` / `jobs:`) 前提で、composite action に
`workflow parse error: MissingField` を返していた。現在は ACT 系ルールが
`action.yml` を直接読む。`bench/cases/g-reusable/composite-*.action.yml` で
ACT002 (未対応 / 廃止予定の `runs.using`) と SEC002 (composite の `run:` への
script injection) が出ることを確認した。actionlint は composite action を
読まないため、この 3 ケースは zghalint の unique-win になる。

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

#### G8 (#276). SEC005 がフォーク判定のガードを見ない (FP) — 対応済み

`bench/cases/b-trigger-checkout/pr-target-guarded.yml`。
`if: github.event.pull_request.head.repo.full_name == github.repository` で
フォーク由来の実行を除外しているジョブでも SEC005 が発火する。SEC022 は
同種のガード解析を持っているので、その判定を SEC005 と共有させたい。

SEC022 のガード解析 (`hasTrustAnchor` / `anchorHolds`) をトリガ非依存に
一般化し、アンカーの集合を `TrustAnchors` として渡す形にした。
`pull_request_target` 版は `github.event.pull_request.head.repo` の
`full_name` / `id` / `owner.*` / `fork` を見る。`||` の迂回路や
`fork == true` のような逆向きのガードを弾く判定はそのまま共有される。
SEC009 (`workflow_run` の checkout) も同じ関数でガードを見るようにした。
SEC021 が担当するトリガ (`workflow_dispatch` / `issue_comment` など) は
フォーク由来かどうかという概念を持たないため、対象外。

#### G9 (#280). 関数呼び出しの結果へのプロパティ / インデックスアクセスを解釈できない (FP) — 要パーサ修正

`bench/cases/e-expression/function-call-property-access.yml`。

```yaml
run: echo "${{ fromJSON('{"tag":"v1"}').tag }}"
run: echo "${{ fromJSON('[1,2,3]')[0] }}"
```

いずれも `EXPR001 unexpected token after expression` (error) になる。式パーサが
関数呼び出しを式の終端として扱い、後続の `.field` / `[index]` を余りとみなす。
`fromJSON(env.CFG).name` や `toJSON(github.event).x` も同じ。actionlint は
3 形すべてを正しく解釈する。

影響は FP だけに留まらない。EXPR001 が出た時点で以降の式チェックが打ち切られる
ため、`bench/cases/e-expression/fromjson-invalid-literal.yml`
(`fromJSON('{bad').name`) では本来出るべき EXPR009 (不正な JSON リテラル) が
落ちる。ベンチ全体で唯一の zghalint FN がこれ。

#### G10 (#281). `needs:` の未定義ジョブ / 循環依存を検出しない — 要ルール追加

`bench/cases/f-syntax-schema/needs-unknown-job.yml` と `needs-cycle.yml`。
存在しないジョブ名を `needs:` に書いても、ジョブ依存が閉路を作っても zghalint は
無反応。どちらも実行時に必ず失敗する構成で、actionlint は `job-needs` として
両方を報告する。

#### G11 (#282). UTF-8 BOM 付きのファイルを解析できない — 対応済み

`bench/cases/i-robustness/bom-prefixed.yml`。

```
$ zghalint --offline bom-prefixed.yml
bom-prefixed.yml: workflow parse error: InvalidValue
```

先頭 3 バイトの BOM がキー名の一部として読まれ、ファイル全体が解析対象から
落ちる。Windows のエディタが書き出す実在の形で、actionlint は問題なく読む。
終了コードは 2 なので黙って通るわけではないが、指摘は 1 件も出ない。

`Tokenizer.init` が先頭の BOM を読み飛ばすようにした。BOM のバイト列は
`source` に残したまま開始位置だけを進めるので、スパンのバイトオフセットは
実ファイルの位置を指したままで、行・カラムもずれない。BOM なしの同等ケースと
同じ行の同じ指摘 (BP008) が出る。

#### G12 (#283). 明示的な YAML ドキュメントマーカーを解析できない — 要パーサ修正

`bench/cases/i-robustness/multi-document.yml`。`---` で始まり `...` で終わる
書き方 (YAML として完全に正当) を `InvalidValue` で拒否する。G11 と同じく
ファイル全体が素通りになる。

#### G13 (#284). 中身のないワークフローを指摘しない — 要ルール追加

`bench/cases/i-robustness/comments-only.yml`。コメントだけのワークフロー
ファイルを `InvalidValue` で拒否する。actionlint は `workflow is empty` と
診断として報告しており、消し忘れのファイルを見つけられる形になっている。
パースエラーではなく診断として出すのが望ましい。

#### G14 (#285). PERM001 がジョブに必要な write 権限まで警告する (FP) — 要ルール改善

`bench/cases/j-clean/` の 3 ケース。

- `clean-codeql-scan.yml` — CodeQL の `security-events: write`
- `clean-release-publish.yml` — trusted publishing の `id-token: write`
- `safe-untrusted-in-with.yml` — ラベル付けジョブの `issues: write`

いずれも GitHub の公式手順どおりの最小権限だが PERM001 (warning) が出る。
zizmor の `excessive-permissions` はどれも指摘しない。ジョブが実際に使う
action / API から必要な scope を推定するか、既知の必須 scope を持たせて
除外する必要がある。ベンチの FP 5 件中 3 件がこれで、precision を 95% に
下げている唯一の要因が G9 と G14 の 2 つ。

#### G15 (#286). API トークンでの publish を指摘しない (trusted publishing 未使用) — 要ルール追加

`bench/cases/d-permissions-secrets/api-token-instead-of-oidc.yml`。

```yaml
- uses: pypa/gh-action-pypi-publish@76f52bc...  # v1.12.4
  with:
    password: ${{ secrets.PYPI_API_TOKEN }}
```

長命の API トークンを渡す形。同じ action は OIDC (trusted publishing) に対応
しており、`id-token: write` があればトークン自体が不要になる。zizmor は
`use-trusted-publishing` として指摘するが、zghalint は該当ルールを持たない。
SEC019 (secret を `env:` 経由にせず直接使う) が同じステップで発火するものの、
「そもそもトークンが要らない」ことは伝えていない。#271 の FN 候補 1 の検証結果。

### 4.2 zghalint が拾えていて外部ツールが拾わないもの

- `PERF001` — `ci.yml` の `actions/setup-python` にキャッシュ設定がない
  (actionlint / zizmor いずれも指摘なし)
- `BP002` ×7 — `name` のないステップ
- `DEP003` — `uses: actions//checkout@v4` のような難読化された `uses:`
  (`bench/cases/c-supply-chain/uses-obfuscated.yml`)。zizmor の `obfuscation`
  はこの形を指摘せず、actionlint は形式不正として拾う。#271 の FN 候補 3 は
  FN ではなかった

### 4.3 意図的に一致させないもの

- zizmor pedantic の `template-injection` 11 件はすべて `matrix.*` の展開。
  zghalint の SEC002 は untrusted context (`github.event.*` など) に限定して
  誤検出を避ける設計であり、pedantic persona との差分は仕様どおり。
- zizmor `concurrency-limits` 2 件は zghalint の `BP005` が同じ 2 ファイルを
  指摘済み (parity 達成)。
- `bench/cases/c-supply-chain/sha-comment-mismatch.yml` (SHA 固定だが末尾の
  `# vX.Y.Z` コメントが別リリースを名乗る) は 3 ツールとも無反応。共通の
  盲点としてケースだけ残し、当面は検出しない。
- `bench/cases/e-expression/env-undefined.yml` (どの `env:` でも定義していない
  `env.NAME` の参照) も 3 ツールとも無反応。同じく共通の盲点。
- YAML のアンカー / エイリアス / マージキーは zghalint (#64) も actionlint も
  解決しない。`bench/cases/i-robustness/yaml-anchors-and-merge-keys.yml` は
  両ツールを skip し、状況の記録だけに使う。
- 外部ツール側の観察: zizmor 1.30.0 は中身のないワークフロー
  (`i-robustness/comments-only.yml`) と `timeout-minutes: "10m"`
  (`f-syntax-schema/shell-and-timeout-types.yml`) でクラッシュする (exit 3)。

### 4.4 ルール間の相互作用メモ

PERF001 (キャッシュを足せ) と SEC016 (リリース系でのキャッシュは危険) は
逆方向の圧力を持つ。`bench/cases/h-practices/cache-in-release-workflow.yml`
(`on: release` + `actions/cache`) で確認したところ、SEC016 だけが発火し
PERF001 は沈黙しており、現状は整合が取れている。

`setup-with-default-cache.yml` (`mlugg/setup-zig` / `astral-sh/setup-uv`) では
PERF001 が正しく沈黙する — つまり「既定でキャッシュする action」の知識は
PERF001 側にはある。G1 はその知識を SEC016 と共有すれば済む。

## 5. 次アクション

- [ ] G1: SEC016 に「既定でキャッシュする setup action」リストを追加する
      (PERF001 が持っている知識を共有する)
- [x] G2: composite action (`action.yml`) の解析サポート
- [x] §4.4: PERF001 と SEC016 の適用条件の整合を確認する
- [ ] G9 (#280): 関数呼び出しの結果へのプロパティ / インデックスアクセスを式パーサに
      解釈させる (EXPR009 の取りこぼしもこれで直る)
- [ ] G10 (#281): `needs:` の未定義ジョブと循環依存を検出する
- [x] G11 (#282): UTF-8 BOM を読み飛ばす
- [ ] G12 (#283): `---` / `...` のドキュメントマーカーを受理する
- [ ] G13 (#284): 中身のないワークフローを診断として報告する
- [ ] G14 (#285): PERM001 がジョブに必要な write 権限を除外する
- [ ] G15 (#286): API トークンでの publish を指摘する (trusted publishing への誘導)
- [x] G5 (#273): SEC002 の汚染源に `inputs.*` と `toJSON(github.event)` を加える
- [x] G6 (#274): SEC020 を `runs-on` の配列形に対応させる
- [x] G7 (#275): SC001 を `uses: docker://...` に対応させる
- [x] G8 (#276): SEC022 のフォークガード解析を SEC005 と共有する
