# 外部リンター統合と parity 整理

最終更新: 2026-09-12

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
| actionlint | 1.7.12 (SHA256 検証) | `.github/workflows/**` (`run:` は shellcheck へ委譲) | `lint` ジョブ |
| zizmor | 1.30.1 | `.github/workflows/**`, `action.yml` | `lint` ジョブ |
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

### 2.2 性能比較に足すツール (`--perf` のみ)

採点行列は actionlint / zizmor の 3 者のままにする。指摘 ID の対応表
(`DEFAULT_KIND_MAP` と `bench:expect`) がこの 2 ツール向けで、方針リンターや
スキーマ検証器を同じ kind に載せる作業は parity gap の追跡とは別物になる。

`--perf` にはローカルのワークフロー YAML を lint / scan する CLI を足す。
導入は `scripts/install-perf-rivals.sh` (Linux x86_64、SHA256 ピン)。PATH に
無ければ「見つからない」として表に載り、計測は続く。

| ツール | 版 | 何をするか |
| --- | --- | --- |
| ghalint | 1.5.6 | セキュリティ方針 (権限、timeout、SHA ピン) |
| octoscan | 0.1.7 | actionlint ベースの脆弱性スキャナ |
| poutine | 1.1.6 | CI/CD サプライチェーンスキャナ (OPA)。`--disable-version-check` |
| action-validator | 0.9.0 | workflow / action の JSON Schema |

載せないもの: frizbee / pinny / scharf / pinact (ピン留め専用)、Scorecard
(GitHub API)、ggshield (シークレット)、Semgrep / Checkov / super-linter
(汎用 SAST / 集約)。詳細は `bench/README.md`。

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

#### G1. SEC016 が「暗黙にキャッシュする setup 系 action」を認識しない  — 対応済み

`release.yml` の `mlugg/setup-zig` に対し zizmor は `cache-poisoning` (high) を
2 件出したが、zghalint の SEC016 は 0 件だった (`use-cache: false` を外した状態で確認済み)。

SEC016 の現行実装 (`src/rules/security.zig`) は

- `actions/cache` の明示利用
- `cache:` 入力を与えた `setup-*` 系 action

しか見ていない。`mlugg/setup-zig`、`astral-sh/setup-uv` のように
**入力を書かなくても既定でキャッシュを有効にする** action がリリース系
ワークフローに現れると検出できない。既知の「既定でキャッシュする action」
リストを SEC016 に持たせるのが対応方針。入力名は action ごとに違い、
`cache:` だけではなく `enable-cache` (`astral-sh/setup-uv`) や
`package-manager-cache` (`actions/setup-node`) や `use-cache`
(`mlugg/setup-zig`) がある。

再現ケースは `bench/cases/h-practices/setup-uv-default-cache-in-release.yml`。
`on: release` とジョブ名 `publish` で `job_at_risk` は立つが、`setup-uv` に
`cache:` が無いので SEC016 は沈黙する。zizmor は `cache-poisoning` を出す。
実運用のワークフロー群を三者比較したところ、同じ形 (setup-uv の
`enable-cache` 省略、setup-node の `package-manager-cache` 省略) が
publish ジョブで複数出た。G33 の tag-push 判定とは別経路。

対応: `cache_setup_actions` を「action 名 + キャッシュ入力名 + 既定で
有効か」の表にし、既定で有効な action は入力の省略そのものを指摘するように
した (`astral-sh/setup-uv` の `enable-cache`、`mlugg/setup-zig` の
`use-cache`)。入力があるときは値を opt-out として読み、`false` のときだけ
沈黙する。これに伴い、opt-in 側 (`cache: false` など) の明示的な無効化も
指摘しなくなった。`actions/setup-node` の自動 npm キャッシュ
(`package-manager-cache` + `package.json` の `packageManager` /
`devEngines.packageManager`) は GA8 (#435) で PERF001 / SEC016 の判定に
入れた。major や未解決 SHA だけでは有効と断定しない。

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

#### G9 (#280). 関数呼び出しの結果へのプロパティ / インデックスアクセスを解釈できない (FP) — 対応済み

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

式パーサに postfix チェーン (`parsePostfix`) を入れて、関数呼び出しの結果にも
`.field` / `[expr]` を続けられるようにした。新しいノード種別は 2 つ
(`property_access` / `index_access`) で、受け手は `children[0]`。コンテキスト
参照はこれまでどおり平坦な文字列パスの `context_access` のままなので、
EXPR010-EXPR016 や SEC002 のパス解決には影響しない。型検査側は受け手の型に
セグメントを 1 つ適用するだけで、`fromJSON` の結果に無いキーは実際には
分からないため診断は出さず `any` に落とす。

これでベンチの FN は 0 件になり、recall は 100% になった。

#### G10 (#281). `needs:` の未定義ジョブ / 循環依存を検出しない — 対応済み

`bench/cases/f-syntax-schema/needs-unknown-job.yml` と `needs-cycle.yml`。
存在しないジョブ名を `needs:` に書いても、ジョブ依存が閉路を作っても zghalint は
無反応だった。どちらも実行時に必ず失敗する構成で、actionlint は `job-needs` として
両方を報告する。

`src/rules/needs_graph.zig` に 2 ルールを追加した。SYN021 は `needs:` の各項目を
ジョブ名の集合と照合し、編集距離 2 以内の候補が 1 つあれば `--fix` のリネームを
付ける。SYN022 はジョブグラフを深さ優先で一度だけ走査し、戻り辺 1 本につき 1 件、
閉路が戻ってくるジョブのキーで報告する (自己参照も閉路)。どちらもパース済みの
`Workflow` だけで完結するので追加の I/O は無い。

ID 命名規則に反する項目 (`1-build`) は SYN006 が既に報告するため SYN021 では
飛ばし、同じ span に error を二重に出さない。指摘位置は問題の名前が書かれている
`needs:` の項目そのものにしたので、ジョブのキー行を指す actionlint に合わせて
いたケースの `@<line>` を 13 → 14 に直した。

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

#### G12 (#283). 明示的な YAML ドキュメントマーカーを解析できない — 対応済み

`bench/cases/i-robustness/multi-document.yml`。`---` で始まり `...` で終わる
書き方 (YAML として完全に正当) を `InvalidValue` で拒否していた。G11 と同じく
ファイル全体が素通りになる。

トークナイザはもともと `---` / `...` を認識しており、落ちていたのはパーサ側
だった。`Parser.parse` は最初のトークンだけを見て `---` を判定していたため、
マーカーの前にコメント行 (ライセンスヘッダやリンタのディレクティブ) が 1 行
でもあると読み飛ばしに失敗していた。コメントと空行を先に読み飛ばしてから
マーカーを判定するようにして、マーカーなしの同等ケースと同じ行に同じ指摘
(BP008) が出るようにした。

ワークフローファイルは単一ドキュメントなので、2 つ目以降の `---` は
`MultipleDocuments` で拒否する。黙って先頭ドキュメントだけを解析すると、
ファイルの残り半分がどのルールからも見えなくなるため。文書終端の `...` は
2 つ目のドキュメントではないので、そのまま読み飛ばす。

#### G13 (#284). 中身のないワークフローを指摘しない — 対応済み

`bench/cases/i-robustness/comments-only.yml`。コメントだけのワークフロー
ファイルを `InvalidValue` で拒否していた。actionlint は `workflow is empty` と
診断として報告しており、消し忘れのファイルを見つけられる形になっている。

SYN020 (`empty-workflow`, error) を追加し、ワークフローパーサに渡す前の
YAML ドキュメントの段階で「中身が無い」ことを報告するようにした。空白と
コメントだけのファイル、および空のマッピング (`{}`) が対象。終了コードは
2 (lint 不能) から 1 (指摘あり) になった。中身のあるルート (シーケンスや
値を持つスカラー) は型の誤りなので、従来どおりパースエラーとして扱う。

#### G14 (#285). PERM001 がジョブに必要な write 権限まで警告する (FP) — 対応済み

`bench/cases/j-clean/` の 3 ケース。

- `clean-codeql-scan.yml` — CodeQL の `security-events: write`
- `clean-release-publish.yml` — trusted publishing の `id-token: write`
- `safe-untrusted-in-with.yml` — ラベル付けジョブの `issues: write`

いずれも GitHub の公式手順どおりの最小権限だが PERM001 が出ていた。
zizmor の `excessive-permissions` はどれも指摘しない。

個別スコープの `write` を一律に報告するのをやめ、**スコープの性質**と
**宣言箇所**の 2 軸で判定するようにした。

軸 1 — 権限昇格に繋がるスコープ (`actions` / `contents` / `deployments` /
`packages`) は宣言箇所を問わず報告する。この 4 つは write を得た時点で
リポジトリが保存・実行・公開するもの (コード、ワークフロー、デプロイ、
パッケージ) を書き換えられ、そのジョブの実行範囲を超えて影響が及ぶ。

軸 2 — 残りはリポジトリの**メタデータ** (issue, PR, check, status,
discussion, project, code scanning alert, attestation, artifact metadata,
models, Pages のデプロイ) を書くか、OIDC トークンを発行する (`id-token`)
だけである。GitHub の公式手順がこれらを `write` で要求しており、それ以下に
絞る手段もない — CodeQL は `security-events: write`、trusted publishing は
`id-token: write`、`actions/deploy-pages` は `pages: write` を要る。
**それを必要とするジョブの上で**指摘してもノイズにしかならないので報告しない。
ただし**ワークフローレベル**の宣言は話が別で、そのスコープが無関係なジョブに
まで配られるため引き続き報告する (autofix は付けない — レベルを下げると必要な
ジョブが壊れるので、直し方は「必要なジョブへ移す」であり機械的には書けない)。

`contents: write` を読み取りだけのジョブで宣言するような過剰権限
(`bench/cases/d-permissions-secrets/job-widens-permissions.yml`) は引き続き
検出する。`write-all` も従来どおり warning。ベンチの FP は 5 件から 0 件に
なり、G9 の解消と合わせて precision は 95% → 100% になった。

回帰ガードは `tests/fixtures/e2e/perm001-scope-placement.yml` (ジョブ側は
出ない) と `perm001-workflow-level-grant.yml` (ワークフロー側は出る)。

#### G15 (#286). API トークンでの publish を指摘しない (trusted publishing 未使用) — 対応済み

`bench/cases/d-permissions-secrets/api-token-instead-of-oidc.yml`。

```yaml
- uses: pypa/gh-action-pypi-publish@76f52bc...  # v1.12.4
  with:
    password: ${{ secrets.PYPI_API_TOKEN }}
```

長命の API トークンを渡す形。同じ action は OIDC (trusted publishing) に対応
しており、`id-token: write` があればトークン自体が不要になる。zizmor は
`use-trusted-publishing` として指摘していた。SEC019 (secret を `env:` 経由に
せず直接使う) が同じステップで発火するものの、「そもそもトークンが要らない」
ことは伝えていなかった。#271 の FN 候補 1 の検証結果。

SEC023 (`use-trusted-publishing`, info) を追加した。OIDC 対応レジストリへの
publish で長命トークンを渡している step を、次の 3 つの形で報告する。

| 対象 | 発火条件 |
|---|---|
| `pypa/gh-action-pypi-publish` | `with.password` が空でない |
| `rubygems/release-gem` | `with.setup-trusted-publisher: false` (既定は trusted publishing) |
| `npm publish` を含む `run:` | 同じ step の `env.NODE_AUTH_TOKEN` が `${{ secrets.* }}` |

いずれも `fix_hint` で「`id-token: write` を付けて trusted publishing へ
切り替える」ことを示す。autofix は付けない — トークンを外すにはレジストリ側の
publisher 設定が要り、ワークフローの書き換えだけでは完結しないため。

npm は step 自身の `env:` だけを見る。ジョブ / ワークフローに束ねた
`NODE_AUTH_TOKEN` は、どの step が publish するのかを静的に決められない。
`${{ steps.*.outputs.* }}` のように実行時に組み立てた値は、既に短命トークンで
ある可能性があるので報告しない。`bench/cases/j-clean/clean-release-publish.yml`
(`npm publish --provenance` をトークン無しで実行する) は FP にならない。

回帰ガードは `tests/fixtures/e2e/sec023-trusted-publishing.yml` (3 つの形が
出る) と `sec023-trusted-publishing-clean.yml` (OIDC で publish する形は
出ない)。

#### G16 (#297). ブロックシーケンスを親キーと同じ桁に書くと読み落とす — 要パーサ修正

```yaml
steps:
- name: Greet the author
  run: echo "${{ github.event.head_commit.message }}"
```

`-` を親キーと同じ桁に置く形は YAML として正当だが、
`Parser.parseBlockMapping` はキーの値を「次行以降で **key_indent より深い**
列に始まるもの」に限っており、同じ桁のシーケンスをそのキーの値として
取り込まない。

現れ方は 2 通りある。

- `steps:` で起きると値が `null` になり、**そのジョブのステップが 1 つも
  無かったことになる**。パースは通ってしまうので、ステップ側のルール
  (SEC002 ほか) が丸ごと沈黙したうえ、SYN003「steps section should not be
  empty」という誤検出まで出る
  (`bench/cases/i-robustness/seq-at-steps-column.yml`)。
- `on.push.branches` で起きると `on` の解析が `InvalidValue` で落ち、
  ファイルごと lint 不能になる
  (`bench/cases/i-robustness/seq-at-trigger-column.yml`)。

実コーパス (`bench/corpus/`、228 ファイル) では 28 ファイルがこの書き方を
含む。actionlint / zizmor はどちらも正しく解析する。

#### G17 (#298). `-` だけの行でシーケンス項目を開けない — 要トークナイザ修正

```yaml
steps:
  -
    name: Greet the author
    run: echo "${{ github.event.head_commit.message }}"
```

`Tokenizer` は `c == '-' and self.peekNext() == ' '` でしかシーケンス項目の
指示子を認めない。行末の `-` は次が改行なので平文スカラー `-` になる。YAML
では `-` の後は空白でも改行でもよい。

これも現れ方が 2 通りある。1 件目の項目がこの形だと `steps:` の値がスカラー
`-` になり `InvalidValue` でファイルごと落ちる
(`bench/cases/i-robustness/bare-dash-sequence-entry.yml`)。2 件目以降だと
シーケンスの走査がそこで止まり、**残りのステップが黙って消える**。

実コーパスでは 32 ファイルがこの書き方を含む。G16 と合わせると 60/228
(26%) が影響を受け、うち 36 ファイルは lint 自体ができない。

#### G18 (#299). BP001 が再利用ワークフロー呼び出しジョブに `timeout-minutes` を足す (FP) — 要ルール修正

```yaml
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    secrets: inherit
```

`checkMissingTimeout` は `uses:` を持つジョブ (reusable workflow の呼び出し)
を除外していない。GitHub Actions はこの形のジョブに `timeout-minutes` を
受け付けず、actionlint も `syntax-check` で弾く。警告が誤検出であるだけでなく
**autofix (safety: safe) が不正なワークフローを書き込む**ので、`--fix` だけで
壊れる。`bench/cases/d-permissions-secrets/secrets-inherit.yml` ほか、
`g-reusable/` の caller 4 件で再現する。

#### G19 (#300 / #335). SEC015 と SEC018 が同じステップへ `with:` を二重挿入する — 対応済み

`bench/cases/d-permissions-secrets/artipacked-upload.yml` の
`actions/checkout` には SEC015 と SEC018 が同時に発火し、どちらも
`with: persist-credentials: false` を挿入する autofix を持つ。
`--fix-unsafe` は両方を適用するため同じステップに `with:` が 2 つ並び、
結果は SYN002 (キー重複) を出す不正なワークフローになる。

同じアンカーへの同一挿入は 1 回にまとめる (#300)。加えて SEC015 が成立する
step では SEC018 を抑制し、より具体的な artifact 漏洩のメッセージだけを出す
(#335)。SEC015 を `.zghalint.yml` で無効にすると SEC018 は残る。

#### G20 (#304). ネットワークに到達できないとき SC003〜SC006 が黙って沈黙する — 対応済み

bench 132 件をネットワーク遮断下の通常実行と `--offline` で突き合わせると、
診断 ID の集合・終了コード・stderr がいずれも完全一致していた。利用者からは
「ネットワークが使えなかった」ことと「指摘が無かった」ことを区別できず、
トークン未設定・レート制限・プロキシ遮断のいずれでも
`bench/cases/c-supply-chain/known-vulnerable-action.yml` 相当の実問題が
グリーンのまま素通りする。

`src/rules/net_status.zig` が「判定できなかったルール」を記録し、実行の
最後に stderr へ 1 行の注記を出すようにした
(`note: SC003, SC005 skipped (github api unreachable; check HTTPS_PROXY / SSL_CERT_FILE)`)。記録はルールの
判定地点で行うので、prefetch が失敗しても REST フォールバックが答えを
出せた場合は注記が出ない。`--offline` / `--quick` は沈黙が意図どおりなので
注記しない。終了コードは 0/1/2 の意味を変えると利用者の CI を壊すため
据え置き。JSON / SARIF への搭載は別途検討。

#### G21 (#305). DEP004 が `actions/checkout` の `path:` で作られるローカル action を誤検出する (FP) — 対応済み

```yaml
- uses: actions/checkout@v4
  with:
    path: action-under-test
- uses: ./action-under-test
```

`./action-under-test` はリポジトリには無く、直前の `actions/checkout` が
`path:` で**実行時に作る**ディレクトリである。静的に見て「見つからない」のは
当然で、DEP004 の指摘は誤検出になる (actionlint は exit 0)。実コーパス
(33 リポジトリ / 228 ワークフロー) の DEP004 44 件は**すべて**この形だった。

DEP004 を step スコープから job スコープへ移し、同一ジョブ内で当該ステップ
より前にある `actions/checkout` の `path:` が指すディレクトリ以下への
`uses: ./...` を対象外にした。`path:` が `${{ }}` を含む場合は実行時にしか
解決できないので同様に対象外とする。composite action の `runs.steps` も
同じ経路を通る。

回帰ガードは `tests/fixtures/e2e/dep004-checkout-path.yml` と
`bench/cases/g-reusable/checkout-path-local-action/`。前者を効かせるため、
E2E ハーネスがローカル action のルートをリポジトリルートに設定するように
した (それまでは `uses: ./x` が常に `.unavailable` になり、`forbid DEP004`
が空振りしていた)。

#### G22 (#346). SYN009 の `--fix` がタイポを特権トリガへ直す — 対応済み

`bench/cases/f-syntax-schema/invalid-event-name.yml`。
`on: pull_request_targt:` は実行されない無効イベントだが、`--fix` が
`did you mean "pull_request_target"` をそのまま適用して特権トリガにする。
zizmor は書き換え後に `dangerous-triggers` を新規に出す。

`docs/rules.md` は SYN009 の候補置換を safe な autofix と書いてあるが、
無効な名前を `pull_request_target` / `workflow_run` のような secrets 付き
トリガへ直すのは意味保存ではない。候補が特権トリガなら `--fix` では触らず、
`--fix-unsafe` でのみ置換する。

#### G23 (#347). SYN001 の `--fix` が既にあるキーへリネームして SYN002 を作る — 対応済み

`bench/cases/f-syntax-schema/unknown-key-job-and-step.yml`。
`runs-on:` の隣の `runs-onn:` を `--fix` が `runs-on` に直すとキーが二つになり、
再 lint で SYN002 が出る。`wth:` は候補が一意でないため触れず、こちらは残る。

リネーム先の兄弟キーが既にあれば autofix を付けない。大文字小文字だけが違う
兄弟も SYN002 と同じく衝突とみなす。

#### G24 (#348). SYN001 のリネームと SEC007 の挿入が同じ `permissions:` を二重に作る — 対応済み

`bench/cases/f-syntax-schema/unknown-key-top-level.yml`。`prmissions:` は
SYN001 が `permissions` へリネームし、SEC007 はトップレベルに `permissions:` が
無いと見て別のブロックを挿入する。`--fix` だけならリネームだけで済むが、
`--fix-unsafe` は両方を適用して SYN002 になる。G19 と同じ「同一ファイルへ
同じキーを二経路で足す」問題で、リネーム先と挿入キーの衝突を fix エンジンが
見ていない。

fix エンジンは、同一マッピングでリネームが作るキーと挿入が作るキーが一致
したら挿入を落とす。リネームは既存のブロックを残すので残す。

#### G25 (#349). `*-dependabot.yml` を Dependabot 設定と誤認してワークフロー検査をしない — 対応済み

`src/main.zig` の `isDependabotFile` はパスが `dependabot.yml` /
`dependabot.yaml` で終わるかだけを見る。実コーパスの
`peter-evans/create-pull-request` の `automerge-dependabot.yml` は
`github.actor == 'dependabot[bot]'` をジョブの `if:` に持つ普通の
ワークフローだが、ファイル名が `dependabot.yml` で終わるため Dependabot
用のパーサへ送られ、**指摘 0 件・終了コード 0** で終わる。
同じ中身を `automerge.yml` にリネームすると SEC014 / BP001 / SEC007 が
普通に出る。

判定をベース名がちょうど `dependabot.yml` / `dependabot.yaml` のときだけに
限った。`isActionMetadataFile` が既に持っていた「`.github/workflows/` の下は
名前によらずワークフロー」という例外も共通ヘルパ `isDocumentFileNamed` に
まとめ、両者で同じ判定にした。回帰ケースは
`bench/cases/b-trigger-checkout/automerge-dependabot.yml`。

#### G26 (#358). BP003 が第三者アクションの古い major を見逃す — 対応済み

```yaml
- uses: softprops/action-gh-release@v1   # 埋め込み表が知る現行 major は 2
```

BP003 は古いアクションを 2 経路で見ていた。埋め込みメタデータ表
（`src/rules/data/popular_actions.zig`）の `runs.using` が廃止済みなら `error`、
手書きのバージョン表（`deprecated_actions`）に載っていれば `warning` である。
表は読んだ major を全て持つが、第三者アクションについては現行 major しか読んで
いないため、古い major の参照はどのエントリにも一致せず `using` が分からない。
手書きの表は `actions/*` の 8 件だけなので、そちらにも掛からない。actionlint /
zizmor も指摘しないので parity gap ではないが、2 経路の隙間に落ちる構造上の穴で
ある。

第 3 の判定として「参照している major < 表が知る最新 major」を `info` で報告する
ようにした（`popular_actions.latestMajor()`）。データは今の表のままでよい。
`deprecated_actions` が名指すアクションは「まだ許容する最も古い major」を人が
決めているので対象外にし、autofix は major を上げる破壊的変更なので `unsafe`
（`--fix-unsafe` 側）に置いた。判断の詳細は
`docs/adr/0015-bp003-behind-current-major.md`。回帰ケースは
`tests/fixtures/e2e/bp003-behind-current-major.yml`。

#### G29. `actions/create-github-app-token` が installation の全権限を継承する — 要ルール追加

`bench/cases/d-permissions-secrets/github-app-token-unscoped.yml`。

```yaml
- uses: actions/create-github-app-token@...
  with:
    app-id: ${{ secrets.APP_ID }}
    private-key: ${{ secrets.PRIVATE_KEY }}
```

`permission-*` 入力を付けないと、発行されるトークンは GitHub App の
installation が持つ全スコープを継承する。zizmor は `github-app` として
指摘する。zghalint には該当ルールが無い。実運用のワークフロー群を三者比較
したところで 3 件出た。`permission-issues: write` のようにスコープを書いた
呼び出しは zizmor も黙るので、入力の有無で切れる。

#### G30 (#382). オブジェクト軸の未定義プロパティを EXPR011 が見ない — 対応済み

`bench/cases/e-expression/matrix-object-property-undeclared.yml`。

```yaml
strategy:
  matrix:
    platform:
      - target: x86_64-unknown-linux-gnu
        arch: x64
steps:
  - run: echo "${{ matrix.platform.image }}"
```

EXPR011 は `matrix.<key>` の第 1 セグメントだけを軸名 / `include:` のキーと
照合し、一致したら残りのパスを見ない。軸値がマッピングでも、どのセルにも
無いプロパティへのアクセスは沈黙する。actionlint はオブジェクト型
`{arch: string; target: string}` に対して `property "image" is not defined`
を出す。スカラー軸の未定義キーは既存の `matrix-key-undeclared.yml` で取れている。

実運用のワークフロー群を三者比較したところで、軸オブジェクトに無いキーを
参照する `run:` / `with:` が複数ジョブで出た。セルによってキーが違う場合は
和集合を宣言済みとみなし、値が式のセルはその軸では沈黙する。

軸ごとにプロパティ名の集合を持たせ、`matrix.<axis>.<prop>` の第 2 セグメント
まで照合するようにした。集合は軸の各セルと、同じ軸を足す `include:`
エントリのマッピングキーの和集合。セルがマッピングでない (スカラー軸、
`${{ }}` で作られるセル、式のキー) 軸は集合を数え上げられないので、その軸の
プロパティは従来どおり見ない。3 セグメント目以降も見ない。

#### G31 (#383). DEP003 が `$/` の自己参照 `uses:` を形式不正にする — 対応済み

`bench/cases/g-reusable/self-repository-prefix.yml`。

```yaml
jobs:
  call:
    uses: $/.github/workflows/reusable.yml
```

`$/.github/workflows/{file}` (ジョブ) と `$/{path}` (ステップ) は、ワークフロー
自身のリポジトリの実行中コミットを指す自己参照で、`./` と同様に `@ref` を
付けてはいけない。DEP003 は `$/` をリモート参照の `{owner}` として読み、
`@ref` が無いので error にする。zizmor は指摘しない。actionlint 1.7.7 も
形式不正とするが、github.com では正規の構文である。

§4.3 の `self-repository` (zizmor が `./` を `$/` へ書き換えろと勧める指摘)
は引き続き採用しない。こちらは既に書かれた `$/` を誤って弾く誤検出。

#### G32 (#384). RUNNER002 が `ubuntu-slim` を未知ラベルにする — 対応済み

`bench/cases/h-practices/ubuntu-slim-runner.yml`。

```yaml
jobs:
  lint:
    runs-on: ubuntu-slim
```

`ubuntu-slim` は GitHub-hosted の 1 vCPU Linux ランナーの公式ラベル。
`known_labels` に無いため、`ubuntu-` で始まる未知ラベルとして RUNNER002 が
error を出す。actionlint 1.7.7 も未知とするが、指摘は誤り。`macos-15-intel`
は `macos-15` の接尾辞として受理される一方、`ubuntu-slim` はどの現行ラベルの
接尾辞にもならない。表を足すときは現行の公式ラベル一覧と突き合わせる。

#### G33 (#386). SEC016 が tag push のリリースを対象にしない — 対応済み

`bench/cases/h-practices/cache-on-tag-push.yml`。

```yaml
on:
  push:
    tags:
      - "v*"
jobs:
  build:
    steps:
      - uses: actions/cache@...
```

SEC016 の対象判定は `on: release` か、ジョブ id / 表示名に `deploy` /
`release` / `publish` / `prod` が含まれることだけである。タグを push して
成果物を出す形はどちらにも落ちず、明示的な `actions/cache` でも沈黙する。
zizmor は tag-push を公開ワークフローとして `cache-poisoning` を出す。

実運用のワークフロー群を三者比較したところ、タグ発火のリリースでジョブ名が
`build` 系のままキャッシュしている形が出た。G1 (既定でキャッシュする
setup action) を直しても、この判定は残る。`on: push` のブランチだけ
(タグ無し) は対象外のままにする。

#### G36 (#419). 真偽値関数の結果を SEC002 が注射とみなす — 対応済み

`bench/cases/a-script-injection/boolean-function-in-run.yml`。
`startsWith(github.event.issue.title, 'fix')` のように、式全体が真偽値を返す
組み込み呼び出しであれば、展開されるのは `true` / `false` だけである。
SEC002 は既存の式パーサと関数カタログで戻り値と引数の個数を確認して除外する。
`&&` / `||` で汚染文字列を返す式、未知の関数、直接の汚染参照は除外しない。
同じ `run:` に安全な式と危険な式がある場合、autofix も危険な式だけを対象にする。

#### G37 (#421). 行をまたぐ plain scalar の `${{ }}` を未閉じにする — 対応済み

`bench/cases/i-robustness/plain-scalar-wrapped-expression.yml` と
`plain-scalar-wrapped-injection.yml`。

```yaml
env:
  REF: ${{ github.sha
    }}
run: echo "${{ github.event.issue.title
  }}"
```

YAML の plain scalar は次のより深い行へ続き、改行は空白に畳まれる。
`${{` と `}}` を別行に置く書き方は正当だが、トークナイザの
`scanPlainScalar` は改行でトークンを終え、`${{` の閉じ探索も同一行に
限っていた。最初の行だけで値が切れ、EXPR001 `unclosed expression: missing }}`
が出ていた。actionlint / zizmor は式として読む。

`skipExpressionInterpolation` はブロック文脈では、その行より深くインデント
した継続行（空行を含む）まで `}}` を探す。閉じが見つかればトークンは行を
またぎ、EXPR001 は出ず SEC002 は式全体を見る。同じ桁か浅い行の `}}` は次の
キーであり、閉じには使わない。flow コレクションは従来どおり同一行に限る。

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
- YAML のアンカー / エイリアス / マージキーは zghalint が #64 で解決するように
  なった (`src/yaml/parser.zig`)。actionlint は alias node を解決せず
  `defaults` を型エラーとして弾くため、
  `bench/cases/i-robustness/yaml-anchors-and-merge-keys.yml` では actionlint
  だけを skip する。
- 外部ツール側の観察: zizmor 1.30.0 は中身のないワークフロー
  (`i-robustness/comments-only.yml`) と `timeout-minutes: "10m"`
  (`f-syntax-schema/shell-and-timeout-types.yml`) でクラッシュする (exit 3)。
- zizmor pedantic / auditor の `anonymous-definition` (workflow / action に
  `name:` が無い) と `self-repository` (`uses: ./` を `$/.` に書き換えろ) は
  採用しない。前者は GitHub UI の表示の話で、後者は公式ドキュメントが
  `./` を正規のローカル参照として載せており、zghalint が DEP004 で見ている
  のもその形である。
- zizmor の `superfluous-actions` (`softprops/action-gh-release` を `gh release`
  の `run:` に書き換えろ) は informational で、第三者アクションの好みの話
  なので採用しない。
- zizmor の `dangerous-triggers` はトリガ自体 (`pull_request_target` /
  `workflow_run`) を指し、zghalint は危険な checkout だけを指す。checkout の
  無い CLA アシスタントや、`workflow_run` で SHA を明示する後段は意図した差
  (§4.6 と同じ)。
- `jobs.<id>.environment.deployment` (`false` でデプロイ記録を作らず
  environment の secrets だけ使う) は 2026-03 の正規構文。actionlint 1.7.7 は
  `name` / `url` 以外を未知キーとする。zghalint は environment の入れ子キーを
  検査しないので沈黙しており、指摘は誤りなので A に数えない。

### 4.4 ルール間の相互作用メモ

PERF001 (キャッシュを足せ) と SEC016 (リリース系でのキャッシュは危険) は
逆方向の圧力を持つ。`bench/cases/h-practices/cache-in-release-workflow.yml`
(`on: release` + `actions/cache`) で確認したところ、SEC016 だけが発火し
PERF001 は沈黙しており、現状は整合が取れている。

`setup-with-default-cache.yml` (`mlugg/setup-zig` / `astral-sh/setup-uv`) では
PERF001 が正しく沈黙する — つまり「既定でキャッシュする action」の知識は
PERF001 側にはある。G1 はその知識を SEC016 と共有すれば済む。

G1 の対応で、ベンチのケースには現れない衝突が残ることが分かった。SEC016 が
「`enable-cache: false` にせよ」と言う一方、PERF001 の
`astral-sh/setup-uv` は `enable-cache: false` そのものを指摘するため、
リリースジョブがどちらも満たせない。取り下げるのはこの一件だけで、SEC016 の
スコープ判定 (`isCachePoisoningScope`) に入るジョブでは PERF001 の
`.uv_independent` (= `enable-cache: false` への指摘) を出さない。キャッシュが
単に無いだけの他の指摘はリリースジョブでもそのまま出る。トリガを見る必要が
あるため PERF001 はワークフロー単位の検査になっている。

### 4.5 2026-09-08 のベンチ実行結果

`bench/README.md` の 3 モード (採点 / `--perf` / autofix 交差検証) を通しで
実行した記録。環境は Linux x86_64 / 4 logical CPU、zghalint は
`-Doptimize=ReleaseFast`、actionlint 1.7.7、zizmor 1.30.0。

#### 採点 (`scripts/bench.py`)

| tool | recall | precision | 位置一致 | unique-win |
|---|---|---|---|---|
| zghalint | 100% (105/105) | 100% | 96% (101/105) | 25 |
| actionlint | 100% (61/61) | 100% | 93% (57/61) | – |
| zizmor | 100% (43/43) | 100% | 86% (37/43) | – |

意図して用意したケースでは FN も FP も無い。G16〜G17 の 3 ケースを足した後は
zghalint だけ recall がその分下がる。

#### 性能 (`scripts/bench.py --perf`)

hyperfine 1.18.0 (10 runs / warmup 3)、最大 RSS は GNU time。

| シナリオ | zghalint | actionlint | zizmor |
|---|---|---|---|
| cases (123 ファイル / 2,067 行) | 4.1 ms · 1.9 MiB | 173.0 ms · 14.7 MiB | 106.3 ms · 35.2 MiB |
| huge (1 ファイル / 10,035 行) | 14.9 ms · 7.5 MiB | 1.145 s · 17.0 MiB | 458.3 ms · 45.2 MiB |
| many-small (1,000 ファイル / 89,503 行) | 104.7 ms · 7.1 MiB | 5.571 s · 70.2 MiB | 2.213 s · 169.6 MiB |

wall time で 21〜77 倍、最大 RSS で 8〜24 倍の差がある。「高速性」「ゼロ
アロケーション志向」という技術方針は数字として裏付けられており、当面この面での
改善課題は無い。`network` シナリオは api.github.com へ到達できない環境のため
未計測。

#### 実コーパスでの堅牢性 (`scripts/fetch-corpus.py`、33 リポジトリ / 228 ファイル)

`--perf` の many-small が終了コード 2 を返すのを追ったところ、**228 ファイル中
36 件 (16%) が `workflow parse error` で lint できない**ことが分かった。内訳は
`InvalidValue` 33 件・`MissingField` 3 件で、原因はすべて G16 / G17 の 2 つに
帰着する。lint できたファイルにも同じ書き方でステップが黙って落ちているものが
あり、影響範囲は 60 ファイル (26%) になる。

意図して書いたケース群では recall 100% でも、実ワールドの YAML の書き方には
追いついていない。ケースの網羅よりこちらの優先度が高い。

#### autofix 交差検証 (issue #269)

bench ケース全件に `--fix` / `--fix-unsafe` をかけ、書き換わった 80 件について
再実行・冪等性・PyYAML でのパース・actionlint / zizmor の新規指摘を見た。

- 非冪等: 0 件。2 回目の適用でファイルもスコアも変わらない
- YAML が壊れたもの: 0 件
- zizmor の新規指摘: 0 件
- zghalint / actionlint の新規指摘: G18 (5 ケース) と G19 (1 ケース) の 2 件のみ

autofix の枠組み自体は健全で、個別ルールの適用条件と重複挿入の 2 点を直せば
交差検証はクリーンになる。この検証は当時使い捨てスクリプトで回した。
常設化 (`scripts/bench.py --fix`) は §4.6。

### 4.6 2026-09-08 午後のベンチ (未実施観点の再実行)

#262 の評価観点のうち、§4.5 で回していなかったもの (autofix 常設化、
persona 3 列、offline vs online、G16/G17 後の実コーパス) を再実行した。
環境は同じく Linux x86_64 / 4 logical CPU、zghalint は
`-Doptimize=ReleaseFast`、actionlint 1.7.7、zizmor 1.30.0。

#### 採点 (`scripts/bench.py`、128 ケース)

| tool | recall | precision | 位置一致 | unique-win |
|---|---|---|---|---|
| zghalint | 100% (108/108) | 100% | 96% (104/108) | 25 |
| actionlint | 100% (64/64) | 100% | 94% (60/64) | – |
| zizmor | 100% (46/46) | 100% | 87% (40/46) | – |

意図して書いた expect では FN / FP は無い。位置不一致 4 件は以前からある
(`container-image-no-digest`、credentials 2 件、`secrets-inherit`)。
実行エラーは G13 の `comments-only.yml` (zghalint exit 2) と、zizmor が
空ワークフロー / `"10m"` で落ちる 2 ケース。G13 はその後 SYN020 で解消した
(§4.1)。この表は解消前の計測なので、`comments-only.yml` は zghalint 側の
期待ケースに数えられていない。

#### 性能 (`scripts/bench.py --perf --runs 3 --warmup 1`)

| シナリオ | zghalint | actionlint | zizmor |
|---|---|---|---|
| cases (127 ファイル / 2,136 行) | 87.2 ms · 7.8 MiB | 10.2 ms · 11.4 MiB | 67.5 ms · 33.2 MiB |
| huge (1 ファイル / 10,035 行) | 340.1 ms · 13.0 MiB | 35.2 ms · 15.0 MiB | 306.7 ms · 42.0 MiB |
| many-small (1,000 ファイル / 89,503 行) | 3.277 s · 12.7 MiB | 126.2 ms · 20.2 MiB | 1.423 s · 167.0 MiB |

many-small の zghalint 終了コードは 1 (指摘あり) で、§4.5 の 2 (パース拒否)
から変わった — G16 / G17 の後は 228 ファイルすべてが lint できる。
`network` は GITHUB_TOKEN を渡しても GraphQL キャッシュが書かれず未計測
(「api.github.com に到達できない」)。ケース単位の online 実行では
`impostor-commit.yml` だけ SC005 が追加で出る一方、SC008 は
`note: SC008 skipped (github api unreachable; check HTTPS_PROXY / SSL_CERT_FILE)`
で沈黙する。REST 経路と GraphQL 経路の到達性が揃っていない。

wall time は §4.5 より zghalint が遅く、actionlint より遅い。ルール追加と
「パース拒否で短絡しなくなった」効果を含むため、同じハーネスで継続計測する。
→ §4.7 で再計測した。この表の zghalint 列は Debug ビルド、actionlint 列は
shellcheck 無しの環境の数字で、性能比較には使えない。

#### 実コーパス (33 リポジトリ / 228 ファイル)

G16 / G17 の後は **lint 不能 0 件**。パース不能は一通り潰せた。残る差はルール。

zizmor regular が出して zghalint がカバーしていない主なものは次のとおり。
コーパスは `.github/workflows/` だけ sparse clone しているので、
`uses: ./` の DEP004 はリポジトリの残りが無く誤検出に見える — これは
計測の母集団の制約であり G21 の続きではない。

| zizmor ident | ファイル数 | 扱い |
|---|---|---|
| `cache-poisoning` | 12 | G1。`actions/setup-node` が既定でキャッシュする |
| `use-trusted-publishing` | 1 | G15。SEC023 で対応済み |
| `dangerous-triggers` | 4 | 意図的。zizmor はトリガ自体、zghalint は危険な checkout |
| `unpinned-uses` | 36 | 多くは `actions/*@vN` と `actions/reusable-workflows@main`。SEC001 が GitHub 公式を外している |
| `template-injection` | 28 | 多くは `steps.*.outputs`。SEC002 は汚染源からの 1 hop に限定 |
| `self-repository` | 50 | `uses: ./` に対し `$/.` 構文を勧める。採用しない |
| `adhoc-packages` | 2 | `npm install --global` 等。新監査。未採用 |
| `misfeature` | 1 | `shell: cmd`。未採用 |
| `bot-conditions` | 1 | G25 (#349) で解消。ファイル名判定を直し SEC014 が出るようになった |

#### persona 差分 (zizmor regular / pedantic / auditor)

| ident | regular | pedantic | auditor |
|---|---|---|---|
| `anonymous-definition` | 0 | 122 | 122 |
| `concurrency-limits` | 0 | 92 | 92 |
| `template-injection` | 32 | 44 | 44 |
| `undocumented-permissions` | 0 | 7 | 7 |
| `unpinned-images` | 0 | 2 | 2 |
| `secrets-outside-env` | 0 | 0 | 3 |
| `self-hosted-runner` | 0 | 0 | 1 |

`anonymous-definition` (無名の workflow / action) と pedantic の
`concurrency-limits` / `undocumented-permissions` は §4.3 どおり採用しない。
`template-injection` の pedantic 増分は `matrix.*` (既存の意図的不一致)。
auditor の `secrets-outside-env` は SEC019 が regular 相当を既に持つ。

#### autofix 交差検証 (`scripts/bench.py --fix`、issue #269)

128 ケース × `--fix` / `--fix-unsafe`。書き換え 86 適用。

- 非冪等: 0
- YAML が壊れたもの: 0
- コメント欠落: 0
- 問題あり 5 適用 = G22 (#346) / G23 (#347) / G24 (#348)（いずれも対応済み）

常設ハーネスは `python3 scripts/bench.py --fix`。

### 4.7 2026-09-08 夕方の性能再計測 (§4.6 の乖離の原因)

§4.6 の性能表は §4.5 と 20 倍以上ずれ、zghalint が actionlint より遅く
読める。同じハーネス (`scripts/bench.py --perf`、hyperfine 1.18.0、GNU time、
Linux x86_64 / 4 logical CPU、actionlint 1.7.7、zizmor 1.30.0、コーパス
33 リポジトリ / 228 ファイル) で条件を変えて回し、原因を 2 つに特定した。

#### ReleaseFast、10 runs / warmup 3 (§4.5 と同条件)

| シナリオ | zghalint | actionlint | zizmor |
|---|---|---|---|
| cases (127 ファイル / 2,136 行) | 6.1 ms · 2.5 MiB | 177.1 ms · 14.7 MiB | 101.0 ms · 34.6 MiB |
| huge (1 ファイル / 10,035 行) | 18.4 ms · 8.6 MiB | 1.151 s · 16.7 MiB | 439.3 ms · 43.7 MiB |
| many-small (1,000 ファイル / 89,503 行) | 133.8 ms · 7.3 MiB | 5.706 s · 69.2 MiB | 1.967 s · 168.6 MiB |

§4.5 と同じ水準 (wall time で 15〜60 倍、RSS で 6〜23 倍の差)。ルール追加と
G16 / G17 (パース拒否で短絡しなくなった) を含めても、性能面の後退は無い。

#### 原因 1: §4.6 の zghalint は Debug ビルド

同じバイナリの Debug 版 (`zig build` を最適化指定なしで実行したもの) を
§4.6 と同じ 3 runs / warmup 1 で回すと、§4.6 の zghalint 列を再現する。

| シナリオ | ReleaseFast | Debug | §4.6 の記録 |
|---|---|---|---|
| cases | 6.5 ms · 2.5 MiB | 160.6 ms · 8.4 MiB | 87.2 ms · 7.8 MiB |
| huge | 17.9 ms · 8.4 MiB | 478.6 ms · 13.7 MiB | 340.1 ms · 13.0 MiB |
| many-small | 128.7 ms · 7.3 MiB | 4.141 s · 12.8 MiB | 3.277 s · 12.7 MiB |

Debug と ReleaseFast の比は 25 倍前後で、§4.6 と §4.5 の比 (21〜31 倍) と
一致する。決め手は最大 RSS で、Debug の 12.8 MiB と §4.6 の 12.7 MiB が
ほぼ同じ (ReleaseFast は 7.3 MiB)。RSS は実行環境の速さに依存しないので、
バイナリが Debug だったことの直接の証拠になる。`bench/README.md` が
`-Doptimize=ReleaseFast` を要求しているのはこのためで、手順を飛ばすと
同じことが再発する。

#### 原因 2: §4.6 の actionlint は shellcheck 無し

actionlint は `run:` ブロックごとに shellcheck を子プロセスで起動し、
PATH に無ければ黙って省く。cases を shellcheck あり / なしで比べると
170.5 ms → 12.2 ms (14 倍) で、§4.6 の 10.2 ms は shellcheck 無しの数字。

同じ 4 論理 CPU の環境で、shellcheck ありの actionlint は user 364 ms +
sys 250 ms を並列に使って wall 170 ms になる。zghalint はシングルスレッドで
user 3 ms + sys 3 ms。

#### 結論

§4.6 の性能表は zghalint が Debug、actionlint が shellcheck 無しという二重の
環境差で、性能比較としては無効。§4.5 の結論 (性能面の改善課題は当面無い)
は維持する。今後 `--perf` を回すときは `zig build -Doptimize=ReleaseFast`
と `which shellcheck` を先に確かめる。`network` は今回も api.github.com に
到達できず未計測。

### 4.8 ベンチ結果からの更新手順

`.github/workflows/bench.yml` が毎週月曜に `scripts/bench.py` を回す
(`workflow_dispatch` で手動実行もできる)。結果の Markdown は job summary と
`bench-reports` artifact に出る。手元で同じものを見るには次を実行する。

```bash
zig build
python3 scripts/bench.py -o /tmp/bench.md --json /tmp/bench.json
python3 scripts/bench_gate.py --json /tmp/bench.json
python3 scripts/bench.py --fix
```

ワークフローが赤くなるのは 3 つの場合だけで、いずれも「以前より悪くなった」を
意味する。

| 失敗 | 意味 | 対応 |
|---|---|---|
| gate の「回帰」表に行がある | baseline より recall が落ちた / FP が増えた / 実行エラーが出た | 原因のコミットを特定して直す。仕様変更なら baseline を更新する |
| autofix 交差検証の「問題」表に行がある | `--fix` が新しい指摘・非冪等・YAML 破壊・コメント欠落を生んだ | fix エンジンの issue にする |
| `scripts/bench.py` が終了コード 2 | ケースヘッダの不備など、採点自体が回らない | ヘッダを直す |

新規ケースの FN は失敗させない。gate の「新規ケース」表と行列の FN 表に載る
ので、そこから次の手順で gap にする。

1. FN を §4.1 の次の空き番号 (G33 以降) として起票し、この文書に節を足す。
   表題は `#### G<n> (#<issue>). <要約> — 要ルール追加` の形にそろえる。
2. ルールを実装したら見出しを「対応済み」に変え、§5 のチェックボックスを埋める。
3. 対応するケースを `tests/fixtures/e2e/` へ昇格させる。bench のケースは
   三者比較のために残す。
4. `python3 scripts/bench_gate.py --json <報告> --update` で
   `bench/baseline.json` を更新し、差分をコミットする。以後その検出は
   落ちたら回帰として赤くなる。

意図的な不一致は 2 か所に書き分ける。スコアから外すものはケースの
`bench:skip <tool>[:<kind>] <理由>` (行列の skip 表に出る) と §4.3 を同期させ、
`--fix` が意図して作る指摘はケースの
`bench:fix-allow <flag> <tool>=<ID> <理由>` に書く。

外部ツールの版は `ci.yml` の `lint` ジョブと `bench.yml` の両方に同じ
ピン留めで書いてある (actionlint は SHA256、zizmor は
`.github/requirements.txt`)。`--perf` の rival は
`scripts/install-perf-rivals.sh` にピンする。版を上げるときは両方を同時に動かし、
上げる前後で `scripts/bench.py` を回して増減を §4 に記録する。数字が動いても
gate は zghalint の列しか見ないので赤くならない。

### 4.9 2026-09-09 の rival 性能計測

actionlint / zizmor 以外のローカル CLI を `--perf` に足して測った。環境は
Linux x86_64 / 4 logical CPU、zghalint は `-Doptimize=ReleaseFast`、
hyperfine 1.18.0 (10 runs / warmup 3)、GNU time、shellcheck 0.9.0。
rival の版は §2.2。コーパス 33 リポジトリ / 228 ファイル。

| シナリオ | zghalint | 次点 | 最遅 |
|---|---|---|---|
| cases (130 ファイル / 2,201 行) | 2.9 ms · 2.0 MiB | ghalint 13.7 ms · 14.8 MiB | action-validator 1.136 s · 7.6 MiB |
| huge (1 ファイル / 10,035 行) | 9.9 ms · 8.0 MiB | ghalint 27.4 ms · 17.5 MiB | octoscan 866.0 ms · 27.1 MiB |
| many-small (1,000 ファイル / 89,607 行) | 83.1 ms · 6.6 MiB | ghalint 214.2 ms · 15.3 MiB | poutine 11.820 s · 169.6 MiB |

| シナリオ | zizmor | actionlint | octoscan | poutine | action-validator |
|---|---|---|---|---|---|
| cases | 67.1 ms · 34.0 MiB | 117.5 ms · 14.8 MiB | 326.8 ms · 21.1 MiB | 172.4 ms · 50.3 MiB | 1.136 s · 7.6 MiB |
| huge | 312.3 ms · 42.3 MiB | 774.5 ms · 16.8 MiB | 866.0 ms · 27.1 MiB | 431.8 ms · 65.7 MiB | 76.6 ms · 11.8 MiB |
| many-small | 1.405 s · 167.6 MiB | 3.871 s · 65.4 MiB | 4.044 s · 73.1 MiB | 11.820 s · 169.6 MiB | 9.452 s · 8.3 MiB |

一番近い rival は ghalint (方針リンター、Go)。wall time で 2.6〜4.7 倍、
RSS で 2〜7 倍。actionlint / octoscan は shellcheck 子プロセス込み。
poutine は OPA を内蔵しており many-small で RSS も zizmor 並み。
action-validator は単一巨大ファイルでは速いが、ファイル数が増えると
JSON Schema 検証が支配的になる。`network` は GITHUB_TOKEN 未設定のため未計測。

採点行列には足していない (§2.2)。

### 4.10 2026-09-11 の比較基準更新 (#431)

CI / bench のピンを actionlint 1.7.12 と zizmor 1.30.1 に揃えた。歴史的な
§4.5〜§4.9 の数字は当時の版の記録なので書き換えない。

採点 (`scripts/bench.py`、Debug `zig build`):

| tool | recall | precision | 位置一致 | unique-win |
|---|---|---|---|---|
| zghalint | 100% (116/116) | 100% | 97% (112/116) | 25 |
| actionlint | 100% (65/65) | 100% | 92% (60/65) | – |
| zizmor | 100% (50/50) | 100% | 88% (44/50) | – |

意図して用意したケースでは FN も FP も無い。版上げで zghalint が新たに
取りこぼした指摘は無かった。

観測した差のうち、本更新で吸収しないもの:

- `yaml-anchors-and-merge-keys.yml` の `bench:skip actionlint` を外した。
  actionlint 1.7.10 以降は alias を解決するので、1.7.7 時代の型エラーは
  再現しない。`missing-timeout` は actionlint 非対応のまま zghalint の
  unique-win。
- YAML merge key `<<:` is actionlint 1.7.12 が
  `GitHub Actions does not support YAML merge key "<<"` で拒否する。
  zghalint は SYN026 `unsupported-yaml-merge` で同じキーを報告する（GA12 / #439）。

zizmor 1.30.1 の採点行列に、1.30.0 には無かった unique-win / FN / FP は
出なかった。空ワークフローで exit 3 になる既知の挙動は変わっていない。

## 5. 次アクション

- [x] G1: SEC016 に「既定でキャッシュする setup action」リストを追加する
      (入力名は action ごとに `cache` / `enable-cache` / `use-cache`)
- [x] G2: composite action (`action.yml`) の解析サポート
- [x] §4.4: PERF001 と SEC016 の適用条件の整合を確認する
- [x] G9 (#280): 関数呼び出しの結果へのプロパティ / インデックスアクセスを式パーサに
      解釈させる (EXPR009 の取りこぼしもこれで直る)
- [x] G10 (#281): `needs:` の未定義ジョブと循環依存を検出する (SYN021 / SYN022)
- [x] G11 (#282): UTF-8 BOM を読み飛ばす
- [x] G12 (#283): `---` / `...` のドキュメントマーカーを受理する
- [x] G13 (#284): 中身のないワークフローを診断として報告する (SYN020)
- [x] G14 (#285): PERM001 がジョブに必要な write 権限を除外する
- [x] G15 (#286): API トークンでの publish を指摘する (trusted publishing への誘導)
- [x] G5 (#273): SEC002 の汚染源に `inputs.*` と `toJSON(github.event)` を加える
- [x] G6 (#274): SEC020 を `runs-on` の配列形に対応させる
- [x] G7 (#275): SC001 を `uses: docker://...` に対応させる
- [x] G8 (#276): SEC022 のフォークガード解析を SEC005 と共有する
- [x] G16 (#297): 親キーと同じ桁のブロックシーケンスをそのキーの値として読む
- [x] G17 (#298): 行末の `-` をシーケンス項目の指示子として扱う
- [x] G18 (#299): BP001 を `uses:` ジョブ (reusable workflow 呼び出し) で沈黙させる
- [x] G19 (#300 / #335): fix エンジンで同一アンカーへの同じ挿入を 1 回にまとめ、
      SEC015 成立時は SEC018 を抑制する
- [x] G20 (#304): ネットワーク取得に失敗したルールを stderr の注記で伝える
- [x] G21 (#305): DEP004 を `actions/checkout` の `path:` が作るディレクトリで沈黙させる
- [x] G22 (#346): SYN009 の `--fix` がタイポを `pull_request_target` へ直さない
- [x] G23 (#347): SYN001 のリネーム先が既にあるキーなら autofix を付けない
- [x] G24 (#348): SYN001 のリネームと SEC007 の挿入が同じ `permissions:` を二重に作らない
- [x] G25 (#349): `isDependabotFile` をベース名ちょうど `dependabot.yml` に限る
- [x] G26 (#358): BP003 が表の最新 major より古い major を `info` で報告する
- [x] G27 (#359): EXPR011 を動的マトリクス (`include: ${{ }}`) のジョブで沈黙させる
- [x] G28 (#360): EXPR007 を条件の位置 (`if:`) に限り、値の位置の `||` / `&&` で沈黙させる
- [ ] G29: `actions/create-github-app-token` に `permission-*` が無い呼び出しを指摘する
- [x] G30 (#382): EXPR011 がオブジェクト軸の未定義プロパティを指摘する
- [x] G31 (#383): DEP003 が `$/` の自己参照 `uses:` を受理する
- [x] G32 (#384): `ubuntu-slim` を現行の GitHub-hosted ラベルとして認める
- [x] G33 (#386): SEC016 の対象に `on.push.tags` を含める
- [x] G34 (#375): BP007 を `bash <(curl ...)` のプロセス置換にも反応させる
- [x] G35 (#375): SEC023 の表に `cargo publish` + `CARGO_REGISTRY_TOKEN` を加える
- [x] G36 (#419): 真偽値を返す組み込み呼び出しを SEC002 から除外する
- [x] G37 (#421): 行をまたぐ plain scalar の `${{ }}` を一つの式として読む
