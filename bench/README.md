# bench: zghalint / actionlint / zizmor の三者比較

同じワークフローを 3 つのリンターに流し、**ツール中立の指摘種別**で採点する
ハーネス。zghalint だけが落とす指摘 (FN) を継続的に洗い出し、
`docs/design/external-linter-parity.md` の gap 番号として起票するのが目的
(issue #262)。

性能計測 (`--perf`) は採点とは別に、actionlint / zizmor に加えて
ghalint / octoscan / poutine / action-validator も同じファイルで測る。
導入は `scripts/install-perf-rivals.sh`。採点行列に足さないのは、指摘 ID の
対応表が actionlint / zizmor に紐づいているため。

```bash
zig build                                   # 採点対象のバイナリを先に作る
python3 scripts/bench.py                    # 行列を stdout へ
python3 scripts/bench.py -o /tmp/bench.md   # ファイルへ
python3 scripts/bench.py --case 'a-*'       # 一部のケースだけ
python3 scripts/bench.py --json /tmp/b.json # 生スコアも出す
python3 scripts/bench.py --fix               # autofix 交差検証 (issue #269)
python3 scripts/bench.py --fix -o /tmp/fix.md --json /tmp/fix.json
```

`actionlint` / `zizmor` が PATH になければ、そのツールは採点対象から外れる
(zghalint だけでも実行できる)。導入手順は `.github/workflows/ci.yml` の
`lint` ジョブと `.github/lint-requirements.txt` を参照。`--perf` の rival
(ghalint / octoscan / poutine / action-validator) は
`scripts/install-perf-rivals.sh` (Linux x86_64、SHA256 ピン)。PATH に無い
rival は「見つからない」として表に載り、計測は続く。

## 配置

```
bench/
  cases/<category>/<name>.yml         # ワークフローのケース
  cases/<category>/<name>.action.yml  # composite action のケース
  cases/<category>/<name>.dependabot.yml  # dependabot 設定のケース
  cases/<category>/<name>/            # 複数ファイルのケース (下記)
```

拡張子は `.yml` / `.yaml` のどちらでもよい。
カテゴリは issue #262 の A〜J に対応する (`a-script-injection`,
`c-supply-chain`, `e-expression`, `j-clean` …)。`*.action.yml` は実行時に
一時ディレクトリへ `action.yml` として複製される — zizmor はファイル名でしか
composite action を認識しないため。`*.dependabot.yml` も同じく
`dependabot.yml` として複製される。行番号は複製前後で変わらない。

### 複数ファイルのケース

カテゴリ直下のディレクトリは、それ自体が 1 ケースになる。ディレクトリ全体が
一時領域へ複製され、そこをリポジトリのルートとしてツールを実行するので、
`uses: ./.github/workflows/reusable.yml` や `uses: ./tool` が実際のリポジトリ
と同じように解決される。

```
cases/g-reusable/missing-required-input/
  .github/workflows/caller.yml    # bench: ヘッダを持つ = エントリファイル
  .github/workflows/reusable.yml  # 呼ばれる側
```

`bench:` ヘッダを持つファイルはツリー内にちょうど 1 つだけ置く。それが
ツールへ渡すエントリファイルになる。複製時に空の `.git` を作る —
actionlint はこれでプロジェクトルートを判定しており、無いとローカル
`uses:` の検査を丸ごと省くため。

## 期待値ヘッダ

先頭のコメントブロックに書く。コメントでも空行でもない行に達した時点で
読み取りを終えるので、本文が `bench:` を含んでいても拾われない。
`expect` も `forbid` も 1 つもないケースはエラーになる。

```yaml
# bench:persona pedantic
# bench:expect template-injection@15 zghalint=SEC002 zizmor=template-injection actionlint=-
# bench:forbid unpinned-action
# bench:skip zghalint:template-injection 意図的な非対応 (parity doc 4.3)
```

### `bench:expect <kind>[@<line>] [<tool>=<IDs>]...`

その指摘が出ることを期待する。`<kind>` は**ツール中立の名前**で、
`<tool>=<ID>` で各ツールの ID に対応づける。

- `<tool>` は `zghalint` / `actionlint` / `zizmor`。
- `=-` は「このツールは出さない見込み」。FN には数えず、unique-win の
  判定に使う。
- 複数 ID は `,` 区切り (`zghalint=SEC015,SEC018`)。
- `ID~text` はメッセージに `text` を含む指摘だけ、`ID!~text` は含まない
  指摘だけに絞る。actionlint の `kind` は粗く、`expression` が
  script injection と `${{ }}` の構文エラーの両方を指すため必要になる。
- `@<line>` は 1 始まりの行番号。位置精度の採点に使う (省略可)。

3 ツールすべての対応づけが必要。よく使う種別は `scripts/bench.py` の
`DEFAULT_KIND_MAP` に登録済みで、ヘッダ側の指定がそれを上書きする。
どちらにもない種別はエラーになる — 対応づけ漏れが黙って recall 0 になるのを
防ぐため。登録済みの対応表は次で出せる (ここに転記すると腐るため置かない)。

```bash
python3 scripts/bench.py --kinds
```

### `bench:forbid <kind> [<tool>=<IDs>]...`

誤検出ガード。構文は `expect` と同じ (`@<line>` は無視される)。出てしまった
ものが FP として precision に効く。

### `bench:skip <tool>[:<kind>] <理由>`

意図的な不一致をスコアから除外する。`<tool>` に `all` を書くとケースごと
全ツールを外す。`:<kind>` を付けるとその種別だけを外す。理由は必須で、
出力の skip 表にそのまま載る。

`*.action.yml` のケースでは actionlint が自動で skip される
(workflow ファイルしか読まないため)。`*.dependabot.yml` のケースでも同じ理由で
actionlint が自動で skip される。zizmor は dependabot 設定を監査するので
skip されない。

### `bench:persona <regular|pedantic|auditor>`

そのケースを採点する zizmor の persona。省略時は `regular`。

### `bench:fix-allow <flag> <tool>=<IDs> <理由>`

autofix 交差検証 (`--fix` モード) 専用。`<flag>` (`--fix` / `--fix-unsafe`) の
書き換えがそのツールに `<IDs>` を出させるのは意図どおりだ、と宣言する。
採点には影響せず、交差検証の「問題」から「許容した増加」表へ移る。理由は必須。

```yaml
# bench:fix-allow --fix-unsafe zizmor=dangerous-triggers 候補が特権トリガのときは --fix-unsafe でのみ置換する (G22)
```

## 採点

| 指標 | 定義 |
|---|---|
| recall | `expect` のうち検出できた件数の割合。落としたものが FN 表に載る |
| precision | `detected / (detected + FP)`。FP は `forbid` に反した指摘 |
| 位置一致 | `@<line>` 付きの `expect` のうち、その行に出た件数の割合 |
| unique-win | zghalint だけが検出した `expect` の件数 |

各ツールは 60 秒でタイムアウトし、クラッシュ・タイムアウト・出力が
パースできない場合は「実行エラー」として記録する — 黙って 0 件として
採点しない (堅牢性の観察点)。zghalint の終了コード 2 (「そのファイルを
lint できなかった」) も同じ扱いにする。JSON 自体は正常に出るため、
そうしないと解析を拒否したファイルが「指摘なし」に化ける。

`--fail-on-fp` を付けると、zghalint が `forbid` に反した時点で非ゼロ終了
する。CI で誤検出の混入を止める用途。

## autofix 交差検証 (`--fix`)

採点ではなく、`--fix` / `--fix-unsafe` の書き換え品質を外部ツールで見る
モード (issue #269)。実装は `scripts/bench_fix.py`。ケースごとにコピーへ
適用し、次を記録する。

1. 書き換え後に zghalint がクラッシュせず、**新しい rule ID** が増えていない
2. actionlint / zizmor にも、修正前に無かった指摘 ID が増えていない
3. もう一度同じフラグを適用してバイト列が変わらない (冪等)
4. 書き換え前に PyYAML が読めていたファイルが、書き換え後も読める
5. コメント行が消えていない

SEC001 の SHA ピン留めは `--offline` では解決できないので、このモードでは
意図どおり無変更になる。指摘が増えたケースは fix エンジンの個別 issue にする。

## 性能計測 (`--perf`)

採点ではなく wall time と最大 RSS を測るモード (issue #268)。実装は
`scripts/bench_perf.py`。zghalint は `-Doptimize=ReleaseFast` で作った
バイナリを渡す — Debug ビルドの数字は比較に使えない。

```bash
zig build -Doptimize=ReleaseFast
python3 scripts/fetch-corpus.py                     # many-small 用のコーパス
sudo scripts/install-perf-rivals.sh                 # ghalint / octoscan / poutine / action-validator
python3 scripts/bench.py --perf                     # Markdown を stdout へ
python3 scripts/bench.py --perf -o /tmp/perf.md --json /tmp/perf.json
python3 scripts/bench.py --perf --runs 3 --warmup 1 # 手元での確認用
```

| シナリオ | 内容 |
|---|---|
| cases | `bench/cases/` のワークフロー全件を 1 回の起動で処理する |
| huge | 約 10,000 行の合成ワークフロー 1 本 (実行時に生成) |
| many-small | `bench/corpus/` を 1000 ファイルに敷き詰めて 1 回の起動で処理する |
| network | cases を対象に、zghalint は `--no-cache` (cold) とディスクキャッシュ (warm)、zizmor は `--offline` とオンラインを比べる |

各コマンドは `hyperfine --warmup 3` (既定; `--runs` / `--warmup` で変更) で
測り、hyperfine が無ければ同じ回数の in-process ループで代用する。最大 RSS
は GNU time (`/usr/bin/time -f %M`、Debian/Ubuntu は `apt-get install time`)
でもう 1 回だけ実行して取る — `time -v` の "Maximum resident set size"。
Python から直接 `wait4(2)` で読むと Linux が親プロセスの RSS を子に
計上するため 15 MiB 前後で床打ちされ、zghalint の実値 (数 MiB) が見えない。
GNU time が無い環境 (macOS の BSD time を含む) では RSS 列は `–` になる。
zghalint / actionlint / zizmor / action-validator はファイル一覧を argv に渡す。
ghalint / octoscan / poutine は `.github/workflows/` しか見ないので、同じ
ファイルをそこに複製してから走らせる (複製は計測に含めない)。poutine は
起動時に版チェックで GitHub へ行くため `--disable-version-check` を付ける。
actionlint と octoscan は PATH に shellcheck があれば `run:` ごとに起動する
— それがデフォルトのコストなので、計測でも外さない。

終了コードは表に載せる。zghalint の 2 は「lint できなかったファイルがある」
の意味で、パースを拒否した実ファイルがあれば many-small で出る (堅牢性の
観察点)。#293 の修正以降、`scripts/fetch-corpus.py` が集める 228 件は
すべてパースを通る。

### 性能比較に足すツール / 足さないツール

GitHub Actions 向けの静的ツールは actionlint / zizmor 以外にもある。`--perf`
に載せるのは、ローカルのワークフロー YAML を lint / scan する CLI で、起動
一回で同じファイル集合を処理できるもの。

| ツール | 何をするか | `--perf` |
|---|---|---|
| [ghalint](https://github.com/suzuki-shunsuke/ghalint) | セキュリティ方針 (権限、timeout、SHA ピン) | 載せる |
| [octoscan](https://github.com/synacktiv/octoscan) | actionlint ベースの脆弱性スキャナ | 載せる |
| [poutine](https://github.com/boostsecurityio/poutine) | CI/CD サプライチェーンスキャナ (OPA) | 載せる |
| [action-validator](https://github.com/mpalmer/action-validator) | workflow / action の JSON Schema | 載せる |
| frizbee / pinny / scharf / pinact | 未ピン留め `uses:` を SHA に直す専用 | 載せない (リンターではない) |
| OpenSSF Scorecard | リポジトリ全体の GitHub API 監査 | 載せない (ネットワーク前提) |
| ggshield | シークレットスキャン | 載せない |
| Semgrep | 汎用 SAST。起動が重い | 載せない |
| Checkov / super-linter | IaC / 多言語の集約 | 載せない |

採点行列 (`scripts/bench.py` の既定モード) は actionlint / zizmor の 3 者のまま。
指摘 ID の対応表と `bench:expect` ヘッダがこの 2 ツール向けで、ghalint の
`job_permissions` と octoscan のルール名を同じ kind に載せる作業は parity
gap の追跡とは別物になる。

network シナリオは `GITHUB_TOKEN` が要る (zghalint は GraphQL 経路でしか
キャッシュを書かず、zizmor はトークン無しだと黙ってオフラインになる)。
計測前に zghalint の cold 実行がキャッシュを書き、zizmor のオンライン実行が
監査を完了することを確かめてから走らせる。トークンが無い、または
api.github.com へ届かない環境では「計測できなかったシナリオ」として理由つきで
載せ、接続失敗のコストを取得コストとして報告しない。`bench/corpus/` が空なら
many-small も同じ扱いになる。

### コーパス (`scripts/fetch-corpus.py`)

`scripts/popular-actions.txt` のリポジトリを `.github/workflows/` だけ
sparse clone し、ワークフローを `bench/corpus/<owner>__<repo>/` へ集める。
上流のライセンスをそのまま持つファイルなので `bench/corpus/` は git 管理外
にし、代わりに `bench/corpus/manifest.json` に取得元 (リポジトリ・コミット・
ファイル名) と取得時刻を残す。`--limit N` で manifest の先頭 N 件に絞り、
`--repo owner/repo` で manifest に無いリポジトリを対象に加える。取得は毎回
`bench/corpus/` を作り直す。

## baseline との比較 (`scripts/bench_gate.py`)

`bench/baseline.json` は前回記録した zghalint のケース別スコア。gate は
今回の `--json` 報告とそれを突き合わせ、**以前より悪くなったときだけ**
非ゼロで終わる。

```bash
python3 scripts/bench.py --json /tmp/bench.json
python3 scripts/bench_gate.py --json /tmp/bench.json          # 比較
python3 scripts/bench_gate.py --json /tmp/bench.json -o gate.md
python3 scripts/bench_gate.py --json /tmp/bench.json --update # baseline を更新する
```

| 判定 | 条件 |
|---|---|
| 回帰 (非ゼロ終了) | 検出数が baseline より減った / `bench:forbid` 違反が増えた / baseline に無かった実行エラーが出た |
| 新規ケース (失敗させない) | baseline に無いケース。その FN は gap の候補として表に載る |
| 注意 (失敗させない) | 位置一致の低下、期待値の増減、baseline から続く実行エラー |

見るのは zghalint の列だけ。actionlint と zizmor の数字は各ツールの版と
ランナーの shellcheck の有無で動くので、gate の対象にすると zghalint と
無関係な赤が出る。ケースを足したりルールを直したりしたら `--update` で
baseline を更新し、`bench/baseline.json` の差分を同じ PR に含める。
`--update` は報告に載ったケースだけを書き換え、載っていないケースはそのまま
残す (消えるのは `bench/cases/` から実体が無くなったものだけ) ので、
`--case` で絞った報告から更新しても baseline は切り詰められない。

## CI

`.github/workflows/bench.yml` が毎週月曜と `workflow_dispatch` で回す。
PR では回さない。

- `score` ジョブ: 採点 → autofix 交差検証 → baseline 比較。回帰・autofix の
  問題・採点の失敗のいずれかでジョブが赤くなる。Markdown は job summary と
  `bench-reports` artifact に出る。
- `perf` ジョブ: `--perf`。数字はランナーの相乗りで揺れるので失敗させず、
  記録だけ残す。

外部ツールの版は `ci.yml` の `lint` ジョブと同じピン留めにする (actionlint は
SHA256、zizmor は `.github/lint-requirements.txt`)。`--perf` の rival は
`scripts/install-perf-rivals.sh` にピンする。上げ方と結果の扱いは
`docs/design/external-linter-parity.md` §4.8。

## ケースを追加する

1. カテゴリのディレクトリに `.yml` を置く (複数ファイルならディレクトリごと)。
2. ヘッダに `bench:expect` / `bench:forbid` を書く。ヘッダ行も本文の行数に
   数えるので、`@<line>` を書いた後にヘッダを増やすとずれる。
3. `python3 scripts/bench.py --case '<category>/*'` で意図どおり採点されるか
   確認する。行番号は実際の出力に合わせる。
4. `python3 scripts/bench_gate.py --json <報告> --update` で baseline に
   加える。
5. `ruff check scripts/ && ruff format --check scripts/` を通す。

ベンチで確認した FN は parity doc の gap として個別 issue に起票し、
ADR → ルール実装 → `tests/fixtures/e2e` への昇格、という流れに乗せる。
