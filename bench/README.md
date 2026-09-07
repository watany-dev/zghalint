# bench: zghalint / actionlint / zizmor の三者比較

同じワークフローを 3 つのリンターに流し、**ツール中立の指摘種別**で採点する
ハーネス。zghalint だけが落とす指摘 (FN) を継続的に洗い出し、
`docs/design/external-linter-parity.md` の gap 番号として起票するのが目的
(issue #262)。

```bash
zig build                                   # 採点対象のバイナリを先に作る
python3 scripts/bench.py                    # 行列を stdout へ
python3 scripts/bench.py -o /tmp/bench.md   # ファイルへ
python3 scripts/bench.py --case 'a-*'       # 一部のケースだけ
python3 scripts/bench.py --json /tmp/b.json # 生スコアも出す
```

`actionlint` / `zizmor` が PATH になければ、そのツールは採点対象から外れる
(zghalint だけでも実行できる)。導入手順は `.github/workflows/ci.yml` の
`lint` ジョブと `.github/lint-requirements.txt` を参照。

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

## ケースを追加する

1. カテゴリのディレクトリに `.yml` を置く (複数ファイルならディレクトリごと)。
2. ヘッダに `bench:expect` / `bench:forbid` を書く。ヘッダ行も本文の行数に
   数えるので、`@<line>` を書いた後にヘッダを増やすとずれる。
3. `python3 scripts/bench.py --case '<category>/*'` で意図どおり採点されるか
   確認する。行番号は実際の出力に合わせる。
4. `ruff check scripts/ && ruff format --check scripts/` を通す。

ベンチで確認した FN は parity doc の gap として個別 issue に起票し、
ADR → ルール実装 → `tests/fixtures/e2e` への昇格、という流れに乗せる。
