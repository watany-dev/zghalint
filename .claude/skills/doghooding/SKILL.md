---
name: doghooding
description: >
  Dogfood zghalint against a real OSS project's CI. Fetch the named
  repository's workflows, run the three-way bench (zghalint vs actionlint +
  zizmor) over them, and turn zghalint's misses into anonymised issues and
  minimal bench cases — the upstream project is never named in anything that
  gets committed or filed. Fire when the user invokes /doghooding or says
  "doghooding", "この OSS の CI でベンチを取って", "実運用のワークフローで
  zghalint を試して", "dogfood against <repo>".
---

# doghooding

指定された OSS の実 CI を持ってきて三者比較にかけ、zghalint 側の穴だけを
**匿名化した最小ケースと issue** に落とす。上流の名前・本文・行番号は
成果物に一切残さない。

対象は引数で受け取る (`/doghooding owner/repo`)。指定が無ければ何を対象に
するか聞く。

## 前提

```bash
zig build                      # 採点対象のバイナリ
which actionlint zizmor        # 無ければ ci.yml の lint ジョブと同じピン留めで導入する
```

- 外部ツールの版は `.github/workflows/ci.yml` の `lint` ジョブに合わせる
  (actionlint は SHA256、zizmor は `.github/requirements.txt`)。
  版が違うと差分がツール更新由来か zghalint 由来か切り分けられない。
- 取得したワークフローは**リポジトリの外**（スクラッチ領域）に置く。上流の
  ライセンスを持つファイルをこのリポジトリに入れない。`bench/corpus/` は
  `scripts/fetch-corpus.py` が毎回作り直すので使わない。

## Phase 1: 取得

```bash
work=$(mktemp -d)
git clone --quiet --depth 1 --filter=blob:none --sparse --no-checkout \
  https://github.com/<owner>/<repo> "$work/src"
git -C "$work/src" sparse-checkout set --no-cone '/.github/workflows/*'
git -C "$work/src" checkout --quiet
git -C "$work/src" rev-parse HEAD    # 手元の記録用。成果物には書かない
ls "$work/src/.github/workflows"
```

`action.yml` / `.github/dependabot.yml` も見たいときは sparse-checkout の
パターンに足す。composite action は zizmor がファイル名でしか判別しないので、
`action.yml` という名前のまま置くこと。

## Phase 2: 三者実行

`bench/cases/` のケースと同じフラグで、同じファイル集合に対して走らせる。
すべてオフライン — ネットワーク由来の差分をスコアに混ぜない。

```bash
zg=$PWD/zig-out/bin/zghalint      # リポジトリのルートで解決してから移動する
cd "$work/src"
"$zg" --format json --color never --offline .github/workflows/*.y*ml \
  > "$work/zghalint.json"; echo "zghalint exit=$?"
actionlint -no-color -format '{{json .}}' \
  > "$work/actionlint.json"; echo "actionlint exit=$?"
zizmor --format json --offline --no-progress --persona regular .github/workflows \
  > "$work/zizmor.json"; echo "zizmor exit=$?"
```

終了コードは 3 本とも「指摘があった」で非ゼロになる (zizmor は重大度で
14 などを返す)。実行エラーと読み違えないこと。ただし **zghalint の exit 2 は
「そのファイルを lint できなかった」** で、JSON は正常に出るぶん 0 件に化ける
— Phase 3 の B 群として必ず拾う。`--persona auditor` で回すと zizmor の指摘は
増えるが、採点の基準は `regular`。auditor の差分は参考扱いにする。

3 本の JSON を `(ファイル, 行)` で突き合わせる:

```bash
python3 - "$work" <<'PY'
import collections, json, pathlib, sys

work = pathlib.Path(sys.argv[1])
rows = collections.defaultdict(lambda: collections.defaultdict(set))
for d in json.loads((work / "zghalint.json").read_text())["diagnostics"]:
    rows[(d["file"], d["line"])]["zghalint"].add(d["rule_id"])
for d in json.loads((work / "actionlint.json").read_text()) or []:
    rows[(d["filepath"], d["line"])]["actionlint"].add(d.get("kind", "?"))
for item in json.loads((work / "zizmor.json").read_text()):
    for loc in item["locations"]:
        sym = loc.get("symbolic", {})
        if sym.get("kind") != "Primary":
            continue
        path = next(iter(sym.get("key", {}).values()), {}).get("verbatim_path", "?")
        line = int(loc["concrete"]["location"]["start_point"]["row"]) + 1
        rows[(path, line)]["zizmor"].add(item.get("ident", "?"))
for (path, line), by in sorted(rows.items()):
    cols = " | ".join(f"{t}={','.join(sorted(v))}" for t, v in sorted(by.items()))
    print(f"{path}:{line} {cols}" + ("  <- FN候補" if "zghalint" not in by else ""))
PY
```

同じ問題でもツールごとに指す行が 1〜数行ずれる (zizmor はステップの `uses:`
行、zghalint はその次の行、など)。`FN候補` の印は機械的な突き合わせでしか
ないので、**前後の行と元のファイルの該当箇所を必ず自分で読んで**確認してから
起票する。

## Phase 3: 差分の分類

| 群 | 中身 | 行き先 |
|---|---|---|
| A. FN | actionlint / zizmor が出して zghalint が出さない、かつ指摘が妥当 | gap として起票 + bench ケース |
| B. 堅牢性 | zghalint の exit 2・parse error・クラッシュ・ステップの黙った脱落 | 最優先で起票。実ワールドの YAML の書き方は意図したケースより価値が高い |
| C. FP | zghalint だけが出していて、読んだ結果その指摘が誤り | 起票 + `bench:forbid` のケース |
| D. unique-win | zghalint だけが出していて妥当 | 記録のみ。起票しない |

意図して外している差分 (`docs/design/external-linter-parity.md` §4.3) は
A にも C にも数えない。既に §4.1 に番号がある gap の再発なら、新規起票ではなく
その節に追記する。

## Phase 4: 最小サンプルに置き換える

**上流のファイルをそのまま持ち込まない。** 現象を再現する最小のワークフローを
自分で書き直す。

- `bench/cases/<category>/<name>.yml` に置く。カテゴリと `bench:` ヘッダの
  書式は `bench/README.md`
- 20 行前後。その指摘に要らないジョブ・ステップ・キーは全部落とす
- 名前は汎用語 (`build`, `deploy`, `run tests`, `example.com`, `MY_TOKEN`)
- 落としながら毎回 3 ツールを回し、**指摘が消えない最小形**まで削る
- ヘッダの `<tool>=<ID>` は 3 ツールぶん埋める。出ない見込みは `=-`
- C 群は `bench:forbid` の安全形ケースにする

削り終えたら、そのファイルだけを見て「どのプロジェクトの CI か分かるか」を
確かめる。分かるなら削り足りない。

## Phase 5: 匿名化

コミットするもの・起票するもの・PR 本文のすべてから次を落とす。

- リポジトリ名・組織名・製品名・その略称、GitHub の URL とコミット SHA
- ホスト名・内部サービス名・レジストリ・self-hosted runner のラベル
- シークレット名・環境名・ブランチ名・パス・ジョブ名/ステップ名の固有部分
- 上流ファイルの引用と行番号 (「実運用のワークフローで見つかった」まで)

起票の書き出しは「実運用のワークフロー群を三者比較したところ」でよい。
どの OSS だったかは会話の中だけに留め、成果物には残さない。

**上流の本物の脆弱性を見つけたら公開 issue に書かない。** zghalint 側の
課題 (検出の有無) だけを起票し、上流の問題そのものは報告せず、ユーザーに
そのまま伝えて判断を仰ぐ (責任ある開示の対象)。

## Phase 6: 起票と取り込み

1. A / B / C を 1 件ずつ issue にする。表題は現象で書く (対象名は入れない)。
   本文に「再現する最小ワークフロー (Phase 4 のケース)」「3 ツールの出力」
   「期待する挙動」を入れる
2. `docs/design/external-linter-parity.md` §4.1 に次の空き番号で節を足し、
   §5 のチェックボックスに `- [ ] G<n> (#<issue>): ...` を足す。表題は
   `#### G<n> (#<issue>). <要約> — 要ルール追加` にそろえる
3. ベンチを回して baseline を更新する

```bash
python3 scripts/bench.py --json /tmp/bench.json -o /tmp/bench.md
python3 scripts/bench_gate.py --json /tmp/bench.json
python3 scripts/bench_gate.py --json /tmp/bench.json --update
```

4. CI を通してからコミットする

```bash
zig build && zig fmt --check src/ build.zig && zig build test --summary all
```

5. ルールを実装するときは別タスク。実装したら §4.8 の手順で
   `tests/fixtures/e2e/` へ昇格させ、bench のケースは三者比較のために残す

最後に `wrapup` を通す。

## 報告

ユーザーには次を返す。対象の実名を出してよいのは**この報告だけ**。

- 対象と対象ファイル数、3 ツールの指摘件数と実行エラー
- A / B / C / D の件数と、起票した issue 番号
- 足した bench ケースと baseline の差分
