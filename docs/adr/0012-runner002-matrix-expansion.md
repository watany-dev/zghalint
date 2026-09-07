# 0012. RUNNER002 matrix 展開

- Status: Accepted
- Date: 2026-09-07
- Issue: [#210](https://github.com/watany-dev/zghalint/issues/210)（ADR 0011 D5 の第二段階）

## Context

ADR 0011 D5 では `runs-on` が `${{ }}` を含む場合をまるごと対象外とした。しかし
matrix ジョブの典型形

```yaml
strategy:
  matrix:
    os: [ubunut-latest, macos-99]
runs-on: ${{ matrix.os }}
```

では、実際のラベルは `strategy.matrix` に静的に書かれている。RUNNER002 が存在
する理由（打ち間違いでジョブが永久に queued のまま止まる）はここでも変わらない
のに、最も多い書き方が丸ごと素通りしていた。

## Decisions

### D1. 展開するのは `${{ matrix.<key> }}` 単体のときだけ

`runs-on` の値をトリムしたものが `${{` で始まり `}}` で終わり、中身が
`matrix.<key>`（`<key>` は英数字・`_`・`-` のみ）である場合に限って展開する。
`${{ matrix.os }}-4-cores` のような連結、`format(...)` のような関数呼び出し、
`inputs.os` など他コンテキストの参照は、ラベル全体を静的に復元できないため
従来どおりスキップする。「復元できたものだけ責任を持って検証する」という
ADR 0011 D1 の姿勢をそのまま式に適用したものである。

### D2. `include` は展開に含め、`exclude` は含めない

`include` は組み合わせを追加するため、そこに書かれた `os:` は実際にランナー
ラベルとして使われる。`exclude` は組み合わせを除去するだけで、その値でジョブが
起動することはない。存在しないラベルを `exclude` に書いても壊れるものはないので
報告しない。

ただし `--fix-unsafe` は例外で、軸の値を直すときに同じラベルを名指しする
`exclude` の値も同時に書き換える。軸だけ直すと除外が何にも一致しなくなり、
作者が消したはずの組み合わせが黙って復活するためである。

### D3. 診断と autofix は matrix の値を指す

`runs-on: ${{ matrix.os }}` の行を指しても直しようがない。診断の span は該当する
matrix 値のスカラに向け、`--fix-unsafe` の置換もその範囲に対して行う。span は
`spans.Anchor` 経由で解決し、引用符付きスカラ（`os: ["ubunut-latest"]`）でも
引用符を巻き込まないようにする。

### D4. 軸の値自体が式ならスキップする

`os: ${{ fromJSON(...) }}` は軸が sequence にならないためそもそも値を持たず、
sequence の要素が式である場合（`- ${{ inputs.os }}`）も静的なラベルではない。
どちらも D1 と同じ理由でスキップする。

## Consequences

- 未知ラベル判定・候補提示・`runner.labels` による許可リストは、直書きの
  `runs-on` と matrix 展開で同じ経路（`classifyLabel` / `reportUnknownLabel`）を
  通る。片方だけ挙動がずれることはない。
- 1 つの軸に複数の未知ラベルがあれば、その数だけ診断が出る。値ごとに独立した
  ジョブが起動しないので、まとめずに各値を指すほうが直しやすい。
