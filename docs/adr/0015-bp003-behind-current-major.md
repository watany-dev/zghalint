# 0015. BP003 の「現行 major より古い major」判定

- Status: Accepted
- Date: 2026-09-09
- Deciders: issue #358（`docs/design/external-linter-parity.md` §4.1 G26）

## Context

実運用のワークフローを流したところ、`actions/*` 以外の広く使われている
アクションが現行 major より古い major で参照されているのに BP003 が何も
言わないケースが出た。

```yaml
- uses: softprops/action-gh-release@v1   # 埋め込み表が知る現行 major は 2
```

BP003 は古いアクションを 2 経路で見ているが、この形はどちらにも掛からない。

1. **埋め込みメタデータ表**（`src/rules/data/popular_actions.zig`）
   `runs.using` が廃止済みランタイムなら `error` にする。表は読んだ major を
   全て持つが、第三者アクションについては現行 major しか読んでいない。参照側の
   `@v1` はどのエントリにも一致せず、`using` が分からないので素通りする。
2. **手書きのバージョン表**（`src/rules/best_practices.zig` の
   `deprecated_actions`）
   `actions/*` の 8 件だけ。第三者アクションの行は無い。

actionlint / zizmor も指摘しないので parity gap ではないが、「古いアクションを
指摘する」ルールを 2 経路持ちながら落ちる構造上の穴なので埋める。

## Decisions

### D1. 対策は (b)「表の現行 major より古い major を警告する」

issue の 2 案のうち、(a)（生成スクリプトで古い major の `using` も取得する）は
表のサイズと生成コストが major の本数だけ増える。しかも救えるのは「古い major の
ランタイムが廃止済みだった」場合に限られ、`node20` で動く古い major は依然として
見逃す。

(b) は今の表のまま「参照している major < 表が知る最新 major」を見るだけで、
データも生成コストも増えない。判定の実体は
`popular_actions.latestMajor()`（owner / repo / path が一致するエントリの
最大 major）である。

### D2. 手書きのバージョン表が名指すアクションは、そちらに任せる

`deprecated_actions` は「まだ許容する最も古い major」を書いた表であり、
`actions/checkout` は `deprecated_below = 4` なので v4 は許容される。表が知る
最新は v5 だが、ここで v4 を指摘すると**キュレーション済みの判断を後から nag に
変えてしまう**。そこで新しい判定は `deprecated_actions` に無いアクションだけを
見る。表に行を足せば、そのアクションの方針は表が持ち続ける。

### D3. severity は info

古いだけの major はまだ動く。`v1` を意図して固定している利用者は珍しくなく、
ランタイムが廃止された場合（`error`）や置き換え先が判明している場合
（`warning`）と違って「今すぐ直さないと壊れる」ものではない。「より良い書き方が
ある」クラスの提案として、SEC019 / SEC023 と同じ `info` に置く。

BP003 は既に 1 ルール 3 severity になるが、これは以前からの設計である——同じ
「古いアクション」でも壊れ方の重さが違うので、severity で分ける。全体を上げ
下げしたい利用者は `.zghalint.yml` の severity override で 1 行書けばよい。

### D4. autofix は `unsafe`

major を上げるのは定義上の破壊的変更である。バージョン表の側の書き換え
（`actions/checkout@v2` → `@v4` など）は置き換え先を人が検証しているので `safe`
のままだが、こちらは表が「最新の major はこれ」と知っているだけで、入力名や
既定値が変わっていないことは何も保証しない。`--fix` では書き換えず、
`--fix-unsafe` を明示した場合だけ `@vN` を書き換える。

## Consequences

- 第三者アクションの古い major に `info[BP003]` が出るようになる。回帰ケースは
  `tests/fixtures/e2e/bp003-behind-current-major.yml`（`.fixed-unsafe` で書き換え
  結果も固定）。
- 検出範囲は `scripts/popular-actions.txt` に載っているアクションに比例する。
  一覧に足せば古い major の検出も増える、という形でメンテナンスの動機が揃う。
- 表の最新 major より**新しい** major（表が追い付いていない場合）は何も言わない。
  SHA ピン・ブランチ・`vN-beta` のような版を名乗らない ref も対象外で、これは
  `lookup()` と同じ方針である。
