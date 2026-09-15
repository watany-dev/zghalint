# FixEngine — TLC の結果と反例

対象: `src/fix/engine.zig` の `flattenAndSort` + `applyFixes`（`--fix` / `--fix-unsafe`）。
モデル: [`FixEngine.tla`](FixEngine.tla)。定数 `N = 2`（ソース 2 バイト）、`MaxFixes = 2`、`MaxEditsPerFix = 2`。

## 実行方法

```bash
cd docs/formal/fix_engine
java -cp /path/to/tla2tools.jar tlc2.TLC -workers auto -config FixEngine.cfg FixEngine.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -workers auto -config FixEngine_atomic.cfg FixEngine.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -workers auto -config FixEngine_order.cfg FixEngine.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -workers auto -config FixEngine_order_noinsert.cfg FixEngine.tla
```

## 結果一覧

| 性質 | 由来 | 結果 | 状態数 |
| --- | --- | --- | --- |
| `NoUnderflow` | C3（コピーループが `src_pos - end` で負にならない） | 成立 | 1,319,716 |
| `KeptDisjoint` | S2（生き残った編集は互いに重ならない） | 成立 | 同上 |
| `LoopMatchesSpec` | S4（後ろから前へのコピー結果 = 前から順に差し替えた結果） | 成立 | 同上 |
| `InsertionsCoexist` | S3（同一バイトの幅ゼロ挿入は両方生き残る） | 成立 | 同上 |
| `FixAtomic` | C4（1 つの Fix は全部適用されるか全部落ちるか） | **違反** | 初期状態で検出 |
| `OrderIndependent` | S5（Fix の収集順で出力が変わらない） | **違反** | 初期状態で検出 |
| `OrderIndependentNoInsert` | S5 の幅ゼロ挿入を除いた版 | **違反** | 初期状態で検出 |

## 反例 1: Fix は原子的に適用されない（`FixAtomic`）

TLC が返した初期状態（記法: `[s, e, r, fix, idx]` = 開始バイト, 終了バイト, 置換内容, 所属 Fix, Fix 内の番号）:

```
fixes = << << [s 0, e 1, r <<>>,        fix 1, idx 1] >>,
           << [s 0, e 0, r <<>>,        fix 2, idx 1],
              [s 0, e 1, r <<>>,        fix 2, idx 2] >> >>
KeptAsc(fixes) = << fix2/idx1 (0,0), fix1/idx1 (0,1) >>
```

- 並べ替え後の順序は `(0,0)` → `(0,1)`(fix1) → `(0,1)`(fix2)。安定ソートで同じ範囲は登録順。
- fix1 の `(0,1)` が採用され、fix2 の `(0,1)` は「重なり」として落とされる。fix2 の `(0,0)` は幅ゼロなので生き残る。
- 結果、**Fix 2 は半分だけ適用される**。

ドメイン用語では: あるルールの自動修正が「A を挿入し、B を書き換える」という 2 手からなるとき、別ルールが B と同じ範囲を先に登録していると、A の挿入だけがファイルに入り B の書き換えは入らない。修正後のワークフローが、どのルールの意図とも一致しない中間状態になる。

## 反例 2: 同一バイトへの挿入は登録順で並ぶ（`OrderIndependent`）

```
fix 1 = << [s 0, e 0, r << <<"r",1,1,1>> >>, fix 1, idx 1] >>
fix 2 = << [s 0, e 0, r << <<"r",2,1,1>> >>, fix 2, idx 1] >>
Expected(fixes)          = << r(fix1), r(fix2), s1, s2 >>
Expected(Reverse(fixes)) = << r(fix2), r(fix1), s1, s2 >>
```

同じ位置（例: ステップの先頭）に 2 つのルールが行を挿入するとき、出力に並ぶ順序は `collectFixes` がルールを走査した順（= `registry.zig` の並び）で決まる。ADR 0001 D5 は「ゴールデンテストで固定」と宣言しているが、ルールの追加や並べ替えで出力が変わる性質であることが確認できた。

## 反例 3: 同一範囲の置換は先に登録した Fix が黙って勝つ（`OrderIndependentNoInsert`）

```
fix 1 = << [s 0, e 1, r <<>>,                 fix 1, idx 1] >>   \* 削除
fix 2 = << [s 0, e 1, r << <<"r",2,1,1>> >>,  fix 2, idx 1] >>   \* 置換
Expected(fixes)          = << s2 >>            \* fix1 の削除だけが反映
Expected(Reverse(fixes)) = << r(fix2), s2 >>  \* fix2 の置換だけが反映
```

同じトークン（例: `uses: actions/checkout@v4`）に対し、ルール X が「削除」、ルール Y が「SHA にピン留め」を出すと、適用されるのはレジストリで先に来る方だけで、もう片方は警告なく捨てられる。`--fix` のユーザーには「Y の修正が効かなかった」ことが伝わらない。
