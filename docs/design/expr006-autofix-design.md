# EXPR006 autofix設計書

## 目的

`EXPR006` は `contains(x, 'literal')` の第 2 引数が string literal の場合に、substring match の意図しないマッチを warning として検出する。現状は `fix_hint` のみで自動修正を提供していない (`src/rules/expressions.zig:646-657`)。

本設計書では、特定のパターンに限定して `contains(ctx, 'lit')` → `ctx == 'lit'` への書き換え edit を `--fix-unsafe` で適用できるようにする。意味論が変わる（substring match → 完全一致）ため常に unsafe fix となる。

関連資料:
- `docs/design/autofix-implementation-plan.md`
- `docs/design/sec017-autofix-design.md`（`env_meta` 拡張の先例。`if_condition_meta` は同じパターン）
- `docs/design/bp002-autofix-design.md`（workflow model への最小拡張パターン）

## スコープ

### V1 対象パターン

以下の全条件を満たす `contains(A, B)` にのみ autofix を付与する。

1. 引数が厳密に 2 個
2. `A` が `context_access` ノード、かつ `value` 文字列に `.*` / `[` / `]` を含まない
3. `B` が `string_literal` で、中身に単一引用符 `'` を含まない
4. 親ノードが `unary_op`（`!`）でない（V1 では否定文脈をスキップ）

V1 変換:

```
contains(github.ref, 'main')  →  github.ref == 'main'
```

- `Fix.safety` は `.unsafe` とする
- 既存の検出条件と診断メッセージは維持する（fix が追加されるだけ）

### V1 非対象（fix を生成しない = 従来どおり diagnostic のみ）

- `A` が `string_literal` / `number_literal`（`'abc' == 'def'` は常に false）
- `A` が `function_call`（例: `contains(toJSON(github.event), 'push')`）
- `A` が配列アクセス（`.*` / `[ ]` 含み） — 配列 contains の可能性あり
- `B` が空文字列、または `''` エスケープ（`'it''s'`）を含むリテラル
- ネストされた `contains`（外側だけの書き換えは内側意図を壊しうる）
- 多重引数（将来 arity が増えた場合に備え保守的に除外）
- 親が `unary_op` の `!` の直下にある場合（V2 で対応）

### V2（フォローアップ設計、別コミット）

V1 が安定した後、親ノードが `unary_op("!")` のケースに拡張する。

```
!contains(github.ref, 'release')  →  github.ref != 'release'
```

`validateNode` に `parent: ?*const ExprNode` を追加して親情報を伝搬する。V1 からは独立したコミット単位で追加する。

## 非スコープ

- `contains(a, b)` を `startsWith(a, b)` / `endsWith(a, b)` へ変換
- OR/AND 連鎖の中で `contains` を並べ替える最適化
- `EXPR007` (`a == 'x' || 'y'`) との同時実装
- expression 全体の再整形やフォーマット

## 現状整理

### 1. diagnostic は出るが fix が付かない

`src/rules/expressions.zig:646-657`:

```zig
if (std.mem.eql(u8, name, "contains") and node.children.len == 2) {
    if (node.children[1].kind == .string_literal) {
        list.append(.{
            .rule_id = "EXPR006",
            .severity = .warning,
            .message = "contains() uses substring matching which may match unintended values",
            .span = span,
            .fix_hint = "use exact comparison (== ) or startsWith()/endsWith() for precise matching",
        }) catch return;
    }
}
```

### 2. ExprNode に byte offset がない

`src/rules/expressions.zig:233-239`:

```zig
pub const ExprNode = struct {
    kind: NodeKind,
    value: []const u8,
    children: []const ExprNode,
};
```

autofix では `contains(...)` 呼び出し全体の「式ソース内オフセット」が必要だが、再帰下降パーサは位置情報を保持していない。

### 3. `checkStep` / `checkJob` が dummy span で呼ぶ

`src/rules/expressions.zig:733,769`:

```zig
const span = Span.point(0, 0, 0);
```

autofix に必要な「ファイル内の expression 開始 byte」が失われている。

### 4. `Step` / `Job` が `if_condition` の value span を持たない

`src/workflow/types.zig` の `Step` / `Job` は `if_condition: ?[]const u8` しか保持しておらず、対応する `ScalarValueMeta` が無い。`env` には既に `env_meta: ?ScalarValueMetaMap` があるが、`if_condition` にはない。

### 5. `${{ ... }}` wrapper のオフセット欠落

`findAndValidateExpressions` (`src/rules/expressions.zig:694-718`) は `${{` を剥いだ後の trimmed 文字列を parser に渡すが、元 scalar 内での開始位置を autofix 側に伝搬していない。

## 設計方針

### Phase A: インフラ拡張

#### A-1. ExprNode / ExprToken に byte offset を追加

`src/rules/expressions.zig`:

```zig
pub const ExprNode = struct {
    kind: NodeKind,
    value: []const u8,
    children: []const ExprNode,
    start_byte: u32 = 0,
    end_byte: u32 = 0,
};
```

- `start_byte` / `end_byte` は式ソース文字列（`validateExpression` に渡される `expr`）内のオフセット
- `ExprTokenizer` の各 token 生成時に byte offset を記録
- `parseXxx` が生成する ExprNode にこれを埋める
- 既存インラインテストは署名非変更（フィールド追加のみ）で通る

#### A-2. `if_condition_meta` を追加

`src/workflow/types.zig` の `Step` / `Job` に `if_condition_meta: ?ScalarValueMeta = null` を追加する。`ScalarValueMeta` は既存の `{ value_span, style }` 型 (`src/workflow/types.zig:9-12`) をそのまま再利用する。

`src/workflow/parser.zig` で `if:` を読む箇所で value span / style を記録する。既存の `env_meta` 記録パターン（SEC017 で導入）と同形。

#### A-3. validateExpression に `expr_base_byte: usize` を追加

```zig
pub fn validateExpression(
    allocator: std.mem.Allocator,
    expr: []const u8,
    base_span: Span,
    list: *DiagnosticList,
    expr_base_byte: usize,
) void
```

- `expr_base_byte` は「ファイル先頭から `expr` 文字列の先頭までのバイトオフセット」
- `validateNode` / `validateFunctionCall` にも thread する
- `findAndValidateExpressions` 側で `${{` スキップと trim 分を加算
- `checkStep` / `checkJob` 側で `step.if_condition_meta.value_span.start_byte` を基点として渡す

### Phase B: Fix 生成本体（V1）

#### B-1. V1 条件判定

`validateFunctionCall` で EXPR006 を検出している箇所に以下を追加する。

```zig
if (node.children.len == 2 and node.children[1].kind == .string_literal) {
    const first = node.children[0];
    const literal = node.children[1];

    const eligible =
        first.kind == .context_access and
        std.mem.indexOfAny(u8, first.value, ".*[]'") == null and
        std.mem.indexOfScalar(u8, literal.value, '\'') == null;
    // 注: context path は '.' を正当に含むため、実装では '.*' のみを除外
}
```

（実装時は `'.*'` 判定と `'['` / `']'` / `'\''` の 3 種を分けて検査する）

#### B-2. Edit 計算

- 対象範囲: `[contains_call.start_byte, contains_call.end_byte)` （式ソース相対）
- 絶対 byte: `expr_base_byte + contains_call.start_byte` 〜 `expr_base_byte + contains_call.end_byte`
- 置換文字列: `{ctx.value} == '{literal.value}'`
  - `ctx.value` は ExprNode の `value`（例: `github.ref`）
  - `literal.value` は ExprNode の `value`（tokenizer が剥いたあとの中身、例: `main`）

生成 edit は 1 件:

```zig
.{
    .start_byte = expr_base_byte + contains_call.start_byte,
    .end_byte   = expr_base_byte + contains_call.end_byte,
    .replacement = replacement,
}
```

#### B-3. Parent 追跡不要（V1）

`validateNode` の署名は変更しない。`validateFunctionCall` は `node` 単体で判定完結する（親が `!` か否かは見ない → 親があっても fix を出さないのが V1）。

### Phase C: DiagnosticList 連携

`DiagnosticList.fixAllocator()` を直接呼び、既存 autofix と同じライフタイム管理に揃える。`validateExpression` の `allocator` パラメータは diagnostic message 用なのでそのまま維持。

## 絶対バイトオフセット計算（ワークスルー例）

### Example 1: plain scalar, `${{ }}` なし

YAML ソース（先頭 byte = 0）:

```
if: contains(github.ref, 'main')
```

- `if_condition_meta.value_span.start_byte` = 4（`c` の位置）
- 経路 2 (bare expression) を通り、`expr_base_byte = value_span.start_byte + leading_trim = 4`
- `ExprNode(contains(...)).start_byte` = 0
- `ExprNode(contains(...)).end_byte` = 28
- 絶対 edit 範囲 = `[4, 32)`
- 置換文字列 = `github.ref == 'main'`
- 結果: `if: github.ref == 'main'`

### Example 2: double-quoted scalar, `${{ }}` ラップ

```
if: "${{ contains(github.ref, 'main') }}"
```

- `value_span.start_byte` = quote 内の `$` の位置
- 経路 1 (`findAndValidateExpressions`) を通り、`${{` を剥がした後の trim 開始オフセットを加算
- `expr_base_byte = value_span.start_byte + "${{".len + leading_space_in_trim`

### 検証すべき境界

| ケース | 経路 |
|--------|------|
| plain scalar (`if: contains(...)`) | 経路 2 (bare expression) |
| double-quoted scalar (`if: "contains(...)"`) | 経路 2 |
| single-quoted scalar (`if: 'contains(...)'`) | 経路 2（YAML parser が `'` を剥がす） |
| `${{ }}` ラップあり | 経路 1 (`findAndValidateExpressions`) |
| 同一 scalar 内の複数 `${{ }}` | 経路 1、各 `${{}}` ごとに独立 Edit |

## テストマトリクス

### 対象（fix が付く）

| 入力 | 期待 replacement |
|------|-----------------|
| `contains(github.ref, 'main')` | `github.ref == 'main'` |
| `contains(matrix.os, 'ubuntu-latest')` | `matrix.os == 'ubuntu-latest'` |
| `contains(steps.x.outputs.y, 'foo')` | `steps.x.outputs.y == 'foo'` |
| `${{ contains(github.event_name, 'push') }}` | `${{ github.event_name == 'push' }}` |

### 非対象（fix が付かない）

| 入力 | 理由 |
|------|------|
| `contains('hello', 'ell')` | first arg が literal |
| `contains(toJSON(github.event), 'push')` | first arg が function_call |
| `contains(github.event.commits.*.message, 'wip')` | `.*` 含み |
| `contains(github.ref, 'it''s')` | リテラルに `''` エスケープ |
| `!contains(github.ref, 'release')` | V1 では unary_op の子を対象外 |
| `contains(a, b, c)` | 引数数が 2 でない |

## 安全性評価

EXPR006 の autofix は `.unsafe` とする。

根拠:

- `contains('foo-bar', 'foo')` = true だが `'foo-bar' == 'foo'` = false で、意味論が変わる
- `--fix` ではなく `--fix-unsafe` 専用
- `docs/design/autofix-implementation-plan.md:192-200` の unsafe リストに準拠
- 既存の `PERM001` 個別 `write→read` や `BP004` の `shell: bash` 挿入と同じポリシー

## 実装差分

### 変更対象

- `src/rules/expressions.zig`（ExprNode / ExprTokenizer / 各 parseXxx / validateExpression / validateNode / validateFunctionCall / findAndValidateExpressions / checkStep / checkJob）
- `src/workflow/types.zig`（Step / Job に `if_condition_meta`）
- `src/workflow/parser.zig`（if: の value span / style 記録）
- `docs/design/expr006-autofix-design.md`（本書）
- `docs/design/autofix-implementation-plan.md`（件数表・Phase 3 表・EXPR006 行の更新 = イテレーション 7）

### 変更しないもの

- `src/fix/engine.zig`
- `src/yaml/parser.zig`
- `src/yaml/types.zig`
- 既存 diagnostic メッセージ

## テスト設計

### 1. 診断に fix が付くこと

- V1 対象パターンで `fix != null`, `Fix.safety == .unsafe`, edit 数が 1 件
- 非対象パターン全てで `fix == null`（既存テストの diagnostic 発火は維持）

### 2. Edit 内容が正しいこと

- `start_byte` / `end_byte` が `contains(...)` 全体を正確にカバー
- replacement が `"{ctx} == '{lit}'"` 形式
- ExprNode の byte offset が tokenizer 位置と一致（parser テスト）

### 3. `fix/engine.zig` 経由で YAML へ適用した結果

- plain scalar / double-quoted / `${{ }}` ラップの各形式で期待どおり書き換わる
- 同一 scalar 内の複数 `${{ }}` が独立して書き換わる
- 適用後の YAML が再パース可能で、EXPR006 診断が消える
- `--fix` では非適用、`--fix-unsafe` で適用

## 実装手順

1. 本設計書の作成とレビュー（イテレーション 0）
2. `ExprNode` / `ExprTokenizer` / 各 `parseXxx` に byte offset を追加（イテレーション 1 / Tidy First）
3. `Step.if_condition_meta` / `Job.if_condition_meta` 追加と parser 充填（イテレーション 2 / Tidy First）
4. `validateExpression` / `validateNode` / `validateFunctionCall` に `expr_base_byte` を thread（イテレーション 3 / Tidy First）
5. EXPR006 fix 生成を TDD で実装、V1 境界テスト追加（イテレーション 4）
6. integration test（YAML → lint → applyFixes → 再パース）を追加（イテレーション 5）
7. V2: unary_op 親検出と `!=` 変換（イテレーション 6、別コミット）
8. `docs/design/autofix-implementation-plan.md` の実装ステータスを更新（イテレーション 7、doc-only コミット）

各イテレーションの完了時に `zig build && zig fmt --check src/ build.zig && zig build test --summary all` を実行する。

## ソースコードとの差分メモ

現状の `src/rules/expressions.zig` は expression AST に位置情報を持たず、`checkStep` / `checkJob` が dummy span で validator を呼んでいる。本設計はこの差分を最小変更で埋め、EXPR007 / SEC014 の Phase 3 残り 2 件にも転用できる基盤（ExprNode の byte offset 化、`if_condition_meta`、`expr_base_byte` 伝搬）として整備する。
