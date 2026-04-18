# BP002 autofix設計書

## 目的

`BP002` は `name` フィールドが無い step を検出するが、現状は `fix_hint` のみで自動修正を提供していない。
`docs/design/autofix-implementation-plan.md` では `BP002` を Phase 1 の優先実装候補（`可 / 中 / 高`）としており、本設計書では既存の edit-based autofix 基盤の上で安全に実装する方法を定義する。

関連資料:
- `docs/design/autofix-implementation-plan.md`
- `docs/design/sec017-autofix-design.md`（span 拡張の先例）

## スコープ

- step mapping が `name` を持たず、`uses` が **mapping の先頭 key** として現れる場合のみ autofix を付与する
- autofix は `uses:` key の直前（= step mapping の先頭）に `name: <生成名>` を挿入する
- `Fix.safety` は `.safe` とする
- 既存の検出条件と診断メッセージは維持する

### 現時点で対象外のケース（将来拡張）

- `uses:` が `if:` / `id:` などより後ろに来る step（挿入位置が step 先頭にならず、設計意図と乖離するため）
- `run:` のみを持つ step（`run` 用の key insertion anchor を parser に追加するまで保留）

これらは診断のみを出し、`fix` は `null` とする。

## 非スコープ

- step mapping 全体の整形・key 並び替え
- `uses` / `run` のどちらも持たない step への autofix
- 生成名の i18n / 大文字小文字ルールのカスタマイズ
- `BP004`（shell 指定）との同時実装

## 現状整理

`src/rules/best_practices.zig:65-75` の `checkMissingStepName` は step の `name` が `null` のとき診断を出す。
ただし `span` は `Span.point(0, 0, 0)` 固定で、位置情報が workflow parser から step へ伝播していないため、edit 対象 byte を復元できない。

一方で YAML AST 上の step mapping には既に以下の情報がある。

- `Mapping.span`: step mapping 全体の byte range
- `MappingEntry.key.span`: 各 key token の byte range
- `MappingEntry.key.span.start_col`: インデント算出に使える

workflow parser 側では step の `uses_key_col` のみ保持しており、step mapping の開始 byte は保持していない。

## 設計方針

### 1. 修正内容は step 先頭への `name:` 挿入に限定する

autofix は step mapping の最初のキーの直前に次を挿入する。

```yaml
steps:
  - uses: actions/checkout@v4
```

```yaml
steps:
  - name: Checkout
    uses: actions/checkout@v4
```

挿入形式を選ぶ理由は次の通り。

- 既存キーの byte range を変更しない
- インデント計算が `start_col` だけで完結する
- `- ` 記法、ブロック記法の両方で同じロジックが使える
- YAML 構造を壊さない最小差分である

### 2. step mapping の span を workflow model に追加する

`src/workflow/types.zig` の `Step` に次を追加する。

```zig
pub const Step = struct {
    // ... 既存 fields ...
    /// Span of the step mapping (including leading `- ` in block-style sequences)
    span: yaml_types.Span = yaml_types.Span.point(0, 0, 0),
};
```

parser 側（`parseStep`）では `m.span` をそのまま格納する。

SEC017 が `env_meta` を追加したのと同じ方針で、rule 実装が必要とする最小の source metadata を workflow model に局所的に乗せる。

### 3. 生成名ルール

`util.zig` に次のヘルパを実装する。

- `stepNameFromRepo(allocator, repo)`: `ActionRef.repo` の先頭 1 文字を ASCII 大文字化して返す。先頭が ASCII letter でない場合は `null`
- `stepNameFromRun(allocator, run)`: `run` の先頭行を trim し最大 40 文字に切り詰める。制御文字や YAML 記号（`'`, `"`, `:`, `#`, `&`, `*`, `!`, `|`, `>`, `%`, `@`, `` ` ``）を含む場合は `null`

BP002 の現行 fix は `uses` のみを anchor とするため、実際に使用するのは `stepNameFromRepo` である。`stepNameFromRun` は run-step 拡張（将来 phase）のために util 層へ先行実装し、単体テストのみ用意する。

| 条件 | 生成名 |
|---|---|
| `step.uses != null` かつ `ActionRef.repo` が取れる | `stepNameFromRepo(repo)`（例: `checkout → "Checkout"`）|
| `step.uses != null` で repo が取れない（local / docker 等） | fix を付けない |
| `uses` が mapping の先頭 key でない | fix を付けない |
| `uses`, `run` どちらも無い | fix を付けない |

生成名に `:` や `"` を含まない ASCII 文字列しか採用しないことで、YAML として再パース可能な plain scalar を保証する。

### 4. 挿入位置とインデント

step mapping の `span.start_line` と `span.start_col` から挿入位置を決定する。

- `uses_key_col` が取れる場合、それを「2 番目以降のキーの indent」として再利用する
- `- ` 記法の場合、`span.start_col` は `-` の列、`uses_key_col` は 2 番目の key のインデント

擬似コード:

```zig
const insert_byte = step.span.start_byte + offset_to_first_key;
const continuation_indent = step.uses_key_col - 1;
const replacement = std.fmt.allocPrint(fix_alloc,
    "name: {s}\n{s}", .{ generated_name, spaces(continuation_indent) }
);
```

`offset_to_first_key` は span 開始から最初の非空白・非 `-` までの byte offset。parser 側で計算して `uses_key_start_byte` として渡す形が簡潔だが、まずは `uses_value_end_byte` と `uses_key_col` から逆算する実装でも可。

本設計では **parser に `step.uses_key_start_byte: ?usize` を追加する**ことを選ぶ。これにより `run` だけの step でも同じパターンで拡張できる（将来的に `run_key_start_byte` を足す余地）。

さらに parser 側で `uses` が mapping の先頭 key である場合のみ `uses_key_start_byte` を格納する。これにより「`if:` が `uses:` より前にある step」では `uses_key_start_byte == null` となり、`buildStepNameFix` は自然に `null` を返す。

### 5. Fix 生成 API

`src/rules/best_practices.zig` に helper を追加する。

```zig
fn buildStepNameFix(
    list: *DiagnosticList,
    step: *const Step,
) ?Fix
```

責務は次の 3 点に限定する。

- 生成名の決定
- indent 計算と replacement 組み立て
- 単一 `Edit` と `Fix` の確保

生成される edit は 1 件:

```zig
.{
    .start_byte = step.uses_key_start_byte.?,
    .end_byte = step.uses_key_start_byte.?,
    .replacement = replacement,
}
```

`DiagnosticList.fixAllocator()` を使い、既存 autofix と同じライフタイム管理に揃える。

### 6. `checkMissingStepName` への組み込み

```zig
fn checkMissingStepName(step: *const Step, diag_list: *DiagnosticList) void {
    if (step.name != null) return;

    var diag = Diagnostic{
        .rule_id = "BP002",
        .severity = .info,
        .message = "Step is missing a 'name' field. ...",
        .span = step.span,
        .fix_hint = "Add a descriptive 'name' to this step.",
    };
    diag.fix = buildStepNameFix(diag_list, step);
    diag_list.append(diag) catch return;
}
```

診断 span も `Span.point(0,0,0)` から `step.span` に変更する。これは `span.start_line > 0` のときだけ有効で、既存テストには影響しない（`Step{}` で構築する場合 `span` のデフォルトは `point(0,0,0)`）。

## 安全性評価

BP002 の autofix は `.safe` とする。

根拠:

- step に `name` を追加することは意味変更を伴わない純粋な documentation 追加である
- 生成名は既存情報（`uses` repo 名 / `run` 先頭行）から決定論的に計算される
- 外部 API や repository 固有情報に依存しない
- 計画書の unsafe list（§unsafe fix の扱い）に BP002 は含まれていない

ただし生成名の品質が低いケース（例: `run: echo hello` → `"echo hello"`）では人間が再編集したくなる可能性があるため、description で「生成名」である旨を明示する。

## 実装差分

### 変更対象

- `src/workflow/types.zig`
- `src/workflow/parser.zig`
- `src/rules/best_practices.zig`
- `src/util.zig`（生成名 helper 追加）
- `docs/design/bp002-autofix-design.md`（本書）
- `docs/design/autofix-implementation-plan.md`

### 変更内容

1. `Step.span` と `Step.uses_key_start_byte` を追加する
2. `parseStep` で span を格納する。`uses_key_start_byte` は `uses` が mapping の先頭 key の場合のみ格納する
3. `util.zig` に `stepNameFromRepo(repo)` と `stepNameFromRun(run)` を追加する（後者は run-step 拡張のため util 層のみ先行実装）
4. `buildStepNameFix` を追加する（anchor は `uses_key_start_byte`）
5. `checkMissingStepName` に fix 付与を組み込む
6. BP002 の autofix テストを 3 層で追加する

### 変更しないもの

- `src/fix/engine.zig`
- `src/yaml/parser.zig`
- `src/yaml/types.zig`

## テスト設計

### 1. 診断に fix が付くこと

- `uses` step（mapping の先頭 key）で `fix != null`、description が `"Add step name"`
- `if:` → `uses:` の順の step で `fix == null`（anchor が null）
- `run` のみの step で `fix == null`（anchor が null）
- local action (`./foo`) step で `fix == null`（repo が取れないため）
- docker action (`docker://...`) step で `fix == null`
- `uses` も `run` も無い step で `fix == null`
- `Fix.safety == .safe`
- edit 数が 1 件

### 2. Edit 内容が正しいこと

- `start_byte == end_byte`（挿入）
- replacement が `"name: <生成名>\n<spaces>"` 形式
- インデントが `uses_key_col - 1` と一致

### 3. `fix/engine.zig` 経由で YAML へ適用した結果

- `- uses: actions/checkout@v4` → `- name: Checkout\n        uses: actions/checkout@v4`
- 適用後の YAML が再パース可能
- 同一 job 内の他 step を壊さない

## 実装手順

1. BP002 用の failing test を追加する
2. `src/workflow/types.zig` に `Step.span` / `Step.uses_key_start_byte` を追加する（tidy commit、BP003 と共用）
3. `src/workflow/parser.zig` の `parseStep` で span と `uses_key_start_byte` を格納する
4. `src/util.zig` に `stepNameFromUses` / `stepNameFromRun` を追加する
5. `buildStepNameFix` を実装する
6. `checkMissingStepName` に fix 付与を組み込む
7. integration test を追加する
8. `zig build`, `zig fmt --check src/ build.zig`, `zig build test --summary all` を実行する

## ソースコードとの差分メモ

現状の `src/rules/best_practices.zig` の `checkMissingStepName` は span を `point(0,0,0)` で構築しており、BP001 のような fix 生成パターンに移行するには workflow model の step に span と insertion anchor を追加する必要がある。
本設計はその差分を最小変更で埋め、BP003 と基盤（`Step.span` / `Step.uses_key_start_byte`）を共用する。
