# DEP002 autofix設計書

## 目的

`DEP002` は Dependabot 設定の `insecure-external-code-execution: allow` を検出するが、現状は `fix_hint` のみで自動修正を提供していない。  
`DEP002` は autofix Phase 1 の優先実装候補であり、本設計書では既存の edit-based autofix 基盤の上で安全に実装する方法を定義する。

## スコープ

- `updates` 配列内の各 entry にある `insecure-external-code-execution: allow` に対して autofix を付与する
- autofix は値を `deny` へ置換する
- `Fix.safety` は `.safe` とする
- 既存の検出条件と診断メッセージは維持する

## 非スコープ

- `insecure-external-code-execution` 行そのものの削除
- Dependabot 設定全体の整形や key 並び替え
- parser / workflow model の span 拡張
- `DEP001` の同時実装

## 現状整理

`src/rules/dependabot.zig` の `checkInsecureExecution` は `updates` 配列を走査し、`insecure-external-code-execution` の値が scalar `allow` のときに `DEP002` を報告する。  
診断位置は `map_entry.span` を使っているが、`Diagnostic.fix` は未設定である。

一方で YAML AST には既に以下の情報がある。

- `MappingEntry.key.span`: key token の byte range
- `Scalar.span`: value token の byte range
- `Scalar.style`: `plain` / `single_quoted` / `double_quoted` / block scalar

このため DEP002 は計画書の「Dependabot `updates` entry 内の key/value span」がなくても、既存 AST だけで autofix を実装できる。

## 設計方針

### 1. 修正内容

autofix は `allow` を `deny` へ置換する。

```yaml
insecure-external-code-execution: allow
```

```yaml
insecure-external-code-execution: deny
```

削除ではなく置換を採る理由は次の通り。

- 明示的に secure な状態へ収束できる
- 1 箇所の scalar 置換で完結する
- entry 削除に比べて改行やインデントの扱いが単純
- fix 適用後の設定意図が読み取りやすい

### 2. 文字列表現の保持

`Scalar.value` は quoted scalar の場合に引用符が除去された値を返す一方、`Scalar.span` は元の token 全体を指す。  
そのため replacement は `Scalar.style` に応じて次のように生成する。

| `Scalar.style` | replacement |
|---|---|
| `plain` | `deny` |
| `single_quoted` | `'deny'` |
| `double_quoted` | `"deny"` |

`literal` / `folded` は `allow` を表現できても Dependabot 設定としては実用性が低く、現状の検出対象も scalar の完全一致であるため、DEP002 autofix の対象外とする。該当ケースが将来問題になった場合のみ追加検討する。

### 3. Fix 生成 API

`src/rules/dependabot.zig` に DEP002 専用 helper を追加する。

```zig
fn buildInsecureExecutionFix(
    list: *DiagnosticList,
    value: yaml_types.Scalar,
) ?diagnostics_mod.Fix
```

責務は次の 3 点に限定する。

- replacement 文字列の生成
- 単一 `Edit` の確保
- `Fix` の組み立て

生成される edit は以下。

```zig
.{ 
    .start_byte = value.span.start_byte,
    .end_byte = value.span.end_byte,
    .replacement = replacement,
}
```

`DiagnosticList.fixAllocator()` を使うことで、既存 autofix 実装と同じライフタイム管理に揃える。

### 4. `checkInsecureExecution` への組み込み

`allow` を検出した箇所では即座に append せず、一度 `Diagnostic` をローカル変数で構築してから `fix` を詰める。

擬似コード:

```zig
if (std.mem.eql(u8, s.value, "allow")) {
    var diag = Diagnostic{
        .rule_id = "DEP002",
        .severity = .warning,
        .message = "...",
        .span = map_entry.span,
        .fix_hint = "Remove 'insecure-external-code-execution: allow' or set it to 'deny'.",
    };
    diag.fix = buildInsecureExecutionFix(diag_list, s);
    diag_list.append(diag) catch return;
}
```

診断 span は既存の `map_entry.span` を維持する。  
autofix 対象 byte range は `Scalar.span` を使うため、診断位置と edit 対象は役割を分ける。

## 安全性評価

DEP002 の autofix は `.safe` とする。

根拠:

- `allow` はルール定義上 insecure な設定であり、`deny` への変更は診断メッセージと整合する
- key の削除や別キー追加ではなく、単純な値置換である
- 外部 API や repository 固有情報に依存しない
- 計画書でも `可 / 低 / 高` に分類されている

## 実装差分

### 変更対象

- `src/rules/dependabot.zig`
- `docs/design/dep002-autofix-design.md`

### 変更内容

1. `buildInsecureExecutionFix` を追加する
2. `checkInsecureExecution` で `Diagnostic.fix` を設定する
3. DEP002 の autofix テストを追加する

### 変更しないもの

- `src/yaml/parser.zig`
- `src/yaml/types.zig`
- `src/fix/engine.zig`

DEP002 は既存の span 情報で実装可能なため、基盤拡張は不要である。

## テスト設計

計画書の TDD 方針に従い、次の 3 層で追加する。

### 1. 診断に fix が付くこと

- `allow` を検出したとき `Diagnostic.fix != null`
- `Fix.description == "set insecure-external-code-execution to deny"`
- `Fix.safety == .safe`
- edit 数が 1 件であること

### 2. Edit 内容が正しいこと

- plain scalar で `allow` の byte range が `deny` に置換される
- single quoted scalar で replacement が `'deny'` になる
- double quoted scalar で replacement が `"deny"` になる

### 3. `fix/engine.zig` 経由で YAML へ適用した結果

- `insecure-external-code-execution: allow` が `...: deny` に変わる
- quoted scalar でも引用符スタイルを保持する
- 同一ファイルの他の `updates` entry を壊さない

## 実装手順

1. DEP002 用の failing test を追加する
2. `buildInsecureExecutionFix` を実装する
3. `checkInsecureExecution` に fix 付与を組み込む
4. integration test を追加する
5. `zig build`, `zig fmt --check src/ build.zig`, `zig build test --summary all` を実行する

## ソースコードとの差分メモ

現状の `src/rules/dependabot.zig` には DEP002 専用の autofix helper が存在せず、計画書の「単純置換で済む」という評価がコードにまだ反映されていない。  
本設計はその差分を最小変更で埋めるものであり、他 rule 向けの edit builder 共通化は別タスクとする。
