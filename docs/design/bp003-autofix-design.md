# BP003 autofix設計書

## 目的

`BP003` は既知の deprecated action version（例: `actions/checkout@v1`）を検出するが、現状は `fix_hint` のみで自動修正を提供していない。
`BP003` は autofix Phase 1 の優先実装候補（`可 / 中 / 高`）であり、本設計書では既存の置換表と edit-based autofix 基盤の上で安全に実装する方法を定義する。

関連資料:
- `docs/design/dep002-autofix-design.md`（scalar style 分岐の先例）

## スコープ

- `uses:` の version 部分が `deprecated_actions` 置換表に一致した場合に autofix を付与する
- autofix は `@<古い version>` の version 部分のみを `<新しい version>` へ置換する
- `Fix.safety` は `.safe` とする
- 既存の検出条件と診断メッセージは維持する

## 非スコープ

- SHA pin や branch 参照の解決（`SEC001` 側のネットワーク依存の責務）
- action name（`owner/repo`）そのものの変更や代替 action への切り替え
- deprecated だが置換表に無い任意 action の検出
- `literal` / `folded` scalar の `uses:` サポート（現実ケースが無い）

## 現状整理

`src/rules/best_practices.zig:112-131` の `checkDeprecatedAction` は以下の処理を行う。

- `step.uses.?.raw` の `@` 前部分と `deprecated_actions` の `action` を比較
- `step.uses.?.ref` と `version` を比較
- 一致したら診断を出す

置換表（`deprecated_actions`）は既に実装済みで、各 entry に `replacement` version が含まれている。

workflow parser 側は `step.uses_value_end_byte` を保持しているため、version 部分の byte range は `(uses_value_end_byte - version.len, uses_value_end_byte)` で算出できる（plain scalar の場合）。

quoted scalar の場合は `Scalar.span` が引用符を含むため、追加の考慮が必要。

## 設計方針

### 1. 修正内容は version 部分の置換に限定する

autofix は `@<old_version>` の version のみを置換する。

```yaml
uses: actions/checkout@v1
```

```yaml
uses: actions/checkout@v4
```

action name (`actions/checkout`) や `@` 記号は変更しない。この方針を採る理由は次の通り。

- byte range が明確で誤爆しない
- quoted スタイルを保持できる
- 置換表の情報のみで完結し、外部参照不要

### 2. 文字列表現の保持

`uses:` の値は quoted のことがあるため、replacement は `Scalar.style` を考慮する必要がある。

| `Scalar.style` | scalar の実体（byte range） | replacement 算出 |
|---|---|---|
| `plain` | `actions/checkout@v1` | `uses_value_end_byte - version.len` から `uses_value_end_byte` を `v4` で置換 |
| `single_quoted` | `'actions/checkout@v1'` | `uses_value_end_byte - 1 - version.len` から `uses_value_end_byte - 1` を `v4` で置換 |
| `double_quoted` | `"actions/checkout@v1"` | 同上（引用符 1 byte 分オフセット）|

`literal` / `folded` は実用性が低く、現状の検出ロジックも `step.uses.ref` を直接比較するため対象外とする。

実装上は scalar style を step に保持する必要がある。現在 `Step.uses_value_end_byte` のみ持っているため、**`Step.uses_value_style: ?ScalarStyle` を追加する**。

### 3. Fix 生成 API

`src/rules/best_practices.zig` に helper を追加する。

```zig
fn buildDeprecatedActionFix(
    list: *DiagnosticList,
    step: *const Step,
    old_version: []const u8,
    new_version: []const u8,
) ?Fix
```

責務は次の 3 点に限定する。

- scalar style による byte offset 補正
- 単一 `Edit` の確保
- `Fix` の組み立て

生成される edit は 1 件:

```zig
.{
    .start_byte = version_start_byte,
    .end_byte = version_end_byte,
    .replacement = new_version,
}
```

`DiagnosticList.fixAllocator()` を使い、既存 autofix と同じライフタイム管理に揃える。

### 4. `checkDeprecatedAction` への組み込み

```zig
fn checkDeprecatedAction(step: *const Step, diag_list: *DiagnosticList) void {
    const action_ref = step.uses orelse return;
    if (action_ref.is_local or action_ref.is_docker) return;

    const action_name = util.actionBaseName(action_ref.raw);
    const version = action_ref.ref orelse return;

    for (deprecated_actions) |dep| {
        if (std.mem.eql(u8, action_name, dep.action) and std.mem.eql(u8, version, dep.version)) {
            var diag = Diagnostic{
                .rule_id = "BP003",
                .severity = .warning,
                .message = "Using deprecated action version. Consider upgrading.",
                .span = step.span,
                .fix_hint = "Upgrade to a newer version.",
            };
            diag.fix = buildDeprecatedActionFix(diag_list, step, dep.version, dep.replacement);
            diag_list.append(diag) catch return;
            return;
        }
    }
}
```

診断 span も `Span.point(0,0,0)` から `step.span` に変更する（BP002 の設計と同じ）。

## 安全性評価

BP003 の autofix は `.safe` とする。

根拠:

- 同じ action のメジャーバージョン upgrade で、action の semantic は保持される（GitHub Actions のメジャーバージョン更新ポリシー）
- 置換表に登録されているペアのみを対象とし、unknown なアクションには適用されない
- 単純な byte range 置換で構造変更を伴わない
- 外部 API や repository 固有情報に依存しない
- 計画書の unsafe list（§unsafe fix の扱い）に BP003 は含まれていない

なお厳密には action のメジャー version upgrade には breaking change が含まれる可能性があるが、`deprecated_actions` 表は手動メンテされた「安全に置換可能」なペアのみを含むため問題ない。

## 実装差分

### 変更対象

- `src/workflow/types.zig`
- `src/workflow/parser.zig`
- `src/rules/best_practices.zig`
- `docs/design/bp003-autofix-design.md`（本書）

### 変更内容

1. `Step.span` を追加する（BP002 と共用）
2. `Step.uses_value_style: ?yaml_types.ScalarStyle` を追加する
3. `parseStep` で span と scalar style を格納する
4. `buildDeprecatedActionFix` を追加する
5. `checkDeprecatedAction` に fix 付与を組み込む
6. BP003 の autofix テストを 3 層で追加する

### 変更しないもの

- `src/fix/engine.zig`
- `src/yaml/parser.zig`
- `src/yaml/types.zig`

## テスト設計

### 1. 診断に fix が付くこと

- `actions/checkout@v1` で `fix != null`、description が `"Upgrade actions/checkout to v4"` 相当
- `actions/setup-python@v4` で `fix != null`
- current version（`@v4`）では診断自体が出ない
- local/docker action では診断自体が出ない
- `Fix.safety == .safe`
- edit 数が 1 件

### 2. Edit 内容が正しいこと

- plain scalar で `start_byte == uses_value_end_byte - "v1".len`、`end_byte == uses_value_end_byte`、replacement == `"v4"`
- single quoted scalar で引用符 1 byte 分オフセットが効く
- double quoted scalar で同様

### 3. `fix/engine.zig` 経由で YAML へ適用した結果

- `uses: actions/checkout@v1` → `uses: actions/checkout@v4`
- `uses: 'actions/checkout@v1'` → `uses: 'actions/checkout@v4'`（引用符保持）
- `uses: "actions/checkout@v1"` → `uses: "actions/checkout@v4"`
- 適用後の YAML が再パース可能
- 同一 workflow 内の他 step を壊さない

## 実装手順

1. BP003 用の failing test を追加する
2. `src/workflow/types.zig` に `Step.span` / `Step.uses_value_style` を追加する（BP002 と共用する tidy commit）
3. `src/workflow/parser.zig` の `parseStep` で span と scalar style を格納する
4. `buildDeprecatedActionFix` を実装する
5. `checkDeprecatedAction` に fix 付与を組み込む
6. integration test を追加する
7. `zig build`, `zig fmt --check src/ build.zig`, `zig build test --summary all` を実行する

## ソースコードとの差分メモ

現状の `src/rules/best_practices.zig` の `checkDeprecatedAction` は置換表を既に持ちつつも `fix` を出していない。
本設計は置換表と parser の既存情報（`uses_value_end_byte`）に scalar style を加えるだけで autofix を実装できる最小差分である。
BP002 と基盤（`Step.span`）を共用する。
