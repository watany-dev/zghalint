# SEC017 autofix設計書

## 目的

`SEC017` は `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` を検出するが、現状は `fix_hint` のみで自動修正を提供していない。  
`docs/design/autofix-implementation-plan.md` では優先実装候補に入っている一方、実装側では `env` の value span を保持していないため、そのままでは edit-based autofix を付与できない。  
本設計書では、既存の workflow parser / model を最小限拡張しつつ、安全に `false` へ置換する方法を定義する。

関連資料:
- `docs/design/sec017-implementation-plan.md`

## スコープ

- workflow-level `env`
- job-level `env`
- step-level `env`
- `ACTIONS_ALLOW_UNSECURE_COMMANDS` の値が scalar `true` の場合に autofix を付与する
- autofix は値を `false` に置換する
- `Fix.safety` は `.safe` とする
- 既存の検出条件と診断メッセージは維持する

## 非スコープ

- `ACTIONS_ALLOW_UNSECURE_COMMANDS` エントリ全体の削除
- `literal` / `folded` scalar に対する autofix
- `env` 以外の `with:` や任意 mapping への span/style 伝播
- `SEC008` の同時実装
- insecure commands 自体の移行提案生成

## 現状整理

`src/rules/security.zig` の `checkEnvForInsecureCommands` は `workflow_types.StringMap` から `ACTIONS_ALLOW_UNSECURE_COMMANDS` を見つけ、値が `"true"` なら `SEC017` を報告する。  
しかし `parseStringMap` は YAML scalar の `span` と `style` を捨てて `[]const u8` だけを `StringMap` に格納するため、診断は出せても edit 対象の byte range を復元できない。

現状の制約は次の通り。

- `Workflow.env`, `Job.env`, `Step.env` はいずれも `?StringMap`
- `StringMap.get()` で取得できるのは値文字列のみ
- `SEC017` の診断 span は `Span.point(0, 0, 0)` 固定
- DEP002 と違って YAML AST 上の `Scalar.span` に rule 実装からアクセスできない

このため `SEC017` は計画書上の「単純置換で済む」カテゴリに見えても、実際には workflow parser / model への最小拡張が前提になる。

## 設計方針

### 1. 修正内容は `true -> false` の値置換に限定する

autofix は `ACTIONS_ALLOW_UNSECURE_COMMANDS` の value scalar 全体を `false` に置換する。

```yaml
env:
  ACTIONS_ALLOW_UNSECURE_COMMANDS: true
```

```yaml
env:
  ACTIONS_ALLOW_UNSECURE_COMMANDS: false
```

削除ではなく置換を採る理由は次の通り。

- value scalar の byte range だけあれば実装できる
- block-style mapping entry 全体の removable span を workflow model に持ち込まなくてよい
- inline comment や前後のインデントを壊しにくい
- fix 適用後の状態が明示的で読みやすい

### 2. `env` 用の最小 metadata を workflow model に追加する

`StringMap` 自体は既存 rule が広く使っているため維持し、`env` 専用の並行 metadata map を追加する。

`src/workflow/types.zig` に次を追加する。

```zig
pub const ScalarValueMeta = struct {
    value_span: yaml_types.Span,
    style: yaml_types.ScalarStyle,
};

pub const ScalarValueMetaMap = std.StringArrayHashMap(ScalarValueMeta);
```

あわせて次の field を追加する。

- `Workflow.env_meta: ?ScalarValueMetaMap = null`
- `Job.env_meta: ?ScalarValueMetaMap = null`
- `Step.env_meta: ?ScalarValueMetaMap = null`

この形にする理由は次の通り。

- 既存の `env.get("KEY")` 呼び出しを壊さない
- `SEC017` だけが必要とする span/style を局所的に参照できる
- parser 変更範囲を `env` のみへ限定できる
- 将来 `SEC019` などで env value span を再利用できる

### 3. parser は `env` だけ metadata 付きで読む

`parseStringMap` は他用途でも使われているため温存し、`env` 専用に新 helper を足す。

```zig
const ParsedStringMap = struct {
    values: types.StringMap,
    meta: types.ScalarValueMetaMap,
};

fn parseStringMapWithMeta(
    allocator: std.mem.Allocator,
    node: Node,
) ParseError!ParsedStringMap
```

helper の責務は次の 2 点に限定する。

- scalar value を `values` へ格納する
- 同じ key の `value_span` / `style` を `meta` へ格納する

`Workflow.env`, `Job.env`, `Step.env` の parse 箇所だけをこの helper に切り替える。  
`with:` や `secrets:` など他の mapping は既存の `parseStringMap` を使い続ける。

### 4. `SEC017` は metadata があるときだけ fix を付与する

`checkEnvForInsecureCommands` は `env_map` と `env_meta` を受け取り、対象 key を見つけたら一度 `Diagnostic` をローカル変数で構築する。

擬似コード:

```zig
if (env_map.get("ACTIONS_ALLOW_UNSECURE_COMMANDS")) |val| {
    if (std.mem.eql(u8, val, "true")) {
        var diag = Diagnostic{
            .rule_id = "SEC017",
            .severity = .warning,
            .message = "insecure workflow commands are enabled via ACTIONS_ALLOW_UNSECURE_COMMANDS",
            .span = meta.value_span,
            .fix_hint = "remove ACTIONS_ALLOW_UNSECURE_COMMANDS or set it to false; use environment files instead of set-env/add-path",
        };
        diag.fix = buildInsecureCommandsFix(list, meta);
        list.append(diag) catch return;
    }
}
```

metadata がない場合は既存通り `fix_hint` のみを返す。  
手書きの unit test や将来の parser 差し替えでも退行しないよう、この fallback は残す。

### 5. replacement は scalar style を保持する

`ACTIONS_ALLOW_UNSECURE_COMMANDS` の値は quoted のことがあるため、replacement は `ScalarValueMeta.style` に応じて決める。

| style | replacement |
|---|---|
| `plain` | `false` |
| `single_quoted` | `'false'` |
| `double_quoted` | `"false"` |

`literal` / `folded` は非スコープとし、diagnostic は出すが autofix は付けない。

### 6. Fix 生成 API

`src/rules/security.zig` に次の helper を追加する。

```zig
fn buildInsecureCommandsFix(
    list: *DiagnosticList,
    meta: workflow_types.ScalarValueMeta,
) ?diagnostics.Fix
```

生成される edit は次の 1 件のみ。

```zig
.{
    .start_byte = meta.value_span.start_byte,
    .end_byte = meta.value_span.end_byte,
    .replacement = replacement,
}
```

`DiagnosticList.fixAllocator()` を使い、既存 autofix と同じライフタイム管理に揃える。

## 安全性評価

`SEC017` の autofix は `.safe` とする。

根拠:

- `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` は GitHub Actions の deprecated insecure workflow commands を再有効化する設定であり、`false` への変更は rule の目的と一致する
- fix は value scalar の単純置換で完結し、構造変更を伴わない
- 外部 API や repository 固有情報に依存しない
- `SEC004` や `DEP002` と同じく、危険な設定値を安全側へ倒す deterministic な修正である

`env` を削除する設計にすると entry span と comment 取り扱いの難度が上がるため、本タスクでは採らない。

## 実装差分

### 変更対象

- `src/workflow/types.zig`
- `src/workflow/parser.zig`
- `src/rules/security.zig`
- `docs/design/sec017-autofix-design.md`
- `docs/design/autofix-implementation-plan.md`

### 変更内容

1. `ScalarValueMeta` / `ScalarValueMetaMap` を追加する
2. `Workflow`, `Job`, `Step` に `env_meta` を追加する
3. `parseStringMapWithMeta` を追加し、`env` parse にだけ適用する
4. `buildInsecureCommandsFix` を追加する
5. `checkEnvForInsecureCommands` とその呼び出し箇所を metadata 対応にする
6. SEC017 の autofix テストを追加する

### 変更しないもの

- `src/fix/engine.zig`
- `src/yaml/parser.zig`
- `src/yaml/types.zig`
- `parseStringMap` の既存利用箇所全般

SEC017 は workflow parser が持つ情報を少し増やせば実装でき、YAML parser 自体の変更は不要である。

## テスト設計

TDD 方針に従い、次の 3 層で追加する。

### 1. 診断に fix が付くこと

- workflow/job/step それぞれで `SEC017` に `fix != null` が付くこと
- `Fix.description == "set ACTIONS_ALLOW_UNSECURE_COMMANDS to false"`
- `Fix.safety == .safe`
- edit 数が 1 件であること

### 2. Edit 内容が正しいこと

- plain scalar では replacement が `false`
- single quoted scalar では replacement が `'false'`
- double quoted scalar では replacement が `"false"`
- `literal` / `folded` scalar では diagnostic は出るが fix は付かない
- metadata がない手動構築 workflow でも diagnostic 自体は維持される

### 3. `fix/engine.zig` 経由で YAML へ適用した結果

- workflow-level `env` の `true` が `false` に変わる
- job-level `env` の `true` が `false` に変わる
- step-level `env` の `true` が `false` に変わる
- quoted style と inline comment を保持する

## 実装手順

1. SEC017 用の failing test を追加する
2. `src/workflow/types.zig` に `env_meta` 用型と field を追加する
3. `src/workflow/parser.zig` に `parseStringMapWithMeta` を実装する
4. `src/rules/security.zig` に `buildInsecureCommandsFix` を追加する
5. `checkEnvForInsecureCommands` を metadata 対応にする
6. integration test を追加する
7. `zig build`, `zig fmt --check src/ build.zig`, `zig build test --summary all` を実行する

## ソースコードとの差分メモ

現状の `src/rules/security.zig` だけを見ると `SEC017` は単純な値置換に見えるが、実際には `src/workflow/parser.zig` の `parseStringMap` が span/style を落としているため、そのままでは autofix を載せられない。  
したがって本タスクの本質は rule 実装よりも、workflow model へ `env` の source metadata を最小限伝播する設計にある。
