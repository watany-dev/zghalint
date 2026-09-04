# SYN006: job ID / step ID 命名規則検証 設計書

## 目的

GitHub Actions の job ID と step ID は、先頭が英字または `_`、以降は英数字・`-`・`_` のみという命名規則に従う必要がある。違反すると GitHub 側でワークフローが起動しない。actionlint の `RuleID`（命名規則部分）と同等の検出を zghalint に追加する。

関連 issue: #61（親 #55）

## スコープ

- `jobs.<job_id>` のキー（job ID）
- `steps.*.id` の値（step ID）
- `jobs.<job_id>.needs` の各エントリ（actionlint 互換）

### 非スコープ

- ID の一意性検証（SYN005 / #60）
- `${{ }}` を含む ID（実行時に解決されるため命名規則チェックをスキップ）
- 空文字 ID（パーサー側で別途扱う想定；本ルールではスキップ）

## 検証ルール

正規表現: `^[a-zA-Z_][a-zA-Z0-9_-]*$`

Zig 実装:

```zig
fn isValidId(id: []const u8) bool {
    if (id.len == 0) return true;
    const first = id[0];
    if (first != '_' and !std.ascii.isAlphabetic(first)) return false;
    for (id[1..]) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return false;
    }
    return true;
}
```

## 診断

| 項目 | 値 |
|------|-----|
| rule_id | `SYN006` |
| name | `invalid-id-naming` |
| severity | `error` |
| category | `syntax` |

メッセージ（actionlint 互換）:

```
invalid job ID "1-build". job ID must start with a letter or _ and contain only alphanumeric characters, -, or _
invalid step ID "my.step". step ID must start with a letter or _ and contain only alphanumeric characters, -, or _
```

fix_hint:

```
rename the ID to start with a letter or _ and use only letters, digits, hyphens, and underscores
```

## Span 伝播

診断位置を正確にするため、workflow parser で以下を保持する。

| フィールド | 型 | ソース |
|-----------|-----|--------|
| `Job.id_span` | `?Span` | `jobs` マッピングのキー token span |
| `Step.id_value_span` | `?Span` | `id:` scalar の value span |
| `Job.needs_spans` | `[]const Span` | `needs` の各エントリの value span（`needs` と並列） |

`needs_spans` が空（手組みの Job など）のときは `job.span` にフォールバックする。

## 実装配置

- 検証ロジック: `src/rules/syntax.zig`
- 型拡張: `src/workflow/types.zig`
- span 付与: `src/workflow/parser.zig`（`parseJobs` / `parseJob` / `parseStep`）
- ドキュメント: `docs/rules.md`

ルール登録は既存の `syntax.rules` 配列に 1 エントリ追加。`check_job` で job ID と needs、`check_step` で step ID を検査する。

## テスト方針

1. `syntax.zig` 内の単体テスト: 検出例・非検出例（issue #61 の YAML 例）
2. `parser.zig` テスト: `id_span` がキー / scalar に対応していること
3. CI: `zig build test --summary all`

## actionlint との差分

| 観点 | actionlint | zghalint SYN006 |
|------|------------|-----------------|
| needs span | 個別 Pos | `Job.needs_spans`（欠ける場合は `job.span`） |
| 重複 ID | 同一 RuleID で検出 | SYN005（未実装）に分離 |
