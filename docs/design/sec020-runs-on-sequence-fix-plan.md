# SEC020 `runs-on:` シーケンス対応 修正プラン

## 背景

PR #34（`feat(rules): add SEC020 self-hosted-runner-fork-triggered`）の Copilot レビュー
[`pullrequestreview-4135404632`](https://github.com/watany-dev/zghalint/pull/34#pullrequestreview-4135404632)
で 3 件の指摘を受けた。本ドキュメントは対応要否の切り分けと、必須項目に対する
実装計画を定める。

関連 ADR: `docs/adr/0001-sec020-runs-on-sequence-support.md`

## レビュー指摘の分類

| # | 指摘箇所 | 種別 | 対応要否 | 重要度 |
|---|---------|------|---------|--------|
| 1 | `src/rules/security.zig:1224` | 真陽性の取りこぼし | 必須 | High |
| 2 | `src/rules/security.zig:4642` | 偽の網羅感 | 必須 | High |
| 3 | `src/rules/security.zig:1222` | 軽微スタイル | 任意 | Low |

### 事実確認

- `Job.runs_on: ?[]const u8` は単一スカラしか保持しない（`src/workflow/types.zig:290`）。
- `src/workflow/parser.zig:281` が `m.getScalar("runs-on")` を呼んでおり、
  `getScalar` は scalar 以外の Node で null を返す（`src/yaml/types.zig:95-103`）。
- 結果として `runs-on: [self-hosted, linux, x64]`（実コードで最頻出のシーケンス形）は
  `job.runs_on == null` となり、SEC020 の `indexOf("self-hosted")` 判定を素通りする。
- `test "SEC020: array-literal runs_on string containing self-hosted -> fires"`
  (`src/rules/security.zig:4634`) は Zig 文字列リテラル `"[self-hosted, linux, x64]"`
  をそのまま `runs_on` に代入しており、`indexOf` は偶然 hit するが、workflow parser を
  通った挙動は検証していない。

## 修正方針

### 方針: 既存 scalar フィールドを温存し、新フィールドを追加する

`Job.runs_on` の型変更は validator など既存全利用箇所に影響するため避ける。
sequence 用に追加フィールド `runs_on_labels: ?[]const []const u8` を併設し、
scalar 形と sequence 形を別ケースで保持する。

利点:

- 既存テスト・バリデータ・ルールは改変不要（`runs_on` だけを見る）。
- 追加後は両方の表現を確認すればよく、チェックロジックが素直。
- 将来 BP 系・PERM 系で "ラベル集合" を問うルールが増えても同じ表現を再利用できる。

## 実装ステップ

### 1. 型拡張（`src/workflow/types.zig`）

```zig
pub const Job = struct {
    ...
    runs_on: ?[]const u8 = null,
    runs_on_labels: ?[]const []const u8 = null,
    ...
};
```

### 2. parser 拡張（`src/workflow/parser.zig:281`）

```zig
if (m.get("runs-on")) |node| {
    switch (node) {
        .scalar => |s| job.runs_on = s.value,
        .sequence => |seq| {
            const labels = try allocator.alloc([]const u8, seq.items.len);
            for (seq.items, 0..) |item, i| {
                labels[i] = switch (item) {
                    .scalar => |s| s.value,
                    else => "",
                };
            }
            job.runs_on_labels = labels;
        },
        else => {},
    }
}
```

`getScalar` 呼び出しは置き換え。flow sequence (`[self-hosted, linux, x64]`) も
block sequence も YAML parser は `.sequence` Node を生成するため両形を同一コードパスで
吸収する。

### 3. SEC020 チェック改修（`src/rules/security.zig:1216-1234`）

```zig
fn checkSelfHostedRunnerForkTriggeredWorkflow(wf: *const Workflow, list: *DiagnosticList) void {
    if (sec020_repo_visibility == .private) return;
    if (!hasForkAccessibleTrigger(wf)) return;

    for (wf.jobs) |job| {                       // 指摘 3: |*job| → |job|
        const has_self_hosted = blk: {
            if (job.runs_on) |s| {
                break :blk std.mem.indexOf(u8, s, "self-hosted") != null;
            }
            if (job.runs_on_labels) |labels| {
                for (labels) |l| {
                    if (std.mem.eql(u8, l, "self-hosted")) break :blk true;
                }
            }
            break :blk false;
        };
        if (!has_self_hosted) continue;

        list.append(.{
            .rule_id = "SEC020",
            .severity = .warning,
            .message = "self-hosted runner is used on a workflow with fork-accessible triggers; untrusted code may execute on your runner host",
            .span = job.span,
            .fix_hint = "use GitHub-hosted runners for fork-accessible triggers, restrict with `if:` to avoid running on fork PRs, or make the runner ephemeral",
        }) catch return;
    }
}
```

### 4. validator 整合（`src/workflow/validator.zig:55-57`）

`runs-on required` 判定が scalar のみを見ているため、sequence 形で埋めたジョブを
誤って違反と報告する。

```zig
if (!has_uses and job.runs_on == null and job.runs_on_labels == null) {
    ...
}
```

### 5. テスト差し替え（`src/rules/security.zig:4634-4646`）

既存の "array-literal runs_on string containing self-hosted -> fires" を削除し、
以下 2 件に置換:

- **model 単体**: `runs_on_labels = &.{"self-hosted", "linux", "x64"}` で発火確認。
- **parser 経由 e2e**: 既存 `test "SEC017: integration applies fix to workflow env"`
  (`src/rules/security.zig:4197` 付近) と同じ構成で、以下の YAML を
  `parseWorkflow` → `Engine.run` させる:

  ```yaml
  name: CI
  on: pull_request
  jobs:
    build:
      runs-on: [self-hosted, linux, x64]
      steps:
        - run: echo hi
  ```

加えて次の回帰テストも追加:

- `runs-on: ubuntu-latest`（scalar・`self-hosted` 不在）→ 発火しない（parser 経由）。
- `runs-on: [ubuntu-latest, x64]`（sequence・`self-hosted` 不在）→ 発火しない（parser 経由）。

### 6. ドキュメント更新

`docs/design/sec020-self-hosted-runner-fork-triggered-design.md` の
"対象範囲" / "検出ロジック" セクションに sequence 形対応を明記。

## 非対象

- `runs-on` の既存スカラ判定が substring match（`indexOf("self-hosted")`）である点の厳密化。
  `"self-hosted-runner-mylabel"` のような label 接頭辞で誤爆する可能性があるが、
  既存挙動の後方互換を優先し別プランとする。
- `runs-on` 式展開 (`${{ matrix.os }}` 等) の解決。model では expression 文字列として
  `runs_on` に残るため、SEC020 は現状どおり素通りする。

## コミット粒度

1 コミット（例: `fix(sec020): detect self-hosted in runs-on sequence form`）に
Step 1–6 をまとめる。model・parser・rule・validator・test が同一欠陥に紐づく不可分変更で、
中間状態で CI が壊れるため。

## 見積もり

- `src/workflow/types.zig`: +1 行
- `src/workflow/parser.zig`: ~+15 行（`getScalar` 置換含む）
- `src/workflow/validator.zig`: +1 行
- `src/rules/security.zig`: 本体 ~+12 行、テスト差し替え・追加 ~+80 行
- `docs/design/sec020-self-hosted-runner-fork-triggered-design.md`: +10 行

## 検証手順

1. `zig build`
2. `zig fmt --check src/ build.zig`
3. `zig build test --summary all`（既存 + 追加テスト全通過）
4. 手動 e2e: `runs-on: [self-hosted, linux]` と `pull_request` を含む fixture で
   `zig build run -- fixture.yml` を実行し、SEC020 診断が 1 件出ることを確認。
