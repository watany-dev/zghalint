# autofix Phase 2 残りルール設計書（PERM001 追加 / BP004 / PERF001）

最終更新: 2026-04-19

## 概要

autofix Phase 2 前半（`BP005`, `PERM002`, `DEP001`、`autofix-phase2-insertion-design.md`）完了後、Phase 2 残り 3 件（`PERM001` 追加対応、`BP004`、`PERF001`）を束ねて設計する。

3 ルールの共通点は「ネットワーク依存なし・パターン変換（Phase 3）未満・既存 `fix_builder` helper で完結する」ことであり、parser 拡張は `PERM001` の `PermissionsMeta` 追加 1 点のみで済む。本書は `autofix-phase2-insertion-design.md` と同じ粒度で、3 ルール横断の設計詳細をまとめる。

決定事項の根拠・代替案却下理由は `docs/adr/0002-autofix-phase2-remainder.md` を参照。

## スコープ

- `PERM001` 追加対応: 検出を 10 → 14 フィールドに拡張し、`id-token` を除く 13 フィールドで `write` → `read` を value-span 置換（unsafe）
- `BP004` (cross-platform shell): Windows-targeting ジョブの `run:` step に `shell: bash` を挿入（unsafe）
- `PERF001` (cache not used): `actions/setup-go` に `cache: true` を付与（unsafe）

### 非スコープ

- Phase 3（`EXPR006/007`, `SEC014`）のパターン変換系 autofix
- ネットワーク依存系（`SEC001`, `SC001/003/006`）の autofix
- `PERF001` の `actions/setup-node` / `actions/setup-python` 対応（lockfile 検出基盤が必要）
- `fix/engine.zig` segfault の解消（`docs/design/pbt-strategy.md` §5 #1）
- 診断 span の位置精度改善

## 技術選定

### Safety は全件 unsafe

3 ルールすべてを `.unsafe` とする。

- `PERM001` 個別 `write` → `read`: GITHUB_TOKEN のスコープを狭めるため、write を前提にした job を壊しうる
- `BP004` `shell: bash`: 既存 `run:` が cmd / pwsh 前提なら壊れる
- `PERF001` `cache: true`: 成功時挙動が変わる（キャッシュ読み書き追加）

いずれも `--fix-unsafe` 指定時のみ適用され、`SEC007` / `PERF003` と整合する。

### id-token は autofix 対象外

`id-token` スコープは GitHub Actions 仕様上 `read` / `none` の 2 値しかなく（`write` の反対は `none`）、機械的に `read` へ置換すると誤った YAML を生成する。本設計では `id-token: write` 検出を残しつつ fix は付けず、専用 `fix_hint` で OIDC 用途を案内する。

### `PermissionsMeta` 方式（PERM001）

個別 value span の保持方針として 3 案を検討:

1. **`Workflow.permissions_meta` / `Job.permissions_meta` 並行保持（採用）**
2. `Permissions` 構造体に直接 `*_value_span: ?Span` を 14 個追加
3. `PermissionLevel` を `struct { level: enum, span: ?Span }` に構造体化

採用案 (1) は既存 `Workflow.env_meta` / `Job.env_meta`（`src/workflow/types.zig:294,321`）と同じ「meta 並行保持」パターンで、既存コードの読み込み経路を変えずに span だけを追加できる。(2) は `Permissions` の全利用箇所が肥大化し、(3) は既存ルールの enum 比較 API を壊すため却下。

### BP004 は step 単位に `shell: bash`

`defaults.run.shell` を job 単位に挿入する方式は、(a) 他 step へ副作用が出る、(b) 既存 `defaults` を持つ job で構造挿入が面倒、(c) step 個別の誤爆リスクを吸収できない、の 3 点で却下。各 step の `shell_insertion_byte` への挿入に統一する。

値は `bash`。`pwsh` は Linux/macOS でも動くが、POSIX スタイル `run:` への誤爆リスクが `bash` より大きい（`$(…)` 展開など）。GitHub 公式の cross-platform 既定値も `bash` である。

### PERF001 は setup-go のみ

`actions/setup-go` の `cache: true` は lockfile を要求せず universally 有効。対して `setup-node` / `setup-python` は `cache: npm` / `cache: pip` に加えて `cache-dependency-path` または該当 lockfile が必要で、wrong-guess で CI が赤く落ちる。lockfile 検出基盤は本設計のスコープ外とし、`fix_hint` のまま据え置く。

### 診断シェイプ不変

PERF001 は「job 単位 / setup 種別ごとに 1 診断」の現仕様を維持する。同一 job 内に複数の `actions/setup-go` step があっても診断は 1 件のままで、fix は multi-edit で全 step を一括書き換えする。これによりユーザー可視の CI 出力は変化しない。

## 雛形

| ルール | Edit の形 | 備考 |
|---|---|---|
| `PERM001` | `replaceScalar(value_span, .plain, "read")` | 個別フィールド毎に 1 Edit。diagnostics 1 件 = fix 1 件 = edit 1 件 |
| `BP004` | `insertMappingEntry(shell_insertion_byte, indent, "shell", "bash")` | step mapping に `shell: bash` 1 行挿入 |
| `PERF001` with-exists | `appendMappingEntry(with_last_entry_end_byte, indent, "cache", "true")` | 既存 `with:` mapping 末尾に追加 |
| `PERF001` no-with | `\n{parent_indent}with:\n{child_indent}cache: true` を `uses_value_end_byte` に挿入 | 2 行ブロック新設 |

## 挿入アンカー

### PERM001

- anchor: `PermissionsMeta.{field}_value_span.byte_range`（各 14 フィールド）
- 形式: value 範囲を `read` に scalar 置換（`replaceScalar`）
- `value_span == null` のとき fix は null（flow-style 等で span 欠落時）
- `id-token` の分岐: comptime 名前比較で検出のみ、fix なし

### BP004

- anchor: `Step.shell_insertion_byte`（`run:` エントリ末尾 = 次行頭、既存 span）
- indent: `Step.span.start_col - 1`（1-based column → 0-based 空白数、`BP001` の `src/rules/best_practices.zig:28` と同一換算）
- `shell_insertion_byte == null` または `span.start_col == 0` のとき fix は null

### PERF001

- `with:` あり → anchor: `Step.with_last_entry_end_byte`、indent: child entry col - 1
- `with:` なし → anchor: `Step.uses_value_end_byte`、parent indent: `Step.uses_key_col - 1`、child indent: `Step.uses_key_col + 1`（+2 ネスト）
- 複数 setup-go step が同 job 内にある場合、spans が揃った step の edits だけ集めて単一 Fix として発行。全 step で span が欠落したら fix なし

## 同 byte 挿入衝突の扱い

本設計の 3 ルールは workflow-top 挿入を行わない（ADR 0001 § D5 で議論された `concurrency_insertion_byte` / `permissions_insertion_byte` の衝突問題は非該当）。

- PERM001: scalar 置換のみ（挿入なし）
- BP004: step mapping 内の `shell_insertion_byte`、step ごとに独立
- PERF001: step mapping 内の `uses_value_end_byte` または `with_last_entry_end_byte`、step ごとに独立

異なる step 間では挿入アンカーが重ならず、同一 step 内でも BP004（`run:` 起点）と PERF001（`uses:` 起点）が同時発火するケースは構造上発生しない。engine 側の ordering 強化は本設計で行わない。

## データフロー

```
workflow YAML
  └─ src/workflow/parser.zig
      ├─ parsePermissions
      │   └─ PermissionsMeta に 14 × value_span を格納    (PERM001)
      ├─ Workflow.permissions_meta                        (PERM001)
      ├─ Job.permissions_meta                             (PERM001)
      ├─ Step.shell_insertion_byte                        (BP004、既存)
      ├─ Step.uses_value_end_byte                         (PERF001、既存)
      ├─ Step.with_last_entry_end_byte                    (PERF001、既存)
      └─ Step.uses_key_col                                (BP004 / PERF001、既存)

rules
  ├─ permissions.zig::checkPermissionsScope     ─┐
  ├─ best_practices.zig::checkCrossPlatformShell ┼─→ build*Fix()
  └─ performance.zig::checkCacheNotUsed         ─┘   ↓
                                  fix_builder.replaceScalar
                                 / insertMappingEntry
                                 / appendMappingEntry
                                                     ↓
                                         Diagnostic.fix (safety=.unsafe)
                                                     ↓
                                         fix/engine.applyFixes (--fix-unsafe のみ)
```

## テスト戦略

### Zig インライン（各ルール .zig 末尾）

各ルールで以下 3 層を揃える（`autofix-phase2-insertion-design.md` と同じ粒度）:

1. 診断検出と `Fix.safety == .unsafe`
2. `fix.edits[*].replacement` の文字列照合と Edit 数の一致
3. `fix_engine.applyFixes` 経由で期待 YAML と一致

追加のゴールデンケース:

- **PERM001**: `id-token: write` は検出のみで fix 欠落を確認、他 13 フィールドは全て fix 付き、14 フィールド全部 `write` での multi-edit 適用
- **BP004**: `shell_insertion_byte == null` の fallback、Windows 判定との組み合わせ、既存 `shell:` 存在時の検出スキップ
- **PERF001**: `with:` 有無 2 ケース、複数 setup-go 同時書換、span 欠落時の skip、setup-node / setup-python は fix なし

### PBT（tests/pbt/）

`tests/pbt/strategies.py` に以下を追加:

- `workflow_with_perm001_individual_write()`: 個別 `write` permission を含む workflow（`id-token` 混在でも対象外の確認）
- `workflow_with_bp004()`: Windows runner（`windows-latest` / `windows-2022`）+ `shell` 未指定の `run:` step
- `workflow_with_perf001_setup_go()`: `actions/setup-go` + `with:` 有無両バリアント

`tests/pbt/test_autofix_idempotency.py` の `st.one_of(...)` に 3 strategy を追加し、以下 2 不変条件で検証:

- `test_unsafe_fix_reduces_diagnostics_workflow`: `--fix-unsafe` 1 回で対象診断数が単調減少
- `test_double_unsafe_fix_is_idempotent_workflow`: 2 回目以降の適用で内容一致

既知 xfail `test_fix_does_not_crash`（`docs/design/pbt-strategy.md` §5 #1）には手を入れない。新 PBT が segfault に当たった場合は個別 xfail を広げず、Zig インラインテスト側に回帰ケースとして抜き出す（ADR 0001 § D7 と同方針）。

## イテレーション分割

ADR 0001 § D6 のコミット分割パターンを踏襲し、5 コミットで進める。

1. **PERM001 追加対応**: parser 拡張（`PermissionsMeta`）+ rule + Zig インラインテスト
2. **BP004 autofix**: rule + Zig インラインテスト（parser 変更なし）
3. **PERF001 autofix**: rule + Zig インラインテスト（parser 変更なし）
4. **PBT 強化**: `strategies.py` に 3 strategy 追加 + `test_autofix_idempotency.py` 拡張
5. **ドキュメント更新**: 本設計書新規 + `autofix-implementation-plan.md` / `pbt-strategy.md` ステータス反映 + ADR 0002

各コミットで CLAUDE.md の CI ゲート（`zig build && zig fmt --check src/ build.zig && zig build test --summary all`）を通す。コミット 4 以降は `python -m pytest tests/pbt/` も通す。

## 関連ドキュメント

- `docs/adr/0002-autofix-phase2-remainder.md` — 決定事項と根拠
- `docs/adr/0001-autofix-phase2-insertion-rules.md` — Phase 2 前半の ADR（本設計のテンプレート）
- `docs/design/autofix-phase2-insertion-design.md` — Phase 2 前半の横断設計
- `docs/design/autofix-implementation-plan.md` — 42 診断 ID 全体の棚卸し
- `docs/design/pbt-strategy.md` — PBT 戦略・ルールカバレッジ表・既知 xfail 一覧
- `src/fix/builder.zig`, `src/fix/engine.zig` — 既存 edit 基盤
- `src/workflow/types.zig:22-41` — `Permissions`（全 14 フィールド）
- `src/workflow/types.zig:227-258` — `Step`（`shell_insertion_byte` / `uses_value_end_byte` / `with_last_entry_end_byte`）
- `src/workflow/parser.zig:446-479` — `parsePermissions`（`PermissionsMeta` 格納の投入箇所）
- `src/rules/permissions.zig` — PERM001 実装
- `src/rules/best_practices.zig` — BP004 実装
- `src/rules/performance.zig` — PERF001 実装
