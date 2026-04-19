# autofix Phase 2 挿入系ルール設計書（BP005 / PERM002 / DEP001）

最終更新: 2026-04-19

## 概要

autofix Phase 1（`BP001`, `BP002`, `BP003`, `SEC004`, `SEC007`, `SEC015`, `SEC017`, `DEP002`, `PERF003`）完了後、Phase 2 挿入系 3 ルール（`BP005`, `PERM002`, `DEP001`）を束ねて設計する。

3 ルールの共通点は「block 形式で新規 mapping エントリを既存 mapping に挿入する」ことであり、`src/fix/builder.zig` を 1 回拡張するだけで横展開できる。本書は `bp002-autofix-design.md`, `bp003-autofix-design.md`, `dep002-autofix-design.md` と同じ粒度で、3 ルール横断の設計詳細をまとめる。

決定事項の根拠・代替案却下理由は `docs/adr/0001-autofix-phase2-insertion-rules.md` を参照。

## スコープ

- `BP005` (push trigger without concurrency): workflow 先頭へ `concurrency:` ブロックを挿入
- `PERM002` (missing job-level permissions): 該当 job の `runs-on:` 直後へ `permissions:` ブロックを挿入
- `DEP001` (dependabot updates without cooldown): 各 `updates` entry の末尾へ `cooldown:` ブロックを挿入

### 非スコープ

- `BP004`, `PERM001` 残り, `PERF001` の autofix
- `fix/engine.zig` の segfault 解消（`docs/design/pbt-strategy.md` §5 #1）
- 診断 span の位置精度改善（`BP005`, `PERM002` は `Span.point(0, 0, 0)` のまま）
- 同 byte 挿入衰突時の決定的順序付け（engine 側の強化）

## 技術選定

### block 形式（複数行）を採用

`SEC007` は flow 形式（`permissions: {contents: read}`）で挿入しているが、Phase 2 3 ルールは以下の理由で block 形式に統一する。

- `BP005` の `concurrency` 雛形には `${{ github.workflow }}` などの expression が含まれ、flow mapping 内に入れると quote / escape の読みにくさが出る
- 複数行 block は diff が追いやすく、レビュー時のノイズが小さい
- Phase 2 以降でも insertion fix は増える見込みで、block 方向に統一した方が helper の再利用が進む

代償として、`src/fix/builder.zig` に block 専用 helper `insertMappingEntryBlock` を追加する。flow 版を採用済みの `SEC007` には遡及しない（diff 影響と既存テスト互換のため）。

### Safety は unsafe で統一

3 ルール全てを `.unsafe` とする。

- `BP005`: concurrency は実行キャンセル挙動を変える
- `PERM002`: permissions は GITHUB_TOKEN スコープを変える
- `DEP001`: cooldown は Dependabot 更新タイミングを変える

いずれも semantics preserving ではないため `--fix-unsafe` 必須に揃える。`SEC007` / `PERF003` と整合する判断。

## 雛形

| ルール | 雛形 |
|---|---|
| `BP005` | ```yaml\nconcurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n``` |
| `PERM002` | ```yaml\npermissions:\n  contents: read\n``` |
| `DEP001` | ```yaml\ncooldown:\n  default-days: 7\n``` |

選定理由:

- `BP005` の `cancel-in-progress` を PR 限定にしたのは、main ブランチの連続 push で前の run を潰すと deploy フローを壊す可能性があるため
- `PERM002` は `SEC007` と同等の最小権限（`contents: read`）。個別 action 毎の推定はスコープ外
- `DEP001` は `default-days: 7` のみ。`semver-major-days` などの詳細分岐はユーザが後から微調整しやすいよう避ける

## 挿入アンカー

### 共通: insertMappingEntryBlock

`src/fix/builder.zig` に追加する helper のシグネチャは以下（`ADR 0001` D3）。

```zig
pub const SubEntry = struct {
    key: []const u8,
    value: []const u8,
};

/// 指定位置に block 形式のキー + 子エントリ群を挿入する。
/// 生成形:
///   <indent>key:\n
///   <indent+child_indent>subkey1: value1\n
///   <indent+child_indent>subkey2: value2\n
///
/// 所有権: `key`, `sub_entries` 内の文字列 slice はいずれも呼び出し側が
/// 保持する。alloc で確保した `replacement` buffer と Edit slice のみが
/// 返却値の所有物。
/// `sub_entries` が空なら null を返す（意図しない empty mapping を防ぐ）。
pub fn insertMappingEntryBlock(
    alloc: std.mem.Allocator,
    pos: InsertPos,
    key: []const u8,
    sub_entries: []const SubEntry,
    child_indent: u32, // 通常 2
) ?[]const Edit;
```

`InsertPos.indent` は 0-based 空白数。`Workflow.top_level_indent` は 0-based で直接渡せるが、`Job.job_indent` は 1-based column（`src/workflow/types.zig:307`, `src/workflow/parser.zig:279`）なので `-1` してから渡す（`BP001` の `src/rules/best_practices.zig:28` と同じ扱い）。

### BP005

- anchor: `Workflow.concurrency_insertion_byte`（`src/workflow/parser.zig:60`、`on:` エントリの `full_span.end_byte`）
- indent: `Workflow.top_level_indent`（= 0）
- `concurrency_insertion_byte == null` のとき fix は null（`on:` を含まない不正 workflow 想定、実行到達しない）

### PERM002

- anchor: `Job.permissions_insertion_byte`（`src/workflow/parser.zig:292`、`runs-on:` または `uses:` の `full_span.end_byte`）
- indent: `Job.job_indent - 1`（1-based column → 0-based 空白数）
- `permissions_insertion_byte == null` または `job_indent == 0` のとき fix は null

### DEP001

dependabot は raw `Mapping` で処理している（`src/rules/dependabot.zig`）ため、以下を sub-entry から直接算出する。

- anchor: 対象 entry の最後の sub-entry の `MappingEntry.full_span.end_byte`
- indent: 最初の sub-entry の `key.span.start_col - 1`
- 任意の sub-entry で `full_span` が null（flow-style mapping、`src/yaml/parser.zig:244-249` は flow entry に `full_span` を設定しない）のとき fix は null

## 同 byte 挿入衰突の扱い

`src/workflow/parser.zig:55-64` により `permissions_insertion_byte` と `concurrency_insertion_byte` は同じ byte を指す。`SEC007` と `BP005` が同一 workflow で同時発火すると、同 byte への zero-length 挿入が 2 件発生する。

`src/fix/engine.zig` の overlap 判定（`flattenAndSort`）は `e.start_byte < last_end` で、ゼロ幅 edit は `start_byte == last_end` となるため両方が通る。逆順適用で 2 件が隣接して挿入され、構文的に valid な YAML が得られる。挿入順序は sort の tie-break に依存するが、ゴールデンテストでピン止めする。

本設計では engine / parser 側の変更は行わず、PBT とゴールデンテストで構文保全を担保する。

## データフロー

```
workflow YAML
  └─ src/workflow/parser.zig
      ├─ Workflow.concurrency_insertion_byte   (BP005)
      ├─ Workflow.top_level_indent
      ├─ Job.permissions_insertion_byte        (PERM002)
      └─ Job.job_indent

dependabot YAML
  └─ src/yaml/parser.zig
      └─ MappingEntry.full_span                (DEP001)

rules
  ├─ best_practices.zig::checkPushConcurrency ─┐
  ├─ permissions.zig::checkJobPermissions    ──┼─→ make*Fix()
  └─ dependabot.zig::checkCooldown           ──┘   ↓
                                       fix_builder.insertMappingEntryBlock
                                                   ↓
                                       Diagnostic.fix (safety=.unsafe)
                                                   ↓
                                       fix/engine.applyFixes (--fix-unsafe のみ)
```

## テスト戦略

### Zig インライン（各ルール .zig に）

1. 診断検出と `Fix.safety == .unsafe`
2. `fix.edits[0].replacement` の文字列照合
3. `fix_engine.applyFixes` 経由で期待 YAML と一致
4. 異常系: `insertion_byte == null` / `job_indent == 0` / flow-style entry

追加のゴールデンケース:
- `SEC007` + `BP005` 同時発火で構文 valid
- 複数 job の `PERM002` で逆順適用が壊れない
- `DEP001` + `DEP002` が同じ entry で共存

### PBT (tests/pbt/)

`tests/pbt/strategies.py` に以下を追加:

- `workflow_with_bp005()`: push trigger + concurrency 欠如
- `workflow_with_perm002()`: third-party action + permissions 欠如
- `workflow_with_dep001()`: dependabot + cooldown 欠如

`tests/pbt/test_autofix_idempotency.py` に新規テスト:

- `test_unsafe_fix_reduces_diagnostics`: `--fix-unsafe` で診断数が単調減少
- `test_double_unsafe_fix_is_idempotent`: `--fix-unsafe` 2 回適用で内容一致

既知 xfail `test_fix_does_not_crash`（`fix/engine.zig` segfault、`docs/design/pbt-strategy.md` §5 #1）には本設計で手を入れない。新 PBT が segfault に当たった場合はインラインテスト側に回帰ケースとして抜き出す。

## イテレーション分割

1. `src/fix/builder.zig` に `insertMappingEntryBlock` 追加（Tidy First）
2. `BP005` autofix
3. `PERM002` autofix
4. `DEP001` autofix
5. PBT 強化（strategies と `--fix-unsafe` 対応テスト）
6. ドキュメント更新（`autofix-implementation-plan.md` ステータス反映、`pbt-strategy.md` カバレッジ表追記）

各コミットで CLAUDE.md の CI ゲート（`zig build && zig fmt --check src/ build.zig && zig build test --summary all`）を通す。

## 関連ドキュメント

- `docs/adr/0001-autofix-phase2-insertion-rules.md` — 決定事項と根拠
- `docs/design/autofix-implementation-plan.md` — Phase 1-3 全体の棚卸し
- `docs/design/bp002-autofix-design.md`, `bp003-autofix-design.md`, `dep002-autofix-design.md` — Phase 1 per-rule 設計書
- `docs/design/pbt-strategy.md` — PBT 戦略、既知 xfail 一覧
- `src/fix/builder.zig`, `src/fix/engine.zig` — 既存 edit 基盤
- `src/workflow/parser.zig:55-64, 278-299` — insertion byte 設定ロジック
