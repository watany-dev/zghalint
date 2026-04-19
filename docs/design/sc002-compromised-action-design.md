# SC002 compromised-action-sha 検知設計書

## 目的

tj-actions/changed-files（GHSA-mrrh-fwg8-r2c3, 2025-03-14）級の **公表済み侵害 action** を SHA / tag 完全一致で検知する。SC003（known-vulnerable-action）は Advisory DB のバージョン範囲マッチで動作するため精度が落ちる（warning 止まり）のに対し、`SC002` は「この SHA は確実に侵害版」という構造的確信度で **error** を返す。

データはソースコード埋込み（ADR D9）。ネットワーク I/O 不要で `--offline` / `--quick` でも動作する。これは zghalint の主要セールスポイントの 1 つになる。

本設計書の判断は `docs/adr/0004-security-gap-fill-sec018-sec021-sc002-sc007.md` の D7 / D9 を単一情報源とする。行番号は本ドキュメント記述時点（commit `f427b0a`）のもの。

## スコープ

- リポジトリ形式の action 参照（`owner/repo@ref` または `owner/repo/path@ref`）
- `ref` が侵害 SHA / tag と完全一致する場合のみ error 発火
- ネットワーク I/O なし、ビルド時静的検証のみ

## 非スコープ

- ローカル action（`./path`）
- Docker action（`docker://...`）
- SHA の prefix match / fuzzy match（誤検知の温床になる）
- CVE DB との自動連携（ADR Follow-up で別途検討）
- autofix（機械的修正は不可能。fork への切替や rollback はユーザ判断）

## 現状整理

| 既存資産 | 位置 | 備考 |
|---|---|---|
| SC003 実装 | `src/rules/advisory.zig:20-123` | Advisory DB との versiion range match。構造の先例 |
| SC004 実装 | `src/rules/archived.zig:69-92` (check), `:189-198` (rule def) | `.dependency` category の先例 |
| `deprecated_actions` 定数配列 | `src/rules/best_practices.zig:106-137` | ソース埋込みデータパターンの先例 |
| `ActionRef.parse` | `src/workflow/types.zig:185-234` | `owner` / `repo` / `ref` / `is_local` / `is_docker` / `is_pinned` 分解 |
| `Category` enum | `src/diagnostics.zig:19-33` | `.dependency` を使う（`supply_chain` は存在しない） |
| `security_rules` 配列 | `src/rules/security.zig:1472-1678` | SC 系も同配列に追加（SC001/003/004/005/006 と同じ場所） |
| lib.zig test orchestration | `src/lib.zig:78-109` | 新規 `.zig` は `_ = @import(...)` 行の追加が必要 |

**`src/rules/data/` ディレクトリは存在しない**（探索済）。本 PR で新設する。

## 設計方針

### 1. データファイルを新設する

新規ファイル `src/rules/data/compromised_actions.zig` を作成する。

```zig
const std = @import("std");

pub const CompromisedAction = struct {
    owner: []const u8,
    repo: []const u8,
    shas: []const []const u8,     // 侵害された SHA（40 char hex、完全一致）
    tags: []const []const u8,     // 侵害された tag / branch ref（完全一致）
    advisory_url: []const u8,     // GHSA / 公式 disclosure の URL
    disclosed: []const u8,        // ISO date "YYYY-MM-DD"
};

pub const compromised_actions = [_]CompromisedAction{
    // 初期エントリは実装時に GHSA DB / StepSecurity disclosures で最終確定。
    // 最低限 tj-actions/changed-files (GHSA-mrrh-fwg8-r2c3) を含めること。
    // ADR D9: 初期は 4-6 件で start、将来 100 件超で外部 JSON 化を検討
};

test "CompromisedAction: shas and tags arrays are well-formed" {
    for (compromised_actions) |entry| {
        try std.testing.expect(entry.owner.len > 0);
        try std.testing.expect(entry.repo.len > 0);
        try std.testing.expect(entry.advisory_url.len > 0);
        try std.testing.expect(entry.disclosed.len == 10); // YYYY-MM-DD
        try std.testing.expect(entry.shas.len + entry.tags.len > 0);
        for (entry.shas) |sha| {
            try std.testing.expect(sha.len == 40); // full SHA-1
        }
    }
}
```

### 2. lib.zig への登録

`src/lib.zig:78-109` の `test` ブロックに 1 行追加する:

```zig
_ = @import("rules/data/compromised_actions.zig");
```

`build.zig` 改修は不要（既存 `lib.zig` の `@import` 走査で自動包含される）。

### 3. 検知関数 `checkCompromisedAction`

`src/rules/security.zig` に step-level check として実装する（SC 系も `security.zig` に集約している既存慣例に従う）。

```zig
const compromised_data = @import("data/compromised_actions.zig");

fn checkCompromisedAction(step: *const Step, list: *DiagnosticList) void {
    const action_ref = step.uses orelse return;
    if (action_ref.is_local or action_ref.is_docker) return;

    const owner = action_ref.owner orelse return;
    const repo = action_ref.repo orelse return;
    const ref = action_ref.ref orelse return;

    for (compromised_data.compromised_actions) |entry| {
        if (!std.mem.eql(u8, owner, entry.owner)) continue;
        if (!std.mem.eql(u8, repo, entry.repo)) continue;

        const sha_match = for (entry.shas) |bad_sha| {
            if (std.mem.eql(u8, ref, bad_sha)) break true;
        } else false;
        const tag_match = for (entry.tags) |bad_tag| {
            if (std.mem.eql(u8, ref, bad_tag)) break true;
        } else false;

        if (!sha_match and !tag_match) return; // owner/repo は一致したが ref は未侵害

        const msg = std.fmt.allocPrint(
            list.messageAllocator(),
            "{s}/{s}@{s} is a known compromised action (disclosed {s}, see {s})",
            .{ owner, repo, ref, entry.disclosed, entry.advisory_url },
        ) catch return;
        list.append(.{
            .rule_id = "SC002",
            .severity = .@"error",
            .message = msg,
            .category = .dependency,
            .span = step.span,
            .fix_hint = "rollback to a pre-incident SHA or migrate to a trusted fork",
        }) catch return;
        return;
    }
}
```

注: `list.messageAllocator()` のような API が既存にない場合、`DiagnosticList` のアロケータ API を実装時に確認する（SC003 の `src/rules/advisory.zig` が動的メッセージ生成の先例）。

### 4. `--offline` / `--quick` 対応

ネットワーク I/O を使わないため、`is_offline` モジュール変数や `init*()` 関数は不要（SC003/SC004 と異なる）。`--offline` でも `--quick` でも通常通り発火する。

**テストで `--offline` 状態での発火を明示的に検証する**（ADR D11）。

### 5. ルール登録

`src/rules/security.zig:1472` の `security_rules` 配列に追加（SC001 と SC003 の間の欠番位置）:

```zig
.{
    .id = "SC002",
    .name = "compromised-action-sha",
    .description = "Action SHA/tag is known to be compromised (GHSA disclosure)",
    .severity = .@"error",
    .category = .dependency,
    .check_step = &checkCompromisedAction,
},
```

### 6. SC003 との役割分担

| 観点 | SC002 | SC003 |
|---|---|---|
| 精度 | 完全一致（誤検知ゼロ） | version range match（誤検知あり） |
| severity | error | warning |
| データ | 埋込み定数 | GitHub Advisory DB（API or disk cache） |
| `--offline` | 常に動作 | キャッシュ有効時のみ |

2 ルールは独立に発火してよい（同一 step で SC002 と SC003 が両方鳴るケースは稀かつ有意義）。

## 安全性評価

- **false positive リスク**: SHA 完全一致のためゼロ。tag の場合は legit tag が後日再 push されるケースを懸念しうるが、tags 配列は侵害期間中の ref のみ記録する運用で対応
- **false negative リスク**: データの鮮度依存。ADR Follow-up で月次 PR / GHSA 自動同期を検討
- **autofix なし**: ユーザの判断を必須にすることで、誤った自動書き換えを防ぐ
- **データ毒入れリスク**: `src/rules/data/compromised_actions.zig` への PR レビューが防衛線。CODEOWNERS 検討（別 PR）

## 実装差分

### 変更対象

- `src/rules/data/compromised_actions.zig` — 新規作成
- `src/rules/security.zig`
  - `@import` 追加
  - `checkCompromisedAction` 追加
  - `security_rules` 配列に `SC002` エントリ追加
  - SC002 のインラインテスト追加
- `src/lib.zig:78-109` の test ブロックに `_ = @import("rules/data/compromised_actions.zig");` 追加

### 変更しないもの

- `build.zig`（`lib.zig` の `@import` で自動包含）
- `src/workflow/*`
- `src/fix/*`（autofix なし）
- `src/rules/advisory.zig`（SC003 は独立）

## テスト設計

### ケース一覧

1. **侵害 SHA hit**: `tj-actions/changed-files@<known-bad-sha>` で SC002 error 発火
2. **未侵害 SHA pass**: `tj-actions/changed-files@<benign-sha>` で発火せず
3. **別 owner / repo pass**: `foo/bar@<same-sha-string>` で発火せず（owner/repo 不一致）
4. **侵害 tag hit**: 侵害 tag 名を指定した場合 error 発火
5. **ローカル action skip**: `./local-action` で発火せず
6. **Docker action skip**: `docker://image@sha256:abc` で発火せず
7. **`--offline` 発火**: `offline = true` で SC002 が発火すること（モジュール変数依存なし）
8. **データ整合**: `compromised_actions` 配列内の全エントリが `disclosed` = YYYY-MM-DD 形式、SHA は 40 char であること（`src/rules/data/compromised_actions.zig` 内のインラインテスト）

### テストヘルパ

既存の `hasDiagnostic`, `findDiagnostic` を使う。初期侵害エントリがない状態だとケース 1, 4 が書けないため、**`tj-actions/changed-files` の実在する侵害 SHA を最初から含める**。

### CI 必須 3 点

```bash
zig build && zig fmt --check src/ build.zig && zig build test --summary all
```

## 実装手順

1. `src/rules/data/compromised_actions.zig` を作成（`CompromisedAction` 型 + 空配列 + データ整合テスト）
2. `src/lib.zig` の test ブロックに `@import` 追加
3. `zig build test` が通ることを確認（空配列でも型レベルの整合は検証される）
4. **Red**: SC002 発火のテスト（ケース 1）を追加（まだ `compromised_actions` が空なので失敗する）
5. **Green**: `tj-actions/changed-files` の侵害 SHA 1 件を `compromised_actions` に追加
6. `checkCompromisedAction` を実装、`security_rules` に登録
7. ケース 2-8 を追加し、必要ならロジック補強
8. `zig build && zig fmt --check src/ build.zig && zig build test --summary all` を通す
9. `docs/rules.md` に SC002 行を追加（SC001 と SC003 の間に挿入）

## 参考

- `docs/adr/0004-security-gap-fill-sec018-sec021-sc002-sc007.md` — 判断の単一情報源（特に D7 / D9 / D11）
- tj-actions/changed-files incident — GHSA-mrrh-fwg8-r2c3, 2025-03-14
- `src/rules/advisory.zig:20-123` — SC003 実装、Advisory 型定義の参考
- `src/rules/archived.zig:69-92, :189-198` — SC004 `.dependency` category 実装
- `src/rules/best_practices.zig:106-137` — `deprecated_actions` 定数配列の書式
- `src/rules/security.zig:1472-1678` — `security_rules` 配列
- `src/workflow/types.zig:185-234` — `ActionRef.parse`（`is_local` / `is_docker` / `is_pinned`）
- `src/lib.zig:78-109` — test orchestration
- `src/diagnostics.zig:19-33` — `Category` enum
