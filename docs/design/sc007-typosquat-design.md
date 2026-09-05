# SC007 typosquat-action 検知設計書

## 目的

`actions/chekout` や `actions/setup-nodes` のような、公式 `actions/*` org への typosquat を Levenshtein 距離 ≤ 2 で検知する。attacker が公式 action 名と 1-2 文字違いの悪意リポジトリを作成し、ユーザの誤記を狙う攻撃面への対処。

初期スコープは owner=`actions` に限定する（正当 fork との区別を構造的に担保するため）。ADR D8 の判断。

本設計書の判断は `docs/adr/0006-security-gap-fill-sec018-sec021-sc002-sc007.md` の D8 を単一情報源とする。行番号は本ドキュメント記述時点（commit `f427b0a`）のもの。

## スコープ

- `owner == "actions"` の action 参照
- trusted action リスト（初期 8 件）との Levenshtein 距離が 1 または 2
- `repo` 名のみ比較（owner は同一のため）

## 非スコープ

- 他 org（`docker/*`, `aws-actions/*`, `github/*`, `hashicorp/*` など）への typosquat（ADR Follow-up）
- 距離 3 以上の類似（false positive 爆増）
- Unicode / マルチバイト文字（本設計では **ASCII 前提**、実質的に action repo 名は ASCII のみ）
- autofix（機械的修正は不可能。ユーザが trusted 候補を確認すべき）

## 現状整理

| 既存資産 | 位置 | 備考 |
|---|---|---|
| `ActionRef.parse` | `src/workflow/types.zig:185-234` | `owner` / `repo` 抽出 |
| `deprecated_actions` 定数配列 | `src/rules/best_practices.zig:106-137` | ソース埋込みパターンの先例 |
| `util.actionBaseName` | `src/util.zig:5-7` | `@` 前の部分抽出（既存ヘルパ） |
| `security_rules` 配列 | `src/rules/security.zig:1472-1678` | SC 系も同配列に登録 |
| Levenshtein 距離実装 | **なし**（探索済） | 本 PR で新設 |

`src/rules/data/` ディレクトリは SC002 と同じ PR 群（または直前）で新設される想定。

## 設計方針

### 1. データファイルを新設する

新規ファイル `src/rules/data/trusted_actions.zig` を作成する。

```zig
const std = @import("std");

pub const TrustedAction = struct {
    owner: []const u8,
    repo: []const u8,
};

pub const trusted_actions = [_]TrustedAction{
    .{ .owner = "actions", .repo = "checkout" },
    .{ .owner = "actions", .repo = "setup-node" },
    .{ .owner = "actions", .repo = "setup-python" },
    .{ .owner = "actions", .repo = "setup-go" },
    .{ .owner = "actions", .repo = "setup-java" },
    .{ .owner = "actions", .repo = "cache" },
    .{ .owner = "actions", .repo = "upload-artifact" },
    .{ .owner = "actions", .repo = "download-artifact" },
};

test "TrustedAction: entries are well-formed" {
    for (trusted_actions) |entry| {
        try std.testing.expect(entry.owner.len > 0);
        try std.testing.expect(entry.repo.len > 0);
    }
}
```

`src/lib.zig:78-109` の test ブロックに `_ = @import("rules/data/trusted_actions.zig");` を追加。

### 2. Levenshtein 距離を `src/util.zig` に追加する

```zig
/// ASCII-only Levenshtein distance. Returns std.math.maxInt(usize) for inputs
/// longer than MAX_LEN to avoid pathological allocations.
pub fn levenshteinDistance(a: []const u8, b: []const u8) usize {
    const MAX_LEN: usize = 64;
    if (a.len > MAX_LEN or b.len > MAX_LEN) return std.math.maxInt(usize);
    if (a.len == 0) return b.len;
    if (b.len == 0) return a.len;

    // 2 行 DP で O(min(|a|,|b|)) メモリ
    var prev: [MAX_LEN + 1]usize = undefined;
    var curr: [MAX_LEN + 1]usize = undefined;
    var i: usize = 0;
    while (i <= b.len) : (i += 1) prev[i] = i;

    i = 1;
    while (i <= a.len) : (i += 1) {
        curr[0] = i;
        var j: usize = 1;
        while (j <= b.len) : (j += 1) {
            const cost: usize = if (a[i - 1] == b[j - 1]) 0 else 1;
            const del = prev[j] + 1;
            const ins = curr[j - 1] + 1;
            const sub = prev[j - 1] + cost;
            curr[j] = @min(@min(del, ins), sub);
        }
        @memcpy(prev[0 .. b.len + 1], curr[0 .. b.len + 1]);
    }
    return prev[b.len];
}

test "levenshteinDistance: basic cases" {
    try std.testing.expectEqual(@as(usize, 0), levenshteinDistance("abc", "abc"));
    try std.testing.expectEqual(@as(usize, 1), levenshteinDistance("chekout", "checkout"));
    try std.testing.expectEqual(@as(usize, 2), levenshteinDistance("cache", "cach"));
    try std.testing.expectEqual(@as(usize, 3), levenshteinDistance("kitten", "sitting"));
    try std.testing.expectEqual(
        std.math.maxInt(usize),
        levenshteinDistance("a" ** 65, "b"),
    );
}
```

**入力前提**:
- ASCII のみ（action repo 名は実質 ASCII のみ）
- 長さ上限 64（fixed-size array で stack-allocate）
- 上限超過時は `maxInt(usize)` を返す → 呼び出し側で `> 2` 判定により自動的に不一致扱い

### 3. 検知関数 `checkTyposquatAction`

`src/rules/security.zig` に step-level check として実装する。

```zig
const trusted_data = @import("data/trusted_actions.zig");
const lev = @import("../util.zig").levenshteinDistance;

fn checkTyposquatAction(step: *const Step, list: *DiagnosticList) void {
    const action_ref = step.uses orelse return;
    if (action_ref.is_local or action_ref.is_docker) return;

    const owner = action_ref.owner orelse return;
    const repo = action_ref.repo orelse return;

    if (!std.mem.eql(u8, owner, "actions")) return; // 初期スコープ

    for (trusted_data.trusted_actions) |trusted| {
        if (!std.mem.eql(u8, owner, trusted.owner)) continue;
        if (std.mem.eql(u8, repo, trusted.repo)) return; // 完全一致は legit

        const distance = lev(repo, trusted.repo);
        if (distance == 0 or distance > 2) continue;

        const msg = std.fmt.allocPrint(
            list.messageAllocator(),
            "'{s}/{s}' looks like a typosquat of '{s}/{s}' (edit distance {d})",
            .{ owner, repo, trusted.owner, trusted.repo, distance },
        ) catch return;
        list.append(.{
            .rule_id = "SC007",
            .severity = .warning,
            .message = msg,
            .category = .dependency,
            .span = step.span,
            .fix_hint = "verify this is the intended action; did you mean actions/<trusted-repo>?",
        }) catch return;
        return; // 同一 step で複数候補に対して複数発火させない（最初の近似で打ち切り）
    }
}
```

注: `list.messageAllocator()` の API 名は SC002 と同じく実装時に `DiagnosticList` (`src/diagnostics.zig:75-138`) で確認する。

### 4. 線形走査で十分

初期エントリ 8 件 × ユーザワークフローの step 数程度では線形走査で十分。将来 trusted リストが 100 件を超えたら prefix index（owner で絞り込む `HashMap(owner, []TrustedAction)`）を検討する。

### 5. ルール登録

`src/rules/security.zig:1472` の `security_rules` 配列に追加（SC006 の直後）:

```zig
.{
    .id = "SC007",
    .name = "typosquat-action",
    .description = "Action name is similar to a well-known actions/* action (possible typosquat)",
    .severity = .warning,
    .category = .dependency,
    .check_step = &checkTyposquatAction,
},
```

### 6. 初期スコープ owner=`actions` の設計判断

ADR D8 の引用:
> 初期スコープは owner が `actions` の場合のみ（`myorg/setup-node` のような正当 fork の誤検知を構造的に回避）

正当な fork・mirror は別 org に作られるのが通例。owner を `actions` に限定することで legit fork（例: `myorg/checkout`）が SC007 に引っかかる可能性を完全排除する。

**将来拡張**: `docker/*`, `aws-actions/*`, `github/*`, `hashicorp/*` 等の trusted owner を拡張する際は、`TrustedAction.owner` フィールドが既に備わっているため、配列への追加のみで対応可能。

## 安全性評価

- **false positive リスク**: owner=`actions` 限定 + 距離 ≤ 2 + 完全一致除外で低い
- **false negative リスク**: 将来の公式人気 action（例: `actions/setup-rust`）が配列にないと検知漏れ。ADR Follow-up で更新フロー検討
- **autofix なし**: ユーザ判断必須。fix_hint に候補を明示することで UX を補完
- **計算量**: 最大 64 char × 64 char × 8 件 = 32768 ops/step。ワークフローあたり 100 step でも数 ms で収まる

## 実装差分

### 変更対象

- `src/rules/data/trusted_actions.zig` — 新規作成
- `src/util.zig` — `levenshteinDistance` 関数 + インラインテスト追加
- `src/rules/security.zig`
  - `@import` 追加
  - `checkTyposquatAction` 追加
  - `security_rules` 配列に `SC007` エントリ追加
  - SC007 のインラインテスト追加
- `src/lib.zig:78-109` の test ブロックに `_ = @import("rules/data/trusted_actions.zig");` 追加

### 変更しないもの

- `build.zig`（`lib.zig` の `@import` で自動包含）
- `src/workflow/*`
- `src/fix/*`（autofix なし）

## テスト設計

### ケース一覧

#### Levenshtein 単体（`src/util.zig` 内）

1. 同一文字列 → 0
2. 1 文字削除 (`chekout` vs `checkout`) → 1
3. 1 文字挿入 → 1
4. 2 文字置換 → 2
5. 長さ 65 超 → `maxInt(usize)`

#### SC007 ルール（`src/rules/security.zig` 内）

6. `actions/chekout` (1 char diff) → SC007 warning 発火 + `did you mean checkout` を message に含む
7. `actions/setup-nodes` (1 char diff: -s) → 発火（`setup-node` と距離 1）
8. `actions/checkout` (完全一致) → 発火せず
9. `myorg/chekout` (owner 外) → 発火せず
10. `actions/unrelated-action-name` (距離 > 2) → 発火せず
11. ローカル action (`./path`) → 発火せず
12. Docker action (`docker://...`) → 発火せず

### CI 必須 3 点

```bash
zig build && zig fmt --check src/ build.zig && zig build test --summary all
```

## 実装手順

1. **Tidy**: `src/util.zig` に `levenshteinDistance` + テスト追加、`zig build test` が通ることを確認
2. `src/rules/data/trusted_actions.zig` を作成し、`src/lib.zig` に `@import` 追加
3. **Red**: SC007 テスト（ケース 6, 8, 9）を追加
4. **Green**: `checkTyposquatAction` を実装、`security_rules` に登録
5. ケース 7, 10, 11, 12 を追加、ロジック補強
6. **Refactor**: `@import` 整理、コメント整理
7. `zig build && zig fmt --check src/ build.zig && zig build test --summary all` を通す
8. `docs/rules.md` に SC007 行を追加

## 参考

- `docs/adr/0006-security-gap-fill-sec018-sec021-sc002-sc007.md` — 判断の単一情報源（特に D8 / D9 / D11）
- `docs/design/sc002-compromised-action-design.md` — 同 PR 群の兄弟設計書
- `src/rules/best_practices.zig:106-137` — `deprecated_actions` 定数配列の書式
- `src/workflow/types.zig:185-234` — `ActionRef.parse`
- `src/rules/security.zig:1472-1678` — `security_rules` 配列
- `src/util.zig:5-7` — 既存 util helper（`actionBaseName`）の書式
- `src/lib.zig:78-109` — test orchestration
- `src/diagnostics.zig:19-33` — `Category` enum（`.dependency` を使う）
