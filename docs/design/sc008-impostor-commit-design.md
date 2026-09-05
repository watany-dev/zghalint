# SC008 impostor-commit 検知設計書

## 目的

`uses: owner/repo@<sha>` の SHA pin に対し、その SHA が upstream リポジトリのいずれの branch・tag からも到達不能（reachable でない）である状態 — いわゆる **impostor commit** — を検出する。GitHub の共有 object DB により fork/未マージ PR の commit も `/commits/{sha}` で 200 を返すため、SHA pin 自体では本攻撃を防げない。

本設計書の判断は `docs/adr/0008-sc008-impostor-commit.md` を単一情報源とする。行番号は本ドキュメント記述時点（commit `57cdc47`）のもの。

## スコープ

- `ActionRef.ref` が 40 文字の hex SHA（全 `uses: owner/repo@<sha>`）
- upstream `owner/repo` に対する tag / branch 到達可能性
- GraphQL バッチ（SC005/SC006 と共用）+ REST `/compare` での判定
- disk_cache v2（24h TTL）での結果共有

## 非スコープ

- short SHA（7-8 文字）ピンの検出 — 既存 SC001 でカバー
- `refs/pull/*`（PR head ref）を legitimate とみなすオプション — follow-up
- `docker://` / `./local-path` action — 対象外（`ActionRef.is_docker` / `is_local` で除外）
- autofix — 候補列挙 `fix_hint` のみ、`Diagnostic.fix = null`
- REST-only フォールバック（token 無し環境）— follow-up

## 現状整理

| 既存資産 | 位置 | 備考 |
|---|---|---|
| `ActionRef.parse` | `src/workflow/types.zig` | `ref` / `is_local` / `is_docker` 判定 |
| SC005 (stale-action-refs) | `src/rules/stale_refs.zig` | SHA→tag 解決。impostor.zig のテンプレート |
| GraphQL batch | `src/rules/graphql.zig` | SC005/SC006 用。本 PR で branches/defaultBranchRef を追加 |
| prefetch orchestrator | `src/rules/prefetch.zig` | disk → GraphQL → REST fallback |
| disk_cache | `src/rules/disk_cache.zig` | 24h TTL。v1 → v2 migration 対象 |
| `engine.Deadline` | `src/rules/engine.zig` | network_deadline_ns。SC008 でも共用 |
| REST `/compare` client | **なし** | 本 PR で新設（prefetch 層） |

## 設計方針

### 1. モジュール構成

新規ファイル `src/rules/impostor.zig` を作成。`src/rules/stale_refs.zig` を 1:1 写像したテンプレート構造を持つ。

```zig
const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const engine = @import("engine.zig");
const workflow = @import("../workflow/types.zig");

pub const ImpostorStatus = enum { legitimate, impostor, unknown };

pub const CachedResult = struct {
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
    status: ImpostorStatus,
    // 候補列挙用に graphql.RepoResult から取り出した最新 tag/branch 情報を保持
    suggested_tags: []const NamedOid = &.{},
    suggested_default: ?NamedOid = null,
};

pub const NamedOid = struct { name: []const u8, oid: []const u8 };

var cache: std.StringHashMapUnmanaged(CachedResult) = .{};
var cache_mu: std.Thread.Mutex = .{};

pub fn initImpostor(allocator: std.mem.Allocator) void { ... }
pub fn deinitImpostor(allocator: std.mem.Allocator) void { ... }

pub fn setCachedImpostorResult(
    allocator: std.mem.Allocator,
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
    result: CachedResult,
) !void { ... }

pub fn lookupCachedImpostorResult(
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
) ?CachedResult { ... }

pub fn checkImpostorCommit(
    step: *const workflow.Step,
    list: *diagnostics.DiagnosticList,
) void { ... }

pub fn shaHasLegitimateCache(
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
) bool { ... }
```

### 2. 判定アルゴリズム D'-full（ADR D2）

prefetch 層が GraphQL + REST で到達可能性を決定し、結果を `setCachedImpostorResult` でキャッシュする。`checkImpostorCommit` は純粋に cache lookup + diagnostic emission。

```zig
pub fn checkImpostorCommit(step: *const workflow.Step, list: *diagnostics.DiagnosticList) void {
    if (!engine.impostorActive()) return;
    const action_ref = step.uses orelse return;
    if (action_ref.is_local or action_ref.is_docker) return;

    const owner = action_ref.owner orelse return;
    const repo = action_ref.repo orelse return;
    const ref = action_ref.ref orelse return;
    if (!isFullSha(ref)) return; // 40-char hex

    const cached = lookupCachedImpostorResult(owner, repo, ref) orelse return;
    if (cached.status != .impostor) return;

    const hint = buildFixHint(list.fixAllocator(), cached) catch "SHA not reachable from upstream; verify against known tags or default branch.";
    const msg = std.fmt.allocPrint(
        list.fixAllocator(),
        "'{s}/{s}@{s}' is not reachable from any branch or tag of the upstream repo (possible impostor commit)",
        .{ owner, repo, ref },
    ) catch return;
    list.append(.{
        .rule_id = "SC008",
        .severity = .warning,
        .message = msg,
        .span = step.span,
        .fix_hint = hint,
    }) catch return;
}
```

### 3. GraphQL クエリ拡張（`graphql.zig`）

既存 `tagNodes` に加えて `branchNodes` と `defaultBranchRef` を同 POST で取得する。

```graphql
r0: repository(owner:"actions", name:"checkout") {
  archived isArchived
  defaultBranchRef { name target { oid } }
  tagNodes: refs(refPrefix:"refs/tags/", first:100) {
    pageInfo { hasNextPage endCursor }
    nodes { name target { oid ... on Tag { target { oid } } } }
  }
  branchNodes: refs(refPrefix:"refs/heads/", first:100) {
    pageInfo { hasNextPage endCursor }
    nodes { name target { oid } }
  }
  # sha_xxxx ブロックは SC005 と同じ
}
```

`RepoInput` / `RepoResult` の拡張:

```zig
pub const RepoInput = struct {
    owner: []const u8,
    repo: []const u8,
    shas: []const []const u8,
    named_refs: []const []const u8 = &.{},
    needs_archived: bool = false,
    needs_tags: bool = false,
    needs_impostor: bool = false, // NEW
    tags_cursor: ?[]const u8 = null,     // NEW (per-repo continuation)
    branches_cursor: ?[]const u8 = null, // NEW
};

pub const RepoResult = struct {
    owner: []const u8,
    repo: []const u8,
    archived: ?bool = null,
    sha_results: []const ShaTagResult = &.{},
    named_results: []const NamedRefResult = &.{},
    missing: bool = false,
    tag_oids_complete: bool = true,
    // NEW
    branch_oids: []const NamedOid = &.{},
    branch_oids_complete: bool = true,
    default_branch: ?NamedOid = null,
    tag_oids: []const NamedOid = &.{}, // fix_hint 用に tag の name を保持
    tags_next_cursor: ?[]const u8 = null,
    branches_next_cursor: ?[]const u8 = null,
};
```

`max_repos_per_batch` を 30 → 20 に下げる（node 数約 2 倍のため GraphQL 500k node 上限に余裕を持たせる）。

### 4. prefetch 層の impostor 判定フェーズ（`prefetch.zig`）

`fetchImpostorCompares` を新設し、GraphQL バッチ完了後に以下を実行:

```
for each RepoResult:
  if not result.tag_oids_complete or not result.branch_oids_complete:
    mark all SHAs as unknown and continue
  for each sha in RepoInput.shas:
    if sha in tag_oids set:        # step1
      set legitimate; continue
    if sha in branch_oids set:     # step2
      set legitimate; continue
    if result.default_branch != null:
      status = compareRest(default_branch.name, sha)  # step3
      if status in {identical, behind}:
        set legitimate; continue
    # step4: 残る全 refs に対し compare 総当り
    legitimate = false
    for each ref_name in branches ∪ tags:
      status = compareRest(ref_name, sha)
      if status in {identical, behind}:
        legitimate = true; break
      if failed:
        mark unknown; break out outer
    if legitimate: set legitimate else: set impostor
```

`compareRest` は `https://api.github.com/repos/{owner}/{repo}/compare/{base}...{head}` を GET し、JSON 応答の `status` フィールド（`identical` / `behind` / `ahead` / `diverged`）を抽出する。404/403/429/タイムアウトは `unknown` 扱い（fail-closed）。

deadline 検査は各 SHA ループの頭 + 各 ref ループの頭で行う。

### 5. disk_cache v2 schema（`disk_cache.zig`）

```zig
pub const BranchEntry = struct { name: []const u8, oid: []const u8 };
pub const ImpostorEntry = struct {
    sha: []const u8,
    status_code: u8, // 'l' | 'i' | 'u'
};

pub const CachedRepo = struct {
    // 既存
    owner: []const u8,
    repo: []const u8,
    archived: ?bool,
    tags: []const TagEntry,
    named_refs: []const NamedRefEntry,
    // NEW (v2)
    branches: []const BranchEntry = &.{},
    impostor: []const ImpostorEntry = &.{},
    default_branch: ?BranchEntry = null,
    cache_format: u32 = 2,
};
```

JSON 書き込み時は常に `cache_format: 2`。読み込み時は `cache_format` フィールド不在 / `= 1` を v1 として扱い、新フィールドを空初期化する。次回 prefetch で v2 に昇格。

`ImpostorStatus` ↔ `status_code` の変換表:

| status_code | ImpostorStatus |
|---|---|
| `'l'` | `.legitimate` |
| `'i'` | `.impostor` |
| `'u'` | `.unknown` |

### 6. SC005 との重複抑制（`engine.postProcess`）

`src/rules/engine.zig` に新関数を追加:

```zig
pub fn postProcess(list: *diagnostics.DiagnosticList) void {
    // SC008 が発火した (owner, repo, sha) を抽出し、
    // 同一 SHA に対する SC005 info を drop する。
    // 実装簡便化のため、impostor.shaHasLegitimateCache の否定版
    // (= "SC008 impostor と確定した SHA か") で判定し、
    // SC005 の span/message から owner/repo/sha を逆引きする代わりに
    // 同一 step span を共有する SC005 を drop する。
}
```

実装簡便化として、SC008 と SC005 は同じ `step.span` を使うため `(span, sha)` ペアで照合する。SHA は SC005 メッセージ本文から抽出するか、あるいは impostor.zig 側に `(owner,repo,sha) → hit` のインデックスを持たせて参照する。

### 7. 公開 API 一覧（`src/lib.zig:78-109`）

```zig
pub const impostor = @import("rules/impostor.zig");

test {
    _ = @import("rules/impostor.zig");
    // ...
}
```

`src/main.zig` の初期化/終了シーケンスに:

```zig
rules.impostor.initImpostor(allocator);
defer rules.impostor.deinitImpostor(allocator);
// engine.run(...) の直後に
engine.postProcess(&list);
```

### 8. ルール登録（`src/rules/security.zig:1734`）

SC006 エントリの直後、BP007 の直前に挿入:

```zig
.{
    .id = "SC008",
    .name = "impostor-commit",
    .description = "SHA-pinned action ref is not reachable from any branch or tag of the upstream repo",
    .severity = .warning,
    .category = .dependency,
    .check_step = &impostor.checkImpostorCommit,
},
```

## 安全性評価

- **false positive リスク**: **低**。fail-closed（`unknown` 化）で、到達可能性判定に不確実性がある場合は診断抑制
- **false negative リスク**: **中**。deadline / rate limit / pagination 打ち切りで `unknown` 化した SHA は検出漏れ。warm cache 運用で緩和
- **rate limit 影響**: step1/step2 で大半が短絡するため実運用の REST コール数は少ない。ワーストケースは 100 branches × 100 tags で 1 SHA あたり最大 201 REST（ADR D5 Consequences 参照）
- **GraphQL node 上限**: branches + pageInfo 追加で node 数約 2 倍。`max_repos_per_batch` を 30 → 20 に下げて 500k node 上限に余裕を持たせる
- **token 無し**: `NoToken` エラーで全 SHA `unknown` → SC008 silent。REST-only フォールバックは follow-up
- **offline / quick mode**: `engine.impostorActive() = false` で check 関数が早期 return

## 実装差分

### 変更対象

- `src/rules/impostor.zig` — **新規作成**
- `src/rules/graphql.zig`
  - `RepoInput` / `RepoResult` 拡張（branches / defaultBranchRef / cursors / complete flags）
  - `buildQuery` に branches 節・defaultBranchRef 追加
  - `parseRepoObject` 拡張
  - `max_repos_per_batch` 30 → 20
  - テスト追加
- `src/rules/prefetch.zig`
  - `buildRepoInputs` で `needs_impostor` フラグ
  - `applyResults` で step1/step2 即時キャッシュ
  - `fetchImpostorCompares` / `compareRest` / `compareAllRefs` を新設
- `src/rules/disk_cache.zig`
  - `CachedRepo` に `branches` / `impostor` / `default_branch` / `cache_format` 追加
  - JSON round-trip / v1 legacy load テスト
- `src/rules/engine.zig`
  - `postProcess(&list)` 新設
  - `impostorActive()` アクセサ（`--offline` / `--quick` 連動）
- `src/rules/security.zig:1734`
  - `const impostor = @import("impostor.zig");` 追加
  - `security_rules` に SC008 エントリ追加
- `src/main.zig:525-526, 318, 343`
  - `initImpostor` / `deinitImpostor` 呼び出し
  - `engine.postProcess(&list)` を `engine.run()` 直後に挿入
- `src/lib.zig:44-104`
  - `rules.impostor` export
  - test import 追加

### 変更しないもの

- `build.zig`（`lib.zig` の `@import` で自動包含）
- `src/workflow/*`
- `src/fix/*`（autofix なし）
- SC005 本体（`stale_refs.zig`）— dedup は engine 層

## テスト設計

### ケース一覧

#### `impostor.zig` 単体

1. **C-1**: impostor status cache → SC008 warning 発火 + span / message 検証
2. **C-2**: legitimate status cache → 発火せず
3. **C-3**: unknown status cache → 発火せず
4. **C-4**: offline mode（`impostorActive() = false`）→ 発火せず
5. **C-5**: invalid SHA（not 40-char hex）→ 発火せず
6. **C-6**: local action / docker action → 発火せず

#### `graphql.zig`

7. `buildQuery`: `needs_impostor = true` 時に branches 節 + defaultBranchRef が出力される
8. `buildQuery`: `tags_cursor` が指定された場合 `after:"<cursor>"` が tagNodes に入る
9. `parseResponse`: `branchNodes.nodes` から `branch_oids` が抽出される
10. `parseResponse`: `pageInfo.hasNextPage=true` → `branch_oids_complete=false`
11. `parseResponse`: `defaultBranchRef` から `default_branch` が抽出される

#### `prefetch.zig`

12. `fetchImpostorCompares`: step1 tag OID 一致で即 legitimate（compare REST 呼ばれない）
13. step2 branch HEAD OID 一致で即 legitimate
14. step3 default branch compare `behind` → legitimate
15. step4 全 ref `ahead`/`diverged` → impostor
16. deadline 到達 → unknown
17. pagination 未完了（`branch_oids_complete=false`）→ 当該 repo の全 SHA を unknown

#### `disk_cache.zig`

18. v2 round-trip（`branches` / `impostor` / `default_branch` を保存・復元）
19. v1 legacy load（`cache_format` 不在のファイルを読んで新フィールド空初期化）
20. `status_code` `'l'`/`'i'`/`'u'` 相互変換

#### `engine.postProcess`

21. SC008 発火で同一 SHA の SC005 info が drop される
22. SC008 非発火時は SC005 が通常通り残る

### CI 必須 3 点

```bash
zig build && zig fmt --check src/ build.zig && zig build test --summary all
```

## 実装手順

1. **Tidy**（Step 1, 完了）: `graphql.zig` pagination を pageInfo ベースに切替
2. **Docs**（Step 2, 本 PR）: ADR 0008 + 本設計書 + `docs/rules.md` 46→47 更新
3. **Red**（Step 3）: `impostor.zig` スケルトン + C-1 の失敗テスト
4. **Green**（Step 4）: `checkImpostorCommit` 本体を mock cache で実装
5. **Green**（Step 5）: `graphql.zig` に branches / defaultBranchRef / cursors 追加、テスト 7-11
6. **Green**（Step 6）: `prefetch.zig` に impostor 判定フェーズ追加、テスト 12-17
7. **Green**（Step 7）: `disk_cache.zig` v2 schema、テスト 18-20
8. **Green**（Step 8）: SC008 登録 + `engine.postProcess` + `main.zig` 結線、テスト 21-22
9. **Refactor**（Step 9）: compare helpers が膨らんでいれば `impostor.zig` もしくは新 `compare.zig` に抽出

各コミット後に CI 3 点セット必須。

## 参考

- `docs/adr/0008-sc008-impostor-commit.md` — 判断の単一情報源
- `docs/design/sc007-typosquat-design.md` — 設計書構成テンプレート（兄弟 PR 群）
- `src/rules/stale_refs.zig` — SC005 実装（SC008 のテンプレ）
- `src/rules/graphql.zig` — GraphQL バッチ（SC008 で拡張）
- `src/rules/prefetch.zig` — prefetch オーケストレータ
- `src/rules/disk_cache.zig` — disk cache（v1→v2 migration 対象）
- `src/rules/engine.zig` — `postProcess` 追加先
- `src/rules/security.zig:1685-1742` — SC006 エントリの直後に SC008 を追加
- `src/diagnostics.zig` — `Diagnostic` / `DiagnosticList` API
- OpenSSF Scorecard `pinnedDependencies` check
- zizmor `impostor-commit` audit
- GitHub REST API `/repos/{owner}/{repo}/compare/{base}...{head}`
