# ネットワーク I/O ボトルネック最適化 設計書

## 1. 概要

`zghalint` は GitHub Actions ワークフローを静的解析するツールだが、次の
ルールはランタイムに GitHub API へ問い合わせる:

| ルール | 目的 | 旧実装の API |
|-------|------|-------------|
| SC003 | 既知脆弱性アクションの検出 (advisory) | `GET /advisories` |
| SC004 | アーカイブ済みリポジトリ参照の検出 | `GET /repos/{o}/{r}` |
| SC005 | SHA ピン止めがタグに対応するかの検証 | `GET /repos/{o}/{r}/git/matching-refs/tags/` ＋ 各 annotated tag に対して `GET /repos/{o}/{r}/git/tags/{sha}` |
| SC006 | ref が tag/branch 両方に存在するかの検証 | `GET /repos/{o}/{r}/git/ref/tags/{ref}` ＋ `GET /repos/{o}/{r}/git/ref/heads/{ref}` |

これらは step ごとに遅延実行されるため、ユニーク action が N 個あると最悪
`N + M` 回の HTTP 往復が発生する。各リクエストは TLS/TCP ハンドシェイクを
行うため、実測で 200ms 近くを占める。本設計はこの I/O ボトルネックを
3 層で解消する。

## 2. 技術選定

### 2.1 共有 HTTP クライアント

- `std.http.Client` は内部で connection pool を持つが、インスタンスごとの
  pool は独立している。旧実装は rule ごと・呼び出しごとに新規 Client を
  生成していたため、pool が効かなかった。
- プロセス単位で 1 つのシングルトンに統一することで、2 回目以降の
  リクエストは keep-alive で ~30ms（RTT のみ）に収まる。
- `std.Thread.Mutex` で POST/GET を直列化する。本設計では prefetch を
  シーケンシャルに走らせるので競合は起きないが、将来の並列化に耐えるため
  Mutex を残す。

### 2.2 GraphQL バッチ

- GitHub GraphQL API v4 は 1 回の POST で複数 repo の属性を取得できる。
  alias 名前空間 (`r0`, `r1`, ...) を使い、最大 30 repo までを一つの
  query にまとめる。30 は node-limit (500k) の安全マージンから決定した。
- Annotated tag は `... on Tag { target { oid } }` のインラインフラグ
  メントで 1 往復で dereference できるため、REST で必要だった逐次展開
  （64 件）が不要になる。
- GraphQL は `GITHUB_TOKEN` が必須。未認証の場合は REST 経路にフォール
  バックする（共有クライアントの恩恵は引き続き受ける）。
- Advisory API は GraphQL スキーマ上で公開されていないため、REST で
  一括取得する既存フローを維持する。

### 2.3 ETag ベース永続ディスクキャッシュ

- ローカル開発の反復実行で、2 回目以降を「ほぼ 0 I/O」にするために
  `$XDG_CACHE_HOME/zghalint/repos/<owner>_<repo>.json` に per-repo で
  結果を保存する。
- TTL は 24 時間。ETag による precheck は `GET /repos/{o}/{r}` の
  `If-None-Match` で行えるが、本 PR では **TTL ベースの簡易実装のみ**
  導入し、ETag precheck は後続の改善項目とする。
- `--no-cache` フラグでキャッシュ無視の強制再取得をサポート。
- 本 PR で採用したスキーマは以下の通り:
  ```json
  {
    "cached_at": 1713400000,
    "archived": true,
    "shas":  [["<sha>", "h"|"n"|"u"]],
    "named": [["<ref>", 0|1, 0|1]]
  }
  ```

## 3. モジュール構成

```
src/rules/
├── http_client.zig   # 共有 std.http.Client + Mutex + 共通ヘッダ
├── graphql.zig       # バッチ query builder / parser / POST driver
├── disk_cache.zig    # per-repo JSON キャッシュ（TTL 24h）
├── prefetch.zig      # オーケストレータ（disk → GraphQL → REST の 3 層）
├── advisory.zig      # SC003
├── archived.zig      # SC004
├── stale_refs.zig    # SC005
└── refconfusion.zig  # SC006
```

各 rule モジュールは以下の公開 API を持つ:

| API | 用途 |
|-----|------|
| `isActive() bool` | prefetch が fetch を issue すべきかの判定 |
| `setCached*(...)` | prefetch が結果を注入する入口 |
| `fetch*Pub(...)` | prefetch が直接 REST を叩くためのラッパ |
| `getArenaAllocator()` | prefetch が rule 寿命の allocator を借りるためのヘルパ |

## 4. 型定義

### 4.1 `http_client.zig`

```zig
pub fn init(allocator: Allocator) void;
pub fn deinit() void;
pub fn getAuthHeader(allocator: Allocator) ?[]const u8;
pub fn writeStandardHeaders(buf: []std.http.Header, auth: ?[]const u8) usize;
pub fn fetch(opts: std.http.Client.FetchOptions) FetchError!std.http.Client.FetchResult;

pub const FetchError = error{
    NotInitialized,
    FetchFailed,
    NetworkDeadlineExceeded,
};
```

### 4.2 `graphql.zig`

```zig
pub const GraphQlError = error{
    RequestFailed,
    ParseFailed,
    RateLimited,
    OutOfMemory,
    NoToken,
};

pub const RepoInput = struct {
    owner: []const u8,
    repo: []const u8,
    sha_refs: []const []const u8 = &.{},
    named_refs: []const []const u8 = &.{},
};

pub const RepoResult = struct {
    owner: []const u8,
    repo: []const u8,
    archived: ?bool = null,
    sha_results: []const ShaTagResult = &.{},
    named_results: []const NamedRefResult = &.{},
    missing: bool = false,
};

pub fn buildQuery(allocator: Allocator, repos: []const RepoInput) ![]const u8;
pub fn batchQuery(allocator: Allocator, repos: []const RepoInput) GraphQlError![]const RepoResult;
```

### 4.3 `disk_cache.zig`

```zig
pub const CachedRepo = struct {
    cached_at: i64 = 0,
    archived: ?bool = null,
    shas: []ShaEntry = &.{},
    named: []NamedEntry = &.{},
};

pub fn load(allocator, owner, repo) ?CachedRepo;
pub fn save(allocator, owner, repo, entry: CachedRepo) !void;
pub fn loadFromDir(dir: std.fs.Dir, allocator, owner, repo) ?CachedRepo;
pub fn saveToDir(dir: std.fs.Dir, allocator, owner, repo, entry: CachedRepo) !void;
pub fn isFresh(cached_at: i64) bool;
```

`load`/`save` resolve the cache directory from `XDG_CACHE_HOME` (or
`$HOME/.cache`) and delegate to the `*FromDir` / `*ToDir` variants. The
dir-taking variants exist so unit tests can drive persistence against
`std.testing.tmpDir` without touching the user's real cache.

`load` parses JSON into an internal arena and only copies the strings
it returns onto the caller's allocator, so passing a GPA is safe.

### 4.4 `prefetch.zig`

```zig
pub const Stats = struct {
    unique_repos: usize = 0,
    unique_sha_refs: usize = 0,
    unique_tag_or_branch_refs: usize = 0,
    cache_hits: usize = 0,
    cache_misses: usize = 0,
};

pub const Options = struct { no_cache: bool = false };

pub fn prefetchAll(allocator, workflows: []const Workflow) !Stats;
pub fn prefetchAllWithOptions(
    allocator,
    workflows: []const Workflow,
    opts: Options,
) !Stats;
```

## 5. データフロー

```
main.zig
  ├─ parseArgs
  ├─ loadConfig
  ├─ http_client.init
  ├─ advisory/archived/stale_refs/refconfusion.init*
  ├─ prefetchNetworkData
  │    ├─ 全 workflow を YAML → Workflow へ parse（捨て用 arena）
  │    └─ prefetchAllWithOptions
  │         ├─ advisory.prefetch()
  │         ├─ collectRefs → {repos, sha_refs, named_refs}
  │         ├─ applyDiskCache
  │         │    └─ repo ごとに disk_cache.load → applyCacheEntry で
  │         │       rule caches に注入し、満たされた ref を set から除去
  │         ├─ tryGraphQlBatch
  │         │    ├─ 残りの repos を max 30 件ずつ graphql.batchQuery
  │         │    ├─ applyResults(persist_dir=null) で rule caches に注入
  │         │    └─ persistRepoResult で disk_cache.save/saveToDir に保存
  │         └─ REST fallback
  │              ├─ fetchRepos / fetchShaRefs / fetchNamedRefs
  │              └─ 各 rule の setCached* を直接呼ぶ（ディスク保存はしない）
  ├─ for each file: parseWorkflow → engine.run（すでに caches は埋まっている）
  └─ output
```

### 層ごとの成否とフォールバック

| 経路 | 成功条件 | 失敗時 |
|------|---------|--------|
| Disk cache | `cached_at` が 24h 以内 | スキップして GraphQL/REST へ |
| GraphQL | `GITHUB_TOKEN` あり ＋ 200 OK | `NoToken`→REST、`RateLimited`→中断、他→REST |
| REST | 常時 | 個別の失敗は当該 step のみスキップ |

## 6. エラー型

- `http_client.FetchError`: 共有クライアント呼び出しの I/O 層エラー。
- `graphql.GraphQlError`: `NoToken` は token 不在、`RequestFailed` は
  HTTP 層失敗、`ParseFailed` は JSON 不整合、`RateLimited` は 403/429。
  prefetch はこれらを見て REST にフォールバックするか中断するかを決める。
- rule 本体（advisory/archived/stale_refs/refconfusion）は prefetch が
  失敗しても遅延 fetch 経路で復旧できる。

## 7. テスト戦略

### 7.1 単体テスト（ネットワーク不要）

- `http_client`: `writeStandardHeaders` の 2/3 要素分岐、未初期化時の
  `NotInitialized` エラー、`init`/`deinit` の冪等性と状態遷移。
- `graphql.buildQuery`: 空入力 / named refs / SHA refs / 複合ケース。
- `graphql.parseResponse`: archived + named、SHA 一致、annotated tag の
  内側 oid 一致、`missing=true`、`data:null`、`errors` のみ、100 件タグ
  ノードでページ上限フォールバック、非 bool `isArchived`、malformed JSON。
- `graphql.encodeRequestBody`: `"` / `\` / `\n` のエスケープ。
- `graphql.batchQuery`: 空入力の短絡。
- `disk_cache.isFresh`: 範囲内 / 期限切れ / 未来タイムスタンプ。
- `disk_cache.loadFromDir`/`saveToDir`: `std.testing.tmpDir` を使った
  ラウンドトリップ、欠損ファイル、TTL 外、malformed JSON、archived=null。
- `prefetch.collectRefs`: ユニーク化、local/docker スキップ、URL 不正な
  owner/repo の拒否。
- `prefetch.buildRepoInputs`: repo 単位での sha/named グルーピング、
  inactive ルールで対応スライスが空になること。
- `prefetch.applyCacheEntry`: ヒット時の rule cache 注入と set からの
  削除、inactive カテゴリのスキップ。
- `prefetch.applyResults`: `missing=true` のスキップ、`persist_dir`
  指定時の tmpDir への書き込み検証。
- `prefetch.prefetchAll`: offline 時 no-op。

### 7.2 CI 必須（CLAUDE.md より）

```
zig build && zig fmt --check src/ build.zig && zig build test --summary all
```

### 7.3 手動計測

- cold run: 空キャッシュ、token あり、20+ 件の action を含むプロジェクト
  → 旧実装比で 50-80% の短縮を目標。
- warm run: 24h 以内の再実行 → ネットワーク 0 I/O（Advisory は別 TTL）。
- token なし: REST フォールバック経路 → 旧実装比で 30-50% の短縮
  （keep-alive のみの効果）。
- rate limit: 403/429 を模擬した統合テストは未実装。`RateLimited` は
  prefetch が検知して以降の fetch を中断する設計にとどめる。

## 8. 今後のイテレーション

- **ETag precheck**: GraphQL 発行前に軽量な `GET /repos/{o}/{r}` を
  `If-None-Match` つきで送り、304 なら GraphQL を完全スキップする。
- **Advisory の GraphQL 化**: スキーマが公開されていないため、現状は
  REST 一括取得のみ。
- **統合計測の自動化**: `docs/design/network-io.md` に書いた目標値を CI
  で継続的に検証する仕組みは未導入。
- **stale_refs REST 経路の annotated tag 逐次展開**: token なしユーザー
  向けに 64 件の逐次 REST が残っている。GraphQL に寄せるのが難しい層
  では別の高速化（まとめ取り）が必要。

## 9. 非対象

- ファイルパース並列化: YAML パースは disk I/O 支配的ではない。
- 新規ルール追加。
- GitHub Enterprise Server のエンドポイント対応。

