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
- GitHub の二次レート制限は HTTP 200 + `errors[].type == "RATE_LIMITED"`
  で通知される（一次レート制限は 403/429 で返るので `http_client.fetch`
  層で検出可能）。`parseResponse` は body 内の `errors` 配列を走査し、
  `RATE_LIMITED` を見つけたら `error.RateLimited` を返して orchestrator に
  伝搬する。

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
├── rest_fallback.zig # GraphQL 不可時の単発 REST 呼び出し（SC004/005/006 共通）
├── prefetch.zig      # オーケストレータ（disk → GraphQL → REST の 3 層）
├── advisory.zig      # SC003
├── archived.zig      # SC004（fetch 実装は rest_fallback に委譲）
├── stale_refs.zig    # SC005（fetch 実装は rest_fallback に委譲）
└── refconfusion.zig  # SC006（fetch 実装は rest_fallback に委譲）
```

REST 個別実装は `rest_fallback.zig` に集約されており、SC004/005/006 の各
rule モジュールは結果を受け取りキャッシュに格納するロジックだけを持つ。

各 rule モジュールは以下の公開 API を持つ:

| API | 用途 |
|-----|------|
| `isActive() bool` | prefetch が fetch を issue すべきかの判定 |
| `setCached*(...)` | prefetch が結果を注入する入口 |
| `getArenaAllocator()` | prefetch が rule 寿命の allocator を借りるためのヘルパ |

prefetch から REST を直接叩く経路は `rest_fallback.fetch*` を使う。
旧設計の `fetch*Pub(...)` ブリッジは `rest_fallback` 抽出に伴い廃止した。

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

pub const FetchedError = FetchError || error{OutOfMemory};

pub const FetchedBody = struct {
    status: std.http.Status,
    body: []u8,
    allocator: Allocator,
    pub fn deinit(self: *FetchedBody) void;
};

pub fn fetchAuthenticatedJson(
    allocator: Allocator,
    url: []const u8,
) FetchedError!FetchedBody;
```

`fetchAuthenticatedJson` は URL 構築・allocating writer 確保・標準ヘッダ
組み立て・GitHub `Accept`/`Authorization` 付与・fetch 実行までの定型 8
ステップを 1 関数にまとめたもの。ステータスは生のまま `FetchedBody.status`
として返すので、`.ok` / `.not_found` / `.forbidden` / `.too_many_requests`
の意味付けは呼び出し側（`rest_fallback`）が担う。

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

### 4.4 `rest_fallback.zig`

GraphQL 経路が使えない場合（`GITHUB_TOKEN` 不在、二次レート制限、
HTTP 失敗など）に SC004/005/006 が必要な情報を REST で 1 件ずつ取得する
共通レイヤ。`http_client.fetchAuthenticatedJson` を使うので、TLS/TCP
セッションは共有クライアントで再利用される。

```zig
pub const RestError = http_client.FetchedError || error{
    HttpError,
    JsonParseError,
    UnexpectedFormat,
    MissingField,
};

pub const TagResolution = enum { has_tag, no_tag, unknown };
pub const RefStatus = enum { ambiguous, not_ambiguous, fetch_failed };

pub fn fetchArchiveStatus(
    allocator: Allocator,
    owner: []const u8,
    repo: []const u8,
) RestError!bool;

pub fn resolveTagForSha(
    allocator: Allocator,
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
) RestError!TagResolution;

pub fn queryRefStatus(
    allocator: Allocator,
    owner: []const u8,
    repo: []const u8,
    ref: []const u8,
) RefStatus;

pub fn resetRateLimit() void;
pub fn isRateLimited() bool;
```

`TagResolution` / `RefStatus` の正規定義はここに置き、`stale_refs.zig`
と `refconfusion.zig` は `pub const TagResolution = rest_fallback.TagResolution;`
の形で再エクスポートする。これにより `rest_fallback → stale_refs/refconfusion`
の循環 import を避けつつ、既存の呼び出し元が参照していた型名を保てる。

`queryRefStatus` 内のレート制限フラグ（`rate_limited`）は本モジュールが
所有する。`refconfusion.{init,deinit}` から `resetRateLimit()` を呼び、
`http_client.fetch` が 403/429 を返した時点で以降のリクエストを短絡する。

### 4.5 `prefetch.zig`

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
  │              │    └─ rest_fallback.fetchArchiveStatus /
  │              │       rest_fallback.resolveTagForSha /
  │              │       rest_fallback.queryRefStatus
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
- `http_client.FetchedError = FetchError || error{OutOfMemory}`:
  `fetchAuthenticatedJson` が body を allocator に書き出すため、I/O 層に
  `OutOfMemory` を加えたもの。
- `rest_fallback.RestError`: GraphQL を経由しない単発 REST 呼び出しの
  失敗集合。`http_client.FetchedError` を包含し、それに `HttpError`
  （非 200 ステータス）/ `JsonParseError` / `UnexpectedFormat` /
  `MissingField` を加えたもの。SC004/005/006 のルール本体は以前
  暗黙に同名のエラーを投げていたが、すべて `RestError` に統合された。
- `graphql.GraphQlError`: `NoToken` は token 不在、`RequestFailed` は
  HTTP 層失敗、`ParseFailed` は JSON 不整合、`RateLimited` は 403/429 の
  HTTP ステータス、もしくは body の `errors[].type == "RATE_LIMITED"`。
  prefetch はこれらを見て REST にフォールバックするか中断するかを決める。
- rule 本体（advisory/archived/stale_refs/refconfusion）は prefetch が
  失敗しても遅延 fetch 経路で復旧できる。

## 7. テスト戦略

### 7.1 単体テスト（ネットワーク不要）

- `http_client`: `writeStandardHeaders` の 2/3 要素分岐、未初期化時の
  `NotInitialized` エラー、`init`/`deinit` の冪等性と状態遷移、
  `getAuthHeader` の token 有無、expired deadline での短絡。
- `graphql.buildQuery`: 空入力 / named refs / SHA refs / 複合ケース。
- `graphql.parseResponse`: archived + named、SHA 一致、annotated tag の
  内側 oid 一致、`missing=true`、`data:null`、`errors` のみ、`errors[].type
  == "RATE_LIMITED"` で `error.RateLimited`（データ併存時も含む）、100 件
  タグノードでページ上限フォールバック、非 bool `isArchived`、malformed
  JSON。
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

