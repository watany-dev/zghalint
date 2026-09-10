# ネットワーク不達時の fail-fast とリクエスト予算 設計書

## 目的

GitHub API に到達できない環境でオンラインモードを走らせたとき、Zig 0.16 への
移行で所要時間が 2 倍になった（80 ファイルのコーパスで 6.2 s → 12.4 s、
issue #402）。原因は zghalint 側の設計の穴が std の挙動変更で露出したもので、
次の 2 つを埋める。

1. **fail-fast**: 最初のトランスポート失敗を覚え、残りの GraphQL バッチ・REST
   フォールバック・遅延 fetch を全て短絡する。
2. **リクエスト予算**: 1 リクエストの待ち時間を「全体の残り予算」から導いた
   上限で打ち切る。

本設計書の判断は `docs/adr/0016-network-fail-fast-and-request-budget.md`
を単一情報源とする。行番号は本ドキュメント記述時点（commit `d9078e8`）の
もの。

## スコープ

- `src/rules/http_client.zig` の `fetch` / `fetchAuthenticatedJson` を通る
  全リクエスト（SC003〜SC006、SC008 の prefetch と遅延 fetch）
- `std.http.Client.FetchError` の分類（トランスポート失敗 vs それ以外）
- `engine.network_deadline_ns` からリクエスト単位の予算を導く仕組み
- 不達判定後の `prefetch.zig` の短絡
- ネットワーク不要の単体テスト（ローカルの応答しないサーバを含む）

## 非スコープ

- `std.http.Client.connectProxied` が CONNECT 後のトンネルへ平文 HTTP を
  流す std 側の不具合（issue #402 の付記）。HTTPS_PROXY 環境（#336）で
  リクエストが一度も成功しない原因だが、zghalint 側では直せない。別 issue で
  upstream への報告とワークアラウンドの要否を扱う。
- 全体予算 10 s の値そのものの見直し。
- 並列 prefetch。`client_mutex` による直列化は維持する。
- `--quick` / `--offline` の挙動。

## 現状整理

| 既存資産 | 位置 | 備考 |
|---|---|---|
| 全体予算 | `src/rules/engine.zig:172-188` | `network_deadline_ns` を `setNetworkDeadline(10 s)` で設定。`isNetworkDeadlineExceeded()` を**リクエストの合間にだけ**見る |
| 予算の設定 | `src/main.zig:772` | prefetch の前に 10 s。`defer clearNetworkDeadline()` |
| 共有クライアント | `src/rules/http_client.zig:164-175` | `fetch` は deadline 超過を先に見て、std の全エラーを `error.FetchFailed` に潰す |
| body 上限 | `src/rules/http_client.zig` `BoundedBody` | 上限超過で writer が `error.WriteFailed` を返す。std の `fetch` はこれも `WriteFailed` で返すので送信失敗と区別できない |
| GraphQL バッチ | `src/rules/graphql.zig:148-192` | `http_client.fetch` の失敗は一律 `error.RequestFailed` |
| prefetch の短絡 | `src/rules/prefetch.zig:495,681,715,734` | 各ループの先頭で `isNetworkDeadlineExceeded()`。GraphQL が `RequestFailed` なら `used_graphql=false` として **REST フォールバックへ進む** |
| REST の sticky フラグ | `src/rules/rest_fallback.zig:40-43,246,331` | `rate_limited` を 403/429 で立て、以後の `queryRefStatus` を `.fetch_failed` にする。今回のフラグの前例 |
| 遅延 fetch | `archived.zig:96` / `stale_refs.zig:84` / `refconfusion.zig:73` | prefetch で埋まらなかった ref を lint 中に個別取得 |
| 不達の報告 | `src/rules/net_status.zig`, `src/main.zig:406` | ルール単位の bit を stderr の注記にまとめる（#304 / #372） |

### 失敗時の時系列（80 ファイル、API 不達）

```
0.15.2 (6.2 s)                        0.16.0 (12.4 s)
─────────────────────────────         ─────────────────────────────────────
GET /advisories  ~6 s → 失敗          GET /advisories  ~6 s → 失敗
POST /graphql   壊れた socket で      pool が壊れた接続を検知して再接続
                sendmsg 即失敗        POST /graphql   ~6 s → 失敗（新 socket + CONNECT）
REST fallback   deadline 超過で短絡    REST fallback   deadline 超過で短絡
```

0.15.2 では死んだ socket を再利用し続けたので 2 本目以降が即失敗していた。
0.16 の connection pool は壊れた接続を捨てて張り直すため、hang する接続先には
**リクエストごとに** 待ち時間を払う。zghalint 側に「前のリクエストで網が
死んでいた」という記憶が無く、しかも 1 リクエストの待ち時間に上限が無い、
という 2 つの穴が同時に露出した。

## 設計方針

### 1. `http_client.fetch` が std のエラーを分類する

`error.FetchFailed` 一本にしていたのをやめ、トランスポート失敗を分ける。
分類は `http_client` の中で閉じる。呼び出し側（graphql / rest_fallback /
advisory）は std のエラー集合を知らないままでよい。

```zig
// src/rules/http_client.zig
pub const FetchError = error{
    NotInitialized,
    /// URI・ヘッダ・リダイレクト・圧縮など、網は生きているが要求が通らない失敗。
    FetchFailed,
    /// 接続・TLS・送受信の失敗。同一プロセス内では回復を期待しない。
    NetworkUnreachable,
    NetworkDeadlineExceeded,
};

fn classify(err: std.http.Client.FetchError) FetchError {
    return switch (err) {
        // HostName.LookupError: 名前解決の失敗は同じプロセス内で直らない
        error.UnknownHostName,
        error.NameServerFailure,
        error.NoAddressReturned,
        error.ResolvConfParseFailed,
        error.DetectingNetworkConfigurationFailed,
        // IpAddress.ConnectError
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.HostUnreachable,
        error.NetworkUnreachable,
        error.NetworkDown,
        error.AddressUnavailable,
        error.Timeout,
        // ConnectTcpError
        error.TlsInitializationFailed,
        // 送受信。キャンセルされた readv / connect は ReadFailed / Canceled で返る（§3）
        error.ReadFailed,
        error.WriteFailed,
        error.Canceled,
        error.HttpConnectionClosing,
        error.HttpRequestTruncated,
        => error.NetworkUnreachable,
        else => error.FetchFailed,
    };
}
```

`WriteFailed` は `BoundedBody` の上限超過でも返るので、`fetch` は呼び出し側
から渡された `response_writer` の状態を見る必要がある。`fetchAuthenticatedJson`
は自前の `BoundedBody` を持つので `body_sink.overflowed` を先に見て
`FetchFailed` に倒す。`fetch` を直接呼ぶ `graphql.batchQuery` も同じ
`BoundedBody` を使うので、`http_client` に `fetchBounded(opts, sink)` を
足して分岐を一箇所に寄せる。

```zig
pub fn fetchBounded(opts: std.http.Client.FetchOptions, sink: *BoundedBody) FetchError!std.http.Client.FetchResult {
    const result = fetchRaw(opts) catch |err| {
        if (sink.overflowed) return error.FetchFailed; // 網の失敗ではない
        return recordFailure(classify(err));
    };
    return result;
}
```

正確なエラー集合は `std.http.Client.FetchError` の定義
（`Uri.ParseError || RequestError || Request.ReceiveHeadError || {StreamTooLong, WriteFailed, UnsupportedCompressionMethod}`）
から `switch` で網羅する。列挙し忘れは `else => FetchFailed` に落ちるので
安全側（短絡しない）に倒れる。

### 2. sticky な不達フラグは `http_client` に置く

```zig
// src/rules/http_client.zig
var network_unreachable: bool = false;

/// init / deinit で必ず戻す。rest_fallback.rate_limited と同じ寿命。
pub fn resetNetworkState() void { network_unreachable = false; }
pub fn isNetworkUnreachable() bool { return network_unreachable; }

fn recordFailure(err: FetchError) FetchError {
    if (err == error.NetworkUnreachable) network_unreachable = true;
    return err;
}

pub fn fetch(opts: std.http.Client.FetchOptions) FetchError!std.http.Client.FetchResult {
    if (network_unreachable) return error.NetworkUnreachable;
    if (engine.isNetworkDeadlineExceeded()) return error.NetworkDeadlineExceeded;
    ...
}
```

`rest_fallback.rate_limited` と違い、GraphQL・REST・advisory・遅延 fetch の
全経路が `http_client.fetch` を通るので、ここに置けば呼び出し側は何も
しなくても短絡される。`prefetch` 側で覚える案（issue の (1) の文面）は
遅延 fetch を取りこぼす。

**1 回の失敗で確定させる。** 「2 回失敗したら」にすると、issue の環境では
2 本目の `POST /graphql` をまるごと払うことになり、倍増がそのまま残る。
誤判定のコストは「今回の実行でネットワークルールが黙る」だけで、それは
`net_status` の注記で利用者に伝わる（§6）。

例外は **keep-alive の失効** だけ。`std.http.Client` は pool の接続が
サーバ側で閉じられていても再送しない（`HttpConnectionClosing` は「keep-alive
接続がついに閉じられた」と std 自身が注記している）。直前のリクエストが
成功していて、失敗の形が `HttpConnectionClosing` / `HttpRequestTruncated`
なら、網が死んだのではなく接続が古かっただけの可能性が高い。この 1 回だけは
`FetchFailed`（sticky でない）に倒し、呼び出し側の次の `fetch` が張り直す。

```zig
var last_fetch_succeeded: bool = false;

fn isStaleKeepAlive(err: std.http.Client.FetchError) bool {
    return last_fetch_succeeded and switch (err) {
        error.HttpConnectionClosing, error.HttpRequestTruncated => true,
        else => false,
    };
}
```

prefetch のリクエストは連続して発行されるので失効の窓は小さく、
2 回連続で同じ形なら `last_fetch_succeeded == false` になっていて sticky に
倒れる。

### 3. リクエスト予算はタスクのキャンセルで実現する

Zig 0.16 の std には使える timeout が無い。

| 候補 | 状態 |
|---|---|
| `ConnectTcpOptions.timeout` | `Client.connectTcpOptions` が `host.connect` に渡していない。渡しても `Io.Threaded.netConnectIpPosix` は `timeout != .none` で `@panic("TODO ...")` |
| 受信 timeout | `Io.Threaded` に無い。`SO_RCVTIMEO` を自前で立てると `EAGAIN` が `errnoBug` に落ちる |
| `Future.cancel` | `Io.Threaded` は `pthread_kill(thread, .IO)` でブロック中の syscall を `EINTR` させ、`netReadPosix` / `posixConnect` が `checkCancel` で `error.Canceled` を返す。`http.Client` の `Stream.Reader` はこれを `ReadFailed` にして接続を `closing` にする |

キャンセルだけが動く。fetch を `Io.concurrent` のタスクに載せ、呼び出し側は
`Io.Event.waitTimeout` で「完了か予算切れの早い方」を待ち、予算切れなら
`Future.cancel` で打ち切る。

```zig
// src/rules/http_client.zig
const Slot = struct {
    opts: std.http.Client.FetchOptions,
    done: std.Io.Event = .unset,
    result: std.http.Client.FetchError!std.http.Client.FetchResult = undefined,
};

fn runFetch(io: std.Io, slot: *Slot) void {
    slot.result = client_storage.fetch(slot.opts);
    slot.done.set(io);
}

fn fetchWithBudget(opts: std.http.Client.FetchOptions, budget: std.Io.Timeout) std.http.Client.FetchError!std.http.Client.FetchResult {
    const io = runtime.io();
    var slot: Slot = .{ .opts = opts };
    var fut = io.concurrent(runFetch, .{ io, &slot }) catch {
        // 並行実行が使えない Io 実装。従来どおり予算なしで待つ。
        return client_storage.fetch(opts);
    };
    const deadline = budget.toDeadline(io);
    while (!slot.done.isSet()) {
        slot.done.waitTimeout(io, deadline) catch |err| switch (err) {
            error.Timeout => if (deadline.toDurationFromNow(io).?.raw.nanoseconds <= 0) {
                fut.cancel(io); // ブロック中の readv / connect を SIGIO で起こす
                return error.Timeout; // → classify で NetworkUnreachable
            },
            error.Canceled => unreachable, // 呼び出し側はタスクではない
        };
    }
    fut.await(io);
    return slot.result;
}
```

`Future.cancel` / `await` は「スレッド安全でない」と std が明記しているので、
呼ぶのは呼び出し側スレッドに限る。タスク側は `Event.set` だけを触る。
`client_mutex` は今までどおり呼び出し側が `lockUncancelable` で持つ
（`std.Io.Mutex` は所有者を持たないので、タスクで `fetch` を走らせても
ロックの持ち主は変わらない）。

スクラッチパッドのプロトタイプで、accept 後に応答しないローカルサーバに
対して次を確認した（Linux、`Io.Threaded`）:

- 予算 1000 ms / 300 ms で `fetch` がちょうどその時間で `ReadFailed` を返す。
- 即座に拒否される接続先（`127.0.0.1:1`）は予算を待たずに 1 ms で返る。
- 打ち切った後も同じ `std.http.Client` で次のリクエストが張れる。

`posixConnect` にも `INTR → checkCancel` があるので、SYN が黒穴に落ちる
接続待ちも同じ経路で打ち切れる。DNS 解決（`netLookupFallible`）は
`Io.Queue` 経由でキャンセル点を持つが、実測はしていない（§未決事項）。

### 4. 予算の導き方

```zig
// src/rules/engine.zig
/// 1 リクエストに許す上限。全体予算の残りがこれより短ければ残りを使う。
pub const request_budget_cap_ns: i128 = 5 * std.time.ns_per_s;

pub fn requestBudget() std.Io.Timeout {
    const deadline = network_deadline_ns orelse return .none;
    const now = std.Io.Clock.awake.now(runtime.io()).nanoseconds;
    const remaining = deadline - now;
    if (remaining <= 0) return .{ .duration = .{ .raw = .fromNanoseconds(0), .clock = .awake } };
    return .{ .duration = .{ .raw = .fromNanoseconds(@intCast(@min(remaining, request_budget_cap_ns))), .clock = .awake } };
}
```

- 上限 5 s の根拠: 成功経路は 23 リクエストを 1 本の接続で流し切っており、
  1 本が 5 s を超えるのは GraphQL の 100 件バッチでも見ていない。全体予算
  10 s の半分にしておけば、初回接続（DNS + TCP + TLS + CONNECT）が遅い
  環境でも 1 本目を切らずに済む。
- 全体予算が無い（テストや将来のライブラリ利用で `network_deadline_ns ==
  null`）なら `.none` で今までどおり無制限。
- 予算切れ（`Timeout`）は §1 で `NetworkUnreachable` に分類し、sticky
  フラグを立てる。「遅いが生きている API」と「死んでいる API」は 10 s の
  予算の中では区別する価値がなく、どちらでも残りのリクエストは間に合わない。

### 5. prefetch と遅延 fetch への伝播

`http_client.fetch` が短絡するので、原理的には呼び出し側の変更は要らない。
それでも `prefetch.zig` には 2 箇所手を入れる。

1. `tryGraphQlBatch` が `RequestFailed` を受けたとき、`http_client
   .isNetworkUnreachable()` なら `true`（= GraphQL を使った）を返して REST
   フォールバックへ進まない。今は `false` を返すので REST の 3 ループが
   それぞれ `fetch` を呼んで即座に `NetworkUnreachable` を貰う。無害だが
   ログとキャッシュ書き込みの無駄になる。
2. 3 つの REST ループの先頭にある `isNetworkDeadlineExceeded()` の隣に
   `isNetworkUnreachable()` を並べる。`graphql.GraphQlError` には
   `NetworkUnreachable` を足し、`batchQuery` は `http_client` のエラーを
   そのまま通す。

遅延 fetch（archived / stale_refs / refconfusion）は変更しない。
`rest_fallback` の各関数が `http_client` から `NetworkUnreachable` を貰って
`.unknown` / `.fetch_failed` に倒し、それぞれの rule が `net_status
.markUnavailable` を呼ぶ既存の経路で足りる。

### 6. 報告

新しい注記は足さない。`net_status` はルール単位の bit を既に持ち、不達なら
「SC003, SC004, ... skipped (github api unreachable; check HTTPS_PROXY /
SSL_CERT_FILE)」と出る。fail-fast で早く諦めても bit の立ち方は同じ。

`--verbose` 相当の出力は無いので、どのリクエストで諦めたかは stderr に
出さない。デバッグ用途は `ZGHALINT_DEBUG_NET=1` のような環境変数に寄せる
案があるが、issue の範囲外。

## テスト戦略

### 単体テスト（ネットワーク不要）

- `http_client.classify`: `std.http.Client.FetchError` の各メンバーに対する
  分類。`inline for` で全メンバーを回し、`NetworkUnreachable` に落ちる集合を
  明示の表と突き合わせる（std のエラー集合が増減したときに `switch` の
  網羅性エラーで気付く）。
- `http_client.fetch`: `network_unreachable` を立てた状態で
  `NetworkUnreachable` を返し、`init` / `deinit` / `resetNetworkState` で
  戻ること。既存の `network_deadline_ns = now - 1` のパターンに揃える。
- `http_client.fetchBounded`: `BoundedBody` が溢れた `WriteFailed` は
  `FetchFailed` になり、フラグが立たないこと。
- `engine.requestBudget`: deadline 無し → `.none`、残り 8 s → 5 s、残り
  2 s → 2 s、超過 → 0。
- `prefetch.tryGraphQlBatch`: 不達フラグが立っている状態で REST に落ちず
  `true` を返すこと。

### ローカルサーバを使う結合テスト

`std.Io.net.IpAddress.listen` で `127.0.0.1:0` を開き、accept だけして
応答しないサーバをテスト内に立てる。

- 予算 200 ms で `fetch` が 200 ms 前後で `NetworkUnreachable` を返す
  （経過時間は 150 ms〜1 s の範囲で検査。CI の負荷でぶれるので上限は緩く）。
- 続けて同じ URL を `fetch` すると **接続せずに** 即 `NetworkUnreachable`
  （経過時間 < 50 ms）。fail-fast の本体。
- `std.testing.io` は `Io.Threaded` で signal handler を持つので、
  キャンセルの経路はテストでも本番と同じ。

### E2E / ベンチ

- `bench/` のコーパス 80 ファイルで issue の再現手順を回し、不達時に
  「1 本目の予算 (5 s) + α」で終わることを手動で確認する。目標は 0.15.2 の
  6.2 s を下回ること。
- 成功経路の所要時間とリクエスト数（23 本、1 接続）が変わらないことを
  `scripts/bench.py --perf` で確認する。`Io.concurrent` のスレッド生成が
  1 リクエストあたりに乗るが、TLS 往復に比べて無視できる。

### CI 必須

```
zig build && zig fmt --check src/ build.zig && zig build test --summary all
```

## 未決事項

- **DNS 解決のキャンセル**: `netLookupFallible` は `Io.Queue` を通すので
  キャンセル点はあるはずだが、`getaddrinfo` 内でブロックしている間に
  SIGIO が届いたときの挙動は未確認。DNS が黒穴になる環境（`UnknownHostName`
  が即返る環境ではない）で実測してから、上限 5 s に DNS を含めるかを決める。
- **上限 5 s の値**: `--network-timeout` のような CLI からの調整は入れない
  前提。実コーパスで 1 本目が 5 s を超えるケースが出たら見直す。
- **`WriteFailed` の曖昧さ**: std に「body が書けなかった」と「送信に失敗した」
  を分ける TODO があるので、直ったら `overflowed` の分岐は消せる。
- **std の proxy トンネル不具合**: 非スコープだが、HTTPS_PROXY 環境では
  本設計が入っても「毎回 5 s 待って諦める」動作になる。upstream 修正か
  zghalint 側の `connectProxied` 相当の実装かは別 issue で判断する。

## 関連

- issue #402、#336（HTTPS_PROXY）、#304 / #372（不達の報告）
- `docs/design/network-io.md` §6 エラー型・§8 今後のイテレーション
- `docs/adr/0016-network-fail-fast-and-request-budget.md`
