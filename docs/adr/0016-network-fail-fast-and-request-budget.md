# 0016. ネットワーク不達時の fail-fast とリクエスト予算

- Status: Proposed
- Date: 2026-09-10
- Deciders: issue #402（設計書 `docs/design/network-fail-fast-design.md`）

## Context

GitHub API に到達できない環境で 80 ファイルのコーパスをオンラインモードで
流すと、Zig 0.15.2 ビルドの 6.2 s が 0.16.0 ビルドでは 12.4 s になった。
成功経路は変わらない（23 リクエストを 1 接続で流す）。

0.15.2 は死んだ socket を再利用し続けたので、最初の `GET /advisories` が
~6 s で失敗した後の `POST /graphql` は `sendmsg` で即失敗していた。0.16 の
`std.http.Client` の connection pool は壊れた接続を検知して張り直すため、
`POST /graphql` がもう一度 ~6 s 待つ。残りの REST フォールバックは 10 s の
全体予算（`engine.network_deadline_ns`）で止まるが、その予算は**リクエストの
合間にしか**見ていない。

つまり zghalint 側には次の 2 つの穴があり、std の挙動が変わって露出した。

1. 「前のリクエストで網が死んでいた」という記憶が無い。
2. 1 リクエストの待ち時間に上限が無い。

## Decisions

### D1. トランスポート失敗を 1 回で確定し、以後の全リクエストを短絡する

`http_client.fetch` が `std.http.Client.FetchError` を分類し、接続・名前
解決・TLS・送受信の失敗を `error.NetworkUnreachable` として返す。同時に
sticky なフラグを立て、以後の `fetch` は接続を試みずに同じエラーを返す。

「2 回失敗したら」にしない。issue の環境では 2 本目の `POST /graphql` を
まるごと払うことになり、倍増がそのまま残る。誤判定のコストは「今回の実行で
ネットワークルールが黙る」だけで、それは既存の `net_status` の注記で利用者に
伝わる。

### D2. フラグは `http_client` に置く

issue の文面は「`prefetch.zig` に記録する」だが、prefetch の後に走る遅延
fetch（archived / stale_refs / refconfusion）が取りこぼされる。GraphQL・REST・
advisory・遅延 fetch の全経路が `http_client.fetch` を通るので、そこに
置けば呼び出し側は変更なしで短絡される。寿命は `rest_fallback.rate_limited`
と同じで、`init` / `deinit` で戻す。

### D3. keep-alive の失効だけは sticky にしない

`std.http.Client` は pool の接続がサーバ側で閉じられていても再送しない
（`HttpConnectionClosing` は「keep-alive 接続がついに閉じられた」ケースだと
std 自身が注記している）。直前のリクエストが成功していて、失敗の形が
`HttpConnectionClosing` / `HttpRequestTruncated` なら、その 1 回だけは
`FetchFailed`（sticky でない）に倒し、次の `fetch` が張り直す。2 回連続なら
直前が失敗なので sticky に倒れる。

同じ理由で `WriteFailed` は `BoundedBody` の上限超過と区別する。上限超過は
網の失敗ではないので `FetchFailed` にし、フラグも立てない。

### D4. リクエスト予算はタスクのキャンセルで実現する

Zig 0.16 の std には使える timeout が無い。`ConnectTcpOptions.timeout` は
`Client` が捨てており、`Io.Threaded` は `timeout != .none` で panic する。
受信 timeout は存在しない。`SO_RCVTIMEO` を自前で立てると `EAGAIN` が
`errnoBug` に落ちる。

動くのは `Future.cancel` だけである。`Io.Threaded` はブロック中の syscall を
`pthread_kill(thread, .IO)` で `EINTR` させ、`netReadPosix` / `posixConnect`
が `error.Canceled` を返す。そこで fetch を `Io.concurrent` のタスクに載せ、
呼び出し側は `Io.Event.waitTimeout` で「完了か予算切れの早い方」を待ち、
予算切れなら `Future.cancel` する。

応答しないローカルサーバに対するプロトタイプで、予算ちょうどで `fetch` が
`ReadFailed` を返すこと、即応答する接続先は予算を待たないこと、打ち切った
後も同じクライアントを再利用できることを確認した。

`Io.concurrent` が使えない `Io` 実装では従来どおり予算なしで待つ。

### D5. 予算は「全体の残り」と「1 本の上限 5 s」の小さい方

`engine.requestBudget()` が `network_deadline_ns` の残りと上限 5 s の小さい方
を `std.Io.Timeout` で返す。全体予算が無いなら `.none`。

上限 5 s の根拠: 成功経路は 23 リクエストを 1 接続で流し切っており、1 本が
5 s を超えるのは GraphQL の 100 件バッチでも見ていない。全体予算 10 s の
半分にしておけば、初回接続（DNS + TCP + TLS + CONNECT）が遅い環境でも 1 本目を
切らずに済む。CLI からの調整は入れない。

予算切れは D1 のトランスポート失敗として扱う。「遅いが生きている API」と
「死んでいる API」は 10 s の中では区別する価値がなく、どちらでも残りの
リクエストは間に合わない。

### D6. GraphQL がトランスポート失敗なら REST フォールバックへ進まない

`tryGraphQlBatch` は `RequestFailed` を「GraphQL を使わなかった」として REST に
落とすが、不達フラグが立っているなら「使った」と返して REST の 3 ループを
飛ばす。D2 により REST 側の `fetch` は即座に失敗するので結果は変わらないが、
ログとキャッシュ書き込みの無駄を省く。

### D7. 報告は変えない

`net_status` はルール単位の bit を既に持ち、不達なら「skipped (github api
unreachable; check HTTPS_PROXY / SSL_CERT_FILE)」と出る。fail-fast で早く
諦めても bit の立ち方は同じなので、新しい注記は足さない。

### D8. std の proxy トンネル不具合は別 issue

`std.http.Client.connectProxied` は CONNECT 後のトンネル接続を
`proxy.protocol` で作るため、https 先に平文 HTTP を流す。HTTPS_PROXY 環境
（#336）でリクエストが一度も成功しない原因だが zghalint 側では直せない。本
設計が入っても HTTPS_PROXY 環境は「1 本目を 5 s 待って諦める」動作になる。
upstream への報告と、zghalint 側で `connectProxied` 相当を持つかは別 issue で
扱う。

## Consequences

- API 不達時の所要時間は「1 本目の予算（最大 5 s）+ lint 本体」になり、
  0.15.2 の 6.2 s を下回る見込み。2 本目以降は接続を試みない。
- `http_client.FetchError` に `NetworkUnreachable` が増え、
  `graphql.GraphQlError` もこれを通す。呼び出し側の `catch` は網羅 switch
  でなければ変更不要。
- `std.http.Client.FetchError` のメンバーが増減すると `classify` の `switch`
  が網羅性エラーで気付かせる。列挙し忘れは `FetchFailed`（短絡しない）に
  倒れる。
- 1 リクエストあたり `Io.concurrent` のスレッド生成が乗る。TLS 往復に比べて
  無視できるが、`scripts/bench.py --perf` で成功経路が変わらないことを確認
  する。
- 未決: DNS が黒穴になる環境でのキャンセルの実測、上限 5 s の妥当性。
  実コーパスで 1 本目が 5 s を超える例が出たら見直す。
