# SC001 イメージ digest ピン止め 設計書

## 目的

SC001 の warning に、`--fix` 時だけレジストリから取った digest への rewrite を
付ける。判断の単一情報源は `docs/adr/0017-sc001-image-digest-pin.md`。本書は
実装の配置と手順である。

## スコープ

- Docker Hub と GHCR のタグ参照を `image@sha256:<digest>` にする safe fix
- `container` / `services` / `uses: docker://` の 3 経路
- `--fix` / `--fix-unsafe` 指定時のみネットワーク。通常 lint は不変

## 非スコープ

- 上記以外のレジストリ、private イメージ、ワークフロー内 `credentials:`
- platform 固有 digest
- `net_status` への SC001
- `--perf --fix` への登録（ADR 0017 D4）

## 現状

`checkUnpinnedImages` と `checkHardcodedContainerCredentials` 内の docker
`uses:` 走査が SC001 を出す。`isImagePinned` は `@sha256:` の有無だけを見る。
`container.image` / `services.*.image` は値 span が無く、診断は job span に
落ちている。`docker://` は `uses_value_span` がある。

SEC001 の先例は `src/rules/sha_pin.zig`。`--fix` のときだけ store を起動し、
ミスは「fix なし」であって「タグが無い」証拠ではない。

## 1. イメージ参照の正規化（fetch 用）

YAML に書かれた文字列から `docker://` を落とし、次に分ける。

- 既に `@sha256:` がある → 対象外（現状どおり診断も出ない）
- `${{` を含む → fetch しない（値が一意でない）
- host が `ghcr.io` → GHCR
- host が空 / `docker.io` / `index.docker.io` / `registry-1.docker.io` → Docker Hub。
  パスが 1 成分なら `library/` を前置
- それ以外 → fix なし

タグが無ければ `latest`。元の綴りは rewrite 側が保持する。

## 2. レジストリ I/O

`http_client.fetchBounded` を使う。外部 SDK は足さない。GitHub の 10s
全体予算（`engine.network_deadline_ns`）はレジストリフェーズの前に閉じる。
1 リクエストの打ち切りは `fetchBounded` の per-request budget に任せる。

Accept は OCI index / Docker manifest list / 単体マニフェストをこの順で出す。
digest は **デコード後の** 応答ボディの SHA-256（小文字 hex）。gzip された
転送バイトをハッシュするとタグが指す digest と一致しない。

Docker Hub:

1. `GET https://auth.docker.io/token?service=registry.docker.io&scope=repository:<name>:pull`
2. `GET https://registry-1.docker.io/v2/<name>/manifests/<tag>`
   `Authorization: Bearer <token>` は `privileged_headers`

GHCR:

1. `GET https://ghcr.io/v2/<name>/manifests/<tag>`（匿名）
2. 401 なら同じ URL を `GITHUB_TOKEN` の Bearer で 1 回だけ再試行

4xx / 空ボディ / ホスト到達失敗は、そのイメージの miss。ADR 0016 の
`NetworkUnreachable` は立てない。同じホストの次のイメージはまだ試す。
レートリミット（429）だけは、そのホストの残りを打ち切る。

通常 lint からは呼ばない。`--fix` かつ not `--quick` のとき、lint 前に
ユニークな未ピン参照を集めて store を埋める（sha_pin と同じ「wanted」）。
lint 中の miss で追加 fetch はしない——遅延 fetch を lint 壁時間に戻さない。

## 3. キャッシュ

`$XDG_CACHE_HOME/zghalint/images/<host>_<name>_<tag>.json`。TTL 24h。
スキーマは `{ "cached_at": <epoch>, "digest": "sha256:<hex>" }`。
`cache_dir.open` と `writeFileAtomic` を流用する。GitHub の repo キャッシュ
ファイルとは混ぜない。

テストは `sha_pin` と同様、プロセス内 store へ digest を直接入れる。
HTTP は `http_client` のローカルサーバテストに寄せ、e2e はネットワークを
踏まない。

## 4. rewrite

`image_meta`（または `uses_value_*`）の style が `.plain` / quoted のときだけ。
`.literal` / `.folded` は null。値が行末でなければ trailing comment は付けない。

置換範囲はタグ（`:` 以降）。タグが無ければイメージ参照の末尾に `@sha256:…` を
挿入する（`alpine` → `alpine@sha256:…`）。`docker://` プレフィックスは残す。

`Fix.safety` は `.safe`。同じタグが当時指していた digest へ固定するだけで、
fix 時点の実行内容は変わらない。description に「この digest は取得時点の
タグ内容である」と書く。

## 実装配置

- `src/workflow/types.zig` / `parser.zig` — `Container.image_meta` /
  `Service.image_meta`
- `src/rules/image_digest.zig` — 参照の分解、store、rewrite。`sha_pin.zig`
  と同じ「ルールが orchestrator を import しない」位置
- `src/rules/security.zig` — SC001 が store を見て fix を付ける。診断 span を
  値 span へ寄せる
- `src/rules/http_client.zig` — レジストリ用の Accept / 匿名 fetch。GitHub
  JSON ヘッダをレジストリへ流さない
- prefetch 相当の収集は `engine` / `main` の `--fix` 経路から
  `image_digest` を呼ぶ。GitHub prefetch のバッチには載せない

## テスト計画

- 単体: 参照の分解（公式イメージ、`ghcr.io`、未対応ホスト、`${{`、既ピン）
- 単体: store miss / hit、offline では inactive
- 単体: スカラー `container:`、`container.image`、`services`、`docker://` の
  rewrite と trailing comment
- 単体: フロー値・block scalar・未対応レジストリは fix なし
- e2e: store に入れた digest で `.fixed` sibling が一致する fixture
