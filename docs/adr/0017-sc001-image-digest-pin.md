# 0017. SC001 コンテナイメージのレジストリ digest ピン止め

- Status: Accepted
- Date: 2026-09-13
- Deciders: issue #417（親 #409。評価は AF0 #322 の △）

## Context

SC001 は `container.image` / `services.*.image` / `uses: docker://…` の
タグ参照を warning にする。直し方は `image:tag` → `image@sha256:…` で、
SEC001 の SHA ピン止めと同じ供給連鎖の話である。#322 では GHCR / Docker Hub
への新規ネットワークが要るため第 1 波では手を付けていない。

診断は既にある。無いのは値の byte range と、`--fix` 時だけレジストリへ
マニフェストを取りに行く経路である。通常 lint の壁時間には乗せない。

本 ADR は issue が挙げた 4 点を確定させる。実装の手順は
`docs/design/sc001-digest-pin-design.md`。

## Decisions

### D1. 対象レジストリは Docker Hub と GHCR。認証は匿名が先

実装当初のホストは次の 2 つだけとする。他は診断を残し fix を出さない。
落ちもしない。

| 参照の形 | レジストリ |
|---|---|
| `alpine:3.19` / `library/alpine:3.19` / `docker.io/…` | Docker Hub (`registry-1.docker.io`)。公式イメージは `library/` を補う |
| `ghcr.io/owner/image:tag` | GHCR (`ghcr.io`) |

認証:

- Docker Hub は匿名 pull の token dance（`auth.docker.io`）だけ。
  `GITHUB_TOKEN` は送らない
- GHCR はまず匿名。401 のときだけ `GITHUB_TOKEN` を `privileged_headers` の
  Bearer にする（リダイレクト先へトークンを持ち出さない、既存 GitHub API と同じ）
- ワークフローの `container.credentials` は使わない。値が
  `${{ secrets.* }}` なら解決できず、平文なら SEC013 の対象であって
  こちらが送るものではない
- private / 未対応レジストリ / 認証失敗は fix なし。診断は残る

`--quick` / `--offline` では fetch せず `diag.fix = null`。`--no-cache` は
ディスクキャッシュだけを無視し、レジストリへは行く（GitHub prefetch と同じ）。

### D2. ピンするのはタグが指しているマニフェスト（index）の digest

マルチアーキは manifest list / OCI index が先に返る。その **index の digest**
を書く。実行 OS の platform child は書かない。

GitHub-hosted runner は ubuntu / macos / windows と amd64 / arm64 が混ざる。
platform digest に固定すると、取った側の runner 以外で pull が失敗する。
index digest ならランタイムが platform を選ぶ。SEC001 が commit oid で一意な
のと同じく、「タグがその瞬間指していたもの」が一意である。

単一 platform のマニフェストしか返らないイメージは、そのマニフェストの
digest を書く。どちらも応答ボディの SHA-256 であり、`Docker-Content-Digest`
ヘッダは使わない（ヘッダ欠落に依存しない）。

digest は取れた瞬間のタグ内容である。タグ移動の race は description に書く。
取れなければ fix を出さない。

### D3. span は `Container` / `Service` の `image_meta` と、既存の `uses:` 値 span

| 参照 | 値の位置 | 既存 | 足すもの |
|---|---|---|---|
| `container: alpine:3.19`（スカラー） | そのスカラー | 値だけ | `Container.image_meta` |
| `container.image:` | `image:` の値 | 値だけ | 同じ `image_meta` |
| `services.<id>: redis:7`（スカラー） | そのスカラー | 値だけ | `Service.image_meta` |
| `services.<id>.image:` | `image:` の値 | 値だけ | 同じ `image_meta` |
| `uses: docker://alpine:3.19` | `uses:` の値 | `uses_value_span` / `uses_value_end_byte` / `uses_value_style` | なし |

`image_meta` は `ScalarValueMeta`（`runs_on_value_span` と同じ形）。診断の
span も job span から値 span へ寄せる。fix が要るから付く精度であり、
診断だけのために parser を広げない。

書き換えは SEC001 に合わせ、タグ部分（無ければイメージ名の末尾）を
`@sha256:<digest>` に置換する。値が行末なら ` # <tag>` を付ける
（Dependabot / 人間が版を読める。暗黙 `latest` は `# latest`）。
フローコレクション内や block scalar は SEC001 と同じく fix なし。

元の書き方（`alpine` か `docker.io/library/alpine` か、`docker://` の有無）は
変えない。レジストリへ正規化した名前は fetch 用であり、ファイルへは戻さない。

### D4. `net_status` に SC001 は足さない

digest 取得は `--fix` / `--fix-unsafe` のときだけ走る。通常 lint は
ネットワークを見ないので、不達注記の対象にならない。

`--fix` で取れなかったイメージは、今までどおり warning が残り fix が付かない。
「調べられなかった」と「タグのまま」は利用者から見て同じ出力であり、stderr
に SC001 用の行を足す価値は無い。GitHub API 不達の sticky フラグ
（ADR 0016）も、レジストリ失敗では立てない——`ghcr.io` が死んでいても
`api.github.com` は生きていることがある。

## Consequences

- 通常 lint の壁時間・RSS・リクエスト数は不変。`--fix` だけイメージごとに
  HTTP が走る（Docker Hub は token + manifest の 2 往復、GHCR は 1 往復が基本）
- 24h の digest ディスクキャッシュを `zghalint/images/` に置く。GitHub の
  per-repo キャッシュとは混ぜない
- `scripts/bench.py --perf` の `--fix` 経路には最初は載せない。レジストリ I/O
  は opt-in であり、採点行列の壁時間に混ぜると GitHub API 側の退行と区別できない
- タグを動かしたイメージは、キャッシュ TTL のあいだ古い digest を書き得る。
  `--no-cache` で打ち消せる
