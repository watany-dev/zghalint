# 0019. 配布チャネルと発見経路

- Status: Accepted
- Date: 2026-09-15
- Deciders: 配布チャネルを増やして使われるようにしたい、という依頼

## Context

v0.0.2 時点のインストール経路は次の 4 つで、バイナリ自体は足りている。

- GitHub Release のアーカイブ（`SHA256SUMS` + SLSA attestation）
- `install.sh`（`curl | sh`）
- Homebrew tap（`watany-dev/tap`、`release.yml` が SHA256SUMS から formula を書く）
- リポジトリ直下の composite action（`uses: watany-dev/zghalint@<tag>`）

欠けているのは「知って、CI に載せる」側である。リポジトリの About 説明と
topics は空、GitHub Marketplace 未掲載、pre-commit / aqua / mise の案内が無い。
Windows 向け Scoop / WinGet、Nix flake、コンテナ画像はまだ無い。

スター 5、fork 0 の時点でパッケージマネージャを横に増やすと、
`docs/maintenance.md` が禁じている「版とハッシュの写し」が増えるだけで、
発見には効かない。Homebrew は既にその写しを release.yml で守っている。

## Decisions

### D1. 発見を先に、パッケージマネージャの横展開は後回し

今入れるのは、ハッシュの写しを増やさずに利用者が既に見ている場所へ出すもの。

| 経路 | なぜ今か |
|---|---|
| GitHub Marketplace | Actions 利用者がツールを探す場所。`action.yml` は既に root にあり、掲載はリリース編集のチェックボックス |
| リポジトリの description / topics | GitHub 内検索の入口。コードでは設定できないので手順だけ `docs/maintenance.md` に書く |
| README の位置づけ | actionlint（構文・式）と zizmor（セキュリティ）の間に立つことを、訪問者が最初に読む文にする |
| Code Scanning のコピー用ワークフロー | SARIF は既に出せる。Marketplace 利用者が「ステップ 1 つで Security タブに載る」と分かると採用理由になる |
| pre-commit（`language: system`） | ローカルで回す人が Homebrew / `install.sh` の次に求める形。Zig 言語バックエンドは pre-commit に無いので、バイナリの再配布はしない |
| aqua のパッケージ定義 | 日本の GitHub Actions 周辺で CLI を入れる標準経路。チェックサムはリリースの `SHA256SUMS` をその場で読むので、版の写しが増えない |
| mise の `ubi:` バックエンド | レジストリ不要で GitHub Release から入れる。README の数行だけ |

対案: Scoop / Nix / WinGet / GHCR を同じ PR で足す。いずれもアーカイブ名かダイジェストの写しが要り、Homebrew と同じ生成ジョブを複製することになる。待っている利用者がいないうちは作らない。

### D2. ハッシュをピンする経路は `SHA256SUMS` を読む生成物だけにする

新しいチャネルが「このタグの linux-x86_64 の sha256 は …」をファイルに書くなら、
`scripts/gen-homebrew-formula.sh` と同じく公開済み `SHA256SUMS` から生成し、
`release.yml` が書き、PBT が欠落を落とす。手書きの版は `install.sh` の
`DEFAULT_VERSION` と `action.yml` の `FALLBACK_VERSION` 以上に増やさない。

aqua の定義は asset 名と `checksum.asset: SHA256SUMS` だけを持ち、タグを埋め込まない。
これならリリースのたびにファイルを触らなくてよい。

### D3. GitHub Action に `output` 入力を足す

CLI は診断を stdout に書く。composite action も同じだったので、
`format: sarif` の結果はステップログに流れ、`upload-sarif` へ渡せなかった。

`output` にパスを渡したときだけ stdout をそのファイルへリダイレクトする。
空なら現行どおり stdout。終了コードは zghalint のまま（error で 1、実行不能で 2）。
リダイレクトは失敗時もファイルに残るので、`if: always()` の upload と組める。

対案: CLI に `--output` を足す。action 以外の利用者は既にシェルのリダイレクトで足りていて、C0 の CLI 穴埋め（`--fail-on` / `--stdin`）と範囲が重なる。action の入力だけに閉じる。

### D4. このリポジトリから出せない掲載は手順に留め、代理投稿しない

Marketplace 掲載、GitHub About / topics、`aquaproj/aqua-registry` への PR は
リポジトリ権限か別リポジトリの貢献ルールが要る。ここでは成果物と手順を置き、
掲載そのものはメンテナが行う。awesome-actions や Show HN も同じ。

Scoop / Nix / GHCR は、具体的な利用者が現れるか、ハッシュ生成を Homebrew と
共有できる用意ができたときに D2 の規則で足す。

## Consequences

- README / `action.yml` / `.pre-commit-hooks.yaml` / `packaging/aqua-registry.yaml` /
  `docs/maintenance.md` が利用者がコピーする入口になる
- v0.0.3 ロードマップの C0（CLI 穴埋め）と直交する。C4 の `--stdin` は
  pre-commit がファイルパスではなく内容を渡したくなったときの続き
- Marketplace を出さないと Action の発見は `uses:` を知っている人に限られる
