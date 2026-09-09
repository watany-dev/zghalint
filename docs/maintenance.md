# メンテナンス手順

バージョン定義が散らないよう、更新時に触る箇所をここに集約する。

## Zig バージョンの更新

**真は `build.zig.zon` の `.minimum_zig_version` 一箇所。**

参照する側:

| 参照元 | 読み方 |
|---|---|
| CI / Release ワークフロー | `mlugg/setup-zig` に `version:` を渡さない。省略時に `build.zig.zon` の `minimum_zig_version` が使われる |
| `scripts/setup-zig.sh` | `build.zig.zon` から `minimum_zig_version` を `sed` で読み出す |

手順:

1. `build.zig.zon` の `.minimum_zig_version` を更新する
2. `zig build && zig fmt --check src/ build.zig && zig build test --summary all` を通す
3. 人間向けの記述（重複を許容している箇所）を更新する
   - `README.md` の "Requires **Zig X.Y.Z** or later"
   - `AGENTS.md` の Prerequisites

`mlugg/setup-zig` を更新する際は、`version` 省略時のフォールバック挙動
（`build.zig.zon` の `minimum_zig_version` を読む）が維持されているか確認する。
挙動が変わった場合はワークフローに `version:` を戻すのではなく、
`build.zig.zon` を読むステップを 1 つ足して各ジョブへ渡す。

## リリース

### タグ命名規則

- 正式リリース: `v<semver>`（例: `v0.2.0`）
- プレリリース: `v<semver>-rc.<N>`（例: `v0.1.0-rc.1`）

`release.yml` は `*-rc.*` にマッチしたタグへ `--prerelease` を付ける。
この規則がリリース種別を決めるため、`-rc.` 以外の接尾辞は使わない。

### バージョンを上げるとき触る箇所

**真は `build.zig.zon` の `.version` 一箇所。** ビルド時に読めない写しだけを
併記し、`scripts/check-version-sync.sh` が食い違いを検出する。

| ファイル | 内容 | 検証 |
|---|---|---|
| `build.zig.zon` の `.version` | `--version` 出力の元（`build.zig` 経由） | `release.yml` の `verify` がタグと突き合わせる |
| `action.yml` の `FALLBACK_VERSION` | ref がリリースタグでない（SHA ピン・移動メジャータグ・ブランチ）ときのダウンロード先 | `ci.yml` の `lint` と `release.yml` の `verify` |
| `install.sh` の `DEFAULT_VERSION` | `curl \| sh` に `--version` を渡さなかったときのダウンロード先 | `ci.yml` の `lint` と `release.yml` の `verify` |
| `README.md` の `uses: watany-dev/zghalint@v...` の例 | 利用者向けの記載 | `ci.yml` の `lint` と `release.yml` の `verify` |

`ci.yml` は `build.zig.zon` との一致だけを見る（引数なし実行）。`release.yml` は
そこにタグとの一致とバイナリの `--version` を足す。

### action.yml のバージョン解決

ダウンロード先タグは次の順で決まる。

1. `version` 入力（明示指定）
2. `GITHUB_ACTION_REF` が `v<major>.<minor>.<patch>` 形式のとき、その ref
3. `action.yml` の `FALLBACK_VERSION`

2 の形式判定を挟むのは、`@<sha>`（SEC001 が求めるピン方法）・`@v0` のような
移動メジャータグ・ブランチ ref がそのままダウンロード URL に入ると 404 に
なるため。これらの ref も「このコミット」は一意に指すので、そのコミットが
属するリリース（3）へ落とす。

### 手順

1. `build.zig.zon` の `.version` を新しいバージョンに更新する
2. `action.yml` の `FALLBACK_VERSION`、`install.sh` の `DEFAULT_VERSION`、
   `README.md` の例を同じバージョンへ揃え、`./scripts/check-version-sync.sh`
   で確認する
3. コミットして `main` へ入れる
4. `git tag v<version> && git push origin v<version>` — 3 を入れた時点で
   `FALLBACK_VERSION` は未公開のリリースを指す。その間に `main` のコミットを
   SHA ピンした利用者はダウンロードに失敗するので、3 と 4 は続けて行う
5. `release.yml` の `verify` ジョブが以下を検証する
   - タグ（先頭 `v` を除く）と `build.zig.zon` の `.version` が一致すること
   - ビルドしたバイナリの `--version` 出力がタグと一致すること

不一致があれば `::error::` を出して落ちるので、タグを打ち直す。

## 配布経路

リリース資産のほかに、`curl | sh` と Homebrew の 2 経路がある。どちらも
公開済みの `SHA256SUMS` を照合するので、資産が揃う前に走らせてはならない。

### install.sh

リポジトリ直下の `install.sh`。利用者は `main` の raw URL から取得して実行する
ため、**`main` に入った時点で公開されている**（タグは介在しない）。壊すと
`curl | sh` が即座に壊れることに注意する。

| 項目 | 場所 |
|---|---|
| 既定のダウンロード先 | `DEFAULT_VERSION`（上のバージョン表） |
| 対応 target | linux / macos × x86_64 / aarch64。Windows はリリースページと action へ案内して終了 |
| 単体テスト | `tests/pbt/test_install_sh.py`（`file://` に置いた偽リリースへ `ZGHALINT_BASE_URL` を向ける） |
| lint | `ci.yml` の `lint` が `shellcheck install.sh` |
| リリース時の実地確認 | `release.yml` の `smoke` が Unix ランナーで実際に公開資産を入れて `--version` を突き合わせる |

### Homebrew tap

`release.yml` の `homebrew` ジョブが `watany-dev/homebrew-tap` の
`Formula/zghalint.rb` を書き換える。

- formula は `scripts/gen-homebrew-formula.sh <tag> <SHA256SUMS>` が生成する。
  チェックサムは公開済みの `SHA256SUMS` をそのまま読む（作り直すと formula が
  利用者のダウンロードするアーカイブと別物を指しうる）
- プレリリース（`-rc.`）はスキップする。`brew install` した利用者に検証中の
  ビルドを渡さないため
- 書き込みは Contents API 1 コミット。チェックアウトして push すると認証情報が
  ワークスペースに残る（SEC015 / zizmor の artipacked）
- 事前に必要なもの: tap リポジトリ `watany-dev/homebrew-tap` が存在すること、
  および `contents: write` を持つ PAT を zghalint 側の secret
  `HOMEBREW_TAP_TOKEN` に置くこと。secret が空ならジョブは `::warning::` を
  出して何もせず成功する（リリース自体は止めない）
- 生成物の妥当性は `ci.yml` の `lint` が毎回確認する（ダミーの `SHA256SUMS` で
  生成して `ruby -c`、およびエントリ欠落時に落ちること）

## 依存の更新

- GitHub Actions（SHA ピン）と `tests/pbt/requirements.txt` は
  `.github/dependabot.yml` により weekly でグループ化された PR が作られる
- action の更新 PR では SHA と `# vX.Y.Z` コメントの両方が書き換わることを確認する
- PBT の依存は `==` で固定する。Hypothesis はバージョン間で生成戦略と
  シュリンク挙動が変わるため、範囲指定にするとコード変更なしに CI の結果が変わる

## popular actions メタデータの更新

**真は各アクションの `action.yml`。** それを読んで生成したスナップショットが
`src/rules/data/popular_actions.zig` で、DEP005 / DEP006 / BP003 が参照する。

| 参照元 | 読み方 |
|---|---|
| 対象アクション一覧 | `scripts/popular-actions.txt`（`owner/repo[/path]@ref` を 1 行ずつ） |
| 生成スクリプト | `scripts/gen-popular-actions.py`（各リポジトリを shallow clone して `action.yml` を読む） |

手順:

1. 一覧を更新する（新しいメジャーが出た、対象を足す / 外す）
2. `python3 scripts/gen-popular-actions.py` を実行する（`pyyaml` と `git` が要る）
3. 生成物の差分を確認する。入力が消えているだけの差分は、上流が本当に消したのか
   一覧の `ref` を巻き戻していないかを疑う
4. `zig build && zig fmt --check src/ build.zig && zig build test --summary all` を通す

データが古いと「上流が足したばかりの入力を未知として報告する」誤検出になる。
一覧に載せるのは、古くなればすぐ気付かれる程度に広く使われているアクションだけに
する。載っていないアクションは検証されないだけで、誤検出にはならない。
