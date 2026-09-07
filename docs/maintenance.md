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

| ファイル | 内容 | 検証 |
|---|---|---|
| `build.zig.zon` の `.version` | `--version` 出力の元（`build.zig` 経由） | `release.yml` の `verify` がタグと突き合わせる |
| `action.yml` の `VERSION=${GITHUB_ACTION_REF:-...}` | `GITHUB_ACTION_REF` が取れない場合のフォールバック | 手動 |
| `README.md` の `uses: watany-dev/zghalint@...` の例 | 利用者向けの記載 | 手動 |

### 手順

1. `build.zig.zon` の `.version` を新しいバージョンに更新する
2. `action.yml` のフォールバックと `README.md` の例を同じバージョンへ揃える
3. コミットして `main` へ入れる
4. `git tag v<version> && git push origin v<version>`
5. `release.yml` の `verify` ジョブが以下を検証する
   - タグ（先頭 `v` を除く）と `build.zig.zon` の `.version` が一致すること
   - ビルドしたバイナリの `--version` 出力がタグと一致すること

不一致があれば `::error::` を出して落ちるので、タグを打ち直す。

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
2. `python3 scripts/gen-popular-actions.py` を実行する（`pyyaml` と `git` が要る。
   `--cache-dir <dir>` を渡すと clone を再利用できる）
3. 生成物の差分を確認する。入力が消えているだけの差分は、上流が本当に消したのか
   一覧の `ref` を巻き戻していないかを疑う
4. `zig build && zig fmt --check src/ build.zig && zig build test --summary all` を通す

データが古いと「上流が足したばかりの入力を未知として報告する」誤検出になる。
一覧に載せるのは、古くなればすぐ気付かれる程度に広く使われているアクションだけに
する。載っていないアクションは検証されないだけで、誤検出にはならない。
