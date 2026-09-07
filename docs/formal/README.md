# 形式仕様とモデル検査

zghalint の 4 つのコンポーネントについて、**ドキュメントが宣言している仕様**と**コードから読み取れる仕様**を TLA+ / Alloy / Z3 で形式化し、モデル検査で反例を探した。本ページはドメインエキスパート（GitHub Actions のセキュリティとリンター運用に詳しい人）向けのまとめで、各反例をワークフロー用語に戻して説明する。詳しいトレースは各ディレクトリの `counterexamples.md` にある。

| モデル | 対象 | 道具 | ディレクトリ |
| --- | --- | --- | --- |
| FixEngine | `--fix` の編集適用 (`src/fix/engine.zig`) | TLA+ / TLC | [`fix_engine/`](fix_engine/) |
| Prefetch | GitHub API のプリフェッチと 24h キャッシュ (`src/rules/prefetch.zig`) | TLA+ / TLC | [`prefetch/`](prefetch/) |
| RuleOwnership | SEC005 / SEC009 / SEC021 の担当分け (`src/rules/security.zig`) | Alloy 6 | [`rule_ownership/`](rule_ownership/) |
| SEC022 | `workflow_run` ゲートの信頼アンカー判定 (`src/rules/security.zig`) | Z3 (python) | [`sec022/`](sec022/) |

## このドキュメントの位置づけ

**解析対象**: `82fad14`（2026-09-07 時点の `main`）。本文中の行番号もこの時点のもの。モデル化した 4 ファイル（`src/fix/engine.zig`, `src/rules/prefetch.zig`, `src/rules/security.zig`, `src/rules/graphql.zig`）は `11f3a17` 時点でも変更されていないので、以下の反例はいずれもまだ有効。

**保守方針**: これは特定時点のスナップショットであり、CI では検査していない。TLA+ / Alloy / Z3 はこのリポジトリのツールチェーンに入っておらず（ゼロ依存方針）、モデルの再実行は手動。コードが変われば反例やファイル参照が古くなりうるので、「常に正しい仕様書」ではなく「この時点で見つかった問題とその証拠」として読むこと。再実行の手順は末尾にある。

## 進め方

1. 各モデルのヘッダーに「宣言された仕様 S1..」と「コード由来の仕様 C1..」を並記した。S はドキュメント（ADR、`docs/design/*.md`、ルール解説、テストの意図）から、C はコードを読んで抽出した。
2. S と C をそれぞれ性質（不変条件 / assert / 充足問題）として書き、S が C の下で成り立つかを検査した。
3. 違反はトレースやインスタンスとして取り出し、ワークフローや運用の言葉に戻した。

## 発見の一覧（重要度順）

| # | モデル | 症状 | 重要度 | ドメインでの意味 | イシュー |
| --- | --- | --- | --- | --- | --- |
| 1 | RuleOwnership | `repository:` が PR head / workflow_run 由来でも無報告 | **高** | fork の PR が `with.repository` 経由で特権トークン付き実行を得られるのに、どのルールも黙る | #218 |
| 2 | RuleOwnership | `workflow_call` を足すと `inputs.*` の検出が消える | **高** | `workflow_dispatch` と `workflow_call` を併記するだけで SEC021 を無効化できる | #219 |
| 3 | SEC022 | `\|\|` や `!` の中のアンカーで条件全体が抑制される | **高** | `contains(message,'x') \|\| full_name == github.repository` が「検証済み」扱い | #220 |
| 4 | Prefetch | RateLimited が「中断」ではなく REST 再試行になる | 中 | レート制限直後に同じ API を REST で叩く | #222 |
| 5 | Prefetch | GraphQL 2 バッチ目失敗で 1 バッチ目の成功結果が `unknown` に上書き | 中 | 一時的失敗で正しい結果を捨て、解決できない旨の診断を出す（31 以上のアクションリポジトリを参照する場合） | #222 |
| 6 | Prefetch | ディスクキャッシュは「最後に問い合わせた SHA」だけを覚える | 中 | pin を 1 つ足す、ブランチを行き来する、SC004 を切る、のいずれでもウォームランが成立しない | #221 |
| 7 | FixEngine | 複数編集の Fix が半分だけ適用される | 中 | 修正後のファイルがどのルールの意図とも一致しない中間状態になる | #223 |
| 8 | FixEngine | 同一範囲の置換は先に登録したルールが黙って勝つ | 低 | `--fix` で片方の修正が無言で捨てられる | #223 |
| 9 | FixEngine | 同一バイトへの挿入順がレジストリの並びで決まる | 低 | ルール追加でゴールデン出力が変わる | #223 |
| 10 | RuleOwnership | `pull_request_target` + `workflow_run` で同じ `ref` に二重報告 | 低 | ノイズのみ | #224 |
| 11 | RuleOwnership | `repository_dispatch` で `github.event.inputs` に発火 | 低 | 誤設定の指摘としては有用な誤検知 | #224 |
| 12 | SEC022 | `head_repository.fork` / `!=` 比較がアンカーにならない誤検知 | 低 | fork を正しく弾いている条件が報告される | #220 |

## 各発見のドメイン説明

### 1. `repository:` の穴（RuleOwnership, Coverage 反例）

```yaml
on: pull_request_target
steps:
  - uses: actions/checkout@v4
    with:
      repository: ${{ github.event.pull_request.head.repo.full_name }}
```

SEC005 と SEC009 は `ref:` のみを検査する。攻撃者は fork の PR で `repository` を自分のリポジトリに向けるだけで、`ref` を触らずに任意のコードを特権トークン付きで走らせられる。`workflow_run.head_repository.full_name` を使った場合も同じ。修正案: SEC005 / SEC009 の検査対象に `with.repository` を加える（SEC021 は既に見ている）。

### 2. `workflow_call` による無効化（RuleOwnership, GapBareInputsWithWorkflowCall）

SEC021 は `workflow_call` が宣言されているワークフローでは bare `inputs.*` を「呼び出し元が渡す信頼できる値」として除外する。しかし `workflow_dispatch` が併記されていれば `inputs.ref` は手動実行者の入力でもある。修正案: `workflow_call` があっても、SEC021 トリガーが 1 つでも併記されていれば bare `inputs` を文脈に含める。

### 3. SEC022 のアンカーは構文位置を見ていない（Z3, S2 違反 16 件）

検出器は `if:` の文字列中に `head_repository.full_name ==` 等が**どこかに現れる**だけで条件全体を「発火元を検証済み」と判断する。Z3 は次のような抜け道を列挙した。

- `contains(head_commit.message, 'x') || head_repository.full_name == github.repository` — 左辺だけで通る
- `!(head_branch != 'main') && !(workflow_run.event == 'push')` — 否定されたアンカー
- `... && head_repository.name == 'repo' && ...` — fork はリポジトリ名を引き継ぐので `name` では弾けない

修正案: AST 上で「アンカーが `&&` の経路で必ず評価され、否定されていない」場合のみ抑制する。`name` はアンカーから外すか弱いアンカーとして扱う。

### 4–6. Prefetch のキャッシュ設計（TLA+, 3 実行の連続モデル）

`docs/design/network-io.md` は「ウォームランはネットワーク 0」「RateLimited で中断」と宣言しているが、モデルは両方を否定した。

- **RateLimited**: 1 バッチ目で受けると `tryGraphQlBatch` が `false` を返し、REST フォールバックが同じ API を叩く。
- **劣化**: 2 バッチ目が失敗すると REST が全 SHA を取り直し、その REST が失敗すると 1 バッチ目で取れていた `has_tag` を `unknown` で上書きする。実装は 1 POST に 30 リポジトリ（SC008 有効時 20）を詰めるので、2 バッチ目が存在するのは lint 対象全体で 31（21）以上の異なるアクションリポジトリを参照する場合に限る。
- **ウォームランが成立しない 3 つの経路**:
  - SC004 有効: archived フラグがキャッシュに乗った repo の新しい SHA は GraphQL に乗らず、遅延取得（永続化なし）で毎回取り直される。
  - SC004 無効: repo が `sets.repos` から除かれないので、全 SHA がキャッシュ済みでも空の GraphQL を送り、空結果でディスクを上書きしてキャッシュを消す。
  - 共通: `persistRepoResult` はこの実行で問い合わせた SHA だけで上書きするので、ディスク上の既存 SHA が消える。

修正案: 永続化はディスクの既存エントリとマージする。`sets.repos` から SHA 残量ゼロかつ archived 不要の repo を除く。RateLimited は `idx` に関係なく REST を抑止する。

### 7–9. FixEngine（TLA+, N=2）

宣言どおり成り立った性質: 後ろから前へのコピーは前から順に差し替えた結果と一致する（S4）、生き残った編集は互いに重ならない（S2）、同一バイトの幅ゼロ挿入は両方残る（S3）、コピーループは負のオフセットを踏まない。

違反した性質:

- **Fix は原子的でない**: Fix 2 の `(0,0)` 挿入は残り `(0,1)` 置換は Fix 1 に負けて落ちる。1 ルールの修正が半分だけ入る。
- **同一範囲の置換は先勝ち**: ルール X の削除とルール Y の置換が同じ範囲なら、レジストリで先の方だけが入り、後の方は無言で捨てられる。
- **同一バイトの挿入順は登録順**: ADR 0001 D5 の「ゴールデンテストで固定」は、ルール追加で壊れる前提を含む。

修正案: 衝突した Fix 全体を落とす（原子性）、あるいは落とした編集を診断として報告する。

### 10–12. 低重要度

- SEC005 と SEC009 は互いを知らないので、両トリガー併記のワークフローで同じ `ref` に 2 件出る。
- SEC021 は「トリガー集合 × 文脈集合」で判定するので、`repository_dispatch` に `github.event.inputs` という実在しない組み合わせでも発火する。
- SEC022 は `head_repository.fork == false` や `full_name != github.repository`（`!=`）をアンカーと見なさないので、fork を正しく弾いた条件でも報告する。

## 成り立った性質

| モデル | 性質 |
| --- | --- |
| FixEngine | `NoUnderflow`, `KeptDisjoint`, `LoopMatchesSpec`, `InsertionsCoexist`（1,319,716 状態） |
| Prefetch | `AllResolvedAtEnd`（ルール実行時点で全 SHA が解決済み。SC004 の有無どちらでも） |
| RuleOwnership | `DeferralIsSafe`（SEC021 が譲った `ref` は必ず SEC005 / SEC009 が拾う） |
| SEC022 | 正検知の健全性（unit test が固定する形は報告される） |

## モデルの限界

- FixEngine はソース 2 バイト、Fix 2 個、Fix あたり編集 2 個まで。反例はすべて初期状態で見つかっているので、この範囲で十分だった。改行で始まる挿入を行末に寄せる `snapInsertionToLineEnd` はモデル化しておらず、位置はソート直前のものとして扱っている。
- Prefetch はリポジトリ 2、SHA 3、実行 3 回。GraphQL は 1 リポジトリ 1 バッチとして抽象化している（実装は 30 リポジトリ / POST）。REST の部分成功や deadline はモデルに含めていない。
- RuleOwnership は式の文字列一致を「文脈の集合」に抽象化している。実装の正規表現が拾えない書き方（間接参照、`env` 経由）は対象外。
- SEC022 は原子式 13 種、AST 5 ノードまで。`fromJSON` や `env` 経由の値は扱っていない。

## 再実行

| モデル | コマンド |
| --- | --- |
| FixEngine | `java -cp tla2tools.jar tlc2.TLC -workers auto -config FixEngine.cfg FixEngine.tla`（ほか 3 つの cfg も同様） |
| Prefetch | `java -cp tla2tools.jar tlc2.TLC -workers auto -config Prefetch_archTRUE.cfg Prefetch.tla`（`archFALSE` も） |
| RuleOwnership | `java -jar alloy.jar exec -c '*' -t text -o - RuleOwnership.als` |
| SEC022 | `pip install z3-solver && python3 sec022_anchor.py` |

使用したバージョン: TLA+ tools 1.8 系、Alloy 6.2.0、z3-solver 4.x。
