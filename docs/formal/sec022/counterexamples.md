# SEC022 — Z3 の結果と反例

対象: SEC022（`workflow_run` の `if:` ゲートが fork で満たせるか）の「信頼アンカー」ヒューリスティック。`src/rules/security.zig` の `checkWorkflowRunBranchGate` / `hasWorkflowRunTrustAnchor`。
モデル: [`sec022_anchor.py`](sec022_anchor.py)。`if:` 条件を最大 5 ノードのブール AST として Z3 に列挙させ、各原子式に「fork の実行で取り得る値」と「本家の実行で取り得る値」を与えた。

## 実行方法

```bash
pip install z3-solver
python3 docs/formal/sec022/sec022_anchor.py
```

## 結果一覧

| 問い合わせ | 由来 | 結果 |
| --- | --- | --- |
| アンカーがあるので抑制されるが、fork がゲートを満たせる条件 | S2（「発火元リポジトリを検証している」ゲートは報告しない） | **16 件**（上限で打ち切り） |
| 報告されるが、fork には満たせず本家には満たせる条件 | 誤検知方向 | **8 件**（上限で打ち切り） |
| 報告されて fork が満たせる条件（健全性確認） | 正検知 | 3 件（期待どおり） |

## 反例 1: `||` でつないだアンカーは何も守らない（S2 違反）

```
if: contains(github.event.workflow_run.head_commit.message, 'x')
    || github.event.workflow_run.head_repository.full_name == github.repository
```

`head_repository.full_name == github.repository` は本来正しいアンカーだが、`||` の左側はコミットメッセージに `x` を含めるだけで fork 作者が真にできる。検出器は条件文中にアンカーが**どこかに出てくる**だけで条件全体を「検証済み」とみなすので沈黙する。同型の反例: `... || head_repository.owner.login == 'org'`、`... || workflow_run.event == 'push'`。

## 反例 2: 否定されたアンカー

```
if: !(github.event.workflow_run.head_branch != 'main')
    && !(github.event.workflow_run.event == 'push')
```

`workflow_run.event == 'push'` は文字列としてはアンカーだが、`!` で反転しているので「push 以外（= fork の pull_request でも可）」を通す条件になっている。`head_repository.name == 'repo'` を `!(...)` で包んだ場合も同じ。

## 反例 3: `head_repository.name` だけではリポジトリを特定できない

```
if: contains(github.event.workflow_run.head_commit.message, 'x')
    && github.event.workflow_run.head_repository.name == 'repo'
    && github.event.workflow_run.head_branch != 'main'
```

fork はリポジトリ名を引き継ぐ（`attacker/repo`）。`name` はアンカー扱いされているが `full_name` や `owner.login` と違って fork を弾けない。`head_repository.id` 以外の「アンカー」は、`full_name == github.repository` / `owner.login == '<org>'` 以外は弱い。

## 反例 4: 誤検知 — `head_repository.fork` と `!=` は無視される

```
if: !(github.event.workflow_run.head_repository.fork == true
      || github.event.workflow_run.head_branch == 'main')
```

`fork == false && head_branch != 'main'` と等価で、fork の実行では通らない。しかし `head_repository.fork` はアンカーに含まれておらず、`head_branch` がゲート文脈なので SEC022 が報告する。同様に `head_repository.full_name != github.repository` は `!=` なので `==` 隣接判定に引っかからず、`!(... || full_name != github.repository)`（= `full_name == github.repository`）が報告される。

## 健全性確認

`!(head_branch == 'main')` のような、本家の unit test が固定している形は報告される（正検知 3 件）。モデルが検出器を過剰に弱く写している訳ではない。

## 結論

SEC022 の「アンカーが条件文のどこかにあれば抑制」は、`||` と `!` を持つ条件式に対しては健全でも完全でもない。抑制の判定は AST 上で「アンカーが `&&` 経路で必ず評価され、否定されていない」ことを見る必要がある。`head_repository.fork` と `!=` 比較をアンカーに含めると誤検知側は減る。
