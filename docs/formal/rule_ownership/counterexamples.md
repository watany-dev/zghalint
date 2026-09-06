# RuleOwnership — Alloy の結果と反例

対象: SEC005（`pull_request_target`）、SEC009（`workflow_run`）、SEC021（dispatch / issue 系トリガー）の間での「攻撃者が制御できる checkout 入力」の担当分け。`src/rules/security.zig`。
モデル: [`RuleOwnership.als`](RuleOwnership.als)。

## 実行方法

```bash
cd docs/formal/rule_ownership
java -jar /path/to/alloy.jar exec -c '*' -t text -o - RuleOwnership.als
```

`-t text -o -` を付けないと、`RuleOwnership/` ディレクトリに skolem 変数だけの Markdown が書かれ、インスタンスの中身が見えない。

## 結果一覧

| 性質 | 由来 | 結果 |
| --- | --- | --- |
| `DeferralIsSafe` | S2（SEC021 が譲った `ref` は必ず隣のルールが報告する） | 成立（反例なし） |
| `Coverage` | S1（危険な checkout は必ずどれかのルールが報告する） | **反例あり** |
| `RefReportedOnce` | S1（`ref` は高々 1 つのルールが報告する） | **反例あり** |
| `NoSpuriousReport` | 誰も制御できない値には発火しない | **反例あり** |
| `GapRepositoryFromPRHead` | Coverage の穴を名前付きで探索 | SAT（穴がある） |
| `GapRepositoryFromWorkflowRun` | 同上 | SAT |
| `GapBareInputsWithWorkflowCall` | 同上 | SAT |
| `GapOther` | 上の 3 つ以外の穴 | SAT（`repository` に `BareInputs`。3 つ目と同根） |

## 反例 1: `repository:` が PR head 由来でも報告されない（`Coverage`）

```
Workflow.events     = {PullRequestTarget}
Step.ref            = {}
Step.repository     = {PRHead}
```

対応するワークフロー:

```yaml
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
```

SEC005 と SEC009 は `ref:` しか見ない。SEC021 は `repository:` も見るが、`pull_request_target` は SEC021 のトリガーではない。fork の PR から `repository` を指定して checkout すれば、`ref` を指定した場合と同じく攻撃者のコードが特権トークン付きで走るが、**どのルールも沈黙する**。`workflow_run` + `github.event.workflow_run.head_repository.full_name` も同じ穴（`GapRepositoryFromWorkflowRun`）。

## 反例 2: `workflow_call` があると `inputs.*` が完全に見逃される（`GapBareInputsWithWorkflowCall`）

```
Workflow.events     = {WorkflowDispatch, WorkflowCall}
Step.ref            = {BareInputs}
```

```yaml
on:
  workflow_dispatch:
    inputs: { ref: { type: string } }
  workflow_call:
    inputs: { ref: { type: string } }
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ inputs.ref }}
```

SEC021 は「`workflow_call` が宣言されていれば `inputs.*` は呼び出し元が渡すものなので信頼できる」として bare `inputs` を文脈から外す。しかし同じワークフローに `workflow_dispatch` も宣言されていれば、`inputs.ref` は手動実行者（write 権限を持つ人、あるいは `workflow_dispatch` を発火できる誰か）が自由に決められる。`workflow_call` を 1 行足すだけで SEC021 の検出を無効化できる。`repository: ${{ inputs.repo }}` でも同じ（`GapOther` の結果）。

## 反例 3: `pull_request_target` と `workflow_run` を両方持つと二重報告（`RefReportedOnce`）

```
Workflow.events     = {PullRequestTarget, WorkflowRun}
Step.ref            = {PRHead, WorkflowRunRef}
```

```yaml
on: [pull_request_target, workflow_run]
steps:
  - uses: actions/checkout@v4
    with:
      ref: ${{ github.event.pull_request.head.sha || github.event.workflow_run.head_sha }}
```

SEC005 と SEC009 は互いを知らないので、同じ `ref` に対して 2 件の診断が出る。SEC021 だけが `ownedByNeighbourRule` で譲る設計になっている。実害は診断のノイズで、セキュリティ上の穴ではない。

## 反例 4: `repository_dispatch` で `github.event.inputs` に発火（`NoSpuriousReport`）

```
Workflow.events     = {RepositoryDispatch}
Step.ref            = {DispatchInputs}
```

`repository_dispatch` のイベントペイロードには `inputs` はなく（`client_payload` がある）、`github.event.inputs.ref` は空文字に評価される。SEC021 は「SEC021 トリガーのどれか × SEC021 文脈のどれか」を掛け合わせて判定するので、トリガーと文脈の組み合わせが実際には存在しない場合でも発火する。誤設定の指摘としては有用なので、低重要度の誤検知として記録する。
