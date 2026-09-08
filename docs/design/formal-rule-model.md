# 形式手法によるルール自体の抜け漏れ検出: Z3 有界モデル検査

最終更新: 2026-09-08

追跡 issue: #307（sub-issue #308〜#314）

## 1. 目的

ルール実装の単体テスト・PBT・fuzz（`docs/design/pbt-strategy.md`）は
「実装が意図どおりに動くか」を確かめる。しかし「意図そのもの ——
`run_dangerous_contexts` や `trigger_context_table` に並べた文脈の一覧 ——
に抜けがないか」は、テストが同じ表を前提に書かれる以上、確かめられない。

本書のモデルはその前提を検査対象にする。GitHub Actions の信頼モデル
（どのトリガでどの `${{ }}` 文脈を攻撃者が書けるか、どこへ流れると危険か）
を実装と独立に**仕様**として書き下し、実装側の表を `src/rules/security.zig`
から機械的に抽出し、両者の差分を Z3 で網羅列挙する。差分の各要素は
「仕様は危険と言うのにどのルールも報告しない組み合わせ」= false negative
の候補であり、実バイナリで確認してから issue にする。

対象は現状 SEC002 / SEC005 / SEC006 / SEC008 / SEC009 / SEC020 / SEC021 /
SEC022（インジェクションと untrusted checkout の系統）。

---

## 2. 構成

```
scripts/formal/
├── spec.py          仕様側: トリガ / 文脈 / シンク / 伝播経路の有限関係
├── impl.py          実装側: security.zig / types.zig から表を抽出
├── model.py         Z3 で Unsafe ∧ ¬Covered の証人を全列挙（性質 P1〜P8）
├── confirm.py       各証人を最小ワークフローに落とし実バイナリで確認
└── requirements.txt z3-solver（固定版）
```

実行:

```bash
zig build
pip install -r scripts/formal/requirements.txt
python3 scripts/formal/model.py            # 証人一覧（--json で機械可読）
python3 scripts/formal/confirm.py          # 実バイナリで確認（--keep DIR で生成物保存）
```

いずれも終了コードは常に 0。モデルは **finder** であって CI ゲートではない。
列挙された抜けは issue として追跡し、直したら証人が消える（§6）。

---

## 3. 仕様側 (`spec.py`)

`src/` から一切導出しない。GitHub の webhook payload 仕様、
"Security hardening for GitHub Actions"、`github.head_ref` の存在条件、
actionlint / zizmor が公開する untrusted 一覧から転記する。

### 3-1. ソート

| ソート | 要素 | 例 |
|---|---|---|
| Trigger | `on:` のイベント名 20 種 | `pull_request_target`, `issue_comment`, `workflow_run`, `gollum` |
| Ctx | `${{ }}` パス。`.*` はシーケンス要素 | `github.event.pull_request.title`, `inputs.*` |
| Sink | 値が到達すると危険な場所 | `run`, `github_script`, `github_env`, `checkout_ref`, `condition` |
| Flow | 値がシンクへ届く経路 | `direct`, `env_context`, `step_output`, `job_output` |

### 3-2. 関係

| 関係 | 意味 |
|---|---|
| `available(t, c)` | トリガ `t` の payload が文脈 `c` を埋める |
| `external(c)` | 任意の GitHub アカウント（fork、通りすがりのコメント者）が書ける |
| `dispatcher(c)` | dispatch / call を起動した側が書ける（`inputs.*`, `client_payload.*`） |
| `ref_shaped(c)` | commit / ref / repository を指し、checkout が取得する「コード」を選ぶ |
| `free_text(c)` | 人が打つ自由文（title / body / message / description …） |
| `privileged(t)` | base リポジトリの secrets と書き込み可能 `GITHUB_TOKEN` を持つ（`pull_request` 以外） |
| `externally_triggerable(t)` | 書き込み権限のないアカウントが発火させられる |
| `carries_fork_code(t)` | payload が fork 上のコードを指す（`issue_comment` は `refs/pull/<n>/merge` 経由で該当） |

著者は `Author` 列挙（`EXTERNAL` / `DISPATCHER` / `COLLABORATOR`）。
labels や release は `COLLABORATOR` として載せ、実装がそれらを表に持つことと
矛盾しないようにしている（モデルはそれらを危険と主張しない）。

---

## 4. 実装側 (`impl.py`)

手写しではなく実行時に抽出する。表を編集すれば次回実行でモデルが変わり、
抽出できなくなれば空集合ではなく `LookupError` になる。

| `Impl` フィールド | 抽出元 | 使うルール |
|---|---|---|
| `run_dangerous` | `run_dangerous_contexts` | SEC002, SEC008 |
| `dispatched_inputs` | `dispatched_inputs_contexts` | SEC002（`workflow_dispatch` / `workflow_call` 宣言時のみ） |
| `condition_dangerous` | `condition_dangerous_contexts` | SEC006 |
| `workflow_run_gate` | `workflow_run_untrusted_gate_contexts` | SEC022 |
| `pr_head_markers` | `isPRHeadValue` | SEC005（`pull_request_target` 宣言時のみ） |
| `workflow_run_markers` | `isWorkflowRunValue` | SEC009（`workflow_run` 宣言時のみ） |
| `trigger_contexts` | `trigger_context_table` | SEC021（`workflow_dispatch` 宣言時は bare `inputs` を追加、#219） |
| `fork_accessible_triggers` | `hasForkAccessibleTrigger` の `=> return true` 腕 | SEC020 |
| `event_types` | `EventType` 列挙 (`types.zig`) | 未知イベントは `.other` に潰れる |
| `followed_flows` | 固定値 `direct`, `step_output` | SEC002 が追う伝播（`checkScriptInjection` の構造から） |

照合意味論も写している。文脈表は `pathMatchesPattern`（セグメント前方一致、
`*` ワイルドカード、大文字小文字無視）→ `matches_prefix`、
`refs/pull/` 型マーカーは `containsAnyMarker`（部分文字列）→ `matches_marker`。

---

## 5. 性質 (`model.py`)

各性質は自由変数 `t, c, sink, f` 上の `Unsafe` と `Covered` の対で、
Z3 に `Unsafe ∧ ¬Covered` を問い、得た証人をブロック節で除外しながら
sat でなくなるまで列挙する。全述語は有限ソート上で外延的に定義するので
決定可能で、列挙は完全である。

| 性質 | Unsafe | Covered | 期待ルール |
|---|---|---|---|
| P1 script injection | `available ∧ (external ∨ dispatcher) ∧ free_text`、sink = `run`、direct | `sec002(t, c)` | SEC002 |
| P2 GITHUB_ENV injection | 同上、sink = `github_env` | `sec008(t, c)` | SEC008 |
| P3 condition gate | `available ∧ external ∧ free_text ∧ ¬ref_shaped`、sink = `condition` | `sec006 ∨ sec022` | SEC006 |
| P4 untrusted checkout | `available ∧ privileged ∧ (external ∨ dispatcher) ∧ ref_shaped`、sink = `checkout_ref` | `sec005 ∨ sec009 ∨ sec021` | SEC005/SEC009/SEC021 |
| P5 SEC021 ⊆ SEC002 | `sec021(t, c)`、sink = `run` | `sec002(t, c)` | SEC002 |
| P6 SEC022 ⊆ SEC002 | `sec022(t, c)`、sink = `run` | `sec002(t, c)` | SEC002 |
| P7 self-hosted fork reach | `carries_fork_code ∧ externally_triggerable`（c は `head.sha` に固定） | `sec020(t)` | SEC020 |
| P8 taint flow | `issue_comment × comment.body × run`（sec002 が持つ既知の組） | `followed(f)` | SEC002 |

設計上の判断:

- **P1 / P2 は `free_text` を要求する。** 番号や SHA はサーバが整形する値で
  シェルのメタ文字を含めない。ref 形の文脈は P4 で見る。
- **P3 は ref 形を除外する。** `head.ref` や labels を `if:` で使う判定は
  #138 で SEC006 から意図的に外した。
- **P5 / P6 はルール間整合性。** checkout ref を選べる文字列（SEC021）や
  `workflow_run` のゲートに使わせない文字列（SEC022）は `run:` に展開すれば
  そのままインジェクションなので、SEC002 が同じ文脈を持たないのは矛盾。
- **P7 / P8 は代表元に固定する。** トリガだけ・経路だけの性質なので、
  無関係な変数の組み合わせごとに同じ抜けを何度も報告しない。

---

## 6. 確認 (`confirm.py`)

証人 `(t, c, sink, flow)` ごとに最小ワークフローを生成し、
`zghalint --quick --format json` で期待ルールが出ないことを確かめる。
モデルの実装像が粗すぎた場合は `covered` として出るので、
その場合は issue ではなくモデルを直す。

生成規則:

- `.*` → `.foo`（`inputs.foo`）、`.*.` → `[0].`（`commits[0].message`）。
- `workflow_dispatch` / `workflow_call` は `inputs: foo:` を宣言、
  `workflow_run` は `workflows: [ci]` / `types: [completed]` を付ける。
- `checkout_ref` は原則 `ref:`、番号文脈は `refs/pull/${{ … }}/merge`、
  リポジトリ名文脈は `repository:` に渡す。
- P7 は `runs-on: self-hosted`。
- 伝播経路は、取り込み側のステップで `env:` と `$TITLE` を使う安全な
  書き方にする。診断が出るなら経路を追った結果だと言えるようにするため。

2026-09-08 時点: **70 / 70 の証人が false negative として確認された**。

---

## 7. 証人と issue の対応

| issue | 性質 | 証人（トリガ × 文脈） | 原因 |
|---|---|---|---|
| #308 F1 | P4 | `issue_comment`, `issues` × `issue.number` | `trigger_context_table` に `issue.number` がなく、`refs/pull/` マーカーは SEC005 だけ |
| #309 F2 | P4, P7 | `pull_request_review`, `pull_request_review_comment` × PR の全 ref 文脈 | `EventType.fromString` が `.other` に潰し、SEC005 / SEC020 / SEC021 のどれも見ない |
| #310 F3 | P4 | `pull_request_target` × `merge_commit_sha` | `isPRHeadValue` のマーカーにない |
| #311 F4 | P4 | `workflow_run` × `pull_requests.*.head.ref` | `isWorkflowRunValue` のマーカーにない（fork PR では空になる点に注意、enhancement） |
| #312 F5 | P1, P2, P5 | `repository_dispatch` × `client_payload.*`；`workflow_dispatch` / `workflow_call` × `inputs.*` (SEC008) | SEC021 は持つが SEC002 / SEC008 は持たない。SEC008 は dispatch 拡張表を見ない |
| #313 F6 | P1, P2, P3, P6 | `head_repository.description`, `head.repo.description`, `head.repo.homepage`, `*.committer.*` | 自由文の文脈が表にない。SEC022 は committer を持つのに SEC002 にはない |
| #314 F7 | P8 | `issue_comment` × `comment.body` via `env_context`, `job_output` | SEC002 が `env:` → `${{ env.X }}` と job `outputs:` → `${{ needs.*.outputs.X }}` を追わない |

### 意図的な除外（issue にしない）

- **`workflow_call` 専用ワークフローの `inputs.*` を checkout ref に渡す**
  （P4 の証人）。caller の解析は範囲外で、#219 の判断どおり bare `inputs` は
  `workflow_dispatch` 併記時のみ untrusted とする。証人としては残す。
- **ref 形の文脈を `if:` で使う**（#138）。モデル側で P3 から除外済み。

---

## 8. 運用

- **ルール修正後**: `confirm.py` を再実行し、対応する証人が `covered` に
  変わることを確認してから issue を閉じる。
- **表を増やしたとき**: `impl.py` は抽出するだけなので変更不要。
  抽出パターンが変わったら（表名・関数シグネチャ）`impl.py` を追随させる。
  抽出失敗は `LookupError` で止まる。
- **仕様を広げるとき**: 新しいトリガ / 文脈 / シンクは `spec.py` にだけ足す。
  実装を見て書かないこと。仕様側が実装を写した瞬間にモデルは何も言わなくなる。
- **新ルールを対象に加えるとき**: `impl.py` に抽出、`model.py` の
  `_define_impl` に述語、`properties()` に性質、`confirm.py` の
  `workflow_for` に生成規則を足す。

## 9. 限界

- 有界モデル。`AVAILABLE` に載せた文脈しか見ない。載せ忘れは検出できない
  （actionlint / zizmor の一覧との突き合わせで補う。#262）。
- 伝播経路は 1 ホップまで。多段の `outputs` 連鎖や composite action 越しの
  流れは扱わない。
- 「危険」の定義は信頼モデルのみで、`author_association` や環境保護などの
  実装側 anchor（`forkGuarded` など）は `confirm.py` の最小ワークフローに
  含めない。anchor があるときに黙る挙動の検証は既存の単体テストの領分。
- 既存の PBT / fuzz（`pbt-strategy.md`）が見るのは実装の性質
  （クラッシュ耐性・決定性・単調性）。本モデルはそれらが前提とする表の
  完全性を見る補完であり、置き換えではない。
