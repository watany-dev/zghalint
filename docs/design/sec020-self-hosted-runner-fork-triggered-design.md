# SEC020 self-hosted-runner-fork-triggered 設計書

## 目的

public リポジトリの self-hosted runner を fork 起動可能な trigger と組み合わせると、外部コントリビュータが PR やコメント経由で runner ホスト上に任意コードを実行できる。これは GitHub 公式も `About self-hosted runners` で強く警告している既知の攻撃面（通称 "pwn your self-hosted runner"）であり、ephemeral でない runner ではホスト永続化まで到達しうる。
`zghalint` の既存 SEC ルールには self-hosted runner を対象にした検出が存在せず（`src/rules/security.zig` 全文で `self-hosted` 言及ゼロ）、このクラスの構成ミスを workflow 単体の静的解析で拾えない。
本設計書は、trigger と `runs-on` を workflow 単位で突き合わせて警告する新ルール `SEC020` を追加する方針を定義する。実装そのものは本設計書承認後の別タスクで行う。

関連資料:

## スコープ

- `Job.runs_on` の文字列に `self-hosted` を部分一致で含む job
- Workflow の `on:` に次のいずれかの trigger が含まれる場合
  - `pull_request`
  - `pull_request_target`
  - `workflow_run`
  - `issue_comment`
- `repo_visibility: public` または `unknown` のときに発火（`unknown` は fail-safe 既定）
- severity = `warning`, category = `security`
- 修正提案は `fix_hint` のみ
- 診断粒度は自己ホスト runner を使う job 単位で 1 件

## 非スコープ

- カスタムランナーラベル（`gpu-linux`, `my-runner` など）を self-hosted として推論する拡張
- `${{ matrix.os }}` / `${{ inputs.runner }}` など動的 `runs-on` の式解決
- YAML sequence 形式 `runs-on: [self-hosted, linux, x64]` の検出（現行 parser は `getScalar("runs-on")` のみ読むため `Job.runs_on` が null となり対象外）
- `runs-on: { group: ..., labels: [...] }` オブジェクト形式のラベル配列を精密にパースすること（文字列部分一致のみ対応）
- `if:` 条件による gate の意味論解釈（fork PR を除外しているかの判定）
- リポジトリ visibility の自動検出（GitHub API 呼び出し）
- auto-fix（`--fix` / `--fix-unsafe`）の提供
- `discussion_comment`, `issues`, `fork` 等、判定対象外の trigger（将来拡張余地）
- 他 SEC/SC/BP/PERF ルールの挙動変更

## 現状整理

`src/workflow/types.zig` および `src/rules/engine.zig` を読むと、本ルールに関連する制約は次の通り。

- `Job.runs_on` は `?[]const u8` で生文字列のみを保持する（`src/workflow/types.zig:284`）。span 情報は持たない。
- `Workflow.on` は `EventConfig` のリストで、`EventType` enum として 15 種を区別する（`src/workflow/types.zig:98-146`）。対象 4 trigger はすべて既存 enum に含まれている。
- `Rule` 構造体の `check_job` シグネチャは `*const Job, *DiagnosticList` のみで、Workflow を参照できない（`src/rules/engine.zig:14-23`）。一方 `check_workflow` は `*const Workflow, *DiagnosticList` で workflow 全体を受け取れる。
- `Engine.run` は `Config` を check 関数に渡さない。SC003-SC006 の advisory 群はモジュールレベル変数＋setter でこの制約を回避している（`src/rules/advisory.zig` ほか）。
- `Config` 構造体にリポジトリ visibility に相当するフィールドは存在しない（`src/config.zig`）。
- 既存 SEC ルール群に self-hosted 関連の検出はなく、fork-accessible trigger と `runs_on` を突き合わせる rule もない。

これらの制約上、`SEC020` は `check_workflow` として実装し、visibility はモジュール変数経由で受け取る設計が素直である。

## 設計方針

### 1. 検出ロジックは `check_workflow` で実装する

判定条件が「workflow の `on:` を見ながら各 job の `runs_on` を走査する」形になるため、`check_job` では不足する。`Rule.check_workflow` で `workflow.jobs` をループし、以下を逐次評価する。

1. workflow が fork-accessible trigger を含むか
2. 含むなら job ごとに `runs_on` の self-hosted 該当性を判定
3. 該当 job ごとに 1 診断を追加

workflow 単位の判定結果はループ前に 1 度だけ計算してキャッシュする。

### 2. `runs_on` の self-hosted 判定は文字列部分一致のみ

`std.mem.indexOf(u8, runs_on, "self-hosted") != null` で判定する。現行 parser (`src/workflow/parser.zig`) は `getScalar("runs-on")` で scalar のみを読むため、`Job.runs_on` に入りうるのは次の形式のみである。

- `runs-on: self-hosted`
- `runs-on: "self-hosted"`
- `runs-on: self-hosted-gpu`（カスタムラベルが `self-hosted` を接頭辞に持つ単一 scalar）

YAML sequence 形式 `runs-on: [self-hosted, linux, x64]` は parser が scalar として扱わないため `Job.runs_on` が null となり本ルールでは検出しない（§2 非スコープ参照）。sequence 対応は `workflow/types.zig` の `runs_on` を `?[]const []const u8` 風の表現に拡張する必要があり、parser / types / バリデータを跨ぐ変更となるため別 PR に分離する（§10 参照）。

カスタムラベル単体（例 `gpu-linux`）を self-hosted と推論しようとすると false positive が増えるため、初版では `self-hosted` リテラルを含む scalar に限る。matrix や inputs による動的値は `${{ ...` を含むので自然に除外される。

### 3. fork-accessible trigger 4 種を判定対象とする

対象 trigger と根拠は以下。

| Trigger | 攻撃面 |
|---|---|
| `pull_request` | 外部 fork からの PR で job が起動する。default では `GITHUB_TOKEN` は read のみだが、self-hosted runner は runner ホスト上の永続状態・ネットワーク・credential に触れうる |
| `pull_request_target` | base リポジトリの secrets と write 権限付きで動作するため最危険。fork の変更を checkout した時点で RCE が成立しうる |
| `workflow_run` | trigger 元 workflow が fork PR 由来の場合、その結果として起動されうる |
| `issue_comment` | 外部ユーザのコメントが trigger になり、slash-command 系 workflow を起動しうる |

`push`, `workflow_dispatch`, `schedule`, `release` 等は fork から起動できないため対象外。

### 4. `repo_visibility` config を追加し、`security.zig` モジュール変数で受け渡す

`SC003` 系の advisory cache と同じパターンで Config を rule 実装に運ぶ。

`src/config.zig`:
```zig
pub const Visibility = enum { public, private, unknown };

pub const Config = struct {
    // ...既存フィールド...
    repo_visibility: Visibility = .unknown,
};
```

YAML からは `repo_visibility: public | private | unknown` を受ける。

`src/rules/security.zig`（モジュールトップ）:
```zig
var sec020_repo_visibility: Visibility = .unknown;

pub fn setRepoVisibility(v: Visibility) void {
    sec020_repo_visibility = v;
}
```

`src/main.zig` の `lintFile` で Engine 初期化前に `security.setRepoVisibility(config.repo_visibility)` を呼ぶ。

### 5. `unknown` は fail-safe で発火扱い

リポジトリ visibility は静的解析では決定不能であり、次のいずれかでしか判別できない。

- ユーザが `.zghalint.yml` に明示設定
- GitHub API で自動判定（本ルールでは非スコープ）

`unknown` を抑制側にすると、設定を書き忘れた public リポジトリで見逃しが起きる。public リポジトリは本ルールが想定する最悪ケースでもあるため、`unknown` は発火扱いとする。private リポジトリで通したいユーザは `.zghalint.yml` に 1 行追加すれば抑制できる。

### 6. 診断粒度は job 単位、span は job span にフォールバック

`Job.runs_on` 自体に span がないため（`src/workflow/types.zig:284`）、該当 job の span を流用する。`SEC005` が同じ理由で job span を使っており先行事例がある。pinpoint 精度向上は `runs_on_span` を追加する別 PR で対応する（本設計書 §10 参照）。

メッセージ:
```
self-hosted runner is used on a workflow with fork-accessible triggers;
untrusted code may execute on your runner host
```

`fix_hint`:
```
use GitHub-hosted runners for fork-accessible triggers,
restrict with `if:` to avoid running on fork PRs,
or make the runner ephemeral
```

### 7. fix_hint のみ提供、auto-fix は出さない

修正方針がコンテキスト依存（GitHub-hosted 移行 / `if:` gate / trigger 削除 / ephemeral 化）で、安全に機械化できる単一解が存在しない。`SEC005` 系と同じ方針で `fix_hint` のみ提供する。

## 安全性評価

本ルールは診断のみで破壊的変更を伴わないため、失敗モードは誤検知／見逃しに帰着する。

**False positive 軽減**:
- self-hosted リテラルに部分一致させるためカスタムラベル単体では発火しない
- private リポジトリでの誤発火は `repo_visibility: private` で抑制できる
- `unknown` 既定発火は 1 行設定で明示的に抑制でき、運用コストは許容範囲

**残存する false negative**:
- カスタムラベルで運用する自前 runner 群（self-hosted リテラルを含まない）
- `${{ matrix.* }}` / `${{ inputs.* }}` による動的 runs_on
- `runs-on: { group: ..., labels: [...] }` オブジェクト形式
- `if: github.event.pull_request.head.repo.full_name == github.repository` 等で fork を除外済みのワークフロー（安全だが発火する）

これらは明示的な非スコープとして設計書に記載する。

`fix_hint` は具体的な代替案を複数提示するのみで、ユーザの環境構成を仮定した破壊的提案を含まない。

## 実装差分

### 変更対象

- `src/config.zig`
- `src/rules/security.zig`
- `src/main.zig`
- `docs/rules.md`
- `README.md`

### 変更内容

1. `src/config.zig` に `Visibility` enum と `Config.repo_visibility: Visibility` フィールドを追加し、YAML パースで `repo_visibility: public | private | unknown` を取り込む
2. `src/rules/security.zig` にモジュール変数 `sec020_repo_visibility` と `pub fn setRepoVisibility(Visibility) void` を追加
3. `hasForkAccessibleTrigger(*const Workflow) bool` ヘルパを追加（`pull_request` / `pull_request_target` / `workflow_run` / `issue_comment` のいずれかが含まれるかを判定）
4. `checkSelfHostedRunnerForkTriggeredWorkflow(*const Workflow, *DiagnosticList) void` を追加
5. `pub const rules` 配列に `SEC020` エントリを追加（`check_workflow` にハンドラ、`check_job` / `check_step` は `null`）
6. `src/main.zig` の `lintFile` で Engine 初期化前に `security.setRepoVisibility(config.repo_visibility)` を呼ぶ
7. `docs/rules.md` の SEC テーブルに SEC020 行を追加し、冒頭の rule 数を `38` → `39` に更新
8. `README.md` L114 周辺の `38 rules` → `39 rules`

### 変更しないもの

- `src/rules/engine.zig`（`Rule` 構造体・`Engine` API 変更なし）
- `src/workflow/types.zig`（`runs_on` span 追加は別 PR に分離）
- `src/workflow/parser.zig`
- 他 SEC / SC / BP / PERF ルール実装
- `src/yaml/*`

## テスト設計

`src/rules/security.zig` 末尾にインラインテストを 14 件追加する。各テスト冒頭で `setRepoVisibility()` を明示呼び出しし、モジュールグローバル状態の漏れを防ぐ。

### 1. Positive: 発火すべきケース

| # | ケース |
|---|---|
| 1 | `runs-on: self-hosted` + `on: pull_request` → 発火 |
| 2 | `runs-on: self-hosted-gpu` （self-hosted 接頭辞の単一 scalar） → 発火 |
| 3 | `runs-on: self-hosted` + `on: pull_request_target` → 発火 |
| 4 | `runs-on: self-hosted` + `on: issue_comment` → 発火 |
| 5 | `runs-on: self-hosted` + `on: workflow_run` → 発火 |
| 6 | 複数 job が存在し、一部だけ self-hosted → 該当 job のみ発火 |

### 2. Negative: 発火すべきでないケース

| # | ケース |
|---|---|
| 7 | `runs-on: ubuntu-latest` + `on: pull_request` → 発火しない |
| 8 | `runs-on: self-hosted` + `on: push` のみ → 発火しない |
| 9 | `runs-on: self-hosted` + `on: workflow_dispatch` → 発火しない |

### 3. Config 分岐

| # | ケース |
|---|---|
| 10 | `repo_visibility: private` → 発火しない |
| 11 | `repo_visibility: public` → 発火する |
| 12 | `repo_visibility` 未指定（`unknown`） → 発火する |

### 4. Edge

| # | ケース |
|---|---|
| 13 | `runs_on == null`（再利用 workflow 呼び出し） → 発火しない |
| 14 | `.zghalint.yml` で `rules.SEC020.enabled: false` → 発火しない |

診断検証項目:
- `rule_id == "SEC020"`
- `severity == .warning`
- `category == .security`
- `fix_hint` が非空であること
- 複数 job ケース（#6）で診断件数が self-hosted 該当 job 数と一致すること

## 実装手順

1. failing test（ケース 1）を先に追加する
2. `src/config.zig` に `Visibility` enum と `repo_visibility` フィールド、YAML パースを追加
3. `src/rules/security.zig` にモジュール変数と `setRepoVisibility` を追加
4. `hasForkAccessibleTrigger` ヘルパを追加
5. `checkSelfHostedRunnerForkTriggeredWorkflow` を実装
6. `pub const rules` 配列に `SEC020` エントリを追加
7. `src/main.zig` で `setRepoVisibility` を呼ぶ
8. 残り 13 テスト（ケース 2〜14）を追加
9. `docs/rules.md` と `README.md` のカウント更新 + SEC020 行追加
10. `zig build && zig fmt --check src/ build.zig && zig build test --summary all` を実行

## ソースコードとの差分メモ

- `Job.runs_on` に span が存在しない制約は SEC005 等でも既に妥協されている既知のものであり、本ルールも同様に job span へフォールバックする。pinpoint 精度向上のため `Job.runs_on_span` を追加する作業は parser / types 横断変更となるため別 PR に分離する（本設計書では非スコープ）。
- `Engine` が `Config` を check 関数に渡さない設計上の制約は、SC003 系 advisory 群がモジュール状態で回避済みの既知パターンである。本ルールもその踏襲に留め、Engine API の変更は行わない。
- `Visibility` 設定は SEC020 以降の public 限定ルール（例: fork-accessible trigger 前提の他 SEC 候補、PERM 系の write 権限厳格化）でも再利用余地があり、将来拡張時の共有資産となる。
