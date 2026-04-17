# autofix実装計画書

## 目的

GitHub Actions / Dependabot 向けルールのうち、autofix が未実装または部分実装の診断を棚卸しし、`実装可否`、`難易度`、`優先度` を付けて段階的に実装できるようにする。

## 対象と集計単位

- 集計単位は CLI 上の「ルール数」ではなく、最終的に `Diagnostic.rule_id` として出力される診断 ID 単位とする
- `docs/rules.md` の 38 rules に対し、autofix 設計上の対象診断 ID は 42 件ある
- 差分の理由は `EXPR` がエンジン上は 1 ルールだが、`EXPR001` から `EXPR007` を個別診断として出力しているため

## 現状サマリ

| 区分 | 件数 | 備考 |
|------|------|------|
| autofix 完全実装済み | 8 | `BP001`, `BP002`, `BP003`, `SEC004`, `SEC015`, `SEC017`, `DEP002`, `PERF003` |
| autofix 部分実装 | 1 | `PERM001` は `write-all` のみ対応 |
| autofix 未着手 | 33 | fix hint のみ、または診断のみ |
| autofix 追加対象合計 | 34 | 部分実装の `PERM001` を含む |

## 既存 autofix 実装

| ID | 状態 | 実装ファイル | 内容 |
|----|------|-------------|------|
| `BP001` | 完全実装 | `src/rules/best_practices.zig` | job 先頭へ `timeout-minutes: 30` を挿入 |
| `BP002` | 完全実装 | `src/rules/best_practices.zig` | step 先頭へ生成した `name:` を挿入（`uses` 起点のみ） |
| `BP003` | 完全実装 | `src/rules/best_practices.zig` | `uses:` の deprecated version を置換表で更新 |
| `PERM001` | 部分実装 | `src/rules/permissions.zig` | `write-all` を `{contents: read}` に置換 |
| `SEC004` | 完全実装 | `src/rules/security.zig` | `permissions: write-all` を `{contents: read}` に置換 |
| `SEC015` | 完全実装 | `src/rules/security.zig` | checkout step に `persist-credentials: false` を挿入 |
| `SEC017` | 完全実装 | `src/rules/security.zig` | `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` を `false` に置換 |
| `DEP002` | 完全実装 | `src/rules/dependabot.zig` | `insecure-external-code-execution: allow` を `deny` に置換 |
| `PERF003` | 完全実装 | `src/rules/performance.zig` | `fail-fast: false` エントリを削除（unsafe） |

## 評価基準

### 実装可否

- `可`: 現在の edit-based autofix 基盤で実装可能。追加 span が少なく、機械的変換が明確
- `条件付き可`: 追加の span 採取、unsafe fix ポリシー、またはネットワーク依存が必要
- `不可/非推奨`: 汎用の機械修正が不明確。誤修正リスクが高い

### 難易度

- `低`: 単純な挿入・置換・削除で済む
- `中`: parser / span 拡張や条件分岐が必要
- `高`: 構文変換、外部解決、意味推論、または unsafe 判定が重い

### 優先度

- `高`: 価値が高く、実装コストに対して効果が大きい
- `中`: 効果はあるが、前提作業や unsafe 判定が必要
- `低`: 効果が限定的、または誤修正リスクが高い

## 未実装・不足一覧

### Security / Supply Chain

| ID | 現状 | 実装可否 | 難易度 | 優先度 | 方針 |
|----|------|----------|--------|--------|------|
| `SEC001` | 未実装 | 条件付き可 | 高 | 低 | tag/branch を SHA に pin するには GitHub API 参照が必要。`--fix-unsafe` 前提 |
| `SEC002` | 未実装 | 不可/非推奨 | 高 | 低 | `run:` の安全な書き換え方が一意に定まらない |
| `SEC003` | 未実装 | 不可/非推奨 | 高 | 低 | secret 名を決められず機械修正不可 |
| `SEC005` | 未実装 | 不可/非推奨 | 高 | 低 | trigger 変更や checkout 方針変更は意味変更が大きい |
| `SEC006` | 未実装 | 不可/非推奨 | 高 | 低 | `if:` 条件の安全な書き換えを一般化しづらい |
| `SEC007` | 未実装 | 条件付き可 | 中 | 中 | workflow 先頭へ最小 `permissions` を挿入できるが、実質 unsafe |
| `SEC008` | 未実装 | 不可/非推奨 | 高 | 低 | `GITHUB_ENV` / `GITHUB_PATH` への書き込みは安全な代替が文脈依存 |
| `SEC010` | 未実装 | 不可/非推奨 | 高 | 低 | `secrets: inherit` を明示列挙へ変換するには secret 一覧が必要 |
| `SEC011` | 未実装 | 不可/非推奨 | 高 | 低 | どの個別 secret に分解すべきか推定不能 |
| `SEC012` | 未実装 | 不可/非推奨 | 高 | 低 | `toJSON/fromJSON` 置換はワークフロー意図に強く依存 |
| `SEC013` | 未実装 | 不可/非推奨 | 高 | 低 | credentials をどの secret に置き換えるか決められない |
| `SEC014` | 未実装 | 条件付き可 | 高 | 低 | `github.actor` を `github.event.sender.type` 等へ書き換えるには式パターン限定が必要 |
| `SEC016` | 未実装 | 不可/非推奨 | 高 | 低 | cache 削除や trigger 制限は意味変更が大きい |
| `SEC017` | 未実装 | 条件付き可 | 中 | 高 | workflow parser / model に `env` value span/style を保持すれば `false` 置換で対応可能。個別設計: `docs/design/sec017-autofix-design.md` |
| `SEC019` | 未実装 | 不可/非推奨 | 高 | 低 | `env:` へ持ち上げるには参照名の決定と複数箇所書換えが必要 |
| `SC001` | 未実装 | 条件付き可 | 高 | 低 | digest 解決にレジストリ参照が必要。ネットワーク依存 |
| `SC003` | 未実装 | 条件付き可 | 高 | 低 | advisory の patched version がある場合のみ候補生成可能。unsafe 寄り |
| `SC004` | 未実装 | 不可/非推奨 | 高 | 低 | 代替 action を決められない |
| `SC005` | 未実装 | 不可/非推奨 | 高 | 低 | stale SHA を何へ置き換えるべきか自動判断できない |
| `SC006` | 未実装 | 条件付き可 | 高 | 低 | ambiguous ref を SHA に固定するには外部解決が必要 |

### Performance / Best Practices / Permissions / Dependabot / Expressions

| ID | 現状 | 実装可否 | 難易度 | 優先度 | 方針 |
|----|------|----------|--------|--------|------|
| `PERF001` | 未実装 | 条件付き可 | 中 | 中 | `setup-*` に `cache:` を足せるが値の選定が言語・パッケージマネージャ依存 |
| `PERF002` | 未実装 | 不可/非推奨 | 高 | 低 | redundant checkout を削除するか `path` を足すかが文脈依存 |
| `PERF003` | 未実装 | 可 | 低 | 高 | `fail-fast: false` の削除、または `true` 置換で対応可能。unsafe fix 扱いが妥当 |
| `BP002` | 未実装 | 可 | 中 | 高 | `uses` の action 名、または `run` 先頭行から step 名を生成して挿入できる。個別設計: `docs/design/bp002-autofix-design.md` |
| `BP003` | 未実装 | 可 | 中 | 高 | 既知の置換表があるため `uses:` の version 部分を機械置換できる。個別設計: `docs/design/bp003-autofix-design.md` |
| `BP004` | 未実装 | 条件付き可 | 中 | 中 | `shell: bash` / `pwsh` のどちらを入れるか方針決めが必要 |
| `BP005` | 未実装 | 条件付き可 | 中 | 中 | workflow に標準 `concurrency` ブロックを挿入可能だが挙動変更が大きい |
| `BP007` | 未実装 | 不可/非推奨 | 高 | 低 | obfuscated 実行の安全な代替コマンドは自動生成できない |
| `PERM001` | 部分実装 | 条件付き可 | 中 | 中 | 個別 `write` を `read` へ落とす autofix は可能だが unsafe |
| `PERM002` | 未実装 | 条件付き可 | 中 | 中 | job-level `permissions` を挿入できるが最低権限の決定は unsafe |
| `DEP001` | 未実装 | 条件付き可 | 中 | 中 | `cooldown` ブロックの雛形挿入は可能だが運用ポリシー依存 |
| `DEP002` | 未実装 | 可 | 低 | 高 | `insecure-external-code-execution: allow` を `deny` へ置換、または削除で対応可能。個別設計: `docs/design/dep002-autofix-design.md` |
| `EXPR001` | 未実装 | 不可/非推奨 | 高 | 低 | 構文エラーの正解を機械推定できない |
| `EXPR002` | 未実装 | 不可/非推奨 | 高 | 低 | unknown context の正しい候補が文脈依存 |
| `EXPR003` | 未実装 | 不可/非推奨 | 高 | 低 | property 名の typo 自動修正は誤爆しやすい |
| `EXPR004` | 未実装 | 不可/非推奨 | 高 | 低 | unknown function の候補生成が不安定 |
| `EXPR005` | 未実装 | 不可/非推奨 | 高 | 低 | 引数追加・削除の正解を決められない |
| `EXPR006` | 未実装 | 条件付き可 | 高 | 中 | `contains()` を `==` や `startsWith()` に変換できるのは一部パターンのみ |
| `EXPR007` | 未実装 | 条件付き可 | 高 | 中 | `a == 'x' || 'y'` 系の限定パターンなら機械展開できる |

## 優先実装候補

### Phase 1: 先に着手すべきもの

| ID | 理由 |
|----|------|
| `SEC017` | `env` value span/style の最小拡張で着手でき、セキュリティ効果が高い |
| `DEP002` | Dependabot 設定の 1 箇所置換で済む |
| `PERF003` | 単純削除で済み、edit も作りやすい |
| `BP003` | 既存の置換表をそのまま使える |
| `BP002` | 生成ロジックは必要だが、ローカル情報だけで完結する |

### Phase 2: unsafe fix と insertion 系の拡張

| ID | 理由 |
|----|------|
| `SEC007` | workflow-level `permissions` ひな形挿入 |
| `PERM002` | job-level `permissions` ひな形挿入 |
| `DEP001` | `cooldown` 雛形挿入 |
| `BP005` | `concurrency` 雛形挿入 |
| `BP004` | `shell` 既定値ポリシー確立後に実装 |
| `PERM001` | 個別 `write` を `read` へ落とす unsafe fix |
| `PERF001` | `cache:` の既定値ポリシー確立後に実装 |

### Phase 3: 条件付きパターン変換

| ID | 理由 |
|----|------|
| `EXPR007` | 限定パターンでの式展開が可能 |
| `EXPR006` | 一部の `contains()` を safer な比較へ変換できる |
| `SEC014` | 一部の bot 判定式だけを対象にした rewrite が考えられる |

### Backlog: ネットワーク依存 or 非推奨

- `SEC001`, `SC001`, `SC003`, `SC006`
- `SEC002`, `SEC003`, `SEC005`, `SEC006`, `SEC008`, `SEC010`, `SEC011`, `SEC012`, `SEC013`, `SEC016`, `SEC019`
- `SC004`, `SC005`
- `PERF002`, `BP007`
- `EXPR001`, `EXPR002`, `EXPR003`, `EXPR004`, `EXPR005`

## 実装前提として必要な基盤拡張

### 1. span / byte offset の拡張

現在の parser が保持している autofix 用の位置情報は次に限られる。

- `Job.span`
- `Permissions.value_span`
- `Step.uses_key_col`
- `Step.uses_value_end_byte`
- `Step.with_last_entry_end_byte`

次の autofix を増やすには、少なくとも以下の span を追加で保持したい。

- `Step.span`
- `Step.name` の有無だけでなく step mapping 全体の開始位置
- `uses:` scalar の開始・終了 byte
- `run`, `shell`, `if`, `env` 各フィールドの key/value span
- `strategy.fail-fast` の value span
- workflow top-level への挿入位置
- job-level `permissions`, `concurrency` の挿入位置
- Dependabot `updates` entry 内の key/value span

### 2. edit builder の共通化

既存の `BP001`, `SEC004`, `SEC015`, `PERM001` は各ルール内で直接 edit を組み立てている。autofix 件数を増やす前に、以下の helper を共通化したい。

- scalar 置換
- mapping entry の追加
- mapping entry の削除
- key 直後 / mapping 末尾への安全な挿入
- インデント計算

## unsafe fix の扱い

- `--fix` は semantics-preserving な fix のみ
- `--fix-unsafe` は挙動変更を伴う fix を許可
- 初期実装では以下を unsafe 扱いに寄せる
  - `PERF003`
  - `SEC007`
  - `PERM001` の個別 `write -> read`
  - `PERM002`
  - `DEP001`
  - `BP004`
  - `BP005`
  - `PERF001`

## 推奨実装順

1. `SEC017`, `DEP002`, `PERF003`, `BP003`, `BP002`
2. span 拡張と共通 edit builder 抽出
3. `SEC007`, `PERM002`, `DEP001`, `BP005`, `PERM001` 追加対応
4. 条件付き変換として `EXPR007`, `EXPR006`, `SEC014` を検討
5. ネットワーク依存 autofix は別設計として切り出す

## TDD 方針

各 rule の autofix 実装は次の 3 層でテストする。

1. 診断に `fix` が付くこと
2. `Fix.safety` と `Edit` の内容が期待通りであること
3. `fix/engine.zig` 経由で YAML へ適用した結果が期待通りであること

最低限、既存の `BP001`, `SEC004`, `SEC015`, `PERM001` と同じ粒度の integration test を新規 rule にも揃える。

## 結論

短期で価値が出るのは、単純置換または局所挿入で完結する `DEP002`, `PERF003`, `BP003`, `BP002` と、最小の env span/style 拡張で実装できる `SEC017` である。  
一方で、security 系の多くと network 依存の supply chain 系は、汎用 autofix より fix hint に留める方が安全である。  
したがって、まずは local / deterministic な autofix を広げ、その後に unsafe fix と span 拡張へ進むのが妥当である。
