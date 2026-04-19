# 0004. PERF001 autofix 拡張: setup-node / setup-python / setup-go gating

- Status: Accepted
- Date: 2026-04-19
- Deciders: grill-me セッション / update-plan セッション（2026-04-19）

## Context

`PERF001` (cache-not-used) の autofix は現状 `actions/setup-go` のみ `cache: true`
を挿入する形で実装されている。`actions/setup-node` / `actions/setup-python` は
`cache` input に具体的なマネージャ名（`npm`/`yarn`/`pnpm`/`pip`/`pipenv`/`poetry`）
を要求するため、リポジトリ内の lockfile を検出して推論する仕組みが必要で、
`docs/design/autofix-implementation-plan.md` では「lockfile 検出基盤が前提」として
保留されていた。

本 ADR は grill-me / update-plan セッションで確定した、lockfile probe を導入して
setup-node / setup-python の autofix を解禁し、併せて setup-go の fix 条件を
引き締める決定を記録する。実装プランは `/root/.claude/plans/autofix-wobbly-neumann.md`
および `docs/design/perf001-lockfile-detection-design.md` を参照。

## Decisions

### D1. lockfile probe はプロセス起動時に1回だけ実施する

- `src/workspace.zig` にモジュール変数 `current: Context` を置き、`main.zig` の
  lint 前に populate する
- パターンは `src/rules/engine.zig` の `network_deadline_ns` を踏襲
- 根拠: rule 内で都度 FS access すると workflow × job × step のループ回数で
  probe が重複し遅くなる。probe は決定的で結果がプロセスライフタイムで不変

### D2. workspace root は `.git` walk-up で特定する

- 最初の workflow file パスから親方向へ `.git` を探索、見つからなければ cwd
  にフォールバック
- 根拠:
  - CI 環境（GitHub Actions 上で zghalint を実行）では cwd = repo root が
    通例だが、`zghalint path/to/specific.yml` と単発呼び出しされる開発者環境
    では cwd が repo root と一致しない
  - `.git` は Git 管理下のリポでは必ず存在する最も確実なマーカー

### D3. setup-go fix は go.sum 検出時のみ生成する

- 従来: `actions/setup-go` を見たら無条件で `cache: true` を提案
- 変更: `go.sum` がワークスペースにあるときのみ fix を生成
- 根拠:
  - `cache: true` は setup-go の default が go.mod dependency path を辿る挙動を
    前提にしているが、go.sum なしの状態で cache を有効化するとエラーになる
    ケースがある
  - 他の setup-* と対称（lockfile 前提）にしたほうが一貫性が高い
- トレードオフ: 既存ユーザーが `setup-go` 単独で fix を期待していた場合、
  go.sum 追加を別途求められる。diagnostic は従来通り出るので気づけない
  リスクは低い

### D4. 複数マネージャ検出時は fix 抑止 + fix_hint に lockfile 列挙

- 例: `package-lock.json` と `yarn.lock` が同居するリポ
- 採用: `fix` は null を返し、`fix_hint` に `Detected lockfiles: <names> —
  specify via .zghalint.yml rules.PERF001.node_cache_manager` を付加
- 却下案: マージ後の最新 lockfile を mtime で選ぶ（誤検出コストが高い）

### D5. `.zghalint.yml` で cache manager を明示上書き可能にする

- `rules.PERF001.node_cache_manager: pnpm` のように指定された場合、probe
  結果を無視してそれを採用
- 根拠: monorepo や lockfile 不在リポでもユーザーが意図を示せる退避路
- 実装: `src/config.zig` に `Perf001Override` を追加し、`main.zig` で probe
  結果にマージ

### D6. Fix safety は全て unsafe

- 根拠: lockfile 推論が決定的でも `cache:` 追加は CI runtime の挙動
  （キャッシュヒット率、デフォルトの restore-keys 戦略）を変更する
- 既存 setup-go fix と一貫性を保つ

### D7. probe エラーは `FileNotFound` 等を区別せず全て「不在」扱い

- `PermissionDenied` / `NotDir` などで errno を分類しない
- 根拠: probe 結果は「fix を能動的に生成するか」にしか使わず、曖昧なら fix
  抑止にフォールバックすれば安全側。errno の細分化は利得なし

### D8. ADR 番号衝突の解消

- 既存 `0002-sec009-workflow-run-untrusted-checkout.md` は `0002-autofix-phase2-remainder.md`
  と番号衝突していた
- 本 PERF001 ADR を採番する前に、Tidy First の独立コミットで
  `0002-sec009-*` → `0003-sec009-*` にリネーム
- 結果: SEC009 ADR = 0003、本 PERF001 ADR = 0004

## Alternatives considered

- **rule 内での都度 probe**: D1 で却下
- **`pyproject.toml` だけで poetry/pip 判定**: 実環境で判定が揺れるため非採用
- **`cache-dependency-path` 自動出力 (monorepo)**: 本イテレーションのスコープ外
- **`working-directory` を見た probe ルート切り替え**: 複雑化するため保留

## Consequences

- setup-node / setup-python の autofix カバレッジが 0% → lockfile ありリポで
  100% に引き上がる
- setup-go の fix は go.sum ありのときのみに絞られ、誤 fix が減る
- `src/workspace.zig` が新設され、将来的に別ルール（例: setup-java のキャッシュ、
  `working-directory` 解決）で再利用可能
- プロセス起動時に1回だけ FS access が増える（現実的にはミリ秒未満）

## Related

- `docs/design/perf001-lockfile-detection-design.md`（設計書）
- `docs/design/autofix-implementation-plan.md`（推奨実装順の更新）
- `src/workspace.zig`（実装）
- `src/rules/performance.zig`（fix dispatcher）
