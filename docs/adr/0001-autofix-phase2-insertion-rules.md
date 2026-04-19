# 0001. autofix Phase 2 挿入系ルール（BP005 / PERM002 / DEP001）

- Status: Accepted
- Date: 2026-04-19
- Deciders: grill-me セッション（2026-04-19）

## Context

`docs/design/autofix-implementation-plan.md` の Phase 1（SEC017, DEP002, PERF003, BP003, BP002）は完全実装済み。
次に進める autofix として、挿入系 unsafe fix を束ねた Phase 2 の先頭 3 ルール（BP005, PERM002, DEP001）を対象にする。

これらは共通して「既存の mapping に block 形式の新規エントリを挿入する」挙動であり、専用 helper を整備することで以降の BP004 / PERM001 残 / PERF001 への足場になる。

本 ADR は grill-me セッションで確定した決定事項とその根拠を記録する。実装プランは `/root/.claude/plans/autofix-floofy-sundae.md` に別途存在する。

## Decisions

### D1. スコープは Phase 2 のうち挿入系 3 ルールに限定する

- 対象: BP005（workflow 先頭 concurrency）、PERM002（job 先頭 permissions）、DEP001（dependabot entry 末尾 cooldown）
- 非対象: BP004, PERM001 残, PERF001
- 根拠: 3 ルールは「mapping への block 挿入」で共通化でき、builder を 1 回拡張すれば横展開できる。同一イテレーションで BP004 / PERF001 を混ぜると挿入以外の判断（shell 種別、cache キー）が入って焦点がぼける

### D2. Fix safety は 3 ルール全て unsafe とする

- 根拠:
  - BP005: concurrency 挿入は実行キャンセル挙動を変える
  - PERM002: permissions 追加は GITHUB_TOKEN スコープを変える
  - DEP001: cooldown は更新頻度を抑制する（タイミング変更）
- いずれも semantics preserving ではないため、SEC007 / PERF003 と同じく `--fix-unsafe` 必須に揃える
- 対立案: DEP001 は throttling だけで安全と見なす案もあったが、Dependabot の運用タイミングが変わることを明確な挙動変更と位置づける

### D3. YAML スタイルは block 形式（複数行）を採用する

- 各雛形は複数行 block として挿入する。flow 形式（1 行）は採用しない
- 根拠:
  - concurrency の `${{ github.workflow }}` を flow mapping に埋めると quote / escape の読みにくさが出る
  - block の方が diff が追いやすく、レビュー時のノイズが小さい
  - 既存の SEC007 は flow 形式（`{contents: read}`）を使っているが、PERM002 も同じ判断基準で書くと量が増えたときに破綻するため、Phase 2 から block に寄せる
- 代償: `fix_builder` に block 対応ヘルパー `insertMappingEntryBlock` を追加する必要がある

### D4. 雛形内容

| ルール | 雛形 |
|---|---|
| BP005 | `concurrency:`\n`  group: ${{ github.workflow }}-${{ github.ref }}`\n`  cancel-in-progress: ${{ github.event_name == 'pull_request' }}` |
| PERM002 | `permissions:`\n`  contents: read` |
| DEP001 | `cooldown:`\n`  default-days: 7` |

- BP005: `cancel-in-progress` を PR 限定にする式を採用。main ブランチの連続 push で前の run を潰すと deploy フローを壊す可能性があるため
- PERM002: SEC007 と同等の最小権限（`contents: read`）に揃える。action 毎の推定はスコープ外
- DEP001: `default-days: 7` のみ。`semver-major-days` などの詳細分岐はユーザが後から微調整しやすいよう避ける

### D5. 同 byte 挿入衰突は現状維持で PBT により構文保全を確認する

- `Workflow.permissions_insertion_byte` と `Workflow.concurrency_insertion_byte` は parser 上同一 byte を指す（`src/workflow/parser.zig:59-60`）
- SEC007 と BP005 が同時発火すると同 byte への zero-length 挿入が 2 件発生する
- fix engine（`src/fix/engine.zig:44-92`）の overlap 判定は `start_byte < last_end` でありゼロ幅の同一位置は両方とも通る。結果として両 block が隣接する順に並ぶ
- 決定: engine 側の順序決定や parser 側 anchor 分離は行わず、PBT + ゴールデンテストで「再 parse 可能 / 診断単調減少」を維持条件として検証する
- 根拠: parser を変えると影響範囲が広く、engine の順序付けは将来の挿入全般に波及する設計判断になる。現在の必要性に対してコスト過大

### D6. コミットは 5 分割（+ ドキュメント更新コミット）する

1. `src/fix/builder.zig` に `insertMappingEntryBlock` 追加（Tidy First）
2. BP005 autofix
3. PERM002 autofix
4. DEP001 autofix
5. PBT 強化（strategies と `--fix-unsafe` 対応 PBT）
6. ドキュメント更新（`autofix-implementation-plan.md` のステータス反映、Phase 2 横断設計書の新規作成、`pbt-strategy.md` カバレッジ表追記）

各コミットで CLAUDE.md の CI ゲート（`zig build && zig fmt --check && zig build test --summary all`）を通す。

### D7. テストは Zig インラインの 3 層 + PBT 拡張

- 各 `src/rules/*.zig` で (a) 診断検出 (b) fix メタデータ (c) `fix_engine.applyFixes` 経由の YAML 一致 を検証
- PBT は `--fix-unsafe` 版の `test_unsafe_fix_reduces_diagnostics` と `test_double_unsafe_fix_is_idempotent` を新設
- `tests/pbt/strategies.py` に `workflow_with_bp005`, `workflow_with_perm002`, `workflow_with_dep001` を追加
- 既存 xfail `test_fix_does_not_crash`（`fix/engine.zig` segfault）には本プランで手を入れない。別タスク（`docs/design/pbt-strategy.md` §5 #1）として残す

## Consequences

### Positive

- block 形式挿入の共通基盤ができるため、以降の BP004 / PERM001 / PERF001 は同 helper で実装できる
- 3 ルールが autofix 対象になり、完全実装済みルール数が 9 → 12 に増える
- PBT に `--fix-unsafe` 経路と挿入系 strategy が加わり、`pbt-strategy.md` §5 #3（PERM/BP/PERF の PBT）の一部が進む

### Negative / Risks

- 同 byte 衰突時の順序が engine の sort 安定性に依存する。将来 engine の sort を変えたら回帰する可能性があるため、ゴールデンテストでピン止めが必要
- `--fix-unsafe` PBT が既存 segfault（xfail #1）を踏む可能性。踏んだ場合は個別 xfail を広げずに、インラインテスト側に回帰ケースとして抜き出す運用とする
- PERM002 の `contents: read` 固定は過小権限になるケースがある（例: release を作る action）。ユーザは `--fix-unsafe` 適用後に手で調整する必要がある。README / fix_hint でのアナウンスは別タスク

## References

- `/root/.claude/plans/autofix-floofy-sundae.md` — 対応する実装プラン
- `docs/design/autofix-implementation-plan.md` — 42 診断 ID 棚卸し、Phase 1-3 の優先度付け
- `docs/design/pbt-strategy.md` — PBT 戦略、既知 xfail 一覧
- `docs/design/bp002-autofix-design.md`, `bp003-autofix-design.md`, `dep002-autofix-design.md` — Phase 1 per-rule 設計書（本 ADR は Phase 2 を束ねる位置づけ）
- `src/fix/builder.zig` — 既存 edit builder
- `src/fix/engine.zig:44-92` — overlap 検出と back-to-front 適用
- `src/workflow/parser.zig:55-65, 278-299` — insertion byte 設定
- `src/yaml/types.zig:71-78` — `MappingEntry.full_span`
- `src/rules/security.zig:322-348` — SEC007（workflow-top 挿入の参考実装）
- `src/rules/best_practices.zig:240-258` — BP005 現行（fix 未付与）
- `src/rules/permissions.zig:94-114` — PERM002 現行（fix 未付与）
- `src/rules/dependabot.zig:17-40` — DEP001 現行（fix 未付与）
