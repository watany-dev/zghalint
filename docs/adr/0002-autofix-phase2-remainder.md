# 0002. autofix Phase 2 残り（PERM001 追加 / BP004 / PERF001）

- Status: Accepted
- Date: 2026-04-19
- Deciders: grill-me セッション（2026-04-19）

## Context

autofix 実装計画のうち、Phase 1（置換系 5 件）と Phase 2 前半（挿入系 3 件、ADR 0001）が完全実装済み。残る Phase 2 のうち、`PERM001` 部分実装の完成、`BP004`、`PERF001` の 3 件を本 ADR の対象とする。

これらは (a) ネットワーク依存でなく、(b) 既存 `fix_builder` helper で実装できる見込みで、(c) パターン変換系（Phase 3: `EXPR006/007`, `SEC014`）に比べて誤爆リスクが読みやすい。本 ADR は grill-me セッションで確定した決定事項と根拠を記録する。

対応する実装プランは `/root/.claude/plans/autofix-smooth-gray.md`、横断設計書は実装時に `docs/design/autofix-phase2-remainder-design.md` として作成する。

## Decisions

### D1. スコープは Phase 2 残りの 3 ルールに限定する

- 対象: PERM001 追加対応、BP004、PERF001（setup-go のみ）
- 非対象: Phase 3（EXPR006/007, SEC014）、ネットワーク依存系（SEC001, SC001/003/006）、PERF001 の setup-node/setup-python（lockfile 検出基盤が必要）
- 根拠: 3 件はすべて local / deterministic なコンテンツ変換で完結し、ADR 0001 と同じコミット分割で進められる。Phase 3 とネットワーク系は別設計に切り出す

### D2. 実装順序は PERM001 → BP004 → PERF001 とする

- 根拠:
  - PERM001 は既存 `makeWriteAllFix` の延長で最小の設計コストから着手できる
  - BP004 は既存 `Step.shell_insertion_byte` が揃っており、`shell` 既定値ポリシーさえ決まれば 1 Edit で終わる
  - PERF001 は `with:` 有無の 2 ケースを扱う必要があり、最も実装が重い
- 各ルール独立コミット。Tidy First 的な parser 拡張の先行投入はしない（PERM001 の `PermissionsMeta` は PERM001 自身のコミットに含める）

### D3. PERM001 追加: 検出を 14 フィールドに拡張し、id-token 除く 13 で unsafe fix

- 検出: 現状 10 フィールドから全 14 フィールド（`attestations`, `discussions`, `pages`, `repository_projects` を追加）へ拡張
- autofix 対象: `id-token` を除く 13 フィールド。`write` を `read` に value-span 置換（unsafe）
- `id-token: write` は検出を残すが、仕様上 `read` が存在しないため autofix は付けず、専用 fix_hint で OIDC 用途を案内
- severity は `.info` 維持（個別 write は意図的なケースが多く、昇格は出力ノイズ）
- 根拠:
  - 4 フィールド未検出は既存ルールの gap で、Tidy First 的に同時解消する価値がある
  - `id-token: read` は GitHub Actions 仕様で存在せず、機械的置換は誤誘導になる
  - fix を `.unsafe` に寄せることで `--fix` の safety 契約を守る（write は意図があって書かれている想定）

### D4. PERM001 追加: 個別 value span 保持は `PermissionsMeta` を新設

- `Workflow.permissions_meta: ?PermissionsMeta` と `Job.permissions_meta: ?PermissionsMeta` を追加
- 各 14 フィールド分の `*_value_span: ?yaml_types.Span` を保持
- 既存 `env_meta: ?ScalarValueMetaMap`（`src/workflow/types.zig:294,321`）と同じ「meta 並行保持」パターン
- 対立案（`PermissionLevel` を構造体化 / 10 個の `*_value_span` を `Permissions` に直接追加）は却下: 前者は既存コードの API 互換を壊す、後者は冗長で env_meta 方針と揃わない
- fix 粒度は per-field（診断 1 件に fix 1 件）。composite fix は現状の診断シェイプを変えるため不採用

### D5. BP004: step 単位に `shell: bash` を挿入する unsafe fix

- 挿入値: `bash`（`pwsh` は POSIX スクリプトへの誤爆が大きい）
- 挿入スコープ: 各 step の `shell_insertion_byte` に直接挿入。`defaults.run.shell` のジョブ単位設定は採用しない（構造挿入が重く、他 step に副作用が出る）
- 根拠:
  - `bash` は全 runner（ubuntu / macOS / Windows の Git Bash）で利用可能で、GitHub 公式が cross-platform の既定値として推奨
  - `run:` 内容の推論（bash vs pwsh）は本質的に曖昧で unsafe の許容範囲を超える
  - step 単位は `SEC015`（`persist-credentials`）と同じ形状で、既存 `fix_builder.insertMappingEntry` で実装できる
  - parser 拡張は不要（既存 `Step.shell_insertion_byte` / `Step.uses_key_col` / `Step.span` で完結）

### D6. PERF001: `actions/setup-go` のみ `cache: true` を付与する unsafe fix

- 対象: `actions/setup-go` のみ。`actions/setup-node` / `actions/setup-python` は lockfile 検出を要し、wrong-guess で CI が赤く落ちる破壊性を持つため本 ADR のスコープ外
- 挿入値: `cache: true`（setup-go は lockfile 不要で universally 有効）
- 挿入戦略: `with:` あり → append、`with:` なし → block 新設（`fix_builder.appendMappingEntry` と `insertMappingEntryBlock` を使い分ける）
- 診断シェイプ: 既存の「job 単位 / setup 種別ごとに 1 診断」を維持。同一ジョブ内の複数 setup-go step は単一 multi-edit fix で一括書き換え
- 根拠:
  - setup-go の `cache: true` は確実に動くため価値が出やすい
  - setup-node/python は lockfile 基盤が別設計として必要で、本 ADR と切り離した方が進捗が安定する
  - 診断シェイプを変えない（ユーザー可視の CI 出力が不変）
  - parser 拡張は不要（既存 `Step.uses_value_end_byte` / `with_last_entry_end_byte` で完結）

### D7. コミットは 5 分割（+ ドキュメント更新コミット）する

1. PERM001 追加対応（parser: `PermissionsMeta` + rule + Zig インラインテスト）
2. BP004 autofix（rule + Zig インラインテスト、parser 変更なし）
3. PERF001 autofix（rule + Zig インラインテスト、parser 変更なし）
4. PBT 強化（strategies 3 個追加、`--fix-unsafe` 冪等 PBT 追加）
5. ドキュメント更新（本 ADR、`autofix-phase2-remainder-design.md` 新規、`pbt-strategy.md` のステータス更新）

各コミットで CLAUDE.md の CI ゲート（`zig build && zig fmt --check src/ build.zig && zig build test --summary all`）を通す。コミット 4 以降は `python -m pytest tests/pbt/` も通す。

### D8. テストは Zig インライン 3 層 + PBT 拡張

- 各ルールで (a) 診断検出と fix 付与 (b) `Fix.safety` と Edit 内容 (c) `fix_engine.applyFixes` 経由の YAML 一致 を検証
- `tests/pbt/strategies.py` に `workflow_with_perm001_individual_write`, `workflow_with_bp004`, `workflow_with_perf001_setup_go` を追加
- `tests/pbt/test_autofix_idempotency.py` に 3 ルール分の `test_unsafe_fix_reduces_diagnostics` / `test_double_unsafe_fix_is_idempotent` を追加
- 既知 xfail `test_fix_does_not_crash`（`docs/design/pbt-strategy.md` §5 #1）には手を入れない。踏んだ場合は個別 xfail を広げず、Zig インラインテスト側に回帰ケースとして抜き出す（ADR 0001 § D7 と同方針）

## Consequences

### Positive

- 完全実装済みルール数が 12 → 15 に、部分実装が 1 → 0 になり、autofix カバレッジが 42 診断 ID 中で明確に前進する
- parser 拡張は PERM001 の `PermissionsMeta` のみで、BP004 / PERF001 は既存 span の再利用で済む（Phase 2 前半で投入済みの資産が活きる）
- PBT ルールカバレッジが 5 → 8 に拡大し、`docs/design/pbt-strategy.md` §5 #3 の進捗が進む
- `id-token` を autofix 対象外にしたことで、OIDC 利用ワークフローを壊さない

### Negative / Risks

- PERM001 の個別 `write → read` 降格は `.unsafe` でも実行時にジョブを壊しうる（write が必要なケース）。`--fix-unsafe` 利用者は既にリスクを許容しているが、README / fix_hint での注意喚起は別タスクとして残る
- BP004 の `bash` 固定は、Windows で cmd / pwsh 前提の `run:` を壊すリスクがある。unsafe 分類と fix_hint で緩和するが、誤爆時は手戻りが発生する
- PERF001 を setup-go のみに限定したことで、node / python 使用者からは「なぜ自分の setup にも autofix が出ないのか」という疑問が出得る。将来 lockfile 検出基盤を導入した段階で拡張する方針を design doc に明記する
- `PermissionsMeta` 追加によるメモリ増加は軽微だが、全 workflow で持つため ReleaseSafe での bench 差分は更新時にチェック対象

## References

- `/root/.claude/plans/autofix-smooth-gray.md` — 対応する実装プラン
- `docs/design/autofix-phase2-insertion-design.md` — Phase 2 前半の横断設計（本 ADR のテンプレート）
- `docs/adr/0001-autofix-phase2-insertion-rules.md` — Phase 2 前半の ADR
- `docs/design/pbt-strategy.md` — PBT 戦略、既知 xfail 一覧
- `src/workflow/types.zig:22-41` — `Permissions`（全 14 フィールド）
- `src/workflow/types.zig:227-258` — `Step`（`span` / `shell_insertion_byte` / `uses_value_end_byte` / `with_last_entry_end_byte`）
- `src/workflow/parser.zig:446-479` — `parsePermissions`（本 ADR で meta 格納を追加する箇所）
- `src/fix/builder.zig` — `replaceScalar` / `insertMappingEntry` / `insertMappingEntryBlock` / `appendMappingEntry`
- `src/rules/permissions.zig:35-89` — PERM001 現行実装
- `src/rules/best_practices.zig:204-217, 313-320` — BP004 現行実装
- `src/rules/performance.zig:30-69` — PERF001 現行実装
