# 0004. Security Gap Fill: SEC018 / SEC021 / SC002 / SC007

- Status: Accepted
- Date: 2026-04-19
- Deciders: grill-me セッション（2026-04-19）

## Context

zghalint は現在 SEC001–SEC020（SEC018 欠番）、SC001/003–006、PERM001–002、DEP001–002 を実装しており、合計 45 ルールでかなり広い範囲をカバーしている。しかし先行ツール（zizmor / poutine / StepSecurity）と照合すると、**実害頻度が高いにもかかわらず未カバー**な領域が 4 つ残っている。

1. `actions/checkout` のデフォルト `persist-credentials: true` に起因する `GITHUB_TOKEN` の `.git/config` 永続化問題
2. `actions/checkout` の `ref:` / `repository:` に untrusted input が流れる攻撃面（SEC005/SEC009 でカバーしきれないトリガー）
3. tj-actions/changed-files（2025-03）級の**既知侵害 action を SHA 単位で止める**仕組み
4. 公式人気 action 名への **typosquat** 検出

本 ADR は grill-me セッションで確定したこれら 4 ルールの設計判断と根拠を記録する。

## Interview Summary

インタビューの分岐点と選択結果:

1. **方向性**: A（網羅性の穴埋め）を採用 — B（新領域）/C（インシデント駆動）/D（運用性向上）は却下
2. **ギャップ領域**: A2a（Checkout 安全性）+ A2c（Typosquat / 禁止リスト）を採用 — A2b/A2d/A2e は見送り
3. **A2a の具体ルール**: A2a-1（persist-credentials）+ A2a-3（untrusted checkout ref）を採用 — A2a-2/A2a-4 は見送り
4. **A2c の具体ルール**: A2c-1（既知侵害ブロックリスト）+ A2c-2（typosquat）を採用 — A2c-3/A2c-4 は見送り
5. **ID / severity**: 既存欠番埋め方針（SEC018 / SC002）+ 次番（SEC021 / SC007）
6. **データ配置**: Zig ソース定数配列（外部 JSON / ネットワーク API は却下）
7. **Autofix 範囲**: SEC018 のみ（他 3 ルールは機械的修正が安全ではない）

## Decisions

### D1. Rule ID 採番: SEC018 / SEC021 / SC002 / SC007

- **SEC018**: `docs/rules.md` 時点で SEC018 が唯一の欠番。穴埋めで連番を整える
- **SEC021**: SEC001–SEC020 の次。新規枠
- **SC002**: SC001（unpinned-images）と SC003（known-vulnerable-action）の間の欠番を埋める
- **SC007**: SC001/003–006 の次。新規枠

欠番埋めにより `docs/rules.md` テーブルの見た目が整うだけでなく、将来「なぜこの番号が抜けているのか」という疑問を残さない。

### D2. Severity: SEC018=warning / SEC021=error / SC002=error / SC007=warning

| ID | severity | 根拠 |
|---|---|---|
| SEC018 | warning | `actions/checkout` のデフォルト挙動に起因する "穴" で、事故確率は高いが即時致命ではない。`fail-on-warning` で明示的に阻止可。SEC015（artipacked, warning）と整合 |
| SEC021 | error | untrusted input に基づく任意ref取得は exploit 直結。SEC005（dangerous-pr-target）/ SEC009（workflow-run-untrusted-checkout）と同クラス |
| SC002 | error | SHA/tag 完全一致による **高精度検知** のため false positive がゼロ。SC003（known-vulnerable-action, warning）は Advisory DB のバージョン範囲マッチで精度が低いため warning に留まるが、SC002 は "この SHA は絶対に侵害版" という確信度が構造的に error 相当 |
| SC007 | warning | Levenshtein 距離ベースで確信度が構造的に低い（legit fork の可能性あり）。SC006（ref-confusion, warning）と同級 |

### D3. Category: SEC 系は `security`、SC 系は `dependency`

既存慣例に完全準拠。`src/rules/archived.zig:195` で SC004 が `.category = .dependency` を使っている例と揃える。`diagnostics.zig:19` の `Category` enum に `supply_chain` は存在しないため、SC プレフィックスのルールは全て `.dependency` に分類される（これは既存慣例であり本 ADR で変更しない）。

### D4. Autofix は SEC018 のみ、safety は `.unsafe`

- **SEC018**: `with.persist-credentials: false` を追加する単純挿入 autofix を用意
- **SEC021 / SC002 / SC007**: autofix なし（機械的置換の意図保存が不可能）

**SEC018 を `.unsafe` とする根拠**:

`FixSafety`（`src/diagnostics.zig:36`）の定義上、`.safe` は "Semantics-preserving mechanical fix"、`.unsafe` は "Fix that may change behavior"。`persist-credentials: false` を追加すると、後続 step が `.git/config` に cache された `GITHUB_TOKEN` を使って `git push` や `gh` コマンドを実行しているワークフローでは動作が変わる。よって厳密には意味保存ではない。RUNNER001（ADR 0003 D4）と同様 `--fix-unsafe` でユーザの明示承認を必須にする。

### D5. SEC018 の検知範囲と autofix 戦略

**検知条件**:

1. `Step.uses` が `actions/checkout@*`
2. `Step.with` が `null` または `with.persist-credentials` キーが未設定 → 発火
3. `with.persist-credentials` が `"true"` を明示 → 発火（ただし autofix 不可）
4. `with.persist-credentials` が `"false"` を明示 → スキップ

**Autofix 戦略** (`.unsafe`):

| 状態 | 挿入点 | 挿入内容 |
|---|---|---|
| `with` = null | `Step.uses_value_end_byte` | `\n{indent}with:\n{indent+2}persist-credentials: false` |
| `with` 存在・キー未設定 | `Step.with_last_entry_end_byte` | `\n{indent+2}persist-credentials: false` |
| `persist-credentials: true` 明示 | — | autofix 不可（value span が `Step.with` StringMap に未保持）|

必要な Step フィールド (`uses_value_end_byte`, `with_last_entry_end_byte`, `uses_key_col`) は `src/workflow/types.zig:247-278` にすべて既存。parser 改修は不要。edge case の autofix 対応は将来 `with_meta: ?ScalarValueMetaMap` 追加時に対応する（Follow-up）。

### D6. SEC021 は SEC005 と重複排除する

- 対象: `uses: actions/checkout@*` な step の `with.ref` / `with.repository`
- 検知: 既存 `src/rules/security.zig` の `containsUntrustedContext` ヘルパ（280 行目付近）を流用
- **SEC005 との差分**: SEC005 は `on: pull_request_target` 前提。SEC021 は `workflow_dispatch` / `repository_dispatch` / `issues` / `issue_comment` などトリガー全般を対象
- **重複抑制**: 両方マッチする場合は SEC005 を優先し SEC021 はスキップ（同じ step で 2 発出さない）

### D7. SC002 は SHA / tag の完全一致で判定、`--offline` で動作

データ構造（`src/rules/data/compromised_actions.zig`）:

```zig
pub const CompromisedAction = struct {
    owner: []const u8,
    repo: []const u8,
    shas: []const []const u8,      // 侵害 SHA（完全一致）
    tags: []const []const u8,      // 侵害 tag（任意）
    advisory_url: []const u8,      // 参照 URL
    disclosed: []const u8,         // "2025-03-14"
};
```

- 判定ロジック: `owner/repo` 一致 ∧（`shas[]` に `ref` が完全一致 ∨ `tags[]` に一致）
- 診断メッセージに `advisory_url` と `disclosed` を含める
- ネットワーク I/O 不要。`--offline` でも動作
- 初期エントリは実装時に GHSA データベース / StepSecurity disclosures で最終確定（4-6 件で start）

### D8. SC007 は Levenshtein 距離 ≤ 2、初期は `owner == "actions"` に限定

データ構造（`src/rules/data/trusted_actions.zig`）:

```zig
pub const TrustedAction = struct {
    owner: []const u8,
    repo: []const u8,
};
```

- 判定ロジック: `trusted_actions[]` のいずれかの `{owner, repo}` に対し、Levenshtein 距離 ≤ 2 かつ完全一致でない
- **初期スコープは owner が `actions` の場合のみ**（`myorg/setup-node` のような正当 fork の誤検知を構造的に回避）
- 将来 trusted owner を拡張できる構造にする

初期エントリ 8 件:

- `actions/checkout`, `actions/setup-node`, `actions/setup-python`, `actions/setup-go`, `actions/setup-java`
- `actions/cache`, `actions/upload-artifact`, `actions/download-artifact`

### D9. データはソース埋込み、外部 JSON / API は不採用

検討案:

- 案1. **ソースコード埋込み**（採用）: `src/rules/data/*.zig` に定数配列
- 案2. 外部 JSON + `@embedFile`: 初期エントリ数が少ないため過剰
- 案3. GitHub API / StepSecurity API: `--offline` 方針と相容れない

採用理由: (1) 既存 `best_practices.zig:113` の `deprecated_actions` と一貫。(2) 初期エントリ数が小さい（侵害 6 件・人気 8 件）。(3) comptime 静的検証が効く。(4) 将来エントリが 100 件を超えたら案2 への移行を検討。

### D10. ドキュメント更新対象

- `docs/adr/0004-security-gap-fill-*.md`: 本 ADR（ADR 連番は `0003` の次。`0002-` が 2 つある既存混乱は無視して `0004` を採る）
- `docs/design/sec018-autofix-design.md`: SEC018 autofix 設計書（`sec017-autofix-design.md` の構成に倣う）
- `docs/rules.md`: **必須更新**。冒頭 "includes **45 rules**" → "**49 rules**"、Security / Supply Chain テーブルに 4 行追加
- `README.md`: ルール件数言及があれば 45→49 更新、新規 4 ルールを Changelog 的に追記

`docs/ROADMAP.md` / `docs/requirements.md` はリポジトリに存在しないため更新対象外。

### D11. テスト方針: 各ルール 3-5 件のインラインテスト

- **SEC018**: persist-credentials 未設定 / true / false + autofix 2 パターン（with null / with 存在）
- **SEC021**: untrusted ref hit / trusted ref pass / SEC005 との重複抑制
- **SC002**: 侵害 SHA hit / 未侵害 SHA pass / 別 owner pass / `--offline` 発火
- **SC007**: `actions/chekout` hit / `actions/checkout` pass / `myorg/chekout` pass（owner 外）

各ルール実装後に CLAUDE.md 必須の CI 3 点セット（`zig build && zig fmt --check && zig build test`）を通す。

### D12. コミット粒度と順序

Tidy → Red → Green → Refactor を各ルール単位で。推奨順序:

1. ADR + design doc（本コミット群）
2. SC002（データ + ルール）
3. SC007（データ + ルール + Levenshtein ヘルパ）
4. SEC021（検知のみ）
5. SEC018 検知
6. SEC018 autofix
7. `docs/rules.md` / `README.md` 更新

## Consequences

- zghalint のルール数が 45 → 49 に増える。`docs/rules.md` が単一情報源
- SC002 は tj-actions 事件再発時に**設定ゼロで即検知**できる状態になり、zghalint の主要セールスポイントの 1 つになる
- SEC018 の導入により既存ワークフローで大量の warning が出る可能性がある。severity を warning に留めた判断は、新規導入時の摩擦を抑えるため。`.zghalint.yml` で error 昇格は可能
- `persist-credentials: true` を明示しているワークフローに対して SEC018 の autofix は効かない。これは将来 `with_meta` 追加で対応する。現時点では診断のみ
- SC007 の Levenshtein 判定は owner=`actions` に限定したため、`actions/*` org を模した typosquat のみ検出。他 org（`docker`, `aws-actions` 等）への攻撃は検出しない。将来 trusted owner を拡張する

## Follow-up

- SC002 侵害 SHA リストの継続更新フロー（月次 PR, GHSA 自動同期など）
- SC007 の trusted owner 拡張（`docker/*`, `aws-actions/*` 等）
- SEC018 `persist-credentials: true` 明示ケースの autofix 対応（`Step.with` への `with_meta` 追加が前提）
- A2a-2（submodules + untrusted ref）, A2a-4（token 過剰スコープ）の追加検討

## 参考

- `docs/adr/0003-runner001-deprecated-runner.md` — 類似の ADR 構成・autofix unsafe 判断の先例
- `docs/design/sec017-autofix-design.md` — SEC018 autofix 設計書のテンプレート
- `docs/rules.md` — zghalint ルールカタログ（単一情報源）
- `src/rules/security.zig:1472` — `security_rules` 配列への追加箇所
- `src/workflow/types.zig:247-278` — `Step` 構造体（autofix 用 span すべて既存）
- tj-actions/changed-files incident (GHSA-mrrh-fwg8-r2c3, 2025-03-14)
- zizmor / poutine / StepSecurity（先行ツール）
