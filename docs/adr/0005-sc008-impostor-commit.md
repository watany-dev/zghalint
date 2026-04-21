# 0005. SC008 impostor-commit 検知

- Status: Accepted
- Date: 2026-04-20
- Deciders: grill-me セッション（2026-04-20）

## Context

GitHub Actions で `uses: owner/repo@<sha>` と SHA pin してもサプライチェーン攻撃を完全には防げない。GitHub は upstream とその全 fork を**共有 object DB**で管理しており、fork 上あるいは未マージ PR の HEAD にしか存在しない commit も `/repos/{owner}/{repo}/commits/{sha}` で 200 を返す。結果として「SHA に pin しているから安全」という開発者の直感が裏切られ、attacker が upstream に存在しない悪意コミットを誘導できる。

この攻撃面は **impostor commit** と呼ばれ、zizmor や OpenSSF Scorecard で重大リスクとして扱われている。zghalint の既存 SC005（stale-action-refs）は「SHA に対応する tag が無い」を info で警告するが、**到達可能性（reachability）は見ていない**。tag が付いていない有効な commit（例: main HEAD や recent commit）を impostor として誤警告する一方、tag 付きの impostor（attacker が fork で tag を打った場合）を見落とす。

impostor commit を検出する独立ルール **SC008** を追加し、SHA pin の最後の防御線とする。

## Interview Summary

grill-me セッション（2026-04-20）で以下の分岐点を確定:

1. **Rule ID 採番**: ADR 0004 で SC007 を typosquat-action に予約済みのため、衝突回避で **SC008** を採用
2. **判定アルゴリズム**: **D'-full**（全 refs 到達可能性、Scorecard 方式と理論的に等価）を採用
3. **統合方式**: **α 案**（SC005 の GraphQL / prefetch / disk_cache パイプラインに相乗り）
4. **SC005 との重複**: **ii 案**（SC008 発火時に同一 SHA の SC005 info を drop）
5. **Pagination**: **a 案**（`pageInfo.hasNextPage` ベースの完全 pagination）
6. **Autofix**: **fix_hint にリッチ候補列挙**のみ、`Diagnostic.fix = null`
7. **デフォルト状態**: デフォルト有効、`.zghalint.yml` で severity override 可能

## Decisions

### D1. Rule ID = SC008, severity = warning, category = dependency

- **ID**: ADR 0004 が SC002（compromised-action）と SC007（typosquat-action）を予約済み。連番で SC008 を採用
- **severity**: `warning`（SC006 ref-confusion と同格）。API 失敗時は `unknown` に倒して fail-closed のため `error` は過剰
- **category**: `.dependency`（SC 系の既存慣例、ADR 0004 D3 参照）

### D2. 判定アルゴリズム D'-full（Scorecard 方式と理論等価）

以下の 4 ステップを順に評価し、短絡成立した時点で結論を返す:

1. **step1: tag target SHA 集合と一致** → `legitimate`
   - GraphQL で取得済みの `tagNodes[].target.oid`（SC005 用データ）を再利用
   - **ゼロ追加コスト**
2. **step2: branch HEAD OID 集合と一致** → `legitimate`
   - GraphQL で追加取得する `branchNodes[].target.oid` と一致
   - `/commits/{sha}/branches-where-head` の代替。**ゼロ追加 REST コスト**
3. **step3: `/compare/{default_branch}...{sha}` が `identical` or `behind`** → `legitimate`
   - 1 REST コール。最頻出ケース（main 直上コミット）に対する高速パス
4. **step4: 残る全 refs（branches + tags）に対し `/compare` 総当り**
   - どれかが `identical` / `behind` → `legitimate`
   - 全てが `ahead` / `diverged` → `impostor`
   - 失敗（404 / 403 / 429 / タイムアウト）→ `unknown`（診断抑制）
5. **deadline 到達 / API 失敗**: `unknown` に倒して fail-closed（偽陽性ゼロを優先）

#### A 案（Scorecard の `/commits/{sha}/branches-where-head` + `/commits/{sha}/pulls`）との等価性検討

A 案は 2 REST で済むが、private API 相当の endpoint に依存する。D'-full は公開 API のみで構成され、長期的に安定。到達可能性という一点では両者は理論的に等価（ref 集合の過渡的境界を無視すれば）。

### D3. 統合方式 α（SC005 パイプラインに相乗り）

- GraphQL クエリを **branches + pageInfo + defaultBranchRef** で拡張し、1 POST で tags/branches/default/archive を同時取得
- disk_cache も共有（24h TTL）
- compare は GraphQL 不能なので prefetch 内に新フェーズ `fetchImpostorCompares` を設ける
- **β 案**（SC008 独立パイプライン）は POST 数が倍増するため却下
- **γ 案**（即時 REST のみ）は cache が使えず低速なため却下

### D4. SC005 との重複抑制（ii 案）

impostor SHA は構造的に SC005 `no_tag` も必ず発火する（tag target 集合に含まれないことが impostor 判定の必要条件の 1 つ）。ノイズ回避のため `engine.postProcess` で SC008 発火済みの `(owner, repo, sha)` に対応する SC005 info を drop する。

- **i 案**（両方出す）: 同じ問題で 2 診断、ユーザ体験を損なう
- **ii 案**（SC005 を drop）: **採用**。SC008 のほうが上位概念
- **iii 案**（SC005 を drop + SC008 メッセージに tag 情報を追記）: 将来検討、初期実装は簡潔さ優先
- **iv 案**（SC008 のみに統合し SC005 を廃止）: SC005 の「tag 付き legitimate commit でも tag が無い」警告は独立価値があるため却下

### D5. 完全 pagination（a 案）

`refs(refPrefix:"refs/heads/", first:100, after:"<cursor>")` を `pageInfo.hasNextPage=false` まで反復する。

- **a 案**: 完全 pagination（**採用**）。1 ページ目は GraphQL バッチに乗り、2 ページ目以降は per-repo serial GraphQL で継続
- **b 案**: first:100 で打ち切り、超過 repo は `unknown` に倒す → 大規模 repo（kubernetes/kubernetes 等）で常に unknown になる
- **c 案**: branch/tag を別 POST で並列 → node 上限緩和と引き換えに POST 数倍増
- **d 案**: REST の `/git/refs` に切替 → per-repo の API コール数爆発

pagination 未完了のまま deadline を迎えた repo は全 SHA を `unknown` に倒し、SC008 診断を抑制する（偽陽性回避優先）。

### D6. Autofix = fix_hint のみ + 候補列挙

`Diagnostic.fix = null`。`fix_hint` に既取得の refs データから候補を整形する:

> "SHA not reachable from upstream. Consider pinning to a known tag (v4=a81bbbf..., v4.2.2=11bd71905...) or default branch (main=c85c95e...)."

追加 API コールなし。候補は最新 semver tag 上位 3 件 + default branch HEAD。

**機械的 autofix を却下する理由**:
- 「どの tag に pin するか」は意図依存（major pin / minor pin / sha pin）で機械的判断不能
- 意図と異なる tag に自動差し替えすると、機能的変更を混入させる恐れ
- RUNNER001（ADR 0003 D4）/ SC007（ADR 0004 D4）と同じ「autofix 保守的運用」方針

### D7. デフォルト有効 + `.zghalint.yml` override

SC006 と同格。`--quick` / `--offline` 時は `isActive() = false` で全パス skip。token 無しで GraphQL が `NoToken` エラーを返す場合は全 SHA を `unknown` に倒す（REST フォールバックは follow-up）。

### D8. disk_cache v2 migration

`cache_format` フィールドで versioning。v1 既存ファイルは `branches` / `impostor` / `default_branch` を空で読み込み、次回 fetch で v2 に昇格。後方互換を保持しつつ段階移行。

- **v1 の欠落データ**: `branches = &.{}`, `impostor = &.{}`, `default_branch = null`
- **SC005 の挙動**: v1 データからも通常通り動作（tags のみ使用）
- **SC008 の挙動**: v1 データでは常に `unknown`（初回実行時に refetch で v2 化）

## Consequences

- zghalint のルール数が SC002/SC007 実装後の数値からさらに +1（`docs/rules.md` の冒頭件数は SC002/SC007 の merge 状況に応じて協調更新）
- GraphQL クエリ node 数が約 2 倍に増える（branchNodes + pageInfo 追加）。`max_repos_per_batch` を 30→20 に下げて GraphQL 500k node 上限に余裕を持たせる
- REST API コールが 1 SHA あたり最悪 `1 + (branches + tags)` 発生する（step3 miss + step4 全 ref compare）。実用上は step1/step2 で大半が短絡
  - **ワーストケース試算**: 100 branches + 100 tags の repo で step1-2 miss + step3 miss の場合、1 SHA あたり最大 201 REST（step3 1 + step4 200）。典型は step1 または step2 で短絡するため 0 REST
- disk_cache の schema が v2 に上がる。v1 cache は自動 migration（空フィールドで読み込み → 次回 fetch で v2 化）
- `GITHUB_TOKEN` が無い環境では SC008 が常に silent（`unknown` 化）。REST-only フォールバックは follow-up
- SC005 の "no_tag" info は SC008 発火時に drop されるため、単独での発火頻度が減る。SC005 の tag resolution 情報を知りたいケースでは `.zghalint.yml` の postProcess 相当を別途考慮する必要がある（現状は dedup 固定）

## Follow-up

- REST-only フォールバック（GraphQL token 無し環境での SC008 動作）
- `Step.uses` の `value_span` 付与による SARIF location 精緻化（SC005/SC006 も受益）
- `refs/pull/*` を legitimate と見做すオプション（PR 内 CI で自己参照するケース用、通常は非推奨）
- Trusted org allowlist（`docker/*` 等への SC008 適用拡張、ADR 0004 の SC007 follow-up と共通化）
- compare 結果の SHA 単位ではなく commit reachability index 化（bloom filter 等、大規模 monorepo 対策）

## 参考

- `docs/adr/0004-security-gap-fill-sec018-sec021-sc002-sc007.md` — ID 衝突回避の根拠（SC007 予約）
- `docs/design/sc008-impostor-commit-design.md` — 本 ADR の実装詳細
- `docs/design/sc007-typosquat-design.md` — 設計書構成テンプレート
- `src/rules/stale_refs.zig` — SC005 実装（SC008 の relatives）
- `src/rules/graphql.zig` — SC005/SC006 GraphQL バッチ（SC008 で拡張）
- `src/rules/prefetch.zig` — prefetch オーケストレータ（`fetchImpostorCompares` 追加）
- OpenSSF Scorecard `pinnedDependencies` check（impostor commit 検知のリファレンス実装）
- zizmor `impostor-commit` audit
- GitHub REST API `/repos/{owner}/{repo}/compare/{base}...{head}`（status: identical/behind/ahead/diverged）
