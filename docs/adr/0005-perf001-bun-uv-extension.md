# 0005. PERF001 検査対象拡張: oven-sh/setup-bun と astral-sh/setup-uv

- Status: Accepted
- Date: 2026-04-20
- Deciders: grill-me セッション / update-plan セッション（2026-04-20）

## Context

`PERF001` (cache-not-used) は ADR 0004 の時点で `actions/setup-node` /
`actions/setup-python` / `actions/setup-go` を対象としていた。近年普及した
runtime installer のうち以下 2 種は別系統の action として提供されており、
既存ロジックではカバーできないことが判明した:

- **bun**: `oven-sh/setup-bun` は `actions/setup-node` の `cache:` input では
  サポートされない（公式対応は npm/yarn/pnpm のみ）。bun 専用に独立 action
  が提供されているが、依存キャッシュは自前で `actions/cache` を添える必要が
  ある（setup-bun 自体には `cache:` input が無い）。
- **uv**: `astral-sh/setup-uv` は `actions/setup-python` の `cache:` input では
  サポートされない（公式対応は pip/pipenv/poetry のみ）。setup-uv は
  `enable-cache: auto` デフォルトで GitHub-hosted runner において自動キャッシュ
  されるため、通常は設定不要。ただし `enable-cache: false` を明示すると
  キャッシュが無効化される。

本 ADR は、これら 2 action を PERF001 の検査対象に追加する決定と、それぞれ
異なる警告条件および autofix 方針を記録する。

## Decisions

### D1. 独立 setup action を `SetupKind` で分類する

- `src/rules/performance.zig` の `CacheableSetup` に `kind: SetupKind` を追加し、
  検査ロジックを以下 3 系統に分岐する:
  - `.with_cache_input`: 既存の setup-node / setup-python / setup-go
  - `.bun_independent`: setup-bun（`actions/cache` 併用の有無で判定）
  - `.uv_independent`: setup-uv（`enable-cache: false` 明示のみ警告）
- 根拠: 既存 3 action は `cache:` input の有無という一様な条件で判定できる
  のに対し、bun は独立 `actions/cache` の有無、uv は inverse logic（明示的
  無効化）と、警告条件が根本的に異なるため、分岐を型で明示する

### D2. bun は autofix なし、warning のみ

- `oven-sh/setup-bun` ステップを検出し、同一ジョブ内に `actions/cache` が
  無い場合に warning を出す
- autofix は生成しない（`fix = null` 固定）
- `fix_hint` で手動対応を案内: `path: ~/.bun/install/cache` を bun lockfile
  でキーした `actions/cache` ステップを追加するよう提示
- 根拠:
  - bun には `with.cache` のような挿入先 input が存在せず、別ステップ挿入が
    必要。別ステップ挿入は `docs/adr/0001-autofix-phase2-insertion-rules.md`
    のスコープ外
  - lockfile を bun.lock / bun.lockb いずれとするかはプロジェクトの bun
    version 依存でツール側が決定しきれない

### D3. bun の lockfile 検出は OR 判定

- `workspace.Context` に `bun_lockfile_present: bool` を追加
- `bun.lock` OR `bun.lockb` のいずれかが workspace root に存在すれば true
- 警告自体は lockfile 有無と独立して発火し、lockfile が不在のときは
  `fix_hint` に「Note: no bun.lock or bun.lockb detected」を追記して情報提供
- 根拠:
  - bun.lock は Bun 1.2 以降の text 形式、bun.lockb はそれ以前の binary 形式。
    どちらも依然として現役で、OR 判定が正しい
  - lockfile 不在時に警告を抑止すると「CI 上に lockfile が無い」新規プロジェクト
    で検知が漏れる

### D4. uv は inverse logic、`enable-cache: "false"` 明示時のみ警告

- `astral-sh/setup-uv` ステップを検出し、`with.enable-cache == "false"` が
  明示され **かつ** 同一ジョブ内に `actions/cache` ステップが無い場合のみ
  warning を出す
- autofix は生成しない（ユーザ判断が必要）
- 根拠:
  - uv のデフォルトは `enable-cache: auto`（GitHub-hosted で ON / self-hosted
    で OFF）で、通常は設定不要
  - `enable-cache` 未指定 or `true` で警告すると false positive が多発する
  - `false` 明示はユーザが意図的に無効化している可能性もあるため、自動修正
    （削除 or `true` 化）は危険
  - `actions/cache` 併用による補完は他の setup-* / setup-bun と同じ扱いで、
    「uv 組み込みキャッシュを無効化して自前 `actions/cache` を使う」構成を
    false positive にしない

### D5. YAML boolean の文字列比較

- `enable-cache: false` の YAML boolean 値と quoted `"false"` の文字列値は
  いずれも `src/workflow/parser.zig` の `parseStringMap` で `"false"` という
  スカラ文字列として保持される（PERF003 の `fail-fast: "false"` と同じ扱い）
- 根拠: 既存 YAML パーサがスカラ値を raw string として保持する設計のため、
  boolean 型への変換は不要

## Consequences

- PERF001 の false negative を減らせる（bun/uv を使うリポで未検知だった
  キャッシュ漏れを検出可能）
- bun については autofix なしのため、ユーザが手動で `actions/cache` ステップ
  を追加する必要がある（`fix_hint` で詳細ガイド）
- uv については false positive を避ける inverse logic のため、`enable-cache`
  を意図的に無効化しているユーザには意図に反した警告が届く（これは仕様
  通りで、設定理由をコメント等で残すことを期待する）
- `self-hosted` runner では uv のデフォルトキャッシュが OFF となるが、本
  ルールでは runner 種別を考慮しない（SC/RUNNER 系ルールの領分）

## Alternatives Considered

### A1. bun を setup-node と統合

却下: `actions/setup-node` の `cache:` input は bun をサポートしておらず、
統合するには別途キャッシュロジックが必要。責務分離を優先した。

### A2. uv を setup-python と統合

却下: 同様に `actions/setup-python` の `cache:` input は uv 非対応。

### A3. uv を常に警告（`enable-cache` 未指定でも）

却下: デフォルトで auto のため false positive が多発する。
`enable-cache: false` 明示のみが確実にキャッシュ無効化されているケース。

### A4. bun autofix を提供

却下: 別ステップ挿入は ADR 0001 のスコープ外。また `actions/cache` の key
生成には OS 毎の hash や lockfile path など多くの決定事項があり、ユーザ判断
に委ねた方が安全。

## References

- grill-me セッション Q1-Q9
- 実装プラン: `/root/.claude/plans/perf001-uv-bun-dreamy-scroll.md`
- 設計書: `docs/design/perf001-lockfile-detection-design.md` の「独立 setup
  action の取り扱い (bun / uv)」セクション
- 関連 ADR: `docs/adr/0004-perf001-cache-extension.md`
- 外部情報確認:
  - `actions/setup-node` action.yml: cache input は npm/yarn/pnpm のみ
  - `actions/setup-python` action.yml: cache input は pip/pipenv/poetry のみ
  - `oven-sh/setup-bun` README: `cache:` input 非提供、`actions/cache` 推奨
  - `astral-sh/setup-uv` README: `enable-cache: auto` デフォルト、false 明示
    で無効化
