# 0003. RUNNER001 deprecated-runner

- Status: Accepted
- Date: 2026-04-19
- Deciders: grill-me セッション（2026-04-19）

## Context

zghalint は 42 ルールを実装済みだが、`src/diagnostics.zig` の `Category` enum に
定義されている `runner` カテゴリにはルールが 1 本も存在しない。アーキ上の
明白な空白である。

GitHub Actions のホステッドランナー画像は定期的に撤去される。撤去済みラベルを
`runs-on:` に書いた workflow はキュー投入時点で失敗し CI が詰まるが、GitHub
側では撤去予定の deprecation notice が出るだけで、既存 workflow の静的検出は
ユーザ任せになっている。zghalint が検出すれば、retirement date 直前の駆け込み
修正や、長期間放置されたリポジトリの死んだ workflow を事前に洗い出せる。

2026-04-19 時点の撤去・撤去予定ラベルは以下のとおり:

- `ubuntu-18.04` (2023-04 撤去)
- `ubuntu-20.04` (2025-04-15 撤去)
- `macos-11`    (2024-06 撤去)
- `macos-12`    (2024-12 撤去)
- `windows-2019` (撤去予定)

本 ADR は grill-me セッションで確定した決定事項とその根拠を記録する。

## Decisions

### D1. Rule ID は RUNNER001、カテゴリは `runner`

- 既存 `Category.runner` が空のため採番コンフリクトなし
- `RUNNER` プレフィックスは他カテゴリの `SEC` / `BP` / `PERF` / `PERM` / `EXPR` /
  `DEP` と同様、カテゴリ名から自然に導出される
- 将来 `RUNNER002`（未知ラベル typo 検出）などを予約可能

### D2. v1 スコープは `jobs.*.runs-on` のスカラのみ

当初検討した以下は v1 対象外とし、別 PR に分割:

- `runs-on: [self-hosted, linux, X64]` 形式（sequence value）
- `strategy.matrix.*` / `strategy.matrix.include[*].*` 内のリテラル一致
- `${{ matrix.os }}` の式解決

根拠:

- `src/workflow/types.zig` の `Job.runs_on: ?[]const u8` はスカラのみを保持する
- `src/workflow/parser.zig` の `parseJob` は `m.getScalar("runs-on")` を使い、
  sequence は `null` として落ちる
- `src/workflow/types.zig` の `Strategy` 構造体には `matrix` フィールドが
  そもそも存在せず、`parseStrategy` も matrix を読まない

これらを扱うには parser と types 双方の拡張が必要で、単独 PR のスコープから
逸脱する。空カテゴリを埋める第一弾として scalar のみに絞った方が、診断精度と
実装工数の両面で合理的。matrix 対応は設計書先行で別 PR にする。

### D3. 単一ルールで status 別に severity を切り替える

- 静的テーブルの各エントリに `status: LabelStatus = .retired | .deprecated` を持つ
- `.retired` の場合は `severity = .@"error"`（実行不可のため）
- `.deprecated` の場合は `severity = .warning`（撤去予定、実行可能）
- `Rule.severity` のデフォルト値は `.warning` を宣言し、SARIF などドキュメント
  表示用のフォールバックとして機能させる
- ユーザが `.zghalint.yml` で severity override した場合、`getEffectiveSeverity`
  は単一 rule_id に対して 1 種類の severity しか返さないため、retired と
  deprecated の両方が同じ severity になる。これは許容する。ユーザが「両方とも
  error にしたい」「両方とも warning にしたい」のどちらも設定可能であり、
  実用上の不便は小さい

### D4. Autofix は `.unsafe`、parser に `runs_on_value_span` を追加

- 意味保存ではない（プリインストール SW・カーネル・既定シェル挙動が異なる）
  ため `.safe` は不適切
- ただし「撤去済みラベルの修正候補は明白」で hint 止まりは勿体ない。
  `--fix-unsafe` 明示オプトインで適用可能にする
- 実装: 静的テーブルの `replacement` フィールドをそのまま `Edit` の
  `replacement` に使う。置換範囲は `job.runs_on_value_span`（新設）の
  `start_byte..end_byte`。`fix_builder` ヘルパは通さず、`DiagnosticList.allocEdit`
  で 1 個の Edit を確保する最小構成
- `runs_on_value_span` の追加は構造的変更なので、機能追加コミットと分離
  （`feat(parser): capture runs_on_value_span for scalar runs-on`）。
  CLAUDE.md の Kent Beck Tidy First 方針に準拠

### D5. 静的テーブルは `src/rules/runner.zig` にインライン定義

- 初期収録 5 件。外部ファイル分離は早すぎる抽象化
- 将来 2 本目の runner 系ルール（例: `RUNNER002` 未知ラベル typo 検出）が
  増えた時点でリファクタリングを検討する

### D6. 初期収録ラベル

| label         | status     | replacement  | note                    |
|---------------|------------|--------------|-------------------------|
| ubuntu-18.04  | retired    | ubuntu-22.04 | removed 2023-04         |
| ubuntu-20.04  | retired    | ubuntu-22.04 | removed 2025-04-15      |
| macos-11      | retired    | macos-13     | removed 2024-06         |
| macos-12      | retired    | macos-13     | removed 2024-12         |
| windows-2019  | deprecated | windows-2022 | scheduled for retirement |

- `ubuntu-latest` / `macos-latest` / `windows-latest` の moving target 警告は
  対象外。再現性のために固定推奨のガイダンスは BP 系ルールとして別途検討
- `macos-13` は 2026-04-19 時点ではまだ GitHub の公式 deprecation notice が
  出ていないため、retirement テーブルには含めない

### D7. Rule name は `deprecated-runner`、フックは `check_job`

- BP003 `deprecated-action-version` と語彙を揃える
- `runs-on` は Job 直下なので `check_job` フックで完結する

### D8. 診断の span と fix_hint

- span は `job.runs_on_value_span ?? job.span`。value span がある通常ケースでは
  ラベル値を正確に pinpoint する
- fix_hint には置換候補のラベル名（例: `"ubuntu-22.04"`）を短く入れる。
  terminal 出力でユーザが即手で直せるように

### D9. `runs_on_value_span == null` 時のフォールバック

- span が取れない場合（理論的には parser 失敗時のみ）、診断は emit しつつ
  `fix = null` にして autofix はスキップする
- 診断メッセージ自体は出したいので、span 欠損で early return はしない

### D10. テストは単体 5 件 + E2E autofix 1 件 = 計 6 件

1. retired ubuntu-20.04 検出（scalar）→ severity=error, fix.safety=unsafe,
   replacement="ubuntu-22.04"
2. deprecated windows-2019 検出 → severity=warning, replacement="windows-2022"
3. 現行ラベル ubuntu-24.04 → 0 件
4. `runs_on = null`（reusable workflow 呼び出し）→ 0 件
5. テーブル外ラベル `self-hosted-custom` → 0 件
6. E2E: YAML → parser → rule → `fix_engine.applyFixes` で実 source が置換される

## Consequences

- 空だった `runner` カテゴリが埋まり、zghalint のカバレッジ表示・設計書上の
  整合性が改善する
- sequence 形式 `runs-on:` や matrix 経由のラベル指定は検出されない。
  `runs-on: [self-hosted, linux]` だけが書かれている workflow に対しては
  false negative。将来の v2 で対応する
- `Job` 構造体に `runs_on_value_span` が追加される。他ルールが将来 runs-on
  の span を必要とする場合（例: BP004 cross-platform shell の診断 pinpoint）
  に再利用可能
- autofix が `--fix-unsafe` でしか適用されないため、CI で自動修正を走らせる
  運用ではユーザの明示承認が必要。安全性とのトレードオフを取った結果

## 参考

- GitHub Actions runner images deprecation announcements
  (https://github.com/actions/runner-images)
- BP003 `deprecated-action-version` （類似 deprecation 検出ルール）
