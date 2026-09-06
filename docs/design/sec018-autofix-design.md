# SEC018 persist-credentials 検知 + autofix 設計書

## 目的

`actions/checkout` のデフォルト挙動 `persist-credentials: true` は `GITHUB_TOKEN` を `.git/config` に永続化するため、後続 step が `.git/config` 経由でトークンを読み出せる。`SEC015` (artipacked) が `upload-artifact` と組み合わせた場合の狭い漏洩経路を既にカバーしているのに対し、本ルール `SEC018` は **checkout step 単独の時点で** デフォルト挙動を警告し、`with.persist-credentials: false` を挿入する `--fix-unsafe` を提供する。

本設計書の判断は `docs/adr/0006-security-gap-fill-sec018-sec021-sc002-sc007.md` の D1-D12 を単一情報源とする。

行番号は本ドキュメント記述時点（commit `f427b0a`）のものである。実装時にズレた場合は `Read` / `git grep` で再確認すること。

## スコープ

- `actions/checkout@*` を使う step（owner=`actions`, repo=`checkout`）
- step-level の `with.persist-credentials` の状態を 3 分岐で評価する
- 検知条件を満たした場合、`--fix-unsafe` で `with.persist-credentials: false` を自動挿入する

## 非スコープ

- `actions/checkout` の fork / 派生 action（例: `octokit/checkout`）
- composite action 内部の checkout
- reusable workflow 内部の checkout（対象 workflow のファイル単位で解析する）
- `persist-credentials: true` を**明示している**場合の autofix（edit 対象 value span が `Step.with` (StringMap) から復元できない）
- `GITHUB_TOKEN` を `env:` 経由で明示渡ししている step の追加分析

## 現状整理

| 既存資産 | 位置 | 備考 |
|---|---|---|
| `isCheckoutAction` | `src/rules/security.zig:273-277` | owner=`actions` / repo=`checkout` の判定。そのまま再利用 |
| `hasPersistCredentialsFalse` | `src/rules/security.zig:1007-1011` | `with.get("persist-credentials") == "false"` 判定。SEC015 から呼ばれている |
| `buildPersistCredentialsFix` → `buildPersistCredentialsFalseFix` | `src/rules/security.zig:1050-1090` | SEC015 用の挿入 autofix。`with == null` / `with` 存在の 2 分岐を既に実装。SEC018 実装時に description / safety を引数化して共有 helper 化済み |
| `Step.uses_value_end_byte` | `src/workflow/types.zig:247-278` | `with == null` 時の挿入 anchor |
| `Step.with_last_entry_end_byte` | `src/workflow/types.zig:247-278` | `with` 存在時の挿入 anchor。フロースタイルの `with:`（entry に `full_span` が無い）、または最終 entry の値がフローコレクション／ブロックスカラーのときは null になる（#171） |
| `Step.uses_key_col` | `src/workflow/types.zig:247-278` | インデント計算用（1-based 列番号） |
| `fix_builder.appendMappingEntry` | `src/fix/builder.zig` | `with` 存在時に再利用 |

`with_last_entry_end_byte` が null のとき、および `with:` キーがソースに存在しつつ空（`with:` / `with: {}` → `Step.with == null` かつ `Step.empty_sections` に `with` を含む）のときは、
安全な挿入位置が無い／`with:` が二重になるため fix を出さない（診断のみ）。

SEC018 のルール実装自体は parser 改修を必要としないが、上記の anchor を正しく null に
落とすため workflow parser 側に安全判定を入れている（`src/workflow/parser.zig` の
`isInlineScalar`）。

## 設計方針

### 1. 発火条件は 3 状態に分岐する

```
state = classifyPersistCredentials(step)
 ├─ .not_set     (with == null または with.persist-credentials キー未設定)  → 発火 + autofix 可
 ├─ .explicit_true                                                        → 発火 + autofix 不可
 └─ .explicit_false                                                       → スキップ
```

実装では以下の enum をローカルに置く。

```zig
const PersistCredentialsState = enum { not_set, explicit_true, explicit_false };

fn classifyPersistCredentials(step: *const Step) PersistCredentialsState {
    const with_map = step.with orelse return .not_set;
    const val = with_map.get("persist-credentials") orelse return .not_set;
    if (std.ascii.eqlIgnoreCase(val, "false")) return .explicit_false;
    if (std.ascii.eqlIgnoreCase(val, "true")) return .explicit_true;
    return .not_set; // value が想定外なら保守的に発火
}
```

`.explicit_true` は autofix 不可なぶん診断メッセージを強めにして `fix_hint` を付ける。
YAML 1.1 の `True` / `FALSE` 等の大文字変種もスカラー文字列として現れるため、`std.ascii.eqlIgnoreCase` で比較する（PR #46 のレビュー対応）。

### 2. `buildPersistCredentialsFix` は共有 helper に格上げする

現状 SEC015 専用（`src/rules/security.zig:1045-1079`）だが、SEC018 でも同一の挿入ロジックが必要。ADR D12 の「Refactor」ステップでシグネチャを次のように変える。

```zig
fn buildPersistCredentialsFalseFix(
    list: *DiagnosticList,
    step: *const Step,
    description: []const u8,
    safety: FixSafety,
) ?Fix
```

- `description` と `safety` を呼び出し側パラメータ化する
- SEC015 呼び出しは `(..., "add persist-credentials: false to checkout step", .safe)` で既存挙動を維持
- SEC018 呼び出しは `(..., "add persist-credentials: false to checkout step", .unsafe)` で追加

これにより SEC015 の既存テストと `.safe` 振る舞いを壊さずに SEC018 を追加できる。

### 3. Autofix 挿入戦略

共有 helper `buildPersistCredentialsFalseFix` (`src/rules/security.zig:1050-1090`) を SEC015 / SEC018 双方から呼ぶ。

| 状態 | 挿入点 | 挿入内容 | 使用 helper |
|---|---|---|---|
| `with == null` | `step.uses_value_end_byte` | `\n{indent(col-1)}with:\n{indent(col+1)}persist-credentials: false` | `std.fmt.allocPrint` |
| `with` 存在・キー未設定 | `step.with_last_entry_end_byte` | `\n{indent(col+1)}persist-credentials: false` | `fix_builder.appendMappingEntry(alloc, insert_at, col + 1, "persist-credentials", "false")` |
| `persist-credentials: true` 明示 | — | autofix 不可 | `fix_hint` のみ |

`step.uses_key_col` は **1-based** 列番号なので、親 `with:` の左余白は `col - 1` スペース、子 `persist-credentials:` は `col + 1` スペース。PERF001 の `buildCacheFix` (`src/rules/performance.zig:84-86`) と同じパターン。`uses_key_col` が未設定の場合は `orelse 7` でデフォルト化し、`col == 0` は guard で早期 return する。

### 4. safety は `.unsafe`

SEC015 との差分:

| 観点 | SEC015 | SEC018 |
|---|---|---|
| 発火経路 | `upload-artifact` と同一 job 内で組み合わさるごく狭い状況 | `actions/checkout` 単独で常に発火（デフォルト挙動への一律警告） |
| autofix 後の副作用範囲 | artifact 漏洩経路が消えるだけ、既存 step の動作は基本維持 | `GITHUB_TOKEN` が `.git/config` から消える → 後続の `git push` / `gh` / composite action が動作不能化しうる |
| 結論 | `.safe` | `.unsafe` |

`FixSafety` 定義（`src/diagnostics.zig:36-45`）の文言「Fix that may change behavior」に SEC018 は該当する。RUNNER001（ADR0003 D4）と同様、`--fix-unsafe` でユーザの明示承認を必須にする。

### 5. 診断メッセージ

```
message  = "actions/checkout persists GITHUB_TOKEN in .git/config by default; subsequent steps can read the token"
severity = .warning
category = .security
fix_hint = "add 'with.persist-credentials: false' unless you need git push / gh from later steps"
```

`explicit_true` 経路では message の末尾に `" (explicitly set to true)"` を足して差別化する。

### 6. ルール登録

`src/rules/security.zig:1472` の `security_rules` 配列に次のエントリを追加する（SEC017 と SEC019 の間）。

```zig
.{
    .id = "SEC018",
    .name = "checkout-persist-credentials",
    .description = "actions/checkout persists GITHUB_TOKEN in .git/config by default",
    .severity = .warning,
    .category = .security,
    .check_step = &checkCheckoutPersistCredentials,
},
```

## 安全性評価

`SEC018` の autofix は `.unsafe` とする。上記「設計方針 4」参照。

また、**autofix の副作用範囲は同一 workflow ファイル内に閉じる**（step 単位の変更で外部ファイルを触らない）。このため `--fix-unsafe` を実行した場合でも差分レビューが可能であり、意図せずパイプラインを壊した場合の roll-back コストは低い。

## 実装差分

### 変更対象

- `src/rules/security.zig`
  - `classifyPersistCredentials` 追加（`std.ascii.eqlIgnoreCase` で大文字変種に対応）
  - `checkCheckoutPersistCredentials` 追加（step-level check）
  - `buildPersistCredentialsFix` を `buildPersistCredentialsFalseFix` にリネーム + `description` / `safety` 引数化
  - 同 helper の indent を 1-based 前提で `col - 1` / `col + 1` に修正（`col == 0` guard 追加、PERF001 と同じパターン）
  - SEC015 の呼び出し箇所を新シグネチャに合わせて更新
  - `security_rules` 配列に `SEC018` エントリ追加（SEC015 と SEC019 の間）
  - SEC018 のインラインテスト追加（大文字変種の回帰テスト含む）

### 変更しないもの

- `src/workflow/types.zig`（`Step` の既存 span フィールドで足りる）
- `src/workflow/parser.zig`
- `src/yaml/*`
- `src/fix/*`
- `src/lib.zig`（`security.zig` は既に `@import` 済）

## テスト設計

TDD の各ケースを `src/rules/security.zig` のテストブロックに追加する。

### ケース一覧

1. **persist-credentials 未設定**（`with == null`）→ diagnostic 発火 + `fix != null` + `safety == .unsafe`
2. **persist-credentials 未設定**（`with` 存在・他キーのみ）→ diagnostic 発火 + `fix != null`
3. **persist-credentials: true 明示** → diagnostic 発火 + `fix == null`
4. **persist-credentials: false 明示** → diagnostic 発火なし
5. **autofix edit 内容検証**（`with == null` 系）: replacement に `with:` と `persist-credentials: false` が含まれ、子インデントが親 + 2 スペース（`col - 1` / `col + 1`）で整列していること
6. **autofix edit 内容検証**（`with` 存在系）: replacement が `persist-credentials: false` を含み、`start_byte == step.with_last_entry_end_byte`
7. **fix/engine.zig 経由で YAML に適用した結果**: YAML が parse 可能な整形された状態であること
8. **YAML boolean の大文字変種**（`True` / `FALSE`）: 正しく explicit_true / explicit_false に分類されること（PR #46 レビュー対応）

### テストヘルパ

`src/rules/security.zig` 既存の `hasDiagnostic` / `findDiagnostic` / `makeEmptyTrigger` をそのまま使う。

### CI 必須 3 点

```bash
zig build && zig fmt --check src/ build.zig && zig build test --summary all
```

`CLAUDE.md` の Completion Requirements に明記されているので必ず実行する。

## 実装手順

1. `classifyPersistCredentials` と `checkCheckoutPersistCredentials`（autofix なし版）の failing test を追加する
2. `checkCheckoutPersistCredentials` を実装し、`security_rules` に登録する（diagnostic のみ通す）
3. `buildPersistCredentialsFix` を `buildPersistCredentialsFalseFix` にリネーム + 引数化する
4. SEC015 の呼び出し側を新シグネチャに合わせる（既存テストが通ること）
5. `checkCheckoutPersistCredentials` 内から `buildPersistCredentialsFalseFix(..., .unsafe)` を呼ぶ
6. autofix テスト（ケース 5-7）を追加する
7. `zig build && zig fmt --check src/ build.zig && zig build test --summary all` を通す
8. `docs/rules.md` に SEC018 行を追加（45 → 46 ルールに）

## 参考

- `docs/adr/0006-security-gap-fill-sec018-sec021-sc002-sc007.md` — 判断の単一情報源（特に D1 / D2 / D4 / D5）
- `docs/adr/0003-runner001-deprecated-runner.md` — `.unsafe` autofix の先例
- `src/rules/security.zig:273-277` — `isCheckoutAction`
- `src/rules/security.zig:1007-1011` — `hasPersistCredentialsFalse`
- `src/rules/security.zig:1013-1048` — SEC015 (artipacked) の `checkArtipacked`
- `src/rules/security.zig:1050-1090` — 共有 helper `buildPersistCredentialsFalseFix`（SEC015 / SEC018 共用）
- `src/rules/security.zig:1096-1135` — `classifyPersistCredentials` / `checkCheckoutPersistCredentials`
- `src/rules/security.zig:1528` — `security_rules` 配列（SEC018 は SEC015 と SEC019 の間に登録済み）
- `src/workflow/types.zig:247-278` — `Step` 構造体（autofix 用 span 全て既存）
- `src/fix/builder.zig` — `appendMappingEntry`
- `src/diagnostics.zig:36-45` — `FixSafety` 定義
