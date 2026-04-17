# コードベース改善点一覧

## 1. 重複関数（HIGH）

| 関数 | 重複箇所 | 行 |
|------|----------|-----|
| `actionBaseName()` | `security.zig:845`, `performance.zig:113`, `best_practices.zig:188` | 完全に同一の実装が3ファイルに存在 |
| `writeJsonString()` | `json.zig:77-96`, `sarif.zig:115-134` | JSON文字列エスケープが完全重複 |
| `makeWriteAllFix()` | `security.zig:174-185`, `permissions.zig:34-45` | パラメータ名以外同一 |
| write-all権限チェック | `security.zig:187-200`, `permissions.zig:48-59` | ルールID・メッセージ以外同一 |

**対策**: 共有ユーティリティモジュールへの抽出

---

## 2. 繰り返しパターン（HIGH）

### `${{ }}` 式スキャンパターン — `security.zig` 内に6箇所

- `hasDangerousContextExpression()` (L387)
- `checkStringForOverprovisionedSecrets()` (L491)
- `checkStringForSecretsOutsideEnv()` (L645)
- `checkStringForUnredactedSecrets()` (L740)
- `checkBotActorInString()` (L895)
- `checkDangerousContextInString()` (L1027)

同一のwhileループ・depth追跡・境界チェックロジックが6回繰り返されている。イテレータヘルパーに抽出可能。

### run/with/envフィールド3重チェック — `security.zig` 内に4箇所

- `checkHardcodedSecrets()` (L123-140)
- `checkOverprovisionedSecrets()` (L450-476)
- `checkUnredactedSecrets()` (L562-588)
- `checkSecretsOutsideEnv()` (L682-700)

Step の `run`, `with`, `env` を順にチェックする同一パターンが4回。

### step/jobラッパー対 — `security.zig`

- `checkUntrustedInCondition` / `checkUntrustedInConditionJob`
- `checkExcessivePermissions` / `checkExcessivePermissionsJob`
- `checkInsecureCommandsStep` / `checkInsecureCommandsJob` / `checkInsecureCommandsWorkflow`
- `checkBotConditionStep` / `checkBotConditionJob`

薄いラッパーが8個。`enum { workflow, job, step }` パラメータで統合可能。

### Severity カウントロジック

- `terminal.zig:113-127`, `json.zig:16-31` — 同一のswitch文で集計

---

## 3. 関数レベルの重複（HIGH）

### `lintFile()` / `lintDependabotFile()` — `main.zig:124-170, 184-239`

ファイル読み込み→YAML解析→診断フィルタリングの流れが80%重複。共通の `readAndParseYaml` ヘルパーに抽出可能。

追加の重複:
- stderr初期化パターン: L130-132, L190-192, L318-320 の3箇所で同一
- 診断フィルタ・コピーループ: L163-169 と L232-238 が完全重複
- マジックナンバー `10 * 1024 * 1024`: L140, L200, L285 の3箇所

### `parseInputDefs` / `parseOutputDefs` / `parseSecretDefs` — `workflow/parser.zig:164-231`

3関数が95%以上同一構造。ジェネリック関数 or コールバックパターンに統合可能。

---

## 4. デッドコード・未使用コード（MEDIUM）

| 項目 | 場所 | 詳細 |
|------|------|------|
| `Diagnostic.format()` | `diagnostics.zig:92-115` | プロダクションコードで未使用。出力モジュールは独自にフォーマット |
| `Parser.errors` (DiagnosticError) | `yaml/parser.zig:25-31, 43, 48` | 宣言・初期化・deinitされるが`append`の呼び出しが一切ない |
| `skipNonNewlineWhitespace()` | `yaml/parser.zig:318-321` | コメントでno-opと明記。3箇所から呼ばれるが何もしない |
| `Mapping` import | `config.zig:7` | インポートされるが直接使用されない |
| `toString()` メソッド群 | `diagnostics.zig:13-20, 35-47, 57-62` | `@tagName`ビルトインで代替可能 |
| `outputTerminal/Json/Sarif` ラッパー | `main.zig:241-253` | 各1回しか呼ばれない薄いラッパー。インライン化可能 |

---

## 5. 設計上の問題（MEDIUM）

### `parseSeverity` と `Severity.toString` の双方向マッピング分離

- `config.zig:175-181` と `diagnostics.zig:13-20` で同じマッピングを逆方向に管理
- `Severity.fromString()` を enum に追加すべき

### `findConfigFile` が `start_dir` パラメータを無視

- `config.zig:221-229` — `_ = start_dir` で明示的に破棄。コメントで「簡略化のため」と記載

### `parseBool` が不明文字列を `true` として扱う

- `config.zig:183-187` — `"banana"` でも `true` を返す。設定ファイルのタイポを検出できない

### YAML Mapping の first-match セマンティクス

- `yaml/types.zig:82-89` — 重複キーがあった場合、最初のマッチを返す。YAML仕様は通常last-match

### Boolean パースの不統一

- `workflow/parser.zig` で6箇所のboolean判定が異なるロジック
- 特にL457は `!eql("false")` で他の `eql("true")` パターンと逆

### `else => {}` による暗黙のエラー無視

- `workflow/parser.zig` の8箇所（L170, 195, 216, 331, 354, 476, 521, 549）で不正なノード型を黙殺

---

## 6. バッファ管理・安全性（MEDIUM）

| 項目 | 場所 | 詳細 |
|------|------|------|
| SARIF固定サイズバッファ | `sarif.zig:74-84` | 1024バイト固定、512バイトで暗黙の切り詰め。ドキュメントなし |
| `allocEdit` のnull返却 | `diagnostics.zig:149-154` | アロケーションエラーを nullable で返す。`append` はエラー伝播するのに非一貫 |
| Silent OOM | `main.zig:168, 238` | `all_diags.append(d) catch {}` でOOMエラーを黙殺 |
| `toOwnedSlice` 後の `fix_arena` リーク | `diagnostics.zig:161-163` | 部分消費済み状態で `fix_arena` が生存 |
| `allocPrint` での文字列リテラルコピー | `main.zig:111` | `allocator.dupe` で十分 |

---

## 7. yaml/parser の問題（MEDIUM）

| 項目 | 場所 | 詳細 |
|------|------|------|
| 矛盾するインデントロジック | `yaml/parser.zig:148-151` | `< key_indent` と `> key_indent` で連続break。`!= key_indent` と同義だがL151は到達不能 |
| `source` フィールドの重複 | `yaml/parser.zig:20-25` | `Parser.source` と `Tokenizer.source` で二重保持 |

---

## 8. マジックナンバー・定数（LOW）

| 値 | 場所 | 説明 |
|-----|------|------|
| `10 * 1024 * 1024` | `main.zig:140, 200, 285` | ファイル読み込み上限10MB。3箇所に散在 |
| `"<unknown>"` | `terminal.zig:36`, `json.zig:48`, `sarif.zig:91` | 不明ファイルのフォールバック文字列 |
| `512`, `1024` | `sarif.zig:74-84` | バッファサイズ |
| `5` | `security.zig:631` | trimmed文字列の最小長チェック。根拠不明 |
| `pos + 4 < s.len` | `security.zig` 6箇所 | `${{` は3文字だが4で境界チェック。保守的だが非直感的 |

---

## 9. build.zig の冗長性（LOW）

- テストモジュール作成が3回ほぼ同一パターンで繰り返し（L47-84）
- `"src/lib.zig"`, `"src/main.zig"`, `"zghalint"` がハードコードで複数箇所に散在

---

## 10. その他（LOW）

| 項目 | 場所 | 詳細 |
|------|------|------|
| lib.zig の再エクスポート不統一 | L35-41 | terminalは3関数、json/sarifは各1関数のみ再エクスポート |
| lib.zig テストブロックの二重インポート | L72-95 | 15モジュールを公開APIとテストブロックで二重にインポート |
| 変数名の不統一 | rules全体 | `diag_list` vs `list`、`j`/`k`/`pos` の意味不明な使用 |
| terminal.zig の色コード三項演算子 | L35-42, L128-131 | `if (use_color)` パターンが多数。色選択ヘルパーに抽出可能 |
| `parseConfigFromNode` の長大さ | `config.zig:99-173` | 74行。rules/ignore/output を個別ヘルパーに分割可能 |
| 設定値バリデーション不足 | `config.zig:110-172` | 不正な severity 値が `null` で黙殺。警告なし |

---

## 推奨リファクタリング優先順位

| 優先度 | 項目 | 削減見込み |
|--------|------|-----------|
| **1** | `actionBaseName()` を共有ユーティリティへ抽出 | 3ファイルの重複解消 |
| **2** | `${{ }}` 式スキャンのイテレータヘルパー作成 | security.zig内6箇所の重複解消 |
| **3** | `writeJsonString()` を共有モジュールへ | 2ファイルの重複解消 |
| **4** | `lintFile`/`lintDependabotFile` の共通化 | main.zig内の80%重複解消 |
| **5** | `parseInputDefs`/`parseOutputDefs`/`parseSecretDefs` の統合 | workflow/parser.zig内68行の重複解消 |
| **6** | step/jobラッパー対の統合 | security.zig内8ラッパーの削減 |
| **7** | デッドコード削除 | 不要コードの除去 |
| **8** | `makeWriteAllFix` / write-allチェックの統合 | security.zig/permissions.zig間の重複解消 |

全体として、コード重複を **20-25%** 削減可能と見込まれる。

---

## 解決済み (PBT 検出)

PBT (`tests/pbt/`) が検出し、以後修正された問題を記録する。新規に解消した
項目は本節に移動し、原本セクション (§1-§10) からは削除する。

| 修正日 | 項目 | 原本セクション | 検出 PBT | 修正コミット概要 |
|---|---|---|---|---|
| 2026-04-17 | `Edit` 構造体のバリデーション不在 (`diagnostics.zig:68-79`) | §6 バッファ管理・安全性 | `test_autofix_idempotency.py::test_fix_does_not_crash` | `applyFixes` に値域検証を追加し、`end_byte > source.len` などの不正 edit を黙って棄却 (`src/fix/engine.zig`) |
| 2026-04-17 | Config 文字列の use-after-free (YAML scalar が `main.loadConfig` の解放後に dangling) | §6 相当 (未記載だった) | `test_monotonicity.py::test_disabling_rule_does_not_increase_diagnostics` / `..._zero_diagnostics` | `Config.strings_arena` を導入し、`rule_overrides` キーと `ignore_patterns` を dupe (`src/config.zig`) |
