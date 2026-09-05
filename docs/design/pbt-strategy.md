# PBT 戦略: Property-Based Testing 強化計画

最終更新: 2026-09-04

## 1. 概要

zghalint の品質保証戦略として **Property-Based Testing (PBT)** を採用し、
従来の例示ベース単体テストでは見つけにくい以下のクラスのバグを継続的に検出する。

- **クラッシュ耐性**: 任意のバイト列・文字列入力で signal 終了しない
- **不変条件違反**: 決定性 / 単調性 / 冪等性 / 出力フォーマット間の整合性
- **ジェネレータ駆動探索**: 構造的に有効な GitHub Actions ワークフローを多数生成し、
  人手では思いつかない入力でルール検出ロジックを揺さぶる

本書は PBT の現状を棚卸しし、強化項目を優先度付きで一覧化する。
本書を以後の PBT 改善作業の基準ドキュメントとする。

---

## 2. 既存 PBT の現状サマリ

PBT は Python/Hypothesis で実装され、`tests/pbt/` に配置されている。
合計 1,043 行・31 個の `@given` テストで 6 カテゴリをカバーする。

| ファイル | 行 | テスト数 | 主な不変条件 | 状態 |
|---|---:|---:|---|---|
| `tests/pbt/strategies.py` | 381 | – | 5 段階のジェネレータ + Phase 2 全 6 ルール専用誘発 strategy (BP004 / BP005 / DEP001 / PERF001 / PERM001 / PERM002) | OK |
| `tests/pbt/conftest.py` | 115 | – | ReleaseSafe ビルド・subprocess 実行・config 書き出し | OK |
| `tests/pbt/test_crash.py` | 87 | 4 | 任意入力で signal 終了しない | OK |
| `tests/pbt/test_determinism.py` | 73 | – | 同一入力 → 同一出力 | OK |
| `tests/pbt/test_monotonicity.py` | 119 | 3 | 問題追加で診断数が減らない / disable で増えない | OK |
| `tests/pbt/test_autofix_idempotency.py` | 344 | 8 | `--fix` / `--fix-unsafe` 冪等・出力再 lint 可 | OK |
| `tests/pbt/test_security_detection.py` | 87 | 3 | SEC001/002/003 を必ず検出 | OK |
| `tests/pbt/test_output_consistency.py` | 212 | – | JSON/SARIF スキーマ・summary 算術 | OK |

**実行設定**: `max_examples=50` (autofix のみ 30), `deadline=None`,
`HealthCheck.too_slow` 抑制。subprocess 実行のため上限 50 例。

**ビルド**: `conftest.py:32-39` でセッション開始時に `zig build -Doptimize=ReleaseSafe`
を一度だけ実行（Debug GPA は遅く、メモリリーク警告で stderr が非決定的になるため）。

---

## 3. ルールカバレッジ

zghalint は 11 種のルールモジュールを `src/rules/` に持つが、PBT で
detection を直接保証しているのは **5 種 (45%)**。

| ルールモジュール | PBT 対象 | 備考 |
|---|:---:|---|
| `security.zig` (SEC001/002/003) | ✅ | `test_security_detection.py` |
| `expressions.zig` | ❌ | 1,667 行・既存単体テスト 190+ |
| `permissions.zig` (PERM001 / PERM002) | ✅ | `test_autofix_idempotency.py` で `--fix-unsafe` 経路をカバー |
| `best_practices.zig` (BP004 / BP005) | ✅ | `test_autofix_idempotency.py` で `--fix-unsafe` 経路をカバー |
| `performance.zig` (PERF001 setup-go) | ✅ | `test_autofix_idempotency.py` で `--fix-unsafe` 経路をカバー |
| `advisory.zig` | ❌ | 外部依存あり、生成困難可能性 |
| `archived.zig` | ❌ | 同上 |
| `dependabot.zig` (DEP001) | ✅ | `test_autofix_idempotency.py` で `--fix-unsafe` 経路をカバー |
| `refconfusion.zig` | ❌ | – |
| `stale_refs.zig` | ❌ | 外部依存あり |
| `engine.zig` | (間接) | 全ルールの実行基盤 |

**目標**: P1 タスク #3 完了で 90%+ にカバー率を引き上げる。

---

## 4. 既知の xfail とその出自

PBT が実際に検出した既知バグを `xfail` で記録する運用とする。これらは
**「PBT が機能している証拠」** であると同時に、解消すべき技術的負債である。

現時点で有効な `xfail` は **なし**。P0 (§5 #1, #2) の修正で過去 3 件は
解消済み。

新規に `xfail` を追加する場合は以下を同時に行う:

- 本節に `場所 / 症状 / 修正タスク` の 3 列で登録
- 修正完了時には該当行を削除し、修正コミットのメッセージに検出経緯を残す

---

## 5. 強化項目の優先度一覧

優先度: **P0** = 最優先 / **P1** = 高 / **P2** = 中 / **P3** = 低

| # | 強化項目 | 優先度 | 必要度の理由 | 投資 | 期待効果 |
|---|---|:---:|---|:---:|---|
| 1 | ~~**fix/engine segfault の根本修正**~~ | **完了** | `applyFixes` に Edit 値域検証を追加し ReleaseSafe panic を解消 (2026-09-04) | 中 | バグ撲滅・xfail 解消 |
| 2 | ~~**config rule override の修正**~~ | **完了** | `Config.strings_arena` 導入で YAML scalar を dupe し use-after-free を解消 (2026-09-04) | 中 | 設定機能復活 |
| 3 | **PERM / BP / PERF ルールの detection PBT 追加** | **P1** | 11 ルール中 8 種が未カバー。`test_security_detection.py` パターンで横展開可 | 小 | カバー率 27% → 90%+ |
| 4 | **YAML パーサ ラウンドトリップ不変条件** (`parse(s) == parse(serialize(parse(s)))`) | **P1** | 1,134 行の自前 YAML パーサ。テスト 36 個のみで網羅性低い | 中 | パーサバグ早期発見 |
| 5 | **生成戦略の拡充**（matrix / reusable workflow / `if` 条件式 / multiline run / 巨大 jobs） | **P1** | 現ジェネレータは固定パターン中心。実運用ワークフローを反映できていない | 中 | 既存テスト全体の実効カバー底上げ |
| 6 | **Zig in-process PBT**（`std.Random` + 既存 `test "..."` 内で seed 駆動） | **P2** | subprocess は遅く 50 例上限。in-process なら 1000+ 例で深掘り可能 | 大 | 高速化・shrinking で root cause 特定容易 |
| 7 | **新しい不変条件の追加** (a) ファイル順序非依存 (b) `--quick` と通常モードの整合性 (c) severity override の単調性 (d) JSON ↔ SARIF の diagnostic 数一致 | **P2** | PBT は不変条件の数が価値を決める。低コストで追加可 | 小 | 検出領域の多角化 |
| 8 | **advisory / archived / dependabot / refconfusion / stale_refs の検出 PBT** | **P2** | 外部依存があり生成困難な可能性。要調査 | 中 | 残ルールの網羅 |
| 9 | **Hypothesis DB 永続化と CI 統合** | **P2** | 失敗事例を再現可能にする。現状ローカル一過性 | 小 | 回帰防止・shrink 結果の蓄積 |
| 10 | **terminal 出力フォーマッタの property test** | **P3** | 視覚出力で重要度低。ANSI escape を含み検証が煩雑 | 中 | 限定的 |

### 推奨実装順序

1. ~~**#1, #2** (P0): xfail 解消で CI から黄信号を消す~~ — 完了 (2026-09-04)
2. **#3** (P1, 投資小): 既存パターンの横展開で一気にカバー率を上げる
3. **#5** (P1, 投資中): ジェネレータ拡充で既存テスト全体の質を底上げ
4. **#4** (P1, 投資中): YAML ラウンドトリップで自前パーサの信頼性確保
5. **#7** (P2, 投資小): 不変条件追加
6. **#6** (P2, 投資大): in-process PBT 基盤の整備（中長期）
7. **#8, #9, #10**: 余裕に応じて

---

## 6. PBT 設計方針

### 6-1. subprocess vs in-process の役割分担

| 種類 | 速度 | 上限例数 | 用途 |
|---|---|---|---|
| **subprocess (Python/Hypothesis)** | 遅い | 50 例/テスト | E2E・出力フォーマット・CLI 統合 |
| **in-process (Zig std.Random)** ※未実装 | 速い | 1000+ 例/テスト | YAML パーサ・式パーサ・内部関数の fuzz |

P2 タスク #6 で in-process 基盤を整備した後は、レイヤ別に使い分ける:

- **YAML/expression パーサ** → in-process で深掘り
- **ルール検出 / `--fix` / 出力フォーマット** → subprocess で E2E 検証
- **クラッシュ耐性の最終確認** → subprocess（実バイナリで signal 終了しないこと）

### 6-2. Hypothesis 設定ポリシー

```python
# tests/pbt/test_*.py 共通設定
PBT_SETTINGS = settings(
    max_examples=50,            # subprocess は 30-50 が現実的
    deadline=None,              # ReleaseSafe ビルドでもバラつくため
    suppress_health_check=[HealthCheck.too_slow],
)
```

`max_examples` を上げる場合は CI 時間と相談。Hypothesis DB（タスク #9）導入後は
過去の失敗例が優先的に再実行されるため、上げ幅を抑えても網羅性は維持できる。

### 6-3. ジェネレータ階層

`tests/pbt/strategies.py` の階層構造:

```
random_bytes / random_text          ← Low-level (crash 検証専用)
        ↓
yaml_like_text                      ← YAML 断片を混ぜたテキスト
        ↓
workflow_yaml()                     ← 構造的に有効な workflow
        ↓
workflow_with_*()                   ← 特定ルール（SEC001-003）を必ず誘発
        ↓
workflow_pair_monotonic()           ← 制約付きペア（単調性検証）
```

新規ルールの detection PBT を書く際は、`workflow_with_*` パターンに倣い
**「そのルールを必ず誘発するジェネレータ」** を `strategies.py` に追加する。

---

## 7. 検証手順

### 既存 PBT の実行

```bash
# 全 PBT 実行（ビルドは自動で 1 回のみ）
pytest tests/pbt/ -v

# 統計表示
pytest tests/pbt/ -v --hypothesis-show-statistics

# 特定カテゴリのみ
pytest tests/pbt/test_crash.py -v
```

### CI 統合（タスク #9 完了後の想定）

```bash
# GitHub Actions 例
- name: PBT
  run: pytest tests/pbt/ -v --hypothesis-profile=ci
```

### 強化作業の完了基準

CLAUDE.md の Completion Requirements に従い、以下を必ず通す:

```bash
zig build && zig fmt --check src/ build.zig && zig build test --summary all
pytest tests/pbt/ -v
```

xfail 修正タスク (#1, #2) では、修正後 `XPASS` (strict=False) として表示が消え、
さらに `xfail` マーカーを削除した上で `pass` することを確認する。

---

## 8. 関連ドキュメント

- `AGENTS.md` — プロジェクト基本方針・テスト品質要件
- `docs/rules.md` — 全ルール一覧（タスク #3 の対象選定根拠）
- `tests/pbt/requirements.txt` — `pytest` / `hypothesis` 依存定義
