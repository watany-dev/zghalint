# PBT 戦略: Property-Based Testing 強化計画

最終更新: 2026-09-07

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
合計 1,731 行・42 個の `@given` テストで 6 カテゴリをカバーする。

| ファイル | 行 | テスト数 | 主な不変条件 | 状態 |
|---|---:|---:|---|---|
| `tests/pbt/strategies.py` | 590 | – | 5 段階のジェネレータ + Phase 2 全 6 ルール専用誘発 strategy (BP004 / BP005 / DEP001 / PERF001 / PERM001 / PERM002) + 回帰用 strategy (`workflow_with_flow_with` #171 / `deeply_nested_expression` #170、`workflow_with_perm002` は ブロックスカラー `runs-on:` #172 を含む) | OK |
| `tests/pbt/conftest.py` | 126 | – | ReleaseSafe ビルド・subprocess 実行・config 書き出し | OK |
| `tests/pbt/test_crash.py` | 103 | 5 | 任意入力で signal 終了しない | OK |
| `tests/pbt/test_determinism.py` | 73 | 4 | 同一入力 → 同一出力 | OK |
| `tests/pbt/test_monotonicity.py` | 119 | 3 | 問題追加で診断数が減らない / disable で増えない | OK |
| `tests/pbt/test_autofix_idempotency.py` | 365 | 10 | `--fix` / `--fix-unsafe` 冪等・出力再 lint 可 | OK |
| `tests/pbt/test_security_detection.py` | 87 | 5 | SEC001/002/003 を必ず検出 | OK |
| `tests/pbt/test_plain_scalar.py` | 56 | 2 | プレーンスカラーの `run:` / `if:` を取りこぼさない (#131) | OK |
| `tests/pbt/test_output_consistency.py` | 212 | 11 | JSON/SARIF スキーマ・summary 算術 | OK |
| `tests/pbt/test_formal_extractor.py` | 43 | 1 | `scripts/formal/impl.py` が `security.zig` の現行の表名をまだ見つけられる（#307。z3 不要） | OK |

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
| `expressions.zig` | (部分) | detection は単体テスト 190+。`deeply_nested_expression` でネスト深度のクラッシュ耐性のみ PBT 対象 (#170) |
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
| 6 | ~~**Zig in-process PBT**~~ | **完了** | `std.Random` 自前実装ではなく `std.testing.fuzz` を採用し、YAML tokenizer / YAML parser / 式パーサの 3 ターゲットを実装 (2026-09-07、§6-4) | 大 | カバレッジ誘導で深掘り・CI で時間制限付き探索 |
| 7 | **新しい不変条件の追加** (a) ファイル順序非依存 (b) `--quick` と通常モードの整合性 (c) severity override の単調性 (d) ~~JSON ↔ SARIF の diagnostic 数一致~~ (完了、§6-5) | **P2** | PBT は不変条件の数が価値を決める。低コストで追加可 | 小 | 検出領域の多角化 |
| 8 | **advisory / archived / dependabot / refconfusion / stale_refs の検出 PBT** | **P2** | 外部依存があり生成困難な可能性。要調査 (dependabot はファズドライバが到達済み、§6-5) | 中 | 残ルールの網羅 |
| 9 | ~~**Hypothesis DB 永続化と CI 統合**~~ | **完了** | `actions/cache` で `.hypothesis/` を run 間に引き継ぎ、依存を `==` で固定、`-x` を `--maxfail=3` に変更 (2026-09-07, #235) | 小 | 回帰防止・shrink 結果の蓄積 |
| 10 | **terminal 出力フォーマッタの property test** | **P3** | 視覚出力で重要度低。ANSI escape を含み検証が煩雑 | 中 | 限定的 |

### 推奨実装順序

1. ~~**#1, #2** (P0): xfail 解消で CI から黄信号を消す~~ — 完了 (2026-09-04)
2. **#3** (P1, 投資小): 既存パターンの横展開で一気にカバー率を上げる
3. **#5** (P1, 投資中): ジェネレータ拡充で既存テスト全体の質を底上げ
4. **#4** (P1, 投資中): YAML ラウンドトリップで自前パーサの信頼性確保
5. **#7** (P2, 投資小): 不変条件追加
6. ~~**#6** (P2, 投資大): in-process PBT 基盤の整備~~ — 完了 (2026-09-07)
7. **#8, #9, #10**: 余裕に応じて

---

## 6. PBT 設計方針

### 6-1. subprocess vs in-process の役割分担

| 種類 | 速度 | 上限例数 | 用途 |
|---|---|---|---|
| **subprocess (Python/Hypothesis)** | 遅い | 50 例/テスト | E2E・出力フォーマット・CLI 統合 |
| **in-process (`std.testing.fuzz`)** | 速い | カバレッジ誘導で無制限 | YAML パーサ・式パーサの fuzz (§6-4) |

in-process 基盤 (タスク #6) が入った現在は、レイヤ別に使い分ける:

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

`max_examples` を上げる場合は CI 時間と相談。Hypothesis DB（タスク #9）は
CI でキャッシュされ、過去の失敗例が優先的に再実行されるため、上げ幅を抑えても
網羅性は維持できる。

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

### 6-4. Zig fuzz テスト (`std.testing.fuzz`)

in-process 側は `std.Random` を自前で回すのではなく、Zig 標準のカバレッジ誘導
ファザを使う。実装は `src/fuzz_test.zig`、実行は `zig build fuzz`。

| ターゲット | 対象 | 検証する性質 |
|---|---|---|
| `fuzz: yaml tokenizer never leaves the source buffer` | `src/yaml/tokenizer.zig` | 全トークンの `start`/`end` が入力範囲内、行・列が 1 以上、必ず `eof` に到達する (停止性) |
| `fuzz: yaml parser survives arbitrary input` | `src/yaml/parser.zig` | 失敗は宣言済み `ParseError` のみ。panic / `unreachable` / 領域外アクセスがない |
| `fuzz: expression parser survives arbitrary input` | `src/rules/expressions.zig` | `validateExpression` が出す診断がすべて well-formed (JSON/SARIF に流れるため) |

**コーパスと回帰の方針**

- シードコーパスは `src/fuzz_test.zig` にインラインで置く。ワークフローの構造と、
  tokenizer の flow/block 状態機械を叩く indicator を最小構成で並べたもの。
- `--fuzz` なしの実行 (`zig build fuzz`、および `zig build test`) はシードを
  1 件ずつ流すだけなので、シードはそのまま回帰テストとして機能する。
- ファジングで見つかったクラッシュは、**バグを持つモジュール側に名前付きの
  単体テスト**として最小化済み入力を追加して直す。ここへシードとして追加するのは
  探索領域を広げる入力に限る。
- バイナリコーパスをリポジトリに置かない。`.zig-cache/v/` は破棄可能であり、
  修正済みバグの再現がキャッシュに依存する状態を作らない。

**運用上の注意**

- fuzz 用のテスト成果物は `use_llvm = true` でビルドする。self-hosted x86_64
  バックエンドは `-fsanitize-coverage` の PC を出さないため、`--fuzz` が
  `std.Build.Fuzz.addEntryPoint` で空の PC リストに当たって panic する。
- **Zig 0.15.2 では `--fuzz` の探索実行が使えない。** ファザ本体が起動直後に
  落ち、ビルドは `run test failure` で終わる。ターゲットを 1 つしか持たない
  最小プロジェクトでも、`.zig-cache` を削除した初回実行でも再現するため、
  zghalint 側の問題ではない。したがって CI に入れているのはシードコーパスの
  決定的実行 (`zig build fuzz`) だけで、探索実行は入れていない。
- Zig 側が直り次第、`--fuzz` を時間制限付きで CI に戻す。`--fuzz` は Web UI を
  立てて常駐し自発的には終了しないので、`timeout --signal=INT 300` で打ち切り、
  終了コード 124 を「所定時間内に反例なし」として扱う形になる。手元で試す場合は
  `zig build fuzz --fuzz --webui=127.0.0.1` (既定のバインドが失敗する環境がある)。

### 6-5. 単体ファズドライバ (`src/fuzz_driver.zig`)

`--fuzz` の探索実行が使えない間、探索そのものは自前のドライバが担う。入力は
seed 1 つから決定的に生成するので、失敗した seed をそのまま再現に使える。

```bash
zig build fuzz-driver -- --iterations 20000 --seed 1000000  # キャンペーン
zig build fuzz-driver -- --seed 1234567 --iterations 1      # 1 件を再現
zig build fuzz-driver -- --file case.yml                    # 最小化済み入力を確認
```

**入力クラス** — 生成した 1 つのバイト列を、それを受け取りうる全経路に流す。

| 経路 | 入口 | 検証する性質 |
|---|---|---|
| ワークフロー | `parser` → `registry.all_rules` | 診断の well-formedness、lint の決定性、`--fix` / `--fix-unsafe` の収束 (8 ラウンド) とパース保存 |
| `action.yml` | `action_metadata` | 同上 (メタデータ経路の診断) |
| `.zghalint.yml` | `config.parseConfig` | 2 回のパースが一致すること。`isRuleEnabled` / `getEffectiveSeverity` を全ルールに、`isIgnored` を固定パス集合に当てた結果でダイジェストを取る |
| `dependabot.yml` | `dependabot.lintDependabot` | 診断の well-formedness と直列化 |
| トークナイザ | `yaml/tokenizer.zig` | span が入力範囲内、必ず停止する |
| 式 | `expressions.validateExpression` | 生の式としての診断が well-formed |
| 出力 | `json` / `sarif` / `terminal` | 直列化が落ちない。**JSON と SARIF の件数が一致する** (#7d) |

**運用**

- 失敗率はキャンペーンの品質指標として見る。修正のたびに同じ seed 範囲で回し直し、
  クラスが消えたことを確認する。
- 最小化は行単位 ddmin → バイト単位トリムのデルタデバッグで行い、得られた最小
  ケースは**バグを持つモジュール側の名前付き単体テスト**にする。ドライバの
  `builtin_seeds` に足すのは探索領域を広げる入力に限る (§6-4 と同じ方針)。
- これまで見つかった autofix バグはすべて「挿入アンカーが、入力が持たない
  ブロック配置を前提にしている」という同じ形をしている。パーサ側の失敗も
  「1 つの壊れた節でファイル全体を諦め、他の全診断まで落とす」という
  1 つの形に収束する。前者は診断を捨てずに済む場所ではアンカーを外し
  (BP004 の `shell:`)、捨てる場所ではリネームを取り下げる (SYN001)。後者は
  失われる内容に診断価値がないか既存の報告経路がある場合に限り寛容化する
  (`needs:` の要素、`with:` / `env:` は SYN004)。
- ブロックスカラーのインデントは 3 件続けて同じクラスを出した。内容の
  インデントは最初の非空行が決めるので、行がない・空行だけ・自分のキーより
  浅い、のいずれでもスカラーは「開いた」ままで、下に書いた行を content として
  飲み込む。`--fix` が挿入した `shell: bash` が毎ラウンド content になり、
  収束しなかった。

**入力クラスの拡張** — 上記を受けて、ドライバに直接与える形を足した。

| 追加した形 | 到達先 |
|---|---|
| ブロックスカラーヘッダ (`\|2` / `\|+` / `>-` と明示インデント) | 挿入アンカーとトークナイザの content 判定 |
| 行全体を任意幅に振り直す変異 | 親より深く兄弟より浅い、格子から外れたインデント |
| matrix の include / exclude、environment、services、container、ジョブ既定値と outputs | どの seed も届いていなかったジョブ節 |
| タグ・ディレクティブ・明示キー・引用キー・2 つ目のドキュメント・全行 CRLF | YAML 層だけが決める形 |

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

### CI 統合（タスク #9 完了）

```yaml
# .github/workflows/ci.yml の pbt ジョブ
- name: Cache Hypothesis example database
  uses: actions/cache@... # v6.1.0
  with:
    path: .hypothesis
    key: hypothesis-${{ runner.os }}-${{ github.run_id }}
    restore-keys: |
      hypothesis-${{ runner.os }}-
- run: pytest tests/pbt/ --maxfail=3 -v
```

`--maxfail=3` は `-x` の代替。42 個の `@given` テストのうち複数の不変条件が
同時に壊れる変更で、1 回の CI run から全体像を掴めるようにしている。

**`--hypothesis-profile=ci` は今回見送った。** 各テストファイルの
`PBT_SETTINGS` が `max_examples` を明示指定しており、`@settings` の明示値は
profile の既定値より優先されるため、profile を登録しても実効値が変わらない。
導入するなら 7 ファイルに散った `PBT_SETTINGS` を 1 箇所へ集約するのが前提で、
それは本タスクの範囲を超える。

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
