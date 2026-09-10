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

拡張後のキャンペーンは失敗率が約 3 倍になり、それまで一度も出ていなかった
`FixBrokeParse` を出した。そこから出たのは**「エントリの範囲が、その行だけを
見て決まっている」**という 1 つのクラスである。行頭から始まる削除範囲は、
`b: strategy: fail-fast: false` のように 1 行に複数キーが載ると外側のキーごと
消す。逆に行末で止まる範囲は、複数行にまたがるフロー collection の `]` や、
閉じ引用符が桁 0 にある引用スカラーを跨げず、挿入が括弧や引用符の内側に落ちる。
いずれもエントリの終端をキー行から独立に求めることで解いた。

節を空にする autofix も同じ根を持つ。`fail-fast: false` だけを消すと
`strategy:` に値がなくなり、次の行が値として読まれる。唯一のキーを消すときは
節ごと消す。

閉じない引用スカラーはファイル末尾まで伸びるので、そのエントリには後ろに
境界がない。挿入した文字列が引用の中身になり、毎ラウンド挿入し直された。
範囲を返さないのが正しい。

節の中身が空なだけで workflow パース全体を落とす形も 2 つ出た
(`credentials:` と `services:` 配下)。1 節の欠落で他の全診断が消えるので、
名前だけのエントリとして受ける。

**変異器の拡張** — 上記のクラスは 1 行の形が鍵なので、その形を直接作る変異を
3 つ足した。行を連結して複数キーを 1 行に載せる、値を「下の行で閉じる」フロー
collection に開き直す、閉じない引用符を差し込む。いずれも偶然にしか到達して
いなかった。

拡張後のキャンペーンは、それまで一度も出ていなかった違反クラス
`DiagnosticSpanOutOfRange` (`span.end_byte > source.len`) を出した。alias
(`*name`) は 2 バイトのトークンでアンカー先ノードの長い本文を運ぶので、値の
中のオフセットがソースのオフセットにならず、式の部分 span がファイル外を指す。
値がトークンに収まらないときはトークンをそのまま報告する。値とソーストークンの
長さが食い違いうる、という新しい形である。

同じキャンペーンから、既知の 2 つの形の残りも出た。文字列リストのキー
(`branches:`) が mapping を持つと workflow パース全体が落ちる (`branches: l:`
は 1 行に 2 キーが載った形)。空リストとして受ける。閉じない引用符の
`uses:` は下に書いた `with:` を引用の中身として飲み込むので、
`persist-credentials` の挿入アンカーが引用の内側に落ち、毎ラウンド書き直された。
アンカーを持たせないのが正しい。

続くキャンペーンは、リネーム先の候補そのものがソースに書けない形を出した。
`needs: [ight]` を `g]t` というジョブ ID にリネームすると `]` がフロー
シーケンスを閉じ、残りが junk として再字句化されて毎ラウンド `t]` が伸びる。
式のリネームは既に識別子文法の外を拒んでいた (#369)。ジョブ ID は同じ文法なので
同じ判定を共有する。**候補が診断として正しくても、書き戻せるとは限らない**という
形である。

その次のキャンペーンは、リネームが成功したせいでパースが落ちる形を出した。
`ntainer:` → `container:` の次のラウンドで `redenials:` → `credentials:` が通ると、
その下のスカラー値が `parseCredentials` に届いて job 全体のパースが
`error.InvalidValue` で失敗し、他の診断が一つも出なくなる。型の不一致は SYN004 が
報告する話であって、パースを諦める理由ではない。`credentials:` を `container:` と
`services:` の両方で寛容にした。**リネームは値の型を直さないので、直した先で
別の検査に当たる**という形である。

ここで変異器に 2 つ足した。行末コメントと、行の値を `${{ }}` で囲む操作である。
どちらも辞書のトークンを無作為な位置に差し込むだけでは滅多に出ない形で、前者は
挿入アンカーが着地する場所そのもの、後者は式ルールが見る「値の全体が 1 つの式」
という形にあたる。60000 回 (seed 16000000)、80000 回 (17000000)、
拡張後の 80000 回 (18100000) はいずれも失敗 0 だった。

150000 回 (19000000) は引用符の開き位置の食い違いを出した。`push: []'` の `'` は
フローシーケンスを閉じた直後にあり、トークナイザはそこから次の `'` までを引用
スカラーとして読むが、挿入アンカーが使う引用状態の走査は `]` の直後を
トークンの先頭と見ていなかった。結果 `on:` エントリが自分の行で終わったことになり、
`permissions:` が引用の中に書き込まれ、その中の `'pull_request'` が対応をずらして
最後に `jobs:` を飲み込んだ。走査をエントリの先頭から始め、`]` `}` の後も
トークンの先頭として数える。**同じ入力に対する 2 つの走査が食い違う**という形である。

同じ食い違いは逆向きにも出た。`) ":` の `"` は既に始まっているプレーンスカラーの
中にあり、トークナイザは行全体を 1 つのスカラーとして読む。走査だけが引用の開始と
見たので `on:` エントリが 7 行下の `"` まで伸び、空セクションの削除が `jobs:` ごと
消した。「空白の直後」ではなく「構造文字の直後」をトークンの先頭とする。

キャンペーン 20000000 が残したもう 1 件は、挿入位置ではなく挿入の後ろ側の解釈が
変わる形だった。行頭の `{` は閉じられないフローマッピングを開き、兄弟キーには
ならない。ブロックマッピングをそこで終わらせていたので、`{` より下の `jobs:` が
丸ごと消えた。`--fix` が `{` の上に `permissions:` を 1 行足しただけで、直前まで
リント済みだったファイルが構文エラーになる。エントリの行に残った余りや、キーより
深い行を読み飛ばすのと同じ扱いに揃える。ただしキーと同じ字下げでも `-` と `---` は
ゴミではなくブロックシーケンスとドキュメントの開始なので、そこではマッピングを
終える。

同じキャンペーンの続きで出た 3 件は、いずれも「削除や挿入がひとつ上の階層まで
波及する」形だった。1 件目、閉じられないフローコレクションはファイル末尾まで
伸びるので、エントリの終わりがどこにも無い。`on: [` の後ろに `--fix` が
`permissions:` 行を足すと、その行がシーケンスの要素として吸われる。閉じ括弧が
無いときは `full_span` を諦める。2 件目、`strategy:` の下が `fail-fast:` だけの
ジョブから PERF003 がそれを消すと、セクションが空になり、さらにジョブ本体も
空になる。セクションがジョブの唯一のキーなら autofix を出さない。3 件目、
`strategy:` の値がスカラーになったときにワークフロー解析ごと失敗していた。
`credentials:` と同じく SYN004 の型不一致として報告し、解析は続ける。

同じ形は `jobs:` そのものにもあった。`on: a: :` は行末が裸の `:` で終わる。値を
探して改行をまたぎ、字下げに関わらず次の行を読んでいたので、下に書いた `jobs:` が
`on:` の値として吸われた。行末の `:` に値は無い。ここを直すと、本体を持たない
ジョブ (`jobs:\n  a:`) が素直に残るようになり、それを解析エラーにしていた 3 つ目の
経路が表に出た。`jobs:` がスカラーを持つ場合ともども、型不一致として報告して解析は
続ける。

ジョブを解析できるようにしただけでは足りない。本体の無いジョブは span が既定値の
ままで、BP001 が 0 行目を指した。行 0 はファイル上の場所ではない。さらに
`body_own_line` の既定が真なので、挿入位置がジョブ id の行 (`jobs: j:` なら
`jobs:` 行) になり、`--fix` のたびに `timeout-minutes: 30` が 1 行ずつ増え続けた。
本体が無いなら span は id の位置、挿入先は無しとする。

新しい入力クラスとして、`on:` 直下のイベントフィルタ (`branches` / `paths-ignore` /
`types` / `cron` / `workflow_run`)、マッピング形の `runs-on:`、ワークフロー全体の
`concurrency` と `env`、`with:` と名前付き secrets を伴う再利用ワークフロー呼び出し、
`action.yml` の node / docker ランナー (`pre` / `post` / `branding`) をシードと
辞書に足した。

続けて、コーパスが一度も書いていなかった 5 つの形を足した。スコープのマッピング形の
`permissions:` (それまでは `write-all` と省略形だけ)、ワークフロー全体をフロー形式で
書いたもの (fix エンジンの挿入位置が行ではなく `{}` の内側になる)、添字と JSON ヘルパ
(`fromJSON` / `toJSON` / `format` / `join` / `['x']` / `.*`) を使う式、キーと値と
コメントに多バイト文字を含むファイル (span も挿入バイト位置もその上を通る)、行末
コメントが全行に付いたファイル。

この 5 つを足したキャンペーンが最初に出したのは、閉じないフローコレクションと同じ
「境界が無い」形だった。`on:` の値の行に残った余りは普通その行に収まるので、改行が
エントリの終わりになる。開き引用符だけは違う。`on:\n ''"` の `"` は下の行まで伸びるので、
値の直後の改行は引用符の内側にある。そこを挿入位置にすると新しいキーは引用符の中の
ただの文字列になり、SEC007 が次のパスでも鳴って `--fix` のたびに `permissions:` 行が
増え続けた。現在のトークンが挿入位置をまたぐなら `full_span` を諦める。

この判定は現在のトークンからしか見えないので、エントリの範囲はパース時に一度だけ測って
`MappingEntry.extent_end` に載せる。ソースから測り直すと、エントリの行で開いて下の行で
閉じるトークンが見えない。入れ子のマッピングの最後のエントリから外側の範囲を読むときに
この差が出た (`on:\n n: ''"`)。

同じ「範囲が伸びすぎる」形がもう一つあった。行末の余りを追う走査は独自のトークン境界を
持っていて、`}` の次を新しいトークンの先頭とみなす。`p: }'` はトークナイザには plain
scalar 一つだが、走査には開き引用符に見えるので、範囲が EOF まで伸びた。挿入位置が次の
兄弟キー `jobs:` の行を越え、その行の閉じない引用符の中に入って、やはり `--fix` のたびに
行が増えた。エントリの範囲は次の兄弟キーの行頭を越えられないので、そこで切り詰める。

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
