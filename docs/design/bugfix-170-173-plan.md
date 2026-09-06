# バグ修正計画: #170 / #171 / #172 / #173

- Status: Draft（実装着手前）
- Date: 2026-09-06
- 対象 Issue: [#170](https://github.com/watany-dev/zghalint/issues/170), [#171](https://github.com/watany-dev/zghalint/issues/171), [#172](https://github.com/watany-dev/zghalint/issues/172), [#173](https://github.com/watany-dev/zghalint/issues/173)

## 1. 概要

ファジングで見つかった 4 件のバグを、それぞれ 1 コミット（Tidy First が必要なものは tidy コミット + 修正コミット）で直す。
4 件はすべて再現済み。Issue に書かれていない追加ケースも再現したので、本計画はそれらも対象に含める。

| # | 症状 | 層 | Issue 外の追加発見 |
|---|---|---|---|
| #173 | `"..."` 内の `\`+改行以降、診断行番号が 1 ずれる | `src/yaml/tokenizer.zig` | なし |
| #170 | 深くネストした `${{ }}` 式で SIGSEGV | `src/rules/expressions.zig` | `!` を 2 万個並べた `!!!…true` でも SIGSEGV（`parseUnary` の自己再帰。Issue の `(`/`fromJSON(` とは別の再帰経路） |
| #172 | ブロックスカラー値の直後に `permissions:`/`concurrency:` を挿入すると次のキー行の内側に入る | `src/yaml/parser.zig` `blockEntryFullSpan` | なし（`full_span` を削除範囲として使う DEP001 等も同じ計算を共有しているため同時に直る） |
| #171 | SEC018 / PERF001 の `with:` 追記 autofix がフローコレクションを破壊 | `src/workflow/parser.zig` + `src/rules/{security,performance}.zig` | (a) `with: {x: y}`（`with:` 自体がフロー）(b) `x: [a, b]` (c) `x: \|` ブロックスカラー、で同様に破壊。(d) `with: {}` / `with:`（空）では `with:` キーが **二重に挿入** される |

## 2. 修正方針と設計判断

### D1. 修正は「安全側に倒す」。autofix の適用範囲を広げる改修は本計画の対象外

#171 は「フロー／ブロックスカラーでも正しく追記する」実装も可能だが、`Mapping.span` がフローコレクションの開始 `{` しか持たない（`src/yaml/parser.zig:201-236`）ため、閉じ括弧の位置を知るには YAML パーサの span 設計を変える必要がある。
本計画では既存の `fix_builder.replaceScalar`（`literal`/`folded` は null を返す）と DEP001（`docs/design/autofix-phase2-insertion-design.md:113`: flow entry は `full_span` が null なので fix は null）の前例に合わせ、**安全に追記できないときは fix を出さない**（診断と `fix_hint` は従来通り出す）。

### D2. 深さ上限は YAML パーサと同じ 256、ガードは `parseUnary` 1 箇所

`src/rules/expressions.zig` の再帰経路は 3 本ある。

1. `parsePrimary`(`.open_paren`) → `parseOr` → `parseAnd` → `parseComparison` → `parseBinary` → `parseUnary` → `parsePrimary`
2. `parseFunctionCall` → `parseOr` → … → `parseUnary` → `parsePrimary` → `parseFunctionCall`
3. `parseUnary` → `parseUnary`（`!` 連続。Issue 未記載、再現済み）

3 本とも `parseUnary` を必ず通るので、`parseUnary` の入口 1 箇所で `depth` を増減すれば全経路を覆える。
上限は `src/yaml/parser.zig:24` の `max_parse_depth = 256` に揃える（1 段あたり 6〜7 フレーム、256 段で約 1,800 フレームなので既定スタックで十分）。

### D3. `#172` はブロックスカラー分岐の特別扱いではなく、スカラー分岐全体を「値の終端行」基準に正す

現状のスカラー分岐（`src/yaml/parser.zig:347-368`）は「スカラーはキーと同じ行で終わる」前提で、`end_line` も `key.span.start_line` 固定になっている。
ブロックスカラーは `scanBlockScalar` の仕様上 `span.end_byte` が「閉じる行の先頭（または EOF）」を指す（末尾の `\n` を既に含む）ので、**行末走査も `\n` の追加消費もしない**。
複数行クォートスカラー（`x: "a\n  b"`）も同じ分岐を通るため、`end_line` は改行数から計算する形に統一する（バイト範囲は従来通り、行・列メタデータのみ正確になる）。

### D4. `with_last_entry_end_byte` はパーサ側で「安全な場合だけ」設定する

`src/workflow/parser.zig:690-698` は `last.value.getSpan().end_byte` を無条件に採用している。以下の条件をすべて満たすときだけ設定する。

- `last.full_span != null`（= `with:` 自体がブロックマッピング。フローマッピングの entry は `full_span` を持たない）
- `last.value == .scalar` かつ `style` が `literal`/`folded` でない（複数行クォートスカラーは閉じクォート位置が終端なので可）

これでルール側（`security.zig:1033`, `performance.zig:95`）は変更不要（`orelse return null` / `orelse continue` が既にある）。

### D5. 空 `with:` の二重挿入は `empty_sections` で防ぐ

`with: {}` / `with: []` / `with:`（値なし）は `isEmptyContainer` により `step.with == null` になり、SEC018 / PERF001 が `insertWithEntry` 経路で `with:` を **もう 1 つ** 挿入する（再現済み）。
`step.empty_sections` に `with` が記録済みなので、両ルールの builder で `with == null` かつ `empty_sections` に `with` があれば null を返す。判定は `src/util.zig` に共有ヘルパーとして置く（security / performance の 2 箇所から使う）。
`uses_value_end_byte` は BP002（`best_practices.zig:131`）も使うため、パーサ側で null にする案は採らない。

### D6. 各修正は「Zig インラインテスト + E2E フィクスチャまたは PBT」の 2 層で固定する

E2E（`tests/fixtures/e2e/`）は行番号を `@<line>` で固定できるので #173 に最適。#170 は 2 万文字の入力が必要なので PBT（`tests/pbt/test_crash.py`）にストラテジを足す。#171 / #172 は `fix_engine.applyFixes` 経由の YAML 一致テスト（ADR 0001 D7 の 3 層目）で固定する。

## 3. イテレーション

各イテレーション完了時に CI ゲートを通してからコミットする。

```bash
zig build && zig fmt --check src/ build.zig && zig build test --summary all
```

### Iteration 1 — #173 ダブルクォート内の行継続で行番号がずれる

**Tidy First（別コミット）**: `src/yaml/tokenizer.zig` に `consumeNewline()`（`pos += 1; line += 1; column = 1`）を抽出する。同じ 3 行が `scanQuotedScalar`（1 箇所）と `scanBlockScalar`（3 箇所: 240-242, 246-248, 267-269）に散らばっている（Extract Helper / Normalize Symmetries）。動作変更なし。

**修正**（`scanQuotedScalar` のエスケープ分岐、`src/yaml/tokenizer.zig:201-206`）:

```zig
if (quote == '"' and self.source[self.pos] == '\\') {
    self.advance();
    if (self.pos < self.source.len) {
        // `\` + 改行は YAML の行継続。改行を食べるので行カウンタも進める。
        if (self.source[self.pos] == '\n') self.consumeNewline() else self.advance();
    }
    continue;
}
```

**テスト**:
- `src/yaml/tokenizer.zig`: `"a \` + 改行 + `b"` の直後のトークンの `line` が 3 になること（現状 2）。`\\` + 改行（エスケープされたバックスラッシュの後の素の改行）で二重カウントしないことも 1 本。
- `tests/fixtures/e2e/bp004-shell-after-quoted-continuation.yml`: Issue の repro をそのまま置き、`# zghalint:expect BP004@8`。`README.md` の表に 1 行追加。

### Iteration 2 — #170 式パーサの再帰深度ガード

**修正**（`src/rules/expressions.zig`）:

```zig
/// `src/yaml/parser.zig` の max_parse_depth と同じ上限。
pub const max_expr_depth: u16 = 256;

pub const ParseError = error{
    UnexpectedToken,
    EmptyExpression,
    UnclosedParen,
    NestingTooDeep,   // 追加
    OutOfMemory,
};

pub const ExprParser = struct {
    ...
    depth: u16 = 0,

    fn parseUnary(self: *ExprParser) ParseError!ExprNode {
        if (self.depth >= max_expr_depth) {
            self.error_message = "expression is nested too deeply";
            return ParseError.NestingTooDeep;
        }
        self.depth += 1;
        defer self.depth -= 1;
        ...  // 既存の本体
    }
};
```

- 診断メッセージ対応表（`src/rules/expressions.zig:473-476`）に `ParseError.NestingTooDeep => parser.error_message orelse "expression is nested too deeply"` を追加。EXPR001 として報告する（新ルール ID は増やさない）。
- `ParseError` を網羅 switch している箇所があればコンパイルエラーで検出されるので、そこも追従する。
- `ExprTokenizer.next` は非再帰であることを確認済み（`src/rules/expressions.zig:73`）。AST を再帰で辿る後段（型検査 `expr-static-typecheck`、`context_access` 収集）は深さ ≤ 256 に抑えられるので追加ガード不要。

**テスト**:
- インライン: `(` ×1000、`fromJSON(` ×1000、`!` ×1000 の 3 本で `expectError(ParseError.NestingTooDeep)`。境界: 200 段の括弧は正常にパースできること。診断層: EXPR001 が 1 件だけ出てメッセージに "nested too deeply" を含むこと。
- PBT: `tests/pbt/strategies.py` に `deeply_nested_expression`（`(`/`fromJSON(`/`!` を 300〜30,000 段）を追加し、`test_crash.py` に `test_no_crash_on_deeply_nested_expression` を追加。

### Iteration 3 — #172 `blockEntryFullSpan` のブロックスカラー終端

**修正**（`src/yaml/parser.zig:341-368` スカラー分岐）:

```zig
if (value == .scalar) {
    const scalar = value.scalar;
    const is_block = scalar.style == .literal or scalar.style == .folded;
    var end_byte = scalar.span.end_byte;
    // ブロックスカラーの span は「閉じる行の先頭（または EOF）」で終わり、末尾の
    // 改行を既に含む。ここから行末を探すと次の兄弟キー行を丸ごと飲み込む。
    if (!is_block) {
        while (end_byte < self.source.len and self.source[end_byte] != '\n') end_byte += 1;
        if (end_byte < self.source.len) end_byte += 1;
    }
    const newlines: u32 = @intCast(std.mem.count(u8, self.source[line_start..end_byte], "\n"));
    return .{
        .start_line = key.span.start_line,
        .start_col = 1,
        .end_line = key.span.start_line + newlines,
        .end_col = @intCast(end_byte - self.lineStartByte(end_byte) + 1),
        .start_byte = line_start,
        .end_byte = end_byte,
    };
}
```

- 単一行スカラーの結果（バイト範囲・行・列）は従来と完全に同じ。変わるのはブロックスカラー（バイト範囲）と複数行クォートスカラー（`end_line` のみ）。
- `full_span` の利用箇所は `src/workflow/parser.zig:147,441,638`（挿入アンカー）、`:846`（`fail_fast_entry_span`）、`src/rules/dependabot.zig:25`（削除範囲）。いずれも `end_byte` を使うので、ブロックスカラー値を持つ entry の削除／後続挿入がまとめて正しくなる。

**テスト**:
- `src/yaml/parser.zig`: `runs-on: |` entry の `full_span` が `"    runs-on: |\n      ubuntu-latest\n"` と一致し `steps:` 行を含まないこと。EOF 直前のブロックスカラー（末尾改行なし）、空行を挟んで次キーが続くケース（`foo\n\n    steps:` — 空行はブロックスカラー側に含まれる現行トークナイザ仕様を固定）。
- `src/workflow/parser.zig`: Issue の repro で `job.permissions_insertion_byte` が `    steps:` 行の先頭を指すこと。`on:` のネストマッピングがブロックスカラー（`workflow_dispatch.inputs.x.description: |`）で終わるケースで `workflow.permissions_insertion_byte` が `jobs:` 行の先頭を指すこと。
- `src/rules/permissions.zig`（PERM002）/ `best_practices.zig`（BP005）: Issue の repro を `applyFixes` に通し、期待 YAML（`permissions:` が `steps:` の前、`runs-on` と同じインデント）と一致すること。
- PBT: `workflow_with_perm002` に `runs-on` をブロックスカラーにするバリアントを追加（`test_fixed_file_is_still_parseable` / `test_double_unsafe_fix_is_idempotent_workflow` が自動でカバー）。

### Iteration 4 — #171 `with:` 追記 autofix の安全化

**修正 1**（`src/workflow/parser.zig:690-698`）:

```zig
.mapping => |with_mapping| {
    if (with_mapping.entries.len > 0) {
        const last = with_mapping.entries[with_mapping.entries.len - 1];
        // 末尾追記が安全なのは `with:` がブロックマッピング（flow entry は
        // full_span を持たない）で、最後の値がインラインスカラーのときだけ。
        // フローコレクションは開始位置しか span を持たず、ブロックスカラーは
        // 次行の先頭で終わるため、どちらもアンカーにできない。
        if (last.full_span != null and isInlineScalar(last.value)) {
            step.with_last_entry_end_byte = last.value.getSpan().end_byte;
        }
    }
},
```

`isInlineScalar(node)`: `.scalar` かつ `style` が `literal`/`folded` 以外。`src/workflow/parser.zig` 内の private helper でよい。

**修正 2**（D5: 空 `with:` の二重挿入）:

- `src/util.zig` に `pub fn hasEmptySection(sections: []const EmptySection, name: []const u8) bool` を追加。
- `buildPersistCredentialsFalseFix`（`src/rules/security.zig:1020-1040`）と `buildCacheFix`（`src/rules/performance.zig:79-115`）の `with == null` 分岐の先頭で `if (util.hasEmptySection(step.empty_sections, "with")) return null;`（PERF001 は `continue`）。

**テスト**:
- `src/workflow/parser.zig`: 実 YAML から `with_last_entry_end_byte` を検証する 6 本 — `with: {x: y}` → null、`x: {a: b}` → null、`x: [a, b]` → null、`x: |` → null、`x: y` → `y` の直後、`x: "multi\n  line"` → 閉じクォートの直後。
- `src/rules/security.zig`: SEC018 で `with_last_entry_end_byte == null` かつ `with != null` → 診断あり・`fix == null`・`fix_hint` あり。`empty_sections` に `with` がある `with == null` step → `fix == null`。Issue repro を `applyFixes` に通して **ファイルが不変** であること。
- `src/rules/performance.zig`: PERF001 で同じ 2 本（`tests/fixtures/perf001-cache/` の既存ゴールデン形式に `setup-node-flow-with/` を追加し、`expected.yml == input.yml` で固定）。
- PBT: `strategies.py` に `workflow_with_flow_with`（checkout + `with: {…}` / `x: […]` / `x: |`）を追加し、`test_fixed_file_is_still_parseable` と `test_unsafe_fix_reduces_diagnostics_workflow` に載せる。SEC018 が fix を出さない場合でも「診断が増えない」性質は成立する。

### Iteration 5 — ドキュメント更新（別コミット）

- `docs/design/sec018-autofix-design.md`: anchor 表（32-34 行）に「`with_last_entry_end_byte` が null になる条件（フロー `with:` / 最終値がフローコレクションまたはブロックスカラー）と、その場合 fix を出さない」を追記。「SEC018 は parser 改修を必要としない」（37 行）を実態に合わせて修正。
- `docs/design/autofix-phase2-insertion-design.md`: anchor 説明（97, 103 行）に「`full_span.end_byte` はブロックスカラー値でも次の兄弟キー行の先頭を指す（#172）」を追記。
- `docs/design/pbt-strategy.md`: 追加した 3 ストラテジをカバレッジ表に追記。
- `docs/rules.md` EXPR001（157 行）: 「ネストが 256 段を超える式」を説明に追加。
- `tests/fixtures/e2e/README.md`: フィクスチャ表に 1 行追加（Iteration 1 で実施）。
- 本計画書は全イテレーション完了後に削除する（`update-docs` スキル 30 行の方針: 完了済み実装計画書は残さない。判断の記録は本書 §2 を ADR 化する価値は低いので、コミットメッセージと設計書追記で足りる）。

### 仕上げ

全イテレーション後に `wrapup` スキル（`/code-review` → `ponytail-review` → 取り込み → `cleanup-comments`）を通す。

## 4. コミット計画

| 順 | 種別 | 内容 |
|---|---|---|
| 1 | tidy | `tokenizer.zig`: `consumeNewline()` 抽出（動作変更なし） |
| 2 | fix | #173 行継続エスケープで行カウンタを進める + tokenizer テスト + E2E フィクスチャ |
| 3 | fix | #170 `ExprParser.depth` / `max_expr_depth` / `NestingTooDeep` + テスト + PBT |
| 4 | fix | #172 `blockEntryFullSpan` スカラー分岐 + yaml/workflow/rule テスト + PBT |
| 5 | fix | #171 `with_last_entry_end_byte` の条件付き設定 + `hasEmptySection` + テスト + ゴールデン + PBT |
| 6 | docs | Iteration 5 |

依存関係: 1→2 のみ。3, 4, 5 は互いに独立（#171 は D4 の条件により #172 に依存しない）。

## 5. 影響範囲

| 変更 | 影響を受ける既存機能 | 確認方法 |
|---|---|---|
| `scanQuotedScalar` の行カウント | ダブルクォート値以降の全診断の行番号（正しい方向に動く） | 既存 E2E（`sec002-run-quoted-scalar.yml` 等）の `@<line>` 固定が通ること |
| `blockEntryFullSpan` | `permissions_insertion_byte` / `concurrency_insertion_byte`（SEC007, BP005, PERM002）、DEP001 削除範囲、`fail_fast_entry_span` | 既存 autofix テスト + PBT `test_fixed_file_is_still_parseable` |
| `with_last_entry_end_byte` の null 化 | SEC015 / SEC018 / PERF001 の autofix 適用率がフロー・ブロックスカラー時に下がる（診断は変わらない） | `test_unsafe_fix_reduces_diagnostics_workflow` は「減らない」を検証するので影響なし |
| `ParseError.NestingTooDeep` | `ParseError` を switch する全箇所 | コンパイルエラーで検出 |

## 6. スコープ外（フォローアップ候補）

- フローコレクション／ブロックスカラーの後にも正しく追記できるようにする改修。`Mapping`/`Sequence` の span に終端を持たせるか、`MappingEntry` に「値の内容終端バイト」を持たせる YAML パーサ側の設計変更が要る。適用率の低下が実運用で問題になってから ADR を切る。
- `with: {}` を `with:\n  persist-credentials: false` に書き換える fix（空フローの置換）。
- `scanBlockScalar` が末尾の空行をブロックスカラー側に含める挙動の是非（本計画では現行仕様として固定する）。

## update-plan 検証結果

### 設計書品質評価

| 設計書 | モジュール設計 | YAML・WF解析 | エラー処理 | 技術選定 | データフロー | 平均 |
|--------|-------------|-------------|-----------|---------|------------|------|
| sec018-autofix-design.md | 90/100 | 75/100 | 90/100 | 90/100 | 90/100 | 87.0 |
| autofix-phase2-insertion-design.md | 95/100 | 85/100 | 90/100 | 95/100 | 95/100 | 92.0 |
| expr-static-typecheck-design.md | 95/100 | 90/100 | 90/100 | 95/100 | 95/100 | 93.0 |

**総合判定**: 🟡 軽微な改善後に着手可能（平均 90.7、ただし sec018 の anchor 記述が実態と乖離）

- sec018 の「YAML・WF解析 75」: anchor 表が `with_last_entry_end_byte` を無条件に使える前提で書かれ、フロー／ブロックスカラーの制約に触れていない（#171 の直接原因の記述漏れ）。Iteration 5 で追記する。
- autofix-phase2 の「YAML・WF解析 85」: `full_span.end_byte` がブロックスカラー値で誤る（#172）ことに触れていない。DEP001 の flow → null 規則（113 行）は本計画 D1 の根拠として有効。
- YAML tokenizer / parser には設計書が存在しないが、#172 / #173 はバグ修正であり新規 Phase ではないため、設計書の新規作成は行わない（`docs/design/pbt-strategy.md` と本書 §2 D3 に判断を残す）。

### 整合性チェック

| チェック項目 | スコア | 詳細 |
|-------------|--------|------|
| 設計書 ↔ ソースコード | 85/100 | sec018 設計書 37 行「parser 改修不要」は本計画で偽になる。行番号参照（`src/workflow/types.zig:247-278` 等）は現行ソースとずれているが本計画の対象外 |
| ADR ↔ 設計書 ↔ ルール一覧 | 95/100 | ADR 0001 D5（parser anchor を分離しない）と #172 修正は矛盾しない（anchor の計算精度を直すだけで anchor の分離はしない）。ADR 0006 の SEC018 autofix 方針（`--fix-unsafe`、`with` 有無で 2 分岐）は維持。ルール数・ID は増減なし。`docs/rules.md` EXPR001 の説明のみ追記 |

### 修正事項

- **P0**: なし
- **P1**: sec018-autofix-design.md の anchor 表と「parser 改修不要」記述の更新（Iteration 5 に組み込み済み）
- **P2**: autofix-phase2-insertion-design.md への #172 注記、`docs/rules.md` EXPR001 説明追記（Iteration 5 に組み込み済み）
