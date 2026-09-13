# AF5: SEC002 / SEC008 / SEC019 env 束縛 autofix 設計書

## 目的

script injection 系の定石の直し方は「untrusted な式を step の `env:` に束縛し、
`run:` 側ではシェル変数として参照する」の一手に収束する。

```yaml
# before
- run: echo "${{ github.event.pull_request.title }}"
# after
- env:
    PULL_REQUEST_TITLE: ${{ github.event.pull_request.title }}
  run: echo "$PULL_REQUEST_TITLE"
```

本設計書は issue #327 が実装前に決めることとして挙げた 6 点を確定させる。

対象ルール:

| ルール | 検出内容 |
|---|---|
| SEC002 script-injection | untrusted な context を `run:` またはコード実行系 action の input で使用 |
| SEC008 github-env-injection | untrusted な入力を `GITHUB_ENV` / `GITHUB_PATH` へ書き込み |
| SEC019 secrets-outside-env | secret を `env:` を経由せず `run:` / `with:` で直接使用 |

いずれも `Fix.safety` は `.unsafe`。挿入する env 変数名がワークフロー作者の命名と
衝突しうること、`run:` の本文をシェルの構文レベルで書き換えることの両方が理由である。

関連資料:
- `docs/design/autofix-phase2-insertion-design.md`
- `docs/design/bp008-autofix-design.md`（`run:` 本文の byte offset 復元の先例）
- `docs/design/sec018-autofix-design.md`（`with:` 挿入の先例、#171 / #300）

## スコープ

- 書き換え対象は `run:` 本文の中に現れる `${{ ... }}` のみ
- 束縛先は step 単位の `env:`（job / workflow 単位には触らない）
- 1 step の全該当式を 1 つの `Fix` にまとめる

## 非スコープ

- `with:` の中の式（SEC019 は `with:` でも検出するが fix は出さない）。
  `env:` に束縛しても `with:` 側は `${{ env.X }}` と書くほかなく、値は結局
  式として展開されるため、リスクも記述量も改善しない
- `actions/github-script` の `script:` input（SEC002 の第二経路）。
  JavaScript の構文レベルの書き換えになり、シェルとは別の設計が要る。
  その設計は `docs/design/af13-github-script-env-binding-design.md`（#416）
- 式そのものの検証（`fromJSON(...)` などの関数呼び出しを含む式）。
  後述の「命名できる式」に限定する

## 1. env 変数名の命名規約

式の中身を context path として読み、次の手順で名前を導く。

1. `.` 区切りのセグメントに分解する。各セグメントは `[A-Za-z_][A-Za-z0-9_-]*` に
   完全一致しなければならない（`[0]`、`*`、関数呼び出し、演算子、リテラルは不一致）
2. 先頭から、意味を持たない root セグメント（`github`、`event`、`secrets`、
   `steps`、`needs`、`inputs`）を落とす。全部落ちてしまう場合は元の全セグメントに戻す
3. 残りの末尾 3 セグメントまでを `_` で連結する
4. ASCII 大文字化し、`-` を `_` に置換する

例:

| 式 | 変数名 |
|---|---|
| `github.event.pull_request.title` | `PULL_REQUEST_TITLE` |
| `github.event.issue.body` | `ISSUE_BODY` |
| `github.head_ref` | `HEAD_REF` |
| `secrets.NPM_TOKEN` | `NPM_TOKEN` |

issue の例が挙げる `PR_TITLE` のような略語は採らない。略語表はワークフロー作者の
語彙に依存し、機械的に決められないためである。

**命名できない式が 1 つでもあれば、その step には fix を出さない。** 一部の式だけを
束縛した結果は「直っていないのに直ったように見える」ファイルであり、部分適用より
無適用のほうが安全である。

**衝突回避**: 導いた名前が `Step.env_keys` の既存キー、同じ `Fix` で既に割り当てた
名前、またはランナーが持つ名前（`PATH`、`HOME` などと `GITHUB_` / `RUNNER_` /
`ACTIONS_` で始まる名前）と衝突する場合、`_2`、`_3`、… を付す。`PATH` を束縛すれば
シェルが自分の `PATH` を失うため、これは見た目の問題ではない。同一の式が同じ step に複数回
現れる場合は 1 つの変数を共有する（束縛は 1 行、参照は複数箇所）。

## 2. シェル別の参照形

### シェルの決定

`step.shell` → job の `defaults.run.shell` → workflow の `defaults.run.shell` →
`runs-on` から推定した既定シェルの順に探す。`runs-on` からも OS が読み取れない場合、
および `shell:` の値が式やカスタム interpreter（`{0}` を含む）である場合は
**fix を出さない**。

`runs-on` からの推定は Linux / macOS（`bash`）だけとし、**Windows は推定しない**。
GitHub の既定は `pwsh` だが、`shell:` の無い Windows の `run:` step にはまさに
BP004 が `shell: bash` を足す fix を出す。両者は別の byte を触るので同時に適用され、
bash の step が `$env:NAME` を読む壊れたファイルになる。`shell:` が明示されていれば
BP004 は発火せず、こちらもその値からシェルを決められる。

| shell | 参照形 |
|---|---|
| `bash`, `sh`, `bash -e {0}` 相当の POSIX 系 | `$NAME` |
| `pwsh`, `powershell` | `$env:NAME` |
| `cmd` | `%NAME%` |
| `python`, その他 | fix を出さない |

### 引用の付け方

参照形をそのまま置くと、置換位置が既に引用の中かどうかで結果が変わる。
`run:` の該当行の先頭から置換位置までを、バックスラッシュエスケープを見ながら
`plain` / `dquote` / `squote` の 3 状態で走査し、置換位置の状態で決める。

- `dquote`（既に二重引用符の中）: 引用符を足さず `$NAME` / `$env:NAME` / `%NAME%`
- `plain`: 自前で二重引用符を付け `"$NAME"` / `"$env:NAME"` / `"%NAME%"`
- `squote`: **fix を出さない**。単一引用符の中では変数が展開されず、
  引用符を跨いで書き換えると元の意味を保てない

## 3. step 単位の `env:` 挿入点

`Step` に 3 つの情報を足す（parser 側）。

- `first_key_start_byte` / `first_key_col` — step mapping の最初のキーの開始 byte と列。
  `env:` が無い step に新しく `env:` ブロックを作るときの挿入点
- `env_last_entry_end_byte` — 既存 `env:` の最後のエントリの値の終端 byte。
  条件は `with_last_entry_end_byte` と同じ（block mapping であること、
  最後の値が inline scalar であること、#171）
- `env_key_col` — 既存 `env:` の最初のキーの列。追記時のインデント

`env:` が無い場合は `fix/builder.zig` に足す `insertMappingEntryBlockBefore` を使う。
これは `insertSequenceItemEntryBefore` と同じアンカー規約（既にインデントされた
兄弟キーの位置に挿し、押し出された兄弟のインデントを末尾で復元する）の mapping 版で、

```
env:
    KEY: ${{ ... }}
```

を 1 つの `Edit` として書き出す。既存 `env:` がある場合は `appendMappingEntries` で
最後のエントリの直後に全束縛を 1 つの `Edit` として追記する。

`env:` キーはあるが値が空（`env:` だけの行）の step は
`util.hasEmptySection(step.empty_sections, "env")` で弾き、fix を出さない。
新規挿入すればキーが二重になり、追記しようにもアンカーが無いためである（#171 と同型）。

## 4. `run:` 本文の書き換え範囲

`Step.run` 内のオフセットから原文 byte への写像は `src/rules/spans.zig` の
`Anchor`（`spans.runAnchor(step)`）が担う。ただし本 fix が扱うのは
`run_meta.style` が `.plain` か `.literal`（`|`）の場合だけとする。

理由は `fix/engine.zig` の `isValidEdit` が **不正な edit を fix ごとではなく
edit 単位で捨てる**ことにある。`expects` による fail-closed は単一 edit の fix では
安全だが、本 fix のように `env:` 挿入と `run:` 書き換えが対になっている多 edit の
fix では、片方だけ落ちると部分適用になる。したがって「原文と value が byte 単位で
一致する」ことが構造的に保証される style に限り、`expects` はさらなる保険として
併用する。

- `.folded`（`>`）: 行が空白に畳まれるため写像が成立しない
- `.single_quoted` / `.double_quoted`: エスケープ解除で byte 列が変わりうる
- `run_meta` が無い: 写像の起点が無い

## 5. 1 ステップに複数の式がある場合

`fix/engine.zig` は範囲が重なる `Fix` を丸ごと捨てるため、束縛と参照書き換えは
step 単位で 1 つの `Fix` にまとめる。診断は式ごとに出るので（SEC002）、
**その step の最初の診断にだけ `Fix` を付け、残りには付けない。**

SEC002 と SEC008 が同じ step で同時に発火した場合、2 つの `Fix` は同じ範囲を
書き換えるので片方が丸ごと捨てられる。残ったほうは単独で完結しており、
捨てられたほうの診断は次回実行で消えているので、結果は正しい。

## 6. SEC015 / SEC018 との共存

SEC015 / SEC018 が挿入するのは `with:` で、アンカーは `uses_value_end_byte`。
本 fix のアンカーは `first_key_start_byte`（新規）または `env_last_entry_end_byte`
（追記）で、いずれも別の byte 位置である。`run:` を持つ step は `uses:` を持たない
ため、そもそも同じ step で両者が発火しない。

#300 の二重挿入は「同じキーを同じアンカーに挿す fix が 2 本ある」ことが原因で、
`env:` を挿す fix は本設計の 3 ルールが共有する 1 つの実装だけである。加えて
`flattenAndSort` の `priorInsertionOfSameKey` が同一挿入を 1 回に畳むので、
仮に 2 本出ても二重挿入にはならない。

## 実装配置

- `src/rules/env_binding.zig` — 命名・シェル・引用状態・`Fix` 組み立ての共有実装
- `src/fix/builder.zig` — `insertMappingEntryBlockBefore` / `appendMappingEntries`
- `src/workflow/types.zig`, `src/workflow/parser.zig` — 上記 4 フィールド
- `src/rules/security.zig` — 3 ルールから該当式の offset を集めて `env_binding` に渡す

SEC019 は現在 `.check_step` で登録されており job も workflow も見られない。
シェル決定に `runs-on` と両レベルの `defaults:` が要るため `.check_workflow` へ移す
（composite action の step 検査には SEC019 は含まれていないので影響は無い）。

## テスト計画

- 単体: 命名（root 落とし、末尾 3 セグメント、衝突回避、命名不能で null）
- 単体: シェル決定（`step.shell` / job defaults / workflow defaults / `runs-on`、
  決められない場合は null）
- 単体: 引用状態（`plain` / `dquote` / `squote`）ごとの参照形
- 単体: `env:` あり / なし、複数式、同一式の重複、`.folded` と `.plain` の style 分岐
- 単体: 3 ルールそれぞれの fix と `.unsafe` 判定
- e2e: `tests/fixtures/e2e/` にシェル別・複数式・既存 `env:` あり／なしの fixture と
  `.fixed-unsafe` sibling
