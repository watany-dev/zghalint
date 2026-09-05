---
name: cleanup-comments
description: >
  Manual-only. Sweep every code comment in the repository, delete everything
  that restates the code, keep only "why" that cannot be reconstructed from
  the code, and turn TODO-like comments into GitHub issues. Fire ONLY when the
  user explicitly invokes /cleanup-comments or says "cleanup-comments" —
  never trigger on your own from an ordinary refactor, review, or tidy
  request.
---

# cleanup-comments

コード中のコメントを全件見て、**コードから復元できない why だけを残し、それ以外は削除する**。
TODO 相当のコメントは GitHub issue に起こし、コメント側は issue 番号参照へ書き換える。

コード自体（識別子、ロジック、文字列リテラル、テスト）は一切変更しない。触るのはコメントのみ。
構造的変更として、機能変更とは別コミットにする（Tidy First）。

## 判断基準

### 削除するもの (what / how)

- コードを読めば分かること: 何をしているか、手順、名前から自明な引数・返り値の説明
  例: `// skip whitespace`, `// Check if ...`, `/// Returns true if ...`, `/// Find the first ...`
- セクション区切りバナー: `// ===== SEC001 =====`, `// --- Tests ---`, `// Shared helpers`
- テスト内の手順説明: `// Should detect SEC015`, `// Apply the fix`, `// Verify ...`
- `///` doc comment も対象。pub であっても名前・シグネチャ・本体から分かるものは削除
- 例示だけのコメント (`/// e.g. "a.b" becomes {"a","b"}`)
- what と why が混在する場合は **why の文だけ残して what の文を削る**（簡潔に書き直してよい）

### 残すもの (why)

- 外部仕様に由来する理由（GitHub Actions / YAML / GitHub API の挙動上こうする必要がある）
- Issue / PR 参照 (`#138`) と、その判断の経緯
- なぜ別の素直な方法を取らないか、過去の不具合の回避
- マジックナンバー・定数値の根拠
- fail-safe / fail-open の方針、順序依存・ソート安定性への依存
- 「span がないので job を anchor にする」のような代替を選んだ理由
- テストで「なぜこのケースを検証するか」を説明する意図コメント（再発防止など）
- 迷ったら: 「消したとき、次の開発者が『なぜこう書いてあるのか』と疑問に思うか？」→ 思うなら残す

### TODO 相当

`TODO` / `FIXME` / `not yet` / `follow-up` / `未対応` / `将来` / `暫定` / `workaround` など、
未完了の作業・既知の制限・保留中の判断を示すコメントは **Phase 1 では削除せず残して列挙**し、
Phase 3 で issue 化してから issue 番号参照に書き換える。

### 機械的な注意

- 文字列リテラル内の `//` (`"https://..."`, テストデータ) は触らない
- 行末コメント (`code // comment`) は末尾部分だけ削る
- 行番号参照を含むコメント (`parser.zig:59-60`) はずれやすいので、識別子名での参照に書き換える
- 日本語コメントも同じ基準
- 連続空行は `zig fmt` が整える

## Phase 1: 削除

1. 対象を列挙する: `grep -rlE '^\s*//|\S\s+//[^/]' src build.zig`
2. ファイル数が多ければ、ファイル集合を重複なく分割してサブエージェントに並列委譲する。
   全員に上の判断基準をそのまま渡し、各自の担当ファイル以外は触らせない。
   サブエージェントは `zig build` / `zig build test` を実行しない（最後にまとめて実行する）
3. 各ファイルで `grep -nE -A1 '^\s*//' FILE` と `grep -nE '\S\s+//[^/]' FILE` を読み、
   行範囲ごとに D=削除 / K=残す / R=書き換え / T=TODO 相当 の判断リストを作る
4. 判断リストを **元ファイルの行番号基準で後ろから** 適用する（前から適用すると行番号がずれる）。
   削除対象行に `//` が無ければ中断する安全弁を入れる
5. `zig fmt FILE` を実行し、残ったコメントを再確認する
6. 報告: 残したコメント一覧、TODO 相当の一覧、迷った判断

## Phase 2: 検証とコミット

1. コメントだけが変わったことを機械的に証明する。文字列リテラル外の `//` 以降と空行を落として
   HEAD と作業ツリーを比較し、全ファイルで一致すること:

   ```python
   # strip.py FILE — `//` コメント（文字列リテラル外）と空行を除去して出力
   import sys
   def strip(src):
       out = []
       for line in src.splitlines():
           res, i, in_str = [], 0, False
           while i < len(line):
               c = line[i]
               if in_str:
                   if c == '\\': res.append(line[i:i+2]); i += 2; continue
                   if c == '"': in_str = False
               elif c == '"': in_str = True
               elif line.startswith('//', i): break
               res.append(c); i += 1
           s = ''.join(res).rstrip()
           if s: out.append(s)
       return '\n'.join(out)
   print(strip(open(sys.argv[1]).read()))
   ```

   ```bash
   for f in $(git diff --name-only); do
     git show HEAD:$f > /tmp/head.zig
     [ "$(python3 strip.py /tmp/head.zig | md5sum)" = "$(python3 strip.py $f | md5sum)" ] || echo "CODE DIFF: $f"
   done
   ```

2. `zig build && zig fmt --check src/ build.zig && zig build test --summary all` を通す
3. コメント削除だけのコミットを作る（TODO 相当はまだ残っている状態でよい）

## Phase 3: TODO を issue 化

1. TODO 相当コメントごとに `mcp__github__search_issues` と open issue 一覧で既存 issue を探す。
   既に追跡されているものは新規作成しない
2. 未追跡のものは `mcp__github__issue_write` で作成する。本文は 背景（該当コメントを引用し、
   何が未対応か）／ 対応内容 ／ 参照（ファイルと関数名、関連 design doc・issue）の 3 節
3. コメント側を「not yet」「follow-up」の表現から issue 番号参照へ書き換える
   （例: `is not handled yet (#158)`, `#161 tracks that decision`）
4. CI を再度通し、issue 参照への書き換えを別コミットにする
5. push する。PR は求められない限り作らない

## 報告

- 削除した種類と残した種類の要約
- 変更ファイル数・差分行数、コメント除去後の等価性チェック結果、CI 結果
- コミット一覧
- 作成した issue 一覧と、既存 issue に寄せたもの
- 末尾に「必要なら」等の条件付き提案は書かない（AGENTS.md）
