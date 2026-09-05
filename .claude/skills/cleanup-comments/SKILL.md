---
name: cleanup-comments
description: >
  Manual-only. Sweep every code comment, delete what restates the code,
  keep only "why" that cannot be reconstructed from the code, and turn
  TODO-like comments into GitHub issues. Fire only when the user invokes
  /cleanup-comments or says "cleanup-comments".
---

# cleanup-comments

コード中のコメントを全件見て、**コードから復元できない why だけを残し、それ以外は削除する**。
コードは触らない。コメントだけの変更として、機能変更とは別コミットにする。

## 基準

- 削除: コードを読めば分かること。手順の説明、名前から自明な doc comment、セクションバナー、テスト内の手順説明
- 残す: 理由。外部仕様の制約、issue 参照、素直な方法を取らない理由、定数の根拠、fail-open / fail-close の方針、順序依存、テストの意図
- 混在していれば why の文だけ残す
- 迷ったら「消したとき、次の開発者が『なぜ』と疑問に思うか」で決める

## TODO

`TODO` / `not yet` / `follow-up` / `未対応` / `暫定` など未完了の作業や保留中の判断を示すコメントは、
既存 issue を探した上で無ければ issue を作り、コメントを issue 番号参照に書き換える。

## 手順

1. コメントを削る。コメント以外が変わっていないことを diff で確かめる
2. `zig build && zig fmt --check src/ build.zig && zig build test --summary all` を通してコミット
3. TODO を issue 化し、参照の書き換えを別コミットにして push
