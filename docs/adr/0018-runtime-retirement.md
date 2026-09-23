# 0018. ランタイム廃止の扱い

- Status: Accepted
- Date: 2026-09-15
- Deciders: issue #550（親 #544「node20 廃止への追従」）

## Context

GitHub Actions の `runs.using` は数年ごとに世代が切り替わる。node12・node16 は
既にランナーから外れ、node20 も 2026-09-23 に外れる。zghalint はこれを 2 箇所で
持っている。

| 場所 | 役割 |
|---|---|
| `src/rules/local_action.zig` の `retired_runtimes` / `ending_runtimes` | 廃止済み / 廃止告知済みのランタイム名 |
| `src/rules/action_metadata.zig` の `supported_using` | ACT002 が受理する `using` の値 |

前者を BP003（`uses:` 先のランタイム）と ACT002（自リポジトリの `action.yml`）が
読む。廃止日が近づくたびに「いつ・どこを・どう切り替えるか」を再発明していたので、
node20 の切替を機に手順として残す。

## Decisions

### D1. 日付によるビルド時・実行時の自動切替はしない

「2026-09-23 を過ぎたら node20 を retired にする」を `@import("builtin")` の
ビルド時刻や実行時の時計から導く実装は採らない。同じバイナリが**走らせた日に
よって診断を変える**と、CI のログと手元の再現が食い違い、`.fixed` 系フィクスチャ
のようにバイト単位で出力を固定しているテストが日付で落ちる。lint の結果は入力
（ワークフロー + 設定 + バイナリ）だけで決まる。

告知から廃止までの数か月は、`ending_runtimes` が `warning` で埋める。

### D2. 廃止はリリースで切り替える

表の書き換えはリリース作業の一部として行う。v0.0.3 が node20 廃止の切替点で、
このリリースを境に BP003 は node20 を `error`、ACT002 は「もう動かない」と報告する。

切替は廃止日の**前**に入れる。v0.0.3 の変更は 2026-09-15、期日の 8 日前である。
D1 で日付を見ないと決めた以上、期日ちょうどに変わるバイナリは作れない。前倒し
なら「まだ動くものを error と言う」数日で済み、利用者は期日前に移行を終えられる。
後追いにすると「もう動かないものを warning と言う」期間ができ、CI が緑のまま
ランナー側で落ちる。誤る向きは前者を選ぶ。

「廃止日より前に出たリリース」は node20 を `warning` のまま報告し続けるが、これは
正しい——その版が作られた時点では実際に動いていた。利用者が期日までに版を上げる
のは、他の検出ルールを取り込むのと同じ普通の更新である。

### D3. 次の廃止（node24）も同じ手順を踏む

告知が出たら `ending_runtimes` に足して `warning`、廃止日を含むリリースで
`retired_runtimes` へ移す。移すときに触る箇所は以下で全部である。

1. `src/rules/local_action.zig` — `ending_runtimes` から `retired_runtimes` へ移す
2. `src/rules/action_metadata.zig` — `supported_using` と `using_expected` から外す
   （`node_using` には残す。未知の値ではなく「廃止された値」として報告するため）
3. `scripts/popular-actions.txt` を見直して
   `python3 scripts/gen-popular-actions.py` を回す（`docs/maintenance.md`）
4. `src/rules/best_practices.zig` の `deprecated_actions` が、廃止するランタイムで
   動く major を推奨していないか確認する。推奨していたら、そのランタイムを積んだ
   最初の major へ上げる（node20 廃止では checkout v4 → v5 など 8 件全て動いた）
5. `CHANGELOG.md` の **Changed** に ACT002 / BP003 の変化を書く
6. `python3 scripts/bench.py --json /tmp/bench.json` と
   `scripts/bench_gate.py --update` で baseline を取り直す

## Consequences

- `ending_runtimes` は次の告知まで空になる。空でも機構は残す——消すと D3 の
  「告知で warning、廃止で error」の半分を毎回書き直すことになる。
- 廃止日をまたぐ期間は、古い版の zghalint と新しい版で同じファイルの severity が
  違う。差が出たら版を確認する、という形で D2 の帰結を受け入れる。
- 4 の確認を怠ると、同じルールが「node20 は廃止だ」と言いながら node20 で動く
  major を fix で書き込む、という自己矛盾が起きる。node20 の切替では実際に
  `deprecated_actions` 8 件全てがその状態だった。
