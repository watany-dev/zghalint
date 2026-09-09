# 起動・アロケーション・メモリ利用率

最終更新: 2026-09-09

`--perf` は wall time と最大 RSS しか出さない。起動が支配的なのか、ファイル
ごとの alloc なのか、RSS がライブヒープなのかは分からない。本メモは
`python3 scripts/bench.py --alloc`（`-Dalloc-stats` バイナリ）で測った内訳と、
そこから見えるボトルネックである。

計測は Linux x86_64 / 4 論理 CPU、`zig build -Doptimize=ReleaseFast
-Dalloc-stats`（strip 済み、2.1 MiB）、3 runs / warmup 1、GNU time の
VmHWM、`strace -c`。CountingAllocator は **親アロケータ**（ReleaseFast では
`smp_allocator`）への要求だけを数える。ファイルごとの YAML / workflow
アリーナ内部の bump はここに出ない。

## 1. 結果

| シナリオ | ファイル | 行 | wall | RSS | allocs | peak heap | peak/RSS |
|---|---|---|---|---|---|---|---|
| version (`--version`) | 0 | 0 | 0.3 ms | 0.8 MiB | 3 | 153 B | ~0% |
| tiny | 1 | 11 | 0.6 ms | 1.5 MiB | 34 | 17 KiB | 1% |
| cases | 136 | 2,315 | 3.3 ms | 2.0 MiB | 2,328 | 135 KiB | 7% |
| huge | 1 | 10,035 | 10.5 ms | 8.0 MiB | 1,052 | 7.5 MiB | 93% |
| many-files (cases×200) | 200 | 3,338 | 4.3 ms | 2.1 MiB | 3,443 | 203 KiB | 9% |

フェーズ別 wall（instrumented、目安）:

| シナリオ | args | config+dedupe | read | yaml | workflow | rules | copy | output |
|---|---|---|---|---|---|---|---|---|
| tiny | 0.03 | 0.05 | 0.01 | 0.02 | 0.02 | 0.05 | 0.00 | 0.01 |
| cases | 0.06 | 0.34 | 0.29 | 0.42 | 0.18 | 1.16 | 0.07 | 0.14 |
| huge | 0.03 | 0.04 | 0.15 | 2.48 | 1.43 | 6.20 | 0.24 | 0.44 |
| many-files | 0.06 | 0.41 | 0.38 | 0.59 | 0.27 | 1.62 | 0.12 | 0.37 |

単位は ms。`config` フェーズは `loadConfig` に加えて `dedupeFiles` の
`realpathAlloc` を含む。

## 2. ボトルネック

### 起動は単ファイル以外では支配的でない

`--version` は 0.3 ms・alloc 3 回・153 B。tiny の 0.6 ms のうち約半分が
プロセス起動で、残りが 1 ファイルの lint。cases（3.3 ms）では起動は 10%
未満。単ファイルの CI ステップをさらに削るなら動的リンカとバイナリサイズ
（2.1 MiB）が下限で、lint 本体ではない。

`http_client.init` や advisory アリーナは `--offline` でも呼ばれるが、
初回 use まで bump しないので `caches` フェーズの alloc は 0 だった。

### 多数ファイルの RSS はヒープではなくバイナリ

cases の peak heap は 135 KiB、RSS は 2.0 MiB。ライブな AST はファイル
ごとにアリーナごと捨てるので、RSS の大半は 2.1 MiB のテキスト＋
`smp_allocator` が返さないスラブ（#294 の mmap 過多は既に無い: cases で
mmap 23 / munmap 24）。peak/RSS 7% は「メモリを食っている」のではなく
「小さなヒープを大きなバイナリが抱えている」。

多数ファイルの syscall はファイルごと: `openat` / `close` / `read` /
`statx` / `readlink`。`readlink` は `dedupeFiles` の realpath（136 ファイル
で 152 回）。`faccessat` の error は欠ける config / lockfile のプローブ。

argv は POSIX でも引数を 1 本ずつ dupe する（cases で args 151 alloc /
18 KiB）。`--fix` で同じファイルを 2 綴り渡したときのためのコピーで、
多数ファイルでは realpath と並んで起動後の固定費になる。

### 巨大ファイルはルール実行と AST 密度

huge の wall の約 59% が `lint_rules`、24% が YAML、14% が workflow 化。
peak heap 7.5 MiB は RSS 8.0 MiB とほぼ一致する（利用率 93%）。ここは
ライブな AST で、アロケータキャッシュではない。

ソースは 417 KiB。親アロケータから見た YAML アリーナは 4.18 MiB（約 10
倍）、workflow 化がさらに 2.14 MiB。ノード・`item_deletes`・ArrayList の
capacity がソースを膨らませる。親から見た YAML alloc は 16 回だけで、
アリーナが 1.5 倍で伸びている — GPA の小片ではなくスラブである。

ルール側は EXPR の overlay（ジョブごと・ステップごとに TypeEnv を積む）
と、`check_step` を持つルールの本体が支配的。workflow 専用ルールの
job/step ループは外したが、huge の wall は測定誤差の範囲で動かなかった
（空ループよりチェック本体の方が重い）。

### サイズ階級

tiny / cases では alloc の大半が ≤4 KiB（アリーナの最初のスラブと診断
メッセージ）。huge の large（>4 KiB）は 60 回で、ソース本体とアリーナ
成長と診断バッファ。小片の GPA 嵐ではない。

## 3. 入れた変更とその効果

- `Engine.run` は `check_job` / `check_step` が両方 null のルールで
  ジョブ・ステップを歩かない。job-only ルールはステップループを走らない。
- YAML パーサはアリーナ上の `ArrayList.toOwnedSlice` をやめた。remap に
  失敗すると exact-size のコピーが残り、コレクションを二重に積むため。

どちらも親アロケータの回数・スラブサイズは huge で変わらなかった
（アリーナの 1.5 倍成長がコピー分を隠す）。コピーを止めた分の bump
浪費はスラブ内に残るだけで、RSS には出ていない。

## 4. 次に効く場所

計測が指しているのは次の 3 点で、起動や mmap ではない。

1. **ルール本体**（huge の 6 ms）。EXPR overlay と step ルールの交差。
2. **YAML AST の密度**（ソースの ~10 倍）。lint だけの実行で
   `item_deletes` を組まない、スカラーをソース slice のままにする
   （既にそう）以外のノードを小さくする。
3. **多数ファイルのパス処理**。`dedupeFiles` の realpath と argv dupe。
   重複が無い argv では string 同一性だけで足り、symlink の 2 綴りだけ
   realpath すれば `readlink` はほぼ消える。
