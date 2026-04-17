#!/bin/bash
set -e

# Claude Code (web) の sandbox 環境では ziglang==0.15.2 の x86_64 self-hosted
# バックエンドが `TODO rework lowerUav` で panic する。LLVM バックエンドなら
# 正常に動くため、`zig` を wrapper 経由にして `-fllvm` を注入する。
# `zig build` は build.zig 自体のコンパイルにも default backend が使われて
# 救えないので、wrapper 内部で必要な build ステップを直接 zig コマンドに
# 展開する。

ZIG_VERSION="0.15.2"
WRAPPER_PATH="/usr/local/bin/zig"
REAL_ZIG_LINK="/usr/local/bin/zig-real"

resolve_real_zig() {
  python3 -c 'import os, ziglang; print(os.path.join(os.path.dirname(ziglang.__file__), "zig"))'
}

install_ziglang() {
  if python3 -c "import ziglang" >/dev/null 2>&1; then
    local current
    current="$(python3 -c 'import ziglang, importlib.metadata as m; print(m.version("ziglang"))' 2>/dev/null || echo "")"
    if [ "$current" = "$ZIG_VERSION" ]; then
      return 0
    fi
  fi
  echo "Installing ziglang==$ZIG_VERSION via pip..."
  pip3 install --quiet "ziglang==$ZIG_VERSION"
}

install_wrapper() {
  local real
  real="$(resolve_real_zig)"

  # `/usr/local/bin/zig` may be a symlink pointing at the real binary.
  # Writing to it via redirection would follow the symlink and corrupt
  # the binary, so remove the link first.
  rm -f "$WRAPPER_PATH" "$REAL_ZIG_LINK"
  ln -s "$real" "$REAL_ZIG_LINK"

  cat >"$WRAPPER_PATH" <<'WRAPPER'
#!/bin/bash
# zghalint Zig wrapper.
#
# pip 配布の ziglang (0.15.2) は x86_64 self-hosted backend を Debug で使うが、
# この環境（gVisor/runsc）だと `TODO rework lowerUav` で panic する。
# LLVM backend (`-fllvm`) を強制すれば動作するので、該当サブコマンドに
# 自動で `-fllvm` を足す。`zig build` は build.zig 自体のコンパイルが救え
# ないため、zghalint プロジェクトの build ステップを直接展開する。
set -e

REAL_ZIG="/usr/local/bin/zig-real"
if [ ! -x "$REAL_ZIG" ]; then
  REAL_ZIG="$(python3 -c 'import os, ziglang; print(os.path.join(os.path.dirname(ziglang.__file__), "zig"))' 2>/dev/null || true)"
fi
if [ -z "$REAL_ZIG" ] || [ ! -x "$REAL_ZIG" ]; then
  echo "zig wrapper: cannot locate the real zig binary" >&2
  exit 127
fi

exec_with_llvm() {
  local sub="$1"
  shift
  for arg in "$@"; do
    case "$arg" in
      -fllvm|-fno-llvm) exec "$REAL_ZIG" "$sub" "$@";;
    esac
  done
  exec "$REAL_ZIG" "$sub" -fllvm "$@"
}

run_build() {
  local step=""
  local run_args=()
  local after_dd=0
  local skip_next=0
  local arg
  for arg in "$@"; do
    if [ $skip_next -eq 1 ]; then
      skip_next=0
      continue
    fi
    if [ $after_dd -eq 1 ]; then
      run_args+=("$arg")
      continue
    fi
    case "$arg" in
      --) after_dd=1;;
      --summary|--prefix|--cache-dir|--global-cache-dir|--zig-lib-dir|--build-file|--build-runner|--seed)
        skip_next=1
        ;;
      --*|-D*|-f*|-j*) ;;  # ignore other build-system flags
      *)
        if [ -z "$step" ]; then
          step="$arg"
        fi
        ;;
    esac
  done

  local out="zig-out"
  mkdir -p "$out/bin" "$out/lib"

  case "$step" in
    ""|install)
      "$REAL_ZIG" build-lib -fllvm --name zghalint \
        -femit-bin="$out/lib/libzghalint.a" \
        -Mroot=src/lib.zig
      "$REAL_ZIG" build-exe -fllvm --name zghalint \
        -femit-bin="$out/bin/zghalint" \
        --dep zghalint -Mroot=src/main.zig -Mzghalint=src/lib.zig
      ;;
    run)
      "$REAL_ZIG" build-exe -fllvm --name zghalint \
        -femit-bin="$out/bin/zghalint" \
        --dep zghalint -Mroot=src/main.zig -Mzghalint=src/lib.zig
      exec "$out/bin/zghalint" "${run_args[@]}"
      ;;
    test)
      "$REAL_ZIG" test -fllvm -Mroot=src/lib.zig
      "$REAL_ZIG" test -fllvm --dep zghalint \
        -Mroot=src/main.zig -Mzghalint=src/lib.zig
      ;;
    test-bin)
      "$REAL_ZIG" test -fllvm --test-no-exec \
        -femit-bin="$out/bin/test" \
        -Mroot=src/lib.zig
      ;;
    fmt)
      "$REAL_ZIG" fmt --check src build.zig
      ;;
    *)
      echo "zig wrapper: unsupported build step: $step" >&2
      echo "supported: (install) | run | test | test-bin | fmt" >&2
      exit 2
      ;;
  esac
}

case "${1:-}" in
  build-exe|build-lib|build-obj|test|run|test-obj|translate-c|reduce)
    sub="$1"
    shift
    exec_with_llvm "$sub" "$@"
    ;;
  build)
    shift
    run_build "$@"
    ;;
  *)
    exec "$REAL_ZIG" "$@"
    ;;
esac
WRAPPER
  chmod +x "$WRAPPER_PATH"
}

if [ "$(id -u)" -ne 0 ] && ! [ -w "$(dirname "$WRAPPER_PATH")" ]; then
  echo "setup-zig.sh: need root privileges to install into $(dirname "$WRAPPER_PATH")" >&2
  exit 1
fi

install_ziglang
install_wrapper

echo "zig wrapper installed: $(zig version)"
