#!/bin/bash
set -e

# Claude Code (web) の sandbox 環境では pip 配布の ziglang 0.15.2 が使う
# x86_64 self-hosted バックエンドが `TODO rework lowerUav` で panic することが
# ある。LLVM バックエンドなら動くため、`zig` を wrapper 経由にしてコンパイル
# 系サブコマンドへ `-fllvm` を注入する。ビルドステップの定義は build.zig に
# 一本化してあるので、wrapper は `-fllvm` の注入だけを行う。

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
# zghalint Zig wrapper: force the LLVM backend on compile subcommands.
set -e

REAL_ZIG="/usr/local/bin/zig-real"
if [ ! -x "$REAL_ZIG" ]; then
  REAL_ZIG="$(python3 -c 'import os, ziglang; print(os.path.join(os.path.dirname(ziglang.__file__), "zig"))' 2>/dev/null || true)"
fi
if [ -z "$REAL_ZIG" ] || [ ! -x "$REAL_ZIG" ]; then
  echo "zig wrapper: cannot locate the real zig binary" >&2
  exit 127
fi

case "${1:-}" in
  build-exe|build-lib|build-obj|test|run|test-obj|translate-c|reduce)
    sub="$1"
    shift
    for arg in "$@"; do
      case "$arg" in
        -fllvm|-fno-llvm) exec "$REAL_ZIG" "$sub" "$@";;
      esac
    done
    exec "$REAL_ZIG" "$sub" -fllvm "$@"
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
