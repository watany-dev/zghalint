#!/bin/bash
set -e

if command -v zig &>/dev/null; then
  echo "zig already installed: $(zig version)"
  exit 0
fi

echo "Installing Zig via pip..."
pip3 install ziglang==0.14.1

# Create symlink so zig is available in PATH
ZIG_BIN="$(python3 -c 'import os, ziglang; print(os.path.join(os.path.dirname(ziglang.__file__), "zig"))')"
ln -sf "$ZIG_BIN" /usr/local/bin/zig

echo "Zig installed: $(zig version)"
