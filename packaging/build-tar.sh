#!/usr/bin/env bash
# Tuấn WireGuard - đóng gói .tar.gz (binary tĩnh cho mọi bản Linux)
# Cách dùng: packaging/build-tar.sh <phiên-bản> <binary> [kiến-trúc]
set -euo pipefail

VERSION="${1:?thiếu phiên bản}"
BIN="${2:?thiếu đường dẫn binary}"
ARCH="${3:-amd64}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TOP="$(cd "$HERE/.." && pwd)"
OUT="$TOP/dist"
NAME="tuan-wg-${VERSION}-linux-${ARCH}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$OUT" "$TMP/$NAME"
install -m 0755 "$BIN" "$TMP/$NAME/tuan-wg"
install -m 0644 "$HERE/tuan-wg.service" "$TMP/$NAME/tuan-wg.service"
install -m 0644 "$HERE/tuan-wg.1" "$TMP/$NAME/tuan-wg.1"
install -m 0644 "$TOP/README.md" "$TOP/CHANGELOG.md" "$TOP/LICENSE" "$TMP/$NAME/"
cat >"$TMP/$NAME/install.sh" <<'EOF'
#!/bin/sh
# Cài Tuấn WireGuard từ gói tar.gz
set -e
cd "$(dirname "$0")"
if [ "$(id -u)" != "0" ]; then echo "Cần chạy với quyền root: sudo ./install.sh"; exit 1; fi
exec ./tuan-wg install "$@"
EOF
chmod 0755 "$TMP/$NAME/install.sh"
TAR="$OUT/$NAME.tar.gz"
tar -C "$TMP" --owner=0 --group=0 --numeric-owner -czf "$TAR" "$NAME"
echo "==> $TAR ($(du -h "$TAR" | cut -f1))"
