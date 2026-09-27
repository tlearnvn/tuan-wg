#!/usr/bin/env bash
# Tuấn WireGuard - đóng gói .deb
# Cách dùng: packaging/build-deb.sh <phiên-bản> <binary> [kiến-trúc]
set -euo pipefail

VERSION="${1:?thiếu phiên bản}"
BIN="${2:?thiếu đường dẫn binary}"
ARCH="${3:-amd64}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TOP="$(cd "$HERE/.." && pwd)"
OUT="$TOP/dist"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

chmod 0755 "$ROOT"
mkdir -p "$OUT" "$ROOT/DEBIAN" "$ROOT/usr/bin" "$ROOT/usr/lib/systemd/system" \
  "$ROOT/usr/share/doc/tuan-wg" "$ROOT/usr/share/man/man1"

install -m 0755 "$BIN" "$ROOT/usr/bin/tuan-wg"
install -m 0644 "$HERE/tuan-wg.service" "$ROOT/usr/lib/systemd/system/tuan-wg.service"
install -m 0644 "$TOP/README.md" "$ROOT/usr/share/doc/tuan-wg/README.md"
gzip -9 -n -c "$TOP/CHANGELOG.md" >"$ROOT/usr/share/doc/tuan-wg/changelog.gz"
chmod 0644 "$ROOT/usr/share/doc/tuan-wg/changelog.gz"
gzip -9 -n -c "$HERE/tuan-wg.1" >"$ROOT/usr/share/man/man1/tuan-wg.1.gz"
chmod 0644 "$ROOT/usr/share/man/man1/tuan-wg.1.gz"
{
  echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
  echo "Upstream-Name: tuan-wg"
  echo "Upstream-Contact: Tuandethuong"
  echo "Source: https://github.com/tlearnvn/tuan-wg"
  echo
  echo "Files: *"
  echo "Copyright: $(date +%Y) Tuandethuong"
  echo "License: MIT"
  echo
  echo "Files: src/qrcodegen.*"
  echo "Copyright: Project Nayuki"
  echo "License: MIT"
  echo
  echo "Files: web/fonts/*"
  echo "Copyright: 2021 The Be Vietnam Pro Project Authors"
  echo "License: OFL-1.1"
  echo
  echo "License: MIT"
  sed 's/^$/./; s/^/ /' "$TOP/LICENSE"
} >"$ROOT/usr/share/doc/tuan-wg/copyright"

for f in postinst prerm postrm; do
  install -m 0755 "$HERE/debian/$f" "$ROOT/DEBIAN/$f"
done
SIZE="$(du -sk --exclude=DEBIAN "$ROOT" | cut -f1)"
sed -e "s/@VERSION@/$VERSION/" -e "s/@ARCH@/$ARCH/" -e "s/@SIZE@/$SIZE/" \
  "$HERE/debian/control.in" >"$ROOT/DEBIAN/control"

DEB="$OUT/tuan-wg_${VERSION}_${ARCH}.deb"
# -Zxz: Debian 10/11/12 chưa đọc được gói nén zstd (mặc định của dpkg Ubuntu)
dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$DEB" >/dev/null
echo "==> $DEB ($(du -h "$DEB" | cut -f1))"
