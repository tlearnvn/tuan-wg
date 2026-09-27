#!/usr/bin/env bash
# Tuấn WireGuard - cài đặt/cập nhật bằng một lệnh
#
#   curl -fsSL https://raw.githubusercontent.com/tlearnvn/tuan-wg/main/scripts/install.sh | sudo bash
#
# Biến môi trường tùy chọn:
#   TUAN_WG_VERSION=1.2.3   cài một phiên bản cụ thể (mặc định: bản mới nhất)
#   TUAN_WG_ARGS="-y --endpoint vpn.example.com"   tham số thêm cho "tuan-wg install"
# Tác giả: Tuandethuong
set -euo pipefail

REPO="tlearnvn/tuan-wg"
VERSION="${TUAN_WG_VERSION:-}"
ARGS="${TUAN_WG_ARGS:-}"

c_green='\033[32m'; c_red='\033[31m'; c_cyan='\033[36m'; c_bold='\033[1m'; c_off='\033[0m'
say() { printf "${c_cyan}==>${c_off} %s\n" "$*"; }
die() { printf "${c_red}Lỗi:${c_off} %s\n" "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "hãy chạy với quyền root (sudo)."
case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  *) die "hiện chỉ hỗ trợ Linux amd64 (máy của bạn: $(uname -m))." ;;
esac

fetch() { # fetch URL FILE
  if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1"
  else die "cần curl hoặc wget."; fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ -n "$VERSION" ]; then
  BASE="https://github.com/$REPO/releases/download/v${VERSION#v}"
  DEB_NAME="tuan-wg_${VERSION#v}_${ARCH}.deb"
  TAR_NAME="tuan-wg-${VERSION#v}-linux-${ARCH}.tar.gz"
else
  BASE="https://github.com/$REPO/releases/latest/download"
  DEB_NAME="tuan-wg_${ARCH}.deb"
  TAR_NAME="tuan-wg-linux-${ARCH}.tar.gz"
fi

printf "\n${c_bold}  Tuấn WireGuard - trình cài đặt nhanh${c_off}\n  https://github.com/%s\n\n" "$REPO"

if command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
  say "Tải gói $DEB_NAME ..."
  fetch "$BASE/$DEB_NAME" "$TMP/tuan-wg.deb" || die "không tải được gói cài đặt."
  say "Cài đặt gói (apt sẽ tự cài wireguard-tools, iptables, iproute2) ..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || true
  if [ -n "$ARGS" ]; then export TUAN_WG_SKIP_SETUP=1; fi
  apt-get install -y "$TMP/tuan-wg.deb"
  if [ -n "$ARGS" ]; then
    # shellcheck disable=SC2086
    tuan-wg install $ARGS
  fi
else
  say "Không có apt - dùng bản tar.gz ($TAR_NAME) ..."
  fetch "$BASE/$TAR_NAME" "$TMP/tuan-wg.tar.gz" || die "không tải được bản tar.gz."
  tar -C "$TMP" -xzf "$TMP/tuan-wg.tar.gz"
  DIR="$(find "$TMP" -maxdepth 1 -type d -name 'tuan-wg-*' | head -n1)"
  # shellcheck disable=SC2086
  "$DIR/tuan-wg" install -y $ARGS
fi

printf "\n${c_green}✔ Hoàn tất!${c_off} Xem trạng thái: ${c_bold}sudo tuan-wg status${c_off}\n"
