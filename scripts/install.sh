#!/usr/bin/env bash
# Tuấn WireGuard - cài đặt/cập nhật bằng một lệnh
#
#   curl -fsSL https://raw.githubusercontent.com/tlearnvn/tuan-wg/HEAD/scripts/install.sh | sudo bash
#
# Cài gói dựng sẵn từ GitHub Releases; nếu chưa có bản phát hành thì tự build từ mã nguồn.
# Biến môi trường tùy chọn:
#   TUAN_WG_VERSION=1.2.3   cài một phiên bản cụ thể (mặc định: bản mới nhất)
#   TUAN_WG_ARGS="-y --endpoint vpn.example.com"   tham số thêm cho "tuan-wg install"
#   TUAN_WG_SOURCE=1        bỏ qua gói dựng sẵn, luôn build từ mã nguồn
#   TUAN_WG_GIT=URL         kho mã nguồn dùng khi build (mặc định: https://github.com/tlearnvn/tuan-wg.git)
# Tác giả: Tuandethuong
set -euo pipefail

REPO="tlearnvn/tuan-wg"
VERSION="${TUAN_WG_VERSION:-}"
ARGS="${TUAN_WG_ARGS:-}"
GIT_URL="${TUAN_WG_GIT:-https://github.com/$REPO.git}"

c_green='\033[32m'; c_red='\033[31m'; c_cyan='\033[36m'; c_bold='\033[1m'; c_off='\033[0m'
say() { printf "${c_cyan}==>${c_off} %s\n" "$*"; }
die() { printf "${c_red}Lỗi:${c_off} %s\n" "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "hãy chạy với quyền root (sudo)."
case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  *) die "hiện chỉ hỗ trợ Linux amd64 (máy của bạn: $(uname -m))." ;;
esac

fetch() { # fetch URL FILE
  if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1"
  else die "cần curl hoặc wget."; fi
}

HAVE_APT=0
if command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then HAVE_APT=1; fi
export DEBIAN_FRONTEND=noninteractive

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Build từ mã nguồn rồi chạy trình cài đặt (binary được chép vào /usr/local/bin/tuan-wg)
build_from_source() {
  say "Build từ mã nguồn (khoảng 1 phút) ..."
  if [ "$HAVE_APT" = 1 ]; then
    apt-get update -qq || true
    apt-get install -y -qq build-essential git ca-certificates >/dev/null || die "không cài được công cụ build (build-essential, git)."
    apt-get install -y -qq musl-tools >/dev/null 2>&1 || true
  fi
  for c in git make cc; do
    command -v "$c" >/dev/null 2>&1 || die "thiếu lệnh '$c' - hãy cài git, make và trình biên dịch C."
  done
  local ref=()
  [ -n "$VERSION" ] && ref=(--branch "v${VERSION#v}")
  git clone -q --depth 1 ${ref[@]+"${ref[@]}"} "$GIT_URL" "$TMP/src" || die "không tải được mã nguồn từ $GIT_URL"
  local target=all bin="$TMP/src/build/tuan-wg"
  if command -v musl-gcc >/dev/null 2>&1; then
    target=static
    bin="$TMP/src/build/static/tuan-wg"
  fi
  if ! make -C "$TMP/src" -j"$(nproc 2>/dev/null || echo 2)" "$target" >"$TMP/build.log" 2>&1; then
    tail -n 30 "$TMP/build.log" >&2
    die "build lỗi (xem log ở trên)."
  fi
  say "Đã build $("$bin" version | head -n1)"
  # shellcheck disable=SC2086
  "$bin" install -y $ARGS
}

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

if [ "${TUAN_WG_SOURCE:-0}" = 1 ]; then
  build_from_source
elif [ "$HAVE_APT" = 1 ]; then
  say "Tải gói $DEB_NAME ..."
  if fetch "$BASE/$DEB_NAME" "$TMP/tuan-wg.deb" 2>/dev/null; then
    say "Cài đặt gói (apt sẽ tự cài wireguard-tools, iptables, iproute2) ..."
    apt-get update -qq || true
    if [ -n "$ARGS" ]; then export TUAN_WG_SKIP_SETUP=1; fi
    apt-get install -y "$TMP/tuan-wg.deb"
    if [ -n "$ARGS" ]; then
      # shellcheck disable=SC2086
      tuan-wg install $ARGS
    fi
  else
    say "Chưa có gói dựng sẵn trên GitHub Releases - chuyển sang build từ mã nguồn."
    build_from_source
  fi
else
  say "Không có apt - dùng bản tar.gz ($TAR_NAME) ..."
  if fetch "$BASE/$TAR_NAME" "$TMP/tuan-wg.tar.gz" 2>/dev/null; then
    tar -C "$TMP" -xzf "$TMP/tuan-wg.tar.gz"
    DIR="$(find "$TMP" -maxdepth 1 -type d -name 'tuan-wg-*' | head -n1)"
    # shellcheck disable=SC2086
    "$DIR/tuan-wg" install -y $ARGS
  else
    say "Chưa có bản tar.gz trên GitHub Releases - chuyển sang build từ mã nguồn."
    build_from_source
  fi
fi

printf "\n${c_green}✔ Hoàn tất!${c_off} Xem trạng thái: ${c_bold}sudo tuan-wg status${c_off}\n"
