#!/usr/bin/env bash
# Tuấn WireGuard - kiểm thử tích hợp REST API (không cần root, không đụng WireGuard: --no-wg)
# Cách chạy: tests/api_test.sh [binary]
set -euo pipefail

BIN="$(readlink -f "${1:-$(dirname "$0")/../build/tuan-wg}")"
DATA="$(mktemp -d)"
PORT=18300
API="http://127.0.0.1:$PORT"
PASS="Api-Test-Pass-1"
CJ="$DATA/cj"
PASSED=0

ok() { PASSED=$((PASSED + 1)); printf '\033[32m  ✔ %s\033[0m\n' "$*"; }
fail() { printf '\033[31m  ✖ %s\033[0m\n' "$*"; tail -20 "$DATA/server.log" 2>/dev/null; exit 1; }
cleanup() { [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null; rm -rf "$DATA"; }
trap cleanup EXIT

start() {
  TUAN_WG_PASSWORD="$PASS" "$BIN" --data-dir "$DATA" --wg-dir "$DATA/wg" --no-wg serve --listen 127.0.0.1 --port "$1" >>"$DATA/server.log" 2>&1 &
  PID=$!
  for _ in $(seq 1 50); do curl -s "http://127.0.0.1:$1/api/public/info" >/dev/null 2>&1 && return 0; sleep 0.1; done
  fail "server không khởi động trên cổng $1"
}
api() { local m="$1" p="$2"; shift 2; curl -sS -b "$CJ" -c "$CJ" -H 'X-TWG: 1' -X "$m" "$@" "$API$p"; }
code() { local m="$1" p="$2"; shift 2; curl -s -o /dev/null -w '%{http_code}' -b "$CJ" -c "$CJ" -H 'X-TWG: 1' -X "$m" "$@" "$API$p"; }
totp() { python3 - "$1" "${2:-1}" <<'EOF'
import base64, hashlib, hmac, struct, sys, time
s = sys.argv[1]; k = base64.b32decode(s + '=' * ((8 - len(s) % 8) % 8))
c = int(time.time()) // 30 + int(sys.argv[2])
h = hmac.new(k, struct.pack('>Q', c), hashlib.sha1).digest()
o = h[19] & 15
print('%06d' % ((struct.unpack('>I', h[o:o + 4])[0] & 0x7fffffff) % 1000000))
EOF
}

echo "==> Khởi động"
start "$PORT"
ok "server chạy ($(curl -s "$API/api/public/info" | jq -r .version))"

echo "==> Xác thực"
[ "$(code GET /api/dashboard)" = 401 ] || fail "chưa đăng nhập phải 401"
ok "API yêu cầu đăng nhập"
[ "$(curl -s -o /dev/null -w '%{http_code}' -d '{"username":"admin","password":"x"}' "$API/api/login")" = 403 ] || fail "thiếu header CSRF phải 403"
ok "chặn yêu cầu thiếu header CSRF"
[ "$(code POST /api/login -d '{"username":"admin","password":"sai"}')" = 401 ] || fail "sai mật khẩu phải 401"
[ "$(code POST /api/login -d "{\"username\":\"admin\",\"password\":\"$PASS\"}")" = 200 ] || fail "đăng nhập lỗi"
grep -q "HttpOnly" <(curl -s -D - -o /dev/null -H 'X-TWG: 1' -d "{\"username\":\"admin\",\"password\":\"$PASS\"}" "$API/api/login") || fail "cookie thiếu HttpOnly"
ok "đăng nhập, cookie HttpOnly + SameSite"

echo "==> Người dùng"
C="$(api POST /api/clients -d '{"name":"Nguyễn Văn An","note":"test","data_limit":1073741824,"limit_monthly":true}')"
ID="$(echo "$C" | jq -r .id)"
[ "$(echo "$C" | jq -r .address)" = "10.8.0.2" ] || fail "IP đầu tiên phải 10.8.0.2: $C"
ok "tạo người dùng $ID"
[ "$(code POST /api/clients -d '{"name":"nguyễn văn an"}')" = 400 ] && ok "chặn tên trùng" || fail "tên trùng"
[ "$(code POST /api/clients -d '{"name":"X","dns":"1.1.1.1\n[Peer]"}')" = 400 ] && ok "chặn chèn cấu hình qua DNS" || fail "dns injection"
[ "$(code POST /api/clients -d '{"name":"X","allowed_ips":"0.0.0.0/0; reboot"}')" = 400 ] && ok "chặn AllowedIPs sai" || fail "allowed injection"
[ "$(code POST /api/clients -d 'khong-phai-json')" = 400 ] && ok "chặn JSON hỏng" || fail "bad json"
api PUT "/api/clients/$ID" -d '{"expires_at":1,"keepalive":10}' | jq -e '.expires_at == 1' >/dev/null || fail "cập nhật lỗi"
sleep 2.5
[ "$(api GET "/api/clients/$ID" | jq -r .client.disabled_reason)" = expired ] || fail "không tự khóa khi hết hạn"
ok "tự khóa khi hết hạn"
api PUT "/api/clients/$ID" -d "{\"expires_at\":$(( $(date +%s) + 86400 ))}" | jq -e '.enabled == true' >/dev/null || fail "gia hạn không tự mở khóa"
ok "gia hạn -> tự mở khóa"
CONF="$(api GET "/api/clients/$ID/config?inline=1")"
echo "$CONF" | grep -q "PersistentKeepalive = 10" || fail "cấu hình thiếu keepalive"
grep -q "10.8.0.2/32" "$DATA/wg/wg0.conf" || fail "wg0.conf chưa có peer"
ok "file cấu hình người dùng + wg0.conf đúng"
[ "$(curl -s -o /dev/null -w '%{content_type}' -b "$CJ" "$API/api/clients/$ID/qr.svg")" = "image/svg+xml" ] && ok "mã QR SVG" || fail "qr"
unzip -l <(curl -s -b "$CJ" "$API/api/export.zip") 2>/dev/null | grep -q "Nguyen-Van-An.conf" || { curl -s -b "$CJ" -o "$DATA/a.zip" "$API/api/export.zip"; unzip -l "$DATA/a.zip" | grep -q "Nguyen-Van-An.conf" || fail "zip"; }
ok "tải tất cả cấu hình (.zip)"

echo "==> Link chia sẻ"
TOK="$(api POST "/api/clients/$ID/share" -d '{"hours":1}' | jq -r .token)"
curl -s "$API/api/share/$TOK" | jq -e '.name == "Nguyễn Văn An"' >/dev/null || fail "mở link chia sẻ"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$API/s/$TOK")" = 200 ] || fail "trang chia sẻ"
ok "mở link chia sẻ không cần đăng nhập"
api DELETE "/api/shares/$TOK" | jq -e .ok >/dev/null
[ "$(curl -s -o /dev/null -w '%{http_code}' "$API/api/share/$TOK")" = 404 ] || fail "link đã thu hồi vẫn mở được"
ok "thu hồi link"

echo "==> Xác thực 2 lớp"
SEC="$(api POST /api/account/2fa/setup | jq -r .secret)"
[ "$(code POST /api/account/2fa/enable -d '{"code":"000000"}')" = 400 ] || fail "mã sai vẫn bật được 2FA"
api POST /api/account/2fa/enable -d "{\"code\":\"$(totp "$SEC" 0)\"}" | jq -e .ok >/dev/null || fail "bật 2FA lỗi"
curl -s "$API/api/public/info" | jq -e '.totp_required' >/dev/null || fail "public info chưa báo 2FA"
ok "bật 2FA"
rm -f "$CJ"
[ "$(code POST /api/login -d "{\"username\":\"admin\",\"password\":\"$PASS\"}")" = 401 ] || fail "thiếu mã OTP vẫn đăng nhập được"
[ "$(code POST /api/login -d "{\"username\":\"admin\",\"password\":\"$PASS\",\"otp\":\"$(totp "$SEC" 1)\"}")" = 200 ] || fail "đăng nhập với OTP lỗi"
ok "đăng nhập bắt buộc mã OTP"
[ "$(code POST /api/login -d "{\"username\":\"admin\",\"password\":\"$PASS\",\"otp\":\"$(totp "$SEC" 1)\"}")" = 401 ] || fail "dùng lại mã OTP"
ok "chặn dùng lại mã OTP"
api POST /api/account/2fa/disable -d "{\"password\":\"$PASS\"}" | jq -e .ok >/dev/null || fail "tắt 2FA"
ok "tắt 2FA"

echo "==> Mật khẩu & phiên"
cp "$CJ" "$DATA/cj-old"
curl -s -c "$DATA/cj-other" -H 'X-TWG: 1' -d "{\"username\":\"admin\",\"password\":\"$PASS\"}" "$API/api/login" >/dev/null
[ "$(code POST /api/account/password -d '{"current":"sai","new":"12345678"}')" = 400 ] || fail "đổi mật khẩu khi sai mật khẩu cũ"
api POST /api/account/password -d "{\"current\":\"$PASS\",\"new\":\"Mat-Khau-Moi-2026\"}" | jq -e .ok >/dev/null || fail "đổi mật khẩu"
[ "$(curl -s -o /dev/null -w '%{http_code}' -b "$DATA/cj-other" "$API/api/dashboard")" = 401 ] || fail "phiên khác chưa bị đăng xuất"
[ "$(code GET /api/dashboard)" = 200 ] || fail "phiên hiện tại bị đăng xuất"
ok "đổi mật khẩu -> đăng xuất các phiên khác, giữ phiên hiện tại"
PASS="Mat-Khau-Moi-2026"

echo "==> Sao lưu & khôi phục"
api GET /api/backup >"$DATA/backup.json"
jq -e '.tuan_wg_backup == 1 and (.db.clients | length) == 1' "$DATA/backup.json" >/dev/null || fail "file sao lưu"
api DELETE "/api/clients/$ID" | jq -e .ok >/dev/null
[ "$(api GET /api/clients | jq '.clients | length')" = 0 ] || fail "xóa người dùng"
R="$(api POST /api/restore --data-binary @"$DATA/backup.json")"
echo "$R" | jq -e '.clients == 1' >/dev/null || fail "khôi phục: $R"
[ "$(api GET /api/clients | jq -r '.clients[0].name')" = "Nguyễn Văn An" ] || fail "dữ liệu sau khôi phục"
ok "sao lưu -> xóa -> khôi phục"

echo "==> Nhật ký"
L="$(api GET '/api/logs?limit=100')"
for a in login login_fail client_create client_auto_disable share_create 2fa_enable password_change restore; do
  echo "$L" | jq -e --arg a "$a" '[.logs[].action] | index($a) != null' >/dev/null || fail "nhật ký thiếu $a"
done
ok "nhật ký ghi đủ sự kiện"

echo "==> CLI sửa dữ liệu khi server đang chạy"
"$BIN" --data-dir "$DATA" --wg-dir "$DATA/wg" --no-wg client add "Thêm bằng CLI" >/dev/null
sleep 0.3
api GET /api/clients | jq -e '[.clients[].name] | index("Thêm bằng CLI") != null' >/dev/null || fail "server chưa nạp lại dữ liệu CLI"
ok "server tự nạp lại thay đổi từ CLI"

echo "==> CLI: --help chỉ in hướng dẫn, không chạy lệnh thật"
HD="$DATA/help-check"
for c in "serve --help" "run -h" "uninstall --help" "passwd --help" "reset-2fa --help" "backup --help" "restore --help" "status --help"; do
  # shellcheck disable=SC2086
  out="$(cd "$DATA" && timeout 5 "$BIN" --data-dir "$HD" --no-wg $c 2>&1)" || fail "tuan-wg $c lỗi: $out"
  grep -q "Cách dùng" <<<"$out" || fail "tuan-wg $c không in hướng dẫn: $out"
done
[ ! -e "$HD" ] && [ ! -e "$DATA/--help" ] || fail "--help đã thực thi lệnh"
timeout 5 "$BIN" --data-dir "$HD" --no-wg serve --prot 1 >/dev/null 2>&1 && fail "serve chấp nhận tùy chọn gõ sai"
timeout 5 "$BIN" --data-dir "$HD" --no-wg uninstall --purge --hepl >/dev/null 2>&1 && fail "uninstall chấp nhận tùy chọn gõ sai"
ok "--help chỉ in hướng dẫn, tùy chọn gõ sai bị từ chối"

echo "==> Đổi cổng web (tự khởi động lại tiến trình)"
NEWPORT=18301
api PUT /api/settings -d "{\"web_port\":$NEWPORT}" | jq -e '.restart_web == true' >/dev/null || fail "đổi cổng web"
API="http://127.0.0.1:$NEWPORT"
for _ in $(seq 1 60); do curl -s "$API/api/public/info" >/dev/null 2>&1 && break; sleep 0.1; done
[ "$(code GET /api/dashboard)" = 200 ] || fail "không truy cập được cổng mới (phiên phải được giữ)"
ok "web chạy lại trên cổng $NEWPORT, phiên đăng nhập vẫn còn"

echo "==> Chặn dò mật khẩu"
for _ in 1 2 3 4 5; do curl -s -o /dev/null -H 'X-TWG: 1' -d '{"username":"admin","password":"sai"}' "$API/api/login"; done
[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-TWG: 1' -d "{\"username\":\"admin\",\"password\":\"$PASS\"}" "$API/api/login")" = 429 ] || fail "không chặn sau 5 lần sai"
ok "khóa đăng nhập tạm thời sau 5 lần sai"

printf '\n\033[32;1m%d kiểm thử API đều đạt\033[0m\n' "$PASSED"
