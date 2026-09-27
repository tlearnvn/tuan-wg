#!/usr/bin/env bash
# Tuấn WireGuard - kiểm thử đầu-cuối với WireGuard thật
#
# Dựng một "máy chủ" WireGuard bằng tuan-wg, một client trong network namespace riêng
# và một "internet" giả lập, rồi kiểm tra:
#   - client kết nối được (ping 10.8.0.1 qua đường hầm)
#   - chuyển tiếp + NAT ra "internet" hoạt động
#   - thống kê dung lượng/online được ghi nhận
#   - tắt/bật người dùng có hiệu lực ngay (wg syncconf, không ngắt người khác)
#   - đổi cổng WireGuard -> interface khởi động lại, client kết nối lại được
#
# Yêu cầu: root, wireguard-tools, iproute2, iptables, curl, jq,
#          module kernel WireGuard hoặc wireguard-go.
# Cách chạy: sudo tests/e2e_wireguard.sh [đường-dẫn-binary]
set -euo pipefail

BIN="${1:-$(dirname "$0")/../build/tuan-wg}"
BIN="$(readlink -f "$BIN")"
DATA=/tmp/twg-e2e
WGDIR=/tmp/twg-e2e-wg
PORT=18181
API="http://127.0.0.1:$PORT"
PASS="e2e-test-password"
export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1

ok() { printf '\033[32m  ✔ %s\033[0m\n' "$*"; }
fail() { printf '\033[31m  ✖ %s\033[0m\n' "$*"; cleanup; exit 1; }
step() { printf '\033[36m==> %s\033[0m\n' "$*"; }

cleanup() {
  set +e
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null && wait "$SRV_PID" 2>/dev/null
  WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go wg-quick down "$WGDIR/wg0.conf" >/dev/null 2>&1
  ip link del wg0 2>/dev/null
  ip netns pids twgcli 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns del twgcli 2>/dev/null
  ip netns del twginet 2>/dev/null
  ip link del twg-cli0 2>/dev/null
  ip link del twg-inet0 2>/dev/null
  rm -f /var/run/wireguard/wgc.sock
  set -e
}
trap cleanup EXIT

# chờ tối đa N giây cho tới khi ping thành công (WireGuard tự bắt tay lại sau ~15 giây)
wait_ping() { # wait_ping IP SECONDS
  local ip="$1" max="$2" t=0
  while [ "$t" -lt "$max" ]; do
    ip netns exec twgcli ping -c 1 -W 1 "$ip" >/dev/null 2>&1 && return 0
    t=$((t + 1))
  done
  return 1
}

api() { # api METHOD PATH [JSON]
  local m="$1" p="$2" d="${3:-}"
  if [ -n "$d" ]; then
    curl -sS -b "$DATA/cj" -c "$DATA/cj" -H 'X-TWG: 1' -X "$m" -d "$d" "$API$p"
  else
    curl -sS -b "$DATA/cj" -c "$DATA/cj" -H 'X-TWG: 1' -X "$m" "$API$p"
  fi
}

cleanup
rm -rf "$DATA" "$WGDIR"
mkdir -p "$DATA" "$WGDIR"

step "Dựng mạng giả lập"
# client <-> máy chủ
ip netns add twgcli
ip link add twg-cli0 type veth peer name twg-cli1
ip link set twg-cli1 netns twgcli
ip addr add 192.168.77.1/24 dev twg-cli0 && ip link set twg-cli0 up
ip -n twgcli addr add 192.168.77.2/24 dev twg-cli1
ip -n twgcli link set twg-cli1 up && ip -n twgcli link set lo up
# máy chủ <-> "internet"
ip netns add twginet
ip link add twg-inet0 type veth peer name twg-inet1
ip link set twg-inet1 netns twginet
ip addr add 172.31.0.1/24 dev twg-inet0 && ip link set twg-inet0 up
ip -n twginet addr add 172.31.0.2/24 dev twg-inet1
ip -n twginet link set twg-inet1 up && ip -n twginet link set lo up
ok "đã tạo namespace twgcli (192.168.77.2) và twginet (172.31.0.2)"

step "Khởi động tuan-wg"
TUAN_WG_PASSWORD="$PASS" "$BIN" --data-dir "$DATA" --wg-dir "$WGDIR" serve --listen 127.0.0.1 --port "$PORT" >"$DATA/server.log" 2>&1 &
SRV_PID=$!
for _ in $(seq 1 50); do curl -s "$API/api/public/info" >/dev/null 2>&1 && break; sleep 0.2; done
curl -s "$API/api/public/info" | jq -e '.app' >/dev/null || fail "server không chạy (xem $DATA/server.log)"
ok "server web chạy tại $API"

api POST /api/login "{\"username\":\"admin\",\"password\":\"$PASS\"}" | jq -e '.ok' >/dev/null || fail "đăng nhập lỗi"
ok "đăng nhập thành công"

# cấu hình: endpoint là IP phía client, WAN là card sang "internet"
api PUT /api/settings '{"endpoint":"192.168.77.1","wan_interface":"twg-inet0","listen_port":51820}' | jq -e '.ok' >/dev/null || fail "lưu cài đặt lỗi"
sleep 1
ip link show wg0 >/dev/null 2>&1 || fail "interface wg0 không được tạo ($(tail -3 "$DATA/server.log"))"
ok "wg0 đã chạy: $(wg show wg0 listen-port) /udp"

step "Tạo người dùng và dựng client"
C=$(api POST /api/clients '{"name":"E2E Điện thoại","allowed_ips":"10.8.0.0/24, 172.31.0.0/24","keepalive":5}')
CID=$(echo "$C" | jq -r .id)
CIP=$(echo "$C" | jq -r .address)
[ -n "$CID" ] && [ "$CID" != null ] || fail "tạo người dùng lỗi: $C"
ok "người dùng $CID - IP $CIP"
api GET "/api/clients/$CID/config?inline=1" >"$DATA/wgc.conf"
grep -q "Endpoint = 192.168.77.1:51820" "$DATA/wgc.conf" || fail "cấu hình client sai endpoint"
C2=$(api POST /api/clients '{"name":"E2E Laptop"}')
C2ID=$(echo "$C2" | jq -r .id)

# dựng client trong namespace bằng wireguard-go (hoặc kernel)
wg-quick strip "$DATA/wgc.conf" >"$DATA/wgc.strip" 2>/dev/null || \
  grep -vE '^(Address|DNS|MTU|#)' "$DATA/wgc.conf" >"$DATA/wgc.strip"
if ip -n twgcli link add wgc type wireguard 2>/dev/null; then :; else
  ip netns exec twgcli wireguard-go wgc >/dev/null 2>&1
fi
ip netns exec twgcli wg setconf wgc "$DATA/wgc.strip"
ip -n twgcli addr add "$CIP/32" dev wgc
ip -n twgcli link set wgc up
ip -n twgcli route add 10.8.0.0/24 dev wgc
ip -n twgcli route add 172.31.0.0/24 dev wgc
ok "client wgc đã cấu hình"

step "Kiểm tra kết nối"
ip netns exec twgcli ping -c 3 -W 2 10.8.0.1 >/dev/null || fail "không ping được 10.8.0.1 qua đường hầm"
ok "ping 10.8.0.1 qua đường hầm WireGuard"
ip netns exec twgcli ping -c 3 -W 2 172.31.0.2 >/dev/null || fail "không ra được 'internet' (forward/NAT lỗi)"
ok "ping 172.31.0.2 qua NAT (chuyển tiếp + MASQUERADE hoạt động)"
ip netns exec twgcli ping -c 20 -i 0.05 -s 1200 -W 2 10.8.0.1 >/dev/null || true

step "Kiểm tra thống kê"
sleep 4
S=$(api GET "/api/clients/$CID")
RX=$(echo "$S" | jq '.client.stats.rx'); TX=$(echo "$S" | jq '.client.stats.tx')
ONLINE=$(echo "$S" | jq '.client.stats.online'); EP=$(echo "$S" | jq -r '.client.stats.endpoint')
[ "$RX" -gt 10000 ] && [ "$TX" -gt 10000 ] || fail "thống kê chưa ghi nhận lưu lượng (rx=$RX tx=$TX)"
[ "$ONLINE" = true ] || fail "người dùng chưa hiện online"
ok "rx=$RX byte, tx=$TX byte, online=$ONLINE, endpoint=$EP"
D=$(api GET /api/dashboard)
[ "$(echo "$D" | jq '.counts.online')" -ge 1 ] || fail "dashboard không đếm online"
ok "dashboard: $(echo "$D" | jq -c '.counts')"

step "Tắt / bật người dùng"
api PUT "/api/clients/$CID" '{"enabled":false}' | jq -e '.enabled == false' >/dev/null || fail "tắt người dùng lỗi"
sleep 1
wg show wg0 peers | grep -q "$(echo "$C" | jq -r .public_key)" && fail "peer vẫn còn trong wg0 sau khi tắt"
if ip netns exec twgcli ping -c 2 -W 1 10.8.0.1 >/dev/null 2>&1; then fail "vẫn ping được khi đã tắt"; fi
ok "đã tắt: client mất kết nối, peer bị gỡ khỏi wg0"
wg show wg0 peers | grep -q "$(echo "$C2" | jq -r .public_key)" || fail "peer khác bị ảnh hưởng"
ok "người dùng khác không bị ảnh hưởng"
api PUT "/api/clients/$CID" '{"enabled":true}' | jq -e '.enabled == true' >/dev/null || fail "bật lại lỗi"
wait_ping 10.8.0.1 40 || fail "không kết nối lại được sau khi bật"
ok "đã bật lại: kết nối phục hồi"

step "Hạn mức dung lượng"
api PUT "/api/clients/$CID" '{"data_limit":1000}' >/dev/null
sleep 5
R=$(api GET "/api/clients/$CID" | jq -r '.client.disabled_reason')
[ "$R" = quota ] || fail "không tự khóa khi vượt hạn mức (reason=$R)"
ok "tự khóa khi vượt hạn mức"
api PUT "/api/clients/$CID" '{"data_limit":0}' | jq -e '.enabled == true' >/dev/null || fail "gỡ hạn mức không mở khóa"
ok "gỡ hạn mức -> tự mở khóa"

step "Đổi cổng WireGuard (khởi động lại interface)"
api PUT /api/settings '{"listen_port":51888}' | jq -e '.ok' >/dev/null || fail "đổi cổng lỗi"
sleep 1
[ "$(wg show wg0 listen-port)" = 51888 ] || fail "cổng chưa đổi"
ip netns exec twgcli wg set wgc peer "$(wg show wg0 public-key)" endpoint 192.168.77.1:51888
wait_ping 10.8.0.1 40 || fail "không kết nối được sau khi đổi cổng"
ok "wg0 chạy cổng 51888, client kết nối lại được"
S2=$(api GET "/api/clients/$CID" | jq '.client.stats.rx')
[ "$S2" -ge "$RX" ] || fail "thống kê bị mất sau khi khởi động lại interface ($S2 < $RX)"
ok "thống kê được giữ nguyên qua lần khởi động lại ($S2 byte)"

step "Xóa người dùng"
api DELETE "/api/clients/$C2ID" | jq -e '.ok' >/dev/null || fail "xóa lỗi"
sleep 0.5
wg show wg0 peers | grep -q "$(echo "$C2" | jq -r .public_key)" && fail "peer vẫn còn sau khi xóa"
ok "đã xóa người dùng và gỡ peer"

printf '\n\033[32;1mTẤT CẢ KIỂM THỬ ĐẦU-CUỐI ĐỀU ĐẠT\033[0m\n'
