/*
 * Tuấn WireGuard - hướng dẫn kết nối trên từng hệ điều hành (dùng chung)
 * Tác giả: Tuandethuong
 */
import { h, icon } from './ui.js';

export function guideContent() {
  const os = (ic, name, steps, url, urlLabel) => h('div', { class: 'os' }, h('b', null, icon(ic), name), h('ol', null, steps.map((s) => h('li', null, s))),
    url ? h('a', { href: url, target: '_blank', rel: 'noopener', class: 'btn sm soft', style: { marginTop: '10px' } }, icon('download'), urlLabel) : null);
  return h('div', { class: 'guide-os' },
    os('phone', 'Android', ['Cài ứng dụng WireGuard từ Google Play', 'Bấm nút + → "Quét từ mã QR"', 'Quét mã QR, đặt tên rồi bật công tắc'], 'https://play.google.com/store/apps/details?id=com.wireguard.android', 'Google Play'),
    os('phone', 'iPhone / iPad', ['Cài ứng dụng WireGuard từ App Store', 'Bấm "Thêm đường hầm" → "Tạo từ mã QR"', 'Quét mã, cho phép thêm cấu hình VPN rồi bật'], 'https://apps.apple.com/app/wireguard/id1441195209', 'App Store'),
    os('monitor', 'Windows', ['Tải và cài WireGuard cho Windows', 'Bấm "Import tunnel(s) from file"', 'Chọn file .conf vừa tải rồi bấm "Activate"'], 'https://download.wireguard.com/windows-client/wireguard-installer.exe', 'Tải cho Windows'),
    os('monitor', 'macOS', ['Cài WireGuard từ Mac App Store', 'Chọn "Import Tunnel(s) from File"', 'Chọn file .conf rồi bấm "Activate"'], 'https://apps.apple.com/app/wireguard/id1451685025', 'Mac App Store'),
    os('server', 'Linux', ['sudo apt install wireguard', 'Chép file vào /etc/wireguard/wg0.conf', 'sudo wg-quick up wg0'], 'https://www.wireguard.com/install/', 'Hướng dẫn cài đặt'));
}
