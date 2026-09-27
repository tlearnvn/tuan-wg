/*
 * Tuấn WireGuard - trang Giới thiệu & lịch sử thay đổi
 * Tác giả: Tuandethuong
 */
import { get, api } from '../api.js';
import { h, icon, clear, busy, add } from '../ui.js';

function esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

function inline(s) {
  return esc(s)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
}

/* Chuyển Markdown đơn giản (CHANGELOG) sang HTML đã được escape */
export function renderMarkdown(md) {
  const out = [];
  let inList = false;
  for (const raw of md.split('\n')) {
    const line = raw.trimEnd();
    const li = /^\s*[-*]\s+(.*)$/.exec(line);
    if (li) { if (!inList) { out.push('<ul>'); inList = true; } out.push('<li>' + inline(li[1]) + '</li>'); continue; }
    if (inList) { out.push('</ul>'); inList = false; }
    if (/^# /.test(line)) continue;
    let m;
    if ((m = /^## (.*)$/.exec(line))) out.push('<h2>' + inline(m[1]) + '</h2>');
    else if ((m = /^### (.*)$/.exec(line))) out.push('<h3>' + inline(m[1]) + '</h3>');
    else if (line.trim() && !/^<!--/.test(line) && !/^\[.*\]:/.test(line)) out.push('<p>' + inline(line) + '</p>');
  }
  if (inList) out.push('</ul>');
  return out.join('\n');
}

function cmpVer(a, b) {
  const pa = String(a).replace(/^v/, '').split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  const pb = String(b).replace(/^v/, '').split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < 3; i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0); }
  return 0;
}

export function mount(el, ctx) {
  const info = ctx.state.session || ctx.state.info;
  const md = h('div', { class: 'md' }, h('div', { class: 'skeleton', style: { height: '200px' } }));
  const upd = h('div', { class: 'muted' }, 'Bấm "Kiểm tra cập nhật" để xem có phiên bản mới trên GitHub không.');
  const repoPath = (info.repo || '').replace(/^https:\/\/github\.com\//, '');
  const checkBtn = h('button', { class: 'btn' }, icon('sparkles'), 'Kiểm tra cập nhật');
  checkBtn.addEventListener('click', async () => {
    busy(checkBtn, true);
    clear(upd);
    try {
      const r = await fetch('https://api.github.com/repos/' + repoPath + '/releases/latest', { headers: { Accept: 'application/vnd.github+json' } });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const rel = await r.json();
      if (cmpVer(rel.tag_name, info.version) > 0) {
        upd.appendChild(h('div', { class: 'alert ok' }, icon('sparkles'), h('div', null, h('b', null, 'Có phiên bản mới ' + rel.tag_name + '! '),
          'Cập nhật bằng lệnh: ', h('code', null, 'curl -fsSL https://raw.githubusercontent.com/' + repoPath + '/main/scripts/install.sh | sudo bash'), ' - ',
          h('a', { href: rel.html_url, target: '_blank', rel: 'noopener' }, 'Xem chi tiết'))));
      } else {
        upd.appendChild(h('div', { class: 'alert ok' }, icon('check'), h('div', null, 'Bạn đang dùng phiên bản mới nhất (v' + info.version + ').')));
      }
    } catch (e) {
      upd.appendChild(h('div', { class: 'alert warn' }, icon('alert'), h('div', null, 'Không kiểm tra được cập nhật (' + e.message + '). Xem thủ công tại ', h('a', { href: info.repo + '/releases', target: '_blank', rel: 'noopener' }, 'GitHub Releases'), '.')));
    } finally { busy(checkBtn, false); }
  });

  const feats = [
    ['users', 'Quản lý người dùng', 'Thêm, sửa, xóa, bật/tắt, thao tác hàng loạt'],
    ['qr', 'Mã QR & file cấu hình', 'Quét bằng điện thoại, tải .conf hoặc .zip tất cả'],
    ['link', 'Link chia sẻ có hạn', 'Gửi cấu hình cho người dùng không cần đăng nhập'],
    ['chart', 'Thống kê dung lượng', 'Theo giờ, ngày, tháng; thời gian thực; xuất CSV'],
    ['clock', 'Hết hạn & hạn mức', 'Tự khóa khi hết hạn/hết dung lượng, làm mới hằng tháng'],
    ['shieldCheck', 'Bảo mật', 'Mật khẩu PBKDF2, 2FA TOTP, chống dò mật khẩu, CSRF'],
    ['server', 'Dịch vụ systemd', 'Tự khởi động cùng máy chủ, tự khôi phục khi lỗi'],
    ['archive', 'Sao lưu & khôi phục', 'Một file JSON, chuyển máy chủ dễ dàng'],
    ['zap', 'Nhẹ & nhanh', 'Viết bằng C, một file chạy duy nhất, không phụ thuộc'],
  ];

  add(el, 
    h('div', { class: 'card hero' }, h('img', { src: '/logo.svg', alt: '' }),
      h('div', { style: { position: 'relative' } },
        h('h2', null, 'Tuấn WireGuard'),
        h('div', { class: 'text-2', style: { margin: '4px 0 10px' } }, 'Giao diện web quản lý máy chủ VPN WireGuard - tiếng Việt, gọn nhẹ, viết bằng C.'),
        h('div', { class: 'row wrap' },
          h('span', { class: 'badge violet' }, 'Phiên bản ' + info.version),
          info.build ? h('span', { class: 'badge' }, 'Build ' + info.build) : null,
          h('span', { class: 'badge green' }, icon('heart'), 'Tác giả: ' + info.author),
          h('a', { class: 'badge blue', href: info.repo, target: '_blank', rel: 'noopener' }, icon('github'), 'GitHub')))),
    h('div', { class: 'dash-grid', style: { gridTemplateColumns: 'minmax(0, 1.4fr) minmax(0, 1fr)' } },
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'Tính năng')),
        h('div', { class: 'card-b' }, h('div', { class: 'features', style: { gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))' } },
          feats.map(([i, t, d]) => h('div', { class: 'feature' }, h('div', { class: 'ic indigo', style: { width: '36px', height: '36px', borderRadius: '11px', display: 'grid', placeItems: 'center', flex: 'none' } }, icon(i)), h('div', null, h('b', null, t), h('span', null, d))))))),
      h('div', { class: 'col', style: { gap: '18px' } },
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'Cập nhật'), h('div', { class: 'spacer' }), checkBtn), h('div', { class: 'card-b' }, upd)),
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'Thông tin')),
          h('div', { class: 'card-b' }, h('dl', { class: 'kv' },
            h('dt', null, 'Tên ứng dụng'), h('dd', null, 'Tuấn WireGuard'),
            h('dt', null, 'Phiên bản'), h('dd', null, info.version),
            h('dt', null, 'Tác giả'), h('dd', null, info.author),
            h('dt', null, 'Mã nguồn'), h('dd', null, h('a', { href: info.repo, target: '_blank', rel: 'noopener' }, repoPath)),
            h('dt', null, 'Giấy phép'), h('dd', null, 'MIT'),
            h('dt', null, 'Font chữ'), h('dd', null, 'Be Vietnam Pro (SIL OFL 1.1)'),
            h('dt', null, 'Mã QR'), h('dd', null, 'QR Code generator - Project Nayuki (MIT)')))))),
    h('div', { class: 'card', style: { marginTop: '18px' } }, h('div', { class: 'card-h' }, h('div', null, h('h3', null, 'Lịch sử thay đổi'), h('div', { class: 'sub' }, 'CHANGELOG - phiên bản được tự động tăng khi mã nguồn thay đổi'))),
      h('div', { class: 'card-b' }, md)));

  api('/CHANGELOG.md', { text: true }).then((t) => { md.innerHTML = renderMarkdown(t); }).catch(() => { md.textContent = 'Không tải được lịch sử thay đổi.'; });
  return null;
}
