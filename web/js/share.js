/*
 * Tuấn WireGuard - trang nhận cấu hình qua link chia sẻ (không cần đăng nhập)
 * Tác giả: Tuandethuong
 */
import { h, icon, copyText, download, fmtDateTime, highlightConf, add } from './ui.js';
import { guideContent } from './guide.js';

const root = document.getElementById('share');
const token = location.pathname.replace(/^\/s\//, '').replace(/\/.*$/, '');

function header() {
  return h('div', { class: 'brand', style: { padding: '0 0 22px' } }, h('img', { src: '/logo.svg', alt: '' }),
    h('div', null, h('div', { class: 'name', style: { color: 'var(--text)' } }, 'Tuấn WireGuard'), h('div', { class: 'ver', style: { color: 'var(--muted)' } }, 'Cấu hình VPN được chia sẻ cho bạn')));
}

async function main() {
  let d;
  try {
    const r = await fetch('/api/share/' + encodeURIComponent(token), { cache: 'no-store' });
    d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Lỗi ' + r.status);
  } catch (e) {
    add(root, header(), h('div', { class: 'card', style: { padding: '40px 24px', textAlign: 'center' } },
      h('div', { class: 'ic red', style: { width: '56px', height: '56px', borderRadius: '16px', display: 'grid', placeItems: 'center', margin: '0 auto 14px' } }, icon('alert')),
      h('h2', { style: { fontSize: '20px' } }, 'Link không khả dụng'),
      h('p', { class: 'text-2' }, e.message + '. Hãy liên hệ quản trị viên để nhận link mới.')));
    return;
  }
  document.title = d.name + ' • Cấu hình VPN';
  const conf = h('div', { class: 'conf-box', html: highlightConf(d.config) });
  const cfgUrl = '/api/share/' + encodeURIComponent(token) + '/config';
  add(root, header(),
    h('div', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h3', { style: { fontSize: '19px' } }, 'Xin chào, đây là cấu hình VPN cho: ', h('span', { style: { color: 'var(--primary)' } }, d.name)),
        h('div', { class: 'sub' }, 'Link hết hạn lúc ' + fmtDateTime(d.expires_at) + '. Không chia sẻ link này cho người khác.'))),
      h('div', { class: 'card-b' },
        h('div', { class: 'conf-grid' },
          h('div', { class: 'col', style: { alignItems: 'center' } },
            h('div', { class: 'qr-box' }, h('img', { src: '/api/share/' + encodeURIComponent(token) + '/qr.svg', alt: 'Mã QR cấu hình' })),
            h('div', { class: 'muted', style: { fontSize: '12.5px', textAlign: 'center' } }, 'Dùng ứng dụng WireGuard để quét mã này')),
          h('div', { class: 'col', style: { gap: '14px' } },
            h('ol', { class: 'steps', style: { padding: 0, margin: 0 } },
              h('li', null, h('div', null, h('b', null, 'Cài ứng dụng WireGuard'), h('div', { class: 'muted' }, 'Miễn phí trên Android, iPhone, Windows, macOS, Linux (xem bên dưới).'))),
              h('li', null, h('div', null, h('b', null, 'Thêm cấu hình'), h('div', { class: 'muted' }, 'Điện thoại: bấm + → Quét mã QR. Máy tính: tải file .conf rồi Import.'))),
              h('li', null, h('div', null, h('b', null, 'Bật kết nối'), h('div', { class: 'muted' }, 'Gạt công tắc để bật VPN. Vậy là xong!')))),
            h('div', { class: 'row wrap' },
              h('button', { class: 'btn primary', onclick: () => download(cfgUrl) }, icon('download'), 'Tải file ' + d.filename + '.conf'),
              h('button', { class: 'btn', onclick: () => copyText(d.config) }, icon('copy'), 'Sao chép cấu hình')),
            h('details', null, h('summary', { style: { cursor: 'pointer', fontWeight: 600, marginBottom: '8px' } }, 'Xem nội dung cấu hình'), conf))))),
    h('div', { class: 'card', style: { marginTop: '18px' } }, h('div', { class: 'card-h' }, h('h3', null, 'Tải ứng dụng WireGuard')), h('div', { class: 'card-b' }, guideContent())),
    h('div', { class: 'muted', style: { textAlign: 'center', marginTop: '24px', fontSize: '12.5px' } }, 'Tuấn WireGuard v' + d.version + ' • Thiết kế bởi Tuandethuong'));
}

main();
