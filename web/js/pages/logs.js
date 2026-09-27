/*
 * Tuấn WireGuard - trang Nhật ký hoạt động
 * Tác giả: Tuandethuong
 */
import { get } from '../api.js';
import { h, icon, clear, toast, timeAgo, fmtDateTime, emptyState, add } from '../ui.js';

export const ACTIONS = {
  login: ['Đăng nhập', 'key', 'green', 'auth'],
  login_fail: ['Đăng nhập thất bại', 'alert', 'red', 'auth'],
  logout: ['Đăng xuất', 'logout', '', 'auth'],
  client_create: ['Thêm người dùng', 'userPlus', 'indigo', 'client'],
  client_update: ['Cập nhật người dùng', 'edit', 'indigo', 'client'],
  client_delete: ['Xóa người dùng', 'trash', 'red', 'client'],
  client_enable: ['Bật người dùng', 'power', 'green', 'client'],
  client_disable: ['Tắt người dùng', 'power', 'amber', 'client'],
  client_auto_disable: ['Tự động khóa', 'clock', 'red', 'system'],
  client_auto_enable: ['Tự động mở khóa', 'clock', 'green', 'system'],
  client_reset: ['Đặt lại dung lượng', 'reset', 'cyan', 'client'],
  client_rekey: ['Tạo lại khóa', 'key', 'amber', 'client'],
  client_download: ['Tải cấu hình', 'download', 'indigo', 'client'],
  client_bulk: ['Thao tác hàng loạt', 'users', 'indigo', 'client'],
  share_create: ['Tạo link chia sẻ', 'link', 'cyan', 'client'],
  share_revoke: ['Thu hồi link chia sẻ', 'x', 'amber', 'client'],
  share_view: ['Mở link chia sẻ', 'eye', 'cyan', 'client'],
  share_download: ['Tải qua link chia sẻ', 'download', 'cyan', 'client'],
  export_zip: ['Tải tất cả cấu hình', 'archive', 'indigo', 'client'],
  settings_update: ['Cập nhật cài đặt', 'settings', 'pink', 'system'],
  wg_restart: ['Khởi động lại WireGuard', 'refresh', 'amber', 'system'],
  password_change: ['Đổi mật khẩu', 'lock', 'pink', 'auth'],
  username_change: ['Đổi tên đăng nhập', 'user', 'pink', 'auth'],
  '2fa_enable': ['Bật xác thực 2 lớp', 'shieldCheck', 'green', 'auth'],
  '2fa_disable': ['Tắt xác thực 2 lớp', 'shield', 'red', 'auth'],
  sessions_revoke: ['Đăng xuất phiên khác', 'logout', 'amber', 'auth'],
  backup: ['Tải bản sao lưu', 'archive', 'cyan', 'system'],
  restore: ['Khôi phục dữ liệu', 'upload', 'red', 'system'],
};

export function mount(el, ctx) {
  let logs = [], q = '', group = 'all', alive = true;
  const tbody = h('tbody');
  const count = h('span', { class: 'muted' });
  const search = h('input', { class: 'input', placeholder: 'Tìm trong nhật ký...', oninput: (e) => { q = e.target.value.toLowerCase(); render(); } });
  const chips = {};
  const chip = (k, label) => (chips[k] = h('button', { class: 'chip', onclick: () => { group = k; render(); } }, label));
  const wrap = h('div', { class: 'card' }, h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
    h('thead', null, h('tr', null, h('th', null, 'Thời gian'), h('th', null, 'Sự kiện'), h('th', null, 'Chi tiết'), h('th', null, 'Địa chỉ IP'))), tbody)));
  const empty = h('div', { class: 'card hidden' });
  add(el, 
    h('div', { class: 'toolbar' }, h('div', { class: 'input-group' }, icon('search'), search),
      chip('all', 'Tất cả'), chip('auth', 'Đăng nhập & bảo mật'), chip('client', 'Người dùng'), chip('system', 'Hệ thống'),
      h('div', { class: 'spacer' }), count),
    wrap, empty);
  ctx.setActions(h('button', { class: 'btn', onclick: load }, icon('refresh'), h('span', { class: 'lbl' }, 'Làm mới')));

  function render() {
    for (const [k, c] of Object.entries(chips)) c.classList.toggle('on', k === group);
    const list = logs.filter((l) => {
      const a = ACTIONS[l.action] || [l.action, 'info', '', 'system'];
      if (group !== 'all' && a[3] !== group) return false;
      return !q || (a[0] + ' ' + l.detail + ' ' + l.ip).toLowerCase().includes(q);
    });
    count.textContent = list.length + ' sự kiện';
    clear(tbody);
    wrap.classList.toggle('hidden', !list.length);
    empty.classList.toggle('hidden', !!list.length);
    clear(empty);
    if (!list.length) empty.appendChild(emptyState('Không có sự kiện nào', 'Các thao tác quản trị và sự kiện hệ thống sẽ hiển thị tại đây.'));
    for (const l of list) {
      const a = ACTIONS[l.action] || [l.action, 'info', '', 'system'];
      tbody.appendChild(h('tr', null,
        h('td', { class: 'nowrap' }, h('div', { style: { fontWeight: 600 } }, timeAgo(l.t)), h('div', { class: 'muted', style: { fontSize: '12px' } }, fmtDateTime(l.t))),
        h('td', { class: 'nowrap' }, h('div', { class: 'row' }, h('div', { class: 'log-ic ic ' + (a[2] || '') , style: a[2] ? null : { background: 'var(--surface-3)', color: 'var(--text-2)' } }, icon(a[1])), h('b', null, a[0]))),
        h('td', null, l.detail || h('span', { class: 'muted' }, '—')),
        h('td', { class: 'mono nowrap' }, l.ip)));
    }
  }

  async function load() {
    try {
      const d = await get('/api/logs?limit=1000');
      logs = d.logs;
      if (alive) render();
    } catch (e) { if (e.status !== 401) toast(e.message, 'err'); }
  }
  tbody.appendChild(h('tr', null, h('td', { colspan: 4 }, h('div', { class: 'skeleton', style: { height: '160px' } }))));
  load();
  const t = setInterval(load, 20000);
  return () => { alive = false; clearInterval(t); };
}
