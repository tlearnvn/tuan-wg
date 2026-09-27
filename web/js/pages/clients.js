/*
 * Tuấn WireGuard - trang Người dùng (CRUD, QR, cấu hình, chia sẻ, thống kê)
 * Tác giả: Tuandethuong
 */
import { get, post, put, del, api } from '../api.js';
import { areaChart, barChart } from '../charts.js';
import {
  h, icon, clear, toast, modal, confirmBox, fmtBytes, fmtRate, timeAgo, fmtDate, fmtDateTime, shortDay, longDay,
  expiryText, avatar, copyText, download, busy, field, switchEl, segmented, emptyState, highlightConf,
 add } from '../ui.js';
import { guideContent } from '../guide.js';

const DOWN = '#6366f1', UP = '#14b8a6';
const GB = 1073741824;

let S = null; /* trạng thái trang */

/* ---------- trạng thái & định dạng ---------- */
function statusOf(c) {
  if (!c.enabled) {
    if (c.disabled_reason === 'expired') return { key: 'expired', text: 'Hết hạn', cls: 'red', dot: 'bad' };
    if (c.disabled_reason === 'quota') return { key: 'quota', text: 'Hết dung lượng', cls: 'amber', dot: 'bad' };
    return { key: 'disabled', text: 'Đã tắt', cls: '', dot: 'bad' };
  }
  if (c.stats.online) return { key: 'online', text: 'Online', cls: 'green', dot: 'on' };
  return { key: 'offline', text: 'Offline', cls: '', dot: null };
}

function quotaEl(c) {
  if (!c.data_limit) {
    return h('div', { class: 'quota' }, h('div', { class: 'muted', style: { fontSize: '12.5px' } }, 'Không giới hạn'),
      h('div', { class: 'q-t' }, h('span', null, 'Tháng: ' + fmtBytes(c.stats.month_rx + c.stats.month_tx))));
  }
  const used = c.stats.used, pct = Math.min(100, (used / c.data_limit) * 100);
  return h('div', { class: 'quota' },
    h('div', { class: 'bar' + (pct >= 100 ? ' full' : pct >= 80 ? ' warn' : '') }, h('i', { style: { width: pct + '%' } })),
    h('div', { class: 'q-t' }, h('span', null, fmtBytes(used, 1) + ' / ' + fmtBytes(c.data_limit, 1)), h('span', null, c.limit_monthly ? 'tháng' : 'tổng')));
}

function trafficEl(c) {
  const st = c.stats;
  return h('div', { class: 'traffic' },
    h('span', { class: 'd', title: 'Tải xuống' }, icon('arrowDown'), fmtBytes(st.tx)),
    h('span', { class: 'u', title: 'Tải lên' }, icon('arrowUp'), fmtBytes(st.rx)));
}

function lastSeen(c, now) {
  const st = c.stats;
  if (st.online && (st.rate_rx + st.rate_tx) > 64) return h('span', { class: 'row', style: { gap: '4px', color: 'var(--success)', fontWeight: 600 } }, icon('activity'), fmtRate(st.rate_rx + st.rate_tx));
  return h('span', { class: 'muted' }, st.handshake ? timeAgo(st.handshake, now) : 'Chưa kết nối');
}

/* ---------- menu nhỏ ---------- */
function popMenu(anchor, items) {
  document.querySelectorAll('.menu-pop').forEach((m) => m.remove());
  const m = h('div', { class: 'menu-pop', role: 'menu' });
  for (const it of items) {
    if (!it) { m.appendChild(h('div', { class: 'sep' })); continue; }
    m.appendChild(h('button', { class: it.danger ? 'danger' : '', role: 'menuitem', onclick: () => { m.remove(); it.run(); } }, icon(it.icon), it.label));
  }
  document.body.appendChild(m);
  const r = anchor.getBoundingClientRect();
  const mw = 220;
  m.style.left = Math.max(8, Math.min(window.innerWidth - mw - 8, r.right - mw)) + 'px';
  const top = r.bottom + 6;
  m.style.top = (top + m.offsetHeight > window.innerHeight - 8 ? r.top - m.offsetHeight - 6 : top) + window.scrollY + 'px';
  setTimeout(() => {
    const off = (e) => { if (!m.contains(e.target)) { m.remove(); document.removeEventListener('pointerdown', off, true); } };
    document.addEventListener('pointerdown', off, true);
  }, 0);
}

/* ---------- dữ liệu ---------- */
async function reload() {
  try {
    const d = await get('/api/clients');
    if (!S) return;
    S.clients = d.clients;
    S.server = d.server;
    S.now = d.now;
    const ids = new Set(S.clients.map((c) => c.id));
    for (const id of [...S.sel]) if (!ids.has(id)) S.sel.delete(id);
    render();
  } catch (e) {
    if (e.status !== 401) toast(e.message, 'err');
  }
}

function filtered() {
  const q = S.q.trim().toLowerCase();
  let list = S.clients.filter((c) => {
    const st = statusOf(c).key;
    if (S.filter === 'online' && st !== 'online') return false;
    if (S.filter === 'offline' && st !== 'offline') return false;
    if (S.filter === 'off' && c.enabled) return false;
    if (S.filter === 'limit' && !(c.expires_at || c.data_limit)) return false;
    if (!q) return true;
    return (c.name + ' ' + c.note + ' ' + c.address + ' ' + c.address6 + ' ' + c.stats.endpoint).toLowerCase().includes(q);
  });
  const by = {
    name: (a, b) => a.name.localeCompare(b.name, 'vi'),
    new: (a, b) => b.created_at - a.created_at,
    usage: (a, b) => (b.stats.rx + b.stats.tx) - (a.stats.rx + a.stats.tx),
    seen: (a, b) => (b.stats.online - a.stats.online) || (b.stats.handshake - a.stats.handshake),
    ip: (a, b) => ipNum(a.address) - ipNum(b.address),
  }[S.sort];
  return list.sort(by);
}

function ipNum(ip) { return (ip || '0.0.0.0').split('.').reduce((a, x) => a * 256 + Number(x), 0); }

/* ---------- vẽ ---------- */
function render() {
  const list = filtered();
  const counts = { all: S.clients.length, online: 0, offline: 0, off: 0, limit: 0 };
  for (const c of S.clients) {
    const k = statusOf(c).key;
    if (k === 'online') counts.online++;
    else if (k === 'offline') counts.offline++;
    else counts.off++;
    if (c.expires_at || c.data_limit) counts.limit++;
  }
  for (const [k, chip] of Object.entries(S.chips)) {
    chip.classList.toggle('on', S.filter === k);
    chip.querySelector('.n').textContent = counts[k];
  }
  renderBulk();
  clear(S.tbody);
  clear(S.cards);
  S.empty.classList.toggle('hidden', list.length > 0);
  S.tableCard.classList.toggle('hidden', list.length === 0);
  if (!list.length) {
    clear(S.empty);
    S.empty.appendChild(S.clients.length
      ? emptyState('Không tìm thấy người dùng', 'Thử đổi từ khóa tìm kiếm hoặc bộ lọc.')
      : emptyState('Chưa có người dùng nào', 'Tạo người dùng đầu tiên để lấy file cấu hình hoặc mã QR kết nối VPN.',
        h('button', { class: 'btn primary', onclick: () => openForm() }, icon('userPlus'), 'Thêm người dùng')));
  }
  S.selAll.checked = list.length > 0 && list.every((c) => S.sel.has(c.id));
  for (const c of list) {
    S.tbody.appendChild(row(c));
    S.cards.appendChild(card(c));
  }
}

function actionsFor(c) {
  return [
    { icon: 'edit', label: 'Sửa thông tin', run: () => openForm(c) },
    { icon: 'link', label: 'Tạo link chia sẻ', run: () => openDetail(c.id, 'share') },
    { icon: 'chart', label: 'Xem thống kê', run: () => openDetail(c.id, 'stats') },
    null,
    { icon: 'reset', label: 'Đặt lại dung lượng', run: () => resetUsage(c) },
    { icon: 'key', label: 'Tạo lại khóa', run: () => rekey(c) },
    null,
    { icon: 'trash', label: 'Xóa người dùng', danger: true, run: () => remove(c) },
  ];
}

function toggleEl(c) {
  return switchEl(c.enabled, null, async (v) => {
    try {
      await put('/api/clients/' + c.id, { enabled: v });
      toast(v ? 'Đã bật ' + c.name : 'Đã tắt ' + c.name);
      reload();
    } catch (e) { toast(e.message, 'err'); reload(); }
  });
}

function row(c) {
  const st = statusOf(c);
  const exp = expiryText(c, S.now);
  const cb = h('input', { type: 'checkbox', checked: S.sel.has(c.id), onchange: (e) => { if (e.target.checked) S.sel.add(c.id); else S.sel.delete(c.id); render(); }, 'aria-label': 'Chọn' });
  const more = h('button', { class: 'icon-btn', title: 'Thêm', onclick: () => popMenu(more, actionsFor(c)) }, icon('more'));
  return h('tr', { class: S.sel.has(c.id) ? 'sel' : '' },
    h('td', { style: { width: '36px' } }, cb),
    h('td', null, h('div', { class: 'user-cell', onclick: () => openDetail(c.id) }, avatar(c.name, st.dot),
      h('div', { style: { minWidth: 0 } }, h('div', { class: 'nm ellipsis' }, c.name), h('div', { class: 'nt ellipsis' }, c.note || 'Tạo ' + fmtDate(c.created_at))))),
    h('td', null, h('span', { class: 'mono' }, c.address), c.address6 ? h('div', { class: 'muted mono', style: { fontSize: '11px' } }, c.address6) : null),
    h('td', null, h('div', { class: 'status-cell' }, h('span', { class: 'badge ' + st.cls }, st.dot === 'on' ? h('span', { class: 'dot on' }) : null, st.text), lastSeen(c, S.now))),
    h('td', null, trafficEl(c)),
    h('td', null, quotaEl(c)),
    h('td', { class: 'nowrap' }, h('span', { class: exp.cls ? 'badge ' + exp.cls : 'muted' }, exp.text)),
    h('td', null, h('div', { class: 'actions' },
      h('button', { class: 'icon-btn', title: 'Mã QR & cấu hình', onclick: () => openDetail(c.id, 'conn') }, icon('qr')),
      h('button', { class: 'icon-btn', title: 'Tải file .conf', onclick: () => download('/api/clients/' + c.id + '/config') }, icon('download')),
      h('span', { title: c.enabled ? 'Tắt' : 'Bật', style: { display: 'inline-flex', alignItems: 'center', padding: '0 6px' } }, toggleEl(c)),
      more)));
}

function card(c) {
  const st = statusOf(c);
  const exp = expiryText(c, S.now);
  const more = h('button', { class: 'icon-btn', onclick: () => popMenu(more, actionsFor(c)) }, icon('more'));
  return h('div', { class: 'card client-card' },
    h('div', { class: 'top' }, avatar(c.name, st.dot),
      h('div', { style: { flex: 1, minWidth: 0 }, onclick: () => openDetail(c.id) }, h('div', { class: 'nm ellipsis', style: { fontWeight: 600 } }, c.name),
        h('div', { class: 'muted mono', style: { fontSize: '12px' } }, c.address)),
      toggleEl(c)),
    h('div', { class: 'meta' },
      h('div', null, h('b', null, 'Trạng thái'), h('span', { class: 'badge ' + st.cls }, st.text)),
      h('div', null, h('b', null, 'Kết nối'), lastSeen(c, S.now)),
      h('div', null, h('b', null, 'Đã dùng'), trafficEl(c)),
      h('div', null, h('b', null, 'Hết hạn'), h('span', { class: exp.cls ? 'badge ' + exp.cls : '' }, exp.text)),
      c.data_limit ? h('div', { style: { gridColumn: '1 / -1' } }, h('b', null, 'Hạn mức'), quotaEl(c)) : null),
    h('div', { class: 'acts' },
      h('button', { class: 'btn sm soft', onclick: () => openDetail(c.id, 'conn') }, icon('qr'), 'QR & cấu hình'),
      h('button', { class: 'btn sm', onclick: () => download('/api/clients/' + c.id + '/config') }, icon('download'), '.conf'),
      h('div', { class: 'spacer' }), more));
}

function renderBulk() {
  const n = S.sel.size;
  S.bulk.classList.toggle('hidden', n === 0);
  S.bulkCount.textContent = 'Đã chọn ' + n + ' người dùng';
}

async function bulk(action) {
  const ids = [...S.sel];
  const labels = { enable: 'bật', disable: 'tắt', reset: 'đặt lại dung lượng cho', delete: 'XÓA' };
  if (action === 'delete' || action === 'reset') {
    const ok = await confirmBox({ title: 'Xác nhận', message: 'Bạn chắc chắn muốn ' + labels[action] + ' ' + ids.length + ' người dùng đã chọn?' + (action === 'delete' ? ' Thao tác này không thể hoàn tác.' : ''), okText: 'Đồng ý', danger: action === 'delete' });
    if (!ok) return;
  }
  try {
    const r = await post('/api/clients/bulk', { ids, action });
    toast('Đã ' + labels[action] + ' ' + r.count + ' người dùng');
    if (action === 'delete') S.sel.clear();
    reload();
  } catch (e) { toast(e.message, 'err'); }
}

/* ---------- thao tác ---------- */
async function remove(c) {
  const ok = await confirmBox({ title: 'Xóa người dùng?', message: h('span', null, 'Người dùng ', h('b', null, c.name), ' sẽ bị xóa vĩnh viễn và mất kết nối VPN ngay lập tức. Thống kê dung lượng cũng bị xóa.'), okText: 'Xóa', danger: true, icon: 'trash' });
  if (!ok) return;
  try { await del('/api/clients/' + c.id); toast('Đã xóa ' + c.name); S.sel.delete(c.id); reload(); } catch (e) { toast(e.message, 'err'); }
}

async function resetUsage(c) {
  const ok = await confirmBox({ title: 'Đặt lại dung lượng?', message: h('span', null, 'Bộ đếm dung lượng của ', h('b', null, c.name), ' sẽ về 0 (lịch sử theo ngày vẫn được giữ). Nếu đang bị khóa do hết dung lượng, người dùng sẽ được mở lại.'), okText: 'Đặt lại', icon: 'reset' });
  if (!ok) return;
  try { await post('/api/clients/' + c.id + '/reset'); toast('Đã đặt lại dung lượng'); reload(); } catch (e) { toast(e.message, 'err'); }
}

async function rekey(c) {
  const ok = await confirmBox({ title: 'Tạo lại khóa?', message: h('span', null, 'Khóa của ', h('b', null, c.name), ' sẽ được tạo mới. Thiết bị đang dùng cấu hình cũ sẽ ', h('b', null, 'mất kết nối'), ' cho tới khi nhập cấu hình mới. Các link chia sẻ cũ bị hủy.'), okText: 'Tạo lại khóa', danger: true, icon: 'key' });
  if (!ok) return;
  try { await post('/api/clients/' + c.id + '/rekey'); toast('Đã tạo khóa mới'); reload(); openDetail(c.id, 'conn'); } catch (e) { toast(e.message, 'err'); }
}

/* ---------- form thêm / sửa ---------- */
function vpnSubnet() {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec((S.server && S.server.address) || '10.8.0.1/24');
  if (!m) return '10.8.0.0/24';
  const p = +m[5];
  let ip = ((+m[1] << 24) | (+m[2] << 16) | (+m[3] << 8) | +m[4]) >>> 0;
  const mask = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
  ip = (ip & mask) >>> 0;
  return [ip >>> 24, (ip >>> 16) & 255, (ip >>> 8) & 255, ip & 255].join('.') + '/' + p;
}

function endOfDay(date) {
  const d = new Date(date);
  d.setHours(23, 59, 59, 0);
  return Math.floor(d.getTime() / 1000);
}

function openForm(c) {
  const edit = !!c;
  const srv = S.server || {};
  const name = h('input', { class: 'input', value: edit ? c.name : '', placeholder: 'Ví dụ: iPhone của Mai', maxlength: 64, required: true });
  const note = h('input', { class: 'input', value: edit ? c.note : '', placeholder: 'Ghi chú (không bắt buộc)', maxlength: 200 });

  /* hết hạn */
  let expMode = edit && c.expires_at ? 'date' : 'never';
  const dateIn = h('input', { class: 'input', type: 'date' });
  if (edit && c.expires_at) {
    const d = new Date(c.expires_at * 1000);
    dateIn.value = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  }
  const dateWrap = h('div', { class: expMode === 'date' ? '' : 'hidden', style: { marginTop: '8px' } }, dateIn);
  const expSeg = segmented([['never', 'Không giới hạn'], ['7', '7 ngày'], ['30', '30 ngày'], ['90', '90 ngày'], ['365', '1 năm'], ['date', 'Chọn ngày']], expMode, (v) => {
    expMode = v;
    dateWrap.classList.toggle('hidden', v !== 'date');
    if (v === 'date' && !dateIn.value) { const d = new Date(Date.now() + 30 * 86400000); dateIn.valueAsDate = d; }
  });

  /* hạn mức */
  const limit = h('input', { class: 'input', type: 'number', min: 0, step: 'any', placeholder: 'Không giới hạn', value: edit && c.data_limit ? +(c.data_limit / GB).toFixed(2) : '' });
  let monthly = edit ? c.limit_monthly : true;

  /* nâng cao */
  const full = srv.allowed_ips || '0.0.0.0/0, ::/0';
  const vpn = vpnSubnet();
  let route = !edit || !c.allowed_ips ? 'full' : c.allowed_ips === vpn ? 'vpn' : 'custom';
  const customIps = h('input', { class: 'input mono', value: edit && route === 'custom' ? c.allowed_ips : '', placeholder: 'Ví dụ: 10.8.0.0/24, 192.168.1.0/24' });
  const routeCards = h('div', { class: 'radio-cards' });
  const drawRoute = () => {
    clear(routeCards);
    const opt = (v, title, desc) => h('label', { class: 'radio-card' + (route === v ? ' on' : '') },
      h('input', { type: 'radio', name: 'route', checked: route === v, onchange: () => { route = v; drawRoute(); } }),
      h('div', null, h('b', null, title), h('span', null, desc)));
    add(routeCards, 
      opt('full', 'Toàn bộ lưu lượng qua VPN', 'Mặc định: ' + full + ' - ẩn IP, bảo vệ khi dùng Wi-Fi công cộng'),
      opt('vpn', 'Chỉ mạng nội bộ VPN', vpn + ' - truy cập máy chủ/thiết bị trong VPN, Internet đi đường thường'),
      opt('custom', 'Tùy chỉnh', 'Tự nhập danh sách dải mạng (AllowedIPs)'));
    if (route === 'custom') routeCards.appendChild(customIps);
  };
  drawRoute();
  const address = h('input', { class: 'input mono', value: edit ? c.address : '', placeholder: 'Tự động cấp' });
  const dns = h('input', { class: 'input mono', value: edit ? c.dns : '', placeholder: 'Mặc định: ' + (srv.dns || 'không đặt') });
  const ka = h('input', { class: 'input', type: 'number', min: 0, max: 3600, value: edit && c.keepalive >= 0 ? c.keepalive : '', placeholder: 'Mặc định: ' + (srv.keepalive || 0) });
  const mtu = h('input', { class: 'input', type: 'number', min: 576, max: 9000, value: edit && c.mtu ? c.mtu : '', placeholder: 'Mặc định' + (srv.mtu ? ': ' + srv.mtu : '') });
  let enabled = edit ? c.enabled : true;

  const adv = h('div', { class: 'form-grid hidden', style: { marginTop: '14px' } },
    h('div', { class: 'full' }, h('div', { class: 'label', style: { marginBottom: '8px' } }, 'Định tuyến (AllowedIPs)'), routeCards),
    field('Địa chỉ IP trong VPN', address, 'Để trống để tự động cấp IP còn trống'),
    field('DNS', dns, 'Ví dụ: 1.1.1.1, 8.8.8.8'),
    field('Persistent Keepalive (giây)', ka, 'Giữ kết nối qua NAT, thường là 25'),
    field('MTU', mtu, 'Để trống nếu không chắc chắn'));
  const advToggle = h('button', { type: 'button', class: 'btn ghost sm', onclick: () => { adv.classList.toggle('hidden'); advToggle.querySelector('svg').style.transform = adv.classList.contains('hidden') ? '' : 'rotate(180deg)'; } }, icon('chevronDown'), 'Tùy chọn nâng cao');
  if (edit && (c.dns || c.allowed_ips || c.keepalive >= 0 || c.mtu)) setTimeout(() => advToggle.click(), 0);

  const err = h('div', { class: 'alert err hidden full' });
  const body = h('div', { class: 'form-grid' },
    err,
    h('div', { class: 'full' }, field('Tên người dùng / thiết bị *', name)),
    h('div', { class: 'full' }, field('Ghi chú', note)),
    h('div', { class: 'form-section' }, 'Giới hạn sử dụng'),
    h('div', { class: 'full' }, h('div', { class: 'field' }, h('label', null, 'Thời hạn sử dụng'), expSeg, dateWrap,
      edit && c.expired ? h('div', { class: 'hint', style: { color: 'var(--danger)' } }, 'Đã hết hạn - chọn thời hạn mới để gia hạn và tự mở khóa') : null)),
    field('Hạn mức dung lượng', h('div', { class: 'input-affix' }, limit, h('span', { class: 'affix' }, 'GB')), 'Tính cả tải lên và tải xuống. Để trống = không giới hạn'),
    h('div', { class: 'field', style: { justifyContent: 'center' } }, h('label', null, 'Chu kỳ hạn mức'), switchEl(monthly, 'Làm mới vào đầu mỗi tháng', (v) => { monthly = v; })),
    edit ? h('div', { class: 'full' }, switchEl(enabled, 'Cho phép kết nối (bật người dùng)', (v) => { enabled = v; })) : null,
    h('div', { class: 'full' }, advToggle, adv));

  const save = h('button', { class: 'btn primary', type: 'submit' }, icon('check'), edit ? 'Lưu thay đổi' : 'Tạo người dùng');
  const m = modal({
    title: edit ? 'Sửa người dùng' : 'Thêm người dùng mới', sub: edit ? c.name + ' • ' + c.address : 'Tạo tài khoản VPN cho một thiết bị',
    size: 'lg', body: h('form', { id: 'clientForm', onsubmit: (e) => { e.preventDefault(); submit(); } }, body),
    footer: [h('button', { class: 'btn', type: 'button', onclick: () => m.close() }, 'Hủy'), save],
  });
  save.addEventListener('click', (e) => { e.preventDefault(); submit(); });

  async function submit() {
    err.classList.add('hidden');
    const payload = { name: name.value.trim(), note: note.value.trim() };
    if (!payload.name) { name.focus(); err.textContent = 'Vui lòng nhập tên người dùng'; err.classList.remove('hidden'); return; }
    if (expMode === 'never') payload.expires_at = 0;
    else if (expMode === 'date') {
      if (!dateIn.value) { err.textContent = 'Vui lòng chọn ngày hết hạn'; err.classList.remove('hidden'); return; }
      payload.expires_at = endOfDay(dateIn.value + 'T12:00:00');
    } else payload.expires_at = endOfDay(Date.now() + Number(expMode) * 86400000);
    const gb = parseFloat(String(limit.value).replace(',', '.'));
    payload.data_limit = gb > 0 ? Math.round(gb * GB) : 0;
    payload.limit_monthly = monthly;
    payload.allowed_ips = route === 'full' ? '' : route === 'vpn' ? vpn : customIps.value.trim();
    if (route === 'custom' && !payload.allowed_ips) { err.textContent = 'Nhập danh sách AllowedIPs hoặc chọn kiểu định tuyến khác'; err.classList.remove('hidden'); return; }
    payload.dns = dns.value.trim();
    payload.keepalive = ka.value === '' ? -1 : Number(ka.value);
    payload.mtu = mtu.value === '' ? 0 : Number(mtu.value);
    if (address.value.trim() && (!edit || address.value.trim() !== c.address)) payload.address = address.value.trim();
    if (edit) payload.enabled = enabled;
    busy(save, true);
    try {
      const r = edit ? await put('/api/clients/' + c.id, payload) : await post('/api/clients', payload);
      m.close();
      toast(edit ? 'Đã lưu ' + r.name : 'Đã tạo người dùng ' + r.name);
      if (r.warning) toast('Cảnh báo: ' + r.warning, 'err', 7000);
      await reload();
      if (!edit) openDetail(r.id, 'conn');
    } catch (e) {
      err.textContent = e.message;
      err.classList.remove('hidden');
      m.body.scrollTop = 0;
    } finally { busy(save, false); }
  }
}

/* ---------- chi tiết người dùng ---------- */
async function openDetail(id, tab = 'conn') {
  let d;
  try { d = await get('/api/clients/' + id); } catch (e) { toast(e.message, 'err'); return; }
  const c = d.client;
  const st = statusOf(c);
  const tabs = [['conn', 'qr', 'Kết nối'], ['stats', 'chart', 'Thống kê'], ['info', 'info', 'Thông tin'], ['share', 'link', 'Chia sẻ'], ['guide', 'book', 'Hướng dẫn']];
  const tabBar = h('div', { class: 'tabs' });
  const pane = h('div');
  const charts = [];
  const m = modal({
    title: h('span', { class: 'row', style: { gap: '12px' } }, avatar(c.name, st.dot), h('span', null, c.name, ' ', h('span', { class: 'badge ' + st.cls, style: { verticalAlign: 'middle' } }, st.text))),
    sub: c.address + (c.note ? ' • ' + c.note : ''), size: 'xl', body: h('div', null, tabBar, pane),
    onClose: () => charts.forEach((x) => x.destroy()),
    footer: [
      h('button', { class: 'btn', onclick: () => { m.close(); openForm(S.clients.find((x) => x.id === id) || c); } }, icon('edit'), 'Sửa'),
      h('div', { class: 'spacer' }),
      h('button', { class: 'btn primary', onclick: () => m.close() }, 'Đóng'),
    ],
  });
  const show = (key) => {
    for (const b of tabBar.children) b.classList.toggle('on', b.dataset.k === key);
    charts.forEach((x) => x.destroy());
    charts.length = 0;
    clear(pane);
    ({ conn: tabConn, stats: tabStats, info: tabInfo, share: tabShare, guide: tabGuide })[key](pane, c, d, charts);
  };
  for (const [k, ic, label] of tabs) tabBar.appendChild(h('button', { 'data-k': k, onclick: () => show(k) }, icon(ic), label));
  show(tab);
}

async function tabConn(pane, c) {
  const conf = h('div', { class: 'conf-box' }, 'Đang tải cấu hình...');
  const qr = h('img', { src: '/api/clients/' + c.id + '/qr.svg?t=' + Date.now(), alt: 'Mã QR cấu hình WireGuard' });
  let text = '';
  add(pane, 
    !c.enabled ? h('div', { class: 'alert warn', style: { marginBottom: '16px' } }, icon('alert'), h('div', null, 'Người dùng đang ', h('b', null, 'bị tắt'), ' - thiết bị sẽ không kết nối được cho tới khi bật lại.')) : null,
    h('div', { class: 'conf-grid' },
      h('div', { class: 'col', style: { alignItems: 'center' } }, h('div', { class: 'qr-box' }, qr),
        h('div', { class: 'muted', style: { fontSize: '12.5px', textAlign: 'center' } }, 'Mở ứng dụng WireGuard trên điện thoại → ', h('b', null, '+'), ' → ', h('b', null, 'Quét mã QR'))),
      h('div', { class: 'col' },
        h('div', { class: 'row wrap' },
          h('button', { class: 'btn primary', onclick: () => download('/api/clients/' + c.id + '/config') }, icon('download'), 'Tải file .conf'),
          h('button', { class: 'btn', onclick: () => copyText(text) }, icon('copy'), 'Sao chép'),
          h('button', { class: 'btn', onclick: () => { pane.closest('.modal').querySelector('.tabs button[data-k=share]').click(); } }, icon('link'), 'Link chia sẻ')),
        conf,
        h('div', { class: 'muted', style: { fontSize: '12px' } }, icon('lock'), ' File chứa khóa riêng (PrivateKey) - chỉ gửi cho đúng người dùng qua kênh an toàn.'))));
  try {
    text = await api('/api/clients/' + c.id + '/config?inline=1', { text: true });
    conf.innerHTML = highlightConf(text);
  } catch (e) { conf.textContent = e.message; }
}

function tabStats(pane, c, d, charts) {
  const s = c.stats;
  const mini = (label, v, color) => h('div', { class: 'card', style: { padding: '14px 16px', boxShadow: 'none' } },
    h('div', { class: 'muted', style: { fontSize: '12.5px', fontWeight: 600 } }, label), h('div', { style: { fontSize: '20px', fontWeight: 700, color } }, v));
  const daysBox = h('div'), hoursBox = h('div');
  add(pane, 
    h('div', { class: 'stats-grid', style: { gap: '12px' } },
      mini('Tổng tải xuống', fmtBytes(s.tx), DOWN), mini('Tổng tải lên', fmtBytes(s.rx), UP),
      mini('Tháng này', fmtBytes(s.month_rx + s.month_tx)), mini('Hôm nay', fmtBytes(s.today_rx + s.today_tx))),
    h('div', { class: 'row', style: { margin: '20px 0 8px' } }, h('b', null, '30 ngày gần nhất'), h('div', { class: 'spacer' }),
      h('div', { class: 'legend' }, h('span', null, h('i', { style: { background: DOWN } }), 'Tải xuống'), h('span', null, h('i', { style: { background: UP } }), 'Tải lên'))),
    daysBox,
    h('div', { style: { margin: '20px 0 8px' } }, h('b', null, '24 giờ gần nhất')), hoursBox);
  charts.push(barChart(daysBox, {
    height: 220, series: [{ name: 'Tải xuống', color: DOWN, values: d.days.map((x) => x.tx) }, { name: 'Tải lên', color: UP, values: d.days.map((x) => x.rx) }],
    xFormat: (i) => shortDay(d.days[i].label), tipTitle: (i) => longDay(d.days[i].label), yFormat: (v) => fmtBytes(v, 1), tipFormat: (v) => fmtBytes(v),
  }));
  charts.push(areaChart(hoursBox, {
    height: 200, series: [{ name: 'Tải xuống', color: DOWN, values: d.hours.map((x) => x.tx) }, { name: 'Tải lên', color: UP, values: d.hours.map((x) => x.rx) }],
    xFormat: (i) => shortDay(d.hours[i].label), tipTitle: (i) => longDay(d.hours[i].label), yFormat: (v) => fmtBytes(v, 1), tipFormat: (v) => fmtBytes(v),
  }));
}

function tabInfo(pane, c) {
  const s = c.stats;
  const srv = S.server || {};
  const kv = (k, v, mono) => [h('dt', null, k), h('dd', { class: mono ? 'mono' : '' }, v)];
  add(pane, h('dl', { class: 'kv', style: { gridTemplateColumns: 'minmax(140px, auto) 1fr' } },
    kv('Mã người dùng', c.id, true),
    kv('Địa chỉ IP', c.address + (c.address6 ? ', ' + c.address6 : ''), true),
    kv('Khóa công khai', h('span', { class: 'row', style: { gap: '6px' } }, c.public_key, h('button', { class: 'icon-btn', onclick: () => copyText(c.public_key) }, icon('copy'))), true),
    kv('Khóa chia sẻ trước (PSK)', c.has_psk ? 'Có (tăng cường bảo mật)' : 'Không'),
    kv('Định tuyến', c.allowed_ips || (srv.allowed_ips || '') + ' (mặc định)', true),
    kv('DNS', c.dns || (srv.dns || '—') + ' (mặc định)', true),
    kv('Keepalive', (c.keepalive >= 0 ? c.keepalive : srv.keepalive) + ' giây' + (c.keepalive >= 0 ? '' : ' (mặc định)')),
    kv('MTU', c.mtu || srv.mtu || 'Mặc định'),
    kv('Thời hạn', c.expires_at ? fmtDateTime(c.expires_at) + ' (' + expiryText(c).text.toLowerCase() + ')' : 'Không giới hạn'),
    kv('Hạn mức', c.data_limit ? fmtBytes(c.data_limit) + (c.limit_monthly ? ' mỗi tháng' : ' tổng cộng') + ' - đã dùng ' + fmtBytes(s.used) : 'Không giới hạn'),
    kv('Kết nối gần nhất', s.handshake ? fmtDateTime(s.handshake) + ' (' + timeAgo(s.handshake) + ')' : 'Chưa từng kết nối'),
    kv('IP thật của thiết bị', s.endpoint || '—', true),
    kv('Tạo lúc', fmtDateTime(c.created_at)),
    kv('Cập nhật', fmtDateTime(c.updated_at))));
}

function tabShare(pane, c, d) {
  let hours = 24;
  const list = h('div', { class: 'list' });
  const renderList = (shares) => {
    clear(list);
    if (!shares.length) { list.appendChild(h('div', { class: 'muted', style: { padding: '14px 0' } }, 'Chưa có link chia sẻ nào đang hoạt động.')); return; }
    for (const sh of shares) {
      const url = location.origin + '/s/' + sh.token;
      list.appendChild(h('div', { class: 'list-item', style: { display: 'block' } },
        h('div', { class: 'share-url' }, h('input', { class: 'input', readonly: true, value: url, onclick: (e) => e.target.select() }),
          h('button', { class: 'btn', onclick: () => copyText(url) }, icon('copy'), 'Sao chép'),
          h('button', { class: 'btn danger', onclick: async () => {
            try { await del('/api/shares/' + sh.token); toast('Đã thu hồi link'); const nd = await get('/api/clients/' + c.id); renderList(nd.shares); } catch (e) { toast(e.message, 'err'); }
          } }, icon('x'), 'Thu hồi')),
        h('div', { class: 'muted', style: { fontSize: '12px', marginTop: '6px' } }, 'Hết hạn ' + fmtDateTime(sh.expires_at) + ' • đã mở ' + sh.views + ' lần')));
    }
  };
  const create = h('button', { class: 'btn primary', onclick: async () => {
    busy(create, true);
    try {
      const r = await post('/api/clients/' + c.id + '/share', { hours });
      const url = location.origin + r.path;
      await copyText(url);
      const nd = await get('/api/clients/' + c.id);
      renderList(nd.shares);
    } catch (e) { toast(e.message, 'err'); } finally { busy(create, false); }
  } }, icon('link'), 'Tạo link');
  add(pane, 
    h('div', { class: 'alert info', style: { marginBottom: '16px' } }, icon('info'), h('div', null, 'Gửi link cho người dùng qua Zalo/Messenger/Email. Họ mở link để quét mã QR hoặc tải file cấu hình mà ', h('b', null, 'không cần đăng nhập'), '. Link tự hết hạn và có thể thu hồi bất kỳ lúc nào.')),
    h('div', { class: 'row wrap', style: { marginBottom: '14px' } }, h('b', null, 'Thời hạn link:'),
      segmented([[1, '1 giờ'], [24, '24 giờ'], [72, '3 ngày'], [168, '7 ngày']], hours, (v) => { hours = v; }), create),
    h('h4', { style: { margin: '10px 0 4px' } }, 'Link đang hoạt động'), list);
  renderList(d.shares);
}

function tabGuide(pane) {
  add(pane, h('p', { class: 'text-2', style: { marginTop: 0 } }, 'Cách kết nối VPN trên từng thiết bị bằng ứng dụng WireGuard chính thức (miễn phí):'), guideContent());
}

/* ---------- mount ---------- */
export function mount(el, ctx) {
  S = { clients: [], server: null, now: 0, q: '', filter: 'all', sort: 'name', sel: new Set(), chips: {} };
  const search = h('input', { class: 'input', placeholder: 'Tìm theo tên, IP, ghi chú...', oninput: (e) => { S.q = e.target.value; render(); } });
  const chip = (k, label) => { const c = h('button', { class: 'chip', onclick: () => { S.filter = k; render(); } }, label, h('span', { class: 'n' }, '0')); S.chips[k] = c; return c; };
  const sort = h('select', { class: 'select', style: { width: 'auto' }, onchange: (e) => { S.sort = e.target.value; render(); } },
    h('option', { value: 'name' }, 'Sắp xếp: Tên'), h('option', { value: 'new' }, 'Mới tạo'), h('option', { value: 'usage' }, 'Dùng nhiều nhất'),
    h('option', { value: 'seen' }, 'Online gần đây'), h('option', { value: 'ip' }, 'Địa chỉ IP'));
  S.selAll = h('input', { type: 'checkbox', 'aria-label': 'Chọn tất cả', onchange: (e) => { for (const c of filtered()) { if (e.target.checked) S.sel.add(c.id); else S.sel.delete(c.id); } render(); } });
  S.tbody = h('tbody');
  S.cards = h('div', { class: 'client-cards' });
  S.empty = h('div', { class: 'card hidden' });
  S.bulkCount = h('span');
  S.bulk = h('div', { class: 'bulkbar hidden' }, icon('check'), S.bulkCount, h('div', { class: 'spacer' }),
    h('button', { class: 'btn sm', onclick: () => bulk('enable') }, icon('power'), 'Bật'),
    h('button', { class: 'btn sm', onclick: () => bulk('disable') }, icon('x'), 'Tắt'),
    h('button', { class: 'btn sm', onclick: () => bulk('reset') }, icon('reset'), 'Đặt lại dung lượng'),
    h('button', { class: 'btn sm danger', onclick: () => bulk('delete') }, icon('trash'), 'Xóa'),
    h('button', { class: 'btn sm ghost', onclick: () => { S.sel.clear(); render(); } }, 'Bỏ chọn'));
  S.tableCard = h('div', { class: 'card client-table' }, h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
    h('thead', null, h('tr', null, h('th', null, S.selAll), h('th', null, 'Người dùng'), h('th', null, 'Địa chỉ IP'), h('th', null, 'Trạng thái'),
      h('th', null, 'Dung lượng'), h('th', null, 'Hạn mức'), h('th', null, 'Thời hạn'), h('th', { style: { textAlign: 'right' } }, 'Thao tác'))),
    S.tbody)));
  add(el, 
    h('div', { class: 'toolbar' }, h('div', { class: 'input-group' }, icon('search'), search),
      chip('all', 'Tất cả'), chip('online', 'Online'), chip('offline', 'Offline'), chip('off', 'Đã khóa'), chip('limit', 'Có giới hạn'),
      h('div', { class: 'spacer' }), sort),
    S.bulk, S.tableCard, S.cards, S.empty);
  ctx.setActions(
    h('button', { class: 'btn', title: 'Tải tất cả cấu hình (.zip)', onclick: () => download('/api/export.zip') }, icon('archive'), h('span', { class: 'lbl' }, 'Tải tất cả')),
    h('button', { class: 'btn primary', onclick: () => openForm() }, icon('userPlus'), h('span', { class: 'lbl' }, 'Thêm người dùng')));
  S.tbody.appendChild(h('tr', null, h('td', { colspan: 8 }, h('div', { class: 'skeleton', style: { height: '160px' } }))));
  reload().then(() => {
    if (/[?&]new=1/.test(location.hash)) { history.replaceState(null, '', '#/nguoi-dung'); openForm(); }
  });
  const timer = setInterval(() => { if (!document.querySelector('.modal-root')) reload(); }, 5000);
  return () => { clearInterval(timer); document.querySelectorAll('.menu-pop').forEach((m) => m.remove()); S = null; };
}
