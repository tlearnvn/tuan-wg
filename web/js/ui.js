/*
 * Tuấn WireGuard - thư viện giao diện dùng chung
 * Tác giả: Tuandethuong
 *
 * Mọi nội dung người dùng đều được chèn bằng textContent (h()) để chống XSS.
 */

/* ---------- tạo phần tử ---------- */
export function h(tag, attrs, ...children) {
  const el = tag === 'svg' || tag === 'path' || tag === 'circle' || tag === 'rect' || tag === 'line' || tag === 'g' || tag === 'polyline' || tag === 'text' || tag === 'defs' || tag === 'linearGradient' || tag === 'stop'
    ? document.createElementNS('http://www.w3.org/2000/svg', tag)
    : document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.setAttribute('class', v);
      else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'html') el.innerHTML = v; /* chỉ dùng với chuỗi tĩnh do ứng dụng tạo */
      else if (k === 'value' && 'value' in el) el.value = v;
      else if (k === 'checked' || k === 'disabled' || k === 'selected') el[k] = !!v;
      else el.setAttribute(k, v === true ? '' : v);
    }
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) append(el, c);
    else if (c instanceof Node) el.appendChild(c);
    else el.appendChild(document.createTextNode(String(c)));
  }
}

/* append an toàn: bỏ qua null/false (Element.append chuẩn sẽ in ra chữ "null") */
export function add(el, ...children) {
  append(el, children);
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function $(sel, root = document) { return root.querySelector(sel); }

/* ---------- icon ---------- */
const ICONS = {
  dashboard: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
  users: '<circle cx="9" cy="8" r="4"/><path d="M2 21v-1a6 6 0 0 1 6-6h2a6 6 0 0 1 6 6v1"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/><path d="M22 21v-1a4 4 0 0 0-3-3.85"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21v-1a7 7 0 0 1 7-7h2a7 7 0 0 1 7 7v1"/>',
  userPlus: '<circle cx="9" cy="8" r="4"/><path d="M2 21v-1a6 6 0 0 1 6-6h2a6 6 0 0 1 6 6v1"/><path d="M19 8v6M16 11h6"/>',
  chart: '<path d="M3 3v18h18"/><path d="M8 17v-6M13 17V7M18 17v-4"/>',
  settings: '<path d="M21 4h-7M10 4H3M21 12h-9M8 12H3M21 20h-5M12 20H3M14 2v4M8 10v4M16 18v4"/>',
  logs: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  edit: '<path d="M17 3a2.85 2.85 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/>',
  trash: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v6M14 11v6"/>',
  download: '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',
  upload: '<path d="M12 21V9M7 14l5-5 5 5M5 3h14"/>',
  qr: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14v.01M14 20h.01M17 20h4v1M20 17h1"/>',
  power: '<path d="M12 2v10M18.4 6.6a9 9 0 1 1-12.77.04"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/>',
  copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  moon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>',
  search: '<circle cx="11" cy="11" r="8"/><path d="M21 21l-4.3-4.3"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  shieldCheck: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>',
  clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
  server: '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/>',
  activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
  arrowDown: '<path d="M12 5v14M19 12l-7 7-7-7"/>',
  arrowUp: '<path d="M12 19V5M5 12l7-7 7 7"/>',
  check: '<path d="M20 6L9 17l-5-5"/>',
  x: '<path d="M18 6L6 18M6 6l12 12"/>',
  key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="M21 2l-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  eye: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19M14.12 14.12a3 3 0 1 1-4.24-4.24M1 1l22 22"/>',
  menu: '<path d="M3 6h18M3 12h18M3 18h18"/>',
  more: '<circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/>',
  globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  cpu: '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/>',
  disk: '<path d="M22 12H2M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11zM6 16h.01M10 16h.01"/>',
  memory: '<rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 10v4M10 10v4M14 10v4M18 10v4"/>',
  wifi: '<path d="M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0M12 20h.01"/>',
  calendar: '<rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/>',
  archive: '<path d="M21 8v13H3V8M1 3h22v5H1zM10 12h4"/>',
  zap: '<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>',
  phone: '<rect x="5" y="2" width="14" height="20" rx="2"/><path d="M12 18h.01"/>',
  monitor: '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
  alert: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01"/>',
  reset: '<path d="M1 4v6h6"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>',
  share: '<path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8M16 6l-4-4-4 4M12 2v13"/>',
  book: '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
  sparkles: '<path d="M12 3l1.9 5.8L20 11l-6.1 2.2L12 19l-1.9-5.8L4 11l6.1-2.2z"/>',
  gauge: '<path d="M12 14l4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/>',
  toggle: '<rect x="1" y="5" width="22" height="14" rx="7"/><circle cx="16" cy="12" r="3"/>',
  file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/>',
  chevronDown: '<path d="M6 9l6 6 6-6"/>',
  chevronRight: '<path d="M9 18l6-6-6-6"/>',
  network: '<rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M12 8v4M5 16v-2h14v2"/>',
  database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
  github: '<path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>',
  heart: '<path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/>',
  filter: '<path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3z"/>',
};

export function icon(name, cls) {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  s.setAttribute('viewBox', '0 0 24 24');
  s.setAttribute('class', 'icon' + (cls ? ' ' + cls : ''));
  s.setAttribute('aria-hidden', 'true');
  s.innerHTML = ICONS[name] || ICONS.info;
  return s;
}

/* ---------- định dạng ---------- */
const nf2 = new Intl.NumberFormat('vi-VN', { maximumFractionDigits: 2 });
const nf1 = new Intl.NumberFormat('vi-VN', { maximumFractionDigits: 1 });
const nf0 = new Intl.NumberFormat('vi-VN', { maximumFractionDigits: 0 });

export function fmtNum(n) { return nf0.format(n || 0); }

export function fmtBytes(b, digits) {
  b = Number(b) || 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  const f = digits === 1 ? nf1 : (i === 0 ? nf0 : nf2);
  return f.format(b) + ' ' + u[i];
}

export function bytesParts(b) {
  const s = fmtBytes(b);
  const i = s.lastIndexOf(' ');
  return [s.slice(0, i), s.slice(i + 1)];
}

/* tốc độ: byte/giây -> bit/giây */
export function fmtRate(bps) {
  let v = (Number(bps) || 0) * 8;
  const u = ['bps', 'Kbps', 'Mbps', 'Gbps'];
  let i = 0;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  return (i === 0 ? nf0 : nf1).format(v) + ' ' + u[i];
}

export function timeAgo(t, now) {
  if (!t) return 'chưa từng';
  now = now || Math.floor(Date.now() / 1000);
  let d = now - t;
  if (d < 0) d = 0;
  if (d < 10) return 'vừa xong';
  if (d < 60) return d + ' giây trước';
  if (d < 3600) return Math.floor(d / 60) + ' phút trước';
  if (d < 86400) return Math.floor(d / 3600) + ' giờ trước';
  if (d < 172800) return 'hôm qua';
  if (d < 2592000) return Math.floor(d / 86400) + ' ngày trước';
  return fmtDate(t);
}

const pad = (n) => String(n).padStart(2, '0');
export function fmtDate(t) {
  if (!t) return '—';
  const d = new Date(t * 1000);
  return pad(d.getDate()) + '/' + pad(d.getMonth() + 1) + '/' + d.getFullYear();
}
export function fmtDateTime(t) {
  if (!t) return '—';
  const d = new Date(t * 1000);
  return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ' ' + fmtDate(t);
}
export function fmtTime(t) {
  const d = new Date(t * 1000);
  return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
}
export function fmtDuration(sec) {
  sec = Math.max(0, Math.floor(sec || 0));
  const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d > 0) return d + ' ngày ' + hh + ' giờ';
  if (hh > 0) return hh + ' giờ ' + m + ' phút';
  return m + ' phút';
}
/* nhãn ngày "2026-09-26" -> "26/09" */
export function shortDay(label) {
  const m = /^(\d{4})-(\d{2})-(\d{2})(?: (\d{2}):00)?$/.exec(label || '');
  if (!m) {
    const mm = /^(\d{4})-(\d{2})$/.exec(label || '');
    return mm ? 'T' + Number(mm[2]) + '/' + mm[1].slice(2) : label;
  }
  if (m[4] !== undefined) return m[4] + 'h';
  return m[3] + '/' + m[2];
}
export function longDay(label) {
  const m = /^(\d{4})-(\d{2})-(\d{2})(?: (\d{2}):00)?$/.exec(label || '');
  if (!m) {
    const mm = /^(\d{4})-(\d{2})$/.exec(label || '');
    return mm ? 'Tháng ' + Number(mm[2]) + '/' + mm[1] : label;
  }
  const dow = ['Chủ nhật', 'Thứ hai', 'Thứ ba', 'Thứ tư', 'Thứ năm', 'Thứ sáu', 'Thứ bảy'][new Date(+m[1], +m[2] - 1, +m[3]).getDay()];
  const day = m[3] + '/' + m[2] + '/' + m[1];
  if (m[4] !== undefined) return m[4] + ':00 - ' + pad((+m[4] + 1) % 24) + ':00, ' + m[3] + '/' + m[2];
  return dow + ', ' + day;
}

export function expiryText(c, now) {
  if (!c.expires_at) return { text: 'Không giới hạn', cls: '' };
  now = now || Math.floor(Date.now() / 1000);
  const d = c.expires_at - now;
  if (d <= 0) return { text: 'Đã hết hạn', cls: 'red' };
  const days = Math.ceil(d / 86400);
  if (days <= 3) return { text: 'Còn ' + (d < 86400 ? Math.max(1, Math.floor(d / 3600)) + ' giờ' : days + ' ngày'), cls: 'amber' };
  return { text: 'Còn ' + days + ' ngày', cls: days <= 7 ? 'amber' : '' };
}

/* ---------- màu avatar ổn định theo tên ---------- */
const AV = [['#6366f1', '#8b5cf6'], ['#06b6d4', '#3b82f6'], ['#10b981', '#059669'], ['#f59e0b', '#f97316'], ['#ec4899', '#f43f5e'], ['#8b5cf6', '#d946ef'], ['#14b8a6', '#06b6d4'], ['#3b82f6', '#6366f1']];
export function avatar(name, status) {
  let hsh = 0;
  for (const ch of name || '?') hsh = (hsh * 31 + ch.codePointAt(0)) >>> 0;
  const [a, b] = AV[hsh % AV.length];
  const words = (name || '?').trim().split(/\s+/).filter(Boolean);
  const init = ((words[0] || '?')[0] + (words.length > 1 ? words[words.length - 1][0] : '')).toUpperCase();
  return h('div', { class: 'avatar', style: { background: `linear-gradient(135deg, ${a}, ${b})` } }, init,
    status ? h('span', { class: 'st ' + status }) : null);
}

/* ---------- thông báo nhanh (toast) ---------- */
export function toast(msg, type = 'ok', ms = 3800) {
  const root = document.getElementById('toasts');
  const ic = type === 'ok' ? 'check' : type === 'err' ? 'alert' : 'info';
  const t = h('div', { class: 'toast ' + type, role: 'status' }, h('div', { class: 'ic' }, icon(ic)), h('div', null, msg));
  root.appendChild(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 220); }, ms);
}

/* ---------- hộp thoại ---------- */
let modalStack = [];
export function modal({ title, sub, body, footer, size, onClose, dismissible = true }) {
  const root = h('div', { class: 'modal-root', role: 'dialog', 'aria-modal': 'true' });
  const bg = h('div', { class: 'modal-bg' });
  const box = h('div', { class: 'modal' + (size ? ' ' + size : '') });
  const close = () => {
    if (!root.isConnected) return;
    root.remove();
    modalStack = modalStack.filter((m) => m !== api);
    document.removeEventListener('keydown', onKey);
    if (onClose) onClose();
  };
  const onKey = (e) => { if (e.key === 'Escape' && dismissible && modalStack[modalStack.length - 1] === api) close(); };
  const head = h('div', { class: 'modal-h' },
    h('div', { style: { flex: 1, minWidth: 0 } }, h('h3', null, title), sub ? h('div', { class: 'sub' }, sub) : null),
    h('button', { class: 'icon-btn', 'aria-label': 'Đóng', onclick: close }, icon('x')));
  const b = h('div', { class: 'modal-b' });
  if (body) append(b, [body]);
  box.append(head, b);
  let f = null;
  if (footer) { f = h('div', { class: 'modal-f' }); append(f, [footer]); box.appendChild(f); }
  if (dismissible) bg.addEventListener('click', close);
  root.append(bg, box);
  document.body.appendChild(root);
  document.addEventListener('keydown', onKey);
  const api = { root, box, body: b, footer: f, close, setBody(n) { clear(b); append(b, [n]); } };
  modalStack.push(api);
  setTimeout(() => { const inp = box.querySelector('input:not([type=hidden]):not([type=checkbox]), textarea'); if (inp) inp.focus(); }, 50);
  return api;
}

export function confirmBox({ title, message, okText = 'Đồng ý', danger = false, icon: ic }) {
  return new Promise((resolve) => {
    let done = false;
    const m = modal({
      title,
      body: h('div', { class: 'row', style: { alignItems: 'flex-start', gap: '14px' } },
        h('div', { class: 'ic ' + (danger ? 'red' : 'indigo'), style: { width: '42px', height: '42px', borderRadius: '12px', display: 'grid', placeItems: 'center', flex: 'none' } }, icon(ic || (danger ? 'alert' : 'info'))),
        h('div', { class: 'text-2', style: { paddingTop: '2px' } }, message)),
      footer: [
        h('button', { class: 'btn', onclick: () => { done = true; m.close(); resolve(false); } }, 'Hủy'),
        h('button', { class: 'btn ' + (danger ? 'danger' : 'primary'), onclick: () => { done = true; m.close(); resolve(true); } }, okText),
      ],
      onClose: () => { if (!done) resolve(false); },
    });
  });
}

/* ---------- tiện ích khác ---------- */
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    const ta = h('textarea', { style: { position: 'fixed', opacity: '0' } });
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e2) { /* bỏ qua */ }
    ta.remove();
  }
  toast('Đã sao chép vào bộ nhớ tạm');
}

export function download(url) {
  const a = h('a', { href: url, download: '' });
  document.body.appendChild(a);
  a.click();
  a.remove();
}

export function busy(btn, on) {
  if (!btn) return;
  if (on) {
    btn.disabled = true;
    btn._old = btn.innerHTML;
    btn.innerHTML = '';
    btn.appendChild(icon('refresh', 'spin'));
    btn.appendChild(document.createTextNode(' Đang xử lý...'));
  } else {
    btn.disabled = false;
    if (btn._old !== undefined) btn.innerHTML = btn._old;
  }
}

export function field(label, input, hint) {
  return h('div', { class: 'field' }, label ? h('label', null, label) : null, input, hint ? h('div', { class: 'hint' }, hint) : null);
}

export function switchEl(checked, label, onchange) {
  const inp = h('input', { type: 'checkbox', checked, onchange: (e) => onchange && onchange(e.target.checked) });
  return h('label', { class: 'switch' }, inp, h('span', { class: 'track' }), label ? h('span', { class: 'txt' }, label) : null);
}

export function segmented(options, value, onchange) {
  const wrap = h('div', { class: 'seg', role: 'tablist' });
  const set = (v) => {
    for (const b of wrap.children) b.classList.toggle('on', b.dataset.v === String(v));
  };
  for (const [v, label] of options) {
    wrap.appendChild(h('button', { type: 'button', 'data-v': String(v), onclick: () => { set(v); onchange(v); } }, label));
  }
  set(value);
  wrap.set = set;
  return wrap;
}

export function emptyState(title, text, action) {
  return h('div', { class: 'empty' },
    h('div', { html: EMPTY_ART }),
    h('h3', null, title), h('div', null, text),
    action ? h('div', { style: { marginTop: '16px' } }, action) : null);
}

const EMPTY_ART = '<svg class="art" viewBox="0 0 150 110" fill="none"><rect x="20" y="18" width="110" height="74" rx="14" fill="currentColor" opacity=".08"/><rect x="34" y="34" width="46" height="8" rx="4" fill="currentColor" opacity=".18"/><rect x="34" y="50" width="82" height="6" rx="3" fill="currentColor" opacity=".12"/><rect x="34" y="62" width="64" height="6" rx="3" fill="currentColor" opacity=".12"/><circle cx="112" cy="30" r="14" fill="url(#eg)"/><path d="M106 30h12M112 24v12" stroke="#fff" stroke-width="3" stroke-linecap="round"/><defs><linearGradient id="eg" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#6366f1"/><stop offset="1" stop-color="#06b6d4"/></linearGradient></defs></svg>';

export function highlightConf(text) {
  /* tô màu cấu hình WireGuard - an toàn vì escape trước khi thêm thẻ */
  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return text.split('\n').map((line) => {
    if (/^\s*#/.test(line)) return '<span class="c">' + esc(line) + '</span>';
    if (/^\s*\[.*\]\s*$/.test(line)) return '<span class="s">' + esc(line) + '</span>';
    const m = /^(\s*[A-Za-z]+)(\s*=\s*)(.*)$/.exec(line);
    if (m) return '<span class="k">' + esc(m[1]) + '</span>' + esc(m[2]) + esc(m[3]);
    return esc(line);
  }).join('\n');
}

export function pwStrength(pw) {
  let s = 0;
  if (!pw) return 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
  if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) s++;
  return Math.max(1, Math.min(4, s));
}
