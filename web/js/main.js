/*
 * Tuấn WireGuard - khung ứng dụng: đăng nhập, bố cục, điều hướng
 * Tác giả: Tuandethuong
 */
import { get, post, setUnauthorizedHandler } from './api.js';
import { h, icon, clear, toast, add } from './ui.js';
import { renderLogin } from './pages/login.js';
import * as dashboard from './pages/dashboard.js';
import * as clients from './pages/clients.js';
import * as stats from './pages/stats.js';
import * as logs from './pages/logs.js';
import * as settings from './pages/settings.js';
import * as about from './pages/about.js';

const ROUTES = [
  { key: 'tong-quan', title: 'Tổng quan', sub: 'Tình trạng máy chủ và lưu lượng theo thời gian thực', icon: 'dashboard', page: dashboard, group: 'Quản lý' },
  { key: 'nguoi-dung', title: 'Người dùng', sub: 'Quản lý thiết bị kết nối VPN', icon: 'users', page: clients, group: 'Quản lý' },
  { key: 'thong-ke', title: 'Thống kê', sub: 'Dung lượng sử dụng theo thời gian và theo người dùng', icon: 'chart', page: stats, group: 'Quản lý' },
  { key: 'nhat-ky', title: 'Nhật ký', sub: 'Lịch sử thao tác và sự kiện hệ thống', icon: 'logs', page: logs, group: 'Hệ thống' },
  { key: 'cai-dat', title: 'Cài đặt', sub: 'Cấu hình máy chủ WireGuard, bảo mật và sao lưu', icon: 'settings', page: settings, group: 'Hệ thống' },
  { key: 'gioi-thieu', title: 'Giới thiệu', sub: 'Phiên bản, tác giả và lịch sử thay đổi', icon: 'info', page: about, group: 'Hệ thống' },
];

export const state = { info: null, session: null };

let cleanup = null;
let statusTimer = null;
let layout = null;

function setTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('twg-theme', t); } catch (e) { /* bỏ qua */ }
  window.dispatchEvent(new Event('themechange'));
}

function themeButton() {
  const cur = () => document.documentElement.getAttribute('data-theme');
  const btn = h('button', { class: 'btn sm', title: 'Đổi giao diện sáng/tối' });
  const paint = () => { clear(btn); add(btn, icon(cur() === 'dark' ? 'sun' : 'moon'), cur() === 'dark' ? 'Sáng' : 'Tối'); };
  btn.addEventListener('click', () => { setTheme(cur() === 'dark' ? 'light' : 'dark'); paint(); });
  paint();
  return btn;
}

async function logout() {
  try { await post('/api/logout'); } catch (e) { /* bỏ qua */ }
  state.session = null;
  showLogin();
}

function buildLayout() {
  const nav = h('nav', { class: 'nav' });
  let group = '';
  for (const r of ROUTES) {
    if (r.group !== group) { group = r.group; nav.appendChild(h('div', { class: 'nav-label' }, group)); }
    nav.appendChild(h('a', { href: '#/' + r.key, 'data-key': r.key }, icon(r.icon), h('span', null, r.title),
      r.key === 'nguoi-dung' ? h('span', { class: 'badge green hidden', id: 'navOnline', title: 'Đang online' }) : null));
  }
  const pill = h('div', { class: 'server-pill' }, h('span', { class: 'dot', id: 'srvDot' }),
    h('div', { style: { minWidth: 0 } }, h('b', { id: 'srvTitle' }, 'Đang kiểm tra...'), h('span', { id: 'srvSub' }, 'WireGuard')));
  const sidebar = h('aside', { class: 'sidebar' },
    h('div', { class: 'brand' }, h('img', { src: '/logo.svg', alt: '' }),
      h('div', null, h('div', { class: 'name' }, 'Tuấn WireGuard'), h('div', { class: 'ver' }, 'v' + state.info.version + ' • ' + state.info.author,
        state.info.demo ? h('span', { class: 'badge amber', style: { height: '18px', marginLeft: '6px', fontSize: '10px' } }, 'DEMO') : null))),
    nav,
    h('div', { class: 'sidebar-foot' }, pill,
      h('div', { class: 'sidebar-actions' }, themeButton(), h('button', { class: 'btn sm', onclick: logout, title: 'Đăng xuất' }, icon('logout'), 'Thoát'))));
  const title = h('h1', null, '');
  const sub = h('div', { class: 'sub' }, '');
  const actions = h('div', { class: 'row' });
  const topbar = h('header', { class: 'topbar' },
    h('button', { class: 'icon-btn menu-btn', 'aria-label': 'Menu', onclick: () => document.body.classList.toggle('nav-open') }, icon('menu')),
    h('div', { style: { minWidth: 0 } }, title, sub), h('div', { class: 'spacer' }), actions);
  const content = h('main', { class: 'content', id: 'content' });
  const root = h('div', { class: 'app' }, sidebar,
    h('div', { class: 'backdrop-nav', onclick: () => document.body.classList.remove('nav-open') }),
    h('div', { class: 'main' }, topbar, content));
  return { root, nav, title, sub, actions, content };
}

async function refreshStatus() {
  try {
    const d = await get('/api/live');
    const dot = document.getElementById('srvDot');
    if (!dot) return;
    const online = d.clients.filter((c) => c.online).length;
    dot.className = 'dot ' + (d.up ? 'on' : 'bad');
    document.getElementById('srvTitle').textContent = d.up ? 'WireGuard đang chạy' : 'WireGuard đã dừng';
    document.getElementById('srvSub').textContent = online + ' thiết bị đang online';
    const b = document.getElementById('navOnline');
    if (b) { b.textContent = online; b.classList.toggle('hidden', online === 0); }
  } catch (e) { /* bỏ qua */ }
}

function route() {
  if (!state.session || !layout) return;
  const key = (location.hash.replace(/^#\/?/, '').split('?')[0]) || 'tong-quan';
  const r = ROUTES.find((x) => x.key === key) || ROUTES[0];
  if (cleanup) { try { cleanup(); } catch (e) { /* bỏ qua */ } cleanup = null; }
  for (const a of layout.nav.querySelectorAll('a')) a.classList.toggle('active', a.dataset.key === r.key);
  layout.title.textContent = r.title;
  layout.sub.textContent = r.sub;
  clear(layout.actions);
  clear(layout.content);
  document.title = r.title + ' • Tuấn WireGuard';
  document.body.classList.remove('nav-open');
  const page = h('div', { class: 'page-enter' });
  layout.content.appendChild(page);
  const ctx = {
    setActions: (...nodes) => { clear(layout.actions); for (const n of nodes.flat()) if (n) layout.actions.appendChild(n); },
    refreshStatus,
    state,
  };
  try {
    cleanup = r.page.mount(page, ctx) || null;
  } catch (e) {
    console.error(e);
    page.appendChild(h('div', { class: 'alert err' }, icon('alert'), 'Lỗi hiển thị trang: ' + e.message));
  }
  window.scrollTo(0, 0);
}

function showApp() {
  const app = document.getElementById('app');
  clear(app);
  layout = buildLayout();
  app.appendChild(layout.root);
  route();
  refreshStatus();
  clearInterval(statusTimer);
  statusTimer = setInterval(refreshStatus, 8000);
}

function showLogin() {
  if (cleanup) { try { cleanup(); } catch (e) { /* bỏ qua */ } cleanup = null; }
  clearInterval(statusTimer);
  layout = null;
  document.querySelectorAll('.modal-root').forEach((m) => m.remove());
  const app = document.getElementById('app');
  clear(app);
  app.appendChild(renderLogin(state.info, async () => {
    state.session = await get('/api/session');
    if (!location.hash) location.hash = '#/tong-quan';
    showApp();
  }));
}

async function boot() {
  try {
    state.info = await get('/api/public/info');
  } catch (e) {
    state.info = { version: '?', author: 'Tuandethuong', app: 'Tuấn WireGuard' };
  }
  try { state.session = await get('/api/session'); } catch (e) { state.session = null; }
  setUnauthorizedHandler(() => {
    if (state.session) toast('Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại', 'info');
    state.session = null;
    showLogin();
  });
  const boot = document.getElementById('boot');
  if (boot) { boot.style.opacity = '0'; setTimeout(() => boot.remove(), 300); }
  if (state.session) showApp();
  else showLogin();
}

window.addEventListener('hashchange', route);
boot();
