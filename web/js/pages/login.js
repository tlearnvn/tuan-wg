/*
 * Tuấn WireGuard - trang đăng nhập
 * Tác giả: Tuandethuong
 */
import { post } from '../api.js';
import { h, icon, add } from '../ui.js';

const NET_ART = `<svg class="net" viewBox="0 0 420 420" fill="none">
  <defs><radialGradient id="ng" cx="50%" cy="50%" r="50%"><stop offset="0" stop-color="#a5b4fc"/><stop offset="1" stop-color="#a5b4fc" stop-opacity="0"/></radialGradient></defs>
  <g stroke="#a5b4fc" stroke-opacity=".35" stroke-width="1.4">
    <path d="M210 210L90 110M210 210L330 90M210 210L360 250M210 210L270 350M210 210L110 310M90 110L40 200M330 90L400 160M360 250L400 160M270 350L360 250M110 310L40 200M110 310L270 350M90 110L200 40L330 90"/>
  </g>
  <circle cx="210" cy="210" r="46" fill="url(#ng)" opacity=".5"/>
  <circle cx="210" cy="210" r="16" fill="#fff"/><circle cx="210" cy="210" r="7" fill="#8b5cf6"/>
  <g fill="#c7d2fe"><circle cx="90" cy="110" r="8"/><circle cx="330" cy="90" r="9"/><circle cx="360" cy="250" r="8"/><circle cx="270" cy="350" r="9"/><circle cx="110" cy="310" r="8"/><circle cx="40" cy="200" r="5"/><circle cx="400" cy="160" r="5"/><circle cx="200" cy="40" r="6"/></g>
</svg>`;

export function renderLogin(info, onSuccess) {
  const user = h('input', { class: 'input', name: 'username', autocomplete: 'username', placeholder: 'admin', required: true });
  const pass = h('input', { class: 'input', name: 'password', type: 'password', autocomplete: 'current-password', placeholder: '••••••••', required: true });
  const otp = h('input', { class: 'input mono', name: 'otp', inputmode: 'numeric', autocomplete: 'one-time-code', placeholder: '6 chữ số trong ứng dụng xác thực', maxlength: 7 });
  const err = h('div', { class: 'alert err hidden' });
  const btn = h('button', { class: 'btn primary lg block', type: 'submit' }, icon('lock'), 'Đăng nhập');
  const eye = h('button', { class: 'icon-btn suffix', type: 'button', 'aria-label': 'Hiện mật khẩu', onclick: () => {
    pass.type = pass.type === 'password' ? 'text' : 'password';
    eye.innerHTML = '';
    eye.appendChild(icon(pass.type === 'password' ? 'eye' : 'eyeOff'));
  } }, icon('eye'));

  const form = h('form', {
    onsubmit: async (e) => {
      e.preventDefault();
      err.classList.add('hidden');
      btn.disabled = true;
      try {
        await post('/api/login', { username: user.value.trim(), password: pass.value, otp: otp.value.trim() });
        await onSuccess();
      } catch (ex) {
        err.textContent = '';
        add(err, icon('alert'), h('div', null, ex.message));
        err.classList.remove('hidden');
        pass.select();
      } finally {
        btn.disabled = false;
      }
    },
  },
  err,
  h('div', { class: 'field' }, h('label', null, 'Tên đăng nhập'), h('div', { class: 'input-group' }, icon('user'), user)),
  h('div', { class: 'field' }, h('label', null, 'Mật khẩu'), h('div', { class: 'input-group' }, icon('key'), pass, eye)),
  info.totp_required ? h('div', { class: 'field' }, h('label', null, 'Mã xác thực 2 lớp'), h('div', { class: 'input-group' }, icon('shieldCheck'), otp)) : null,
  btn);

  const feats = [
    ['users', 'Quản lý người dùng'], ['qr', 'Mã QR cho điện thoại'],
    ['chart', 'Thống kê dung lượng'], ['shieldCheck', 'Bảo mật 2 lớp'],
  ];
  return h('div', { class: 'login' },
    h('div', { class: 'login-art' },
      h('div', { html: NET_ART }),
      h('div', { class: 'brand' }, h('img', { src: '/logo.svg', alt: '' }), h('div', null, h('div', { class: 'name' }, 'Tuấn WireGuard'), h('div', { class: 'ver' }, 'Phiên bản ' + info.version))),
      h('h2', null, 'Quản lý VPN ', h('span', null, 'WireGuard'), ' dễ dàng, nhanh và an toàn'),
      h('p', null, 'Tạo tài khoản VPN trong vài giây, xuất cấu hình bằng mã QR, theo dõi dung lượng từng người dùng theo thời gian thực.'),
      h('div', { class: 'feats' }, feats.map(([i, t]) => h('div', { class: 'feat' }, icon(i), t))),
      h('div', { class: 'foot' }, '© ' + new Date().getFullYear() + ' ' + info.author + ' • Mã nguồn mở')),
    h('div', { class: 'login-form' },
      h('div', { class: 'login-card' },
        h('div', { class: 'brand', style: { padding: '0 0 26px' } }, h('img', { src: '/logo.svg', alt: '' }),
          h('div', null, h('div', { class: 'name', style: { color: 'var(--text)' } }, 'Tuấn WireGuard'), h('div', { class: 'ver', style: { color: 'var(--muted)' } }, 'v' + info.version))),
        h('h1', null, 'Xin chào! 👋'),
        h('div', { class: 'lead' }, 'Đăng nhập để quản lý máy chủ VPN của bạn.'),
        info.demo ? h('div', { class: 'alert info', style: { marginBottom: '16px' } }, icon('info'), h('div', null, 'Chế độ demo - tài khoản ', h('b', null, 'admin'), ' / mật khẩu ', h('b', null, 'admin'))) : null,
        form,
        h('div', { class: 'foot' }, 'Quên mật khẩu? Chạy ', h('code', null, 'sudo tuan-wg passwd'), ' trên máy chủ.', h('br'), 'Thiết kế bởi ', h('b', null, info.author)))));
}
