/*
 * Tuấn WireGuard - trang Cài đặt
 * Tác giả: Tuandethuong
 */
import { get, post, put, api } from '../api.js';
import { h, icon, clear, toast, modal, confirmBox, busy, field, switchEl, copyText, download, timeAgo, fmtDateTime, pwStrength, add } from '../ui.js';

const TABS = [['wg', 'server', 'WireGuard'], ['web', 'globe', 'Giao diện web'], ['account', 'shieldCheck', 'Tài khoản & bảo mật'], ['backup', 'archive', 'Sao lưu & khôi phục']];

function tzOptions(cur) {
  const named = { 420: 'Việt Nam, Thái Lan, Indonesia (WIB)', 480: 'Singapore, Malaysia, Trung Quốc', 540: 'Nhật Bản, Hàn Quốc', 0: 'Giờ quốc tế (UTC)', 60: 'Pháp, Đức (giờ chuẩn)', 330: 'Ấn Độ', '-300': 'New York (giờ chuẩn)', '-480': 'Los Angeles (giờ chuẩn)', 600: 'Sydney (giờ chuẩn)' };
  const opts = [];
  for (let m = -720; m <= 840; m += 30) {
    if (m % 60 !== 0 && !named[m]) continue;
    const sign = m >= 0 ? '+' : '-', a = Math.abs(m);
    const lbl = 'UTC' + sign + Math.floor(a / 60) + (a % 60 ? ':' + String(a % 60).padStart(2, '0') : '') + (named[m] ? ' - ' + named[m] : '');
    opts.push(h('option', { value: m, selected: m === cur }, lbl));
  }
  return opts;
}

function uaLabel(ua) {
  if (!ua) return 'Không rõ thiết bị';
  const b = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : /curl/i.test(ua) ? 'curl' : 'Trình duyệt';
  const o = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : '';
  return b + (o ? ' trên ' + o : '');
}

export function mount(el, ctx) {
  let tab = 'wg', s = null, alive = true;
  const tabBar = h('div', { class: 'tabs' });
  const pane = h('div');
  for (const [k, ic, label] of TABS) tabBar.appendChild(h('button', { 'data-k': k, onclick: () => show(k) }, icon(ic), label));
  add(el, tabBar, pane);

  async function load() {
    try { s = await get('/api/settings'); } catch (e) { toast(e.message, 'err'); return false; }
    return true;
  }

  async function show(k) {
    tab = k;
    for (const b of tabBar.children) b.classList.toggle('on', b.dataset.k === k);
    clear(pane);
    pane.appendChild(h('div', { class: 'card skeleton', style: { height: '300px' } }));
    if (!s && !(await load())) return;
    if (!alive || tab !== k) return;
    clear(pane);
    ({ wg: wgTab, web: webTab, account: accountTab, backup: backupTab })[k]();
  }

  async function save(payload, btn, msg) {
    busy(btn, true);
    try {
      const r = await put('/api/settings', payload);
      await load();
      toast(msg || 'Đã lưu cài đặt');
      if (r.warning) toast('Cảnh báo: ' + r.warning, 'err', 8000);
      ctx.refreshStatus();
      return r;
    } catch (e) { toast(e.message, 'err', 6000); return null; } finally { busy(btn, false); }
  }

  /* ---------- WireGuard ---------- */
  function wgTab() {
    const inp = (k, attrs) => h('input', Object.assign({ class: 'input', value: s[k] ?? '' }, attrs || {}));
    const endpoint = inp('endpoint', { placeholder: 'vpn.tenmien.vn hoặc IP công khai' });
    const port = inp('listen_port', { type: 'number', min: 1, max: 65535 });
    const address = inp('address', { class: 'input mono' });
    const address6 = inp('address6', { class: 'input mono', placeholder: 'fd42:42:42::1/64' });
    const dns = inp('dns', { class: 'input mono', placeholder: '1.1.1.1, 8.8.8.8' });
    const allowed = inp('allowed_ips', { class: 'input mono' });
    const ka = inp('keepalive', { type: 'number', min: 0, max: 3600 });
    const mtu = h('input', { class: 'input', type: 'number', min: 0, max: 9000, value: s.mtu || '', placeholder: 'Tự động (thường 1420)' });
    const wan = inp('wan_interface', { class: 'input mono', placeholder: 'Tự phát hiện: ' + (s.detected_wan || 'eth0') });
    const up = h('textarea', { class: 'textarea', rows: 4, placeholder: s.auto_post_up }, s.post_up);
    const down = h('textarea', { class: 'textarea', rows: 4, placeholder: s.auto_post_down }, s.post_down);
    const tz = h('select', { class: 'select' }, tzOptions(s.tz_offset));
    let ipv6 = s.ipv6, iso = s.client_isolation, psk = s.use_psk;
    const v6wrap = h('div', { class: ipv6 ? '' : 'hidden' }, field('Dải IPv6', address6, 'Địa chỉ IPv6 nội bộ (ULA) của máy chủ'));
    const detect = h('button', { class: 'btn', type: 'button', onclick: async () => {
      busy(detect, true);
      try { const r = await get('/api/detect-ip'); if (r.public_ip) { endpoint.value = r.public_ip; toast('Đã phát hiện IP công khai: ' + r.public_ip); } else toast('Không phát hiện được IP công khai. IP nội bộ: ' + (r.local_ip || '?'), 'err'); } catch (e) { toast(e.message, 'err'); } finally { busy(detect, false); }
    } }, icon('globe'), 'Tự phát hiện');
    const saveBtn = h('button', { class: 'btn primary' }, icon('check'), 'Lưu cài đặt');
    const restartBtn = h('button', { class: 'btn' }, icon('refresh'), 'Khởi động lại WireGuard');
    saveBtn.addEventListener('click', async () => {
      if (address.value.trim() !== s.address && !(await confirmBox({ title: 'Đổi dải mạng VPN?', message: 'Tất cả người dùng sẽ được cấp lại địa chỉ IP trong dải mới. Mọi thiết bị cần tải lại file cấu hình / quét lại mã QR.', okText: 'Tiếp tục', danger: true }))) return;
      await save({
        endpoint: endpoint.value.trim(), listen_port: Number(port.value), address: address.value.trim(), ipv6, address6: address6.value.trim(),
        dns: dns.value.trim(), allowed_ips: allowed.value.trim(), keepalive: Number(ka.value || 0), mtu: Number(mtu.value || 0),
        wan_interface: wan.value.trim(), post_up: up.value.trim(), post_down: down.value.trim(), client_isolation: iso, use_psk: psk, tz_offset: Number(tz.value),
      }, saveBtn);
    });
    restartBtn.addEventListener('click', async () => {
      if (!await confirmBox({ title: 'Khởi động lại WireGuard?', message: 'Các thiết bị sẽ mất kết nối vài giây rồi tự kết nối lại.', okText: 'Khởi động lại', icon: 'refresh' })) return;
      busy(restartBtn, true);
      try { await post('/api/wireguard/restart'); toast('Đã khởi động lại WireGuard'); ctx.refreshStatus(); } catch (e) { toast(e.message, 'err', 7000); } finally { busy(restartBtn, false); }
    });
    add(pane, 
      h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('div', null, h('h3', null, 'Máy chủ'), h('div', { class: 'sub' }, 'Địa chỉ mà thiết bị dùng để kết nối tới VPN'))),
        h('div', { class: 'card-b form-grid' },
          h('div', { class: 'full' }, field('Endpoint (tên miền hoặc IP công khai)', h('div', { class: 'row' }, endpoint, detect), 'Được ghi vào file cấu hình của người dùng. Có thể thêm cổng riêng, ví dụ: vpn.tenmien.vn:443')),
          field('Cổng lắng nghe (UDP)', port, 'Mặc định 51820. Nhớ mở cổng này trên tường lửa/nhà cung cấp VPS'),
          field('Dải mạng VPN (IPv4)', address, 'Địa chỉ máy chủ/prefix, ví dụ 10.8.0.1/24 (tối đa 253 người dùng)'),
          h('div', { class: 'full' }, switchEl(ipv6, 'Bật IPv6 trong đường hầm', (v) => { ipv6 = v; v6wrap.classList.toggle('hidden', !v); })),
          h('div', { class: 'full' }, v6wrap))),
      h('div', { class: 'card', style: { marginTop: '18px' } }, h('div', { class: 'card-h' }, h('div', null, h('h3', null, 'Mặc định cho người dùng'), h('div', { class: 'sub' }, 'Áp dụng cho file cấu hình tải về (có thể ghi đè từng người dùng)'))),
        h('div', { class: 'card-b form-grid' },
          field('DNS', dns, 'Máy chủ DNS thiết bị dùng khi bật VPN'),
          field('AllowedIPs', allowed, '0.0.0.0/0, ::/0 = toàn bộ lưu lượng đi qua VPN'),
          field('Persistent Keepalive (giây)', ka, '25 giây giúp giữ kết nối qua NAT. 0 = tắt'),
          field('MTU', mtu, 'Để trống nếu không chắc chắn'),
          h('div', { class: 'full' }, switchEl(psk, 'Tạo khóa chia sẻ trước (PresharedKey) cho người dùng mới - tăng bảo mật', (v) => { psk = v; })))),
      h('div', { class: 'card', style: { marginTop: '18px' } }, h('div', { class: 'card-h' }, h('div', null, h('h3', null, 'Mạng & tường lửa'), h('div', { class: 'sub' }, 'Chuyển tiếp gói tin và NAT ra Internet'))),
        h('div', { class: 'card-b form-grid' },
          field('Card mạng WAN', wan, 'Card mạng ra Internet để NAT (MASQUERADE)'),
          field('Múi giờ thống kê', tz, 'Dùng để tính dung lượng theo ngày/tháng'),
          h('div', { class: 'full' }, switchEl(iso, 'Chặn các thiết bị trong VPN liên lạc với nhau (cách ly client)', (v) => { iso = v; })),
          h('div', { class: 'form-section' }, 'Nâng cao'),
          h('div', { class: 'full' }, h('div', { class: 'alert warn' }, icon('alert'), h('div', null, 'PostUp/PostDown là lệnh shell chạy với quyền root khi bật/tắt WireGuard. ', h('b', null, 'Để trống để dùng quy tắc tự động'), ' (khuyến nghị).'))),
          h('div', { class: 'full' }, field('PostUp', up)),
          h('div', { class: 'full' }, field('PostDown', down)))),
      h('div', { class: 'card', style: { marginTop: '18px' } }, h('div', { class: 'card-h' }, h('h3', null, 'Thông tin')),
        h('div', { class: 'card-b' }, h('dl', { class: 'kv' },
          h('dt', null, 'Interface'), h('dd', { class: 'mono' }, s.interface),
          h('dt', null, 'Khóa công khai máy chủ'), h('dd', { class: 'mono row', style: { gap: '6px' } }, s.public_key, h('button', { class: 'icon-btn', onclick: () => copyText(s.public_key) }, icon('copy'))),
          h('dt', null, 'IP nội bộ'), h('dd', { class: 'mono' }, s.local_ip || '—'),
          h('dt', null, 'Thư mục dữ liệu'), h('dd', { class: 'mono' }, s.data_dir),
          h('dt', null, 'Cấu hình WireGuard'), h('dd', { class: 'mono' }, s.wg_dir + '/' + s.interface + '.conf'))),
        h('div', { class: 'card-f' }, restartBtn, saveBtn)));
  }

  /* ---------- Web ---------- */
  function webTab() {
    const listen = h('input', { class: 'input mono', value: s.web_listen });
    const port = h('input', { class: 'input', type: 'number', min: 1, max: 65535, value: s.web_port });
    const hours = h('input', { class: 'input', type: 'number', min: 1, max: 8760, value: s.session_hours });
    const saveBtn = h('button', { class: 'btn primary' }, icon('check'), 'Lưu cài đặt');
    saveBtn.addEventListener('click', async () => {
      const newPort = Number(port.value), changed = newPort !== s.web_port || listen.value.trim() !== s.web_listen;
      if (changed && !(await confirmBox({ title: 'Khởi động lại giao diện web?', message: 'Giao diện web sẽ khởi động lại tại địa chỉ/cổng mới. Hãy chắc chắn cổng mới đã được mở trên tường lửa.', okText: 'Lưu & khởi động lại' }))) return;
      const r = await save({ web_listen: listen.value.trim(), web_port: newPort, session_hours: Number(hours.value) }, saveBtn);
      if (r && r.restart_web) {
        const url = location.protocol + '//' + location.hostname + ':' + r.web_port + '/';
        modal({ title: 'Đang khởi động lại...', dismissible: false, body: h('div', { class: 'col', style: { alignItems: 'center', textAlign: 'center', padding: '10px 0' } }, icon('refresh', 'spin'), h('div', null, 'Đang chuyển tới ', h('b', { class: 'mono' }, url))) });
        setTimeout(() => { location.href = url; }, 3500);
      }
    });
    add(pane, h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('div', null, h('h3', null, 'Giao diện web'), h('div', { class: 'sub' }, 'Địa chỉ truy cập trang quản trị này'))),
      h('div', { class: 'card-b form-grid' },
        field('Địa chỉ lắng nghe', listen, '0.0.0.0 = mọi địa chỉ. Đặt IP của wg0 (vd 10.8.0.1) để chỉ truy cập được khi đã kết nối VPN'),
        field('Cổng web (TCP)', port, 'Mặc định 51821'),
        field('Thời gian ghi nhớ đăng nhập (giờ)', hours, 'Phiên tự gia hạn khi bạn còn sử dụng. 168 giờ = 7 ngày'),
        h('div', { class: 'full' }, h('div', { class: 'alert info' }, icon('shield'), h('div', null, h('b', null, 'Khuyến nghị bảo mật: '), 'dùng HTTPS bằng reverse proxy (Caddy/Nginx) hoặc chỉ cho truy cập qua VPN. Xem hướng dẫn trong tài liệu trên GitHub.')))),
      h('div', { class: 'card-f' }, saveBtn)));
  }

  /* ---------- Tài khoản ---------- */
  async function accountTab() {
    const sess = await get('/api/session');
    const user = h('input', { class: 'input', value: sess.username, autocomplete: 'username' });
    const upw = h('input', { class: 'input', type: 'password', placeholder: 'Mật khẩu hiện tại', autocomplete: 'current-password' });
    const userBtn = h('button', { class: 'btn' }, 'Đổi tên đăng nhập');
    userBtn.addEventListener('click', async () => {
      busy(userBtn, true);
      try { await post('/api/account/username', { username: user.value.trim(), password: upw.value }); toast('Đã đổi tên đăng nhập'); upw.value = ''; } catch (e) { toast(e.message, 'err'); } finally { busy(userBtn, false); }
    });
    const cur = h('input', { class: 'input', type: 'password', autocomplete: 'current-password' });
    const nw = h('input', { class: 'input', type: 'password', autocomplete: 'new-password' });
    const nw2 = h('input', { class: 'input', type: 'password', autocomplete: 'new-password' });
    const meter = h('div', { class: 'pw-meter' }, h('i'), h('i'), h('i'), h('i'));
    nw.addEventListener('input', () => { meter.className = 'pw-meter s' + (nw.value ? pwStrength(nw.value) : 0); });
    const pwBtn = h('button', { class: 'btn primary' }, icon('lock'), 'Đổi mật khẩu');
    pwBtn.addEventListener('click', async () => {
      if (nw.value !== nw2.value) { toast('Mật khẩu nhập lại không khớp', 'err'); return; }
      busy(pwBtn, true);
      try { await post('/api/account/password', { current: cur.value, new: nw.value }); toast('Đã đổi mật khẩu. Các phiên đăng nhập khác đã bị đăng xuất.'); cur.value = nw.value = nw2.value = ''; loadSessions(); } catch (e) { toast(e.message, 'err'); } finally { busy(pwBtn, false); }
    });

    const tfa = h('div');
    const renderTfa = (on) => {
      clear(tfa);
      add(tfa, h('div', { class: 'row', style: { alignItems: 'flex-start', gap: '14px' } },
        h('div', { class: 'ic ' + (on ? 'green' : 'amber'), style: { width: '46px', height: '46px', borderRadius: '14px', display: 'grid', placeItems: 'center', flex: 'none' } }, icon(on ? 'shieldCheck' : 'shield')),
        h('div', { style: { flex: 1 } }, h('b', null, on ? 'Đang bật xác thực 2 lớp' : 'Chưa bật xác thực 2 lớp'),
          h('div', { class: 'muted', style: { fontSize: '13px' } }, on ? 'Khi đăng nhập cần nhập mã 6 số từ ứng dụng Google Authenticator / Microsoft Authenticator / Authy.' : 'Bảo vệ tài khoản quản trị bằng mã 6 số thay đổi mỗi 30 giây từ điện thoại.')),
        on ? h('button', { class: 'btn danger', onclick: disable2fa }, 'Tắt 2FA') : h('button', { class: 'btn primary', onclick: setup2fa }, icon('shieldCheck'), 'Bật 2FA')));
    };
    renderTfa(sess.totp_enabled);

    async function setup2fa() {
      let r;
      try { r = await post('/api/account/2fa/setup'); } catch (e) { toast(e.message, 'err'); return; }
      const code = h('input', { class: 'input mono', inputmode: 'numeric', placeholder: '123456', maxlength: 7, style: { fontSize: '18px', letterSpacing: '4px', textAlign: 'center' } });
      const ok = h('button', { class: 'btn primary' }, icon('check'), 'Xác nhận & bật');
      const img = h('img', { src: 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(r.qr_svg), alt: 'QR 2FA' });
      const m = modal({
        title: 'Bật xác thực 2 lớp', sub: 'Quét mã bằng ứng dụng xác thực trên điện thoại', size: 'lg',
        body: h('div', { class: 'conf-grid' }, h('div', { class: 'qr-box' }, img),
          h('ol', { class: 'steps', style: { padding: 0, margin: 0 } },
            h('li', null, h('div', null, 'Cài ', h('b', null, 'Google Authenticator'), ', ', h('b', null, 'Microsoft Authenticator'), ' hoặc ', h('b', null, 'Authy'), ' trên điện thoại.')),
            h('li', null, h('div', null, 'Quét mã QR bên cạnh. Nếu không quét được, nhập mã: ', h('div', { class: 'row', style: { marginTop: '6px' } }, h('code', { style: { wordBreak: 'break-all' } }, r.secret), h('button', { class: 'icon-btn', onclick: () => copyText(r.secret) }, icon('copy'))))),
            h('li', null, h('div', { style: { flex: 1 } }, 'Nhập mã 6 số đang hiển thị để xác nhận:', h('div', { style: { marginTop: '8px' } }, code))))),
        footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Hủy'), ok],
      });
      ok.addEventListener('click', async () => {
        busy(ok, true);
        try { await post('/api/account/2fa/enable', { code: code.value }); m.close(); toast('Đã bật xác thực 2 lớp'); renderTfa(true); } catch (e) { toast(e.message, 'err'); } finally { busy(ok, false); }
      });
    }

    async function disable2fa() {
      const pw = h('input', { class: 'input', type: 'password', placeholder: 'Mật khẩu hiện tại' });
      const ok = h('button', { class: 'btn danger' }, 'Tắt 2FA');
      const m = modal({ title: 'Tắt xác thực 2 lớp?', body: h('div', { class: 'col' }, h('div', { class: 'text-2' }, 'Nhập mật khẩu để xác nhận.'), pw), footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Hủy'), ok] });
      ok.addEventListener('click', async () => {
        try { await post('/api/account/2fa/disable', { password: pw.value }); m.close(); toast('Đã tắt xác thực 2 lớp'); renderTfa(false); } catch (e) { toast(e.message, 'err'); }
      });
    }

    const sessBody = h('tbody');
    async function loadSessions() {
      try {
        const d = await get('/api/sessions');
        clear(sessBody);
        for (const x of d.sessions) {
          sessBody.appendChild(h('tr', null,
            h('td', null, h('div', { class: 'row' }, icon(/Android|iPhone|iPad/.test(x.ua) ? 'phone' : 'monitor'), h('b', null, uaLabel(x.ua)), x.current ? h('span', { class: 'badge green' }, 'Phiên này') : null)),
            h('td', { class: 'mono' }, x.ip), h('td', null, timeAgo(x.last_seen)), h('td', { class: 'muted' }, fmtDateTime(x.created))));
        }
      } catch (e) { toast(e.message, 'err'); }
    }
    const revoke = h('button', { class: 'btn', onclick: async () => {
      try { const r = await post('/api/sessions/revoke-others'); toast('Đã đăng xuất ' + r.count + ' phiên khác'); loadSessions(); } catch (e) { toast(e.message, 'err'); }
    } }, icon('logout'), 'Đăng xuất các phiên khác');
    loadSessions();

    add(pane, 
      h('div', { class: 'dash-grid', style: { marginTop: 0, gridTemplateColumns: 'minmax(0,1fr) minmax(0,1fr)' } },
        h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'Đổi mật khẩu')),
          h('div', { class: 'card-b col', style: { gap: '14px' } }, field('Mật khẩu hiện tại', cur), h('div', { class: 'field' }, h('label', null, 'Mật khẩu mới'), nw, meter, h('div', { class: 'hint' }, 'Tối thiểu 8 ký tự, nên có chữ hoa, số và ký tự đặc biệt')), field('Nhập lại mật khẩu mới', nw2)),
          h('div', { class: 'card-f' }, pwBtn)),
        h('div', { class: 'col', style: { gap: '18px' } },
          h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'Xác thực 2 lớp (2FA)')), h('div', { class: 'card-b' }, tfa)),
          h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'Tên đăng nhập')),
            h('div', { class: 'card-b col', style: { gap: '12px' } }, field('Tên đăng nhập mới', user), upw), h('div', { class: 'card-f' }, userBtn)))),
      h('div', { class: 'card', style: { marginTop: '18px' } }, h('div', { class: 'card-h' }, h('div', null, h('h3', null, 'Phiên đăng nhập'), h('div', { class: 'sub' }, 'Các thiết bị đang đăng nhập trang quản trị')), h('div', { class: 'spacer' }), revoke),
        h('div', { class: 'card-b' }, h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
          h('thead', null, h('tr', null, h('th', null, 'Thiết bị'), h('th', null, 'Địa chỉ IP'), h('th', null, 'Hoạt động'), h('th', null, 'Đăng nhập lúc'))), sessBody)))));
  }

  /* ---------- Sao lưu ---------- */
  function backupTab() {
    const file = h('input', { type: 'file', accept: '.json,application/json', class: 'hidden' });
    const restoreBtn = h('button', { class: 'btn danger', onclick: () => file.click() }, icon('upload'), 'Chọn file & khôi phục');
    file.addEventListener('change', async () => {
      const f = file.files[0];
      file.value = '';
      if (!f) return;
      const ok = await confirmBox({ title: 'Khôi phục dữ liệu?', message: h('span', null, 'Toàn bộ người dùng, cài đặt và tài khoản quản trị hiện tại sẽ bị ', h('b', null, 'thay thế'), ' bằng dữ liệu trong file ', h('b', null, f.name), '. WireGuard sẽ khởi động lại.'), okText: 'Khôi phục', danger: true, icon: 'upload' });
      if (!ok) return;
      busy(restoreBtn, true);
      try {
        const text = await f.text();
        const r = await api('/api/restore', { method: 'POST', body: text, raw: true });
        toast('Đã khôi phục ' + r.clients + ' người dùng');
        s = null;
        setTimeout(() => location.reload(), 1200);
      } catch (e) { toast(e.message, 'err', 7000); } finally { busy(restoreBtn, false); }
    });
    const item = (ic, color, title, desc, btn) => h('div', { class: 'list-item', style: { padding: '16px 0' } },
      h('div', { class: 'ic ' + color, style: { width: '44px', height: '44px', borderRadius: '13px', display: 'grid', placeItems: 'center', flex: 'none' } }, icon(ic)),
      h('div', { style: { flex: 1 } }, h('b', null, title), h('div', { class: 'muted', style: { fontSize: '13px' } }, desc)), btn);
    add(pane, h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('div', null, h('h3', null, 'Sao lưu & khôi phục'), h('div', { class: 'sub' }, 'Nên sao lưu định kỳ và lưu file ở nơi an toàn (file chứa khóa riêng)'))),
      h('div', { class: 'card-b list' },
        item('archive', 'cyan', 'Tải bản sao lưu', 'Toàn bộ cài đặt, người dùng, khóa và thống kê trong một file .json', h('button', { class: 'btn primary', onclick: () => download('/api/backup') }, icon('download'), 'Tải bản sao lưu')),
        item('file', 'indigo', 'Tải tất cả cấu hình', 'File .zip chứa cấu hình WireGuard (.conf) của mọi người dùng', h('button', { class: 'btn', onclick: () => download('/api/export.zip') }, icon('download'), 'Tải .zip')),
        item('upload', 'red', 'Khôi phục từ bản sao lưu', 'Thay thế dữ liệu hiện tại bằng file sao lưu (.json) - dùng khi chuyển máy chủ', h('div', null, restoreBtn, file)))),
      h('div', { class: 'alert info', style: { marginTop: '18px' } }, icon('info'), h('div', null, 'Có thể sao lưu bằng dòng lệnh: ', h('code', null, 'sudo tuan-wg backup /root/tuan-wg-backup.json'), ' và khôi phục: ', h('code', null, 'sudo tuan-wg restore <file>'))));
  }

  show('wg');
  return () => { alive = false; };
}
