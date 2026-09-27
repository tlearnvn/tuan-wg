/*
 * Tuấn WireGuard - trang Tổng quan
 * Tác giả: Tuandethuong
 */
import { get, post } from '../api.js';
import { areaChart, barChart, ring } from '../charts.js';
import { h, icon, clear, toast, fmtBytes, bytesParts, fmtRate, fmtTime, fmtDuration, shortDay, longDay, copyText, avatar, confirmBox, busy, add } from '../ui.js';

const DOWN = '#6366f1', UP = '#14b8a6';

function stat(ic, color, label, value, unit, extra) {
  return h('div', { class: 'card stat', style: { color: 'var(--text)' } },
    h('div', { class: 'ic ' + color }, icon(ic)),
    h('div', { style: { minWidth: 0 } },
      h('div', { class: 'lbl' }, label),
      h('div', { class: 'val' }, value, unit ? h('small', null, unit) : null),
      extra ? h('div', { class: 'extra' }, extra) : null));
}

function updown(tx, rx) {
  return [h('span', { style: { color: DOWN } }, '↓ ', fmtBytes(tx)), h('span', { style: { color: UP } }, '↑ ', fmtBytes(rx))];
}

export function mount(el, ctx) {
  let data = null, live = null, liveChart = null, weekChart = null, timers = [], alive = true;
  const alerts = h('div', { class: 'col', style: { marginBottom: '18px' } });
  const statsRow = h('div', { class: 'stats-grid' });
  const liveNums = h('div', { class: 'row', style: { gap: '26px' } });
  const liveBox = h('div');
  const serverBox = h('div');
  const weekBox = h('div');
  const weekTotal = h('div', { class: 'sub' });
  const topBox = h('div', { class: 'list' });
  const sysBox = h('div');

  const restartBtn = h('button', { class: 'btn sm', onclick: async () => {
    if (!await confirmBox({ title: 'Khởi động lại WireGuard?', message: 'Các thiết bị đang kết nối sẽ bị gián đoạn vài giây rồi tự kết nối lại.', okText: 'Khởi động lại', icon: 'refresh' })) return;
    busy(restartBtn, true);
    try { await post('/api/wireguard/restart'); toast('Đã khởi động lại WireGuard'); load(); ctx.refreshStatus(); } catch (e) { toast(e.message, 'err'); } finally { busy(restartBtn, false); }
  } }, icon('refresh'), 'Khởi động lại');

  add(el, 
    alerts, statsRow,
    h('div', { class: 'dash-grid' },
      h('div', { class: 'card' },
        h('div', { class: 'card-h' }, h('div', null, h('h3', null, 'Băng thông thời gian thực'), h('div', { class: 'sub' }, '5 phút gần nhất, cập nhật mỗi 2 giây')), h('div', { class: 'spacer' }),
          h('div', { class: 'legend' }, h('span', null, h('i', { style: { background: DOWN } }), 'Tải xuống'), h('span', null, h('i', { style: { background: UP } }), 'Tải lên'))),
        h('div', { class: 'card-b' }, liveNums, h('div', { style: { marginTop: '10px' } }, liveBox))),
      h('div', { class: 'card' },
        h('div', { class: 'card-h' }, h('h3', null, 'Máy chủ WireGuard'), h('div', { class: 'spacer' }), restartBtn),
        h('div', { class: 'card-b' }, serverBox))),
    h('div', { class: 'dash-grid' },
      h('div', { class: 'card' },
        h('div', { class: 'card-h' }, h('div', null, h('h3', null, '7 ngày qua'), weekTotal), h('div', { class: 'spacer' }),
          h('a', { href: '#/thong-ke', class: 'btn sm ghost' }, 'Xem chi tiết', icon('chevronRight'))),
        h('div', { class: 'card-b' }, weekBox)),
      h('div', { class: 'card' },
        h('div', { class: 'card-h' }, h('div', null, h('h3', null, 'Dùng nhiều nhất tháng này'), h('div', { class: 'sub' }, 'Top 5 người dùng theo dung lượng'))),
        h('div', { class: 'card-b' }, topBox))),
    h('div', { class: 'card', style: { marginTop: '18px' } },
      h('div', { class: 'card-h' }, h('h3', null, 'Tài nguyên hệ thống')),
      h('div', { class: 'card-b' }, sysBox)));

  ctx.setActions(h('a', { href: '#/nguoi-dung?new=1', class: 'btn primary' }, icon('userPlus'), h('span', { class: 'lbl' }, 'Thêm người dùng')));

  function renderAlerts() {
    clear(alerts);
    const s = data.server;
    if (data.demo) alerts.appendChild(h('div', { class: 'alert info' }, icon('info'), h('div', null, h('b', null, 'Chế độ demo: '), 'dữ liệu là mẫu, lưu lượng được mô phỏng và không có thay đổi nào tác động tới WireGuard thật.')));
    if (!s.tools) alerts.appendChild(h('div', { class: 'alert err' }, icon('alert'), h('div', null, h('b', null, 'Chưa cài wireguard-tools. '), 'Hãy chạy ', h('code', null, 'sudo apt install wireguard-tools'), ' hoặc ', h('code', null, 'sudo tuan-wg install'), '.')));
    else if (!s.up) alerts.appendChild(h('div', { class: 'alert err' }, icon('alert'), h('div', null, h('b', null, 'WireGuard chưa chạy. '), s.error ? s.error : 'Bấm "Khởi động lại" để thử khởi động interface ' + s.interface + '.')));
    if (!s.endpoint_set) alerts.appendChild(h('div', { class: 'alert warn' }, icon('alert'), h('div', null, h('b', null, 'Chưa đặt địa chỉ máy chủ (Endpoint). '), 'File cấu hình đang dùng IP tự phát hiện ', h('code', null, s.endpoint), '. ', h('a', { href: '#/cai-dat' }, 'Đặt tên miền/IP công khai'))));
    alerts.classList.toggle('hidden', !alerts.children.length);
  }

  function renderStats() {
    const c = data.counts, t = data.traffic;
    const [tv, tu] = bytesParts(t.today_rx + t.today_tx);
    const [mv, mu] = bytesParts(t.month_rx + t.month_tx);
    clear(statsRow);
    add(statsRow, 
      stat('users', 'indigo', 'Người dùng', c.total, null, [h('span', null, c.enabled + ' đang bật'), c.disabled ? h('span', null, c.disabled + ' đã khóa') : null]),
      stat('wifi', 'green', 'Đang online', h('span', { id: 'dOnline' }, c.online), '/ ' + c.enabled, [h('span', null, 'kết nối trong 3 phút qua')]),
      stat('activity', 'cyan', 'Hôm nay', tv, tu, updown(t.today_tx, t.today_rx)),
      stat('database', 'amber', 'Tháng này', mv, mu, updown(t.month_tx, t.month_rx)));
  }

  function renderServer() {
    const s = data.server;
    clear(serverBox);
    add(serverBox, 
      h('div', { class: 'row', style: { marginBottom: '14px' } },
        h('span', { class: 'badge ' + (s.up ? 'green' : 'red') }, h('span', { class: 'dot ' + (s.up ? 'on' : 'bad') }), s.up ? 'Đang hoạt động' : 'Đã dừng'),
        h('span', { class: 'badge' }, s.interface), h('span', { class: 'badge violet' }, 'UDP ' + s.listen_port)),
      h('dl', { class: 'kv' },
        h('dt', null, 'Endpoint'), h('dd', { class: 'mono' }, s.endpoint),
        h('dt', null, 'Dải mạng VPN'), h('dd', { class: 'mono' }, s.address + (s.ipv6 ? ', ' + s.address6 : '')),
        h('dt', null, 'DNS'), h('dd', { class: 'mono' }, s.dns || '—'),
        h('dt', null, 'Khóa công khai'), h('dd', { class: 'mono row', style: { gap: '6px' } }, h('span', { class: 'ellipsis', style: { maxWidth: '180px' } }, s.public_key),
          h('button', { class: 'icon-btn', title: 'Sao chép', onclick: () => copyText(s.public_key) }, icon('copy'))),
        h('dt', null, 'WireGuard'), h('dd', null, s.wg_version ? 'v' + s.wg_version : '—'),
        h('dt', null, 'Panel chạy'), h('dd', null, fmtDuration(data.now - s.panel_started))));
  }

  function renderWeek() {
    const w = data.week;
    let sum = 0;
    for (const d of w) sum += d.rx + d.tx;
    weekTotal.textContent = 'Tổng ' + fmtBytes(sum);
    const opts = {
      height: 230,
      series: [{ name: 'Tải xuống', color: DOWN, values: w.map((d) => d.tx) }, { name: 'Tải lên', color: UP, values: w.map((d) => d.rx) }],
      xFormat: (i) => shortDay(w[i].label), tipTitle: (i) => longDay(w[i].label), yFormat: (v) => fmtBytes(v, 1), tipFormat: (v) => fmtBytes(v),
    };
    if (weekChart) weekChart.update(opts); else weekChart = barChart(weekBox, opts);
  }

  function renderTop() {
    clear(topBox);
    if (!data.top.length) { topBox.appendChild(h('div', { class: 'muted', style: { padding: '20px 0', textAlign: 'center' } }, 'Chưa có dữ liệu sử dụng trong tháng này')); return; }
    const max = Math.max(...data.top.map((t) => t.rx + t.tx), 1);
    for (const t of data.top) {
      const v = t.rx + t.tx;
      topBox.appendChild(h('div', { class: 'list-item' }, avatar(t.name, t.online ? 'on' : null),
        h('div', { style: { flex: 1, minWidth: 0 } },
          h('div', { class: 'row', style: { justifyContent: 'space-between' } }, h('b', { class: 'ellipsis' }, t.name), h('span', { class: 'nowrap', style: { fontWeight: 600 } }, fmtBytes(v))),
          h('div', { class: 'bar', style: { marginTop: '7px' } }, h('i', { style: { width: (v / max) * 100 + '%' } })))));
    }
  }

  function sysItem(title, pct, color, lines) {
    return h('div', { class: 'row', style: { gap: '16px' } },
      h('div', { style: { position: 'relative', width: '64px', height: '64px' } }, ring(pct, color),
        h('div', { style: { position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', fontWeight: 700, fontSize: '13px' } }, Math.round(pct) + '%')),
      h('div', null, h('b', null, title), lines.map((l) => h('div', { class: 'muted', style: { fontSize: '12.5px' } }, l))));
  }

  function renderSys() {
    const s = data.system;
    const mem = s.mem_total ? ((s.mem_total - s.mem_avail) / s.mem_total) * 100 : 0;
    const disk = s.disk_total ? ((s.disk_total - s.disk_free) / s.disk_total) * 100 : 0;
    clear(sysBox);
    add(sysBox, h('div', { class: 'dash-grid-3', style: { marginTop: 0 } },
      sysItem('CPU', s.cpu, '#6366f1', [s.cpus + ' nhân • tải ' + s.load1.toFixed(2) + ' / ' + s.load5.toFixed(2) + ' / ' + s.load15.toFixed(2)]),
      sysItem('Bộ nhớ RAM', mem, '#06b6d4', [fmtBytes(s.mem_total - s.mem_avail) + ' / ' + fmtBytes(s.mem_total)]),
      sysItem('Ổ đĩa', disk, '#f59e0b', [fmtBytes(s.disk_total - s.disk_free) + ' / ' + fmtBytes(s.disk_total)])),
      h('dl', { class: 'kv', style: { marginTop: '18px', gridTemplateColumns: 'auto 1fr auto 1fr' } },
        h('dt', null, 'Máy chủ'), h('dd', null, s.hostname), h('dt', null, 'Hệ điều hành'), h('dd', null, s.os || '—'),
        h('dt', null, 'Kernel'), h('dd', null, s.kernel), h('dt', null, 'Thời gian chạy'), h('dd', null, fmtDuration(s.uptime))));
  }

  function renderLive() {
    const pts = (live && live.points) || [];
    const rx = live ? live.rate_rx : 0, tx = live ? live.rate_tx : 0;
    clear(liveNums);
    add(liveNums, 
      h('div', null, h('div', { class: 'muted', style: { fontSize: '12.5px', fontWeight: 600 } }, '↓ Tải xuống'), h('div', { class: 'live-num', style: { color: DOWN } }, fmtRate(tx))),
      h('div', null, h('div', { class: 'muted', style: { fontSize: '12.5px', fontWeight: 600 } }, '↑ Tải lên'), h('div', { class: 'live-num', style: { color: UP } }, fmtRate(rx))));
    const opts = {
      height: 210, base: 1000, padLeft: 70,
      series: [{ name: 'Tải xuống', color: DOWN, values: pts.map((p) => p[2]) }, { name: 'Tải lên', color: UP, values: pts.map((p) => p[1]) }],
      xFormat: (i) => fmtTime(pts[i][0]), tipTitle: (i) => fmtTime(pts[i][0]), yFormat: (v) => fmtRate(v), tipFormat: (v) => fmtRate(v),
    };
    if (liveChart) liveChart.update(opts); else liveChart = areaChart(liveBox, opts);
    const on = document.getElementById('dOnline');
    if (on && live) on.textContent = live.clients.filter((c) => c.online).length;
  }

  async function load() {
    try {
      data = await get('/api/dashboard');
      if (!alive) return;
      live = live || { points: data.live, rate_rx: data.traffic.rate_rx, rate_tx: data.traffic.rate_tx, clients: [] };
      renderAlerts(); renderStats(); renderServer(); renderWeek(); renderTop(); renderSys(); renderLive();
    } catch (e) {
      if (alive && e.status !== 401) toast(e.message, 'err');
    }
  }

  async function pollLive() {
    try { live = await get('/api/live'); if (alive) renderLive(); } catch (e) { /* bỏ qua */ }
  }

  add(statsRow, ...[1, 2, 3, 4].map(() => h('div', { class: 'card skeleton', style: { height: '104px' } })));
  load();
  timers.push(setInterval(pollLive, 2000), setInterval(load, 15000));
  return () => { alive = false; timers.forEach(clearInterval); if (liveChart) liveChart.destroy(); if (weekChart) weekChart.destroy(); };
}
