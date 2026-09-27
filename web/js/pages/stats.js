/*
 * Tuấn WireGuard - trang Thống kê
 * Tác giả: Tuandethuong
 */
import { get } from '../api.js';
import { barChart, areaChart } from '../charts.js';
import { h, icon, clear, toast, fmtBytes, bytesParts, shortDay, longDay, avatar, segmented, add } from '../ui.js';

const DOWN = '#6366f1', UP = '#14b8a6';
const RANGES = [['24h', '24 giờ'], ['7d', '7 ngày'], ['30d', '30 ngày'], ['90d', '90 ngày'], ['12m', '12 tháng']];

export function mount(el, ctx) {
  let range = '30d', chart = null, data = null, alive = true, sortKey = 'total';
  const sum = h('div', { class: 'stats-grid' });
  const chartBox = h('div');
  const chartTitle = h('h3', null, '');
  const tbody = h('tbody');
  const seg = segmented(RANGES, range, (v) => { range = v; load(); });

  add(el, 
    h('div', { class: 'toolbar' }, seg, h('div', { class: 'spacer' }),
      h('button', { class: 'btn', onclick: exportCsv }, icon('download'), 'Xuất CSV')),
    sum,
    h('div', { class: 'card', style: { marginTop: '18px' } },
      h('div', { class: 'card-h' }, chartTitle, h('div', { class: 'spacer' }),
        h('div', { class: 'legend' }, h('span', null, h('i', { style: { background: DOWN } }), 'Tải xuống'), h('span', null, h('i', { style: { background: UP } }), 'Tải lên'))),
      h('div', { class: 'card-b' }, chartBox)),
    h('div', { class: 'card', style: { marginTop: '18px' } },
      h('div', { class: 'card-h' }, h('div', null, h('h3', null, 'Dung lượng theo người dùng'), h('div', { class: 'sub' }, 'Trong khoảng thời gian đã chọn'))),
      h('div', { class: 'card-b', style: { paddingTop: '12px' } }, h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
        h('thead', null, h('tr', null, h('th', null, '#'), h('th', null, 'Người dùng'), h('th', null, 'Tải xuống'), h('th', null, 'Tải lên'),
          h('th', null, 'Tổng'), h('th', null, 'Tỷ lệ'), h('th', null, 'Tích lũy từ đầu'))), tbody)))));

  function card(ic, color, label, bytes, extra) {
    const [v, u] = bytesParts(bytes);
    return h('div', { class: 'card stat' }, h('div', { class: 'ic ' + color }, icon(ic)),
      h('div', null, h('div', { class: 'lbl' }, label), h('div', { class: 'val' }, v, h('small', null, u)), extra ? h('div', { class: 'extra' }, extra) : null));
  }

  function render() {
    const s = data.series;
    let rx = 0, tx = 0, peak = -1, peakV = 0;
    s.forEach((p, i) => { rx += p.rx; tx += p.tx; if (p.rx + p.tx > peakV) { peakV = p.rx + p.tx; peak = i; } });
    const unit = data.unit === 'hour' ? 'giờ' : data.unit === 'day' ? 'ngày' : 'tháng';
    const nonzero = s.filter((p) => p.rx + p.tx > 0).length || 1;
    clear(sum);
    add(sum, 
      card('arrowDown', 'indigo', 'Tổng tải xuống', tx),
      card('arrowUp', 'cyan', 'Tổng tải lên', rx),
      card('database', 'amber', 'Trung bình mỗi ' + unit, (rx + tx) / nonzero, 'tính trên ' + nonzero + ' ' + unit + ' có dữ liệu'),
      card('zap', 'pink', 'Cao điểm', peakV, peak >= 0 ? longDay(s[peak].label) : '—'));
    chartTitle.textContent = 'Lưu lượng theo ' + unit + ' - ' + RANGES.find((r) => r[0] === range)[1] + ' qua';
    const opts = {
      height: 300, series: [{ name: 'Tải xuống', color: DOWN, values: s.map((p) => p.tx) }, { name: 'Tải lên', color: UP, values: s.map((p) => p.rx) }],
      xFormat: (i) => shortDay(s[i].label), tipTitle: (i) => longDay(s[i].label), yFormat: (v) => fmtBytes(v, 1), tipFormat: (v) => fmtBytes(v),
    };
    if (chart) chart.destroy();
    chart = (range === '24h' ? areaChart : barChart)(chartBox, opts);

    const list = data.clients.map((c) => ({ ...c, total: c.rx + c.tx })).filter((c) => c.total > 0 || c.total_rx + c.total_tx > 0);
    list.sort((a, b) => b[sortKey] - a[sortKey]);
    const all = Math.max(1, list.reduce((a, c) => a + c.total, 0));
    clear(tbody);
    if (!list.length) tbody.appendChild(h('tr', null, h('td', { colspan: 7, class: 'muted', style: { textAlign: 'center', padding: '28px' } }, 'Chưa có dữ liệu trong khoảng thời gian này')));
    list.forEach((c, i) => {
      const pct = (c.total / all) * 100;
      tbody.appendChild(h('tr', null,
        h('td', null, h('div', { class: 'rank' + (i < 3 && c.total > 0 ? ' r' + (i + 1) : '') }, i + 1)),
        h('td', null, h('div', { class: 'user-cell' }, avatar(c.name, c.online ? 'on' : null), h('div', null, h('div', { class: 'nm' }, c.name), h('div', { class: 'nt mono' }, c.address)))),
        h('td', { class: 'nowrap', style: { color: DOWN, fontWeight: 600 } }, fmtBytes(c.tx)),
        h('td', { class: 'nowrap', style: { color: UP, fontWeight: 600 } }, fmtBytes(c.rx)),
        h('td', { class: 'nowrap', style: { fontWeight: 700 } }, fmtBytes(c.total)),
        h('td', null, h('div', { class: 'share-bar' }, h('div', { class: 'bar' }, h('i', { style: { width: pct + '%' } })), h('span', null, pct.toFixed(1).replace('.', ',') + '%'))),
        h('td', { class: 'nowrap muted' }, fmtBytes(c.total_rx + c.total_tx))));
    });
  }

  function exportCsv() {
    if (!data) return;
    const rows = [['Nguoi dung', 'IP', 'Tai xuong (byte)', 'Tai len (byte)', 'Tong (byte)']];
    for (const c of data.clients) rows.push([c.name, c.address, c.tx, c.rx, c.rx + c.tx]);
    rows.push([]);
    rows.push(['Thoi gian', 'Tai xuong (byte)', 'Tai len (byte)']);
    for (const p of data.series) rows.push([p.label, p.tx, p.rx]);
    const csv = '﻿' + rows.map((r) => r.map((x) => '"' + String(x ?? '').replace(/"/g, '""') + '"').join(',')).join('\r\n');
    const a = h('a', { href: URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' })), download: 'tuan-wg-thong-ke-' + range + '.csv' });
    document.body.appendChild(a); a.click(); a.remove();
  }

  async function load() {
    try {
      data = await get('/api/stats?range=' + range);
      if (alive) render();
    } catch (e) { if (e.status !== 401) toast(e.message, 'err'); }
  }
  add(sum, ...[1, 2, 3, 4].map(() => h('div', { class: 'card skeleton', style: { height: '104px' } })));
  load();
  const t = setInterval(load, 30000);
  return () => { alive = false; clearInterval(t); if (chart) chart.destroy(); };
}
