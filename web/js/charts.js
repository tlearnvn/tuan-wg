/*
 * Tuấn WireGuard - biểu đồ SVG (không dùng thư viện ngoài)
 * Tác giả: Tuandethuong
 */
import { h } from './ui.js';

const NS = 'http://www.w3.org/2000/svg';
let gradId = 0;

function s(tag, attrs) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  return el;
}

/* bước "đẹp" cho trục Y, base = 1024 (byte) hoặc 1000 (bit/giây) */
function niceScale(max, base, ticks = 4) {
  if (!(max > 0)) max = 1;
  let unit = 1;
  if (base) {
    while (max / unit >= base && unit < base ** 5) unit *= base;
  }
  const raw = max / unit / ticks;
  const exp = Math.floor(Math.log10(raw));
  const f = raw / 10 ** exp;
  const nf = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10;
  let step = nf * 10 ** exp * unit;
  if (step < 1) step = 1; /* không có "0,25 B" */
  return { step, max: step * ticks };
}

function monotone(pts) {
  const n = pts.length;
  if (n === 0) return '';
  if (n === 1) return `M${pts[0][0]},${pts[0][1]}`;
  const dx = [], m = [];
  for (let i = 0; i < n - 1; i++) {
    dx[i] = pts[i + 1][0] - pts[i][0] || 1e-6;
    m[i] = (pts[i + 1][1] - pts[i][1]) / dx[i];
  }
  const t = [m[0]];
  for (let i = 1; i < n - 1; i++) {
    t[i] = m[i - 1] * m[i] <= 0 ? 0 : (3 * (dx[i - 1] + dx[i])) / ((2 * dx[i] + dx[i - 1]) / m[i - 1] + (dx[i] + 2 * dx[i - 1]) / m[i]);
  }
  t[n - 1] = m[n - 2];
  let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
  for (let i = 0; i < n - 1; i++) {
    const [x0, y0] = pts[i], [x1, y1] = pts[i + 1], hh = dx[i];
    d += `C${(x0 + hh / 3).toFixed(1)},${(y0 + (t[i] * hh) / 3).toFixed(1)},${(x1 - hh / 3).toFixed(1)},${(y1 - (t[i + 1] * hh) / 3).toFixed(1)},${x1.toFixed(1)},${y1.toFixed(1)}`;
  }
  return d;
}

function baseChart(el, opts, draw) {
  el.classList.add('chart');
  el.innerHTML = '';
  const svg = s('svg', { role: 'img' });
  const tip = h('div', { class: 'chart-tip' });
  el.append(svg, tip);
  let cur = opts;
  const render = () => {
    const w = Math.max(200, el.clientWidth);
    const hgt = cur.height || 240;
    svg.setAttribute('viewBox', `0 0 ${w} ${hgt}`);
    svg.setAttribute('height', hgt);
    svg.innerHTML = '';
    draw(svg, tip, w, hgt, cur);
  };
  const ro = new ResizeObserver(() => render());
  ro.observe(el);
  render();
  return {
    update(o) { cur = Object.assign({}, cur, o); render(); },
    destroy() { ro.disconnect(); el.innerHTML = ''; },
  };
}

function axes(svg, w, hgt, pad, scale, yFormat) {
  for (let i = 0; i <= 4; i++) {
    const v = scale.step * i;
    const y = pad.t + (hgt - pad.t - pad.b) * (1 - v / scale.max);
    svg.appendChild(s('line', { x1: pad.l, x2: w - pad.r, y1: y, y2: y, class: 'grid-line' }));
    const t = s('text', { x: pad.l - 8, y: y + 4, 'text-anchor': 'end', class: 'axis-text' });
    t.textContent = yFormat(v);
    svg.appendChild(t);
  }
}

function xLabels(svg, n, xOf, hgt, pad, fmt, w) {
  if (!fmt || n === 0) return;
  const maxLabels = Math.max(2, Math.floor((w - pad.l - pad.r) / 64));
  const every = Math.max(1, Math.ceil(n / maxLabels));
  for (let i = 0; i < n; i++) {
    if (i % every !== 0 && i !== n - 1) continue;
    if (i === n - 1 && i % every !== 0 && (n - 1) % every < every * 0.6) continue;
    const t = s('text', { x: xOf(i), y: hgt - 8, 'text-anchor': 'middle', class: 'axis-text' });
    t.textContent = fmt(i);
    svg.appendChild(t);
  }
}

function emptyNote(svg, w, hgt, pad, series) {
  const any = series.some((sr) => sr.values.some((v) => v > 0));
  if (any) return;
  const t = s('text', { x: pad.l + (w - pad.l - pad.r) / 2, y: pad.t + (hgt - pad.t - pad.b) / 2, 'text-anchor': 'middle', class: 'axis-text', 'font-size': 13 });
  t.textContent = 'Chưa có dữ liệu';
  svg.appendChild(t);
}

function showTip(tip, el, x, y, title, rows) {
  tip.innerHTML = '';
  tip.appendChild(h('div', { class: 't' }, title));
  for (const r of rows) tip.appendChild(h('div', { class: 'r' }, h('span', null, h('i', { style: { background: r.color } }), ' ', r.name), h('b', null, r.value)));
  const bw = el.clientWidth;
  tip.style.left = Math.min(Math.max(x, 90), bw - 90) + 'px';
  tip.style.top = Math.max(y, 60) + 'px';
  tip.classList.add('show');
}

/* Biểu đồ vùng (đường cong mượt) */
export function areaChart(el, opts) {
  return baseChart(el, opts, (svg, tip, w, hgt, o) => {
    const pad = { l: o.padLeft || 64, r: 12, t: 12, b: 28 };
    const series = o.series || [];
    const n = Math.max(...series.map((x) => x.values.length), 0);
    const max = Math.max(1, ...series.flatMap((x) => x.values.map((v) => v || 0)));
    const scale = niceScale(max, o.base === undefined ? 1024 : o.base);
    const iw = w - pad.l - pad.r, ih = hgt - pad.t - pad.b;
    const xOf = (i) => pad.l + (n <= 1 ? iw / 2 : (iw * i) / (n - 1));
    const yOf = (v) => pad.t + ih * (1 - (v || 0) / scale.max);
    axes(svg, w, hgt, pad, scale, o.yFormat || String);
    xLabels(svg, n, xOf, hgt, pad, o.xFormat, w);
    const defs = s('defs');
    svg.appendChild(defs);
    for (const sr of series) {
      const id = 'ag' + ++gradId;
      const g = s('linearGradient', { id, x1: 0, y1: 0, x2: 0, y2: 1 });
      g.append(s('stop', { offset: '0%', 'stop-color': sr.color, 'stop-opacity': o.fillOpacity || 0.28 }), s('stop', { offset: '100%', 'stop-color': sr.color, 'stop-opacity': 0 }));
      defs.appendChild(g);
      const pts = sr.values.map((v, i) => [xOf(i), yOf(v)]);
      if (pts.length) {
        const line = monotone(pts);
        const area = line + `L${xOf(pts.length - 1)},${pad.t + ih}L${xOf(0)},${pad.t + ih}Z`;
        svg.appendChild(s('path', { d: area, fill: `url(#${id})` }));
        svg.appendChild(s('path', { d: line, fill: 'none', stroke: sr.color, 'stroke-width': 2.2, 'stroke-linecap': 'round' }));
      }
    }
    emptyNote(svg, w, hgt, pad, series);
    const hl = s('line', { y1: pad.t, y2: pad.t + ih, class: 'hover-line', opacity: 0 });
    svg.appendChild(hl);
    const dots = series.map((sr) => { const c = s('circle', { r: 4.5, fill: sr.color, stroke: 'var(--surface)', 'stroke-width': 2, opacity: 0 }); svg.appendChild(c); return c; });
    const ov = s('rect', { x: pad.l, y: pad.t, width: iw, height: ih, fill: 'transparent' });
    svg.appendChild(ov);
    const move = (ev) => {
      if (!n) return;
      const r = svg.getBoundingClientRect();
      const mx = ((ev.clientX - r.left) / r.width) * w;
      const i = Math.max(0, Math.min(n - 1, Math.round(((mx - pad.l) / iw) * (n - 1))));
      const x = xOf(i);
      hl.setAttribute('x1', x); hl.setAttribute('x2', x); hl.setAttribute('opacity', 1);
      let minY = hgt;
      series.forEach((sr, k) => { const y = yOf(sr.values[i]); minY = Math.min(minY, y); dots[k].setAttribute('cx', x); dots[k].setAttribute('cy', y); dots[k].setAttribute('opacity', 1); });
      showTip(tip, el, (x / w) * r.width, (minY / hgt) * r.height, o.tipTitle ? o.tipTitle(i) : String(i),
        series.map((sr) => ({ name: sr.name, color: sr.color, value: (o.tipFormat || o.yFormat || String)(sr.values[i] || 0) })));
    };
    const leave = () => { hl.setAttribute('opacity', 0); dots.forEach((d) => d.setAttribute('opacity', 0)); tip.classList.remove('show'); };
    ov.addEventListener('pointermove', move);
    ov.addEventListener('pointerleave', leave);
  });
}

/* Biểu đồ cột (xếp chồng) */
export function barChart(el, opts) {
  return baseChart(el, opts, (svg, tip, w, hgt, o) => {
    const pad = { l: o.padLeft || 64, r: 12, t: 12, b: 28 };
    const series = o.series || [];
    const n = Math.max(...series.map((x) => x.values.length), 0);
    const totals = Array.from({ length: n }, (_, i) => series.reduce((a, sr) => a + (sr.values[i] || 0), 0));
    const scale = niceScale(Math.max(1, ...totals), o.base === undefined ? 1024 : o.base);
    const iw = w - pad.l - pad.r, ih = hgt - pad.t - pad.b;
    const step = n ? iw / n : iw;
    const bw = Math.max(3, Math.min(34, step * 0.62));
    const xOf = (i) => pad.l + step * i + step / 2;
    const yOf = (v) => pad.t + ih * (1 - v / scale.max);
    axes(svg, w, hgt, pad, scale, o.yFormat || String);
    xLabels(svg, n, xOf, hgt, pad, o.xFormat, w);
    const hover = s('rect', { y: pad.t, height: ih, width: step, rx: 8, fill: 'var(--surface-3)', opacity: 0 });
    svg.appendChild(hover);
    for (let i = 0; i < n; i++) {
      let acc = 0;
      series.forEach((sr, k) => {
        const v = sr.values[i] || 0;
        if (v <= 0) return;
        const y0 = yOf(acc), y1 = yOf(acc + v);
        acc += v;
        const top = k === series.length - 1 || series.slice(k + 1).every((x) => !(x.values[i] > 0));
        const x = xOf(i) - bw / 2, hh = Math.max(1.5, y0 - y1), rr = top ? Math.min(6, bw / 2, hh) : 0;
        const d = `M${x},${y0}V${y1 + rr}Q${x},${y1} ${x + rr},${y1}H${x + bw - rr}Q${x + bw},${y1} ${x + bw},${y1 + rr}V${y0}Z`;
        svg.appendChild(s('path', { d, fill: sr.color, opacity: 0.92 }));
      });
    }
    emptyNote(svg, w, hgt, pad, series);
    const ov = s('rect', { x: pad.l, y: pad.t, width: iw, height: ih, fill: 'transparent' });
    svg.appendChild(ov);
    ov.addEventListener('pointermove', (ev) => {
      if (!n) return;
      const r = svg.getBoundingClientRect();
      const mx = ((ev.clientX - r.left) / r.width) * w;
      const i = Math.max(0, Math.min(n - 1, Math.floor((mx - pad.l) / step)));
      hover.setAttribute('x', pad.l + step * i); hover.setAttribute('opacity', 0.7);
      const rows = series.map((sr) => ({ name: sr.name, color: sr.color, value: (o.tipFormat || o.yFormat || String)(sr.values[i] || 0) }));
      if (series.length > 1) rows.push({ name: 'Tổng', color: 'transparent', value: (o.tipFormat || o.yFormat || String)(totals[i]) });
      showTip(tip, el, (xOf(i) / w) * r.width, (yOf(totals[i]) / hgt) * r.height, o.tipTitle ? o.tipTitle(i) : String(i), rows);
    });
    ov.addEventListener('pointerleave', () => { hover.setAttribute('opacity', 0); tip.classList.remove('show'); });
    if (o.onClick) ov.addEventListener('click', (ev) => {
      const r = svg.getBoundingClientRect();
      const i = Math.floor(((((ev.clientX - r.left) / r.width) * w) - pad.l) / step);
      if (i >= 0 && i < n) o.onClick(i);
    });
  });
}

/* Vòng tròn phần trăm nhỏ */
export function ring(pct, color, size = 64) {
  const r = (size - 8) / 2, c = 2 * Math.PI * r;
  const svg = s('svg', { viewBox: `0 0 ${size} ${size}`, width: size, height: size });
  svg.appendChild(s('circle', { cx: size / 2, cy: size / 2, r, fill: 'none', stroke: 'var(--surface-3)', 'stroke-width': 7 }));
  svg.appendChild(s('circle', { cx: size / 2, cy: size / 2, r, fill: 'none', stroke: color, 'stroke-width': 7, 'stroke-linecap': 'round', 'stroke-dasharray': `${(c * Math.min(100, Math.max(0, pct))) / 100} ${c}`, transform: `rotate(-90 ${size / 2} ${size / 2})` }));
  return svg;
}
