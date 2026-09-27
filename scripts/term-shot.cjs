#!/usr/bin/env node
/*
 * Tuấn WireGuard - chuyển output terminal (có mã màu ANSI) thành ảnh PNG cho tài liệu
 * Cách dùng: NODE_PATH=$(npm root -g) node scripts/term-shot.cjs <input.txt> <output.png> "<tiêu đề>" [độ-rộng-cột]
 */
const { chromium } = require('playwright');
const fs = require('fs');

const [, , input, output, title = 'root@vps: ~', colsArg] = process.argv;
const raw = fs.readFileSync(input, 'utf8').replace(/\r/g, '');
const COLORS = ['#1f2937', '#f87171', '#34d399', '#fbbf24', '#60a5fa', '#c084fc', '#22d3ee', '#e5e7eb'];
const BRIGHT = ['#4b5563', '#fca5a5', '#6ee7b7', '#fde68a', '#93c5fd', '#d8b4fe', '#67e8f9', '#ffffff'];

function esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

function ansiToHtml(text) {
  let out = '', st = { fg: null, bg: null, bold: false, dim: false };
  const open = () => {
    const css = [];
    if (st.fg) css.push('color:' + st.fg);
    if (st.bg) css.push('background:' + st.bg);
    if (st.bold) css.push('font-weight:700');
    if (st.dim) css.push('opacity:.6');
    return css.length ? '<span style="' + css.join(';') + '">' : '<span>';
  };
  const re = /\x1b\[([0-9;?]*)([A-Za-z])/g;
  let last = 0, m;
  out += open();
  while ((m = re.exec(text))) {
    out += esc(text.slice(last, m.index));
    last = re.lastIndex;
    if (m[2] !== 'm') continue;
    const codes = m[1] === '' ? [0] : m[1].split(';').map(Number);
    for (const c of codes) {
      if (c === 0) st = { fg: null, bg: null, bold: false, dim: false };
      else if (c === 1) st.bold = true;
      else if (c === 2) st.dim = true;
      else if (c === 22) { st.bold = false; st.dim = false; }
      else if (c >= 30 && c <= 37) st.fg = COLORS[c - 30];
      else if (c >= 90 && c <= 97) st.fg = BRIGHT[c - 90];
      else if (c >= 40 && c <= 47) st.bg = COLORS[c - 40];
      else if (c >= 100 && c <= 107) st.bg = BRIGHT[c - 100];
      else if (c === 39) st.fg = null;
      else if (c === 49) st.bg = null;
    }
    out += '</span>' + open();
  }
  out += esc(text.slice(last)) + '</span>';
  /* mỗi dòng là một khối riêng; dòng mã QR (ký tự khối) dùng line-height 1 để không hở */
  return out.split('\n').map((l) => '<div class="' + (/[▀▄█]/.test(l) ? 'qr' : 'ln') + '">' + (l || ' ') + '</div>').join('');
}

(async () => {
  const cols = Number(colsArg) || 100;
  const html = `<!doctype html><html><head><meta charset="utf-8"><style>
    body { margin: 0; padding: 28px; background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 55%, #06b6d4 100%); display: inline-block; }
    .win { border-radius: 12px; overflow: hidden; box-shadow: 0 24px 60px -12px rgba(15, 23, 42, .6); background: #0f1424; display: inline-block; }
    .bar { height: 36px; background: #1b2236; display: flex; align-items: center; padding: 0 14px; gap: 8px; position: relative; }
    .bar i { width: 12px; height: 12px; border-radius: 50%; display: inline-block; }
    .bar b { position: absolute; left: 0; right: 0; text-align: center; color: #9aa4c4; font: 600 13px system-ui, sans-serif; }
    pre { margin: 0; padding: 16px 20px 20px; color: #e5e7eb; font: 14px/1.42 'DejaVu Sans Mono', 'Liberation Mono', monospace; width: ${cols}ch; white-space: pre; }
    pre .qr { line-height: 1; height: 1em; overflow: visible; }
    pre .ln { min-height: 1.42em; }
  </style></head><body><div class="win"><div class="bar"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i><i style="background:#28c840"></i><b>${esc(title)}</b></div><pre>${ansiToHtml(raw)}</pre></div></body></html>`;
  const browser = await chromium.launch();
  const page = await browser.newPage({ deviceScaleFactor: 2, viewport: { width: 1800, height: 800 } });
  await page.setContent(html);
  await page.evaluate(() => document.fonts.ready);
  const el = await page.$('body');
  await el.screenshot({ path: output });
  await browser.close();
  console.log('  ✔ ' + output);
})().catch((e) => { console.error(e); process.exit(1); });
