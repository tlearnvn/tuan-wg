#!/usr/bin/env node
/*
 * Tuấn WireGuard - chụp ảnh màn hình giao diện cho tài liệu + kiểm thử giao diện (smoke test)
 *
 * Cách dùng:
 *   ./build/tuan-wg serve --demo --listen 127.0.0.1 --port 18080 &
 *   NODE_PATH=$(npm root -g) node scripts/screenshots.cjs http://127.0.0.1:18080 docs/images
 *
 * Thoát với mã lỗi nếu trang có lỗi JavaScript.
 */
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const BASE = process.argv[2] || 'http://127.0.0.1:18080';
const OUT = process.argv[3] || 'docs/images';
const ONLY = process.env.ONLY ? process.env.ONLY.split(',') : null;
fs.mkdirSync(OUT, { recursive: true });

const errors = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function newPage(browser, opts = {}) {
  const ctx = await browser.newContext({
    viewport: opts.viewport || { width: 1440, height: 900 },
    deviceScaleFactor: opts.scale || 2,
    colorScheme: opts.dark ? 'dark' : 'light',
    locale: 'vi-VN',
    timezoneId: 'Asia/Ho_Chi_Minh',
    isMobile: !!opts.mobile,
    hasTouch: !!opts.mobile,
  });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
  page.on('console', (m) => {
    /* 401 khi chưa đăng nhập là bình thường */
    if (m.type() === 'error' && !/status of 401/.test(m.text())) errors.push('console: ' + m.text());
  });
  return { ctx, page };
}

async function login(page) {
  await page.goto(BASE + '/');
  await page.waitForSelector('input[name=username]');
  await page.fill('input[name=username]', 'admin');
  await page.fill('input[name=password]', 'admin');
  await page.click('button[type=submit]');
  await page.waitForSelector('.sidebar');
}

async function shot(page, name, opts = {}) {
  if (ONLY && !ONLY.includes(name)) return;
  await sleep(opts.wait || 900);
  /* bỏ thông báo nổi (toast) còn sót lại để ảnh gọn gàng */
  await page.evaluate(() => document.querySelectorAll('.toasts > *').forEach((t) => t.remove()));
  const file = path.join(OUT, name + '.png');
  if (opts.el) {
    await (await page.$(opts.el)).screenshot({ path: file });
  } else if (opts.full) {
    const vp = page.viewportSize();
    const hgt = await page.evaluate(() => Math.ceil(document.documentElement.scrollHeight));
    await page.setViewportSize({ width: vp.width, height: Math.max(vp.height, hgt) });
    await sleep(400);
    await page.screenshot({ path: file });
    await page.setViewportSize(vp);
  } else {
    await page.screenshot({ path: file });
  }
  console.log('  ✔ ' + file);
}

/* kiểm tra không có phần tử nào tràn ngang khỏi màn hình (lỗi hay gặp trên điện thoại) */
async function checkFit(page, where) {
  const bad = await page.evaluate(() => {
    const vw = document.documentElement.clientWidth;
    const out = [];
    if (document.documentElement.scrollWidth > vw + 1) out.push('trang rộng ' + document.documentElement.scrollWidth + 'px');
    /* phần tử thò ra ngoài màn hình, trừ khi nằm trong vùng cuộn/cắt có chủ đích (bảng, thanh tab...) */
    const clipped = (el) => {
      for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
        const ox = getComputedStyle(p).overflowX;
        if (ox !== 'visible' && p.getBoundingClientRect().right <= vw + 1) return true;
      }
      return false;
    };
    for (const el of document.querySelectorAll('.main *, .modal-root *, .share *')) {
      if (el.closest('.sidebar')) continue;
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.height === 0 || r.right <= vw + 1) continue;
      if (clipped(el)) continue;
      out.push(el.tagName.toLowerCase() + ([...el.classList].length ? '.' + [...el.classList].join('.') : '') + ' (phải=' + Math.round(r.right) + 'px, "' + (el.textContent || '').trim().slice(0, 30) + '")');
    }
    return out.length ? 'khung nhìn ' + vw + 'px: ' + [...new Set(out)].slice(0, 5).join(', ') : '';
  });
  if (bad) errors.push('tràn ngang ở ' + where + ' - ' + bad);
}

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || undefined });

  /* ---------- desktop sáng ---------- */
  {
    const { ctx, page } = await newPage(browser);
    await page.goto(BASE + '/');
    await page.waitForSelector('input[name=username]');
    await shot(page, 'login');
    await login(page);
    await page.goto(BASE + '/#/tong-quan');
    await page.waitForSelector('.stat .val');
    await sleep(4500); /* chờ biểu đồ thời gian thực có dữ liệu */
    await shot(page, 'dashboard', { full: true });

    await page.goto(BASE + '/#/nguoi-dung');
    await page.waitForSelector('.client-table tbody tr .user-cell');
    await shot(page, 'clients', { full: true });

    await page.click('.topbar .btn.primary');
    await page.waitForSelector('.modal');
    await page.fill('.modal input.input', 'iPhone của Mai');
    await page.click('.modal .seg button[data-v="30"]');
    await page.fill('.modal input[type=number]', '50');
    await shot(page, 'client-form');
    await page.click('.modal .btn.ghost.sm');
    await shot(page, 'client-form-advanced');
    await page.click('.modal-f .btn.primary');
    await page.waitForSelector('.modal .qr-box img');
    await page.waitForSelector('.modal .conf-box .k');
    await shot(page, 'client-qr');
    await page.click('.modal .tabs button[data-k=share]');
    await page.click('.modal .tab-share-create, .modal .btn.primary:has-text("Tạo link")');
    await page.waitForSelector('.modal .share-url input');
    await shot(page, 'client-share');
    await page.click('.modal .tabs button[data-k=guide]');
    await shot(page, 'client-guide');
    await page.keyboard.press('Escape');
    await page.waitForSelector('.modal', { state: 'detached' });

    /* thống kê + thông tin của một người dùng đã có lưu lượng */
    await page.click('.client-table tbody tr:has-text("Laptop Tuấn") .user-cell');
    await page.waitForSelector('.modal .tabs');
    await page.click('.modal .tabs button[data-k=stats]');
    await page.waitForSelector('.modal .chart svg path');
    await shot(page, 'client-stats', { wait: 1500 });
    await page.click('.modal .tabs button[data-k=info]');
    await shot(page, 'client-info');
    await page.keyboard.press('Escape');

    /* chọn nhiều người dùng */
    for (const i of [2, 3, 4]) await page.check(`.client-table tbody tr:nth-child(${i}) input[type=checkbox]`);
    await shot(page, 'clients-bulk');
    await page.click('.bulkbar .btn.ghost');

    /* menu thao tác */
    await page.click('.client-table tbody tr:nth-child(2) .actions .icon-btn[title="Thêm"]');
    await shot(page, 'clients-menu');
    await page.keyboard.press('Escape');
    await page.mouse.click(5, 5);

    await page.goto(BASE + '/#/thong-ke');
    await page.waitForSelector('.chart svg path');
    await shot(page, 'stats', { full: true, wait: 1400 });

    /* vài thao tác thường gặp để trang nhật ký có dữ liệu minh họa */
    await page.evaluate(async () => {
      const H = { 'X-TWG': '1', 'Content-Type': 'application/json' };
      await fetch('/api/login', { method: 'POST', headers: H, body: JSON.stringify({ username: 'admin', password: 'sai-mat-khau' }) });
      const cs = (await (await fetch('/api/clients', { headers: H })).json()).clients;
      const by = (n) => cs.find((c) => c.name === n) || cs[0];
      const put = (c, body) => fetch('/api/clients/' + c.id, { method: 'PUT', headers: H, body: JSON.stringify(body) });
      await fetch('/api/clients/' + by('Laptop Tuấn').id + '/config', { headers: H });
      await put(by('Máy tính Lan'), { enabled: true });
      await put(by('Máy tính Lan'), { enabled: false });
      await fetch('/api/clients/' + by('Khách - Hùng').id + '/reset', { method: 'POST', headers: H });
      await fetch('/api/settings', { method: 'PUT', headers: H, body: JSON.stringify({ dns: '1.1.1.1, 8.8.8.8' }) });
      await fetch('/api/export.zip', { headers: H });
      await fetch('/api/backup', { headers: H });
    });
    await page.goto(BASE + '/#/nhat-ky');
    await page.waitForSelector('.table tbody tr .log-ic');
    await shot(page, 'logs');

    await page.goto(BASE + '/#/cai-dat');
    await page.waitForSelector('.tabs button.on');
    await sleep(600);
    await shot(page, 'settings-wireguard', { full: true });
    await page.click('.tabs button[data-k=web]');
    await shot(page, 'settings-web');
    await page.click('.tabs button[data-k=account]');
    await page.waitForSelector('.pw-meter');
    await shot(page, 'settings-account', { full: true });
    await page.click('.tabs button[data-k=backup]');
    await shot(page, 'settings-backup');

    await page.goto(BASE + '/#/gioi-thieu');
    await page.waitForSelector('.md h2');
    await shot(page, 'about', { full: true });

    /* trang chia sẻ công khai */
    const tok = await page.evaluate(async () => {
      const r = await fetch('/api/clients', { headers: { 'X-TWG': '1' } });
      const d = await r.json();
      const c = d.clients.find((x) => x.enabled);
      const s = await fetch('/api/clients/' + c.id + '/share', { method: 'POST', headers: { 'X-TWG': '1', 'Content-Type': 'application/json' }, body: '{"hours":72}' });
      return (await s.json()).token;
    });
    const pub = await newPage(browser);
    await pub.page.goto(BASE + '/s/' + tok);
    await pub.page.waitForSelector('.qr-box img');
    await shot(pub.page, 'share-page', { full: true });
    await pub.ctx.close();
    await ctx.close();
  }

  /* ---------- desktop tối ---------- */
  {
    const { ctx, page } = await newPage(browser, { dark: true });
    await login(page);
    await page.goto(BASE + '/#/tong-quan');
    await page.waitForSelector('.stat .val');
    await sleep(4500);
    await shot(page, 'dashboard-dark', { full: true });
    await page.goto(BASE + '/#/nguoi-dung');
    await page.waitForSelector('.client-table tbody tr .user-cell');
    await shot(page, 'clients-dark');
    await ctx.close();
  }

  /* ---------- điện thoại ---------- */
  {
    const { ctx, page } = await newPage(browser, { viewport: { width: 390, height: 844 }, scale: 3, mobile: true });
    await page.goto(BASE + '/');
    await page.waitForSelector('input[name=username]');
    await shot(page, 'mobile-login');
    await checkFit(page, 'đăng nhập (điện thoại)');
    await login(page);
    await page.goto(BASE + '/#/tong-quan');
    await page.waitForSelector('.stat .val');
    await sleep(3000);
    await shot(page, 'mobile-dashboard');
    await checkFit(page, 'tổng quan (điện thoại)');
    await page.goto(BASE + '/#/nguoi-dung');
    await page.waitForSelector('.client-cards .client-card');
    await shot(page, 'mobile-clients');
    await checkFit(page, 'người dùng (điện thoại)');
    await page.click('.menu-btn');
    await shot(page, 'mobile-menu', { wait: 500 });
    await page.click('.backdrop-nav', { position: { x: 360, y: 300 } });
    await page.click('.client-cards .client-card .btn.soft');
    await page.waitForSelector('.modal .qr-box img');
    await shot(page, 'mobile-qr', { wait: 1200 });
    await checkFit(page, 'mã QR (điện thoại)');
    for (const k of ['stats', 'info', 'share', 'guide']) {
      await page.click('.modal .tabs button[data-k=' + k + ']');
      await sleep(500);
      await checkFit(page, 'tab ' + k + ' (điện thoại)');
    }
    await page.keyboard.press('Escape');
    await sleep(300);
    await page.click('.topbar .btn.primary');
    await page.waitForSelector('.modal input.input');
    await sleep(400);
    await checkFit(page, 'form thêm người dùng (điện thoại)');
    await page.keyboard.press('Escape');
    for (const r of ['thong-ke', 'nhat-ky', 'cai-dat', 'gioi-thieu']) {
      await page.goto(BASE + '/#/' + r);
      await sleep(900);
      await checkFit(page, r + ' (điện thoại)');
      if (r === 'cai-dat') {
        for (const k of ['web', 'account', 'backup']) {
          await page.click('.tabs button[data-k=' + k + ']');
          await sleep(600);
          await checkFit(page, 'cài đặt/' + k + ' (điện thoại)');
        }
      }
    }
    const tok = await page.evaluate(async () => {
      const r = await fetch('/api/clients', { headers: { 'X-TWG': '1' } });
      const c = (await r.json()).clients.find((x) => x.enabled);
      const s = await fetch('/api/clients/' + c.id + '/share', { method: 'POST', headers: { 'X-TWG': '1', 'Content-Type': 'application/json' }, body: '{"hours":1}' });
      return (await s.json()).token;
    });
    await page.goto(BASE + '/s/' + tok);
    await page.waitForSelector('.qr-box img');
    await sleep(500);
    await checkFit(page, 'trang chia sẻ (điện thoại)');
    await ctx.close();
  }

  await browser.close();
  if (errors.length) {
    console.error('\nLỖI GIAO DIỆN:\n' + [...new Set(errors)].join('\n'));
    process.exit(1);
  }
  console.log('\nKhông có lỗi JavaScript.');
})().catch((e) => { console.error(e); process.exit(1); });
