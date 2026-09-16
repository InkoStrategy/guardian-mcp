'use strict';
/**
 * Capture real states of the live /pay-safe page and render the slides, all at 1920x1080 scale.
 * Output: build/frames/*.jpg and build/frames/meta.json (element boxes in CSS pixels, scale 1.5).
 */
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('C:/Users/mynam/Desktop/VASYA/project-os/node_modules/playwright-core');

const OUT = path.join(__dirname, 'build', 'frames');
fs.mkdirSync(OUT, { recursive: true });
const URL = 'https://guardian-mcp-rho.vercel.app/pay-safe';
const SCALE = 1.5;
const SCENARIOS = [
  { key: 'honest', title: 'Honest seller', verdict: 'ALLOW' },
  { key: 'bait', title: 'Price bait-and-switch', verdict: 'DENY' },
  { key: 'payee', title: 'Poisoned payee', verdict: 'DENY' },
  { key: 'domain', title: 'Wrong EIP-712 domain', verdict: 'WARN' },
  { key: 'shellurl', title: 'Shell payload in the URL', verdict: 'DENY' },
];

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 720 }, deviceScaleFactor: SCALE, colorScheme: 'dark' });
  const page = await context.newPage();
  const meta = { scale: SCALE, viewport: { width: 1280, height: 720 }, states: {}, slides: [], imageScanTop: {} };

  // slides
  await page.goto('file:///' + path.join(__dirname, 'slides.html').replace(/\\/g, '/'));
  await page.evaluate(() => document.fonts.ready);
  for (const id of ['S1', 'S2', 'S10', 'S11', 'S13', 'S12']) {
    await page.evaluate((s) => window.show(s), id);
    await page.screenshot({ path: path.join(OUT, 'slide-' + id + '.jpg'), type: 'jpeg', quality: 95 });
    meta.slides.push(id);
  }

  // live page
  await page.goto(URL, { waitUntil: 'networkidle' });
  await page.waitForSelector('button.sc');
  await page.waitForSelector('#scanKpi .card');
  await page.waitForFunction(() => document.querySelectorAll('#scanFindings li').length > 3);
  await page.mouse.move(1260, 10);
  const boxOf = (sel) => page.evaluate((s) => { const e = document.querySelector(s); if (!e) return null; const r = e.getBoundingClientRect(); return { x: r.x + scrollX, y: r.y + scrollY, w: r.width, h: r.height }; }, sel);
  const shot = async (name, full) => {
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: path.join(OUT, name + '.jpg'), type: 'jpeg', quality: 92, fullPage: true, clip: full ? undefined : { x: 0, y: 0, width: 1280, height: 1500 } });
    const info = await page.evaluate(() => { const lead = document.querySelector('#scanLead'); const h2 = lead.previousElementSibling; return { docHeight: document.documentElement.scrollHeight, scanTop: (h2 ? h2.getBoundingClientRect().top : lead.getBoundingClientRect().top) + scrollY }; });
    meta.imageScanTop[name + '.jpg'] = info.scanTop;
    return Object.assign({ file: name + '.jpg' }, info);
  };
  meta.states.base = await shot('page-base');
  meta.buttons = await page.evaluate(() => [...document.querySelectorAll('button.sc')].map((b) => { const r = b.getBoundingClientRect(); return { title: b.querySelector('.t').textContent, x: r.x + scrollX, y: r.y + scrollY, w: r.width, h: r.height }; }));
  meta.form = await boxOf('#custom');
  meta.feeLabel = await boxOf('label[for=fee]');

  for (const s of SCENARIOS) {
    const btn = page.locator('button.sc', { hasText: s.title }).first();
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.waitForTimeout(400);
    await btn.hover();
    await page.waitForTimeout(250);
    const hover = await shot('page-' + s.key + '-hover');
    await page.evaluate(() => window.scrollTo(0, 0));
    await btn.click();
    const loading = await shot('page-' + s.key + '-loading');
    await page.waitForSelector('#result .badge.' + s.verdict, { timeout: 45000 });
    await page.mouse.move(1260, 10);
    await page.waitForTimeout(900);
    const result = await shot('page-' + s.key + '-result');
    meta.states[s.key] = { hover, loading, result, resultBox: await boxOf('#result'), scanLead: await boxOf('#scanLead'), scanKpi: await boxOf('#scanKpi'), scanFindings: await boxOf('#scanFindings'), badge: await page.textContent('#result .badge') };
    console.log(s.key, meta.states[s.key].badge, JSON.stringify(meta.states[s.key].resultBox));
  }
  meta.states.scanShot = await shot('page-scan', true);
  meta.scan = { scanLead: await boxOf('#scanLead'), scanKpi: await boxOf('#scanKpi'), scanFindings: await boxOf('#scanFindings') };
  meta.scan.denyRowsHeight = await page.evaluate(() => { const lis = [...document.querySelectorAll('#scanFindings li')]; const top = document.querySelector('#scanFindings').getBoundingClientRect().top; let bottom = top; for (const li of lis) { if (li.querySelector('.sev.DENY')) bottom = li.getBoundingClientRect().bottom; } return bottom - top; });
  console.log('scan', JSON.stringify(meta.scan));
  fs.writeFileSync(path.join(OUT, 'meta.json'), JSON.stringify(meta, null, 1));
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
