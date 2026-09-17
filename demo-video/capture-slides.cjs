'use strict';
// Re-capture only the slide images from slides.html, leaving live-page frames and meta.json untouched.
const path = require('node:path');
const { chromium } = require('C:/Users/mynam/Desktop/VASYA/project-os/node_modules/playwright-core');
const OUT = path.join(__dirname, 'build', 'frames');
const ids = process.argv.slice(2).length ? process.argv.slice(2) : ['S1', 'S2', 'S12'];
(async () => {
  const b = await chromium.launch({ headless: true });
  const ctx = await b.newContext({ viewport: { width: 1280, height: 720 }, deviceScaleFactor: 1.5, colorScheme: 'dark' });
  const p = await ctx.newPage();
  await p.goto('file:///' + path.join(__dirname, 'slides.html').replace(/\\/g, '/'));
  await p.evaluate(() => document.fonts.ready);
  for (const id of ids) {
    await p.evaluate((s) => window.show(s), id);
    await p.waitForTimeout(150);
    await p.screenshot({ path: path.join(OUT, 'slide-' + id + '.jpg'), type: 'jpeg', quality: 95 });
    console.log('captured slide-' + id + '.jpg');
  }
  await b.close();
})().catch((e) => { console.error(e.message); process.exit(1); });
