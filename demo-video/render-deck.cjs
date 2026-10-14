'use strict';

/** Renders demo-video/deck.html to a print-ready PDF (one 16:9 page per slide) for the Dev Day form. */
const path = require('path');
const fs = require('fs');
const { pathToFileURL } = require('url');
const { chromium } = require(path.join('C:/Users/mynam/Desktop/VASYA/project-os/node_modules', 'playwright-core'));

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1600, height: 900 } });
  await page.goto(pathToFileURL(path.resolve(__dirname, 'deck.html')).href, { waitUntil: 'networkidle' });
  await page.waitForTimeout(500);

  const out = path.resolve(__dirname, 'out', 'GuardianMCP-PaySafe-LNO-Alpha.pdf');
  await page.pdf({
    path: out,
    width: '1600px',
    height: '900px',
    printBackground: true,
    margin: { top: '0', right: '0', bottom: '0', left: '0' },
    pageRanges: '1-8',
  });

  // A PNG of slide 1 is handy wherever a deck cannot be uploaded.
  const cover = path.resolve(__dirname, 'out', 'deck-cover.png');
  await page.screenshot({ path: cover, clip: { x: 0, y: 0, width: 1600, height: 900 } });

  await browser.close();
  console.log('PDF   : ' + out + '  (' + (fs.statSync(out).size / 1048576).toFixed(2) + ' MB)');
  console.log('cover : ' + cover + '  (' + (fs.statSync(cover).size / 1024).toFixed(0) + ' KB)');
})();
