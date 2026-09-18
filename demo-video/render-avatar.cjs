'use strict';

/** Renders demo-video/avatar.html to a 1024x1024 PNG for the Dev Day "Team Display Picture" field. */
const path = require('path');
const fs = require('fs');
const { pathToFileURL } = require('url');
const { chromium } = require(path.join('C:/Users/mynam/Desktop/VASYA/project-os/node_modules', 'playwright-core'));

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1024, height: 1024 }, deviceScaleFactor: 1 });
  await page.goto(pathToFileURL(path.resolve(__dirname, 'avatar.html')).href);
  await page.waitForTimeout(400);
  const out = path.resolve(__dirname, 'out', 'team-avatar.png');
  await page.screenshot({ path: out });
  await browser.close();
  console.log('wrote ' + out + '  (' + (fs.statSync(out).size / 1024).toFixed(0) + ' KB, 1024x1024)');
})();
