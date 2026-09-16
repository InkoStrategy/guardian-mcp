'use strict';
// Export sentence timings of the rendered video: build/timeline.json and out/guardian-pay-safe-demo.en.srt
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('C:/Users/mynam/Desktop/VASYA/project-os/node_modules/playwright-core');
const ROOT = __dirname, BUILD = path.join(ROOT, 'build');
const PRE = 0.4; // black pre-roll before the first scene in render output
const server = http.createServer((req, res) => {
  const url = decodeURIComponent(req.url.split('?')[0]);
  let file = null;
  if (url === '/compose.html') file = path.join(ROOT, 'compose.html');
  else if (url === '/plan.json') file = path.join(BUILD, 'plan.json');
  else if (url.startsWith('/audio/')) file = path.join(BUILD, 'audio', path.basename(url));
  if (!file || !fs.existsSync(file)) { res.statusCode = 404; return res.end(); }
  fs.createReadStream(file).pipe(res);
}).listen(0, '127.0.0.1', async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto('http://127.0.0.1:' + server.address().port + '/compose.html');
  const tl = await page.evaluate(() => window.getTimeline());
  await browser.close(); server.close();
  for (const s of tl.scenes) { s.start += PRE; for (const x of s.sentences) { x.start += PRE; x.end += PRE; } }
  fs.writeFileSync(path.join(BUILD, 'timeline.json'), JSON.stringify(tl, null, 1));
  const ts = (t) => { const ms = Math.round(t * 1000); const h = Math.floor(ms / 3600000), m = Math.floor(ms / 60000) % 60, s = Math.floor(ms / 1000) % 60, r = ms % 1000; return String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0') + ',' + String(r).padStart(3, '0'); };
  const all = tl.scenes.flatMap((s) => s.sentences);
  const srt = all.map((x, i) => (i + 1) + '\n' + ts(x.start) + ' --> ' + ts(Math.min(x.end + 0.25, all[i + 1] ? all[i + 1].start - 0.02 : x.end + 0.6)) + '\n' + x.display + '\n').join('\n');
  fs.mkdirSync(path.join(ROOT, 'out'), { recursive: true });
  fs.writeFileSync(path.join(ROOT, 'out', 'guardian-pay-safe-demo.en.srt'), srt);
  for (const s of tl.scenes) console.log(s.id, s.type, s.start.toFixed(2), '+' + s.duration.toFixed(2), '|', s.sentences.map((x) => x.start.toFixed(1) + '-' + x.end.toFixed(1) + ' ' + x.display).join(' || '));
});
