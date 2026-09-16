'use strict';
/**
 * Inspect a rendered WebM in Chromium: duration, frames at given times (PNG), audio loudness per second.
 *   node verify.cjs build/pilot-fixed.webm 1,5,12.5 [--prefix pilot]
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('C:/Users/mynam/Desktop/VASYA/project-os/node_modules/playwright-core');

const file = path.resolve(process.argv[2]);
const times = (process.argv[3] || '1').split(',').map(Number);
const pi = process.argv.indexOf('--prefix');
const prefix = pi > 0 ? process.argv[pi + 1] : 'frame';
const CHECK = path.join(__dirname, 'build', 'check');
fs.mkdirSync(CHECK, { recursive: true });

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url.startsWith('/save/')) {
    const out = fs.createWriteStream(path.join(CHECK, path.basename(req.url)));
    req.pipe(out); out.on('finish', () => res.end('ok')); return;
  }
  if (req.url === '/') { res.setHeader('content-type', 'text/html'); return res.end('<video id=v muted></video><canvas id=c width=1920 height=1080></canvas>'); }
  if (req.url === '/video.webm') {
    const stat = fs.statSync(file);
    const range = req.headers.range;
    if (range) {
      const [s, e] = range.replace('bytes=', '').split('-');
      const start = Number(s); const end = e ? Number(e) : stat.size - 1;
      res.writeHead(206, { 'content-range': `bytes ${start}-${end}/${stat.size}`, 'accept-ranges': 'bytes', 'content-length': end - start + 1, 'content-type': 'video/webm' });
      return fs.createReadStream(file, { start, end }).pipe(res);
    }
    res.writeHead(200, { 'content-length': stat.size, 'content-type': 'video/webm', 'accept-ranges': 'bytes' });
    return fs.createReadStream(file).pipe(res);
  }
  res.statusCode = 404; res.end();
}).listen(0, '127.0.0.1', async () => {
  const base = 'http://127.0.0.1:' + server.address().port;
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto(base + '/');
  const report = await page.evaluate(async ({ times, prefix }) => {
    const v = document.getElementById('v');
    const c = document.getElementById('c');
    const g = c.getContext('2d');
    v.src = '/video.webm';
    await new Promise((r, j) => { v.onloadedmetadata = r; v.onerror = () => j(new Error('video error ' + (v.error && v.error.message))); });
    const out = { duration: v.duration, width: v.videoWidth, height: v.videoHeight, frames: [] };
    for (const t of times) {
      await new Promise((r) => { v.onseeked = r; v.currentTime = Math.min(t, v.duration - 0.05); });
      await new Promise((r) => setTimeout(r, 120));
      g.drawImage(v, 0, 0, 1920, 1080);
      const blob = await new Promise((r) => c.toBlob(r, 'image/jpeg', 0.85));
      const name = prefix + '-' + String(t).replace('.', '_') + '.jpg';
      await fetch('/save/' + name, { method: 'POST', body: blob });
      out.frames.push(name);
    }
    const ab = await (await fetch('/video.webm')).arrayBuffer();
    const ac = new OfflineAudioContext(1, 48000, 48000);
    const buf = await ac.decodeAudioData(ab);
    const data = buf.getChannelData(0);
    const sr = buf.sampleRate;
    const perSecond = [];
    for (let s = 0; s * sr < data.length; s++) {
      let sum = 0; let n = 0;
      for (let i = s * sr; i < Math.min(data.length, (s + 1) * sr); i += 16) { sum += data[i] * data[i]; n++; }
      perSecond.push(Math.round(Math.sqrt(sum / Math.max(1, n)) * 1000) / 1000);
    }
    out.audioSeconds = buf.duration;
    out.rmsPerSecond = perSecond;
    return out;
  }, { times, prefix });
  console.log(JSON.stringify(report));
  await browser.close();
  server.close();
});
