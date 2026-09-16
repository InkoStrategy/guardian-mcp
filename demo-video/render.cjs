'use strict';
/**
 * Build plan.json, synthesize the voice-over, render the demo video in headless Chromium and fix its duration.
 *
 *   node render.cjs                    full video -> out/guardian-pay-safe-demo.webm
 *   node render.cjs --from S3 --to S4  partial pilot -> build/pilot.webm
 *   node render.cjs --skip-tts         reuse build/audio
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { chromium } = require('C:/Users/mynam/Desktop/VASYA/project-os/node_modules/playwright-core');
const { fix } = require('./webm-duration.cjs');

const ROOT = __dirname;
const BUILD = path.join(ROOT, 'build');
const OUTDIR = path.join(ROOT, 'out');
const argv = process.argv.slice(2);
const opt = (k) => { const i = argv.indexOf('--' + k); return i >= 0 ? argv[i + 1] : undefined; };
const flag = (k) => argv.includes('--' + k);

function readCapture(name) {
  const lines = fs.readFileSync(path.join(ROOT, 'captures', name), 'utf8').replace(/\r/g, '').split('\n').filter((l, i, a) => !(l === '' && i === a.length - 1));
  return lines;
}

function buildPlan() {
  const narration = JSON.parse(fs.readFileSync(path.join(ROOT, 'narration.json'), 'utf8'));
  const meta = JSON.parse(fs.readFileSync(path.join(BUILD, 'frames', 'meta.json'), 'utf8'));
  const visuals = {
    S1: { type: 'slide', img: 'slide-S1.jpg' },
    S2: { type: 'slide', img: 'slide-S2.jpg' },
    S3: { type: 'page', key: 'honest', button: 'Honest seller', clickCue: 2, leadHighlights: { cue: 1, fractions: [0.0, 0.42, 0.68] } },
    S4: { type: 'page', key: 'bait', button: 'Price bait-and-switch' },
    S5: { type: 'page', key: 'payee', button: 'Poisoned payee', payeeCard: { cue: 1 } },
    S6: { type: 'page', key: 'domain', button: 'Wrong EIP-712 domain', domainCallout: true },
    S7: { type: 'page', key: 'shellurl', button: 'Shell payload in the URL' },
    S8: { type: 'scan' },
    S9: { type: 'terminal' },
    S10: { type: 'slide', img: 'slide-S10.jpg' },
    S11: { type: 'slide', img: 'slide-S11.jpg' },
    S13: { type: 'slide', img: 'slide-S13.jpg' },
    S12: { type: 'slide', img: 'slide-S12.jpg' },
  };
  const terminal = [
    { label: 'attack listing: endpoint never contacted', cmd: 'node scripts/safe-pay.js --sid 39876 --agent 13761', lines: readCapture('safepay-attack.txt'), weight: 0.27 },
    { label: 'marketplace seller, wrong EIP-712 domain: stopped on WARN', cmd: 'node scripts/safe-pay.js --sid 33342 --agent 13761 --param scoutMode=best', lines: readCapture('safepay-eip712.txt'), weight: 0.36 },
    { label: 'marketplace listing: ALLOW, quote matches, pay command printed', cmd: 'node scripts/safe-pay.js --sid 39856 --agent 13761 --max 0.01', lines: readCapture('safepay-listing.txt'), weight: 0.37 },
  ];
  for (const sc of narration.scenes) if (!visuals[sc.id]) throw new Error('no visual for ' + sc.id);
  // payee inset card: the demo listing wallet vs the poisoned payTo, checksummed like the page shows them
  const { getAddress } = require('C:/Users/mynam/guardian-mcp/node_modules/ethers');
  const demo = require('C:/Users/mynam/guardian-mcp/src/demo-sellers.js');
  const payee = { expected: getAddress(demo.DEMO_PAY_TO), payTo: getAddress(demo.SCENARIOS['payee-swap'].entry.payTo) };
  // scan cards from the published report
  const scan = JSON.parse(fs.readFileSync('C:/Users/mynam/guardian-mcp/docs/trust-scan.json', 'utf8'));
  const eip712 = [];
  const advisory = {};
  for (const r of scan.results) {
    if (r.verdict !== 'WARN') continue;
    for (const f of r.findings || []) {
      if (f.code === 'eip712_domain_mismatch') {
        const m = f.message.match(/name "([^"]*)" version "([^"]*)"/);
        eip712.push({ service: r.service, sid: r.sid, name: m ? m[1] : '?', version: m ? m[2] : '?' });
      } else if (f.severity === 'WARN') {
        advisory[f.code] = advisory[f.code] || new Set();
        advisory[f.code].add(r.sid);
      }
    }
  }
  const scanCards = { eip712, advisory: Object.fromEntries(Object.entries(advisory).map(([k, v]) => [k, v.size])), totals: scan.totals };
  const plan = { scenes: narration.scenes, visuals, meta, terminal, payee, scanCards, terminalCues: [1, 2, 3], scanCues: { kpi: 1, deny: 3, warn: 4, advisory: 5 } };
  fs.writeFileSync(path.join(BUILD, 'plan.json'), JSON.stringify(plan, null, 1));
  return plan;
}

function serve() {
  const types = { '.html': 'text/html; charset=utf-8', '.json': 'application/json', '.jpg': 'image/jpeg', '.wav': 'audio/wav', '.webm': 'video/webm' };
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const url = decodeURIComponent(req.url.split('?')[0]);
      if (req.method === 'POST' && url.startsWith('/save/')) {
        const out = fs.createWriteStream(path.join(BUILD, path.basename(url)));
        req.pipe(out);
        out.on('finish', () => res.end('ok'));
        return;
      }
      let file;
      if (url === '/' || url === '/compose.html') file = path.join(ROOT, 'compose.html');
      else if (url === '/plan.json') file = path.join(BUILD, 'plan.json');
      else if (url.startsWith('/frames/')) file = path.join(BUILD, 'frames', path.basename(url));
      else if (url.startsWith('/audio/')) file = path.join(BUILD, 'audio', path.basename(url));
      else if (url.startsWith('/build/')) file = path.join(BUILD, path.basename(url));
      if (!file || !fs.existsSync(file)) { res.statusCode = 404; return res.end(); }
      res.setHeader('content-type', types[path.extname(file)] || 'application/octet-stream');
      fs.createReadStream(file).pipe(res);
    }).listen(0, '127.0.0.1', () => resolve(server));
  });
}

(async () => {
  fs.mkdirSync(OUTDIR, { recursive: true });
  buildPlan();
  if (!flag('skip-tts')) {
    const r = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.join(ROOT, 'tts.ps1')], { encoding: 'utf8' });
    process.stdout.write(r.stdout || '');
    if (r.status !== 0) { console.error(r.stderr); process.exit(1); }
  }
  const server = await serve();
  const base = 'http://127.0.0.1:' + server.address().port;
  const browser = await chromium.launch({ headless: true, args: ['--autoplay-policy=no-user-gesture-required'] });
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
  page.on('console', (m) => { if (m.type() === 'error') console.log('page error:', m.text()); });
  page.on('pageerror', (e) => console.log('page exception:', e.message));
  await page.goto(base + '/compose.html');
  const partial = Boolean(opt('from') || opt('to'));
  const outName = partial ? 'pilot.webm' : 'render.webm';
  const started = Date.now();
  const result = await page.evaluate((o) => window.renderVideo(o), { from: opt('from'), to: opt('to'), out: outName, mime: opt('mime'), bitrate: opt('bitrate') ? Number(opt('bitrate')) : undefined });
  await browser.close();
  server.close();
  console.log(JSON.stringify(Object.assign({ wallSeconds: Math.round((Date.now() - started) / 1000) }, result)));
  const raw = fs.readFileSync(path.join(BUILD, outName));
  const target = partial ? path.join(BUILD, 'pilot-fixed.webm') : path.join(OUTDIR, 'guardian-pay-safe-demo.webm');
  fs.writeFileSync(target, fix(raw, result.seconds));
  console.log('wrote', target, fs.statSync(target).size, 'bytes');
})().catch((e) => { console.error(e); process.exit(1); });
