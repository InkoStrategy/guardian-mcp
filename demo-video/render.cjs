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
    S0: { type: 'terminal', blocks: 'coldopen', cues: [0], header: 'A real AI agent · about to pay a scam on OKX.AI', min: 8 },
    S1: { type: 'slide', img: 'slide-S1.jpg' },
    S2: { type: 'slide', img: 'slide-S2.jpg' },
    S3: { type: 'page', key: 'honest', button: 'Honest seller', clickCue: 1, leadHighlights: { cue: 0, fractions: [0.0, 0.42, 0.68] } },
    S4: { type: 'page', key: 'bait', button: 'Price bait-and-switch' },
    S5: { type: 'page', key: 'payee', button: 'Poisoned payee', payeeCard: { cue: 0 } },
    S6: { type: 'page', key: 'domain', button: 'Wrong EIP-712 domain', domainCallout: true },
    S7: { type: 'scan' },
    S8: { type: 'terminal', blocks: 'mcp', cues: [0, 2], header: "OKX Onchain OS CLI  ·  onchainos payment quote → GuardianMCP /mcp", min: 22 },
    S9: { type: 'terminal', blocks: 'gate', cues: [0, 2, 3], header: 'Onchain OS payment gate  ·  check-quote + Claude Code hook', min: 26 },
    S9B: { type: 'terminal', blocks: 'agentrun', cues: [0, 1, 2], header: 'Unedited headless AI agent  ·  real Onchain OS CLI  ·  claude -p', min: 24 },
    S10: { type: 'terminal', blocks: 'goodpay', cues: [0, 1], header: 'Onchain OS buyer  ·  node scripts/safe-pay.js  ·  real payment' },
    S12: { type: 'slide', img: 'slide-S12.jpg' },
  };
  const terminal = [
    { label: 'attack listing: endpoint never contacted', cmd: 'node scripts/safe-pay.js --sid 39876 --agent 13761', lines: readCapture('safepay-attack.txt'), weight: 0.27 },
    { label: 'marketplace seller, wrong EIP-712 domain: stopped on WARN', cmd: 'node scripts/safe-pay.js --sid 33342 --agent 13761 --param scoutMode=best', lines: readCapture('safepay-eip712.txt'), weight: 0.36 },
    { label: 'marketplace listing: ALLOW, quote matches, owner-approved payment', cmd: 'node scripts/safe-pay.js --sid 39856 --agent 13761 --max 0.01 --method POST --param url=https://guardian-mcp-rho.vercel.app/pay-safe --pay --yes', lines: readCapture('safepay-paid.txt'), weight: 0.3, fontSize: 21 },
    { label: 'settlement verified on X Layer', cmd: 'node scripts/verify-settlement.js --tx 0xd0dab0bb9ae26fd68b4772d2a7f197314ec296a606530077a233c3769cf3070d --pay-to 0xc4622689eb6c38c929fe254777b449a5dedf9d60 --amount 5000 --payer 0xe1c6f89df50fb68282d52e34d6001d65005ff67b', lines: readCapture('settlement.txt'), weight: 0.2, highlight: 'Settled   as checked' },
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
  // Extra terminal block sets for the MCP-server and payment-gate scenes (built in the 17 Sep window).
  // Content is the real CLI output captured live on 17 Sep (captures/mcp-discover.txt, gate-split.txt).
  const terminals = {
    mcp: [
      { label: "OKX's own CLI discovers the MCP server", cmd: 'onchainos payment quote https://guardian-mcp-rho.vercel.app/mcp',
        lines: ['MCP server exposes 10 tool(s): check_payment, probe_payment,', 'check_quote, verify_settlement, check_listing, check_address,', 'check_domain, analyze_transaction, analyze_signature, guard'], weight: 0.45 },
      { label: 'ask the check_listing tool about the real malicious listing sid 39876', cmd: 'onchainos payment quote .../mcp --tool check_listing --param sid=39876',
        lines: ['service   Market Signal API,  seller Atlas Data API #11194', 'listed    0.00001 USDT,  endpoint on 0m.ar', 'verdict   DENY', 'reasons   endpoint_url_injection, challenge_field_injection,', '          long_payment_timeout, eip712_domain_mismatch'], weight: 0.55 },
    ],
    gate: [
      { label: 'the wallet quote saves the header payee; its summary never names it', cmd: 'onchainos payment quote .../demo/x402/header-body-split',
        lines: ['Will pay 0.001 USDT (exact, X Layer)', 'the CLI saved payee 0x5b0c...1A09 from the header;', 'the 402 body instead shows 0xe1c6...f67b'], weight: 0.36 },
      { label: 'Guardian checks the saved quote and binds the verdict', cmd: 'node scripts/check-quote.js --payment-id pay_adde... --fee 0.001 --token 0x779d...',
        lines: ['Verdict   DENY challenge_header_body_mismatch', 'the 402 body shows one payment, the entry payment pay signs pays another', 'Bound     onchainos payment pay is now blocked for this quote'], weight: 0.34 },
      { label: 'the Claude Code hook blocks the payment', cmd: 'onchainos payment pay --payment-id pay_adde... --yes',
        lines: ['deny -- GuardianMCP: DENY challenge_header_body_mismatch'], weight: 0.3 },
    ],
    goodpay: [
      { label: 'real listing sid 39856: ALLOW, quote matches, owner-approved payment', cmd: 'node scripts/safe-pay.js --sid 39856 --agent 13761 --max 0.01 --method POST --pay --yes', lines: readCapture('safepay-paid.txt'), weight: 0.6, fontSize: 21 },
      { label: 'settlement verified on X Layer', cmd: 'node scripts/verify-settlement.js --tx 0xd0dab0bb...3070d --pay-to 0xc462...9d60 --amount 5000', lines: readCapture('settlement.txt'), weight: 0.4, highlight: 'as checked' },
    ],
    // Cold open: a real agent's pay hitting the hook, shown before the title.
    coldopen: [
      { label: 'a real headless AI agent, about to pay a scam listing', cmd: 'onchainos payment pay --payment-id pay_3e11b4... --selected-index 0 --yes',
        lines: ['deny -- GuardianMCP: DENY challenge_header_body_mismatch, fresh_recipient', 'the seller shows one wallet in the body and pays another in the header', 'agent: the payment was blocked, and correctly so.'], weight: 1 },
    ],
    // The unedited headless agent run (demo-video/captures/agent-runs/guardian-header-body-split.md).
    agentrun: [
      { label: 'the agent quotes the seller', cmd: 'onchainos payment quote .../demo/x402/header-body-split',
        lines: ['Will pay 0.001 USDT (exact, X Layer)', 'agent: decoded payee 0x5b0c...1A09 does not match the body wallet 0xe1c6...f67b'], weight: 0.3 },
      { label: 'the agent checks the quote with Guardian', cmd: 'node scripts/check-quote.js --payment-id pay_3e11b4... --fee 0.001 --token 0x779d...',
        lines: ['Verdict   DENY challenge_header_body_mismatch, fresh_recipient', 'Next      do not pay this quote. No pay command on DENY.'], weight: 0.34 },
      { label: 'the agent tries to pay anyway; the hook blocks it', cmd: 'onchainos payment pay --payment-id pay_3e11b4... --selected-index 0 --yes',
        lines: ['deny -- GuardianMCP: DENY challenge_header_body_mismatch, fresh_recipient', 'agent: the payment was blocked, and correctly so.'], weight: 0.36 },
    ],
  };
  const plan = { scenes: narration.scenes, visuals, meta, terminal, terminals, payee, scanCards, terminalCues: [1, 2, 3, 5], scanCues: { kpi: 1, deny: 3, warn: 4, advisory: 5 } };
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
