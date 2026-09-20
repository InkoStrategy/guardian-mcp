'use strict';

/**
 * Checks every surface an OKX Dev Day judge can click, against the live deployment.
 * Run it before judging: `node scripts/devday-check.cjs`
 */

const BASE = process.env.GUARDIAN_BASE || 'https://guardian-mcp-rho.vercel.app';
const REPO = 'https://github.com/InkoStrategy/guardian-mcp';
const RAW = 'https://raw.githubusercontent.com/InkoStrategy/guardian-mcp/main';
const YT = 'https://youtu.be/hsvqdNWk5C4';

const results = [];
const pass = (name, detail) => results.push({ ok: true, name, detail });
const fail = (name, detail) => results.push({ ok: false, name, detail });

async function get(url, opts) {
  const res = await fetch(url, Object.assign({ redirect: 'follow' }, opts));
  return res;
}

async function checkPage(path, name) {
  try {
    const res = await get(BASE + path);
    res.status === 200 ? pass(name, path + ' → 200') : fail(name, path + ' → ' + res.status);
  } catch (e) { fail(name, path + ' → ' + e.message); }
}

async function mcp(method, params) {
  const res = await get(BASE + '/mcp', {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const text = await res.text();
  const line = text.split('\n').find((l) => l.startsWith('data:')) || text;
  return { status: res.status, headers: res.headers, body: JSON.parse(line.replace(/^data:\s*/, '')) };
}

async function main() {
  console.log('Checking ' + BASE + '\n');

  // 1. every page a judge lands on
  for (const [p, n] of [['/', 'API root'], ['/pay-safe', 'Pay-Safe page'], ['/trust', 'Trust scan page'],
    ['/company', 'Company page'], ['/agent-runs', 'Agent runs page'], ['/demo', 'Demo page'],
    ['/trust-scan', 'Latest scan JSON'], ['/trust-scans', 'Dated scan history'], ['/stats', 'Public stats']]) {
    await checkPage(p, n);
  }

  // 2. the videos and their captions must actually be served, not swallowed by the catch-all rewrite
  for (const [p, n, type] of [['/demo-short.webm', 'Short cut (34s)', 'video/webm'],
    ['/demo-v61.webm', 'Full cut (3:56)', 'video/webm'],
    ['/demo-v61.en.vtt', 'Captions (WebVTT)', 'text/vtt']]) {
    try {
      const res = await get(BASE + p, { method: 'HEAD' });
      const ct = res.headers.get('content-type') || '';
      if (res.status === 200 && ct.includes(type.split('/')[1])) pass(n, p + ' → 200 ' + ct.split(';')[0]);
      else fail(n, p + ' → ' + res.status + ' ' + ct);
    } catch (e) { fail(n, p + ' → ' + e.message); }
  }

  // 3. the MCP server OKX's own CLI talks to
  try {
    const r = await mcp('tools/list', {});
    const tools = (r.body.result && r.body.result.tools) || [];
    tools.length === 10 ? pass('MCP tools/list', tools.length + ' tools')
      : fail('MCP tools/list', 'expected 10 tools, got ' + tools.length);
  } catch (e) { fail('MCP tools/list', e.message); }

  // 4. the listing the demo video shows — it left the marketplace, so this must come from a dated snapshot
  try {
    const r = await mcp('tools/call', { name: 'check_listing', arguments: { sid: 39876 } });
    const text = JSON.stringify(r.body);
    /DENY/.test(text) ? pass('check_listing 39876', 'still returns DENY (dated snapshot)')
      : fail('check_listing 39876', 'no DENY in response');
  } catch (e) { fail('check_listing 39876', e.message); }

  // 5. the paid tool must still demand payment
  try {
    const r = await mcp('tools/call', { name: 'guard', arguments: { to: '0x0000000000000000000000000000000000000000', chainId: 1 } });
    const hdr = r.headers.get('payment-required');
    const paid = r.status === 402 || !!hdr || /402|payment/i.test(JSON.stringify(r.body));
    paid ? pass('Paid guard tool', 'returns an x402 challenge')
      : fail('Paid guard tool', 'no payment challenge (status ' + r.status + ')');
  } catch (e) { fail('Paid guard tool', e.message); }

  // 6. the flagship catch, live
  try {
    const res = await get(BASE + '/probe-payment', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: BASE + '/demo/x402/header-body-split' }),
    });
    const j = await res.json();
    j.verdict === 'DENY' && (j.reasons || []).includes('challenge_header_body_mismatch')
      ? pass('Header/body split catch', 'DENY challenge_header_body_mismatch')
      : fail('Header/body split catch', 'got ' + j.verdict + ' ' + (j.reasons || []).join(','));
  } catch (e) { fail('Header/body split catch', e.message); }

  // 7. the on-chain fact behind the EIP-712 finding
  try {
    const j = await (await get(BASE + '/verify-eip712-domain')).json();
    j.accepted && j.accepted.name === 'USD₮0' && j.accepted.version === '1'
      ? pass('EIP-712 on-chain read', 'contract accepts only USD₮0 / 1')
      : fail('EIP-712 on-chain read', JSON.stringify(j.accepted));
  } catch (e) { fail('EIP-712 on-chain read', e.message); }

  // 8. the scan history the judge is told grows daily
  try {
    const j = await (await get(BASE + '/trust-scans')).json();
    const snaps = j.snapshots || j.history || [];
    const last = snaps[snaps.length - 1];
    snaps.length >= 3 && last && last.totals.services >= 40
      ? pass('Scan history', snaps.length + ' dated scans, newest ' + last.date + ' with ' + last.totals.services + ' services')
      : fail('Scan history', 'only ' + snaps.length + ' snapshots');
  } catch (e) { fail('Scan history', e.message); }

  // 9. what the submission form points at
  for (const [url, n] of [[REPO, 'GitHub repo'], [RAW + '/README.md', 'README'], [RAW + '/DEVDAY.md', 'DEVDAY.md judge doc']]) {
    try {
      const res = await get(url);
      res.status === 200 ? pass(n, 'public, 200') : fail(n, res.status + '');
    } catch (e) { fail(n, e.message); }
  }
  try {
    const html = await (await get(YT, { headers: { 'user-agent': 'Mozilla/5.0' } })).text();
    const m = html.match(/"lengthSeconds":"(\d+)"/);
    const secs = m ? Number(m[1]) : 0;
    secs >= 120 && secs <= 240
      ? pass('YouTube demo', secs + 's — inside the form\'s 2–4 minute rule')
      : fail('YouTube demo', secs ? secs + 's is outside 2–4 minutes' : 'could not read the video');
  } catch (e) { fail('YouTube demo', e.message); }

  // ---- report
  console.log('');
  for (const r of results) console.log((r.ok ? '  PASS  ' : '  FAIL  ') + r.name.padEnd(26) + r.detail);
  const bad = results.filter((r) => !r.ok);
  console.log('\n' + (results.length - bad.length) + '/' + results.length + ' checks passed');
  if (bad.length) { console.log('\nBROKEN:'); for (const r of bad) console.log('  - ' + r.name + ': ' + r.detail); }
  return bad.length ? 1 : 0;
}

main().then((c) => process.exit(c)).catch((e) => { console.error(e); process.exit(1); });
