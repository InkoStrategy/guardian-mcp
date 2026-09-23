'use strict';

/**
 * OKX.AI Pay-Safe trust scan.
 *
 * For every paid A2MCP service listed on OKX.AI: request the endpoint once WITHOUT paying, capture the x402
 * challenge (PAYMENT-REQUIRED header, v1 402 body, or an MCP tools/call 402 / JSON-RPC error), and run Pay-Safe against the marketplace listing
 * (listed price, listed token, listed endpoint). Nothing is paid or signed.
 *
 *   node scripts/okxai-trust-scan.js [--limit 80] [--concurrency 2] [--guardian https://guardian-mcp-rho.vercel.app] [--local]
 *
 * Needs the onchainos CLI (logged in) to read marketplace listings. Writes docs/trust-scan.json and docs/trust-scan.md.
 */

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { fetchChallenge, challengeOf } = require('../src/x402-probe');

const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
// 80 was a ceiling, not a measurement: the 18 Sep scan returned exactly 80 because that was the cap,
// which made the following days look like a decline. Keep this comfortably above the real catalogue.
const LIMIT = Number(arg('limit', 250));
const GUARDIAN = arg('guardian', 'https://guardian-mcp-rho.vercel.app');
const LOCAL = process.argv.includes('--local');
const CONCURRENCY = Math.max(1, Number(arg('concurrency', 2)));
const ONCHAINOS = process.env.ONCHAINOS_BIN || (process.platform === 'win32' ? path.join(process.env.USERPROFILE || '', '.local', 'bin', 'onchainos.exe') : 'onchainos');
const KEYWORDS = ['market data', 'trading signals', 'token analysis', 'security', 'research', 'crypto', 'defi', 'wallet', 'news', 'api', 'data', 'ai', 'image', 'polymarket', 'x layer'];

function cli(args) {
  const r = spawnSync(ONCHAINOS, args, { encoding: 'utf8', maxBuffer: 32e6, windowsHide: true });
  const out = r.stdout || '';
  const i = out.indexOf('{');
  try { return JSON.parse(out.slice(i)); } catch { return null; }
}

function listings() {
  const seen = new Map();
  for (const kw of KEYWORDS) {
    let after = null;
    for (let page = 0; page < 5 && seen.size < LIMIT * 3; page++) {
      const args = ['agent', 'service-match', '--keywords', kw, '--min-payment-token-amount', '0.000001', '--limit', '10'];
      if (after) args.push('--search-after', after);
      const j = cli(args);
      const data = j && j.data;
      if (!data || !Array.isArray(data.services)) break;
      for (const s of data.services) {
        if (s.serviceType !== 'A2MCP' || !s.endpoint || !(Number(s.feeAmount) > 0)) continue;
        if (!seen.has(s.sid)) seen.set(s.sid, { sid: s.sid, serviceName: s.serviceName, endpoint: s.endpoint, feeAmount: Number(s.feeAmount), feeToken: s.feeToken, feeTokenSymbol: s.feeTokenSymbol, aspAgentId: s.asp && s.asp.aspAgentId, aspName: s.asp && s.asp.aspName, soldCount: s.asp && s.asp.soldCount, keyword: kw });
      }
      if (!data.hasMore || !data.searchAfter) break;
      after = data.searchAfter;
    }
  }
  return [...seen.values()].slice(0, LIMIT);
}

async function check(body) {
  if (LOCAL) return require('../src/paysafe').checkPayment(body, {});
  const res = await fetch(GUARDIAN + '/check-payment', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const j = await res.json();
  if (res.status !== 200) throw new Error(j.error || 'HTTP ' + res.status);
  return j;
}

async function main() {
  const services = listings();
  console.error('listed paid A2MCP services:', services.length);
  const results = [];
  const queue = services.slice();
  const worker = async () => {
    while (queue.length) {
      const s = queue.shift();
      const row = { sid: s.sid, service: s.serviceName, asp: s.aspName, aspAgentId: s.aspAgentId, endpoint: s.endpoint, listed: { feeAmount: s.feeAmount, feeToken: s.feeToken, symbol: s.feeTokenSymbol } };
      const ch = await fetchChallenge(s.endpoint);
      if (ch.error) { row.probe = 'unreachable'; row.detail = ch.error; results.push(row); continue; }
      row.http = { method: ch.method, status: ch.status };
      const challenge = challengeOf(ch);
      if (!challenge) { row.probe = ch.status === 402 ? '402_without_x402_challenge' : 'no_payment_challenge'; results.push(row); continue; }
      row.probe = 'challenge';
      try {
        const v = await check({ paymentRequired: challenge, requestUrl: s.endpoint, expected: { feeAmount: s.feeAmount, feeToken: s.feeToken, endpoint: s.endpoint } });
        const allFindings = v.details.findings.map((f) => ({ code: f.code, severity: f.severity, subject: f.subject || null, message: String(f.message || '').slice(0, 400) }));
        // Separate Guardian's own infrastructure conditions (a store/RPC timeout during the scan) from the
        // seller's risk. They mean "some checks were skipped for this row", never that the seller is riskier.
        const INFRA = new Set(['shared_state_unavailable', 'rpc_unavailable', 'threat_intel_unavailable']);
        const sellerFindings = allFindings.filter((f) => !INFRA.has(f.code));
        const infra = (v.reasons || []).filter((c) => INFRA.has(c));
        const SEV = { ALLOW: 0, WARN: 1, DENY: 2 };
        const verdict = sellerFindings.reduce((acc, f) => (SEV[f.severity] > SEV[acc] ? f.severity : acc), 'ALLOW');
        row.verdict = verdict;
        row.reasons = (v.reasons || []).filter((c) => !INFRA.has(c));
        if (infra.length) row.infra = infra;
        row.summary = v.summary;
        row.findings = allFindings;
        const sel = v.details.selected;
        row.challenge = { network: sel.network, scheme: sel.scheme, asset: sel.asset, amount: sel.amount, payTo: sel.payTo, entries: v.details.entries.length };
      } catch (e) {
        row.probe = 'challenge_invalid';
        row.detail = e.message;
      }
      results.push(row);
      console.error(String(results.length).padStart(3), (row.verdict || row.probe).padEnd(28), s.serviceName);
    }
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));

  const count = (pred) => results.filter(pred).length;
  const reasonCounts = {};
  for (const r of results) for (const c of r.reasons || []) reasonCounts[c] = (reasonCounts[c] || 0) + 1;
  const report = {
    generatedAt: new Date().toISOString(),
    source: 'OKX.AI marketplace (onchainos agent service-match), paid A2MCP services',
    method: 'One unpaid request per endpoint to capture the x402 challenge; Pay-Safe /check-payment against the listing. No payments, no signatures.',
    totals: {
      services: results.length,
      challenge: count((r) => r.probe === 'challenge'),
      allow: count((r) => r.verdict === 'ALLOW'),
      warn: count((r) => r.verdict === 'WARN'),
      deny: count((r) => r.verdict === 'DENY'),
      no_challenge: count((r) => r.probe === 'no_payment_challenge' || r.probe === '402_without_x402_challenge'),
      unreachable: count((r) => r.probe === 'unreachable'),
      invalid: count((r) => r.probe === 'challenge_invalid'),
    },
    reasons: Object.fromEntries(Object.entries(reasonCounts).sort((a, b) => b[1] - a[1])),
    results: results.sort((a, b) => ({ DENY: 0, WARN: 1, ALLOW: 2 }[a.verdict] ?? 3) - ({ DENY: 0, WARN: 1, ALLOW: 2 }[b.verdict] ?? 3)),
  };
  const docs = path.join(__dirname, '..', 'docs');
  fs.writeFileSync(path.join(docs, 'trust-scan.json'), JSON.stringify(report, null, 1));
  const esc = (t) => String(t).replace(/\|/g, '/').replace(/[\r\n]+/g, ' ');
  const highlights = report.results.filter((r) => r.verdict && r.verdict !== 'ALLOW').flatMap((r) => (r.findings || []).filter((f) => f.severity !== 'ALLOW').map((f) => '- **' + f.severity + ' ' + f.code + '** in ' + esc(r.service) + ' (sid ' + r.sid + '): ' + esc(f.message)));
  const md = ['# OKX.AI Pay-Safe trust scan', '', 'Generated ' + report.generatedAt + '. ' + report.method, '', '| Metric | Count |', '|---|---|']
    .concat(Object.entries(report.totals).map(([k, v]) => '| ' + k + ' | ' + v + ' |'))
    .concat(['', '## Reasons', '', '| Rule | Services |', '|---|---|'], Object.entries(report.reasons).map(([k, v]) => '| `' + k + '` | ' + v + ' |'))
    .concat(['', '## Findings', ''], highlights)
    .concat(['', '## Services', '', '| Verdict | Service | Listed | Challenge | Reasons |', '|---|---|---|---|---|'],
      report.results.map((r) => '| ' + (r.verdict || r.probe) + ' | ' + String(r.service).replace(/\|/g, '/') + ' (sid ' + r.sid + ') | ' + r.listed.feeAmount + ' ' + (r.listed.symbol || '') + ' | ' + (r.challenge ? (r.challenge.amount.human || r.challenge.amount.atomic) + ' ' + ((r.challenge.asset && r.challenge.asset.symbol) || '') + ' on ' + r.challenge.network : '—') + ' | ' + ((r.reasons || []).join(', ') || r.detail || '') + ' |'));
  fs.writeFileSync(path.join(docs, 'trust-scan.md'), md.join('\n') + '\n');
  console.log(JSON.stringify(report.totals), JSON.stringify(report.reasons));
}

main().catch((e) => { console.error(e); process.exit(1); });
