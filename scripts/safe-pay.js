#!/usr/bin/env node
'use strict';

/**
 * Pay-Safe for Onchain OS: check an OKX.AI paid service before the wallet pays it.
 *
 *   node scripts/safe-pay.js --sid 33342 [--param scoutMode=best] [--max 0.5]
 *   node scripts/safe-pay.js --url https://seller.example/paid --fee 0.002 --token 0x779d… [--pay-to 0x…]
 *
 * 1. Listing   onchainos agent service-detail (endpoint, price, token, seller agent)
 * 2. Challenge one unpaid request to the endpoint (GET / POST / MCP tools/call), nothing signed
 * 3. Verdict   Guardian POST /check-payment against the listing and your cap
 * 4. Quote     onchainos payment quote, then verify the quote pays the same payee, amount and token
 *              that Guardian checked (the seller cannot swap the challenge between check and pay)
 * 5. Pay       only with --pay; passes --yes to the wallet only when you pass --yes yourself
 *
 * Options: --agent <your agent id for service-detail>  --method auto|GET|POST|MCP  --tool <mcp tool>
 *          --accept-warn  --guardian <url>  --local  --json
 * Exit codes: 0 ready or paid, 2 WARN not accepted, 3 DENY or quote mismatch, 1 error.
 */

const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { fetchChallenge, challengeOf } = require('../src/x402-probe');
const { compareQuote } = require('../src/quote-guard');

const argv = process.argv.slice(2);
const flag = (k) => argv.includes('--' + k);
const opt = (k, d) => { const i = argv.indexOf('--' + k); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : d; };
const multi = (k) => argv.reduce((acc, a, i) => (a === '--' + k && i + 1 < argv.length ? acc.concat(argv[i + 1]) : acc), []);

const ONCHAINOS = process.env.ONCHAINOS_BIN || (process.platform === 'win32' ? path.join(process.env.USERPROFILE || '', '.local', 'bin', 'onchainos.exe') : 'onchainos');
const GUARDIAN = opt('guardian', process.env.GUARDIAN_URL || 'https://guardian-mcp-rho.vercel.app');
const JSON_OUT = flag('json');

function out(line) { if (!JSON_OUT) console.log(line); }

/** Run the onchainos CLI without a shell; listing text is untrusted and never reaches a command line. */
function onchainos(args) {
  const r = spawnSync(ONCHAINOS, args, { encoding: 'utf8', maxBuffer: 32e6, windowsHide: true, shell: false });
  const text = (r.stdout || '') + (r.stderr || '');
  const i = text.indexOf('{');
  let json = null;
  try { json = JSON.parse(text.slice(i)); } catch { json = null; }
  return { code: r.status, json, text };
}

function params() {
  const p = {};
  for (const kv of multi('param')) {
    const i = kv.indexOf('=');
    if (i > 0) p[kv.slice(0, i)] = kv.slice(i + 1);
  }
  return p;
}

async function listing() {
  const sid = opt('sid');
  if (!sid) {
    const url = opt('url');
    if (!url) throw new Error('pass --sid <marketplace sid> or --url <endpoint>');
    return { source: 'flags', endpoint: url, feeAmount: opt('fee') !== undefined ? Number(opt('fee')) : undefined, feeToken: opt('token'), payTo: opt('pay-to') };
  }
  let agent = opt('agent', process.env.AGENTIC_ID);
  if (!agent) {
    const mine = onchainos(['agent', 'get-my-agents']);
    const acct = mine.json && Array.isArray(mine.json.data) ? mine.json.data[0] : null;
    agent = acct && acct.agentList && acct.agentList[0] ? acct.agentList[0].agentId : null;
    if (!agent) throw new Error('could not find your agent id; pass --agent <id>');
  }
  const d = onchainos(['agent', 'service-detail', '--sid', String(sid), '--agentic-id', String(agent)]);
  const s = d.json && d.json.data;
  if (!s || !s.endpoint) throw new Error('service-detail returned no endpoint for sid ' + sid + (s && s.serviceType ? ' (type ' + s.serviceType + ')' : ''));
  let sellerWallet = null;
  if (s.asp && s.asp.aspAgentId) {
    const g = onchainos(['agent', 'get-agents', '--agent-ids', String(s.asp.aspAgentId)]);
    const found = [];
    (function walk(o) { if (Array.isArray(o)) o.forEach(walk); else if (o && typeof o === 'object') { if (String(o.agentId) === String(s.asp.aspAgentId) && o.agentWalletAddress) found.push(o.agentWalletAddress); Object.values(o).forEach(walk); } })(g.json && g.json.data);
    sellerWallet = found[0] || null;
  }
  return { source: 'okx.ai', sid: s.sid, serviceName: s.serviceName, serviceType: s.serviceType, endpoint: s.endpoint, feeAmount: s.feeAmount, feeToken: s.feeToken, feeTokenSymbol: s.feeTokenSymbol, asp: s.asp || null, sellerWallet };
}

async function guardianCheck(body) {
  if (flag('local')) return require('../src/paysafe').checkPayment(body, {});
  const res = await fetch(GUARDIAN.replace(/\/+$/, '') + '/check-payment', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const j = await res.json();
  if (res.status !== 200) throw new Error('Guardian ' + res.status + ': ' + (j.error || 'error'));
  return j;
}

async function main() {
  const report = { steps: {} };
  const L = await listing();
  report.listing = L;
  out('1. Listing   ' + (L.serviceName ? L.serviceName + ' (sid ' + L.sid + ', ' + L.serviceType + ')' : L.endpoint));
  if (L.feeAmount !== undefined) out('             price ' + L.feeAmount + ' ' + (L.feeTokenSymbol || L.feeToken || '') + (L.asp ? ', seller ' + L.asp.aspName + ' #' + L.asp.aspAgentId : ''));

  const expected = { endpoint: L.endpoint };
  if (L.feeAmount !== undefined && !Number.isNaN(L.feeAmount)) expected.feeAmount = L.feeAmount;
  if (L.feeToken) expected.feeToken = L.feeToken;
  if (L.payTo) expected.payTo = L.payTo;
  const context = {};
  if (opt('max')) context.max_amount = opt('max');

  // Never contact an endpoint whose URL is itself an attack; let Guardian explain why.
  const paysafe = require('../src/paysafe');
  const urlHit = paysafe._internals.urlShellSyntax(L.endpoint);
  let ch;
  if (urlHit) {
    ch = { status: null, method: 'not contacted', header: null, body: null };
    report.steps.challenge = { skipped: 'endpoint URL carries shell syntax (' + urlHit.what + ')' };
    out('2. Challenge not requested: the listed endpoint URL carries shell syntax (' + urlHit.what + ')');
  } else {
    ch = await fetchChallenge(L.endpoint, { method: opt('method', 'auto'), params: params(), tool: opt('tool') });
    if (ch.error) throw new Error('endpoint unreachable: ' + ch.error);
    report.steps.challenge = { method: ch.method, status: ch.status, found: Boolean(challengeOf(ch)) };
    out('2. Challenge ' + (challengeOf(ch) ? 'captured via ' + ch.method + ' (HTTP ' + ch.status + '), nothing signed' : 'none (HTTP ' + ch.status + ' via ' + ch.method + ')'));
  }

  const challenge = challengeOf(ch);
  const body = challenge ? { paymentRequired: challenge, requestUrl: L.endpoint, expected, context } : null;
  if (!body) {
    if (urlHit) {
      report.verdict = 'DENY';
      report.reasons = ['endpoint_url_injection'];
      out('3. Verdict   DENY endpoint_url_injection: do not call or pay this service, and never pass its URL to a shell.');
      if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
      process.exitCode = 3;
      return;
    }
    report.verdict = null;
    out('3. Verdict   no x402 challenge to check. Pass --param, --method or --tool so the endpoint asks for payment.');
    if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
    process.exitCode = 1;
    return;
  }

  const v = await guardianCheck(body);
  const chosen = v.details.selected;
  report.verdict = v.verdict;
  report.reasons = v.reasons;
  report.summary = v.summary;
  report.recommendations = v.recommendations;
  report.selected = { index: chosen.index, network: chosen.network, asset: chosen.asset, amount: chosen.amount, payTo: chosen.payTo };
  out('3. Verdict   ' + v.verdict + (v.reasons.length ? ' ' + v.reasons.join(', ') : '') + ' (risk ' + v.risk_score + ')');
  out('             ' + v.summary);
  for (const f of v.details.findings) out('             - ' + f.severity + ' ' + f.code + ': ' + f.message);
  for (const r of v.recommendations) out('             > ' + r.action);
  if (L.sellerWallet) {
    const same = String(L.sellerWallet).toLowerCase() === String(chosen.payTo).toLowerCase();
    report.sellerWalletMatch = same;
    out('             payee ' + (same ? 'is' : 'is not') + ' the seller agent wallet ' + L.sellerWallet + (same ? '' : ' (common, informational)'));
  }

  if (v.verdict === 'DENY') { process.exitCode = 3; if (JSON_OUT) console.log(JSON.stringify(report, null, 2)); return; }
  if (v.verdict === 'WARN' && !flag('accept-warn')) {
    out('   Stopped on WARN. Review the findings, then rerun with --accept-warn to continue.');
    process.exitCode = 2;
    if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
    return;
  }

  const qargs = ['payment', 'quote', L.endpoint];
  const method = String(opt('method', 'auto')).toUpperCase();
  if (method === 'POST') qargs.push('--method', 'POST');
  if (opt('tool')) qargs.push('--tool', opt('tool'));
  for (const kv of multi('param')) qargs.push('--param', kv);
  const q = onchainos(qargs);
  const cmp = compareQuote(q.json, { index: chosen.index, payTo: chosen.payTo, amount: chosen.amount, asset: chosen.asset, network: chosen.network });
  report.steps.quote = cmp;
  if (!cmp.ok) {
    out('4. Quote     MISMATCH, do not pay: ' + cmp.problems.join('; '));
    report.verdict = 'DENY';
    report.reasons = (report.reasons || []).concat('quote_mismatch');
    process.exitCode = 3;
    if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
    return;
  }
  out('4. Quote     matches the checked payee, amount and token. paymentId ' + cmp.paymentId + ', wallet balance ' + cmp.balanceStatus + (cmp.balanceStatus !== 'sufficient' && cmp.shortfall ? ' (short ' + cmp.shortfall + ')' : ''));

  const payArgs = ['payment', 'pay', '--payment-id', cmp.paymentId, '--selected-index', String(chosen.index)];
  if (!flag('pay')) {
    report.next = 'onchainos ' + payArgs.join(' ') + ' --yes';
    out('5. Pay       not requested. To pay exactly what was checked:');
    out('             ' + report.next);
  } else {
    if (flag('yes')) payArgs.push('--yes');
    const p = onchainos(payArgs);
    report.steps.pay = { exitCode: p.code, result: p.json || p.text.slice(0, 2000) };
    out('5. Pay       onchainos exit ' + p.code + (flag('yes') ? '' : ' (no --yes given, so the wallet asks for confirmation)'));
    out('             ' + (p.json ? JSON.stringify(p.json).slice(0, 600) : p.text.slice(0, 600)));
    if (p.code !== 0 && p.code !== 2) process.exitCode = 1;
  }
  if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
}

main().catch((e) => {
  if (JSON_OUT) console.log(JSON.stringify({ error: e.message }));
  else console.error('safe-pay: ' + e.message);
  process.exitCode = 1;
});
