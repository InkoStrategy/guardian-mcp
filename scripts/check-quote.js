#!/usr/bin/env node
'use strict';

/**
 * Check an Onchain OS payment quote with GuardianMCP and bind the verdict to its paymentId.
 *
 *   onchainos payment quote <endpoint> [--tool X | --method POST] [--param k=v]
 *   node scripts/check-quote.js --payment-id pay_… --sid 39856 [--selected-index 0] [--max 0.05]
 *   node scripts/check-quote.js --payment-id pay_… --endpoint https://seller/paid --fee 0.005 --token 0x779d… [--pay-to 0x…]
 *
 * 1. Quote     reads ~/.onchainos/payments/<paymentId>.json, the entries payment pay signs without re-fetching
 * 2. Listing   onchainos agent service-detail --sid (or --endpoint/--fee/--token/--pay-to flags)
 * 3. Verdict   Guardian POST /check-quote (owner wallet id, deposit address and balance are removed first)
 * 4. Bound     writes ~/.guardian/payments/<paymentId>.json with the verdict and the fingerprint of the entry,
 *              which hooks/claude-code-pretooluse.js requires before payment pay runs
 * 5. Next      on ALLOW prints the pay command, never with --yes
 *
 * Options: --guardian <url>  --local  --json  --agent <id for service-detail>
 * Exit codes: 0 ALLOW, 2 WARN, 3 DENY, 1 error.
 */

const binding = require('../src/quote-binding');
const cli = require('../src/onchainos-cli');

const GUARDIAN_DEFAULT = process.env.GUARDIAN_URL || 'https://guardian-mcp-rho.vercel.app';

/**
 * @param {object} o { paymentId, selectedIndex?, expected?, context?, sid?, guardian?, local?, deps? (local only), log?, env? }
 * @returns {Promise<{result: object, ledgerFile: string, entry: object}>}
 */
async function checkAndBind(o) {
  const log = typeof o.log === 'function' ? o.log : () => {};
  const env = o.env || process.env;
  if (!binding.isPaymentId(o.paymentId)) throw new Error('pass --payment-id pay_… from onchainos payment quote');
  const state = binding.readPaymentState(o.paymentId, env);
  if (!state) throw new Error('no persisted quote at ' + binding.stateDir(env) + '/' + o.paymentId + '.json');
  const nq = binding.normalizeQuote(state);
  const body = { quote: binding.publicState(state), context: o.context || undefined };
  if (o.selectedIndex !== undefined && o.selectedIndex !== null) body.selectedIndex = Number(o.selectedIndex);
  if (o.expected) body.expected = o.expected;
  else if (o.sid) body.sid = Number(o.sid);

  let result;
  if (o.local) {
    result = await require('../src/check-quote').checkQuote(body, Object.assign({ trustScan: () => { try { return require('../docs/trust-scan.json'); } catch { return null; } } }, o.deps || {}));
  } else {
    const url = String(o.guardian || GUARDIAN_DEFAULT).replace(/\/+$/, '') + '/check-quote';
    log('             POST ' + url + ' (owner wallet id, deposit address and balance removed)');
    const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const j = await res.json().catch(() => ({}));
    if (res.status !== 200) throw new Error('Guardian ' + res.status + ': ' + (j.error || 'error'));
    result = j;
  }
  const index = result.details && result.details.quote ? result.details.quote.selectedIndex : null;
  const localFp = Number.isInteger(index) ? binding.fingerprint(nq, index) : null;
  if (!result.binding || !localFp || result.binding.fingerprint !== localFp) {
    throw new Error('Guardian checked a different entry than the persisted quote holds; nothing was bound');
  }
  const entry = {
    paymentId: nq.paymentId,
    selectedIndex: index,
    fingerprint: localFp,
    verdict: result.verdict,
    reasons: result.reasons,
    summary: result.summary,
    next_command: result.next_command || null,
    endpoint: nq.endpointUrl,
    expected: o.expected || null,
    expectedSource: result.details.quote.expectedSource || null,
    checkedAt: new Date().toISOString(),
    quoteExpiresAt: result.details.quote.expiresAt,
    guardian: o.local ? 'local' : String(o.guardian || GUARDIAN_DEFAULT),
  };
  const ledgerFile = binding.writeLedger(entry, env);
  return { result, ledgerFile, entry };
}

async function main() {
  const argv = process.argv.slice(2);
  const flag = (k) => argv.includes('--' + k);
  const opt = (k, d) => { const i = argv.indexOf('--' + k); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : d; };
  const JSON_OUT = flag('json');
  const out = (line) => { if (!JSON_OUT) console.log(line); };

  const paymentId = opt('payment-id');
  const state = binding.readPaymentState(paymentId);
  if (!state) throw new Error('no persisted quote for ' + String(paymentId) + ' in ' + binding.stateDir() + '; run onchainos payment quote first');
  const nq = binding.normalizeQuote(state);
  out('1. Quote     ' + nq.paymentId + ' for ' + JSON.stringify(nq.endpointUrl) + ' (' + (nq.rawAccepts ? nq.rawAccepts.length : 0) + ' entries' + (nq.expiresAt ? ', expires ' + new Date(nq.expiresAt * 1000).toISOString() : '') + ')');
  out('             read from ' + binding.stateDir() + ', the entries payment pay signs without re-fetching the 402');

  let expected = null;
  const sid = opt('sid');
  if (sid) {
    out('2. Listing   OKX.AI sid ' + Number(sid));
    const L = cli.serviceListing(sid, opt('agent', process.env.AGENTIC_ID), out);
    expected = { endpoint: L.endpoint };
    if (L.feeAmount !== undefined && !Number.isNaN(Number(L.feeAmount))) expected.feeAmount = Number(L.feeAmount);
    if (L.feeToken) expected.feeToken = L.feeToken;
    out('             ' + (L.serviceName || '') + ', price ' + L.feeAmount + ' ' + (L.feeTokenSymbol || L.feeToken || '') + (L.asp ? ', seller ' + L.asp.aspName + ' #' + L.asp.aspAgentId : ''));
  } else if (opt('endpoint') || opt('fee') || opt('token') || opt('pay-to')) {
    expected = {};
    if (opt('endpoint')) expected.endpoint = opt('endpoint');
    if (opt('fee') !== undefined) expected.feeAmount = Number(opt('fee'));
    if (opt('token')) expected.feeToken = opt('token');
    if (opt('pay-to')) expected.payTo = opt('pay-to');
    out('2. Listing   from flags');
  } else {
    out('2. Listing   none given: price, token and payee cannot be compared with a listing (pass --sid or --endpoint/--fee/--token)');
  }
  const context = opt('max') ? { max_amount: opt('max') } : undefined;

  out('3. Verdict   ' + (flag('local') ? 'local Guardian' : 'Guardian'));
  const { result, ledgerFile, entry } = await checkAndBind({ paymentId, selectedIndex: opt('selected-index'), expected, context, guardian: opt('guardian'), local: flag('local'), log: out });
  out('             ' + result.verdict + (result.reasons.length ? ' ' + result.reasons.join(', ') : '') + ' (risk ' + result.risk_score + ')');
  out('             ' + result.summary);
  for (const f of result.details.findings) out('             - ' + f.severity + ' ' + f.code + ': ' + f.message);
  for (const r of result.recommendations) out('             > ' + r.action);
  out('4. Bound     accepts[' + entry.selectedIndex + '] fingerprint ' + entry.fingerprint.slice(0, 16) + '… written to ' + ledgerFile);
  if (result.next_command) {
    out('5. Next      ' + result.next_command);
    out('             Without --yes the wallet only returns a confirmation prompt (exit 2) and pays nothing. The wallet owner adds --yes after reading the verdict.');
  } else {
    out('5. Next      do not pay this quote. ' + (result.details.quote.note || ''));
  }
  if (JSON_OUT) console.log(JSON.stringify({ result, ledgerFile, entry }, null, 2));
  process.exitCode = result.verdict === 'ALLOW' ? 0 : result.verdict === 'WARN' ? 2 : 3;
}

module.exports = { checkAndBind };

if (require.main === module) {
  main().catch((e) => {
    if (process.argv.includes('--json')) console.log(JSON.stringify({ error: e.message }));
    else console.error('check-quote: ' + e.message);
    process.exitCode = 1;
  });
}
