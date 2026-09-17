'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { checkQuote } = require('../src/check-quote');
const binding = require('../src/quote-binding');
const demo = require('../src/demo-sellers');
const { createMemoryStore } = require('../src/store');

// Fixtures are real `onchainos payment quote` runs (17 Sep 2026) against the deployed demo sellers, the
// paid MCP guard tool and URL Change Check API sid 39856, with the owner wallet id, deposit address and balance removed.
const F = (name) => JSON.parse(JSON.stringify(require('./fixtures/' + name + '.json')));
const BASE = 'https://guardian-mcp-rho.vercel.app/demo/x402/';
const listing = (scenario) => Object.assign({ endpoint: BASE + scenario }, demo.LISTING);
const OTHER = '0x5b0c6a8d2e41f97b3c0d18e6a4f2b95c7d3e1a09';

function reader() {
  return {
    endpoint: 'fake://xlayer',
    async addressState(a) { return { address: a, isContract: false, txCount: 57, balance: '1000000000000000000', codeSize: 0, code: '0x' }; },
    async call() { throw new Error('no calls expected'); },
  };
}
const deps = (now, extra) => Object.assign({ store: createMemoryStore(), env: {}, now: Date.parse(now), reader: reader(), trustScan: () => require('../docs/trust-scan.json') }, extra || {});
const DEMO_NOW = '2026-09-17T07:27:00Z';

test('check-quote: honest persisted quote is ALLOW with a pay command without --yes and a binding', async () => {
  const r = await checkQuote({ quote: F('state-honest'), expected: listing('honest') }, deps(DEMO_NOW));
  assert.equal(r.verdict, 'ALLOW', JSON.stringify(r.reasons));
  assert.equal(r.next_command, 'onchainos payment pay --payment-id pay_6219026516fffba4f41fac8d --selected-index 0');
  assert.ok(!/--yes|--force/.test(r.next_command));
  assert.equal(r.details.quote.source, 'payment-state');
  assert.equal(r.binding.paymentId, 'pay_6219026516fffba4f41fac8d');
  assert.equal(r.binding.fingerprint, binding.fingerprint(binding.normalizeQuote(F('state-honest')), 0));
});

test('check-quote: demo quotes recorded from the real CLI get the verdicts their stories promise', async () => {
  const bait = await checkQuote({ quote: F('state-price-bait'), expected: listing('price-bait') }, deps(DEMO_NOW));
  assert.equal(bait.verdict, 'DENY');
  assert.ok(bait.reasons.includes('amount_above_listing'));
  assert.equal(bait.next_command, null);
  const domain = await checkQuote({ quote: F('state-wrong-domain'), expected: listing('wrong-domain') }, deps(DEMO_NOW));
  assert.equal(domain.verdict, 'WARN');
  assert.deepEqual(domain.reasons, ['eip712_domain_mismatch']);
  assert.equal(domain.next_command, null);
  // The CLI's own stdout for the same seller: same verdict, but no binding without the signed entries.
  const stdout = await checkQuote({ quote: F('quote-wrong-domain'), expected: listing('wrong-domain') }, deps(DEMO_NOW));
  assert.equal(stdout.verdict, 'WARN');
  assert.equal(stdout.details.quote.source, 'quote-output');
  assert.equal(stdout.binding, null);
});

test('check-quote: JSON-RPC merchant body of the paid MCP guard tool, business params kept in the pay command', async () => {
  const r = await checkQuote({ quote: F('state-mcp-guard'), expected: { feeAmount: 0.099, feeToken: demo.LISTING.feeToken, endpoint: 'https://guardian-mcp-rho.vercel.app/mcp', payTo: demo.DEMO_PAY_TO } }, deps('2026-09-17T07:24:00Z'));
  assert.equal(r.verdict, 'ALLOW', JSON.stringify(r.reasons));
  assert.equal(r.next_command, 'onchainos payment pay --payment-id pay_cc6cc66a4bed85fbc941930d --selected-index 0 --param chainId=1 --param data=0x --param to=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48');
});

test('check-quote: the real paid sid 39856 quote (header-only seller) checks against the trust scan listing', async () => {
  const r = await checkQuote({ quote: F('state-sid39856-paid'), sid: 39856 }, deps('2026-09-16T21:27:00Z'));
  assert.equal(r.verdict, 'ALLOW', JSON.stringify(r.details.findings));
  assert.match(r.details.quote.expectedSource, /trust scan/);
  const later = await checkQuote({ quote: F('state-sid39856-paid'), sid: 39856 }, deps('2026-09-17T07:27:00Z'));
  assert.ok(later.reasons.includes('quote_expired'));
  assert.equal(later.next_command, null);
});

test('check-quote: merchant body showing another payee than the signed entry is DENY challenge_header_body_mismatch', async () => {
  const q = F('state-honest');
  q.merchant_body = q.merchant_body.replace(demo.DEMO_PAY_TO, OTHER);
  const r = await checkQuote({ quote: q, expected: listing('honest') }, deps(DEMO_NOW));
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('challenge_header_body_mismatch'));
  assert.equal(r.next_command, null);
});

test('check-quote: quote whose summary disagrees with the signed entry is DENY quote_inconsistent', async () => {
  const q = F('state-honest');
  q.decoded_challenge.recipient = OTHER;
  q.candidates[0].amount = '999';
  const r = await checkQuote({ quote: q, expected: listing('honest') }, deps(DEMO_NOW));
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('quote_inconsistent'));
});

test('check-quote: quote output from a header-only seller is WARN quote_partial and not bindable', async () => {
  const q = F('quote-honest');
  q.data.merchantBody = '{}';
  const r = await checkQuote({ quote: q, expected: listing('honest') }, deps(DEMO_NOW));
  assert.equal(r.verdict, 'WARN');
  assert.deepEqual(r.reasons, ['quote_partial']);
  assert.equal(r.binding, null);
});

test('check-quote: unsafe stored params are not printed into a command', async () => {
  const q = F('state-honest');
  q.known_params = { url: 'https://x.example/$(id)' };
  const r = await checkQuote({ quote: q, expected: listing('honest') }, deps(DEMO_NOW));
  assert.equal(r.verdict, 'ALLOW');
  assert.equal(r.next_command, null);
  assert.match(r.details.quote.note, /manual quoting/);
});

test('check-quote: validation errors', async () => {
  await assert.rejects(checkQuote({}, deps(DEMO_NOW)), /"quote" is required/);
  await assert.rejects(checkQuote({ quote: { ok: false, error: 'endpoint_unreachable' } }, deps(DEMO_NOW)), /quote failed/);
  await assert.rejects(checkQuote({ quote: { payment_id: '../../etc/passwd' } }, deps(DEMO_NOW)), /paymentId/);
  await assert.rejects(checkQuote({ quote: F('state-honest'), selectedIndex: 3 }, deps(DEMO_NOW)), /selectedIndex/);
});

test('quote-binding: CLI default index, fingerprint sensitivity and public state', () => {
  assert.equal(binding.cliDefaultIndex([{ scheme: 'upto' }, { scheme: 'aggr_deferred' }, { scheme: 'exact' }]), 2);
  assert.equal(binding.cliDefaultIndex([{ scheme: 'upto' }, { scheme: 'aggr_deferred' }]), 1);
  assert.equal(binding.cliDefaultIndex([{ scheme: 'upto' }]), 0);
  const nq = binding.normalizeQuote(F('state-honest'));
  const fp = binding.fingerprint(nq, 0);
  for (const mutate of [(s) => { s.raw_accepts[0].payTo = OTHER; }, (s) => { s.raw_accepts[0].amount = '1001'; }, (s) => { s.raw_accepts[0].extra.name = 'USDT'; }, (s) => { s.endpoint_url += '?x=1'; }]) {
    const s = F('state-honest');
    mutate(s);
    assert.notEqual(binding.fingerprint(binding.normalizeQuote(s), 0), fp);
  }
  const pub = binding.publicState({ payment_id: 'pay_abcdefabcdef', owner_wallet: 'id', candidates: [{ depositAddress: '0x1', availableAmount: '5', amount: '1' }] });
  assert.equal(pub.owner_wallet, undefined);
  assert.deepEqual(pub.candidates, [{ amount: '1' }]);
});

test('check-quote: live header-body-split quote, the CLI persisted the header payee while the body shows the listing wallet', async () => {
  const q = F('state-header-body-split');
  assert.equal(q.raw_accepts[0].payTo.toLowerCase(), demo.SPLIT_PAY_TO);
  assert.equal(JSON.parse(q.merchant_body).accepts[0].payTo, demo.DEMO_PAY_TO);
  // OKX.AI listings carry price, token and endpoint but no payee, so the split alone must be enough to stop it.
  const r = await checkQuote({ quote: q, expected: { feeAmount: 0.001, feeToken: demo.LISTING.feeToken, endpoint: BASE + 'header-body-split' } }, deps('2026-09-17T07:45:00Z'));
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('challenge_header_body_mismatch'));
  assert.ok(!r.reasons.includes('payto_mismatch_listing'));
  assert.equal(r.next_command, null);
});
