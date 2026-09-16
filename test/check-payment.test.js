'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { Wallet } = require('ethers');
const { checkPayment, X402_UPTO_PERMIT2_PROXY } = require('../src/paysafe');
const { createMemoryStore } = require('../src/store');
const seed = require('../src/seed');

const USDT0 = '0x779Ded0c9e1022225f8E0630b35a9b54bE713736';
const PAY_TO = '0xE1c6F89df50Fb68282d52e34d6001d65005ff67b';
const NOW = Date.parse('2026-09-17T10:00:00Z');
const NOW_SEC = Math.floor(NOW / 1000);

// Real challenge captured from https://lno-radar-api.vercel.app/paid/snapshot (PAYMENT-REQUIRED header, decoded).
const REAL = {
  x402Version: 2,
  error: 'Payment required',
  resource: { url: 'http://lno-radar-api.vercel.app/paid/snapshot?instId=BTC-USDT-SWAP', description: 'OKX perpetual snapshot', mimeType: '' },
  accepts: [{ scheme: 'exact', network: 'eip155:196', amount: '2000', asset: USDT0.toLowerCase(), payTo: PAY_TO.toLowerCase(), maxTimeoutSeconds: 120, extra: { name: 'USD₮0', version: '1' } }],
};
const b64 = (o) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64');
const LISTING = { feeAmount: 0.002, feeToken: USDT0.toLowerCase(), endpoint: 'https://lno-radar-api.vercel.app/paid/snapshot', payTo: PAY_TO };
const REQUEST_URL = 'https://lno-radar-api.vercel.app/paid/snapshot?instId=BTC-USDT-SWAP';

function reader(overrides) {
  const map = new Map(Object.entries(overrides || {}).map(([k, v]) => [k.toLowerCase(), v]));
  return {
    endpoint: 'fake://xlayer',
    async addressState(a) {
      return Object.assign({ address: a }, map.get(a.toLowerCase()) || { isContract: false, txCount: 57, balance: '1000000000000000000', codeSize: 0, code: '0x' });
    },
    async call() { throw new Error('no calls expected'); },
  };
}
const deps = (extra) => Object.assign({ reader: reader(), store: createMemoryStore(), env: {}, now: NOW }, extra || {});
const clone = (o) => JSON.parse(JSON.stringify(o));

test('check-payment: real Radar challenge that matches its listing is ALLOW', async () => {
  const r = await checkPayment({ paymentRequired: b64(REAL), requestUrl: REQUEST_URL, expected: LISTING }, deps());
  assert.equal(r.verdict, 'ALLOW', JSON.stringify(r.reasons));
  assert.equal(r.details.selected.amount.human, '0.002');
  assert.equal(r.details.selected.asset.symbol, 'USDT0');
  assert.equal(r.recommended_index, 0);
  assert.match(r.summary, /0\.002 USDT0 \(2000\) on xlayer/);
});

test('check-payment: price bait-and-switch (1000x the listing) is DENY', async () => {
  const bait = clone(REAL);
  bait.accepts[0].amount = '2000000';
  const r = await checkPayment({ paymentRequired: bait, requestUrl: REQUEST_URL, expected: LISTING }, deps());
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('amount_above_listing'));
  assert.ok(r.recommendations.some((x) => x.code === 'amount_above_listing'));
});

test('check-payment: hijacked endpoint paying a different wallet is DENY', async () => {
  const hijack = clone(REAL);
  hijack.accepts[0].payTo = '0x1111111111111111111111111111111111111111';
  const r = await checkPayment({ paymentRequired: hijack, requestUrl: REQUEST_URL, expected: LISTING }, deps());
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('payto_mismatch_listing'));
});

test('check-payment: payee that imitates the listed wallet is payto_poisoning', async () => {
  const poison = clone(REAL);
  poison.accepts[0].payTo = '0xe1c6aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf67b';
  const r = await checkPayment({ paymentRequired: poison, expected: LISTING }, deps());
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('payto_poisoning'));
});

test('check-payment: fake stablecoin that imitates USD₮0 is DENY asset_lookalike', async () => {
  const fake = clone(REAL);
  fake.accepts[0].asset = '0x779d000000000000000000000000000000003736';
  const r = await checkPayment({ paymentRequired: fake, requestUrl: REQUEST_URL }, deps({ reader: reader({ '0x779d000000000000000000000000000000003736': { isContract: true, txCount: 1, balance: '0', codeSize: 900, code: '0x60' } }) }));
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('asset_lookalike'));
});

test('check-payment: 402 served from a different domain than the listing is DENY', async () => {
  const r = await checkPayment({ paymentRequired: REAL, requestUrl: 'https://lno-radar-api-payments.xyz/paid/snapshot', expected: LISTING }, deps());
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('payment_domain_mismatch'));
});

test('check-payment: token different from the listing is DENY asset_mismatch_listing', async () => {
  const other = clone(REAL);
  other.accepts[0].asset = '0x74b7f16337b8972027f6196a17a631ac6de26d22';
  const r = await checkPayment({ paymentRequired: other, requestUrl: REQUEST_URL, expected: LISTING }, deps());
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('asset_mismatch_listing'));
});

test('check-payment: amount above the agent cap is DENY', async () => {
  const r = await checkPayment({ paymentRequired: REAL, requestUrl: REQUEST_URL, context: { max_amount: '0.001' } }, deps());
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('amount_above_user_cap'));
});

async function signEip3009(wallet, { to, value, validAfter, validBefore }) {
  const nonce = '0x' + '11'.repeat(32);
  const domain = { name: 'USD₮0', version: '1', chainId: 196, verifyingContract: USDT0 };
  const types = { TransferWithAuthorization: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' }] };
  const authorization = { from: wallet.address, to, value: String(value), validAfter: String(validAfter), validBefore: String(validBefore), nonce };
  const signature = await wallet.signTypedData(domain, types, authorization);
  return { x402Version: 2, resource: REAL.resource, accepted: Object.assign({}, REAL.accepts[0], { payTo: to }), payload: { authorization, signature } };
}

test('check-payment: valid EIP-3009 signature for the exact challenge is ALLOW', async () => {
  const wallet = Wallet.createRandom();
  const signed = await signEip3009(wallet, { to: PAY_TO, value: 2000, validAfter: NOW_SEC - 5, validBefore: NOW_SEC + 120 });
  const r = await checkPayment({ paymentRequired: b64(REAL), requestUrl: REQUEST_URL, expected: LISTING, paymentSignature: b64(signed), context: { from: wallet.address } }, deps());
  assert.equal(r.verdict, 'ALLOW', JSON.stringify(r.reasons));
  assert.equal(r.details.signed.kind, 'eip3009');
});

test('check-payment: signature that pays someone else is DENY', async () => {
  const wallet = Wallet.createRandom();
  const signed = await signEip3009(wallet, { to: '0x2222222222222222222222222222222222222222', value: 2000, validAfter: NOW_SEC - 5, validBefore: NOW_SEC + 120 });
  signed.accepted = REAL.accepts[0];
  const r = await checkPayment({ paymentRequired: REAL, requestUrl: REQUEST_URL, paymentSignature: signed, selectedIndex: 0 }, deps());
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('signed_recipient_mismatch'));
});

test('check-payment: signature from another wallet does not recover', async () => {
  const wallet = Wallet.createRandom();
  const signed = await signEip3009(wallet, { to: PAY_TO, value: 2000, validAfter: NOW_SEC - 5, validBefore: NOW_SEC + 120 });
  signed.payload.authorization.from = Wallet.createRandom().address;
  const r = await checkPayment({ paymentRequired: REAL, requestUrl: REQUEST_URL, paymentSignature: signed }, deps());
  assert.ok(r.reasons.includes('signature_does_not_recover'));
});

test('check-payment: long-lived authorisation is WARN', async () => {
  const wallet = Wallet.createRandom();
  const signed = await signEip3009(wallet, { to: PAY_TO, value: 2000, validAfter: NOW_SEC - 5, validBefore: NOW_SEC + 30 * 86400 });
  const r = await checkPayment({ paymentRequired: REAL, requestUrl: REQUEST_URL, paymentSignature: signed }, deps());
  assert.equal(r.verdict, 'WARN');
  assert.ok(r.reasons.includes('signed_validity_too_long'));
});

test('check-payment: upto Permit2 with a non-proxy spender is DENY', async () => {
  const upto = clone(REAL);
  upto.accepts[0].scheme = 'upto';
  upto.accepts[0].extra = { name: 'USD₮0', version: '1', facilitatorAddress: '0x3333333333333333333333333333333333333333' };
  const signed = { x402Version: 2, accepted: upto.accepts[0], payload: { signature: '0x' + 'ab'.repeat(65), permit2Authorization: { from: '0x4444444444444444444444444444444444444444', permitted: { token: USDT0, amount: '2000' }, spender: '0x5555555555555555555555555555555555555555', nonce: '1', deadline: String(NOW_SEC + 100), witness: { to: PAY_TO, validAfter: String(NOW_SEC - 600), facilitator: '0x3333333333333333333333333333333333333333' } } } };
  const r = await checkPayment({ paymentRequired: upto, requestUrl: REQUEST_URL, paymentSignature: signed }, deps());
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('signed_spender_not_x402_proxy'));
  assert.ok(r.reasons.includes('permit2_approval_required'));
  signed.payload.permit2Authorization.spender = X402_UPTO_PERMIT2_PROXY;
  const ok = await checkPayment({ paymentRequired: upto, requestUrl: REQUEST_URL, paymentSignature: signed }, deps());
  assert.ok(!ok.reasons.includes('signed_spender_not_x402_proxy'));
});

test('check-payment: payee in the ScamSniffer seed database is DENY', async () => {
  const store = createMemoryStore();
  const drainer = '0x7fb2224cc00a8d9106ac9280abde1e2f480f4f41';
  await seed.applySeed(store, { source: 't', sha: 's', addresses: [drainer], domains: [] });
  const bad = clone(REAL);
  bad.accepts[0].payTo = drainer;
  const r = await checkPayment({ paymentRequired: bad, requestUrl: REQUEST_URL }, deps({ store }));
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('scam_database_address'), JSON.stringify(r.reasons));
});

test('check-payment: legacy v1 body with maxAmountRequired and network name is parsed', async () => {
  const v1 = { x402Version: 1, accepts: [{ scheme: 'exact', network: 'base', maxAmountRequired: '10000', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: PAY_TO, resource: 'https://api.example.com/data', maxTimeoutSeconds: 60, extra: { name: 'USD Coin', version: '2' } }] };
  const r = await checkPayment({ paymentRequired: v1, requestUrl: 'https://api.example.com/data' }, deps());
  assert.equal(r.details.selected.chainId, 8453);
  assert.equal(r.details.selected.amount.human, '0.01');
  assert.equal(r.details.selected.asset.symbol, 'USDC');
});

test('check-payment: picks the safe entry when one of several accepts is bad', async () => {
  const multi = clone(REAL);
  multi.accepts.unshift(Object.assign({}, REAL.accepts[0], { payTo: '0x1111111111111111111111111111111111111111' }));
  const r = await checkPayment({ paymentRequired: multi, requestUrl: REQUEST_URL, expected: LISTING }, deps());
  assert.equal(r.recommended_index, 1);
  assert.equal(r.details.entries[0].verdict, 'DENY');
  assert.ok(r.reasons.includes('multiple_payees'));
});

test('check-payment: bad input is a ValidationError', async () => {
  await assert.rejects(checkPayment({}, deps()), /paymentRequired/);
  await assert.rejects(checkPayment({ paymentRequired: 'not-base64-json' }, deps()), /base64/);
  await assert.rejects(checkPayment({ paymentRequired: { x402Version: 2, accepts: [{ amount: '1.5', asset: USDT0, payTo: PAY_TO, network: 'eip155:196' }] } }, deps()), /atomic/);
});

test('HTTP POST /check-payment returns 200 with a verdict and 400 on bad body', async () => {
  const handler = require('../api/index');
  handler.quickOptions = { reader: reader(), store: createMemoryStore(), env: {}, now: NOW };
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  try {
    const ok = await fetch(base + '/check-payment', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ paymentRequired: b64(REAL), requestUrl: REQUEST_URL, expected: LISTING }) });
    assert.equal(ok.status, 200);
    const body = await ok.json();
    assert.equal(body.verdict, 'ALLOW', JSON.stringify(body.reasons));
    const bad = await fetch(base + '/check-payment', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ nope: true }) });
    assert.equal(bad.status, 400);
    const rules = await (await fetch(base + '/rules')).json();
    const codes = JSON.stringify(rules);
    assert.ok(codes.includes('amount_above_listing'));
  } finally {
    delete handler.quickOptions;
    server.close();
  }
});
