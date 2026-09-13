'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { Interface } = require('ethers');
const { encodePaymentSignatureHeader, decodePaymentRequiredHeader } = require('@okxweb3/x402-core/http');
const premium = require('../src/premium');

const erc20 = new Interface(['function approve(address spender, uint256 amount)']);
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const V2ROUTER = '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D';
const PAY_TO = '0xe1c6f89df50fb68282d52e34d6001d65005ff67b';
const PAYER = '0x1111111111111111111111111111111111111111';

function fakeFacilitator(opts) {
  opts = opts || {};
  const calls = { verify: 0, settle: 0 };
  return {
    calls,
    async getSupported() {
      return { kinds: [{ x402Version: 2, scheme: 'exact', network: 'eip155:196' }], extensions: [], signers: {} };
    },
    async verify(payload) {
      calls.verify += 1;
      if (opts.invalid) return { isValid: false, invalidReason: 'insufficient_funds' };
      return { isValid: true, payer: payload.payload.authorization.from };
    },
    async settle(payload, requirements) {
      calls.settle += 1;
      if (opts.settleFail) return { success: false, errorReason: 'settle_failed', network: requirements.network };
      return { success: true, transaction: '0x' + 'ab'.repeat(32), network: requirements.network, payer: payload.payload.authorization.from };
    },
  };
}

const ENV = { OKX_API_KEY: 'k', OKX_SECRET_KEY: 's', OKX_PASSPHRASE: 'p', PREMIUM_PAY_TO: PAY_TO, PREMIUM_PRICE: '$0.099', PREMIUM_NETWORK: 'eip155:196' };

async function withServer(options, fn) {
  const handler = require('../api/index.js');
  handler.premiumOptions = options;
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  try {
    await fn(async (path, body, headers) => {
      const r = await fetch(base + path, { method: 'POST', headers: Object.assign({ 'content-type': 'application/json' }, headers || {}), body: JSON.stringify(body) });
      const text = await r.text();
      let json = null;
      try { json = JSON.parse(text); } catch { /* not json */ }
      return { status: r.status, headers: r.headers, body: json, text };
    });
  } finally {
    server.close();
    handler.premiumOptions = undefined;
  }
}

function paidHeader(requirements, overrides) {
  const payload = {
    x402Version: 2,
    scheme: requirements.scheme,
    network: requirements.network,
    payload: {
      signature: '0x' + 'ab'.repeat(65),
      authorization: Object.assign({ from: PAYER, to: requirements.payTo, value: requirements.amount, validAfter: '0', validBefore: '9999999999', nonce: '0x' + '11'.repeat(32) }, overrides || {}),
    },
    accepted: requirements,
  };
  return encodePaymentSignatureHeader(payload);
}

test('premium: without OKX credentials /guard answers 503, never 402 (no one signs for nothing)', async () => {
  assert.equal(premium.config({}).ready, false);
  assert.match(premium.config({}).reason, /OKX Developer API credentials/);
  await withServer(undefined, async (post) => {
    const r = await post('/guard', { to: USDC, data: '0x' });
    assert.equal(r.status, 503);
    assert.match(r.body.error, /not available yet/);
    assert.equal(r.headers.get('payment-required'), null);
  });
});

test('premium: unpaid request gets 402 with PAYMENT-REQUIRED for 0.099 USDT0 on X Layer, body mirrors the header', async () => {
  await withServer({ facilitatorClient: fakeFacilitator(), env: ENV }, async (post) => {
    const r = await post('/guard', { to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, 1n]) });
    assert.equal(r.status, 402);
    const decoded = decodePaymentRequiredHeader(r.headers.get('payment-required'));
    assert.equal(decoded.x402Version, 2);
    const acc = decoded.accepts[0];
    assert.equal(acc.scheme, 'exact');
    assert.equal(acc.network, 'eip155:196');
    assert.equal(acc.amount, '99000');
    assert.equal(acc.payTo.toLowerCase(), PAY_TO);
    assert.equal(acc.asset.toLowerCase(), '0x779ded0c9e1022225f8e0630b35a9b54be713736');
    assert.equal(r.body.accepts[0].amount, '99000', 'body mirrors the header');
  });
});

test('premium: paid replay is verified, analysed, settled; PAYMENT-RESPONSE header and payment details returned', async () => {
  const fac = fakeFacilitator();
  await withServer({ facilitatorClient: fac, env: ENV }, async (post) => {
    const body = { to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, 1n]), context: { session_id: 'premium-1' } };
    const first = await post('/guard', body);
    const req = decodePaymentRequiredHeader(first.headers.get('payment-required')).accepts[0];
    const paid = await post('/guard', body, { 'payment-signature': paidHeader(req) });
    assert.equal(paid.status, 200, paid.text);
    assert.equal(paid.body.verdict, 'ALLOW');
    assert.equal(paid.body.details.premium, true);
    assert.equal(paid.body.details.payment.settled, true);
    assert.equal(paid.body.details.payment.payer.toLowerCase(), PAYER);
    assert.ok(paid.headers.get('payment-response'), 'settlement receipt header present');
    assert.equal(paid.body.details.session_health.status, 'healthy');
    assert.equal(fac.calls.verify, 1);
    assert.equal(fac.calls.settle, 1);
  });
});

test('premium: invalid payment is rejected with 402 and the analysis never runs; failed settlement is reported', async () => {
  await withServer({ facilitatorClient: fakeFacilitator({ invalid: true }), env: ENV }, async (post) => {
    const body = { to: USDC, data: '0x' };
    const first = await post('/guard', body);
    const req = decodePaymentRequiredHeader(first.headers.get('payment-required')).accepts[0];
    const bad = await post('/guard', body, { 'payment-signature': paidHeader(req) });
    assert.equal(bad.status, 402);
    assert.equal(bad.body.verdict, undefined);
  });
  await withServer({ facilitatorClient: fakeFacilitator({ settleFail: true }), env: ENV }, async (post) => {
    const body = { to: USDC, data: '0x' };
    const first = await post('/guard', body);
    const req = decodePaymentRequiredHeader(first.headers.get('payment-required')).accepts[0];
    const r = await post('/guard', body, { 'payment-signature': paidHeader(req) });
    assert.equal(r.status, 402);
    assert.match(JSON.stringify(r.body), /settle/i);
  });
});

test('premium: signature kind is routed to the signature analyzer', async () => {
  await withServer({ facilitatorClient: fakeFacilitator(), env: ENV }, async (post) => {
    const body = { kind: 'signature', type: 'personal_sign', message: '0x' + 'ab'.repeat(32) };
    const first = await post('/guard', body);
    const req = decodePaymentRequiredHeader(first.headers.get('payment-required')).accepts[0];
    const paid = await post('/guard', body, { 'payment-signature': paidHeader(req) });
    assert.equal(paid.status, 200, paid.text);
    assert.equal(paid.body.verdict, 'DENY');
    assert.ok(paid.body.reasons.includes('blind_hash_signing'));
  });
});
