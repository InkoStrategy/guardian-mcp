'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { encodePaymentSignatureHeader, decodePaymentRequiredHeader } = require('@okxweb3/x402-core/http');
const { createMemoryStore } = require('../src/store');
const demo = require('../src/demo-sellers');
const { TRANSFER_TOPIC } = require('../src/settlement');

const USDT0 = '0x779ded0c9e1022225f8e0630b35a9b54be713736';
const PAY_TO = '0xe1c6f89df50fb68282d52e34d6001d65005ff67b';
const PAYER = '0x1111111111111111111111111111111111111111';
const NOW = Date.parse('2026-09-17T10:00:00Z');

function reader() {
  return {
    endpoint: 'fake://chain',
    async addressState(a) { return { address: a, isContract: false, txCount: 57, balance: '1000000000000000000', codeSize: 0, code: '0x' }; },
    async call() { throw new Error('no calls expected'); },
  };
}

function demoFetch() {
  return async (url, init) => {
    const u = new URL(url);
    const req = { method: (init && init.method) || 'GET', headers: { host: u.host, 'x-forwarded-proto': 'https' } };
    const out = { statusCode: 200, headers: {}, body: '' };
    const res = { set statusCode(v) { out.statusCode = v; }, get statusCode() { return out.statusCode; }, setHeader(k, v) { out.headers[k.toLowerCase()] = v; }, end(b) { out.body = b || ''; } };
    if (!demo.handle(req, res, u.pathname)) { out.statusCode = 404; out.body = '{}'; }
    return new Response(out.body, { status: out.statusCode, headers: out.headers });
  };
}

function fakeFacilitator() {
  const calls = { verify: 0, settle: 0 };
  return {
    calls,
    async getSupported() { return { kinds: [{ x402Version: 2, scheme: 'exact', network: 'eip155:196' }], extensions: [], signers: {} }; },
    async verify(payload) { calls.verify += 1; return { isValid: true, payer: payload.payload.authorization.from }; },
    async settle(payload, requirements) { calls.settle += 1; return { success: true, transaction: '0x' + 'ab'.repeat(32), network: requirements.network, payer: payload.payload.authorization.from }; },
  };
}
const ENV = { OKX_API_KEY: 'k', OKX_SECRET_KEY: 's', OKX_PASSPHRASE: 'p', PREMIUM_PAY_TO: PAY_TO, PREMIUM_PRICE: '$0.099', PREMIUM_NETWORK: 'eip155:196' };

async function withMcp(options, fn) {
  const handler = require('../api/index.js');
  const saved = { quick: handler.quickOptions, probe: handler.probeOptions, premium: handler.premiumOptions, settlement: handler.settlementOptions };
  handler.quickOptions = options.quick;
  handler.probeOptions = options.probe;
  handler.premiumOptions = options.premium;
  handler.settlementOptions = options.settlement;
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  let id = 0;
  const rpc = async (method, params, extra) => {
    const e = extra || {};
    const body = e.raw !== undefined ? e.raw : JSON.stringify(Object.assign({ jsonrpc: '2.0', method }, e.notification ? {} : { id: ++id }, params ? { params } : {}));
    const r = await fetch(base + '/mcp', { method: e.method || 'POST', headers: Object.assign({ 'content-type': 'application/json', accept: 'application/json' }, e.headers || {}), body: e.method === 'GET' ? undefined : body });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { json = null; }
    return { status: r.status, headers: r.headers, json, text };
  };
  try {
    await fn(rpc);
  } finally {
    server.close();
    Object.assign(handler, { quickOptions: saved.quick, probeOptions: saved.probe, premiumOptions: saved.premium, settlementOptions: saved.settlement });
  }
}

const quick = () => ({ reader: reader(), store: createMemoryStore(), env: {}, now: NOW });

test('mcp: initialize, notifications, ping and tools/list', async () => {
  await withMcp({ quick: quick() }, async (rpc) => {
    const init = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
    assert.equal(init.status, 200);
    assert.equal(init.json.result.protocolVersion, '2025-06-18');
    assert.ok(init.json.result.capabilities.tools);
    assert.equal(init.json.result.serverInfo.name, 'guardian-mcp');
    const note = await rpc('notifications/initialized', null, { notification: true });
    assert.equal(note.status, 202);
    assert.equal((await rpc('ping')).json.result && typeof (await rpc('ping')).json.result, 'object');
    const list = await rpc('tools/list');
    const names = list.json.result.tools.map((t) => t.name);
    for (const n of ['check_payment', 'probe_payment', 'verify_settlement', 'check_listing', 'check_address', 'check_domain', 'analyze_transaction', 'analyze_signature', 'guard']) assert.ok(names.includes(n), n);
    for (const t of list.json.result.tools) assert.equal(t.inputSchema.type, 'object', t.name);
  });
});

test('mcp: JSON when the client accepts JSON, SSE only when it accepts just text/event-stream', async () => {
  await withMcp({ quick: quick() }, async (rpc) => {
    const both = await rpc('tools/list', null, { headers: { accept: 'application/json, text/event-stream' } });
    assert.match(both.headers.get('content-type'), /application\/json/);
    const r = await rpc('tools/list', null, { headers: { accept: 'text/event-stream' } });
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-type'), /text\/event-stream/);
    const line = r.text.split('\n').find((l) => l.startsWith('data: '));
    assert.ok(JSON.parse(line.slice(6)).result.tools.length >= 8);
  });
});

test('mcp: check_payment tool returns the Pay-Safe verdict as structured content', async () => {
  const challenge = { x402Version: 2, resource: { url: 'https://seller.example/paid' }, accepts: [{ scheme: 'exact', network: 'eip155:196', amount: '2000000', asset: USDT0, payTo: PAY_TO, maxTimeoutSeconds: 120, extra: { name: 'USD₮0', version: '1' } }] };
  await withMcp({ quick: quick() }, async (rpc) => {
    const r = await rpc('tools/call', { name: 'check_payment', arguments: { paymentRequired: challenge, requestUrl: 'https://seller.example/paid', expected: { feeAmount: 0.002, feeToken: USDT0, endpoint: 'https://seller.example/paid' } } });
    assert.equal(r.status, 200);
    assert.equal(r.json.result.isError, false);
    assert.equal(r.json.result.structuredContent.verdict, 'DENY');
    assert.ok(r.json.result.structuredContent.reasons.includes('amount_above_listing'));
    assert.match(r.json.result.content[0].text, /amount_above_listing/);
  });
});

test('mcp: probe_payment tool checks a demo seller without paying', async () => {
  const endpoint = 'https://demo.test/demo/x402/payee-swap';
  const probe = { lookup: async () => [{ address: '76.76.21.21', family: 4 }], fetchImpl: demoFetch() };
  await withMcp({ quick: quick(), probe }, async (rpc) => {
    const r = await rpc('tools/call', { name: 'probe_payment', arguments: { url: endpoint, expected: Object.assign({ endpoint }, demo.LISTING) } });
    assert.equal(r.json.result.structuredContent.verdict, 'DENY');
    assert.ok(r.json.result.structuredContent.reasons.includes('payto_poisoning'));
    const bad = await rpc('tools/call', { name: 'probe_payment', arguments: { url: 'https://127.0.0.1/x' } });
    assert.equal(bad.json.result.isError, true);
  });
});

test('mcp: verify_settlement tool reads the receipt', async () => {
  const pad = (a) => '0x' + '0'.repeat(24) + a.slice(2);
  const receipt = { status: '0x1', blockNumber: '0x438b488', from: '0xde95edc8d29ea5a44654e40b0ab3613dfe000591', logs: [{ address: USDT0, topics: [TRANSFER_TOPIC, pad(PAY_TO), pad('0xc4622689eb6c38c929fe254777b449a5dedf9d60')], data: '0x' + (5000).toString(16).padStart(64, '0') }] };
  const fetchImpl = async (url, init) => {
    const m = JSON.parse(init.body).method;
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: m === 'eth_getTransactionReceipt' ? receipt : { timestamp: '0x68c9d634' } }));
  };
  await withMcp({ quick: quick(), settlement: { fetchImpl, rpcUrls: ['https://rpc.test'] } }, async (rpc) => {
    const r = await rpc('tools/call', { name: 'verify_settlement', arguments: { txHash: '0x' + 'd0'.repeat(32), payTo: '0xc4622689eb6c38c929fe254777b449a5dedf9d60', amount: 5000 } });
    assert.equal(r.json.result.structuredContent.ok, true, JSON.stringify(r.json.result));
    assert.equal(r.json.result.structuredContent.blockNumber, 70825096);
  });
});

test('mcp: protocol errors', async () => {
  await withMcp({ quick: quick() }, async (rpc) => {
    const unknown = await rpc('tools/call', { name: 'nope', arguments: {} });
    assert.equal(unknown.json.error.code, -32602);
    const method = await rpc('resources/list');
    assert.equal(method.json.error.code, -32601);
    const parse = await rpc(null, null, { raw: '{not json' });
    assert.equal(parse.status, 400);
    assert.equal(parse.json.error.code, -32700);
    const get = await rpc(null, null, { method: 'GET' });
    assert.equal(get.status, 405);
    const batch = await rpc(null, null, { raw: JSON.stringify([{ jsonrpc: '2.0', id: 1, method: 'ping' }]) });
    assert.equal(batch.json.error.code, -32600);
  });
});

test('mcp: paid guard tool without OKX credentials is a tool error, never a 402', async () => {
  await withMcp({ quick: quick(), premium: { env: {} } }, async (rpc) => {
    const r = await rpc('tools/call', { name: 'guard', arguments: { to: USDT0, data: '0x' } });
    assert.equal(r.status, 200);
    assert.equal(r.json.result.isError, true);
    assert.match(r.json.result.content[0].text, /not available yet/);
    assert.equal(r.headers.get('payment-required'), null);
  });
});

test('mcp: paid guard tool answers 402 at tools/call, then settles a paid replay', async () => {
  const facilitator = fakeFacilitator();
  await withMcp({ quick: quick(), premium: { env: ENV, facilitatorClient: facilitator } }, async (rpc) => {
    const list = await rpc('tools/list');
    assert.equal(list.status, 200, 'tools/list stays free');
    const args = { to: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', data: '0x', chainId: 1 };
    const unpaid = await rpc('tools/call', { name: 'guard', arguments: args });
    assert.equal(unpaid.status, 402);
    const header = unpaid.headers.get('payment-required');
    assert.ok(header);
    const required = decodePaymentRequiredHeader(header);
    assert.equal(required.accepts[0].network, 'eip155:196');
    assert.equal(required.accepts[0].amount, '99000');
    assert.equal(unpaid.json.error.code, 402);
    assert.equal(unpaid.json.error.data.accepts[0].payTo.toLowerCase(), PAY_TO);
    const reqs = required.accepts[0];
    const payment = encodePaymentSignatureHeader({ x402Version: 2, scheme: reqs.scheme, network: reqs.network, accepted: reqs, payload: { signature: '0x' + 'ab'.repeat(65), authorization: { from: PAYER, to: reqs.payTo, value: reqs.amount, validAfter: '0', validBefore: '9999999999', nonce: '0x' + '22'.repeat(32) } } });
    const paid = await rpc('tools/call', { name: 'guard', arguments: args }, { headers: { 'payment-signature': payment } });
    assert.equal(paid.status, 200, paid.text);
    assert.equal(paid.json.result.isError, false);
    assert.equal(paid.json.result.structuredContent.details.premium, true);
    assert.equal(paid.json.result.structuredContent.details.payment.payer.toLowerCase(), PAYER);
    assert.equal(facilitator.calls.settle, 1);
    assert.ok(paid.headers.get('payment-response'));
  });
});

test('mcp: check_listing tool reads the published trust scan, with a historical fallback', async () => {
  await withMcp({ quick: quick() }, async (rpc) => {
    // sid 39876 (the malicious listing) was flagged on 16 Sep and later dropped off the marketplace; it must
    // stay checkable via the dated-snapshot fallback even though it is not in the current scan.
    const hit = await rpc('tools/call', { name: 'check_listing', arguments: { sid: 39876 } });
    const sc = hit.json.result.structuredContent;
    assert.equal(sc.found, true);
    assert.equal(sc.verdict, 'DENY');
    assert.ok(sc.reasons.includes('endpoint_url_injection'));
    // Either it is in the current scan (current:true) or it comes from a dated snapshot (current:false + a date).
    if (sc.current === false) assert.match(sc.scanDate, /^\d{4}-\d{2}-\d{2}$/);
    const miss = await rpc('tools/call', { name: 'check_listing', arguments: { sid: 99999999 } });
    assert.equal(miss.json.result.structuredContent.found, false);
    const bad = await rpc('tools/call', { name: 'check_listing', arguments: { sid: 'x' } });
    assert.equal(bad.json.result.isError, true);
  });
});

test('mcp: dogfood, Pay-Safe probes the paid guard tool of this MCP server and checks its challenge', async () => {
  const facilitator = fakeFacilitator();
  const handler = require('../api/index.js');
  const saved = handler.premiumOptions;
  handler.premiumOptions = { env: ENV, facilitatorClient: facilitator };
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = 'http://127.0.0.1:' + server.address().port + '/mcp';
  try {
    const { mcpProbe, challengeOf } = require('../src/x402-probe');
    const { checkPayment } = require('../src/paysafe');
    const probe = await mcpProbe(url, { tool: 'guard', args: { to: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', data: '0x' } });
    assert.equal(probe.status, 402);
    const verdict = await checkPayment({ paymentRequired: challengeOf(probe), requestUrl: url, expected: { feeAmount: 0.099, feeToken: USDT0, endpoint: url, payTo: PAY_TO } }, quick());
    assert.notEqual(verdict.verdict, 'DENY', JSON.stringify(verdict.reasons));
    // A local test server is plain http on a bare IP, so only those transport/host warnings may appear.
    assert.deepEqual(verdict.reasons.filter((r) => !['insecure_payment_endpoint', 'endpoint_domain_suspicious'].includes(r)), [], JSON.stringify(verdict.reasons));
    assert.equal(verdict.details.selected.amount.atomic, '99000');
    assert.equal(verdict.details.selected.asset.canonical, true);
    assert.equal(facilitator.calls.settle, 0, 'nothing was paid');
  } finally {
    server.close();
    handler.premiumOptions = saved;
  }
});

test('HTTP: POST /verify-settlement verifies a receipt and rejects bad input', async () => {
  const pad = (a) => '0x' + '0'.repeat(24) + a.slice(2);
  const payee = '0xc4622689eb6c38c929fe254777b449a5dedf9d60';
  const receipt = { status: '0x1', blockNumber: '0x438b488', from: '0xde95edc8d29ea5a44654e40b0ab3613dfe000591', logs: [{ address: USDT0, topics: [TRANSFER_TOPIC, pad(PAY_TO), pad(payee)], data: '0x' + (5000).toString(16).padStart(64, '0') }] };
  const fetchImpl = async (u, init) => new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: JSON.parse(init.body).method === 'eth_getTransactionReceipt' ? receipt : { timestamp: '0x68c9d634' } }));
  const handler = require('../api/index.js');
  const saved = handler.settlementOptions;
  handler.settlementOptions = { fetchImpl, rpcUrls: ['https://rpc.test'] };
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  try {
    const ok = await fetch(base + '/verify-settlement', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ txHash: '0x' + 'd0'.repeat(32), payTo: payee, amount: 5000 }) });
    assert.equal(ok.status, 200);
    assert.equal((await ok.json()).ok, true);
    const bad = await fetch(base + '/verify-settlement', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ txHash: '0x12', payTo: payee, amount: 5000 }) });
    assert.equal(bad.status, 400);
  } finally {
    server.close();
    handler.settlementOptions = saved;
  }
});

test('mcp and HTTP: check_quote checks a persisted Onchain OS quote and binds the verdict', async () => {
  const quote = require('./fixtures/state-price-bait.json');
  const expected = Object.assign({ endpoint: 'https://guardian-mcp-rho.vercel.app/demo/x402/price-bait' }, demo.LISTING);
  await withMcp({ quick: quick() }, async (rpc) => {
    const names = (await rpc('tools/list')).json.result.tools.map((t) => t.name);
    assert.ok(names.includes('check_quote'));
    const r = await rpc('tools/call', { name: 'check_quote', arguments: { quote, expected } });
    assert.equal(r.json.result.isError, false);
    const v = r.json.result.structuredContent;
    assert.equal(v.verdict, 'DENY');
    assert.ok(v.reasons.includes('amount_above_listing'));
    assert.ok(v.reasons.includes('quote_expired'));
    assert.equal(v.next_command, null);
    assert.equal(v.binding.paymentId, 'pay_ab29f55e5a11a76c3d24640e');
    const bad = await rpc('tools/call', { name: 'check_quote', arguments: {} });
    assert.equal(bad.json.result.isError, true);
  });
  const handler = require('../api/index.js');
  const saved = handler.quickOptions;
  handler.quickOptions = quick();
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  try {
    const ok = await fetch(base + '/check-quote', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ quote, sid: 39856 }) });
    assert.equal(ok.status, 200);
    const j = await ok.json();
    assert.equal(j.details.quote.paymentId, 'pay_ab29f55e5a11a76c3d24640e');
    const bad = await fetch(base + '/check-quote', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ quote: { payment_id: 'nope' } }) });
    assert.equal(bad.status, 400);
  } finally {
    server.close();
    handler.quickOptions = saved;
  }
});
