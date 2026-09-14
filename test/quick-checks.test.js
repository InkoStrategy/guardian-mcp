'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { checkAddress, checkDomain } = require('../src/quick-checks');
const { createMemoryStore } = require('../src/store');
const seed = require('../src/seed');

const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3';
const ACTIVE = '0x1111111111111111111111111111111111111111';
const FRESH = '0x2222222222222222222222222222222222222222';
const DRAINER = '0xdead00000000000000000000000000000000beef';

function reader() {
  const map = new Map([
    [PERMIT2.toLowerCase(), { isContract: true, txCount: 1, balance: '0', codeSize: 5000, code: '0x' + '60'.repeat(5000) }],
    [ACTIVE.toLowerCase(), { isContract: false, txCount: 99, balance: '2000000000000000000', codeSize: 0, code: '0x' }],
    [FRESH.toLowerCase(), { isContract: false, txCount: 0, balance: '0', codeSize: 0, code: '0x' }],
    [DRAINER, { isContract: false, txCount: 3, balance: '10000000000000000', codeSize: 0, code: '0x' }],
  ]);
  return { endpoint: 'fake://chain', async addressState(a) { return Object.assign({ address: a }, map.get(a.toLowerCase()) || { isContract: false, txCount: 0, balance: '0', codeSize: 0, code: '0x' }); } };
}

test('check-address: recipient roles, spender roles, registry, seed and look-alikes', async () => {
  const store = createMemoryStore();
  await seed.applySeed(store, { source: 't', sha: 's', addresses: [DRAINER], domains: ['evil-airdrop.com'] });
  const deps = { reader: reader(), store, env: {} };

  const ok = await checkAddress({ address: ACTIVE }, deps);
  assert.equal(ok.verdict, 'ALLOW');
  assert.equal(ok.details.reputation.tier, 'neutral');
  assert.match(ok.summary, /a wallet address/);

  const fresh = await checkAddress({ address: FRESH }, deps);
  assert.equal(fresh.verdict, 'WARN');
  assert.deepEqual(fresh.reasons, ['fresh_recipient']);

  const spenderEoa = await checkAddress({ address: ACTIVE, role: 'spender' }, deps);
  assert.equal(spenderEoa.verdict, 'DENY');
  assert.deepEqual(spenderEoa.reasons, ['approval_to_eoa']);

  const permit2 = await checkAddress({ address: PERMIT2, role: 'spender' }, deps);
  assert.equal(permit2.verdict, 'ALLOW');
  assert.equal(permit2.details.known.name, 'Permit2');
  assert.equal(permit2.details.reputation.tier, 'trusted');

  const drainerSend = await checkAddress({ address: DRAINER }, deps);
  assert.equal(drainerSend.verdict, 'DENY', 'curated list: sending to a listed drainer is blocked');
  assert.ok(drainerSend.reasons.includes('scam_database_address'));
  assert.equal(drainerSend.details.scam_database, true);
  const drainerApprove = await checkAddress({ address: DRAINER, role: 'spender' }, deps);
  assert.equal(drainerApprove.verdict, 'DENY');

  const fake = await checkAddress({ address: '0x0000' + 'ab'.repeat(16) + '8ba3', role: 'spender' }, deps);
  assert.ok(fake.reasons.includes('contract_lookalike'));

  await assert.rejects(checkAddress({ address: 'nope' }, deps), /address/);
  await assert.rejects(checkAddress({ address: ACTIVE, chainId: 999999 }, deps), /chainId/);
});

test('check-address: RPC outage degrades to WARN', async () => {
  const broken = { endpoint: 'x', async addressState() { const { RpcError } = require('../src/rpc'); throw new RpcError('down'); } };
  const r = await checkAddress({ address: ACTIVE }, { reader: broken, store: createMemoryStore(), env: {} });
  assert.equal(r.verdict, 'WARN');
  assert.deepEqual(r.reasons, ['rpc_unavailable']);
});

test('check-domain: trusted, phishing pattern, seeded database, plain url, bad input', async () => {
  const store = createMemoryStore();
  await seed.applySeed(store, { source: 't', sha: 's', addresses: [], domains: ['racksbet.com'] });
  const deps = { store, env: {} };
  const t = await checkDomain({ url: 'https://app.uniswap.org/swap' }, deps);
  assert.equal(t.verdict, 'ALLOW');
  assert.equal(t.details.trusted, true);
  const p = await checkDomain({ domain: 'okx-airdrop-claim.xyz' }, deps);
  assert.equal(p.verdict, 'DENY');
  assert.ok(p.reasons.includes('injection_pattern'));
  const s = await checkDomain({ url: 'http://www.racksbet.com/promo' }, deps);
  assert.equal(s.verdict, 'DENY');
  assert.ok(s.reasons.includes('scam_database_domain'));
  const n = await checkDomain({ domain: 'docs.example.org' }, deps);
  assert.equal(n.verdict, 'ALLOW');
  await assert.rejects(checkDomain({}, deps), /domain/);
});

test('HTTP: /check-address and /check-domain respond and validate', async () => {
  const handler = require('../api/index.js');
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  const post = async (path, body) => { const r = await fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status, body: await r.json() }; };
  try {
    const bad = await post('/check-address', { address: 'x' });
    assert.equal(bad.status, 400);
    const dom = await post('/check-domain', { domain: 'metamask.io.secure-login.xyz' });
    assert.equal(dom.status, 200);
    assert.equal(dom.body.verdict, 'DENY');
  } finally {
    server.close();
  }
});
