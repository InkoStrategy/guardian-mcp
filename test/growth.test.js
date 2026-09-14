'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { Interface } = require('ethers');
const { analyze } = require('../src/analyzer');
const { createMemoryStore } = require('../src/store');
const seed = require('../src/seed');
const stats = require('../src/stats');
const feedback = require('../src/feedback');
const pricing = require('../src/pricing');

const erc20 = new Interface(['function approve(address spender, uint256 amount)', 'function transfer(address to, uint256 amount)']);
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const V2ROUTER = '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D';
const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3';
const USER = '0x1111111111111111111111111111111111111111';
const DRAINER = '0xdead00000000000000000000000000000000beef';
const FRIEND = '0x3333333333333333333333333333333333333333';

function fakeChain() {
  const CONTRACT = { isContract: true, txCount: 1, balance: '0', codeSize: 4000, code: '0x' + '60'.repeat(4000) };
  const map = new Map([[USDC.toLowerCase(), CONTRACT], [V2ROUTER.toLowerCase(), CONTRACT], [DRAINER, CONTRACT], [USER.toLowerCase(), { isContract: false, txCount: 10, balance: '1000000000000000000', codeSize: 0, code: '0x' }], [FRIEND.toLowerCase(), { isContract: false, txCount: 50, balance: '1000000000000000000', codeSize: 0, code: '0x' }]]);
  return { endpoint: 'fake://chain', async addressState(address) { return Object.assign({ address }, map.get(address.toLowerCase()) || { isContract: false, txCount: 0, balance: '0', codeSize: 0, code: '0x' }); } };
}
const reader = fakeChain();
const deps = (store, extra) => Object.assign({ reader, store, env: {} }, extra || {});

const LISTS = { source: 'test-list', addresses: [DRAINER, PERMIT2.toLowerCase(), 'not-an-address', '0xABCDEF0123456789ABCDEF0123456789ABCDEF01'], domains: ['EVIL-Airdrop.com', 'https://www.claim-okx-rewards.xyz/path', 'bad', 'ok.example.org', 'weird host!'], sha: 'sha-1' };

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

test('seed: lists are normalised, registry addresses are never seeded, swap is atomic and idempotent by hash', async () => {
  const store = createMemoryStore();
  // fetchLists-equivalent normalisation happens in fetchLists; applySeed takes normalised lists. Normalise here the same way.
  const lists = { source: LISTS.source, sha: LISTS.sha, addresses: LISTS.addresses.map((a) => a.toLowerCase()).filter((a) => /^0x[0-9a-f]{40}$/.test(a) && a !== PERMIT2.toLowerCase()), domains: LISTS.domains.map(seed.normalizeHost).filter((d) => /^[a-z0-9.-]+$/.test(d) && d.includes('.')) };
  const first = await seed.applySeed(store, lists);
  assert.equal(first.changed, true);
  assert.equal(first.addresses, 2);
  assert.deepEqual(lists.domains, ['evil-airdrop.com', 'claim-okx-rewards.xyz', 'ok.example.org']);
  const again = await seed.applySeed(store, lists);
  assert.equal(again.changed, false, 'same hash is a no-op');
  const forced = await seed.applySeed(store, lists, { force: true });
  assert.equal(forced.changed, true);
  const m = await seed.meta(store);
  assert.equal(m.addresses, 2);
  assert.equal(m.domains, 3);

  const look = await seed.lookup(store, [DRAINER, V2ROUTER], ['login.evil-airdrop.com', 'ok.example.org', 'example.org', 'com']);
  assert.equal(look.addresses[DRAINER], true);
  assert.equal(look.addresses[V2ROUTER.toLowerCase()], false);
  assert.equal(look.domains['login.evil-airdrop.com'], 'evil-airdrop.com', 'parent domain matches');
  assert.equal(look.domains['ok.example.org'], 'ok.example.org');
  assert.equal(look.domains['example.org'], null, 'a seeded subdomain does not taint its parent');
  assert.equal(look.domains.com, null, 'the TLD itself never matches');
});

test('seed: seeded drainer blocks approvals, calls and transfers on first sight; seeded domain blocks', async () => {
  const store = createMemoryStore();
  await seed.applySeed(store, { source: 't', sha: 's', addresses: [DRAINER], domains: ['evil-airdrop.com'] });
  const approve = await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [DRAINER, 1n]) }, deps(store));
  assert.equal(approve.verdict, 'DENY');
  assert.ok(approve.reasons.includes('scam_database_address'));
  assert.equal(approve.details.threat_intel.seed.addresses[DRAINER], true);
  const transfer = await analyze({ to: USDC, data: erc20.encodeFunctionData('transfer', [DRAINER, 1n]) }, deps(store));
  assert.equal(transfer.verdict, 'DENY', 'curated list: transfers to a listed drainer are blocked too');
  assert.deepEqual(transfer.reasons, ['scam_database_address']);
  const call = await analyze({ to: DRAINER, data: '0xdeadbeef' + '00'.repeat(32) }, deps(store));
  assert.equal(call.verdict, 'DENY');
  const domain = await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, 1n]), context: { recent_sources: ['https://login.evil-airdrop.com/x'] } }, deps(store));
  assert.equal(domain.verdict, 'DENY');
  assert.ok(domain.reasons.includes('scam_database_domain'));
  assert.ok(domain.reasons.includes('injection_pattern'), 'static pattern also fires on the phishing keyword');
});

// ---------------------------------------------------------------------------
// Stats + feedback
// ---------------------------------------------------------------------------

test('stats: usage counters, daily buckets, distinct sessions; public snapshot hides per-rule data', async () => {
  const store = createMemoryStore();
  const t0 = Date.UTC(2026, 8, 13, 12, 0, 0);
  await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, 1n]), context: { session_id: 'a' } }, deps(store, { now: t0 }));
  await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [USER, 1n]) }, deps(store, { now: t0 + 1000 }));
  await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, 2n ** 256n - 1n]), context: { session_id: 'b' } }, deps(store, { now: t0 + 2000 }));
  const pub = await stats.snapshot(store, { now: t0 + 3000, ruleCodes: ['unlimited_approval', 'unknown_spender'] });
  assert.equal(pub.calls.total, 3);
  assert.deepEqual(pub.verdicts, { ALLOW: 1, WARN: 1, DENY: 1 });
  assert.equal(pub.distinct_sessions, 2);
  assert.equal(pub.blocked_share, 33.3);
  assert.equal(pub.daily[pub.daily.length - 1].calls, 3);
  assert.equal(pub.daily[pub.daily.length - 1].sessions, 2);
  assert.equal(pub.rules, undefined, 'public view must not expose per-rule counters');
  assert.deepEqual(Object.keys(pub.feedback), ['total']);
  const internal = await stats.snapshot(store, { now: t0 + 3000, ruleCodes: ['unlimited_approval', 'unknown_spender'], internal: true });
  assert.equal(internal.rules.find((r) => r.code === 'unlimited_approval').hits, 1);
});

test('feedback: validation, false positives per rule, missed attacks, rate limit', async () => {
  const store = createMemoryStore();
  const rules = new Set(['unlimited_approval', 'fresh_recipient']);
  assert.throws(() => feedback.normalize({ verdict: 'MAYBE', correct: true }, rules), /verdict/);
  assert.throws(() => feedback.normalize({ verdict: 'WARN', correct: 'yes' }, rules), /correct/);
  assert.throws(() => feedback.normalize({ verdict: 'WARN', correct: false }, rules), /rule_codes/);
  assert.throws(() => feedback.normalize({ verdict: 'WARN', correct: false, rule_codes: ['nope'] }, rules), /unknown rule code/);
  const fp = feedback.normalize({ verdict: 'WARN', correct: false, rule_codes: ['fresh_recipient'], comment: 'it was my own new wallet', request_id: 'abcd1234-ef' }, rules);
  await feedback.submit(store, fp, 'agent-1', 1_000);
  await feedback.submit(store, feedback.normalize({ verdict: 'WARN', correct: true, rule_code: 'fresh_recipient' }, rules), 'agent-2', 2_000);
  await feedback.submit(store, feedback.normalize({ verdict: 'ALLOW', correct: false }, rules), 'agent-3', 3_000);
  const snap = await stats.snapshot(store, { internal: true, ruleCodes: ['fresh_recipient'] });
  const fr = snap.rules.find((r) => r.code === 'fresh_recipient');
  assert.equal(fr.feedback_false, 1);
  assert.equal(fr.feedback_correct, 1);
  assert.equal(fr.false_share, 50);
  assert.equal(snap.feedback.missed_attacks, 1, 'ALLOW marked wrong = missed attack');
  const recent = await feedback.recent(store, 10);
  assert.equal(recent.length, 3);
  assert.equal(recent[0].verdict, 'ALLOW');
  for (let i = 0; i < feedback.RATE_LIMIT_PER_HOUR; i += 1) await feedback.submit(store, fp, 'spammer', 10_000);
  await assert.rejects(feedback.submit(store, fp, 'spammer', 10_000), /rate limit/);
});

// ---------------------------------------------------------------------------
// Pricing (dormant in wave 1; logic must still be right)
// ---------------------------------------------------------------------------

test('pricing: free by default; premium detection; auto mode switches by usage AND elapsed days, never by date alone', async () => {
  const store = createMemoryStore();
  assert.deepEqual(pricing.premiumFeatures('transaction', { context: {} }), []);
  assert.deepEqual(pricing.premiumFeatures('transaction', { context: { session_id: 's', alert_webhook: 'https://x', reference_tx: {} } }), ['session_health', 'owner_alerts', 'differential_check']);
  assert.deepEqual(pricing.premiumFeatures('signature', {}), ['signature_analysis']);
  const free = await pricing.resolve(store, {});
  assert.equal(free.charging, false);
  const noPrice = await pricing.resolve(store, { PRICING_MODE: 'premium' });
  assert.equal(noPrice.charging, false, 'premium mode without a price charges nothing');
  const prem = await pricing.resolve(store, { PRICING_MODE: 'premium', X402_PREMIUM_PRICE: '10000' });
  assert.equal(prem.charging, true);
  const env = { PRICING_MODE: 'auto', X402_PREMIUM_PRICE: '10000', FREE_CALLS: '3', FREE_SESSIONS: '2', FREE_DAYS: '30' };
  const t0 = Date.UTC(2026, 0, 1);
  const a0 = await pricing.resolve(store, env, t0);
  assert.equal(a0.charging, false);
  for (let i = 0; i < 3; i += 1) await stats.record(store, { now: t0 + i, verdict: 'ALLOW', kind: 'transaction', codes: [], sessionId: 's' + i });
  const usageOnly = await pricing.resolve(store, env, t0 + 5 * 86400000);
  assert.equal(usageOnly.charging, false, 'usage reached but 30 days not passed');
  assert.match(usageOnly.reason, /days since first call/);
  const both = await pricing.resolve(store, env, t0 + 31 * 86400000);
  assert.equal(both.charging, true);
  const sticky = await pricing.resolve(store, env, t0 + 32 * 86400000);
  assert.match(sticky.reason, /active since/);
  assert.equal(pricing.isGrandfathered(USER, { GRANDFATHERED_PAYERS: USER.toLowerCase() + ',0xabc' }), true);
});

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

test('HTTP: /stats public, /admin/stats needs token, /dashboard is HTML, /feedback works, /cron/seed is protected', async () => {
  process.env.ADMIN_TOKEN = 'test-admin-token';
  process.env.CRON_SECRET = 'test-cron-secret';
  const handler = require('../api/index.js');
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  const j = async (method, path, body, headers) => {
    const r = await fetch(base + path, { method, headers: Object.assign({ 'content-type': 'application/json' }, headers || {}), body: body ? JSON.stringify(body) : undefined });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* html */ }
    return { status: r.status, body: json, text, type: r.headers.get('content-type') };
  };
  try {
    const an = await j('POST', '/analyze', { to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, 1n]) });
    assert.equal(an.status, 200);
    assert.match(an.body.details.request_id, /^[0-9a-f-]{36}$/);
    const pub = await j('GET', '/stats');
    assert.equal(pub.status, 200);
    assert.ok(pub.body.calls.total >= 1);
    assert.equal(pub.body.rules, undefined);
    const noAuth = await j('GET', '/admin/stats');
    assert.equal(noAuth.status, 401);
    const admin = await j('GET', '/admin/stats', null, { 'x-admin-token': 'test-admin-token' });
    assert.equal(admin.status, 200);
    assert.ok(Array.isArray(admin.body.rules));
    assert.ok(Array.isArray(admin.body.recent_feedback));
    assert.equal(admin.body.pricing.charging, false);
    const dash = await j('GET', '/dashboard');
    assert.equal(dash.status, 200);
    assert.match(dash.type, /text\/html/);
    assert.match(dash.text, /Guardian MCP/);
    const fb = await j('POST', '/feedback', { request_id: an.body.details.request_id, verdict: 'ALLOW', correct: true });
    assert.equal(fb.status, 200);
    assert.equal(fb.body.accepted, true);
    const badFb = await j('POST', '/feedback', { verdict: 'DENY', correct: false, rule_codes: ['made_up'] });
    assert.equal(badFb.status, 400);
    const cronNo = await j('GET', '/cron/seed');
    assert.equal(cronNo.status, 401);
    const cronBad = await j('GET', '/cron/seed', null, { authorization: 'Bearer wrong' });
    assert.equal(cronBad.status, 401);
  } finally {
    server.close();
    delete process.env.ADMIN_TOKEN;
    delete process.env.CRON_SECRET;
  }
});
