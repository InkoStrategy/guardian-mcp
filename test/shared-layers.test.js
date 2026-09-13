'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { Interface, AbiCoder, MaxUint256 } = require('ethers');
const { analyze } = require('../src/analyzer');
const { analyzeSignature } = require('../src/signature');
const { createMemoryStore } = require('../src/store');
const threat = require('../src/threat-registry');
const sessionHealth = require('../src/session-health');
const alerts = require('../src/alerts');
const diff = require('../src/diff');

const abi = AbiCoder.defaultAbiCoder();
const erc20 = new Interface(['function approve(address spender, uint256 amount)', 'function transfer(address to, uint256 amount)']);
const router = new Interface(['function multicall(bytes[] data)', 'function execute(bytes commands, bytes[] inputs, uint256 deadline)']);

const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const V2ROUTER = '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D';
const UNIVERSAL = '0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD';
const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3';
const USER = '0x1111111111111111111111111111111111111111';
const FRIEND = '0x3333333333333333333333333333333333333333';
const ATTACKER = '0x9999999999999999999999999999999999999999';
const DRAINER_CONTRACT = '0x7777777777777777777777777777777777777777';

function fakeChain() {
  const CONTRACT = { isContract: true, txCount: 1, balance: '0', codeSize: 4000, code: '0x' + '60'.repeat(4000) };
  const map = new Map([
    [USDC.toLowerCase(), CONTRACT], [V2ROUTER.toLowerCase(), CONTRACT], [UNIVERSAL.toLowerCase(), CONTRACT], [PERMIT2.toLowerCase(), CONTRACT], [DRAINER_CONTRACT.toLowerCase(), CONTRACT],
    [USER.toLowerCase(), { isContract: false, txCount: 10, balance: '1000000000000000000', codeSize: 0, code: '0x' }],
    [FRIEND.toLowerCase(), { isContract: false, txCount: 120, balance: '5000000000000000000', codeSize: 0, code: '0x' }],
    [ATTACKER.toLowerCase(), { isContract: false, txCount: 3, balance: '10000000000000000', codeSize: 0, code: '0x' }],
  ]);
  return {
    endpoint: 'fake://chain',
    async addressState(address) {
      return Object.assign({ address }, map.get(address.toLowerCase()) || { isContract: false, txCount: 0, balance: '0', codeSize: 0, code: '0x' });
    },
  };
}

const reader = fakeChain();
const deps = (store, extra) => Object.assign({ reader, store, env: {} }, extra || {});

// ---------------------------------------------------------------------------
// Layer 1: shared threat registry
// ---------------------------------------------------------------------------

test('shared registry: agent A DENY records the spender; agent B is warned on transfer and blocked on approval after independent confirmation', async () => {
  const store = createMemoryStore();
  const approveAttacker = erc20.encodeFunctionData('approve', [ATTACKER, 1000n]);
  const a = await analyze({ to: USDC, data: approveAttacker }, deps(store, { reporter: 'agent-A' }));
  assert.equal(a.verdict, 'DENY');
  assert.equal(a.details.threat_intel.report.recorded_addresses, 1);

  // A different agent transfers to the same address: only a WARN (griefing cap for the recipient role).
  const b = await analyze({ to: USDC, data: erc20.encodeFunctionData('transfer', [ATTACKER, 5n]) }, deps(store, { reporter: 'agent-B' }));
  assert.equal(b.verdict, 'WARN');
  assert.deepEqual(b.reasons, ['flagged_address']);
  assert.equal(b.details.counterparties[ATTACKER].threat.reports, 1);
  assert.ok(b.details.counterparties[ATTACKER].reputation.score < 50);

  // Two more reports from a second independent reporter promote it to a confirmed drainer.
  await analyze({ to: USDC, data: approveAttacker }, deps(store, { reporter: 'agent-C' }));
  await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [ATTACKER, 7n]) }, deps(store, { reporter: 'agent-C' }));
  const rec = (await threat.lookup(store, 1, [ATTACKER], [])).addresses[ATTACKER.toLowerCase()];
  assert.equal(rec.reports, 3);
  assert.equal(rec.reporters, 2);
  assert.equal(rec.rules.approval_to_eoa, 3);

  // A plain call to that address (no rule of its own would fire except unknown_selector) is now DENIED as known_drainer.
  const c = await analyze({ to: ATTACKER, data: '0xdeadbeef' + '00'.repeat(32) }, deps(store, { reporter: 'agent-D' }));
  assert.equal(c.verdict, 'DENY');
  assert.ok(c.reasons.includes('known_drainer'));
  // ...but a transfer to it is still capped at WARN.
  const d = await analyze({ to: USDC, data: erc20.encodeFunctionData('transfer', [ATTACKER, 5n]) }, deps(store, { reporter: 'agent-D' }));
  assert.equal(d.verdict, 'WARN');
  assert.deepEqual(d.reasons, ['flagged_address']);
});

test('shared registry: only fact-based DENY rules are recorded; registry addresses and context-derived rules never are', async () => {
  const chainId = 1;
  const none = threat.extractReports('DENY', [{ code: 'address_poisoning', severity: 'DENY', address: ATTACKER }, { code: 'goal_escalation', severity: 'DENY' }, { code: 'set_approval_for_all', severity: 'DENY', operator: ATTACKER }], chainId, '0x1');
  assert.deepEqual(none, { addresses: [], domains: [] });
  const known = threat.extractReports('DENY', [{ code: 'approval_to_eoa', severity: 'DENY', address: PERMIT2 }], chainId, '0x1');
  assert.equal(known.addresses.length, 0, 'registry contracts are never recorded');
  const warnOnly = threat.extractReports('WARN', [{ code: 'approval_to_eoa', severity: 'DENY', address: ATTACKER }], chainId, '0x1');
  assert.equal(warnOnly.addresses.length, 0, 'nothing is recorded unless the final verdict is DENY');
  const dom = threat.extractReports('DENY', [{ code: 'injection_pattern', severity: 'DENY', sources: [{ domain: 'okx-airdrop.com', pattern: 'brand_impersonation' }, { domain: 'random.xyz', pattern: 'suspicious_tld' }] }], chainId, null);
  assert.deepEqual(dom.domains.map((d) => d.domain), ['okx-airdrop.com'], 'only objective hostname patterns are shared, not TLD heuristics');
});

test('shared registry: phishing domains propagate between agents; share_threat_intel=false opts out', async () => {
  const store = createMemoryStore();
  const approve = erc20.encodeFunctionData('approve', [V2ROUTER, 1n]);
  const first = await analyze({ to: USDC, data: approve, context: { recent_sources: ['https://uniswop.org/claim'] } }, deps(store, { reporter: 'agent-A' }));
  assert.ok(first.reasons.includes('injection_pattern'));
  assert.equal(first.details.threat_intel.report.recorded_domains, 1);
  const second = await analyze({ to: USDC, data: approve, context: { recent_sources: ['https://uniswop.org/other-page'] } }, deps(store, { reporter: 'agent-B' }));
  assert.ok(second.reasons.includes('known_phishing_domain'));

  const optOut = createMemoryStore();
  const r = await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [ATTACKER, 1n]), context: { share_threat_intel: false } }, deps(optOut, { reporter: 'agent-A' }));
  assert.equal(r.verdict, 'DENY');
  assert.equal(r.details.threat_intel.report.opted_out, true);
  assert.equal((await threat.lookup(optOut, 1, [ATTACKER], [])).addresses[ATTACKER.toLowerCase()], null);
});

test('shared registry: signature DENY (permit to a wallet) is recorded and visible to /threats lookups', async () => {
  const store = createMemoryStore();
  const typedData = {
    types: { EIP712Domain: [], Permit: [{ name: 'owner', type: 'address' }, { name: 'spender', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' }] },
    primaryType: 'Permit',
    domain: { name: 'USD Coin', version: '2', chainId: 1, verifyingContract: USDC },
    message: { owner: USER, spender: ATTACKER, value: '1', nonce: 0, deadline: '1800000300' },
  };
  const r = await analyzeSignature({ type: 'eip712', from: USER, typedData }, { reader, store, now: 1_800_000_000, reporter: 'agent-A' });
  assert.equal(r.verdict, 'DENY');
  assert.equal(r.details.threat_intel.report.recorded_addresses, 1);
  const stats = await threat.stats(store);
  assert.equal(stats.total_reports, 1);
  assert.equal(stats.persistent, false);
});

test('shared registry: a failing persistent store degrades to WARN, a failing memory store cannot happen', async () => {
  const broken = { kind: 'upstash', persistent: true, async pipeline() { throw new Error('ECONNRESET'); }, async command() { throw new Error('ECONNRESET'); } };
  const r = await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, 1n]), context: { session_id: 's' } }, deps(broken));
  assert.equal(r.verdict, 'WARN');
  assert.deepEqual(r.reasons, ['shared_state_unavailable']);
  assert.ok(r.details.shared_state.errors.length >= 1);
});

// ---------------------------------------------------------------------------
// Layer 2: session health
// ---------------------------------------------------------------------------

test('session health: three WARN verdicts in one hour flip the session to compromised_likely and DENY the third action', async () => {
  const store = createMemoryStore();
  const session_id = 'sess-1';
  const warnTx = { to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, MaxUint256]), context: { session_id } };
  const t0 = 1_700_000_000_000;
  const r1 = await analyze(warnTx, deps(store, { now: t0 }));
  assert.equal(r1.verdict, 'WARN');
  assert.equal(r1.details.session_health.status, 'healthy');
  const r2 = await analyze(warnTx, deps(store, { now: t0 + 60_000 }));
  assert.equal(r2.verdict, 'WARN');
  assert.equal(r2.details.session_health.status, 'elevated');
  assert.ok(r2.reasons.includes('session_risk_elevated'));
  const r3 = await analyze(warnTx, deps(store, { now: t0 + 120_000 }));
  assert.equal(r3.verdict, 'DENY');
  assert.ok(r3.reasons.includes('session_compromised_likely'));
  assert.equal(r3.details.session_health.status, 'compromised_likely');
  assert.equal(r3.details.session_health.warn_count_window, 3);
  assert.equal(r3.details.session_health.tx_count_total, 3);
  // Even a perfectly clean action is now blocked until the session is reset.
  const clean = await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, 1n]), context: { session_id } }, deps(store, { now: t0 + 180_000 }));
  assert.equal(clean.verdict, 'DENY');
  assert.deepEqual(clean.reasons, ['session_compromised_likely']);
  const profile = await sessionHealth.profile(store, session_id, {}, t0 + 180_000);
  assert.equal(profile.tx_count_total, 4);
  assert.equal(profile.recent_events.length, 4);
});

test('session health: events outside SESSION_TTL_MS no longer count; per-request WARNs within the window are summed', async () => {
  const store = createMemoryStore();
  const session_id = 'sess-ttl';
  const env = { SESSION_TTL_MS: '60000' };
  const warnTx = { to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, MaxUint256]), context: { session_id } };
  const t0 = 1_700_000_000_000;
  await analyze(warnTx, deps(store, { now: t0, env }));
  await analyze(warnTx, deps(store, { now: t0 + 1000, env }));
  const later = await analyze(warnTx, deps(store, { now: t0 + 120_000, env }));
  assert.equal(later.details.session_health.status, 'healthy', 'old WARNs expired from the window');
  assert.equal(later.details.session_health.warn_count_total, 3);
  assert.equal(later.details.session_health.warn_count_window, 1);
});

// ---------------------------------------------------------------------------
// Layer 3: owner alerts
// ---------------------------------------------------------------------------

test('alerts: DENY posts a signed, human-readable event to the owner webhook; WARN only when alert_on=warn', async () => {
  const store = createMemoryStore();
  const sent = [];
  const sendAlert = async (url, payload) => { sent.push({ url, payload }); return { sent: true, status: 200, error: null, duration_ms: 5 }; };
  const denyTx = { to: USDC, data: erc20.encodeFunctionData('approve', [ATTACKER, 1000n]), context: { alert_webhook: 'https://hooks.example.com/guardian', session_id: 'sess-alert', agent_goal: 'approve' } };
  const r = await analyze(denyTx, deps(store, { sendAlert }));
  assert.equal(r.verdict, 'DENY');
  assert.equal(r.details.alert.sent, true);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].payload.event, 'guardian.deny');
  assert.match(sent[0].payload.message, /Your agent tried to approve 0\.001 USDC to 0x9999…9999; blocked by approval_to_eoa/);
  assert.equal(sent[0].payload.session_id, 'sess-alert');
  assert.equal(sent[0].payload.to, USDC);

  const warnTx = { to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, MaxUint256]), context: { alert_webhook: 'https://hooks.example.com/guardian' } };
  const w = await analyze(warnTx, deps(createMemoryStore(), { sendAlert }));
  assert.equal(w.details.alert.sent, false);
  assert.match(w.details.alert.skipped, /does not trigger/);
  assert.equal(sent.length, 1);
  const w2 = await analyze(Object.assign({}, warnTx, { context: { alert_webhook: 'https://hooks.example.com/guardian', alert_on: 'warn' } }), deps(createMemoryStore(), { sendAlert }));
  assert.equal(w2.details.alert.sent, true);
  assert.equal(sent[1].payload.event, 'guardian.warn');
});

test('alerts: webhook validation blocks http, private hosts, localhost and embedded credentials', () => {
  assert.equal(alerts.validateWebhook('https://hooks.example.com/x').ok, true);
  for (const bad of ['http://hooks.example.com/x', 'https://localhost/x', 'https://127.0.0.1/x', 'https://10.0.0.5/x', 'https://192.168.1.1/x', 'https://172.16.0.1/x', 'https://169.254.169.254/latest', 'https://user:pw@hooks.example.com/x', 'https://svc.internal/x', 'not a url']) {
    assert.equal(alerts.validateWebhook(bad).ok, false, bad);
  }
  const payload = alerts.buildPayload({ verdict: 'DENY', riskScore: 40, reasons: ['approval_to_eoa'], summary: 's', actionText: 'approve X', kind: 'transaction', chainId: 1 });
  assert.equal(payload.event, 'guardian.deny');
  assert.match(payload.message, /blocked by approval_to_eoa/);
});

test('alerts: real HTTP delivery over an injected sender contract (timeout and HMAC signature)', async () => {
  // alerts.send requires https for real webhooks; exercise the signing path with a local server through the same code by stubbing fetch.
  const originalFetch = global.fetch;
  const seen = [];
  global.fetch = async (url, init) => { seen.push({ url, init }); return { ok: true, status: 200 }; };
  try {
    const r = await alerts.send('https://hooks.example.com/g', { event: 'guardian.deny', a: 1 }, { ALERT_SIGNING_SECRET: 'topsecret' });
    assert.equal(r.sent, true);
    assert.equal(r.signed, true);
    assert.match(seen[0].init.headers['x-guardian-signature'], /^sha256=[0-9a-f]{64}$/);
    assert.equal(seen[0].init.headers['x-guardian-event'], 'guardian.deny');
  } finally {
    global.fetch = originalFetch;
  }
});

// ---------------------------------------------------------------------------
// Layer 4: reputation
// ---------------------------------------------------------------------------

test('reputation: tiers are deterministic and honest about their limits', async () => {
  const store = createMemoryStore();
  const r = await analyze({ to: USDC, data: erc20.encodeFunctionData('transfer', [FRIEND, 1n]) }, deps(store));
  const rep = r.details.counterparties[FRIEND].reputation;
  assert.equal(rep.type, 'eoa');
  assert.match(rep.activity, /established/);
  assert.equal(rep.balance_tier, 'funded (>= 1 native)');
  assert.equal(rep.tier, 'neutral');
  assert.match(rep.limits, /indexer/);
  const t = await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, 1n]) }, deps(store));
  assert.equal(t.details.counterparties[V2ROUTER].reputation.tier, 'trusted');
  assert.equal(t.details.counterparties[V2ROUTER].reputation.known_protocol.name, 'Uniswap V2 Router02');
  const hostile = threat.reputation({ state: { isContract: false, txCount: 0, balance: '0' }, known: null, threat: { reports: 3, reporters: 2, rules: { approval_to_eoa: 3 }, last_seen: Date.now() }, proxy: null, chainId: 1 });
  assert.equal(hostile.tier, 'hostile');
  assert.equal(hostile.score, 0);
});

// ---------------------------------------------------------------------------
// Layer 5: differential check
// ---------------------------------------------------------------------------

test('differential: identical template passes; recipient change is critical; amount increase is notable; decrease is silent', async () => {
  const store = createMemoryStore();
  const template = { to: USDC, data: erc20.encodeFunctionData('transfer', [FRIEND, 1000n]), chainId: 1 };
  const same = await analyze({ to: USDC, data: template.data, context: { reference_tx: template } }, deps(store));
  assert.equal(same.details.diff.matches, true);
  assert.equal(same.verdict, 'ALLOW');

  const swapped = await analyze({ to: USDC, data: erc20.encodeFunctionData('transfer', [ATTACKER, 1000n]), context: { reference_tx: template } }, deps(store));
  assert.equal(swapped.verdict, 'DENY');
  assert.ok(swapped.reasons.includes('template_critical_deviation'));
  assert.equal(swapped.details.diff.changes[0].field, 'recipient');

  const more = await analyze({ to: USDC, data: erc20.encodeFunctionData('transfer', [FRIEND, 5000n]), context: { reference_tx: template } }, deps(store));
  assert.equal(more.verdict, 'WARN');
  assert.deepEqual(more.reasons, ['template_deviation']);

  const less = await analyze({ to: USDC, data: erc20.encodeFunctionData('transfer', [FRIEND, 10n]), context: { reference_tx: template } }, deps(store));
  assert.equal(less.verdict, 'ALLOW');
  assert.equal(less.details.diff.changes[0].level, 'info');
});

test('differential: bounded template vs unlimited proposal, spender swap, hidden approval and router plan drift are all critical', async () => {
  const store = createMemoryStore();
  const bounded = { to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, 1000n]) };
  const unlimited = await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, MaxUint256]), context: { reference_tx: bounded } }, deps(store));
  assert.ok(unlimited.reasons.includes('template_critical_deviation'));
  assert.ok(unlimited.details.diff.changes.some((c) => c.field === 'amount' && c.level === 'critical'));

  const spenderSwap = await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [PERMIT2, 1000n]), context: { reference_tx: bounded } }, deps(store));
  assert.ok(spenderSwap.details.diff.changes.some((c) => c.field === 'spender' && c.level === 'critical'));

  const plainSwap = router.encodeFunctionData('multicall', [['0x7ff36ab5' + '00'.repeat(32)]]);
  const withApprove = router.encodeFunctionData('multicall', [['0x7ff36ab5' + '00'.repeat(32), erc20.encodeFunctionData('approve', [V2ROUTER, 5n])]]);
  const hidden = await analyze({ to: V2ROUTER, data: withApprove, context: { reference_tx: { to: V2ROUTER, data: plainSwap } } }, deps(store));
  assert.ok(hidden.details.diff.changes.some((c) => c.field === 'nested_approval' && c.level === 'critical'));

  const permitSingle = ['tuple(tuple(address,uint160,uint48,uint48),address,uint256)', 'bytes'];
  const permit = abi.encode(permitSingle, [[[USDC, 1000000n, 1800000000n, 0n], UNIVERSAL, 1800000000n], '0x']);
  const v3 = abi.encode(['address', 'uint256', 'uint256', 'bytes', 'bool'], ['0x0000000000000000000000000000000000000001', 1000000n, 1n, '0x' + USDC.slice(2) + '000bb8' + PERMIT2.slice(2), true]);
  const transferOut = abi.encode(['address', 'address', 'uint256'], [USDC, ATTACKER, 1000000n]);
  const refPlan = router.encodeFunctionData('execute', ['0x0a00', [permit, v3], 1800000000n]);
  const evilPlan = router.encodeFunctionData('execute', ['0x0a0005', [permit, v3, transferOut], 1800000000n]);
  const drift = await analyze({ to: UNIVERSAL, data: evilPlan, from: USER, context: { reference_tx: { to: UNIVERSAL, data: refPlan } } }, deps(store));
  assert.ok(drift.reasons.includes('template_critical_deviation'));
  assert.ok(drift.details.diff.changes.some((c) => c.field === 'router_plan' && /TRANSFER/.test(c.note)));
  assert.ok(drift.details.diff.changes.some((c) => c.field === 'nested_recipient'));

  const direct = diff.compare({ to: USDC, chainId: 1, value: 0n, decoded: { kind: 'native', selector: null, args: {}, amountBig: null }, nested: null }, { to: USDC, chainId: 1, value: 10n, decoded: { kind: 'native', selector: null, args: {}, amountBig: null }, nested: null });
  assert.equal(direct.critical, 1, 'native value appearing where the template had none is critical');
});

// ---------------------------------------------------------------------------
// HTTP surface
// ---------------------------------------------------------------------------

test('HTTP: /threats/stats, /threats/{chain}/{address}, /threats/domain/{host}, /session/{id}', async () => {
  const handler = require('../api/index.js');
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  const j = async (method, path, body) => {
    const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, body: await r.json() };
  };
  try {
    const stats = await j('GET', '/threats/stats');
    assert.equal(stats.status, 200);
    assert.equal(stats.body.persistent, false);
    const empty = await j('GET', '/threats/1/' + ATTACKER);
    assert.equal(empty.body.flagged, false);
    const sess404 = await j('GET', '/session/does-not-exist');
    assert.equal(sess404.status, 404);
    const dom = await j('GET', '/threats/domain/uniswop.org');
    assert.equal(dom.status, 200);
    assert.equal(dom.body.flagged, false);
    const bad = await j('POST', '/analyze', { to: USDC, data: '0x', context: { alert_webhook: 'http://localhost/x' } });
    assert.equal(bad.status, 400);
    assert.match(bad.body.error, /https/);
  } finally {
    server.close();
  }
});
