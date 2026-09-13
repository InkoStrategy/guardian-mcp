'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { Interface, MaxUint256 } = require('ethers');
const { analyze, computeRiskScore, ValidationError, RULES, RULE_CATALOG } = require('../src/analyzer');
const ctx = require('../src/context-analyzer');
const { createMemoryStore } = require('../src/store');

const erc20 = new Interface([
  'function approve(address spender, uint256 amount)',
  'function transfer(address to, uint256 amount)',
]);
const erc721 = new Interface(['function setApprovalForAll(address operator, bool approved)']);

const TOKEN = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const ROUTER = '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D';
const EOA_ACTIVE = '0x1111111111111111111111111111111111111111';

function fakeReader() {
  const CONTRACT = { isContract: true, txCount: 1, balance: '0' };
  const ACTIVE = { isContract: false, txCount: 42, balance: '1000000000000000000' };
  const map = new Map([[TOKEN.toLowerCase(), CONTRACT], [ROUTER.toLowerCase(), ACTIVE && CONTRACT], [EOA_ACTIVE.toLowerCase(), ACTIVE]]);
  return {
    endpoint: 'fake://chain',
    async addressState(address) {
      const s = map.get(address.toLowerCase());
      if (!s) throw new Error('no fake state for ' + address);
      return Object.assign({ address }, s);
    },
  };
}

const reader = fakeReader();
const APPROVE_SMALL = erc20.encodeFunctionData('approve', [ROUTER, 1000n]);
const APPROVE_MAX = erc20.encodeFunctionData('approve', [ROUTER, MaxUint256]);
const TRANSFER_SMALL = erc20.encodeFunctionData('transfer', [EOA_ACTIVE, 1000n]);
const SWAP = '0x7ff36ab5' + '00'.repeat(32);

/** Fresh env + fresh session store per test so tests never share state. */
function deps(extra) {
  return Object.assign({ reader, env: {}, store: createMemoryStore(), sessionStore: ctx.createSessionStore({ ttlMs: 3600000 }) }, extra || {});
}

// 1. Backward compatibility: no context -> old behaviour, context_analyzed=false
test('1. without context: behaves as before and reports context_analyzed=false', async () => {
  const r = await analyze({ to: TOKEN, data: APPROVE_SMALL }, deps());
  assert.equal(r.verdict, 'ALLOW');
  assert.deepEqual(r.reasons, []);
  assert.equal(r.details.context_analyzed, false);
  assert.equal(r.details.intent_analysis, null);
  assert.deepEqual(r.details.context_signals, []);
  assert.equal(r.details.risk_score, 0);
  assert.equal(r.details.session_risk_score, 0);
});

// 2. intent_mismatch
test('2. intent_mismatch: goal=transfer but tx=approve -> WARN', async () => {
  const r = await analyze({ to: TOKEN, data: APPROVE_SMALL, context: { agent_goal: 'transfer' } }, deps());
  assert.equal(r.verdict, 'WARN');
  assert.deepEqual(r.reasons, ['intent_mismatch']);
  assert.equal(r.details.context_analyzed, true);
  assert.equal(r.details.intent_analysis.normalized_goal, 'transfer');
  assert.equal(r.details.intent_analysis.transaction_intent, 'approve');
  assert.equal(r.details.intent_analysis.match, false);
});

test('2b. matching goal gives no intent finding; "swap tokens" is compatible with approve', async () => {
  const a = await analyze({ to: TOKEN, data: APPROVE_SMALL, context: { agent_goal: 'approve' } }, deps());
  const b = await analyze({ to: TOKEN, data: APPROVE_SMALL, context: { agent_goal: 'swap tokens' } }, deps());
  const c = await analyze({ to: ROUTER, data: SWAP, context: { agent_goal: 'swap tokens' } }, deps());
  for (const r of [a, b, c]) {
    assert.equal(r.verdict, 'ALLOW');
    assert.equal(r.details.intent_analysis.match, true);
  }
});

// 3. untrusted_source_before_tx
test('3. untrusted_source_before_tx: unknown domain + small approve -> WARN; + unlimited approve -> DENY', async () => {
  const warn = await analyze({ to: TOKEN, data: APPROVE_SMALL, context: { agent_goal: 'approve', recent_sources: ['https://random-blog.example.org/post'] } }, deps());
  assert.equal(warn.verdict, 'WARN');
  assert.deepEqual(warn.reasons, ['untrusted_source_before_tx']);
  assert.equal(warn.details.findings.find((f) => f.code === 'untrusted_source_before_tx').large_amount, false);

  const deny = await analyze({ to: TOKEN, data: APPROVE_MAX, context: { agent_goal: 'approve', recent_sources: ['https://random-blog.example.org/post'] } }, deps());
  assert.equal(deny.verdict, 'DENY');
  assert.ok(deny.reasons.includes('untrusted_source_before_tx'));
  assert.ok(deny.reasons.includes('unlimited_approval'));
  assert.equal(deny.details.findings.find((f) => f.code === 'untrusted_source_before_tx').severity, 'DENY');
});

test('3b. untrusted source with a non-sensitive tx (swap) does not trigger untrusted_source_before_tx', async () => {
  const r = await analyze({ to: ROUTER, data: SWAP, context: { agent_goal: 'swap', recent_sources: ['https://random-blog.example.org/post'] } }, deps());
  assert.equal(r.verdict, 'ALLOW');
});

// 4. injection_pattern
test('4. injection_pattern: phishing domains -> DENY', async () => {
  const cases = [
    ['https://okx-airdrop-claim.com/verify', 'brand_impersonation'],
    ['https://uniswop.org/app', 'typosquatting'],
    ['https://metamask.io.secure-login.xyz/', 'brand_impersonation'],
    ['https://free-nft.zip/', 'suspicious_tld'],
    ['http://185.220.101.4/wallet', 'ip_address_host'],
    ['https://xn--0kx-9na.com/', 'punycode'],
    ['https://c0inbase.com/', 'brand_impersonation'],
  ];
  for (const [src, expected] of cases) {
    const r = await analyze({ to: TOKEN, data: APPROVE_SMALL, context: { agent_goal: 'approve', recent_sources: [src] } }, deps());
    assert.equal(r.verdict, 'DENY', src);
    assert.ok(r.reasons.includes('injection_pattern'), src);
    const f = r.details.findings.find((x) => x.code === 'injection_pattern');
    assert.equal(f.sources[0].pattern, expected, src);
  }
  // Official brand domains are NOT flagged
  assert.equal(ctx.detectPhishingPattern('app.uniswap.org'), null);
  assert.equal(ctx.detectPhishingPattern('web3.okx.com'), null);
  assert.equal(ctx.detectPhishingPattern('docs.example.com'), null);
});

// 5. rapid_context_shift
test('5. rapid_context_shift: web_fetch right before tx + goal mismatch -> WARN', async () => {
  const r = await analyze({ to: TOKEN, data: APPROVE_SMALL, context: { agent_goal: 'transfer', recent_tool_calls: ['read_file', 'web_fetch', 'analyze'] } }, deps());
  assert.equal(r.verdict, 'WARN');
  assert.ok(r.reasons.includes('rapid_context_shift'));
  assert.ok(r.reasons.includes('intent_mismatch'));
  assert.equal(r.details.context_sources.last_tool_call, 'web_fetch');

  // Same tool calls but goal matches -> no shift signal
  const ok = await analyze({ to: TOKEN, data: APPROVE_SMALL, context: { agent_goal: 'approve', recent_tool_calls: ['read_file', 'web_fetch', 'analyze'] } }, deps());
  assert.equal(ok.reasons.includes('rapid_context_shift'), false);

  // Mismatch but last tool was not an ingest tool -> no shift signal
  const noIngest = await analyze({ to: TOKEN, data: APPROVE_SMALL, context: { agent_goal: 'transfer', recent_tool_calls: ['web_fetch', 'calculate', 'analyze'] } }, deps());
  assert.equal(noIngest.reasons.includes('rapid_context_shift'), false);
});

// 6. memory_poisoning_signal
test('6. memory_poisoning_signal: 5 distinct untrusted domains accumulated in one session -> WARN', async () => {
  const d = deps();
  const session_id = 'sess-poison';
  const sources = ['https://a.example.org', 'https://b.example.org', 'https://c.example.org'];
  const first = await analyze({ to: ROUTER, data: SWAP, context: { agent_goal: 'swap', session_id, recent_sources: sources } }, d);
  assert.equal(first.reasons.includes('memory_poisoning_signal'), false, 'exactly 3 domains must not trigger');
  const second = await analyze({ to: ROUTER, data: SWAP, context: { agent_goal: 'swap', session_id, recent_sources: ['https://d.example.org', 'https://e.example.org'] } }, d);
  assert.equal(second.verdict, 'WARN');
  assert.ok(second.reasons.includes('memory_poisoning_signal'));
  assert.equal(second.details.context_sources.session_untrusted_domains.length, 5);
});

// 7. goal_escalation
test('7. goal_escalation: goal=read but tx=approve -> DENY (no duplicate intent_mismatch)', async () => {
  const r = await analyze({ to: TOKEN, data: APPROVE_SMALL, context: { agent_goal: 'read' } }, deps());
  assert.equal(r.verdict, 'DENY');
  assert.deepEqual(r.reasons, ['goal_escalation']);
  const t = await analyze({ to: TOKEN, data: TRANSFER_SMALL, context: { agent_goal: 'analyze' } }, deps());
  assert.equal(t.verdict, 'DENY');
  assert.ok(t.reasons.includes('goal_escalation'));
  const n = await analyze({ to: EOA_ACTIVE, data: '0x', value: '1', context: { agent_goal: 'analyze' } }, deps());
  assert.ok(n.reasons.includes('goal_escalation'));
});

// 8. risk_score arithmetic
test('8. computeRiskScore: weights and bonuses', () => {
  assert.equal(computeRiskScore([]), 0);
  assert.equal(computeRiskScore([{ code: 'fresh_recipient', severity: 'WARN' }]), 15);
  assert.equal(computeRiskScore([{ code: 'zero_address', severity: 'DENY' }]), 40);
  assert.equal(computeRiskScore([{ code: 'intent_mismatch', severity: 'WARN' }]), 35);
  assert.equal(computeRiskScore([{ code: 'injection_pattern', severity: 'DENY' }]), 90);
  assert.equal(computeRiskScore([{ code: 'unlimited_approval', severity: 'WARN' }, { code: 'approval_to_eoa', severity: 'DENY' }]), 55);
  assert.equal(computeRiskScore([{ code: 'x', severity: 'ALLOW' }]), 0);
});

test('8b. risk_score and session_risk_score are populated end-to-end', async () => {
  const r = await analyze({ to: TOKEN, data: APPROVE_MAX, context: { agent_goal: 'transfer' } }, deps());
  // unlimited_approval (WARN 15) + intent_mismatch (WARN 15 + 20)
  assert.equal(r.details.risk_score, 50);
  assert.equal(r.details.session_risk_score, 35);
});

// 9. session TTL
test('9. session TTL: domains older than SESSION_TTL_MS do not count', async () => {
  const store = ctx.createSessionStore({ ttlMs: 1000 });
  const session_id = 'sess-ttl';
  const t0 = 1_000_000;
  const old = await analyze({ to: ROUTER, data: SWAP, context: { agent_goal: 'swap', session_id, recent_sources: ['https://a.example.org', 'https://b.example.org', 'https://c.example.org'] } }, deps({ sessionStore: store, now: t0 }));
  assert.equal(old.reasons.includes('memory_poisoning_signal'), false);
  const later = await analyze({ to: ROUTER, data: SWAP, context: { agent_goal: 'swap', session_id, recent_sources: ['https://d.example.org', 'https://e.example.org'] } }, deps({ sessionStore: store, now: t0 + 5000 }));
  assert.equal(later.reasons.includes('memory_poisoning_signal'), false, 'expired domains must be forgotten');
  assert.equal(later.details.context_sources.session_untrusted_domains.length, 2);
  const within = await analyze({ to: ROUTER, data: SWAP, context: { agent_goal: 'swap', session_id, recent_sources: ['https://f.example.org', 'https://g.example.org'] } }, deps({ sessionStore: store, now: t0 + 5500 }));
  assert.ok(within.reasons.includes('memory_poisoning_signal'), 'domains within TTL accumulate');
});

// 10. trusted domain
test('10. trusted domains (defaults, env override, RPC hosts, api: and user input) do not trigger', async () => {
  const r = await analyze({ to: TOKEN, data: APPROVE_MAX, context: { agent_goal: 'approve', recent_sources: ['https://www.coingecko.com/en/coins/usdc', 'https://api.etherscan.io/api?module=account', 'https://ethereum-rpc.publicnode.com', 'api:coingecko', 'user input'] } }, deps());
  assert.deepEqual(r.reasons, ['unlimited_approval']);
  assert.equal(r.details.context_sources.trusted.length, 4);
  assert.equal(r.details.context_sources.untrusted.length, 0);

  const custom = await analyze({ to: TOKEN, data: APPROVE_SMALL, context: { agent_goal: 'approve', recent_sources: ['https://docs.mycompany.internal-tools.com/x'] } }, deps({ env: { TRUSTED_DOMAINS: 'internal-tools.com' } }));
  assert.equal(custom.verdict, 'ALLOW');
  const list = ctx.getTrustedDomains({ TRUSTED_DOMAINS: 'internal-tools.com' });
  assert.equal(list.source, 'env');
  assert.deepEqual(list.configured, ['internal-tools.com']);
  assert.ok(list.domains.includes('ethereum-rpc.publicnode.com'));
});

// 11. backward compatibility of legacy requests and validation of bad context
test('11. legacy requests never fail; malformed context is a ValidationError, not a crash', async () => {
  const legacy = [
    { to: TOKEN, data: APPROVE_SMALL },
    { to: TOKEN },
    { to: EOA_ACTIVE, data: '0x', value: '1' },
    { to: ROUTER, data: SWAP, chainId: '1' },
  ];
  for (const req of legacy) {
    const r = await analyze(req, deps());
    assert.ok(['ALLOW', 'WARN', 'DENY'].includes(r.verdict));
    assert.equal(r.details.context_analyzed, false);
    assert.ok('risk_score' in r.details);
  }
  await assert.rejects(analyze({ to: TOKEN, data: APPROVE_SMALL, context: 'nope' }, deps()), ValidationError);
  await assert.rejects(analyze({ to: TOKEN, data: APPROVE_SMALL, context: { recent_sources: 'x' } }, deps()), ValidationError);
  await assert.rejects(analyze({ to: TOKEN, data: APPROVE_SMALL, context: { intent_match: 'yes' } }, deps()), ValidationError);
  const empty = await analyze({ to: TOKEN, data: APPROVE_SMALL, context: {} }, deps());
  assert.equal(empty.verdict, 'ALLOW');
  assert.equal(empty.details.context_analyzed, true);
});

// 12. cap at 100
test('12. risk_score is capped at 100', async () => {
  const many = Array.from({ length: 10 }, () => ({ code: 'injection_pattern', severity: 'DENY' }));
  assert.equal(computeRiskScore(many), 100);
  const r = await analyze({
    to: TOKEN,
    data: erc721.encodeFunctionData('setApprovalForAll', [EOA_ACTIVE, true]),
    context: { agent_goal: 'read', recent_sources: ['https://okx-airdrop.click/claim', 'https://a.example.org'], recent_tool_calls: ['web_fetch'] },
  }, deps());
  assert.equal(r.verdict, 'DENY');
  assert.equal(r.details.risk_score, 100);
});

// 13. fail-safe wrapper
test('13. context_analysis_failed: a throwing session store degrades to WARN, never ALLOW', async () => {
  const brokenStore = { ttlMs: 1, record() { throw new Error('boom'); }, peek() { return []; } };
  const r = await analyze({ to: TOKEN, data: APPROVE_SMALL, context: { agent_goal: 'approve', session_id: 's1' } }, deps({ sessionStore: brokenStore }));
  assert.equal(r.verdict, 'WARN');
  assert.deepEqual(r.reasons, ['context_analysis_failed']);
});

// 14. intent_match=false from caller
test('14. caller intent_match=false is honoured as intent_mismatch', async () => {
  const r = await analyze({ to: TOKEN, data: APPROVE_SMALL, context: { agent_goal: 'approve', intent_match: false } }, deps());
  assert.equal(r.verdict, 'WARN');
  assert.deepEqual(r.reasons, ['intent_mismatch']);
  assert.equal(r.details.intent_analysis.caller_intent_match, false);
});

// 15. rule catalogue integrity
test('15. RULE_CATALOG covers every code and RULES stays a code list', () => {
  const codes = RULE_CATALOG.map((r) => r.code);
  for (const c of ['unlimited_approval', 'set_approval_for_all', 'approval_to_eoa', 'fresh_recipient', 'zero_address', 'unknown_selector', 'intent_mismatch', 'untrusted_source_before_tx', 'injection_pattern', 'rapid_context_shift', 'memory_poisoning_signal', 'goal_escalation', 'context_analysis_failed']) {
    assert.ok(codes.includes(c), c);
  }
  assert.deepEqual(RULES, codes);
  for (const r of RULE_CATALOG) assert.ok(r.description.length > 20, r.code);
});
