'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { Interface, AbiCoder, MaxUint256, parseUnits, Wallet } = require('ethers');
const { analyze } = require('../src/analyzer');
const { analyzeSignature } = require('../src/signature');
const registry = require('../src/registry');
const nested = require('../src/nested');
const intel = require('../src/intel');
const { RpcError } = require('../src/rpc');
const { createMemoryStore } = require('../src/store');

const abi = AbiCoder.defaultAbiCoder();
const erc20 = new Interface([
  'function approve(address spender, uint256 amount)',
  'function transfer(address to, uint256 amount)',
  'function symbol() view returns (string)',
  'function decimals() view returns (uint8)',
  'function name() view returns (string)',
  'function balanceOf(address) view returns (uint256)',
  'function allowance(address,address) view returns (uint256)',
]);
const router = new Interface([
  'function multicall(bytes[] data)',
  'function execute(bytes commands, bytes[] inputs, uint256 deadline)',
  'function sweepToken(address token, uint256 amountMinimum, address recipient)',
  'function exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96) params)',
]);

const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const LINK = '0x514910771AF9Ca656af840dff83E8264EcF986CA'; // not in the static registry
const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3';
const UNIVERSAL = '0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD';
const SWAPROUTER02 = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45';
const V2ROUTER = '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D';
const USER = '0x1111111111111111111111111111111111111111';
const ATTACKER = '0x9999999999999999999999999999999999999999';
const UNKNOWN_CONTRACT = '0x4444444444444444444444444444444444444444';
const TINY_CONTRACT = '0x5555555555555555555555555555555555555555';
const PROXY_CONTRACT = '0x6666666666666666666666666666666666666666';
const FAKE_PERMIT2 = '0x0000dEaDbEEF00000000000000000000000078bA3'.slice(0, 42);

/**
 * Fake reader that supports addressState, call, getStorage and estimateGas so
 * the enrichment path runs without network access.
 */
function fakeChain(opts) {
  opts = opts || {};
  const CONTRACT = { isContract: true, txCount: 1, balance: '0', codeSize: 4000, code: '0x' + '60'.repeat(4000) };
  const states = new Map([
    [USDC.toLowerCase(), CONTRACT],
    [LINK.toLowerCase(), CONTRACT],
    [PERMIT2.toLowerCase(), CONTRACT],
    [UNIVERSAL.toLowerCase(), CONTRACT],
    [SWAPROUTER02.toLowerCase(), CONTRACT],
    [V2ROUTER.toLowerCase(), CONTRACT],
    [UNKNOWN_CONTRACT.toLowerCase(), CONTRACT],
    [TINY_CONTRACT.toLowerCase(), { isContract: true, txCount: 1, balance: '0', codeSize: 20, code: '0x' + '60'.repeat(20) }],
    [PROXY_CONTRACT.toLowerCase(), CONTRACT],
    ['0x0000000000000068f116a894984e2db1123eb395', CONTRACT], // Seaport 1.6
    [USER.toLowerCase(), { isContract: false, txCount: 10, balance: '1000000000000000000', codeSize: 0, code: '0x' }],
    [ATTACKER.toLowerCase(), { isContract: false, txCount: 0, balance: '0', codeSize: 0, code: '0x' }],
  ]);
  const balances = opts.balances || {};
  return {
    endpoint: 'fake://chain',
    calls: [],
    async addressState(address) {
      const s = states.get(address.toLowerCase());
      if (!s) return { address, isContract: false, txCount: 0, balance: '0', codeSize: 0, code: '0x' };
      return Object.assign({ address }, s);
    },
    async call(tx) {
      this.calls.push(tx);
      const sel = tx.data.slice(0, 10);
      const to = tx.to.toLowerCase();
      if (opts.revert && tx.from) {
        const err = new Error('execution reverted: ' + opts.revert);
        err.code = 'CALL_EXCEPTION';
        err.data = '0x08c379a0' + abi.encode(['string'], [opts.revert]).slice(2);
        throw err;
      }
      if (tx.from) return '0x' + '00'.repeat(31) + '01'; // simulated state-changing call succeeds
      if (to === LINK.toLowerCase()) {
        if (sel === '0x95d89b41') return abi.encode(['string'], ['LINK']);
        if (sel === '0x313ce567') return abi.encode(['uint8'], [18]);
        if (sel === '0x06fdde03') return abi.encode(['string'], ['ChainLink Token']);
      }
      if (sel === '0x70a08231') return abi.encode(['uint256'], [balances[to] || 0n]);
      if (sel === '0xdd62ed3e') return abi.encode(['uint256'], [0n]);
      const err = new Error('execution reverted');
      err.code = 'CALL_EXCEPTION';
      err.data = '0x';
      throw err;
    },
    async getStorage(address, slot) {
      if (address.toLowerCase() === PROXY_CONTRACT.toLowerCase() && slot === intel.EIP1967_IMPL_SLOT) return '0x000000000000000000000000' + UNKNOWN_CONTRACT.slice(2).toLowerCase();
      return '0x' + '00'.repeat(32);
    },
    async estimateGas() {
      return 52000n;
    },
  };
}

test('registry: canonical contracts and tokens resolve, look-alikes are detected', () => {
  assert.equal(registry.lookupContract(1, PERMIT2).name, 'Permit2');
  assert.equal(registry.lookupContract(8453, PERMIT2).name, 'Permit2');
  assert.equal(registry.lookupToken(1, USDC).symbol, 'USDC');
  assert.equal(registry.lookupToken(1, LINK), null);
  const fake = '0x0000' + 'ab'.repeat(16) + '8ba3';
  assert.ok(registry.isLookalike(fake, PERMIT2));
  assert.equal(registry.findRegistryLookalike(1, fake).name, 'Permit2');
  assert.equal(registry.findRegistryLookalike(1, PERMIT2), null, 'the real address is not a look-alike of itself');
});

test('token meta: registry hit needs no RPC, unknown token is read on-chain and formatted', async () => {
  const chain = fakeChain();
  const usdc = await intel.getTokenMeta(chain, 1, USDC);
  assert.equal(usdc.source, 'static-registry');
  const link = await intel.getTokenMeta(chain, 1, LINK);
  assert.equal(link.symbol, 'LINK');
  assert.equal(link.decimals, 18);
  assert.equal(link.source, 'onchain');
  assert.equal(intel.formatAmount(parseUnits('1234.5', 18), link), '1234.5 LINK');
  assert.equal(intel.formatAmount(2500000n, usdc), '2.5 USDC');
  assert.equal(intel.formatAmount(5n, null), '5 raw units');
});

test('summary + safe_alternative: unlimited USDC approve to Uniswap router is explained and bounded', async () => {
  const data = erc20.encodeFunctionData('approve', [V2ROUTER, MaxUint256]);
  const r = await analyze({ to: USDC, data, context: { expected_amount: '150.5' } }, { store: createMemoryStore(), reader: fakeChain() });
  assert.equal(r.verdict, 'WARN');
  assert.match(r.summary, /Approve UNLIMITED USDC/);
  assert.match(r.summary, /Uniswap V2 Router02 \(dex-router/);
  assert.equal(r.details.safe_alternative.available, true);
  assert.equal(r.details.safe_alternative.amountRaw, '150500000');
  const decodedAlt = erc20.decodeFunctionData('approve', r.details.safe_alternative.data);
  assert.equal(decodedAlt[0], V2ROUTER);
  assert.equal(decodedAlt[1], 150500000n);
  assert.ok(r.details.recommendations.some((x) => x.code === 'unlimited_approval'));
  assert.equal(r.details.counterparties[V2ROUTER].known.name, 'Uniswap V2 Router02');
});

test('unknown_spender: unlimited approve to an unrecognised contract, proxy and tiny contracts are called out', async () => {
  const chain = fakeChain();
  const a = await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [UNKNOWN_CONTRACT, MaxUint256]) }, { reader: chain, store: createMemoryStore() });
  assert.deepEqual(new Set(a.reasons), new Set(['unlimited_approval', 'unknown_spender']));
  assert.equal(a.details.risk_score, 30);

  const p = await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [PROXY_CONTRACT, MaxUint256]) }, { reader: chain, store: createMemoryStore() });
  const f = p.details.findings.find((x) => x.code === 'unknown_spender');
  assert.match(f.message, /upgradeable proxy/);
  assert.equal(p.details.counterparties[PROXY_CONTRACT].proxy.type, 'eip1967-upgradeable-proxy');
  assert.equal(p.details.counterparties[PROXY_CONTRACT].proxy.implementation, UNKNOWN_CONTRACT);

  const t = await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [TINY_CONTRACT, MaxUint256]) }, { reader: chain, store: createMemoryStore() });
  assert.match(t.details.findings.find((x) => x.code === 'unknown_spender').message, /20 bytes of code/);

  const bounded = await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [UNKNOWN_CONTRACT, 1000n]) }, { reader: chain, store: createMemoryStore() });
  assert.equal(bounded.verdict, 'ALLOW', 'bounded approval to an unknown contract is not flagged');
});

test('address_poisoning: recipient imitating a known address is DENIED; the real address passes', async () => {
  const real = '0xabcd000000000000000000000000000000001234';
  const poison = '0xabcd' + 'ff'.repeat(16) + '1234';
  const chain = fakeChain();
  const bad = await analyze({ to: USDC, data: erc20.encodeFunctionData('transfer', [poison, 1n]), context: { known_addresses: [real] } }, { reader: chain, store: createMemoryStore() });
  assert.equal(bad.verdict, 'DENY');
  assert.ok(bad.reasons.includes('address_poisoning'));
  const good = await analyze({ to: USDC, data: erc20.encodeFunctionData('transfer', [real, 1n]), context: { known_addresses: [real] } }, { reader: chain, store: createMemoryStore() });
  assert.equal(good.reasons.includes('address_poisoning'), false);
  const nativePoison = await analyze({ to: poison, data: '0x', value: '1', context: { known_addresses: [real] } }, { reader: chain, store: createMemoryStore() });
  assert.ok(nativePoison.reasons.includes('address_poisoning'));
});

test('contract_lookalike: approving a Permit2 look-alike is DENIED without any context', async () => {
  const fake = '0x0000' + 'ab'.repeat(16) + '8ba3';
  const r = await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [fake, 1000n]) }, { store: createMemoryStore(), reader: fakeChain() });
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('contract_lookalike'));
  assert.equal(r.details.findings.find((f) => f.code === 'contract_lookalike').imitatesName, 'Permit2');
});

test('nested multicall: an approve hidden inside multicall is analysed like a top-level approve', async () => {
  const inner = erc20.encodeFunctionData('approve', [ATTACKER, MaxUint256]);
  const data = router.encodeFunctionData('multicall', [[inner]]);
  const r = await analyze({ to: USDC, data }, { store: createMemoryStore(), reader: fakeChain() });
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('approval_to_eoa'));
  assert.ok(r.reasons.includes('unlimited_approval'));
  assert.equal(r.details.nested_calls.inner.length, 1);
  assert.equal(r.details.nested_calls.inner[0].kind, 'approve');
});

test('router helpers: sweepToken / exactInputSingle to a third party -> WARN, to self -> ALLOW', async () => {
  const chain = fakeChain();
  const sweepOut = router.encodeFunctionData('sweepToken', [USDC, 0n, ATTACKER]);
  const bad = await analyze({ to: SWAPROUTER02, data: router.encodeFunctionData('multicall', [[sweepOut]]), from: USER }, { reader: chain, store: createMemoryStore() });
  assert.ok(bad.reasons.includes('router_output_to_third_party'));
  assert.ok(bad.reasons.includes('fresh_recipient'), 'the third-party recipient is also checked on-chain');

  const swapSelf = router.encodeFunctionData('exactInputSingle', [{ tokenIn: USDC, tokenOut: LINK, fee: 3000, recipient: USER, amountIn: 1n, amountOutMinimum: 0n, sqrtPriceLimitX96: 0n }]);
  const good = await analyze({ to: SWAPROUTER02, data: router.encodeFunctionData('multicall', [[swapSelf]]), from: USER }, { reader: chain, store: createMemoryStore() });
  assert.equal(good.reasons.includes('router_output_to_third_party'), false);
});

test('Universal Router: PERMIT2_PERMIT to a foreign spender + TRANSFER to attacker are DENIED; honest plan is ALLOWED', async () => {
  const UINT160_MAX = 2n ** 160n - 1n;
  const permitSingle = ['tuple(tuple(address,uint160,uint48,uint48),address,uint256)', 'bytes'];
  const evilPermit = abi.encode(permitSingle, [[[USDC, UINT160_MAX, 281474976710655n, 0n], ATTACKER, 99999999999n], '0x']);
  const transferOut = abi.encode(['address', 'address', 'uint256'], [USDC, ATTACKER, 1000000n]);
  const evil = router.encodeFunctionData('execute', ['0x0a05', [evilPermit, transferOut], 99999999999n]);
  const r = await analyze({ to: UNIVERSAL, data: evil, from: USER }, { store: createMemoryStore(), reader: fakeChain() });
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('permit_spender_mismatch'));
  assert.ok(r.reasons.includes('unlimited_approval'));
  assert.ok(r.reasons.includes('router_output_to_third_party'));
  assert.deepEqual(r.details.nested_calls.routerPlan.map((s) => s.command), ['PERMIT2_PERMIT', 'TRANSFER']);
  assert.match(r.summary, /Router plan: PERMIT2_PERMIT → TRANSFER/);

  const honestPermit = abi.encode(permitSingle, [[[USDC, 1000000n, 1800000000n, 0n], UNIVERSAL, 1800000000n], '0x']);
  const v3swap = abi.encode(['address', 'uint256', 'uint256', 'bytes', 'bool'], [nested.MSG_SENDER, 1000000n, 1n, '0x' + USDC.slice(2) + '000bb8' + LINK.slice(2), true]);
  const honest = router.encodeFunctionData('execute', ['0x0a00', [honestPermit, v3swap], 1800000000n]);
  const ok = await analyze({ to: UNIVERSAL, data: honest, from: USER }, { store: createMemoryStore(), reader: fakeChain() });
  assert.equal(ok.verdict, 'ALLOW');
  assert.equal(ok.details.nested_calls.permits[0].spender, UNIVERSAL);
});

test('simulation: revert reason is decoded and surfaced; insufficient balance is detected', async () => {
  const data = erc20.encodeFunctionData('transfer', [USER, parseUnits('100', 6)]);
  const rev = await analyze({ to: USDC, data, from: USER }, { store: createMemoryStore(), reader: fakeChain({ revert: 'ERC20: transfer amount exceeds balance' }) });
  assert.ok(rev.reasons.includes('simulation_reverted'));
  assert.equal(rev.details.simulation.revert.reason, 'ERC20: transfer amount exceeds balance');
  assert.equal(rev.details.simulation.revert.selector, '0x08c379a0');

  const low = await analyze({ to: USDC, data, from: USER }, { store: createMemoryStore(), reader: fakeChain({ balances: { [USDC.toLowerCase()]: 5000000n } }) });
  assert.ok(low.reasons.includes('insufficient_balance'));
  assert.match(low.details.findings.find((f) => f.code === 'insufficient_balance').message, /5 USDC is below the transfer amount 100 USDC/);
  assert.equal(low.details.simulation.gasEstimate, '52000');

  const noFrom = await analyze({ to: USDC, data }, { store: createMemoryStore(), reader: fakeChain({ revert: 'x' }) });
  assert.equal(noFrom.details.simulation.ran, false);
  assert.equal(noFrom.reasons.includes('simulation_reverted'), false);
});

test('simulation_unavailable: RPC failure during a requested simulation degrades to WARN', async () => {
  const chain = fakeChain();
  chain.call = async (tx) => {
    if (tx.from) throw new RpcError('gateway timeout');
    const err = new Error('execution reverted');
    err.code = 'CALL_EXCEPTION';
    err.data = '0x';
    throw err;
  };
  const r = await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, 1n]), from: USER }, { reader: chain, store: createMemoryStore() });
  assert.equal(r.verdict, 'WARN');
  assert.ok(r.reasons.includes('simulation_unavailable'));
});

test('signature: ERC-2612 permit unlimited + far deadline to a wallet -> DENY', async () => {
  const typedData = {
    types: { EIP712Domain: [], Permit: [{ name: 'owner', type: 'address' }, { name: 'spender', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' }] },
    primaryType: 'Permit',
    domain: { name: 'USD Coin', version: '2', chainId: 1, verifyingContract: USDC },
    message: { owner: USER, spender: ATTACKER, value: MaxUint256.toString(), nonce: 0, deadline: MaxUint256.toString() },
  };
  const r = await analyzeSignature({ type: 'eip712', from: USER, typedData }, { store: createMemoryStore(), reader: fakeChain(), now: 1_800_000_000 });
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('approval_to_eoa'));
  assert.ok(r.reasons.includes('unlimited_approval'));
  assert.ok(r.reasons.includes('far_deadline'));
  assert.equal(r.details.classification, 'erc2612_permit');
  assert.equal(r.details.token.symbol, 'USDC');
  assert.match(r.summary, /ERC-2612 permit/);
});

test('signature: bounded Permit2 to Universal Router with short deadline -> ALLOW; spoofed Permit2 domain -> DENY', async () => {
  const now = 1_800_000_000;
  const base = {
    types: { EIP712Domain: [], PermitSingle: [{ name: 'details', type: 'PermitDetails' }, { name: 'spender', type: 'address' }, { name: 'sigDeadline', type: 'uint256' }], PermitDetails: [{ name: 'token', type: 'address' }, { name: 'amount', type: 'uint160' }, { name: 'expiration', type: 'uint48' }, { name: 'nonce', type: 'uint48' }] },
    primaryType: 'PermitSingle',
    domain: { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 },
    message: { details: { token: USDC, amount: '1000000', expiration: String(now + 3600), nonce: 0 }, spender: UNIVERSAL, sigDeadline: String(now + 600) },
  };
  const ok = await analyzeSignature({ type: 'eip712', from: USER, typedData: base }, { store: createMemoryStore(), reader: fakeChain(), now });
  assert.equal(ok.verdict, 'ALLOW', JSON.stringify(ok.reasons));
  assert.equal(ok.details.spender.known.name, 'Uniswap Universal Router');
  assert.equal(ok.details.amount, '1 USDC');

  const spoofed = JSON.parse(JSON.stringify(base));
  spoofed.domain.verifyingContract = UNKNOWN_CONTRACT;
  const bad = await analyzeSignature({ type: 'eip712', from: USER, typedData: spoofed }, { store: createMemoryStore(), reader: fakeChain(), now });
  assert.equal(bad.verdict, 'DENY');
  assert.ok(bad.reasons.includes('permit2_domain_mismatch'));

  const unlimited = JSON.parse(JSON.stringify(base));
  unlimited.message.details.amount = (2n ** 160n - 1n).toString();
  unlimited.message.details.expiration = (2n ** 48n - 1n).toString();
  unlimited.message.spender = UNKNOWN_CONTRACT;
  const u = await analyzeSignature({ type: 'eip712', from: USER, typedData: unlimited }, { store: createMemoryStore(), reader: fakeChain(), now });
  assert.deepEqual(new Set(u.reasons), new Set(['unlimited_approval', 'far_deadline', 'unknown_spender']));
});

test('signature: Permit2 PermitTransferFrom is flagged as an immediate transfer authorisation', async () => {
  const now = 1_800_000_000;
  const typedData = {
    types: { EIP712Domain: [], PermitTransferFrom: [{ name: 'permitted', type: 'TokenPermissions' }, { name: 'spender', type: 'address' }, { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' }], TokenPermissions: [{ name: 'token', type: 'address' }, { name: 'amount', type: 'uint256' }] },
    primaryType: 'PermitTransferFrom',
    domain: { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 },
    message: { permitted: { token: USDC, amount: '5000000000' }, spender: UNKNOWN_CONTRACT, nonce: 1, deadline: String(now + 300) },
  };
  const r = await analyzeSignature({ type: 'eip712', from: USER, typedData }, { store: createMemoryStore(), reader: fakeChain(), now });
  assert.equal(r.verdict, 'WARN');
  assert.ok(r.reasons.includes('signature_transfer_authorization'));
  assert.equal(r.details.amount, '5000 USDC');
});

test('signature: Seaport order giving NFTs away for nothing -> DENY; fair order -> ALLOW', async () => {
  const mk = (consideration) => ({
    types: { EIP712Domain: [], OrderComponents: [{ name: 'offerer', type: 'address' }, { name: 'offer', type: 'OfferItem[]' }, { name: 'consideration', type: 'ConsiderationItem[]' }, { name: 'endTime', type: 'uint256' }], OfferItem: [], ConsiderationItem: [] },
    primaryType: 'OrderComponents',
    domain: { name: 'Seaport', version: '1.6', chainId: 1, verifyingContract: '0x0000000000000068F116a894984e2DB1123eB395' },
    message: { offerer: USER, offer: [{ itemType: 2, token: '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D', identifierOrCriteria: '1', startAmount: '1', endAmount: '1' }], consideration, endTime: '1800003600' },
  });
  const drain = await analyzeSignature({ type: 'eip712', from: USER, typedData: mk([]) }, { store: createMemoryStore(), reader: fakeChain(), now: 1_800_000_000 });
  assert.equal(drain.verdict, 'DENY');
  assert.ok(drain.reasons.includes('seaport_zero_consideration'));
  const zeroToOfferer = await analyzeSignature({ type: 'eip712', from: USER, typedData: mk([{ itemType: 0, token: '0x0000000000000000000000000000000000000000', identifierOrCriteria: '0', startAmount: '0', endAmount: '0', recipient: USER }]) }, { store: createMemoryStore(), reader: fakeChain(), now: 1_800_000_000 });
  assert.ok(zeroToOfferer.reasons.includes('seaport_zero_consideration'));
  const fair = await analyzeSignature({ type: 'eip712', from: USER, typedData: mk([{ itemType: 0, token: '0x0000000000000000000000000000000000000000', identifierOrCriteria: '0', startAmount: '1000000000000000000', endAmount: '1000000000000000000', recipient: USER }]) }, { store: createMemoryStore(), reader: fakeChain(), now: 1_800_000_000 });
  assert.equal(fair.verdict, 'ALLOW');
});

test('signature: blind hash, eth_sign, SIWE phishing and plain text', async () => {
  const hash = await analyzeSignature({ type: 'personal_sign', message: '0x' + 'ab'.repeat(32) });
  assert.equal(hash.verdict, 'DENY');
  assert.ok(hash.reasons.includes('blind_hash_signing'));

  const ethSign = await analyzeSignature({ type: 'eth_sign', message: '0x' + 'ab'.repeat(32) });
  assert.ok(ethSign.reasons.includes('eth_sign_deprecated'));

  const siwe = 'okx-wallet-verify.xyz wants you to sign in with your Ethereum account:\n' + USER + '\n\nSign in\n\nURI: https://okx-wallet-verify.xyz\nVersion: 1\nChain ID: 1\nNonce: abc\nIssued At: 2026-09-13T00:00:00Z';
  const phish = await analyzeSignature({ type: 'personal_sign', from: USER, message: siwe });
  assert.equal(phish.verdict, 'DENY');
  assert.ok(phish.reasons.includes('siwe_phishing_domain'));

  const legit = 'app.uniswap.org wants you to sign in with your Ethereum account:\n' + USER + '\n\nURI: https://app.uniswap.org\nVersion: 1\nChain ID: 1\nNonce: abc\nIssued At: 2026-09-13T00:00:00Z';
  const ok = await analyzeSignature({ type: 'personal_sign', from: USER, message: legit });
  assert.equal(ok.verdict, 'ALLOW');
  assert.equal(ok.details.classification, 'siwe');

  const text = await analyzeSignature({ type: 'personal_sign', message: 'I agree to the terms of service' });
  assert.equal(text.verdict, 'ALLOW');
  const hexText = await analyzeSignature({ type: 'personal_sign', message: '0x' + Buffer.from('hello world', 'utf8').toString('hex') });
  assert.equal(hexText.details.classification, 'text');
});

test('signature: validation errors and context integration', async () => {
  await assert.rejects(analyzeSignature({ type: 'eip712' }), /typedData/);
  await assert.rejects(analyzeSignature({ type: 'bogus', message: 'x' }), /type/);
  const typedData = {
    types: { EIP712Domain: [], Permit: [{ name: 'owner', type: 'address' }, { name: 'spender', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' }] },
    primaryType: 'Permit',
    domain: { name: 'USD Coin', version: '2', chainId: 1, verifyingContract: USDC },
    message: { owner: USER, spender: V2ROUTER, value: '1000000', nonce: 0, deadline: '1800000300' },
  };
  const r = await analyzeSignature({ type: 'eip712', from: USER, typedData, context: { agent_goal: 'read' } }, { store: createMemoryStore(), reader: fakeChain(), now: 1_800_000_000 });
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('goal_escalation'));
  assert.equal(r.details.context_analyzed, true);
});

test('backward compatibility: legacy shape unchanged, new fields present, fake readers without eth_call still work', async () => {
  const legacyReader = { endpoint: 'x', async addressState(address) { return { address, isContract: true, txCount: 1, balance: '0' }; } };
  const r = await analyze({ to: USDC, data: erc20.encodeFunctionData('approve', [V2ROUTER, 1n]) }, { reader: legacyReader, store: createMemoryStore() });
  assert.equal(r.verdict, 'ALLOW');
  assert.equal(r.details.enrichment.ran, false);
  assert.equal(r.details.enrichment.skipped, 'reader does not support eth_call');
  assert.equal(typeof r.summary, 'string');
  assert.equal(r.details.token.symbol, 'USDC', 'registry token meta works without RPC');
  for (const k of ['verdict', 'reasons', 'details']) assert.ok(k in r);
  for (const k of ['chainId', 'to', 'selector', 'function', 'callType', 'decoded', 'findings', 'addressChecks', 'rpc', 'risk_score', 'context_analyzed']) assert.ok(k in r.details, k);
});
