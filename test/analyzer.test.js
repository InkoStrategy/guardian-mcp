'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { Interface, MaxUint256 } = require('ethers');
const { analyze, ValidationError } = require('../src/analyzer');
const { RpcError } = require('../src/rpc');

const erc20 = new Interface([
  'function approve(address spender, uint256 amount)',
  'function increaseAllowance(address spender, uint256 addedValue)',
  'function transfer(address to, uint256 amount)',
  'function transferFrom(address from, address to, uint256 amount)',
]);
const erc721 = new Interface(['function setApprovalForAll(address operator, bool approved)']);

const TOKEN = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'; // USDC (mainnet)
const ROUTER = '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D'; // Uniswap V2 router (contract)
const EOA_ACTIVE = '0x1111111111111111111111111111111111111111';
const EOA_FRESH = '0x2222222222222222222222222222222222222222';
const ZERO = '0x0000000000000000000000000000000000000000';

/** Deterministic fake chain reader keyed by lowercase address. */
function fakeReader(states, opts) {
  const map = new Map(Object.entries(states).map(([k, v]) => [k.toLowerCase(), v]));
  return {
    endpoint: 'fake://chain',
    async addressState(address) {
      if (opts && opts.fail) throw new RpcError('simulated outage');
      const s = map.get(address.toLowerCase());
      if (!s) throw new Error('fake reader has no state for ' + address);
      return { address, isContract: s.isContract, txCount: s.txCount, balance: s.balance };
    },
  };
}

const CONTRACT = { isContract: true, txCount: 1, balance: '0' };
const ACTIVE = { isContract: false, txCount: 42, balance: '1000000000000000000' };
const FRESH = { isContract: false, txCount: 0, balance: '0' };

const reader = fakeReader({
  [TOKEN]: CONTRACT,
  [ROUTER]: CONTRACT,
  [EOA_ACTIVE]: ACTIVE,
  [EOA_FRESH]: FRESH,
});

test('input validation rejects a bad address and odd hex', async () => {
  await assert.rejects(analyze({ to: '0x123', data: '0x' }), ValidationError);
  await assert.rejects(analyze({ to: TOKEN, data: '0xabc' }), ValidationError);
  await assert.rejects(analyze({ to: TOKEN, data: '0x095ea7b3', chainId: 999999 }), ValidationError);
});

test('unlimited_approval: approve(MAX_UINT256) to a contract -> WARN', async () => {
  const data = erc20.encodeFunctionData('approve', [ROUTER, MaxUint256]);
  const r = await analyze({ to: TOKEN, data }, { reader });
  assert.equal(r.verdict, 'WARN');
  assert.deepEqual(r.reasons, ['unlimited_approval']);
  assert.equal(r.details.decoded.spender, ROUTER);
});

test('bounded approval to a contract -> ALLOW', async () => {
  const data = erc20.encodeFunctionData('approve', [ROUTER, 1000000n]);
  const r = await analyze({ to: TOKEN, data }, { reader });
  assert.equal(r.verdict, 'ALLOW');
  assert.deepEqual(r.reasons, []);
});

test('approval_to_eoa: approve to a plain wallet -> DENY (even when bounded)', async () => {
  const data = erc20.encodeFunctionData('increaseAllowance', [EOA_ACTIVE, 5n]);
  const r = await analyze({ to: TOKEN, data }, { reader });
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('approval_to_eoa'));
});

test('unlimited approval to an EOA -> DENY with both reasons', async () => {
  const data = erc20.encodeFunctionData('approve', [EOA_FRESH, MaxUint256]);
  const r = await analyze({ to: TOKEN, data }, { reader });
  assert.equal(r.verdict, 'DENY');
  assert.deepEqual(new Set(r.reasons), new Set(['unlimited_approval', 'approval_to_eoa']));
});

test('set_approval_for_all(true) -> DENY; revocation (false) -> ALLOW', async () => {
  const grant = erc721.encodeFunctionData('setApprovalForAll', [ROUTER, true]);
  const revoke = erc721.encodeFunctionData('setApprovalForAll', [ROUTER, false]);
  const g = await analyze({ to: TOKEN, data: grant }, { reader });
  const v = await analyze({ to: TOKEN, data: revoke }, { reader });
  assert.equal(g.verdict, 'DENY');
  assert.ok(g.reasons.includes('set_approval_for_all'));
  assert.equal(v.verdict, 'ALLOW');
});

test('fresh_recipient: ERC-20 transfer to address with no history -> WARN', async () => {
  const data = erc20.encodeFunctionData('transfer', [EOA_FRESH, 100n]);
  const r = await analyze({ to: TOKEN, data }, { reader });
  assert.equal(r.verdict, 'WARN');
  assert.deepEqual(r.reasons, ['fresh_recipient']);
});

test('transfer to an active wallet -> ALLOW', async () => {
  const data = erc20.encodeFunctionData('transferFrom', [EOA_ACTIVE, EOA_ACTIVE, 100n]);
  const r = await analyze({ to: TOKEN, data }, { reader });
  assert.equal(r.verdict, 'ALLOW');
});

test('fresh_recipient: native transfer (empty data, value > 0) -> WARN', async () => {
  const r = await analyze({ to: EOA_FRESH, data: '0x', value: '1000000000000000' }, { reader });
  assert.equal(r.verdict, 'WARN');
  assert.deepEqual(r.reasons, ['fresh_recipient']);
  assert.equal(r.details.callType, 'native');
});

test('zero_address: transfer to 0x0 -> DENY without touching the chain', async () => {
  const data = erc20.encodeFunctionData('transfer', [ZERO, 1n]);
  const r = await analyze({ to: TOKEN, data }, { reader });
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('zero_address'));
  const native = await analyze({ to: ZERO, data: '0x', value: '1' }, { reader: fakeReader({}, { fail: true }) });
  assert.equal(native.verdict, 'DENY');
});

test('unknown_selector -> WARN', async () => {
  const r = await analyze({ to: ROUTER, data: '0xdeadbeef' + '00'.repeat(32) }, { reader });
  assert.equal(r.verdict, 'WARN');
  assert.ok(r.reasons.includes('unknown_selector'));
});

test('known DEX selector to a contract -> ALLOW', async () => {
  const r = await analyze({ to: ROUTER, data: '0x7ff36ab5' + '00'.repeat(32) }, { reader });
  assert.equal(r.verdict, 'ALLOW');
  assert.equal(r.details.function, 'swapExactETHForTokens(uint256,address[],address,uint256)');
});

test('calldata_to_eoa: calling a function on a wallet address -> WARN', async () => {
  const data = erc20.encodeFunctionData('approve', [ROUTER, 1n]);
  const r = await analyze({ to: EOA_ACTIVE, data }, { reader });
  assert.equal(r.verdict, 'WARN');
  assert.ok(r.reasons.includes('calldata_to_eoa'));
});

test('FAIL-SAFE: RPC outage never yields ALLOW', async () => {
  const data = erc20.encodeFunctionData('approve', [ROUTER, 1n]);
  const r = await analyze({ to: TOKEN, data }, { reader: fakeReader({}, { fail: true }) });
  assert.equal(r.verdict, 'WARN');
  assert.deepEqual(r.reasons, ['rpc_unavailable']);
  assert.equal(r.details.rpc.ok, false);
});

test('FAIL-SAFE: RPC outage on a DENY case still DENIES', async () => {
  const data = erc721.encodeFunctionData('setApprovalForAll', [ROUTER, true]);
  const r = await analyze({ to: TOKEN, data }, { reader: fakeReader({}, { fail: true }) });
  assert.equal(r.verdict, 'DENY');
  assert.ok(r.reasons.includes('set_approval_for_all'));
  assert.ok(r.reasons.includes('rpc_unavailable'));
});
