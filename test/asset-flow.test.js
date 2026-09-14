'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { id, zeroPadValue, toBeHex } = require('ethers');
const { analyze } = require('../src/analyzer');
const { createMemoryStore } = require('../src/store');
const assetFlow = require('../src/asset-flow');
const seed = require('../src/seed');

const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const V2ROUTER = '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D';
const USER = '0x1111111111111111111111111111111111111111';
const CLAIM_CONTRACT = '0x4444444444444444444444444444444444444444';
const DRAINER = '0xdead00000000000000000000000000000000beef';
const POOL = '0x5555555555555555555555555555555555555555';
const TRANSFER = id('Transfer(address,address,uint256)');

function log(address, from, to, value) {
  return { address, topics: [TRANSFER, zeroPadValue(from, 32), zeroPadValue(to, 32)], data: toBeHex(value, 32) };
}

function fakeChain(logsByTo, opts) {
  opts = opts || {};
  const CONTRACT = { isContract: true, txCount: 1, balance: '0', codeSize: 4000, code: '0x' + '60'.repeat(4000) };
  const EOA = { isContract: false, txCount: 5, balance: '10000000000000000', codeSize: 0, code: '0x' };
  const map = new Map([[USDC.toLowerCase(), CONTRACT], [V2ROUTER.toLowerCase(), CONTRACT], [CLAIM_CONTRACT.toLowerCase(), CONTRACT], [POOL.toLowerCase(), CONTRACT], [USER.toLowerCase(), EOA], [DRAINER, EOA]]);
  return {
    endpoint: 'fake://chain',
    async addressState(a) { return Object.assign({ address: a }, map.get(a.toLowerCase()) || EOA); },
    async call() { const e = new Error('execution reverted'); e.code = 'CALL_EXCEPTION'; e.data = '0x'; throw e; },
    async getStorage() { return '0x' + '00'.repeat(32); },
    async send(method, params) {
      if (method !== 'eth_simulateV1') throw new Error('unexpected ' + method);
      if (opts.unsupported) { const e = new Error('the method eth_simulateV1 does not exist/is not available'); e.error = { code: -32601 }; throw e; }
      const call = params[0].blockStateCalls[0].calls[0];
      const logs = logsByTo[call.to.toLowerCase()] || [];
      return [{ number: '0x1', calls: [{ status: opts.revert ? '0x0' : '0x1', gasUsed: '0x5208', returnData: '0x', logs: opts.revert ? [] : logs, error: opts.revert ? { message: 'execution reverted' } : undefined }] }];
    },
  };
}

test('asset-flow: parses ETH sentinel, ERC-20 and ERC-721 transfers into net positions', () => {
  const logs = [
    log(assetFlow.ETH_SENTINEL, USER, CLAIM_CONTRACT, 10n ** 18n),
    log(assetFlow.ETH_SENTINEL, CLAIM_CONTRACT, DRAINER, 10n ** 18n),
    log(USDC, POOL, USER, 25000000n),
    { address: '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D', topics: [TRANSFER, zeroPadValue(USER, 32), zeroPadValue(POOL, 32), toBeHex(7n, 32)], data: '0x' },
  ];
  const transfers = assetFlow.parseLogs(logs);
  assert.equal(transfers.length, 4);
  assert.equal(transfers[0].asset, 'ETH');
  assert.equal(transfers[3].standard, 'erc721');
  const net = assetFlow.netPositions(transfers);
  assert.equal(net.get(USER.toLowerCase()).get('ETH'), -(10n ** 18n));
  assert.equal(net.get(DRAINER).get('ETH'), 10n ** 18n);
  assert.equal(net.get(CLAIM_CONTRACT.toLowerCase()).get('ETH'), 0n);
  assert.equal(net.get(USER.toLowerCase()).get(USDC), 25000000n);
});

test('funds_flow_no_return: unknown "claim" call forwards ETH to a wallet -> WARN; seeded wallet -> DENY funds_flow_to_flagged', async () => {
  const logs = { [CLAIM_CONTRACT.toLowerCase()]: [log(assetFlow.ETH_SENTINEL, USER, CLAIM_CONTRACT, 10n ** 17n), log(assetFlow.ETH_SENTINEL, CLAIM_CONTRACT, DRAINER, 10n ** 17n)] };
  const store = createMemoryStore();
  const r = await analyze({ to: CLAIM_CONTRACT, data: '0x4e71d92d', value: (10n ** 17n).toString(), from: USER }, { reader: fakeChain(logs), store, env: {} });
  assert.equal(r.verdict, 'WARN');
  assert.ok(r.reasons.includes('funds_flow_no_return'), r.reasons.join(','));
  assert.equal(r.details.asset_flow.final_recipients[0].address.toLowerCase(), DRAINER);
  assert.match(r.summary, /Simulated value flow for sender: -0\.1 ETH/);

  await seed.applySeed(store, { source: 't', sha: 's', addresses: [DRAINER], domains: [] });
  const d = await analyze({ to: CLAIM_CONTRACT, data: '0x4e71d92d', value: (10n ** 17n).toString(), from: USER }, { reader: fakeChain(logs), store, env: {} });
  assert.equal(d.verdict, 'DENY');
  assert.ok(d.reasons.includes('funds_flow_to_flagged'));
  assert.ok(d.reasons.includes('scam_database_address'));
});

test('asset-flow: a swap that returns tokens to the sender is not flagged; contracts as sinks are fine', async () => {
  const logs = { [V2ROUTER.toLowerCase()]: [log(assetFlow.ETH_SENTINEL, USER, V2ROUTER, 10n ** 16n), log(assetFlow.ETH_SENTINEL, V2ROUTER, POOL, 10n ** 16n), log(USDC, POOL, USER, 25000000n)] };
  const r = await analyze({ to: V2ROUTER, data: '0x7ff36ab5' + '00'.repeat(32), value: (10n ** 16n).toString(), from: USER }, { reader: fakeChain(logs), store: createMemoryStore(), env: {} });
  assert.equal(r.reasons.includes('funds_flow_no_return'), false);
  assert.deepEqual(r.details.asset_flow.sender_net.map((n) => n.asset), ['ETH', USDC]);
  assert.match(r.summary, /-0\.01 ETH, \+25 USDC/);
});

test('asset-flow: unsupported RPC and reverted simulation degrade gracefully', async () => {
  const u = await analyze({ to: CLAIM_CONTRACT, data: '0x4e71d92d', from: USER }, { reader: fakeChain({}, { unsupported: true }), store: createMemoryStore(), env: {} });
  assert.equal(u.details.asset_flow.supported, false);
  assert.equal(u.reasons.includes('funds_flow_no_return'), false);
  const rv = await analyze({ to: CLAIM_CONTRACT, data: '0x4e71d92d', from: USER }, { reader: fakeChain({}, { revert: true }), store: createMemoryStore(), env: {} });
  assert.equal(rv.details.asset_flow.reverted, true);
  assert.equal(rv.reasons.includes('funds_flow_no_return'), false);
});
