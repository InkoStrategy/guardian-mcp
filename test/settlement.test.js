'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { verifySettlement, TRANSFER_TOPIC } = require('../src/settlement');

const TX = '0xd0dab0bb9ae26fd68b4772d2a7f197314ec296a606530077a233c3769cf3070d';
const USDT0 = '0x779ded0c9e1022225f8e0630b35a9b54be713736';
const PAYER = '0xe1c6f89df50fb68282d52e34d6001d65005ff67b';
const PAYEE = '0xc4622689eb6c38c929fe254777b449a5dedf9d60';
const pad = (a) => '0x' + '0'.repeat(24) + a.slice(2);
const amountHex = (n) => '0x' + BigInt(n).toString(16).padStart(64, '0');

// Shape of the real X Layer receipt for the Pay-Safe demo payment (block 70825096).
function rpc(receipt) {
  return async (url, init) => {
    const body = JSON.parse(init.body);
    const result = body.method === 'eth_getTransactionReceipt' ? receipt : { timestamp: '0x' + Math.floor(Date.parse('2026-09-16T21:28:52Z') / 1000).toString(16) };
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { headers: { 'content-type': 'application/json' } });
  };
}
const receipt = (logs, status) => ({ status: status || '0x1', blockNumber: '0x' + (70825096).toString(16), from: '0xde95edc8d29ea5a44654e40b0ab3613dfe000591', logs });
const transfer = (token, from, to, amount) => ({ address: token, topics: [TRANSFER_TOPIC, pad(from), pad(to)], data: amountHex(amount) });

test('settlement: transfer of the checked token, payee and amount is settled as checked', async () => {
  const r = await verifySettlement({ txHash: TX, payTo: PAYEE, amount: '5000', asset: USDT0, payer: PAYER, rpcUrls: ['https://rpc.test'], fetchImpl: rpc(receipt([transfer(USDT0, PAYER, PAYEE, 5000)])) });
  assert.equal(r.ok, true, r.problems.join('; '));
  assert.equal(r.status, 'success');
  assert.equal(r.blockNumber, 70825096);
  assert.equal(r.timestamp, '2026-09-16T21:28:52.000Z');
});

test('settlement: different payee, amount or token is not settled as checked', async () => {
  const other = '0x1111111111111111111111111111111111111111';
  for (const logs of [[transfer(USDT0, PAYER, other, 5000)], [transfer(USDT0, PAYER, PAYEE, 5000000)], [transfer('0x74b7f16337b8972027f6196a17a631ac6de26d22', PAYER, PAYEE, 5000)]]) {
    const r = await verifySettlement({ txHash: TX, payTo: PAYEE, amount: '5000', asset: USDT0, payer: PAYER, rpcUrls: ['https://rpc.test'], fetchImpl: rpc(receipt(logs)) });
    assert.equal(r.ok, false);
    assert.ok(r.problems.length > 0);
  }
});

test('settlement: extra transfers from the payer and reverted transactions are flagged', async () => {
  const extra = await verifySettlement({ txHash: TX, payTo: PAYEE, amount: '5000', asset: USDT0, payer: PAYER, rpcUrls: ['https://rpc.test'], fetchImpl: rpc(receipt([transfer(USDT0, PAYER, PAYEE, 5000), transfer(USDT0, PAYER, '0x2222222222222222222222222222222222222222', 90000)])) });
  assert.equal(extra.ok, false);
  assert.match(extra.problems.join(' '), /other transfer/);
  const reverted = await verifySettlement({ txHash: TX, payTo: PAYEE, amount: '5000', asset: USDT0, rpcUrls: ['https://rpc.test'], fetchImpl: rpc(receipt([transfer(USDT0, PAYER, PAYEE, 5000)], '0x0')) });
  assert.equal(reverted.ok, false);
  assert.equal(reverted.status, 'failed');
});

test('settlement: pending and bad input', async () => {
  const pending = await verifySettlement({ txHash: TX, payTo: PAYEE, amount: '5000', asset: USDT0, rpcUrls: ['https://rpc.test'], fetchImpl: rpc(null) });
  assert.equal(pending.status, 'pending');
  await assert.rejects(verifySettlement({ txHash: '0x12', payTo: PAYEE, amount: '5000', asset: USDT0 }), /txHash/);
});
