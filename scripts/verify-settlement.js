#!/usr/bin/env node
'use strict';

/**
 * Verify on-chain that a settled x402 payment moved exactly what Pay-Safe checked. Read-only.
 *
 *   node scripts/verify-settlement.js --tx 0x… --pay-to 0x… --amount 5000 [--token 0x779d…] [--payer 0x…] [--chain 196]
 *
 * Exit codes: 0 settled as checked, 3 mismatch or reverted, 1 error or pending.
 */

const { verifySettlement } = require('../src/settlement');

const argv = process.argv.slice(2);
const opt = (k, d) => { const i = argv.indexOf('--' + k); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : d; };
const USDT0 = '0x779ded0c9e1022225f8e0630b35a9b54be713736';
const short = (a) => (a && a.length === 42 ? a.slice(0, 6) + '…' + a.slice(-4) : a);

(async () => {
  const p = { txHash: opt('tx'), payTo: opt('pay-to'), amount: opt('amount'), asset: opt('token', USDT0), payer: opt('payer'), chainId: Number(opt('chain', 196)) };
  const r = await verifySettlement(p);
  console.log('1. Receipt   ' + r.status + (r.blockNumber ? ' in block ' + r.blockNumber : '') + (r.timestamp ? ' at ' + r.timestamp : '') + (r.submitter ? ', submitted by facilitator ' + short(r.submitter) : ''));
  for (const t of r.transfers) console.log('             Transfer ' + t.amount + ' of ' + short(t.token) + ' from ' + short(t.from) + ' to ' + short(t.to));
  if (r.ok) console.log('2. Settled   as checked: payee ' + short(p.payTo) + ', amount ' + p.amount + ', token ' + short(p.asset));
  else console.log('2. Settled   NOT as checked: ' + r.problems.join('; '));
  process.exitCode = r.ok ? 0 : r.status === 'pending' ? 1 : 3;
})().catch((e) => { console.error('verify-settlement: ' + e.message); process.exitCode = 1; });
