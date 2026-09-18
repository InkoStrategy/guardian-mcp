'use strict';

/**
 * Lists the OKX.AI sellers whose 402 challenge declares an EIP-712 domain the token contract does not use,
 * so their TransferWithAuthorization signatures cannot verify on-chain. Source: the dated trust snapshots.
 * Usage: node scripts/eip712-outreach.js [YYYY-MM-DD]
 */

const path = require('path');
const fs = require('fs');

const date = process.argv[2] || '2026-09-18';
const file = path.resolve(__dirname, '..', 'docs', 'trust-scans', date + '.json');
if (!fs.existsSync(file)) { console.error('no snapshot for ' + date); process.exit(1); }

const snap = JSON.parse(fs.readFileSync(file, 'utf8'));
const rows = snap.results || snap.services || snap.rows || [];

const declaredOf = (msg) => {
  const m = /extra declares the EIP-712 domain name "([^"]+)" version "([^"]+)"/.exec(msg || '');
  return m ? { name: m[1], version: m[2] } : null;
};

const hits = [];
for (const r of rows) {
  const f = (r.findings || []).find((x) => x.code === 'eip712_domain_mismatch');
  if (!f) continue;
  hits.push({
    sid: r.sid,
    service: r.service,
    seller: r.asp,
    agentId: r.aspAgentId,
    endpoint: r.endpoint,
    fee: r.listed && r.listed.feeAmount,
    payTo: r.challenge && r.challenge.payTo,
    declared: declaredOf(f.message),
  });
}

console.log('EIP-712 domain mismatches on ' + date + ': ' + hits.length + ' of ' + rows.length + ' services\n');
const byDomain = {};
for (const h of hits) {
  const k = h.declared ? h.declared.name + ' / ' + h.declared.version : 'unparsed';
  (byDomain[k] = byDomain[k] || []).push(h);
}
for (const [dom, list] of Object.entries(byDomain)) {
  console.log('declares "' + dom + '"  -> ' + list.length + ' service(s)');
  for (const h of list) {
    console.log('   sid ' + h.sid + '  ' + h.service);
    console.log('      seller: ' + h.seller + ' (agent ' + h.agentId + ')  fee ' + h.fee + '  payTo ' + h.payTo);
    console.log('      ' + h.endpoint);
  }
  console.log('');
}

const sellers = [...new Set(hits.map((h) => h.seller))];
console.log('distinct sellers to contact: ' + sellers.length + ' -> ' + sellers.join(', '));

const out = path.resolve(__dirname, '..', 'docs', 'eip712-outreach-' + date + '.json');
fs.writeFileSync(out, JSON.stringify({ date, correct: { name: 'USD₮0', version: '1' }, count: hits.length, sellers, services: hits }, null, 2));
console.log('\nwrote ' + path.relative(process.cwd(), out));
