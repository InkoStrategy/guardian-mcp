#!/usr/bin/env node
'use strict';

/**
 * Prove the eip712_domain_mismatch rule against the chain, not a hardcoded table.
 *
 * Reads DOMAIN_SEPARATOR() (selector 0x3644e515) live from the USD₮0 token on X Layer, then recomputes the
 * EIP-712 domain separator for the (name, version) pairs sellers actually declare and shows which one the
 * contract accepts. Only the canonical pair matches; every other declared domain would fail at settlement.
 *
 *   node scripts/verify-eip712-domain.js
 *
 * Read-only eth_call; nothing is signed or paid.
 */

const { AbiCoder, keccak256, toUtf8Bytes, getAddress } = require('ethers');
const { rpcUrlsFor } = require('../src/rpc');

const CHAIN_ID = 196; // X Layer
const TOKEN = '0x779ded0c9e1022225f8e0630b35a9b54be713736'; // USD₮0
const DOMAIN_SEPARATOR_SELECTOR = '0x3644e515';
// EIP-712 domain typehash for EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
const DOMAIN_TYPEHASH = keccak256(toUtf8Bytes('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'));

function computeDomainSeparator(name, version) {
  const enc = AbiCoder.defaultAbiCoder().encode(
    ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
    [DOMAIN_TYPEHASH, keccak256(toUtf8Bytes(name)), keccak256(toUtf8Bytes(version)), CHAIN_ID, getAddress(TOKEN)],
  );
  return keccak256(enc);
}

async function ethCall(to, data) {
  const urls = rpcUrlsFor(CHAIN_ID);
  let lastErr;
  for (const url of urls) {
    try {
      const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to, data }, 'latest'] }) });
      const j = await res.json();
      if (j.error) throw new Error(j.error.message || JSON.stringify(j.error));
      return j.result;
    } catch (e) { lastErr = e; }
  }
  throw lastErr || new Error('all RPCs failed');
}

async function main() {
  const onchain = (await ethCall(TOKEN, DOMAIN_SEPARATOR_SELECTOR) || '').toLowerCase();
  console.log('USD₮0 ' + TOKEN + ' on X Layer (chainId ' + CHAIN_ID + ')');
  console.log('on-chain DOMAIN_SEPARATOR() = ' + onchain);
  console.log('');
  // The pairs seen declared across the marketplace scan, canonical first.
  const declared = [
    ['USD₮0', '1'],
    ['USDT', '1'],
    ['USDT₀', '1'],
    ['USD₮0', '2'],
    ['USD Coin', '2'],
  ];
  let matched = null;
  for (const [name, version] of declared) {
    const local = computeDomainSeparator(name, version).toLowerCase();
    const ok = local === onchain;
    if (ok) matched = [name, version];
    console.log((ok ? 'MATCH  ' : 'reject ') + 'name=' + JSON.stringify(name).padEnd(10) + ' version=' + JSON.stringify(version) + '  -> ' + local.slice(0, 12) + '…');
  }
  console.log('');
  if (matched) console.log('The contract accepts ONLY name ' + JSON.stringify(matched[0]) + ' version ' + JSON.stringify(matched[1]) + '. Any other declared domain fails TransferWithAuthorization on-chain, so the buyer would pay and the call would still be rejected.');
  else console.log('No declared pair reproduced the on-chain DOMAIN_SEPARATOR — check the RPC and inputs.');
  process.exitCode = matched ? 0 : 1;
}

main().catch((e) => { console.error('verify-eip712-domain:', e.message); process.exitCode = 1; });
