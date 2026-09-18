'use strict';

/**
 * Live on-chain verification of a token's EIP-712 domain. Reads DOMAIN_SEPARATOR() (selector 0x3644e515)
 * from the token contract and recomputes the separator for a declared (name, version) pair, so the
 * eip712_domain_mismatch finding rests on an on-chain read, not only a hardcoded table. Cached in-process.
 */

const { AbiCoder, keccak256, toUtf8Bytes, getAddress } = require('ethers');
const { rpcUrlsFor } = require('./rpc');

const DOMAIN_SEPARATOR_SELECTOR = '0x3644e515';
const DOMAIN_TYPEHASH = keccak256(toUtf8Bytes('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'));
const CACHE = new Map(); // key `${chainId}:${token}` -> { ts, separator }
const TTL_MS = 10 * 60 * 1000;

function computeSeparator(name, version, chainId, token) {
  const enc = AbiCoder.defaultAbiCoder().encode(
    ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
    [DOMAIN_TYPEHASH, keccak256(toUtf8Bytes(String(name))), keccak256(toUtf8Bytes(String(version))), chainId, getAddress(token)],
  );
  return keccak256(enc).toLowerCase();
}

async function readDomainSeparator(chainId, token, fetchImpl) {
  const key = chainId + ':' + String(token).toLowerCase();
  const hit = CACHE.get(key);
  if (hit && (Date.now() - hit.ts) < TTL_MS) return hit.separator;
  const doFetch = fetchImpl || fetch;
  const urls = rpcUrlsFor(chainId);
  let lastErr;
  for (const url of urls) {
    try {
      const res = await doFetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: token, data: DOMAIN_SEPARATOR_SELECTOR }, 'latest'] }) });
      const j = await res.json();
      if (j.error) throw new Error(j.error.message || 'rpc error');
      const sep = String(j.result || '').toLowerCase();
      if (/^0x[0-9a-f]{64}$/.test(sep)) { CACHE.set(key, { ts: Date.now(), separator: sep }); return sep; }
      throw new Error('no DOMAIN_SEPARATOR returned');
    } catch (e) { lastErr = e; }
  }
  throw lastErr || new Error('all RPCs failed');
}

/**
 * @returns {{token, chainId, onchainDomainSeparator, declared: [{name,version,matches,separator}], accepted: {name,version}|null}}
 */
async function verify(chainId, token, declaredPairs, fetchImpl) {
  const onchain = await readDomainSeparator(chainId, token, fetchImpl);
  const pairs = (declaredPairs && declaredPairs.length ? declaredPairs : [['USD₮0', '1'], ['USDT', '1'], ['USDT₀', '1'], ['USD₮0', '2']]).map(([name, version]) => {
    const separator = computeSeparator(name, version, chainId, token);
    return { name, version, separator: separator.slice(0, 14) + '…', matches: separator === onchain };
  });
  const acc = pairs.find((p) => p.matches);
  return { token: getAddress(token), chainId, onchainDomainSeparator: onchain, declared: pairs, accepted: acc ? { name: acc.name, version: acc.version } : null };
}

module.exports = { verify, readDomainSeparator, computeSeparator };
