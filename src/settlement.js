'use strict';

/**
 * Post-payment check: did the settled transaction move exactly what Pay-Safe checked?
 *
 * Reads the receipt from the chain (no wallet, no signing) and looks for an ERC-20 Transfer of the checked
 * token, from the payer, to the checked payee, for the checked atomic amount. x402 settlement is submitted by
 * a facilitator, so the transaction sender is not the payer; the Transfer log is what matters.
 */

const { rpcUrlsFor } = require('./rpc');

const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;

async function rpcCall(urls, method, params, fetchImpl, timeoutMs) {
  let lastErr = null;
  for (const url of urls) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs || 8000);
    try {
      const res = await (fetchImpl || fetch)(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: ctrl.signal });
      const j = await res.json();
      if (j.error) throw new Error(j.error.message || 'rpc error');
      return j.result;
    } catch (err) {
      lastErr = err;
    } finally {
      clearTimeout(t);
    }
  }
  throw new Error('all RPC endpoints failed: ' + (lastErr ? lastErr.message : 'no endpoints'));
}

const lc = (a) => String(a || '').toLowerCase();
const topicAddr = (topic) => '0x' + String(topic).slice(26).toLowerCase();

/**
 * @param {object} p { txHash, chainId=196, payTo, amount (atomic string), asset, payer?, rpcUrls?, fetchImpl? }
 * @returns {Promise<{ok, status, blockNumber, timestamp, transfers, matched, problems}>}
 */
async function verifySettlement(p) {
  if (!HASH_RE.test(String(p.txHash || ''))) throw new Error('txHash must be a 32-byte 0x hash');
  for (const k of ['payTo', 'asset']) if (!ADDR_RE.test(String(p[k] || ''))) throw new Error(k + ' must be an address');
  if (!/^\d+$/.test(String(p.amount || ''))) throw new Error('amount must be an atomic integer string');
  const chainId = Number(p.chainId || 196);
  const urls = p.rpcUrls || rpcUrlsFor(chainId);
  const receipt = await rpcCall(urls, 'eth_getTransactionReceipt', [p.txHash], p.fetchImpl);
  if (!receipt) return { ok: false, status: 'pending', problems: ['no receipt yet'], transfers: [], matched: null };
  const status = receipt.status === '0x1' ? 'success' : 'failed';
  const transfers = (receipt.logs || [])
    .filter((l) => l.topics && l.topics[0] === TRANSFER_TOPIC && l.topics.length >= 3)
    .map((l) => ({ token: lc(l.address), from: topicAddr(l.topics[1]), to: topicAddr(l.topics[2]), amount: BigInt(l.data === '0x' ? 0 : l.data).toString() }));
  const matched = transfers.find((t) => t.token === lc(p.asset) && t.to === lc(p.payTo) && t.amount === String(p.amount) && (!p.payer || t.from === lc(p.payer))) || null;
  const problems = [];
  if (status !== 'success') problems.push('transaction reverted');
  if (!matched) {
    const sameToken = transfers.filter((t) => t.token === lc(p.asset));
    if (!sameToken.length) problems.push('no transfer of the checked token');
    else problems.push('token moved differently than checked: ' + sameToken.map((t) => t.amount + ' to ' + t.to).join(', '));
  }
  const extra = transfers.filter((t) => t !== matched && (!p.payer || t.from === lc(p.payer)));
  if (matched && extra.length) problems.push('the payer also sent ' + extra.length + ' other transfer(s) in this transaction');
  let timestamp = null;
  try {
    const block = await rpcCall(urls, 'eth_getBlockByNumber', [receipt.blockNumber, false], p.fetchImpl);
    if (block && block.timestamp) timestamp = new Date(parseInt(block.timestamp, 16) * 1000).toISOString();
  } catch { /* timestamp is informational */ }
  return { ok: status === 'success' && Boolean(matched) && problems.length === 0, status, blockNumber: parseInt(receipt.blockNumber, 16), timestamp, submitter: lc(receipt.from), transfers, matched, problems };
}

module.exports = { verifySettlement, TRANSFER_TOPIC };
