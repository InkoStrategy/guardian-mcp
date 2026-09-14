'use strict';

/**
 * Asset-flow simulation: where does the value actually end up?
 *
 * Uses eth_simulateV1 with traceTransfers (supported by the default public
 * nodes) and a balance state override for the sender, so the flow is visible
 * even for a wallet that is empty right now. Parses native ETH transfer logs
 * (synthetic address 0xeeee…eeee), ERC-20 Transfer and ERC-721 Transfer events
 * into per-address net positions.
 *
 * What it answers:
 *   - which addresses hold more value after the call (final recipients)
 *   - what the sender gives and gets back
 * which is exactly the information calldata alone cannot give for an
 * unknown function on an intermediary contract that forwards to a drainer.
 */

const { id, parseEther, getAddress } = require('ethers');
const { isMethodNotFound, isRevert, RpcError } = require('./rpc');

const ETH_SENTINEL = '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const TOPIC_TRANSFER = id('Transfer(address,address,uint256)');
const TOPIC_1155_SINGLE = id('TransferSingle(address,address,address,uint256,uint256)');
const OVERRIDE_BALANCE = parseEther('1000');

function topicAddr(t) {
  return t ? getAddress('0x' + t.slice(-40)) : null;
}

function parseLogs(logs) {
  const transfers = [];
  for (const l of logs || []) {
    const topics = l.topics || [];
    if (!topics.length) continue;
    const t0 = topics[0].toLowerCase();
    const addr = String(l.address).toLowerCase();
    if (t0 === TOPIC_TRANSFER && topics.length === 3) {
      const value = BigInt(l.data && l.data !== '0x' ? l.data : '0x0');
      transfers.push({ asset: addr === ETH_SENTINEL ? 'ETH' : getAddress(l.address), standard: addr === ETH_SENTINEL ? 'native' : 'erc20', from: topicAddr(topics[1]), to: topicAddr(topics[2]), value: value.toString(), valueBig: value });
    } else if (t0 === TOPIC_TRANSFER && topics.length === 4) {
      transfers.push({ asset: getAddress(l.address), standard: 'erc721', from: topicAddr(topics[1]), to: topicAddr(topics[2]), tokenId: BigInt(topics[3]).toString(), value: '1', valueBig: 1n });
    } else if (t0 === TOPIC_1155_SINGLE && topics.length === 4) {
      let value = 1n;
      try {
        value = BigInt('0x' + l.data.slice(2 + 64, 2 + 128));
      } catch {
        value = 1n;
      }
      transfers.push({ asset: getAddress(l.address), standard: 'erc1155', from: topicAddr(topics[2]), to: topicAddr(topics[3]), value: value.toString(), valueBig: value });
    }
  }
  return transfers;
}

/** Net position per address per asset. Positive = received more than sent. */
function netPositions(transfers) {
  const net = new Map(); // addr -> Map(asset -> bigint)
  const bump = (a, asset, delta) => {
    if (!a) return;
    const k = a.toLowerCase();
    if (!net.has(k)) net.set(k, new Map());
    const m = net.get(k);
    m.set(asset, (m.get(asset) || 0n) + delta);
  };
  for (const t of transfers) {
    bump(t.from, t.asset, -t.valueBig);
    bump(t.to, t.asset, t.valueBig);
  }
  return net;
}

/**
 * @param {object} reader chain reader with send()
 * @param {{from:string,to:string,data:string,value:bigint}} tx
 * @returns {Promise<object>} { ran, supported, status, reverted, error, transfers, sender_net, recipients, gasUsed }
 */
async function simulateFlow(reader, tx) {
  const out = { ran: false, supported: null, status: null, reverted: false, error: null, transfers: [], sender_net: [], recipients: [], gasUsed: null };
  if (!reader || typeof reader.send !== 'function') {
    out.supported = false;
    out.error = 'reader does not support raw RPC';
    return out;
  }
  const call = { from: tx.from, to: tx.to, data: tx.data || '0x', value: '0x' + (tx.value || 0n).toString(16) };
  const params = [{ blockStateCalls: [{ stateOverrides: { [tx.from]: { balance: '0x' + (OVERRIDE_BALANCE + (tx.value || 0n)).toString(16) } }, calls: [call] }], traceTransfers: true, validation: false }, 'latest'];
  let res;
  try {
    res = await reader.send('eth_simulateV1', params);
  } catch (err) {
    if (isMethodNotFound(err)) {
      out.supported = false;
      out.error = 'eth_simulateV1 not supported by this RPC';
      return out;
    }
    if (isRevert(err)) {
      out.ran = true;
      out.supported = true;
      out.reverted = true;
      out.error = err.shortMessage || err.message;
      return out;
    }
    throw err instanceof RpcError ? err : new RpcError('eth_simulateV1 failed: ' + err.message, err);
  }
  const block = Array.isArray(res) ? res[0] : null;
  const c = block && block.calls && block.calls[0];
  if (!c) {
    out.supported = false;
    out.error = 'unexpected eth_simulateV1 response shape';
    return out;
  }
  out.ran = true;
  out.supported = true;
  out.status = c.status;
  out.gasUsed = c.gasUsed ? BigInt(c.gasUsed).toString() : null;
  if (c.status !== '0x1') {
    out.reverted = true;
    out.error = (c.error && c.error.message) || 'call reverted in simulation';
    return out;
  }
  const transfers = parseLogs(c.logs);
  out.transfers = transfers.map((t) => ({ asset: t.asset, standard: t.standard, from: t.from, to: t.to, value: t.value, tokenId: t.tokenId }));
  const net = netPositions(transfers);
  const sender = tx.from.toLowerCase();
  const senderNet = net.get(sender) || new Map();
  out.sender_net = Array.from(senderNet.entries()).filter(([, v]) => v !== 0n).map(([asset, v]) => ({ asset, delta: v.toString() }));
  for (const [addr, m] of net) {
    if (addr === sender) continue;
    const gains = Array.from(m.entries()).filter(([, v]) => v > 0n).map(([asset, v]) => ({ asset, delta: v.toString() }));
    if (gains.length) out.recipients.push({ address: getAddress(addr), gains });
  }
  return out;
}

const FLOW_RULES = [
  { code: 'funds_flow_to_flagged', severity: 'DENY', layer: 'asset-flow', description: 'Simulation shows value ending at an address listed in the ScamSniffer database, reported as a drainer, or imitating a known contract, even though the transaction itself does not name that address.' },
  { code: 'funds_flow_no_return', severity: 'WARN', layer: 'asset-flow', description: 'Simulation shows the sender giving value to a plain wallet (not a contract) through an unrecognised call and receiving nothing back. The classic shape of a "claim" or "mint" drain.' },
];

module.exports = { simulateFlow, parseLogs, netPositions, ETH_SENTINEL, FLOW_RULES };
