'use strict';

/**
 * On-chain intelligence: token metadata, contract inspection, simulation.
 * Everything here is "enrichment": failures are reported, never hidden, and the
 * caller decides how they affect the verdict.
 */

const { Interface, AbiCoder, dataSlice, toUtf8String, getAddress, formatUnits, parseUnits } = require('ethers');
const registry = require('./registry');
const { isRevert, RpcError } = require('./rpc');

const abi = AbiCoder.defaultAbiCoder();

const ERC20 = new Interface([
  'function symbol() view returns (string)',
  'function decimals() view returns (uint8)',
  'function name() view returns (string)',
  'function balanceOf(address) view returns (uint256)',
  'function allowance(address,address) view returns (uint256)',
  'function approve(address,uint256)',
]);

const EIP1967_IMPL_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const EIP1967_BEACON_SLOT = '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50';
const EIP1167_RE = /^0x363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$/i;
const TINY_CODE_BYTES = 64;

const PANIC_CODES = {
  0x01: 'assertion failed', 0x11: 'arithmetic overflow/underflow', 0x12: 'division by zero', 0x21: 'invalid enum value',
  0x22: 'invalid storage byte array', 0x31: 'pop on empty array', 0x32: 'array index out of bounds', 0x41: 'out of memory', 0x51: 'invalid internal function',
};

const MAX_CACHE = 5000;
const tokenCache = new Map();

function cacheGet(key) {
  const v = tokenCache.get(key);
  if (v !== undefined) {
    tokenCache.delete(key);
    tokenCache.set(key, v);
  }
  return v;
}

function cacheSet(key, value) {
  if (tokenCache.size >= MAX_CACHE) tokenCache.delete(tokenCache.keys().next().value);
  tokenCache.set(key, value);
}

function canCall(reader) {
  return Boolean(reader) && typeof reader.call === 'function';
}

function decodeStringOrBytes32(hex) {
  if (!hex || hex === '0x') return null;
  try {
    return abi.decode(['string'], hex)[0];
  } catch {
    /* fall through */
  }
  if (hex.length === 66) {
    try {
      const raw = Buffer.from(hex.slice(2), 'hex');
      const end = raw.indexOf(0);
      return raw.subarray(0, end === -1 ? raw.length : end).toString('utf8');
    } catch {
      return null;
    }
  }
  return null;
}

/** Decode a revert payload into a human message. */
function decodeRevert(err) {
  const out = { reason: null, selector: null, kind: 'unknown' };
  const data = (err && (err.data || (err.info && err.info.error && err.info.error.data))) || null;
  if (err && err.reason && typeof err.reason === 'string' && err.reason !== 'require(false)') {
    out.reason = err.reason;
    out.kind = 'error';
  }
  if (typeof data === 'string' && data.startsWith('0x') && data.length >= 10) {
    out.selector = data.slice(0, 10);
    try {
      if (out.selector === '0x08c379a0') {
        out.reason = abi.decode(['string'], dataSlice(data, 4))[0];
        out.kind = 'error';
      } else if (out.selector === '0x4e487b71') {
        const code = Number(abi.decode(['uint256'], dataSlice(data, 4))[0]);
        out.reason = 'panic: ' + (PANIC_CODES[code] || '0x' + code.toString(16));
        out.kind = 'panic';
      } else if (data.length > 10) {
        out.kind = 'custom';
        if (!out.reason) out.reason = 'custom error ' + out.selector;
      }
    } catch {
      /* keep what we have */
    }
  }
  if (!out.reason) {
    if (data === '0x' || data === null) {
      out.reason = 'reverted without a reason';
      out.kind = 'silent';
    } else if (err && err.shortMessage) out.reason = err.shortMessage;
    else out.reason = 'execution reverted';
  }
  return out;
}

/**
 * ERC-20 metadata: registry first, then on-chain symbol()/decimals()/name().
 * @returns {Promise<null|{symbol:string,decimals:number,name:string|null,source:string}>}
 */
async function getTokenMeta(reader, chainId, address) {
  const known = registry.lookupToken(chainId, address);
  if (known) return known;
  if (!canCall(reader)) return null;
  const key = chainId + ':' + String(address).toLowerCase();
  const cached = cacheGet(key);
  if (cached !== undefined) return cached;

  const call = async (fn) => {
    try {
      return await reader.call({ to: address, data: ERC20.encodeFunctionData(fn) });
    } catch (err) {
      if (isRevert(err)) return null;
      throw err;
    }
  };
  const [symbolHex, decimalsHex, nameHex] = await Promise.all([call('symbol'), call('decimals'), call('name')]);
  let meta = null;
  const symbol = decodeStringOrBytes32(symbolHex);
  let decimals = null;
  if (decimalsHex && decimalsHex !== '0x') {
    try {
      decimals = Number(abi.decode(['uint8'], decimalsHex)[0]);
    } catch {
      decimals = null;
    }
  }
  if (symbol && decimals !== null) {
    meta = { address: String(address).toLowerCase(), symbol: symbol.slice(0, 32), decimals, name: (decodeStringOrBytes32(nameHex) || '').slice(0, 64) || null, source: 'onchain' };
  } else if (symbol || nameHex) {
    // ERC-721/1155 collections expose name()/symbol() without decimals()
    meta = { address: String(address).toLowerCase(), symbol: symbol ? symbol.slice(0, 32) : null, decimals: null, name: (decodeStringOrBytes32(nameHex) || '').slice(0, 64) || null, source: 'onchain', nonFungible: true };
  }
  cacheSet(key, meta);
  return meta;
}

function formatAmount(raw, meta) {
  const big = typeof raw === 'bigint' ? raw : BigInt(raw);
  if (meta && Number.isInteger(meta.decimals)) {
    let s = formatUnits(big, meta.decimals);
    if (s.includes('.')) s = s.replace(/\.?0+$/, '');
    return s + ' ' + (meta.symbol || 'tokens');
  }
  return big.toString() + ' raw units';
}

function isUnlimited(raw) {
  const big = typeof raw === 'bigint' ? raw : BigInt(raw);
  return big > (2n ** 255n - 1n);
}

/**
 * Inspect a contract's shape from its code (already fetched) and, when the
 * reader supports it, its EIP-1967 storage.
 */
async function inspectContract(reader, chainId, address, state) {
  const out = {
    address: getAddress(address),
    known: registry.lookupContract(chainId, address),
    isContract: Boolean(state && state.isContract),
    codeSize: state ? state.codeSize || 0 : 0,
    proxy: null,
    tiny: false,
    lookalikeOf: registry.findRegistryLookalike(chainId, address),
  };
  if (!out.isContract) return out;
  const code = state.code || '0x';
  const m = code.match(EIP1167_RE);
  if (m) {
    out.proxy = { type: 'eip1167-minimal-proxy', implementation: getAddress('0x' + m[1]) };
  } else if (reader && typeof reader.getStorage === 'function') {
    try {
      const slot = await reader.getStorage(address, EIP1967_IMPL_SLOT);
      if (slot && /^0x0*[1-9a-f]/i.test(slot)) {
        out.proxy = { type: 'eip1967-upgradeable-proxy', implementation: getAddress('0x' + slot.slice(-40)) };
      } else {
        const beacon = await reader.getStorage(address, EIP1967_BEACON_SLOT);
        if (beacon && /^0x0*[1-9a-f]/i.test(beacon)) out.proxy = { type: 'eip1967-beacon-proxy', beacon: getAddress('0x' + beacon.slice(-40)) };
      }
    } catch (err) {
      if (!(err instanceof RpcError)) throw err;
      out.proxyCheckError = err.message;
    }
  }
  out.tiny = !out.proxy && out.codeSize > 0 && out.codeSize < TINY_CODE_BYTES;
  return out;
}

/** eth_call + eth_estimateGas from `from`. Reverts are answers; RpcError propagates. */
async function simulate(reader, tx) {
  const req = { from: tx.from, to: tx.to, data: tx.data, value: tx.value };
  const out = { ran: true, ok: null, reverted: false, revert: null, gasEstimate: null, returnData: null };
  try {
    out.returnData = await reader.call(req);
    out.ok = true;
  } catch (err) {
    if (!isRevert(err)) throw err;
    out.ok = false;
    out.reverted = true;
    out.revert = decodeRevert(err);
    return out;
  }
  if (typeof reader.estimateGas === 'function') {
    try {
      const gas = await reader.estimateGas(req);
      out.gasEstimate = gas.toString();
    } catch (err) {
      if (!isRevert(err)) throw err;
      out.ok = false;
      out.reverted = true;
      out.revert = decodeRevert(err);
    }
  }
  return out;
}

/** Current ERC-20 balance of `from` and (optionally) allowance to `spender`. */
async function readErc20State(reader, token, from, spender) {
  const out = { balance: null, allowance: null };
  const call = async (data) => {
    try {
      const hex = await reader.call({ to: token, data });
      return hex && hex !== '0x' ? abi.decode(['uint256'], hex)[0] : null;
    } catch (err) {
      if (isRevert(err)) return null;
      throw err;
    }
  };
  const [bal, allow] = await Promise.all([
    call(ERC20.encodeFunctionData('balanceOf', [from])),
    spender ? call(ERC20.encodeFunctionData('allowance', [from, spender])) : Promise.resolve(null),
  ]);
  if (bal !== null) out.balance = bal.toString();
  if (allow !== null) out.allowance = allow.toString();
  return out;
}

/** Build approve(spender, amount) calldata for a bounded allowance. */
function boundedApproveCalldata(spender, humanAmount, meta) {
  if (!meta || !Number.isInteger(meta.decimals)) return null;
  const raw = parseUnits(String(humanAmount), meta.decimals);
  return { data: ERC20.encodeFunctionData('approve', [spender, raw]), amountRaw: raw.toString(), amount: formatAmount(raw, meta) };
}

function revokeApproveCalldata(spender) {
  return ERC20.encodeFunctionData('approve', [spender, 0n]);
}

module.exports = {
  getTokenMeta,
  formatAmount,
  isUnlimited,
  inspectContract,
  simulate,
  decodeRevert,
  readErc20State,
  boundedApproveCalldata,
  revokeApproveCalldata,
  canCall,
  EIP1967_IMPL_SLOT,
};
