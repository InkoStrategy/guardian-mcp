'use strict';

const { AbiCoder, getAddress, isAddress, isHexString, dataSlice, MaxUint256, ZeroAddress } = require('ethers');
const { createChainReader, RpcError, supportedChainIds } = require('./rpc');

const abi = AbiCoder.defaultAbiCoder();

const SEVERITY = { ALLOW: 0, WARN: 1, DENY: 2 };

/** Selectors we decode and apply rules to. */
const DECODED = {
  '0x095ea7b3': { name: 'approve(address,uint256)', kind: 'approve', types: ['address', 'uint256'], spender: 0, amount: 1 },
  '0x39509351': { name: 'increaseAllowance(address,uint256)', kind: 'approve', types: ['address', 'uint256'], spender: 0, amount: 1 },
  '0xd505accf': { name: 'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)', kind: 'approve', types: ['address', 'address', 'uint256', 'uint256', 'uint8', 'bytes32', 'bytes32'], spender: 1, amount: 2 },
  '0xa22cb465': { name: 'setApprovalForAll(address,bool)', kind: 'approvalForAll', types: ['address', 'bool'], operator: 0, approved: 1 },
  '0xa9059cbb': { name: 'transfer(address,uint256)', kind: 'transfer', types: ['address', 'uint256'], recipient: 0, amount: 1 },
  '0x23b872dd': { name: 'transferFrom(address,address,uint256)', kind: 'transfer', types: ['address', 'address', 'uint256'], recipient: 1, amount: 2 },
  '0x42842e0e': { name: 'safeTransferFrom(address,address,uint256)', kind: 'transfer', types: ['address', 'address', 'uint256'], recipient: 1, amount: 2 },
  '0xb88d4fde': { name: 'safeTransferFrom(address,address,uint256,bytes)', kind: 'transfer', types: ['address', 'address', 'uint256', 'bytes'], recipient: 1, amount: 2 },
  '0xf242432a': { name: 'safeTransferFrom(address,address,uint256,uint256,bytes)', kind: 'transfer', types: ['address', 'address', 'uint256', 'uint256', 'bytes'], recipient: 1, amount: 3 },
  '0x2eb2c2d6': { name: 'safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)', kind: 'transfer', types: ['address', 'address', 'uint256[]', 'uint256[]', 'bytes'], recipient: 1 },
};

/** Well-known selectors that are recognised (not "unknown") but carry no dedicated rule. */
const KNOWN = {
  '0xd0e30db0': 'deposit()',
  '0x2e1a7d4d': 'withdraw(uint256)',
  '0x7ff36ab5': 'swapExactETHForTokens(uint256,address[],address,uint256)',
  '0x18cbafe5': 'swapExactTokensForETH(uint256,uint256,address[],address,uint256)',
  '0x38ed1739': 'swapExactTokensForTokens(uint256,uint256,address[],address,uint256)',
  '0x8803dbee': 'swapTokensForExactTokens(uint256,uint256,address[],address,uint256)',
  '0xfb3bdb41': 'swapETHForExactTokens(uint256,address[],address,uint256)',
  '0x414bf389': 'exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))',
  '0xc04b8d59': 'exactInput((bytes,address,uint256,uint256,uint256))',
  '0x04e45aaf': 'exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))',
  '0xb858183f': 'exactInput((bytes,address,uint256,uint256))',
  '0x5ae401dc': 'multicall(uint256,bytes[])',
  '0xac9650d8': 'multicall(bytes[])',
  '0x1f0464d1': 'multicall(bytes32,bytes[])',
  '0x3593564c': 'execute(bytes,bytes[],uint256)',
  '0x24856bc3': 'execute(bytes,bytes[])',
  '0x12aa3caf': 'swap(address,(address,address,address,address,uint256,uint256,uint256),bytes,bytes)',
  '0x0502b1c5': 'unoswap(address,uint256,uint256,uint256[])',
  '0x415565b0': 'transformERC20(address,address,uint256,uint256,(uint32,bytes)[])',
  '0xe8e33700': 'addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)',
  '0xf305d719': 'addLiquidityETH(address,uint256,uint256,uint256,address,uint256)',
  '0xbaa2abde': 'removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)',
  '0x02751cec': 'removeLiquidityETH(address,uint256,uint256,uint256,address,uint256)',
  '0xa694fc3a': 'stake(uint256)',
  '0x2e17de78': 'unstake(uint256)',
  '0x3ccfd60b': 'withdraw()',
  '0x4e71d92d': 'claim()',
  '0x6a627842': 'mint(address)',
  '0x40c10f19': 'mint(address,uint256)',
  '0xa0712d68': 'mint(uint256)',
  '0x42966c68': 'burn(uint256)',
  '0x1249c58b': 'mint()',
  '0x70a08231': 'balanceOf(address)',
  '0xdd62ed3e': 'allowance(address,address)',
};

const MAX_UINT256 = MaxUint256;
const HALF_UINT256 = MAX_UINT256 >> 1n; // 2^255 - 1
const BURN_ADDRESSES = new Set([
  ZeroAddress.toLowerCase(),
  '0x000000000000000000000000000000000000dead',
]);

class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ValidationError';
  }
}

function parseChainId(raw) {
  if (raw === undefined || raw === null || raw === '') return 1;
  const n = typeof raw === 'string' && raw.startsWith('0x') ? Number.parseInt(raw, 16) : Number(raw);
  if (!Number.isInteger(n) || n <= 0) throw new ValidationError('chainId must be a positive integer');
  if (!supportedChainIds().includes(n) && !process.env['RPC_URL_' + n]) {
    throw new ValidationError('chainId ' + n + ' is not supported. Supported: ' + supportedChainIds().join(', ') + ' (or set RPC_URL_' + n + ')');
  }
  return n;
}

function parseValue(raw) {
  if (raw === undefined || raw === null || raw === '') return 0n;
  try {
    if (typeof raw === 'number') {
      if (!Number.isInteger(raw) || raw < 0) throw new Error();
      return BigInt(raw);
    }
    const s = String(raw).trim();
    if (!/^(0x[0-9a-fA-F]+|[0-9]+)$/.test(s)) throw new Error();
    return BigInt(s);
  } catch {
    throw new ValidationError('value must be a non-negative integer (decimal or 0x hex string) in wei');
  }
}

function normalizeInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new ValidationError('Request body must be a JSON object');
  }
  const { to, data, chainId, value } = input;
  if (typeof to !== 'string' || !isAddress(to)) {
    throw new ValidationError('"to" must be a valid 0x-prefixed EVM address (40 hex chars)');
  }
  let calldata = data === undefined || data === null ? '0x' : data;
  if (typeof calldata !== 'string') throw new ValidationError('"data" must be a hex string');
  calldata = calldata.trim();
  if (calldata === '') calldata = '0x';
  if (!calldata.startsWith('0x')) calldata = '0x' + calldata;
  if (!isHexString(calldata)) throw new ValidationError('"data" must be a 0x-prefixed hex string with an even number of hex characters');
  if (calldata.length > 2 && calldata.length < 10) throw new ValidationError('"data" is shorter than a 4-byte function selector');
  return {
    to: getAddress(to),
    data: calldata.toLowerCase(),
    chainId: parseChainId(chainId),
    value: parseValue(value),
  };
}

function decodeCalldata(data) {
  if (data === '0x') return { selector: null, function: null, kind: 'native', args: {}, amountBig: null };
  const selector = dataSlice(data, 0, 4);
  const spec = DECODED[selector];
  if (spec) {
    let decoded;
    try {
      decoded = abi.decode(spec.types, dataSlice(data, 4));
    } catch (err) {
      return { selector, function: spec.name, kind: 'malformed', args: {}, amountBig: null, decodeError: err.shortMessage || err.message };
    }
    const args = {};
    if (spec.spender !== undefined) args.spender = getAddress(decoded[spec.spender]);
    if (spec.operator !== undefined) args.operator = getAddress(decoded[spec.operator]);
    if (spec.recipient !== undefined) args.recipient = getAddress(decoded[spec.recipient]);
    if (spec.amount !== undefined) args.amount = decoded[spec.amount].toString();
    if (spec.approved !== undefined) args.approved = Boolean(decoded[spec.approved]);
    return { selector, function: spec.name, kind: spec.kind, args, amountBig: spec.amount !== undefined ? decoded[spec.amount] : null };
  }
  if (KNOWN[selector]) return { selector, function: KNOWN[selector], kind: 'known', args: {}, amountBig: null };
  return { selector, function: null, kind: 'unknown', args: {}, amountBig: null };
}

function finding(code, severity, message, extra) {
  return Object.assign({ code, severity, message }, extra || {});
}

function isBurn(address) {
  return BURN_ADDRESSES.has(address.toLowerCase());
}

/**
 * Analyse a transaction request.
 * @param {{to:string,data?:string,chainId?:number|string,value?:string|number}} input
 * @param {{reader?: object}} [deps] optional injected chain reader (tests)
 */
async function analyze(input, deps) {
  deps = deps || {};
  const tx = normalizeInput(input);
  const decoded = decodeCalldata(tx.data);
  const findings = [];
  const addressChecks = {};
  const rpc = { ok: true, endpoint: null, error: null };

  // ---------- Static (offline) rules ----------
  if (isBurn(tx.to)) {
    findings.push(finding('zero_address', 'DENY', 'Transaction target ' + tx.to + ' is a burn address; anything sent there is unrecoverable.', { address: tx.to }));
  }
  if (decoded.kind === 'transfer' && decoded.args.recipient && isBurn(decoded.args.recipient)) {
    findings.push(finding('zero_address', 'DENY', 'Transfer recipient ' + decoded.args.recipient + ' is a burn address; tokens will be lost.', { address: decoded.args.recipient }));
  }
  if (decoded.kind === 'approve' && isBurn(decoded.args.spender)) {
    findings.push(finding('zero_address', 'DENY', 'Approval spender ' + decoded.args.spender + ' is the zero address.', { address: decoded.args.spender }));
  }
  if (decoded.kind === 'approvalForAll' && isBurn(decoded.args.operator)) {
    findings.push(finding('zero_address', 'DENY', 'setApprovalForAll operator ' + decoded.args.operator + ' is the zero address.', { address: decoded.args.operator }));
  }

  if (decoded.kind === 'approve' && decoded.amountBig !== null) {
    if (decoded.amountBig === MAX_UINT256) {
      findings.push(finding('unlimited_approval', 'WARN', 'Approval amount is MAX_UINT256 (unlimited). Spender ' + decoded.args.spender + ' could move your entire balance of this token at any time.', { spender: decoded.args.spender, amount: decoded.args.amount }));
    } else if (decoded.amountBig > HALF_UINT256) {
      findings.push(finding('unlimited_approval', 'WARN', 'Approval amount exceeds 2^255 and is effectively unlimited for spender ' + decoded.args.spender + '.', { spender: decoded.args.spender, amount: decoded.args.amount, effectivelyUnlimited: true }));
    }
  }

  if (decoded.kind === 'approvalForAll' && decoded.args.approved) {
    findings.push(finding('set_approval_for_all', 'DENY', 'setApprovalForAll(true) grants operator ' + decoded.args.operator + ' control over EVERY token of this collection, now and in the future.', { operator: decoded.args.operator }));
  }

  if (decoded.kind === 'unknown') {
    findings.push(finding('unknown_selector', 'WARN', 'Function selector ' + decoded.selector + ' is not recognised; the effect of this call cannot be determined.', { selector: decoded.selector }));
  }
  if (decoded.kind === 'malformed') {
    findings.push(finding('unknown_selector', 'WARN', 'Calldata for ' + decoded.function + ' could not be decoded: ' + decoded.decodeError, { selector: decoded.selector }));
  }

  // ---------- On-chain rules ----------
  const needsChain = [];
  if (tx.data !== '0x') needsChain.push({ role: 'target', address: tx.to });
  if (decoded.kind === 'native' && tx.value > 0n && !isBurn(tx.to)) needsChain.push({ role: 'recipient', address: tx.to });
  if (decoded.kind === 'transfer' && decoded.args.recipient && !isBurn(decoded.args.recipient)) {
    needsChain.push({ role: 'recipient', address: decoded.args.recipient });
  }
  if (decoded.kind === 'approve' && !isBurn(decoded.args.spender)) needsChain.push({ role: 'spender', address: decoded.args.spender });
  if (decoded.kind === 'approvalForAll' && decoded.args.approved && !isBurn(decoded.args.operator)) {
    needsChain.push({ role: 'spender', address: decoded.args.operator });
  }

  if (needsChain.length > 0) {
    let reader = deps.reader;
    try {
      if (!reader) reader = createChainReader(tx.chainId);
      const unique = Array.from(new Map(needsChain.map((n) => [n.address.toLowerCase(), n.address])).values());
      const states = await Promise.all(unique.map((a) => reader.addressState(a)));
      const byAddr = new Map(states.map((s) => [s.address.toLowerCase(), s]));
      rpc.endpoint = reader.endpoint || null;

      for (const item of needsChain) {
        const state = byAddr.get(item.address.toLowerCase());
        addressChecks[item.role] = Object.assign({}, state, { role: item.role });
        if (item.role === 'target' && !state.isContract) {
          findings.push(finding('calldata_to_eoa', 'WARN', 'Target ' + item.address + ' has no contract code, yet calldata is attached. The call will do nothing on-chain except transfer value; this usually means a wrong address.', { address: item.address }));
        }
        if (item.role === 'spender' && !state.isContract) {
          findings.push(finding('approval_to_eoa', 'DENY', 'Approval granted to ' + item.address + ', which is an externally owned wallet, not a contract. Legitimate protocols never require approving a plain wallet; this pattern is used to drain tokens.', { address: item.address }));
        }
        if (item.role === 'recipient' && !state.isContract && state.txCount === 0 && BigInt(state.balance) === 0n) {
          findings.push(finding('fresh_recipient', 'WARN', 'Recipient ' + item.address + ' has no transaction history and zero balance. Double-check the address; typos and address-poisoning attacks look exactly like this.', { address: item.address }));
        }
      }
    } catch (err) {
      rpc.ok = false;
      rpc.error = err instanceof RpcError ? err.message : 'Unexpected RPC failure: ' + err.message;
      findings.push(finding('rpc_unavailable', 'WARN', 'On-chain checks could not be completed (' + rpc.error + '). Fail-safe: contract-code and address-history checks were skipped, so the verdict is downgraded to WARN.', { attemptedChecks: needsChain.map((n) => n.role) }));
    }
  }

  // ---------- Verdict ----------
  let verdict = 'ALLOW';
  for (const f of findings) if (SEVERITY[f.severity] > SEVERITY[verdict]) verdict = f.severity;

  const reasons = Array.from(new Set(findings.map((f) => f.code)));
  return {
    verdict,
    reasons,
    details: {
      chainId: tx.chainId,
      to: tx.to,
      value: tx.value.toString(),
      selector: decoded.selector,
      function: decoded.function,
      callType: decoded.kind,
      decoded: decoded.args,
      findings,
      addressChecks,
      rpc,
      analyzedAt: new Date().toISOString(),
    },
  };
}

module.exports = {
  analyze,
  normalizeInput,
  decodeCalldata,
  ValidationError,
  RULES: ['unlimited_approval', 'set_approval_for_all', 'approval_to_eoa', 'fresh_recipient', 'zero_address', 'unknown_selector', 'calldata_to_eoa', 'rpc_unavailable'],
};
