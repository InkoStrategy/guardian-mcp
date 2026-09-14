'use strict';

const { AbiCoder, getAddress, isAddress, isHexString, dataSlice, MaxUint256, ZeroAddress } = require('ethers');
const { createChainReader, RpcError, supportedChainIds, chainName } = require('./rpc');
const contextAnalyzer = require('./context-analyzer');
const registry = require('./registry');
const intel = require('./intel');
const nested = require('./nested');
const summaryBuilder = require('./summary');
const pipeline = require('./pipeline');
const threatRegistry = require('./threat-registry');
const sessionHealth = require('./session-health');
const diff = require('./diff');
const assetFlow = require('./asset-flow');

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
  '0x472b43f3': 'swapExactTokensForTokens(uint256,uint256,address[],address)',
  '0x42712a67': 'swapTokensForExactTokens(uint256,uint256,address[],address)',
  '0x414bf389': 'exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))',
  '0xc04b8d59': 'exactInput((bytes,address,uint256,uint256,uint256))',
  '0x04e45aaf': 'exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))',
  '0xb858183f': 'exactInput((bytes,address,uint256,uint256))',
  '0xdf2ab5bb': 'sweepToken(address,uint256,address)',
  '0x49404b7c': 'unwrapWETH9(uint256,address)',
  '0x12210e8a': 'refundETH()',
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
const BURN_ADDRESSES = new Set([ZeroAddress.toLowerCase(), '0x000000000000000000000000000000000000dead']);

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
  const { to, data, chainId, value, context, from } = input;
  let validatedContext = null;
  try {
    validatedContext = contextAnalyzer.validateContext(context);
  } catch (err) {
    throw new ValidationError(err.message);
  }
  if (typeof to !== 'string' || !isAddress(to)) {
    throw new ValidationError('"to" must be a valid 0x-prefixed EVM address (40 hex chars)');
  }
  let fromAddr = null;
  if (from !== undefined && from !== null && from !== '') {
    if (typeof from !== 'string' || !isAddress(from)) throw new ValidationError('"from" must be a valid 0x-prefixed EVM address');
    fromAddr = getAddress(from);
  }
  let calldata = data === undefined || data === null ? '0x' : data;
  if (typeof calldata !== 'string') throw new ValidationError('"data" must be a hex string');
  calldata = calldata.trim();
  if (calldata === '') calldata = '0x';
  if (!calldata.startsWith('0x')) calldata = '0x' + calldata;
  if (!isHexString(calldata)) throw new ValidationError('"data" must be a 0x-prefixed hex string with an even number of hex characters');
  if (calldata.length > 2 && calldata.length < 10) throw new ValidationError('"data" is shorter than a 4-byte function selector');
  if (calldata.length > 2 + 2 * 128 * 1024) throw new ValidationError('"data" exceeds 128 KB');
  return {
    to: getAddress(to),
    from: fromAddr,
    data: calldata.toLowerCase(),
    chainId: parseChainId(chainId),
    value: parseValue(value),
    context: validatedContext,
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
  return BURN_ADDRESSES.has(String(address).toLowerCase());
}

/** Risk-score weights. Verdict is still the max severity; the score is an additive signal for ranking/alerting. */
const RISK_WEIGHTS = { WARN: 15, DENY: 40 };
const RISK_BONUS = { intent_mismatch: 20, injection_pattern: 50 };

/**
 * Additive risk score in [0, 100].
 * ALLOW-level findings add 0, every WARN adds 15, every DENY adds 40,
 * intent_mismatch adds a further 20 and injection_pattern a further 50. Capped at 100.
 */
function computeRiskScore(findings) {
  let score = 0;
  for (const f of findings || []) {
    score += RISK_WEIGHTS[f.severity] || 0;
    score += RISK_BONUS[f.code] || 0;
  }
  return Math.min(100, Math.max(0, score));
}

// ---------------------------------------------------------------------------
// Static (offline) rules, applied to the top-level call and to every inner call
// ---------------------------------------------------------------------------

function applyStaticRules(decoded, tx, findings, via) {
  const tag = via ? { via } : {};
  if (decoded.kind === 'transfer' && decoded.args.recipient && isBurn(decoded.args.recipient)) {
    findings.push(finding('zero_address', 'DENY', 'Transfer recipient ' + decoded.args.recipient + ' is a burn address; tokens will be lost.', Object.assign({ address: decoded.args.recipient }, tag)));
  }
  if (decoded.kind === 'approve' && isBurn(decoded.args.spender)) {
    findings.push(finding('zero_address', 'DENY', 'Approval spender ' + decoded.args.spender + ' is the zero address.', Object.assign({ address: decoded.args.spender }, tag)));
  }
  if (decoded.kind === 'approvalForAll' && isBurn(decoded.args.operator)) {
    findings.push(finding('zero_address', 'DENY', 'setApprovalForAll operator ' + decoded.args.operator + ' is the zero address.', Object.assign({ address: decoded.args.operator }, tag)));
  }
  if (decoded.kind === 'approve' && decoded.amountBig !== null) {
    if (decoded.amountBig === MAX_UINT256) {
      findings.push(finding('unlimited_approval', 'WARN', 'Approval amount is MAX_UINT256 (unlimited). Spender ' + decoded.args.spender + ' could move your entire balance of this token at any time.', Object.assign({ spender: decoded.args.spender, amount: decoded.args.amount }, tag)));
    } else if (decoded.amountBig > HALF_UINT256) {
      findings.push(finding('unlimited_approval', 'WARN', 'Approval amount exceeds 2^255 and is effectively unlimited for spender ' + decoded.args.spender + '.', Object.assign({ spender: decoded.args.spender, amount: decoded.args.amount, effectivelyUnlimited: true }, tag)));
    }
  }
  if (decoded.kind === 'approvalForAll' && decoded.args.approved) {
    findings.push(finding('set_approval_for_all', 'DENY', 'setApprovalForAll(true) grants operator ' + decoded.args.operator + ' control over EVERY token of this collection, now and in the future.', Object.assign({ operator: decoded.args.operator }, tag)));
  }
  if (decoded.kind === 'unknown') {
    findings.push(finding('unknown_selector', 'WARN', 'Function selector ' + decoded.selector + ' is not recognised; the effect of this call cannot be determined.', Object.assign({ selector: decoded.selector }, tag)));
  }
  if (decoded.kind === 'malformed') {
    findings.push(finding('unknown_selector', 'WARN', 'Calldata for ' + decoded.function + ' could not be decoded: ' + decoded.decodeError, Object.assign({ selector: decoded.selector }, tag)));
  }
}

/** Which addresses need on-chain state, and in which role. */
function collectRoles(decoded, tx, via) {
  const roles = [];
  if (decoded.kind === 'transfer' && decoded.args.recipient && !isBurn(decoded.args.recipient)) roles.push({ role: 'recipient', address: decoded.args.recipient, via });
  if (decoded.kind === 'approve' && decoded.args.spender && !isBurn(decoded.args.spender)) roles.push({ role: 'spender', address: decoded.args.spender, via });
  if (decoded.kind === 'approvalForAll' && decoded.args.approved && !isBurn(decoded.args.operator)) roles.push({ role: 'spender', address: decoded.args.operator, via });
  return roles;
}

/** Address-poisoning and registry look-alike checks (offline). */
function applyLookalikeRules(items, tx, findings) {
  const known = (tx.context && tx.context.known_addresses) || [];
  const knownSet = new Set(known.map((k) => k.toLowerCase()));
  const seen = new Set();
  for (const item of items) {
    const a = String(item.address).toLowerCase();
    const key = item.role + ':' + a;
    if (seen.has(key)) continue;
    seen.add(key);
    if (knownSet.has(a)) continue;
    const imitated = known.find((k) => registry.isLookalike(a, k));
    if (imitated) {
      findings.push(finding('address_poisoning', 'DENY', item.role + ' ' + item.address + ' shares the visible prefix and suffix of your known address ' + imitated + ' but is a different address. This is the address-poisoning attack pattern.', { role: item.role, address: item.address, imitates: imitated, via: item.via || null }));
      continue;
    }
    const reg = registry.findRegistryLookalike(tx.chainId, a);
    if (reg) {
      findings.push(finding('contract_lookalike', 'DENY', item.role + ' ' + item.address + ' imitates ' + reg.name + ' (' + reg.address + ') but is a different address.', { role: item.role, address: item.address, imitates: reg.address, imitatesName: reg.name, via: item.via || null }));
    }
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

/**
 * Analyse a transaction request.
 * @param {{to:string,data?:string,chainId?:number|string,value?:string|number,from?:string,context?:object}} input
 * @param {{reader?: object, env?: object, sessionStore?: object, now?: number}} [deps]
 */
async function analyze(input, deps) {
  deps = deps || {};
  const tx = normalizeInput(input);
  const decoded = decodeCalldata(tx.data);
  const findings = [];
  const addressChecks = {};
  const addressInfo = {};
  const rpc = { ok: true, endpoint: null, error: null };
  const enrichment = { ran: false, skipped: null, errors: [] };

  // ---------- Static rules ----------
  if (isBurn(tx.to)) {
    findings.push(finding('zero_address', 'DENY', 'Transaction target ' + tx.to + ' is a burn address; anything sent there is unrecoverable.', { address: tx.to }));
  }
  applyStaticRules(decoded, tx, findings, null);

  // ---------- Nested calls (multicall / Universal Router / router helpers) ----------
  let nestedInfo = null;
  const innerDecoded = [];
  if (decoded.kind === 'known') {
    nestedInfo = nested.decodeNested(tx.to, tx.data);
    for (const inner of nestedInfo.inner) {
      const d = decodeCalldata(inner.data);
      inner.function = d.function;
      inner.kind = d.kind;
      inner.args = d.args;
      innerDecoded.push({ decoded: d, via: inner.via });
      if (d.kind !== 'unknown' && d.kind !== 'known' && d.kind !== 'native') applyStaticRules(d, tx, findings, inner.via);
    }
    for (const r of nestedInfo.recipients) {
      r.thirdParty = !nested.isSelfRecipient(r.address, { to: tx.to, from: tx.from });
    }
    for (const p of nestedInfo.permits) {
      if (p.spender && p.spender.toLowerCase() !== tx.to.toLowerCase()) {
        findings.push(finding('permit_spender_mismatch', 'DENY', 'Embedded Permit2 permit grants allowance to ' + p.spender + ', not to the router being called (' + tx.to + ').', { spender: p.spender, token: p.token, via: p.via }));
      }
      if (p.unlimited) {
        findings.push(finding('unlimited_approval', 'WARN', 'Embedded Permit2 permit grants an unlimited allowance for ' + (p.token || 'a token') + ' to ' + p.spender + '.', { spender: p.spender, token: p.token, via: p.via, permit2: true }));
      }
    }
    const thirdParty = nestedInfo.recipients.filter((r) => r.thirdParty);
    for (const r of thirdParty) {
      if (r.action === 'permit2_transfer') {
        findings.push(finding('permit2_pull_to_third_party', 'DENY', 'The router pulls your tokens via Permit2 and sends ' + (r.amount || 'them') + ' straight to ' + r.address + '.', { recipient: r.address, token: r.token, via: r.via }));
      } else if (r.action === 'pay_portion' && Number.isInteger(r.bips) && r.bips <= 100) {
        r.feeLike = true; // <= 1% fee to an aggregator collector is routine
      } else {
        findings.push(finding('router_output_to_third_party', 'WARN', 'Router step ' + r.via.split(' > ').pop() + ' sends its output to ' + r.address + ', which is neither you nor the router.', { recipient: r.address, action: r.action, token: r.token, amount: r.amount, bips: r.bips, via: r.via }));
      }
    }
  }

  // ---------- Address roles ----------
  const needsChain = [];
  if (tx.data !== '0x') needsChain.push({ role: 'target', address: tx.to, via: null });
  if (decoded.kind === 'native' && tx.value > 0n && !isBurn(tx.to)) needsChain.push({ role: 'recipient', address: tx.to, via: null });
  for (const r of collectRoles(decoded, tx, null)) needsChain.push(r);
  for (const inner of innerDecoded) for (const r of collectRoles(inner.decoded, tx, inner.via)) needsChain.push(r);
  if (nestedInfo) {
    for (const r of nestedInfo.recipients) if (r.thirdParty && !r.feeLike && !isBurn(r.address)) needsChain.push({ role: 'recipient', address: r.address, via: r.via });
    for (const p of nestedInfo.permits) if (p.spender && !isBurn(p.spender)) needsChain.push({ role: 'spender', address: p.spender, via: p.via });
  }

  applyLookalikeRules(needsChain.filter((n) => n.role !== 'target').concat(decoded.kind === 'known' || decoded.kind === 'unknown' ? [{ role: 'target', address: tx.to }] : []), tx, findings);

  // ---------- On-chain rules ----------
  let reader = deps.reader;
  let states = new Map();
  if (needsChain.length > 0) {
    try {
      if (!reader) reader = createChainReader(tx.chainId);
      const unique = Array.from(new Map(needsChain.map((n) => [n.address.toLowerCase(), n.address])).values());
      const list = await Promise.all(unique.map((a) => reader.addressState(a)));
      states = new Map(list.map((s) => [s.address.toLowerCase(), s]));
      rpc.endpoint = reader.endpoint || null;

      const done = new Set();
      for (const item of needsChain) {
        const state = states.get(item.address.toLowerCase());
        const key = item.role + ':' + item.address.toLowerCase();
        const label = item.via ? item.role + '@' + item.via.split(' > ').pop() : item.role;
        if (!addressChecks[label]) addressChecks[label] = { address: state.address, isContract: state.isContract, txCount: state.txCount, balance: state.balance, codeSize: state.codeSize, role: item.role, via: item.via || null };
        if (done.has(key)) continue;
        done.add(key);
        const tag = item.via ? { via: item.via } : {};
        if (item.role === 'target' && !state.isContract) {
          findings.push(finding('calldata_to_eoa', 'WARN', 'Target ' + item.address + ' has no contract code, yet calldata is attached. The call will do nothing on-chain except transfer value; this usually means a wrong address.', { address: item.address }));
        }
        if (item.role === 'spender' && !state.isContract) {
          findings.push(finding('approval_to_eoa', 'DENY', 'Approval granted to ' + item.address + ', which is an externally owned wallet, not a contract. Legitimate protocols never require approving a plain wallet; this pattern is used to drain tokens.', Object.assign({ address: item.address }, tag)));
        }
        if (item.role === 'recipient' && !state.isContract && state.txCount === 0 && BigInt(state.balance) === 0n) {
          findings.push(finding('fresh_recipient', 'WARN', 'Recipient ' + item.address + ' has no transaction history and zero balance. Double-check the address; typos and address-poisoning attacks look exactly like this.', Object.assign({ address: item.address }, tag)));
        }
      }
    } catch (err) {
      rpc.ok = false;
      rpc.error = err instanceof RpcError ? err.message : 'Unexpected RPC failure: ' + err.message;
      findings.push(finding('rpc_unavailable', 'WARN', 'On-chain checks could not be completed (' + rpc.error + '). Fail-safe: contract-code and address-history checks were skipped, so the verdict is downgraded to WARN.', { attemptedChecks: needsChain.map((n) => n.role) }));
    }
  }

  // ---------- Enrichment: token metadata, counterparty intelligence, simulation ----------
  let tokenMeta = null;
  let simulation = { ran: false, reason: tx.from ? null : 'no "from" supplied' };
  let flow = { ran: false, supported: null, error: tx.from ? null : 'no "from" supplied', transfers: [], sender_net: [], recipients: [] };
  let erc20State = null;
  if (rpc.ok && reader && intel.canCall(reader)) {
    enrichment.ran = true;
    const isTokenCall = decoded.kind === 'approve' || decoded.kind === 'transfer' || decoded.kind === 'approvalForAll';
    const jobs = [];
    if (isTokenCall) {
      jobs.push(intel.getTokenMeta(reader, tx.chainId, tx.to).then((m) => { tokenMeta = m; }).catch((e) => enrichment.errors.push('tokenMeta: ' + e.message)));
    } else {
      tokenMeta = registry.lookupToken(tx.chainId, tx.to);
    }
    for (const [addrLower, state] of states) {
      jobs.push(intel.inspectContract(reader, tx.chainId, state.address, state).then((info) => {
        info.fresh = !state.isContract && state.txCount === 0 && BigInt(state.balance) === 0n;
        addressInfo[addrLower] = info;
      }).catch((e) => enrichment.errors.push('inspect ' + addrLower + ': ' + e.message)));
    }
    if (tx.from) {
      jobs.push(assetFlow.simulateFlow(reader, { from: tx.from, to: tx.to, data: tx.data, value: tx.value }).then((f) => { flow = f; }).catch((e) => {
        flow = { ran: false, supported: null, error: e.message, transfers: [], sender_net: [], recipients: [] };
        enrichment.errors.push('assetFlow: ' + e.message);
      }));
      jobs.push(intel.simulate(reader, { from: tx.from, to: tx.to, data: tx.data, value: tx.value }).then((s) => { simulation = s; }).catch((e) => {
        simulation = { ran: false, reason: e.message };
        enrichment.errors.push('simulate: ' + e.message);
        findings.push(finding('simulation_unavailable', 'WARN', 'Simulation was requested (from supplied) but the RPC did not answer: ' + e.message, {}));
      }));
      if (decoded.kind === 'transfer' || decoded.kind === 'approve') {
        jobs.push(intel.readErc20State(reader, tx.to, tx.from, decoded.kind === 'approve' ? decoded.args.spender : null).then((s) => { erc20State = s; }).catch((e) => enrichment.errors.push('erc20State: ' + e.message)));
      }
    }
    await Promise.all(jobs);
  } else {
    enrichment.skipped = !reader ? 'no reader' : !intel.canCall(reader) ? 'reader does not support eth_call' : 'rpc unavailable';
    for (const [addrLower, state] of states) {
      addressInfo[addrLower] = { address: state.address, known: registry.lookupContract(tx.chainId, state.address), isContract: state.isContract, codeSize: state.codeSize, proxy: null, tiny: false, fresh: !state.isContract && state.txCount === 0 && BigInt(state.balance) === 0n, lookalikeOf: null };
    }
    if (decoded.kind === 'approve' || decoded.kind === 'transfer' || decoded.kind === 'approvalForAll') tokenMeta = registry.lookupToken(tx.chainId, tx.to);
  }
  for (const [addrLower, state] of states) {
    if (!addressInfo[addrLower]) addressInfo[addrLower] = { address: state.address, known: registry.lookupContract(tx.chainId, state.address), isContract: state.isContract, codeSize: state.codeSize, proxy: null, tiny: false, fresh: false, lookalikeOf: null };
  }

  // ---------- Rules that depend on enrichment ----------
  const spenderItems = needsChain.filter((n) => n.role === 'spender');
  const unlimitedSpenders = new Set(findings.filter((f) => f.code === 'unlimited_approval' && f.spender).map((f) => f.spender.toLowerCase()));
  for (const item of spenderItems) {
    const info = addressInfo[item.address.toLowerCase()];
    if (!info || !info.isContract) continue;
    if (unlimitedSpenders.has(item.address.toLowerCase()) && !info.known) {
      findings.push(finding('unknown_spender', 'WARN', 'Unlimited allowance to ' + item.address + ', which is a contract but not a recognised protocol' + (info.proxy && info.proxy.type.includes('upgradeable') ? ' and is an upgradeable proxy whose logic can change after you approve' : '') + (info.tiny ? ' and has only ' + info.codeSize + ' bytes of code' : '') + '.', { address: item.address, proxy: info.proxy, codeSize: info.codeSize, via: item.via || null }));
    }
  }
  if (simulation.ran && simulation.reverted) {
    findings.push(finding('simulation_reverted', 'WARN', 'eth_call from ' + tx.from + ' reverts: ' + simulation.revert.reason + '. The transaction would fail and burn gas.', { reason: simulation.revert.reason, selector: simulation.revert.selector, kind: simulation.revert.kind }));
  }
  if (erc20State && decoded.kind === 'transfer' && decoded.amountBig !== null && erc20State.balance !== null && BigInt(erc20State.balance) < decoded.amountBig) {
    findings.push(finding('insufficient_balance', 'WARN', 'Sender balance ' + intel.formatAmount(erc20State.balance, tokenMeta) + ' is below the transfer amount ' + intel.formatAmount(decoded.amountBig, tokenMeta) + '.', { balance: erc20State.balance, amount: decoded.args.amount }));
  }

  // ---------- Asset flow: who ends up holding the value ----------
  const flowRecipients = [];
  if (flow.ran && !flow.reverted && flow.recipients.length && reader) {
    const candidates = flow.recipients.filter((r) => r.address.toLowerCase() !== tx.from.toLowerCase()).slice(0, 6);
    await Promise.all(candidates.map(async (r) => {
      const lower = r.address.toLowerCase();
      let state = states.get(lower) || null;
      if (!state) {
        try {
          state = await reader.addressState(r.address);
        } catch (e) {
          enrichment.errors.push('flow recipient state ' + lower + ': ' + e.message);
        }
      }
      const known = registry.lookupContract(tx.chainId, r.address) || registry.lookupToken(tx.chainId, r.address);
      flowRecipients.push({ address: r.address, gains: r.gains, isContract: state ? state.isContract : null, known: known ? { name: known.name || known.symbol, category: known.category || 'token' } : null, lookalikeOf: registry.findRegistryLookalike(tx.chainId, r.address) });
    }));
    const senderGivesOnly = flow.sender_net.length > 0 && flow.sender_net.every((n) => BigInt(n.delta) < 0n);
    const isCall = decoded.kind === 'unknown' || decoded.kind === 'known' || decoded.kind === 'malformed';
    const eoaSinks = flowRecipients.filter((r) => r.isContract === false && !r.known);
    if (isCall && senderGivesOnly && eoaSinks.length) {
      findings.push(finding('funds_flow_no_return', 'WARN', 'Simulation shows the sender giving ' + flow.sender_net.map((n) => intel.formatAmount(-BigInt(n.delta), n.asset === 'ETH' ? { decimals: 18, symbol: registry.nativeSymbol(tx.chainId) } : registry.lookupToken(tx.chainId, n.asset))).join(', ') + ' and receiving nothing back; the value ends at plain wallet(s) ' + eoaSinks.map((r) => r.address).join(', ') + ' behind an unrecognised call.', { recipients: eoaSinks.map((r) => r.address), sender_net: flow.sender_net }));
    }
    for (const r of flowRecipients) {
      if (r.lookalikeOf) findings.push(finding('funds_flow_to_flagged', 'DENY', 'Simulation shows value ending at ' + r.address + ', which imitates ' + r.lookalikeOf.name + ' (' + r.lookalikeOf.address + ').', { address: r.address, imitates: r.lookalikeOf.address }));
    }
  }

  // ---------- Shared threat intelligence + reputation ----------
  const threatTargets = needsChain.filter((n) => n.role !== 'target').map((n) => ({ role: n.role, address: n.address }));
  if (decoded.kind !== 'native' && decoded.kind !== 'approve' && decoded.kind !== 'transfer' && decoded.kind !== 'approvalForAll') threatTargets.push({ role: 'target', address: tx.to });
  for (const r of flowRecipients) if (!r.known) threatTargets.push({ role: 'flow_recipient', address: r.address });
  const sourceDomains = [];
  for (const s of (tx.context && tx.context.recent_sources) || []) {
    const parsed = contextAnalyzer.extractDomain(s);
    if (parsed && parsed.domain && parsed.kind === 'url') sourceDomains.push(parsed.domain);
  }
  const threatIntel = await pipeline.threatLookup({ store: deps.store, env: deps.env, chainId: tx.chainId, addresses: threatTargets, domains: sourceDomains });
  for (const f of threatIntel.findings) findings.push(f);
  for (const r of flowRecipients) {
    const lower = r.address.toLowerCase();
    const hit = threatIntel.findings.find((f) => f.address === lower && ['scam_database_address', 'known_drainer', 'flagged_address'].includes(f.code));
    if (hit && !findings.some((f) => f.code === 'funds_flow_to_flagged' && f.address === r.address)) {
      findings.push(finding('funds_flow_to_flagged', hit.severity === 'WARN' ? 'WARN' : 'DENY', 'Simulation shows value ending at ' + r.address + ' (' + hit.code + '), even though the transaction does not name that address directly.', { address: r.address, via: hit.code, gains: r.gains }));
    }
  }
  for (const [addrLower, info] of Object.entries(addressInfo)) {
    const state = states.get(addrLower);
    if (!state) continue;
    info.reputation = threatRegistry.reputation({ state, known: info.known, threat: threatIntel.intel.addresses[addrLower] || null, proxy: info.proxy, chainId: tx.chainId });
  }

  // ---------- Differential check against a trusted template ----------
  let diffResult = null;
  if (tx.context && tx.context.reference_tx) {
    try {
      const ref = tx.context.reference_tx;
      const refData = (ref.data || '0x').toLowerCase();
      const refDecoded = decodeCalldata(refData);
      let refNested = null;
      if (refDecoded.kind === 'known') {
        refNested = nested.decodeNested(getAddress(ref.to), refData);
        for (const inner of refNested.inner) inner.kind = decodeCalldata(inner.data).kind, inner.args = decodeCalldata(inner.data).args;
        for (const r of refNested.recipients) r.thirdParty = !nested.isSelfRecipient(r.address, { to: getAddress(ref.to), from: tx.from });
      }
      diffResult = diff.compare(
        { to: getAddress(ref.to), chainId: ref.chainId === undefined ? tx.chainId : parseChainId(ref.chainId), value: parseValue(ref.value), decoded: refDecoded, nested: refNested },
        { to: tx.to, chainId: tx.chainId, value: tx.value, decoded, nested: nestedInfo },
      );
      const df = diff.toFinding(diffResult);
      if (df) findings.push(df);
    } catch (err) {
      diffResult = { error: err.message };
      findings.push(finding('template_deviation', 'WARN', 'The reference template could not be compared (' + err.message + '); treat the deviation check as failed.', { layer: 'differential' }));
    }
  }

  // ---------- Agent-integrity layer (intent / context / runtime) ----------
  const contextAnalyzed = tx.context !== null;
  let intentAnalysis = null;
  let contextSignals = [];
  let contextFindings = [];
  let contextSources = null;
  if (contextAnalyzed) {
    try {
      const ctx = contextAnalyzer.analyzeContext(tx.context, decoded, tx.value, { env: deps.env, sessionStore: deps.sessionStore, now: deps.now });
      contextFindings = ctx.findings;
      intentAnalysis = ctx.intent_analysis;
      contextSignals = ctx.context_signals;
      contextSources = ctx.sources;
    } catch (err) {
      const failed = finding('context_analysis_failed', 'WARN', 'Context analysis failed unexpectedly (' + (err && err.message ? err.message : String(err)) + '). Fail-safe: verdict is at least WARN.', { layer: 'context' });
      contextFindings = [failed];
      contextSignals = [{ code: failed.code, severity: failed.severity, message: failed.message }];
    }
    for (const f of contextFindings) findings.push(f);
  }

  // ---------- Verdict, session health, threat report, alert ----------
  const chain = chainName(tx.chainId);
  const buildSummary = (verdict) => {
    try {
      let text = summaryBuilder.buildSummary({ verdict, decoded, tx, chainName: chain, tokenMeta, addressInfo, findings, nested: nestedInfo });
      if (flow.ran && !flow.reverted && flow.sender_net.length) {
        const parts = flow.sender_net.map((n) => { const d = BigInt(n.delta); const meta = n.asset === 'ETH' ? { decimals: 18, symbol: registry.nativeSymbol(tx.chainId) } : registry.lookupToken(tx.chainId, n.asset); return (d < 0n ? '-' : '+') + intel.formatAmount(d < 0n ? -d : d, meta); });
        text += ' Simulated value flow for sender: ' + parts.join(', ') + '.';
      }
      return text;
    } catch (err) {
      enrichment.errors.push('summary: ' + err.message);
      return 'Verdict ' + verdict + ': ' + Array.from(new Set(findings.map((f) => f.code))).join(', ');
    }
  };
  const actionText = summaryBuilder.actionText ? summaryBuilder.actionText({ decoded, tx, tokenMeta, addressInfo }) : null;
  const fin = await pipeline.finalize({
    store: deps.store, env: deps.env, now: deps.now, reporter: deps.reporter, sendAlert: deps.sendAlert,
    kind: 'transaction', chainId: tx.chainId, to: tx.to, selector: decoded.selector, context: tx.context,
    findings, computeRiskScore, buildSummary, actionText,
  });
  const { verdict, reasons, summary } = fin;
  const riskScore = fin.risk_score;
  const sessionRiskScore = computeRiskScore(contextFindings);

  let recommendations;
  let safeAlternative;
  try {
    recommendations = summaryBuilder.buildRecommendations(findings);
    safeAlternative = summaryBuilder.buildSafeAlternative({ verdict, decoded, tx, tokenMeta, findings });
  } catch (err) {
    recommendations = [];
    safeAlternative = null;
    enrichment.errors.push('recommendations: ' + err.message);
  }

  const counterparties = {};
  for (const [a, info] of Object.entries(addressInfo)) {
    counterparties[info.address || a] = { known: info.known, isContract: info.isContract, proxy: info.proxy, codeSize: info.codeSize, tiny: info.tiny, fresh: info.fresh, reputation: info.reputation || null, threat: threatIntel.intel.addresses[a] || null };
  }

  return {
    verdict,
    reasons,
    summary,
    details: {
      chainId: tx.chainId,
      chain,
      to: tx.to,
      from: tx.from,
      value: tx.value.toString(),
      selector: decoded.selector,
      function: decoded.function,
      callType: decoded.kind,
      decoded: decoded.args,
      amount: decoded.amountBig !== null ? intel.formatAmount(decoded.amountBig, tokenMeta) : decoded.kind === 'native' ? intel.formatAmount(tx.value, { decimals: 18, symbol: registry.nativeSymbol(tx.chainId) }) : null,
      token: tokenMeta,
      counterparties,
      nested_calls: nestedInfo ? { inner: nestedInfo.inner.map((i) => ({ via: i.via, selector: i.selector, function: i.function, kind: i.kind, args: i.args })), recipients: nestedInfo.recipients, permits: nestedInfo.permits, routerPlan: nestedInfo.routerPlan, truncated: nestedInfo.truncated } : null,
      simulation,
      asset_flow: Object.assign({}, flow, { final_recipients: flowRecipients }),
      erc20State,
      findings,
      addressChecks,
      rpc,
      enrichment,
      risk_score: riskScore,
      recommendations,
      safe_alternative: safeAlternative,
      request_id: fin.request_id,
      threat_intel: { backend: threatIntel.intel.backend, persistent: threatIntel.intel.persistent, error: threatIntel.error, addresses: threatIntel.intel.addresses, domains: threatIntel.intel.domains, seed: threatIntel.intel.seed, report: fin.threat_report },
      session_health: fin.session_health,
      alert: fin.alert,
      shared_state: fin.shared_state,
      diff: diffResult,
      context_analyzed: contextAnalyzed,
      intent_analysis: intentAnalysis,
      context_signals: contextSignals,
      context_sources: contextSources,
      session_risk_score: sessionRiskScore,
      analyzedAt: new Date().toISOString(),
    },
  };
}

/** Catalogue of every rule with severity and description (served by GET /rules). */
const RULE_CATALOG = [
  { code: 'zero_address', severity: 'DENY', layer: 'transaction', description: 'Target, transfer recipient, spender or operator is the zero address or 0x...dEaD.' },
  { code: 'set_approval_for_all', severity: 'DENY', layer: 'transaction', description: 'setApprovalForAll(operator, true): full control over every token of the collection.' },
  { code: 'approval_to_eoa', severity: 'DENY', layer: 'transaction', description: 'approve / increaseAllowance / permit / setApprovalForAll to an address without contract code (a plain wallet).' },
  { code: 'address_poisoning', severity: 'DENY', layer: 'transaction', description: 'Recipient or spender shares the visible prefix and suffix of an address in context.known_addresses but is a different address.' },
  { code: 'contract_lookalike', severity: 'DENY', layer: 'transaction', description: 'Address imitates a well-known contract or token from the built-in registry (same 4+4 hex characters, different address).' },
  { code: 'permit_spender_mismatch', severity: 'DENY', layer: 'transaction', description: 'A Permit2 permit embedded in a Universal Router call grants allowance to a contract other than the router.' },
  { code: 'permit2_pull_to_third_party', severity: 'DENY', layer: 'transaction', description: 'A Universal Router PERMIT2_TRANSFER_FROM sends your tokens to an address that is neither you nor the router.' },
  { code: 'unlimited_approval', severity: 'WARN', layer: 'transaction', description: 'Approval amount is MAX_UINT256 or above 2^255 (effectively unlimited), including Permit2 permits embedded in router calls.' },
  { code: 'unknown_spender', severity: 'WARN', layer: 'transaction', description: 'Unlimited allowance to a contract that is not in the known-protocol registry; notes upgradeable proxies and tiny contracts.' },
  { code: 'router_output_to_third_party', severity: 'WARN', layer: 'transaction', description: 'A swap, sweep, unwrap or transfer step inside a router call sends output to an address that is neither you nor the router.' },
  { code: 'fresh_recipient', severity: 'WARN', layer: 'transaction', description: 'Recipient of an ERC-20/721/1155 or native transfer has nonce 0, zero balance and no code.' },
  { code: 'unknown_selector', severity: 'WARN', layer: 'transaction', description: 'Function selector is not recognised or calldata cannot be decoded.' },
  { code: 'calldata_to_eoa', severity: 'WARN', layer: 'transaction', description: 'Calldata is attached but the target has no contract code.' },
  { code: 'simulation_reverted', severity: 'WARN', layer: 'simulation', description: 'eth_call from the supplied "from" reverts; the decoded revert reason is included.' },
  { code: 'simulation_unavailable', severity: 'WARN', layer: 'simulation', description: 'Simulation was requested ("from" supplied) but the RPC failed.' },
  { code: 'insufficient_balance', severity: 'WARN', layer: 'simulation', description: 'ERC-20 balance of "from" is below the transfer amount.' },
  { code: 'rpc_unavailable', severity: 'WARN', layer: 'transaction', description: 'On-chain checks could not run. Fail-safe: never ALLOW.' },
].concat(assetFlow.FLOW_RULES, contextAnalyzer.CONTEXT_RULES, threatRegistry.THREAT_RULES.filter((r) => r.code !== 'threat_intel_unavailable'), sessionHealth.SESSION_RULES, diff.DIFF_RULES, pipeline.PIPELINE_RULES);

module.exports = {
  analyze,
  normalizeInput,
  decodeCalldata,
  computeRiskScore,
  ValidationError,
  RULES: RULE_CATALOG.map((r) => r.code),
  RULE_CATALOG,
};
