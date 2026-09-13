'use strict';

/**
 * Nested-call decoding: multicall wrappers, Uniswap Universal Router command
 * plans and SwapRouter-style helper functions. The goal is to see *where the
 * money goes* inside a call that looks like a routine swap.
 */

const { AbiCoder, dataSlice, getAddress, ZeroAddress } = require('ethers');

const abi = AbiCoder.defaultAbiCoder();

const MAX_DEPTH = 3;
const MAX_INNER_CALLS = 64;
const UINT160_MAX = 2n ** 160n - 1n;

const MSG_SENDER = '0x0000000000000000000000000000000000000001';
const ADDRESS_THIS = '0x0000000000000000000000000000000000000002';

const MULTICALL = {
  '0xac9650d8': { name: 'multicall(bytes[])', types: ['bytes[]'], calls: 0 },
  '0x5ae401dc': { name: 'multicall(uint256,bytes[])', types: ['uint256', 'bytes[]'], calls: 1 },
  '0x1f0464d1': { name: 'multicall(bytes32,bytes[])', types: ['bytes32', 'bytes[]'], calls: 1 },
};

const UNIVERSAL_EXECUTE = {
  '0x3593564c': { name: 'execute(bytes,bytes[],uint256)', types: ['bytes', 'bytes[]', 'uint256'] },
  '0x24856bc3': { name: 'execute(bytes,bytes[])', types: ['bytes', 'bytes[]'] },
};

/** Functions whose output recipient is an explicit argument. */
const RECIPIENT_FUNCTIONS = {
  '0xdf2ab5bb': { name: 'sweepToken(address,uint256,address)', types: ['address', 'uint256', 'address'], recipient: 2, token: 0, action: 'sweep' },
  '0x49404b7c': { name: 'unwrapWETH9(uint256,address)', types: ['uint256', 'address'], recipient: 1, action: 'unwrap' },
  '0x04e45aaf': { name: 'exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))', types: ['tuple(address,address,uint24,address,uint256,uint256,uint160)'], tupleRecipient: 3, action: 'swap' },
  '0x414bf389': { name: 'exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))', types: ['tuple(address,address,uint24,address,uint256,uint256,uint256,uint160)'], tupleRecipient: 3, action: 'swap' },
  '0xb858183f': { name: 'exactInput((bytes,address,uint256,uint256))', types: ['tuple(bytes,address,uint256,uint256)'], tupleRecipient: 1, action: 'swap' },
  '0xc04b8d59': { name: 'exactInput((bytes,address,uint256,uint256,uint256))', types: ['tuple(bytes,address,uint256,uint256,uint256)'], tupleRecipient: 1, action: 'swap' },
  '0x38ed1739': { name: 'swapExactTokensForTokens(uint256,uint256,address[],address,uint256)', types: ['uint256', 'uint256', 'address[]', 'address', 'uint256'], recipient: 3, action: 'swap' },
  '0x8803dbee': { name: 'swapTokensForExactTokens(uint256,uint256,address[],address,uint256)', types: ['uint256', 'uint256', 'address[]', 'address', 'uint256'], recipient: 3, action: 'swap' },
  '0x7ff36ab5': { name: 'swapExactETHForTokens(uint256,address[],address,uint256)', types: ['uint256', 'address[]', 'address', 'uint256'], recipient: 2, action: 'swap' },
  '0x18cbafe5': { name: 'swapExactTokensForETH(uint256,uint256,address[],address,uint256)', types: ['uint256', 'uint256', 'address[]', 'address', 'uint256'], recipient: 3, action: 'swap' },
  '0xfb3bdb41': { name: 'swapETHForExactTokens(uint256,address[],address,uint256)', types: ['uint256', 'address[]', 'address', 'uint256'], recipient: 2, action: 'swap' },
  '0x472b43f3': { name: 'swapExactTokensForTokens(uint256,uint256,address[],address)', types: ['uint256', 'uint256', 'address[]', 'address'], recipient: 3, action: 'swap' },
  '0x42712a67': { name: 'swapTokensForExactTokens(uint256,uint256,address[],address)', types: ['uint256', 'uint256', 'address[]', 'address'], recipient: 3, action: 'swap' },
};

const PERMIT_SINGLE = 'tuple(tuple(address,uint160,uint48,uint48),address,uint256)';
const PERMIT_BATCH = 'tuple(tuple(address,uint160,uint48,uint48)[],address,uint256)';

/** Universal Router command catalogue (Commands.sol). */
const UR_COMMANDS = {
  0x00: { name: 'V3_SWAP_EXACT_IN', types: ['address', 'uint256', 'uint256', 'bytes', 'bool'], recipient: 0, action: 'swap' },
  0x01: { name: 'V3_SWAP_EXACT_OUT', types: ['address', 'uint256', 'uint256', 'bytes', 'bool'], recipient: 0, action: 'swap' },
  0x02: { name: 'PERMIT2_TRANSFER_FROM', types: ['address', 'address', 'uint160'], token: 0, recipient: 1, amount: 2, action: 'permit2_transfer' },
  0x03: { name: 'PERMIT2_PERMIT_BATCH', types: [PERMIT_BATCH, 'bytes'], action: 'permit2_permit_batch' },
  0x04: { name: 'SWEEP', types: ['address', 'address', 'uint256'], token: 0, recipient: 1, amount: 2, action: 'sweep' },
  0x05: { name: 'TRANSFER', types: ['address', 'address', 'uint256'], token: 0, recipient: 1, amount: 2, action: 'transfer' },
  0x06: { name: 'PAY_PORTION', types: ['address', 'address', 'uint256'], token: 0, recipient: 1, bips: 2, action: 'pay_portion' },
  0x08: { name: 'V2_SWAP_EXACT_IN', types: ['address', 'uint256', 'uint256', 'address[]', 'bool'], recipient: 0, action: 'swap' },
  0x09: { name: 'V2_SWAP_EXACT_OUT', types: ['address', 'uint256', 'uint256', 'address[]', 'bool'], recipient: 0, action: 'swap' },
  0x0a: { name: 'PERMIT2_PERMIT', types: [PERMIT_SINGLE, 'bytes'], action: 'permit2_permit' },
  0x0b: { name: 'WRAP_ETH', types: ['address', 'uint256'], recipient: 0, action: 'wrap' },
  0x0c: { name: 'UNWRAP_WETH', types: ['address', 'uint256'], recipient: 0, action: 'unwrap' },
  0x0d: { name: 'PERMIT2_TRANSFER_FROM_BATCH', types: ['tuple(address,address,uint160,address)[]'], action: 'permit2_transfer_batch' },
  0x0e: { name: 'BALANCE_CHECK_ERC20', types: ['address', 'address', 'uint256'], action: 'check' },
  0x10: { name: 'V4_SWAP', types: null, action: 'swap' },
  0x11: { name: 'V3_POSITION_MANAGER_PERMIT', types: null, action: 'position' },
  0x12: { name: 'V3_POSITION_MANAGER_CALL', types: null, action: 'position' },
  0x13: { name: 'V4_INITIALIZE_POOL', types: null, action: 'position' },
  0x14: { name: 'V4_POSITION_MANAGER_CALL', types: null, action: 'position' },
  0x21: { name: 'EXECUTE_SUB_PLAN', types: ['bytes', 'bytes[]'], action: 'sub_plan' },
};

function safeDecode(types, data) {
  try {
    return abi.decode(types, data);
  } catch {
    return null;
  }
}

function addr(v) {
  try {
    return getAddress(v);
  } catch {
    return null;
  }
}

/**
 * Walk the calldata and collect inner calls, money-out recipients and permits.
 * @returns {{inner: object[], recipients: object[], permits: object[], routerPlan: object[]|null, truncated: boolean}}
 */
function decodeNested(to, data, opts) {
  opts = opts || {};
  const out = { inner: [], recipients: [], permits: [], routerPlan: null, truncated: false };
  walk(to, data, 0, 'top', out);
  return out;
}

function walk(to, data, depth, via, out) {
  if (depth > MAX_DEPTH || out.inner.length >= MAX_INNER_CALLS) {
    out.truncated = true;
    return;
  }
  if (typeof data !== 'string' || data.length < 10) return;
  const selector = dataSlice(data, 0, 4);
  const body = dataSlice(data, 4);

  if (MULTICALL[selector]) {
    const spec = MULTICALL[selector];
    const dec = safeDecode(spec.types, body);
    if (!dec) return;
    const calls = dec[spec.calls];
    for (const inner of calls) {
      if (out.inner.length >= MAX_INNER_CALLS) {
        out.truncated = true;
        break;
      }
      const innerSel = inner.length >= 10 ? dataSlice(inner, 0, 4) : null;
      out.inner.push({ depth: depth + 1, via: via + ' > ' + spec.name, to, data: inner, selector: innerSel });
      walk(to, inner, depth + 1, via + ' > ' + spec.name, out);
    }
    return;
  }

  if (UNIVERSAL_EXECUTE[selector]) {
    const spec = UNIVERSAL_EXECUTE[selector];
    const dec = safeDecode(spec.types, body);
    if (!dec) return;
    const plan = decodeRouterPlan(dec[0], dec[1], depth + 1, via + ' > ' + spec.name, out);
    if (depth === 0) out.routerPlan = plan;
    return;
  }

  if (RECIPIENT_FUNCTIONS[selector]) {
    const spec = RECIPIENT_FUNCTIONS[selector];
    const dec = safeDecode(spec.types, body);
    if (!dec) return;
    let recipient = null;
    if (spec.tupleRecipient !== undefined) recipient = addr(dec[0][spec.tupleRecipient]);
    else if (spec.recipient !== undefined) recipient = addr(dec[spec.recipient]);
    if (recipient) {
      out.recipients.push({ address: recipient, action: spec.action, via: via + ' > ' + spec.name, token: spec.token !== undefined ? addr(dec[spec.token]) : null, amount: null, depth });
    }
  }
}

function decodeRouterPlan(commands, inputs, depth, via, out) {
  const plan = [];
  const bytes = Buffer.from(commands.slice(2), 'hex');
  for (let i = 0; i < bytes.length && i < inputs.length; i += 1) {
    const raw = bytes[i];
    const type = raw & 0x3f;
    const allowRevert = Boolean(raw & 0x80);
    const spec = UR_COMMANDS[type];
    const step = { index: i, command: spec ? spec.name : 'UNKNOWN_0x' + type.toString(16), allowRevert, action: spec ? spec.action : 'unknown', details: {} };
    if (spec && spec.types) {
      const dec = safeDecode(spec.types, inputs[i]);
      if (dec) {
        if (spec.action === 'sub_plan') {
          step.details.subPlan = decodeRouterPlan(dec[0], dec[1], depth + 1, via + ' > EXECUTE_SUB_PLAN', out);
        } else if (spec.action === 'permit2_permit') {
          const single = dec[0];
          const details = single[0];
          const p = { token: addr(details[0]), amount: BigInt(details[1]).toString(), unlimited: BigInt(details[1]) === UINT160_MAX, expiration: Number(details[2]), spender: addr(single[1]), sigDeadline: BigInt(single[2]).toString(), via: via + ' > PERMIT2_PERMIT' };
          step.details = p;
          out.permits.push(p);
        } else if (spec.action === 'permit2_permit_batch') {
          const batch = dec[0];
          const spender = addr(batch[1]);
          const items = batch[0].map((d) => ({ token: addr(d[0]), amount: BigInt(d[1]).toString(), unlimited: BigInt(d[1]) === UINT160_MAX, expiration: Number(d[2]), spender, sigDeadline: BigInt(batch[2]).toString(), via: via + ' > PERMIT2_PERMIT_BATCH' }));
          step.details = { spender, items };
          for (const it of items) out.permits.push(it);
        } else if (spec.action === 'permit2_transfer_batch') {
          const items = dec[0].map((d) => ({ from: addr(d[0]), recipient: addr(d[1]), amount: BigInt(d[2]).toString(), token: addr(d[3]) }));
          step.details = { items };
          for (const it of items) if (it.recipient) out.recipients.push({ address: it.recipient, action: 'permit2_transfer', via: via + ' > PERMIT2_TRANSFER_FROM_BATCH', token: it.token, amount: it.amount, depth });
        } else {
          if (spec.token !== undefined) step.details.token = addr(dec[spec.token]);
          if (spec.recipient !== undefined) step.details.recipient = addr(dec[spec.recipient]);
          if (spec.amount !== undefined) step.details.amount = BigInt(dec[spec.amount]).toString();
          if (spec.bips !== undefined) step.details.bips = Number(dec[spec.bips]);
          if (step.details.recipient) {
            out.recipients.push({ address: step.details.recipient, action: spec.action, via: via + ' > ' + spec.name, token: step.details.token || null, amount: step.details.amount || null, bips: step.details.bips, depth });
          }
        }
      } else {
        step.decodeError = true;
      }
    }
    plan.push(step);
  }
  return plan;
}

/** Sentinel or self recipients that mean "back to the user / stays in router". */
function isSelfRecipient(address, ctx) {
  const a = String(address).toLowerCase();
  if (a === MSG_SENDER.toLowerCase() || a === ADDRESS_THIS.toLowerCase() || a === ZeroAddress.toLowerCase()) return true;
  if (ctx.to && a === String(ctx.to).toLowerCase()) return true;
  if (ctx.from && a === String(ctx.from).toLowerCase()) return true;
  return false;
}

module.exports = { decodeNested, isSelfRecipient, UR_COMMANDS, MSG_SENDER, ADDRESS_THIS, UINT160_MAX };
