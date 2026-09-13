'use strict';

const { JsonRpcProvider, Network, FetchRequest } = require('ethers');

/**
 * Default public RPC endpoints per chain. Order = fallback order.
 * Override any chain with env RPC_URL_<chainId> (comma-separated list).
 */
const DEFAULT_CHAINS = {
  1: { name: 'ethereum', rpcs: ['https://ethereum-rpc.publicnode.com', 'https://eth.llamarpc.com', 'https://cloudflare-eth.com'] },
  10: { name: 'optimism', rpcs: ['https://optimism-rpc.publicnode.com', 'https://mainnet.optimism.io'] },
  56: { name: 'bsc', rpcs: ['https://bsc-rpc.publicnode.com', 'https://bsc-dataseed.bnbchain.org'] },
  137: { name: 'polygon', rpcs: ['https://polygon-bor-rpc.publicnode.com', 'https://polygon-rpc.com'] },
  196: { name: 'xlayer', rpcs: ['https://rpc.xlayer.tech', 'https://xlayerrpc.okx.com'] },
  250: { name: 'fantom', rpcs: ['https://rpcapi.fantom.network', 'https://fantom-rpc.publicnode.com', 'https://rpc.ftm.tools'] },
  8453: { name: 'base', rpcs: ['https://base-rpc.publicnode.com', 'https://mainnet.base.org'] },
  42161: { name: 'arbitrum', rpcs: ['https://arbitrum-one-rpc.publicnode.com', 'https://arb1.arbitrum.io/rpc'] },
  43114: { name: 'avalanche', rpcs: ['https://api.avax.network/ext/bc/C/rpc', 'https://avalanche-c-chain-rpc.publicnode.com'] },
};

const RPC_TIMEOUT_MS = Number.parseInt(process.env.RPC_TIMEOUT_MS || '4000', 10);
const RPC_BUDGET_MS = Number.parseInt(process.env.RPC_BUDGET_MS || '7000', 10);

class RpcError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'RpcError';
    if (cause) this.cause = cause;
  }
}

function supportedChainIds() {
  return Object.keys(DEFAULT_CHAINS).map(Number);
}

function chainName(chainId) {
  return DEFAULT_CHAINS[chainId] ? DEFAULT_CHAINS[chainId].name : `chain-${chainId}`;
}

function rpcUrlsFor(chainId) {
  const envList = process.env[`RPC_URL_${chainId}`];
  if (envList && envList.trim()) {
    return envList.split(',').map((s) => s.trim()).filter(Boolean);
  }
  return DEFAULT_CHAINS[chainId] ? DEFAULT_CHAINS[chainId].rpcs.slice() : [];
}

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new RpcError(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function makeProvider(url, chainId) {
  const req = new FetchRequest(url);
  req.timeout = RPC_TIMEOUT_MS;
  const network = Network.from(BigInt(chainId));
  return new JsonRpcProvider(req, network, { staticNetwork: network, batchMaxCount: 1 });
}

/**
 * Snapshot of an address: code presence, nonce, balance.
 * @returns {Promise<{address:string,isContract:boolean,txCount:number,balance:string}>}
 */
async function readAddressState(provider, address) {
  const [code, txCount, balance] = await Promise.all([
    provider.getCode(address),
    provider.getTransactionCount(address),
    provider.getBalance(address),
  ]);
  const hasCode = typeof code === 'string' && code !== '0x' && code.length > 2;
  return {
    address,
    isContract: hasCode,
    txCount: Number(txCount),
    balance: balance.toString(),
    codeSize: hasCode ? (code.length - 2) / 2 : 0,
    code: hasCode ? code : '0x',
  };
}

/** ethers surfaces an on-chain revert as CALL_EXCEPTION; that is a valid answer, not an RPC failure. */
function isRevert(err) {
  return Boolean(err) && (err.code === 'CALL_EXCEPTION' || (err.error && err.error.code === 3) || (typeof err.message === 'string' && /execution reverted|revert/i.test(err.message) && err.code !== 'TIMEOUT'));
}

/**
 * Chain reader with per-call timeout, endpoint fallback and a global budget.
 * All failures surface as RpcError so the analyzer can degrade to WARN.
 */
function createChainReader(chainId) {
  const urls = rpcUrlsFor(chainId);
  if (urls.length === 0) {
    throw new RpcError(`No RPC endpoint configured for chainId ${chainId}`);
  }
  const startedAt = Date.now();
  let activeIndex = 0;
  let providers = urls.map(() => null);
  let lastEndpoint = null;

  function remainingBudget() {
    return RPC_BUDGET_MS - (Date.now() - startedAt);
  }

  async function attempt(fn, label) {
    const errors = [];
    for (let i = activeIndex; i < urls.length; i += 1) {
      const budget = remainingBudget();
      if (budget <= 0) {
        throw new RpcError(`RPC budget of ${RPC_BUDGET_MS}ms exhausted (${label})`, errors[errors.length - 1]);
      }
      if (!providers[i]) providers[i] = makeProvider(urls[i], chainId);
      try {
        const result = await withTimeout(fn(providers[i]), Math.min(RPC_TIMEOUT_MS, budget), `${label} via ${urls[i]}`);
        activeIndex = i;
        lastEndpoint = urls[i];
        return result;
      } catch (err) {
        if (isRevert(err)) {
          // The node answered; the call itself reverted. Do not fail over.
          activeIndex = i;
          lastEndpoint = urls[i];
          throw err;
        }
        errors.push(err);
        providers[i] = null;
      }
    }
    const last = errors[errors.length - 1];
    throw new RpcError(`All ${urls.length} RPC endpoint(s) failed for ${label}: ${last ? last.message : 'unknown error'}`, last);
  }

  return {
    chainId,
    chainName: chainName(chainId),
    addressState: (address) => attempt((p) => readAddressState(p, address), `addressState(${address})`),
    /** eth_call. Reverts propagate as CALL_EXCEPTION (see isRevert); transport errors as RpcError. */
    call: (tx) => attempt((p) => p.call(tx), `call(${tx.to})`),
    getStorage: (address, slot) => attempt((p) => p.getStorage(address, slot), `getStorage(${address})`),
    estimateGas: (tx) => attempt((p) => p.estimateGas(tx), `estimateGas(${tx.to})`),
    get endpoint() {
      return lastEndpoint;
    },
  };
}

module.exports = {
  DEFAULT_CHAINS,
  RpcError,
  isRevert,
  createChainReader,
  supportedChainIds,
  chainName,
  rpcUrlsFor,
};
