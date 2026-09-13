'use strict';

/**
 * Static registry of well-known contracts and tokens.
 *
 * Every address here is a widely published canonical deployment. The registry
 * is used to (1) label counterparties in human-readable output, (2) lower the
 * false-positive rate for routine DeFi flows, and (3) detect look-alike
 * addresses that imitate these contracts (address poisoning against agents).
 *
 * The key 'any' holds deployments that share the same address on every chain
 * (deterministic CREATE2 deployments).
 */

const KNOWN_CONTRACTS = {
  any: {
    '0x000000000022d473030f116ddee9f6b43ac78ba3': { name: 'Permit2', category: 'permit2', vendor: 'Uniswap' },
    '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad': { name: 'Uniswap Universal Router', category: 'dex-router', vendor: 'Uniswap' },
    '0x00000000000000adc04c56bf30ac9d3c0aaf14dc': { name: 'Seaport 1.5', category: 'nft-marketplace', vendor: 'OpenSea' },
    '0x0000000000000068f116a894984e2db1123eb395': { name: 'Seaport 1.6', category: 'nft-marketplace', vendor: 'OpenSea' },
    '0x1e0049783f008a0085193e00003d00cd54003c71': { name: 'OpenSea Conduit', category: 'nft-marketplace', vendor: 'OpenSea' },
    '0xca11bde05977b3631167028862be2a173976ca11': { name: 'Multicall3', category: 'utility', vendor: 'mds1' },
  },
  1: {
    '0x7a250d5630b4cf539739df2c5dacb4c659f2488d': { name: 'Uniswap V2 Router02', category: 'dex-router', vendor: 'Uniswap' },
    '0xe592427a0aece92de3edee1f18e0157c05861564': { name: 'Uniswap V3 SwapRouter', category: 'dex-router', vendor: 'Uniswap' },
    '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45': { name: 'Uniswap V3 SwapRouter02', category: 'dex-router', vendor: 'Uniswap' },
    '0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b': { name: 'Uniswap Universal Router (legacy)', category: 'dex-router', vendor: 'Uniswap' },
    '0x66a9893cc07d91d95644aedd05d03f95e1dba8af': { name: 'Uniswap V4 Universal Router', category: 'dex-router', vendor: 'Uniswap' },
    '0x1111111254eeb25477b68fb85ed929f73a960582': { name: '1inch AggregationRouter V5', category: 'dex-router', vendor: '1inch' },
    '0x111111125421ca6dc452d289314280a0f8842a65': { name: '1inch AggregationRouter V6', category: 'dex-router', vendor: '1inch' },
    '0xdef1c0ded9bec7f1a1670819833240f027b25eff': { name: '0x Exchange Proxy', category: 'dex-router', vendor: '0x' },
    '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2': { name: 'Aave V3 Pool', category: 'lending', vendor: 'Aave' },
    '0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f': { name: 'SushiSwap Router', category: 'dex-router', vendor: 'Sushi' },
    '0xae7ab96520de3a18e5e111b5eaab095312d7fe84': { name: 'Lido stETH', category: 'liquid-staking', vendor: 'Lido' },
    '0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0': { name: 'Lido wstETH', category: 'liquid-staking', vendor: 'Lido' },
  },
  10: {
    '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45': { name: 'Uniswap V3 SwapRouter02', category: 'dex-router', vendor: 'Uniswap' },
    '0xe592427a0aece92de3edee1f18e0157c05861564': { name: 'Uniswap V3 SwapRouter', category: 'dex-router', vendor: 'Uniswap' },
    '0x1111111254eeb25477b68fb85ed929f73a960582': { name: '1inch AggregationRouter V5', category: 'dex-router', vendor: '1inch' },
    '0x111111125421ca6dc452d289314280a0f8842a65': { name: '1inch AggregationRouter V6', category: 'dex-router', vendor: '1inch' },
    '0xdef1c0ded9bec7f1a1670819833240f027b25eff': { name: '0x Exchange Proxy', category: 'dex-router', vendor: '0x' },
  },
  56: {
    '0x10ed43c718714eb63d5aa57b78b54704e256024e': { name: 'PancakeSwap V2 Router', category: 'dex-router', vendor: 'PancakeSwap' },
    '0x13f4ea83d0bd40e75c8222255bc855a974568dd4': { name: 'PancakeSwap Smart Router V3', category: 'dex-router', vendor: 'PancakeSwap' },
    '0x1111111254eeb25477b68fb85ed929f73a960582': { name: '1inch AggregationRouter V5', category: 'dex-router', vendor: '1inch' },
    '0x111111125421ca6dc452d289314280a0f8842a65': { name: '1inch AggregationRouter V6', category: 'dex-router', vendor: '1inch' },
    '0xdef1c0ded9bec7f1a1670819833240f027b25eff': { name: '0x Exchange Proxy', category: 'dex-router', vendor: '0x' },
  },
  137: {
    '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45': { name: 'Uniswap V3 SwapRouter02', category: 'dex-router', vendor: 'Uniswap' },
    '0xe592427a0aece92de3edee1f18e0157c05861564': { name: 'Uniswap V3 SwapRouter', category: 'dex-router', vendor: 'Uniswap' },
    '0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff': { name: 'QuickSwap Router', category: 'dex-router', vendor: 'QuickSwap' },
    '0x1111111254eeb25477b68fb85ed929f73a960582': { name: '1inch AggregationRouter V5', category: 'dex-router', vendor: '1inch' },
    '0x111111125421ca6dc452d289314280a0f8842a65': { name: '1inch AggregationRouter V6', category: 'dex-router', vendor: '1inch' },
    '0xdef1c0ded9bec7f1a1670819833240f027b25eff': { name: '0x Exchange Proxy', category: 'dex-router', vendor: '0x' },
  },
  8453: {
    '0x2626664c2603336e57b271c5c0b26f421741e481': { name: 'Uniswap V3 SwapRouter02', category: 'dex-router', vendor: 'Uniswap' },
    '0xcf77a3ba9a5ca399b7c97c74d54e5b1beb874e43': { name: 'Aerodrome Router', category: 'dex-router', vendor: 'Aerodrome' },
    '0x1111111254eeb25477b68fb85ed929f73a960582': { name: '1inch AggregationRouter V5', category: 'dex-router', vendor: '1inch' },
    '0x111111125421ca6dc452d289314280a0f8842a65': { name: '1inch AggregationRouter V6', category: 'dex-router', vendor: '1inch' },
    '0xdef1c0ded9bec7f1a1670819833240f027b25eff': { name: '0x Exchange Proxy', category: 'dex-router', vendor: '0x' },
  },
  42161: {
    '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45': { name: 'Uniswap V3 SwapRouter02', category: 'dex-router', vendor: 'Uniswap' },
    '0xe592427a0aece92de3edee1f18e0157c05861564': { name: 'Uniswap V3 SwapRouter', category: 'dex-router', vendor: 'Uniswap' },
    '0x1111111254eeb25477b68fb85ed929f73a960582': { name: '1inch AggregationRouter V5', category: 'dex-router', vendor: '1inch' },
    '0x111111125421ca6dc452d289314280a0f8842a65': { name: '1inch AggregationRouter V6', category: 'dex-router', vendor: '1inch' },
    '0xdef1c0ded9bec7f1a1670819833240f027b25eff': { name: '0x Exchange Proxy', category: 'dex-router', vendor: '0x' },
  },
  43114: {
    '0x60ae616a2155ee3d9a68541ba4544862310933d4': { name: 'Trader Joe Router', category: 'dex-router', vendor: 'Trader Joe' },
    '0x1111111254eeb25477b68fb85ed929f73a960582': { name: '1inch AggregationRouter V5', category: 'dex-router', vendor: '1inch' },
    '0x111111125421ca6dc452d289314280a0f8842a65': { name: '1inch AggregationRouter V6', category: 'dex-router', vendor: '1inch' },
    '0xdef1c0ded9bec7f1a1670819833240f027b25eff': { name: '0x Exchange Proxy', category: 'dex-router', vendor: '0x' },
  },
};

const KNOWN_TOKENS = {
  1: {
    '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2': { symbol: 'WETH', decimals: 18, name: 'Wrapped Ether' },
    '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': { symbol: 'USDC', decimals: 6, name: 'USD Coin' },
    '0xdac17f958d2ee523a2206206994597c13d831ec7': { symbol: 'USDT', decimals: 6, name: 'Tether USD' },
    '0x6b175474e89094c44da98b954eedeac495271d0f': { symbol: 'DAI', decimals: 18, name: 'Dai Stablecoin' },
    '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599': { symbol: 'WBTC', decimals: 8, name: 'Wrapped BTC' },
    '0xae7ab96520de3a18e5e111b5eaab095312d7fe84': { symbol: 'stETH', decimals: 18, name: 'Lido Staked Ether' },
    '0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0': { symbol: 'wstETH', decimals: 18, name: 'Wrapped stETH' },
  },
  10: {
    '0x4200000000000000000000000000000000000006': { symbol: 'WETH', decimals: 18, name: 'Wrapped Ether' },
    '0x0b2c639c533813f4aa9d7837caf62653d097ff85': { symbol: 'USDC', decimals: 6, name: 'USD Coin' },
    '0x94b008aa00579c1307b0ef2c499ad98a8ce58e58': { symbol: 'USDT', decimals: 6, name: 'Tether USD' },
    '0x4200000000000000000000000000000000000042': { symbol: 'OP', decimals: 18, name: 'Optimism' },
  },
  56: {
    '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c': { symbol: 'WBNB', decimals: 18, name: 'Wrapped BNB' },
    '0x55d398326f99059ff775485246999027b3197955': { symbol: 'USDT', decimals: 18, name: 'Tether USD (BSC)' },
    '0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d': { symbol: 'USDC', decimals: 18, name: 'USD Coin (BSC)' },
  },
  137: {
    '0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270': { symbol: 'WPOL', decimals: 18, name: 'Wrapped POL (ex-WMATIC)' },
    '0x3c499c542cef5e3811e1192ce70d8cc03d5c3359': { symbol: 'USDC', decimals: 6, name: 'USD Coin' },
    '0x2791bca1f2de4661ed88a30c99a7a9449aa84174': { symbol: 'USDC.e', decimals: 6, name: 'USD Coin (bridged)' },
    '0xc2132d05d31c914a87c6611c10748aeb04b58e8f': { symbol: 'USDT', decimals: 6, name: 'Tether USD' },
  },
  196: {
    '0xe538905cf8410324e03a5a23c1c177a474d59b2b': { symbol: 'WOKB', decimals: 18, name: 'Wrapped OKB' },
    '0x1e4a5963abfd975d8c9021ce480b42188849d41d': { symbol: 'USDT', decimals: 6, name: 'Tether USD' },
    '0x74b7f16337b8972027f6196a17a631ac6de26d22': { symbol: 'USDC', decimals: 6, name: 'USD Coin' },
  },
  8453: {
    '0x4200000000000000000000000000000000000006': { symbol: 'WETH', decimals: 18, name: 'Wrapped Ether' },
    '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913': { symbol: 'USDC', decimals: 6, name: 'USD Coin' },
  },
  42161: {
    '0x82af49447d8a07e3bd95bd0d56f35241523fbab1': { symbol: 'WETH', decimals: 18, name: 'Wrapped Ether' },
    '0xaf88d065e77c8cc2239327c5edb3a432268e5831': { symbol: 'USDC', decimals: 6, name: 'USD Coin' },
    '0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9': { symbol: 'USDT', decimals: 6, name: 'Tether USD' },
    '0x912ce59144191c1204e64559fe8253a0e49e6548': { symbol: 'ARB', decimals: 18, name: 'Arbitrum' },
  },
  43114: {
    '0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7': { symbol: 'WAVAX', decimals: 18, name: 'Wrapped AVAX' },
    '0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e': { symbol: 'USDC', decimals: 6, name: 'USD Coin' },
  },
};

const NATIVE_SYMBOL = { 1: 'ETH', 10: 'ETH', 56: 'BNB', 137: 'POL', 196: 'OKB', 250: 'FTM', 8453: 'ETH', 42161: 'ETH', 43114: 'AVAX' };

function lookupContract(chainId, address) {
  const a = String(address).toLowerCase();
  const hit = (KNOWN_CONTRACTS[chainId] && KNOWN_CONTRACTS[chainId][a]) || KNOWN_CONTRACTS.any[a];
  return hit ? Object.assign({ address: a, source: 'static-registry' }, hit) : null;
}

function lookupToken(chainId, address) {
  const a = String(address).toLowerCase();
  const hit = KNOWN_TOKENS[chainId] && KNOWN_TOKENS[chainId][a];
  return hit ? Object.assign({ address: a, source: 'static-registry' }, hit) : null;
}

function nativeSymbol(chainId) {
  return NATIVE_SYMBOL[chainId] || 'native';
}

/**
 * Address-poisoning check: does `candidate` share the visible prefix and suffix
 * of `reference` while being a different address? Wallet UIs show 0xABCD…1234,
 * so attackers generate vanity addresses with the same 4+4 hex characters.
 */
function isLookalike(candidate, reference, prefixLen, suffixLen) {
  prefixLen = prefixLen || 4;
  suffixLen = suffixLen || 4;
  const c = String(candidate).toLowerCase().replace(/^0x/, '');
  const r = String(reference).toLowerCase().replace(/^0x/, '');
  if (c.length !== 40 || r.length !== 40 || c === r) return false;
  return c.slice(0, prefixLen) === r.slice(0, prefixLen) && c.slice(-suffixLen) === r.slice(-suffixLen);
}

/** Find a registry contract or token that `address` imitates on this chain. */
function findRegistryLookalike(chainId, address) {
  const pools = [KNOWN_CONTRACTS.any, KNOWN_CONTRACTS[chainId] || {}, KNOWN_TOKENS[chainId] || {}];
  for (const pool of pools) {
    for (const [known, meta] of Object.entries(pool)) {
      if (isLookalike(address, known)) return Object.assign({ address: known }, meta);
    }
  }
  return null;
}

function allKnownAddresses(chainId) {
  return Object.keys(KNOWN_CONTRACTS.any)
    .concat(Object.keys(KNOWN_CONTRACTS[chainId] || {}))
    .concat(Object.keys(KNOWN_TOKENS[chainId] || {}));
}

module.exports = {
  KNOWN_CONTRACTS,
  KNOWN_TOKENS,
  lookupContract,
  lookupToken,
  nativeSymbol,
  isLookalike,
  findRegistryLookalike,
  allKnownAddresses,
};
