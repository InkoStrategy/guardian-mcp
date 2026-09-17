'use strict';

/**
 * Pay-Safe: pre-flight check of an x402 payment BEFORE an agent pays it.
 *
 * POST /check-payment
 * {
 *   "paymentRequired": "<base64 PAYMENT-REQUIRED header>" | { x402Version, resource, accepts[] },   // or:
 *   "payment": { network|chainId, asset, amount, payTo, scheme?, maxTimeoutSeconds?, extra? },    // flattened quote
 *   "requestUrl": "https://seller.example/paid/route",       // URL the agent called and got 402 from
 *   "selectedIndex": 0,                                      // accepts[] entry the agent intends to pay (optional)
 *   "paymentSignature": "<base64 PAYMENT-SIGNATURE / X-PAYMENT>" | {...},   // optional: verify the signed payload before replay
 *   "expected": {                                            // what the marketplace listing promised (optional but recommended)
 *     "feeAmount": 0.002, "feeToken": "0x779d…", "endpoint": "https://seller.example/paid/route",
 *     "payTo": "0x…", "maxAmount": "2000", "aspAgentId": "13761", "sid": 40709
 *   },
 *   "context": { "known_addresses": ["0x…"], "max_amount": "1.5", "from": "0x…", "session_id": "…" }
 * }
 *
 * Wire names (PAYMENT-REQUIRED, PAYMENT-SIGNATURE, X-PAYMENT, x402Version, accepts, payTo) are protocol literals.
 */

const { getAddress, verifyTypedData } = require('ethers');
const { supportedChainIds, chainName } = require('./rpc');
const registry = require('./registry');
const quick = require('./quick-checks');
const contextAnalyzer = require('./context-analyzer');
const stats = require('./stats');
const { getStore } = require('./store');

class PaymentValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ValidationError';
  }
}

const ZERO = '0x0000000000000000000000000000000000000000';
const PERMIT2 = '0x000000000022d473030f116ddee9f6b43ac78ba3';
const X402_EXACT_PERMIT2_PROXY = '0x402085c248eea27d92e8b30b2c58ed07f9e20001';
const X402_UPTO_PERMIT2_PROXY = '0x4020e7393b728a3939659e5732f87fdd8e680002';
const MAX_ACCEPTS = 20;
const LONG_TIMEOUT_SECONDS = 3600;
const VALIDITY_SLACK_SECONDS = 600;

/** Canonical x402 settlement assets (address → meta). Sources: @okxweb3/x402-evm DEFAULT_STABLECOINS, x402 defaults. */
const SETTLEMENT_ASSETS = {
  196: {
    '0x779ded0c9e1022225f8e0630b35a9b54be713736': { symbol: 'USDT0', decimals: 6, eip712Name: 'USD₮0', eip712Version: '1', eip712DomainSeparator: '0xd591d9baf744328d9400b923cb02c9474d367d591ca1ab24d8c4068be527599d' },
    '0x1e4a5963abfd975d8c9021ce480b42188849d41d': { symbol: 'USDT', decimals: 6 },
    '0x74b7f16337b8972027f6196a17a631ac6de26d22': { symbol: 'USDC', decimals: 6 },
  },
  1952: {
    '0x9e29b3aada05bf2d2c827af80bd28dc0b9b4fb0c': { symbol: 'USDT0', decimals: 6, eip712Name: 'USD₮0', eip712Version: '1', testnet: true },
  },
  8453: {
    '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913': { symbol: 'USDC', decimals: 6, eip712Name: 'USD Coin', eip712Version: '2' },
  },
  84532: {
    '0x036cbd53842c5426634e7929541ec2318f3dcf7e': { symbol: 'USDC', decimals: 6, eip712Name: 'USDC', eip712Version: '2', testnet: true },
  },
};
const STABLE_SYMBOLS = new Set(['USDC', 'USDT', 'USDT0', 'USDG', 'DAI', 'USDC.E']);

/** x402 v1 network names → chainId. */
const V1_NETWORKS = { base: 8453, 'base-sepolia': 84532, 'x-layer': 196, xlayer: 196, 'x-layer-testnet': 1952, polygon: 137, avalanche: 43114, arbitrum: 42161, optimism: 10, ethereum: 1, mainnet: 1, bsc: 56 };

const PAYMENT_RULES = [
  { code: 'payment_network_unsupported', severity: 'WARN', layer: 'payment', description: 'The challenge settles on a network Guardian cannot inspect (non-EVM or unknown chain); on-chain checks were skipped.' },
  { code: 'testnet_payment', severity: 'WARN', layer: 'payment', description: 'The challenge asks for payment on a testnet. Real services on OKX.AI settle on mainnet.' },
  { code: 'unknown_payment_scheme', severity: 'WARN', layer: 'payment', description: 'The x402 scheme is not one of exact, upto, aggr_deferred or period.' },
  { code: 'unknown_settlement_asset', severity: 'WARN', layer: 'payment', description: 'The asset is not a recognised x402 settlement stablecoin on this network.' },
  { code: 'asset_lookalike', severity: 'DENY', layer: 'payment', description: 'The asset imitates a canonical stablecoin (same visible prefix/suffix) but is a different contract.' },
  { code: 'asset_not_contract', severity: 'DENY', layer: 'payment', description: 'The asset address has no contract code; no token can be paid there.' },
  { code: 'asset_mismatch_listing', severity: 'DENY', layer: 'payment', description: 'The token in the challenge differs from the token the marketplace listing promised.' },
  { code: 'eip712_domain_mismatch', severity: 'WARN', layer: 'payment', description: 'extra.name / extra.version do not match the canonical EIP-712 domain of the asset; the signature will be rejected or signed for a different token.' },
  { code: 'amount_above_listing', severity: 'DENY', layer: 'payment', description: 'The amount requested is higher than the listed price (price bait-and-switch).' },
  { code: 'amount_above_user_cap', severity: 'DENY', layer: 'payment', description: 'The amount exceeds the spending cap the agent was given (context.max_amount).' },
  { code: 'upto_cap_above_listing', severity: 'WARN', layer: 'payment', description: 'An upto (metered) authorisation allows charging more than the listed price.' },
  { code: 'recurring_payment', severity: 'WARN', layer: 'payment', description: 'The period scheme authorises recurring charges; confirm the subscription terms with the user.' },
  { code: 'permit2_approval_required', severity: 'WARN', layer: 'payment', description: 'Permit2-based schemes need a one-time token approval to the canonical Permit2 contract; approve only Permit2, never another spender.' },
  { code: 'payto_zero_address', severity: 'DENY', layer: 'payment', description: 'The payee is the zero address; funds would be burned.' },
  { code: 'payto_is_asset', severity: 'DENY', layer: 'payment', description: 'The payee is the token contract itself; funds sent there are usually unrecoverable.' },
  { code: 'payto_mismatch_listing', severity: 'DENY', layer: 'payment', description: 'The payee differs from the wallet the marketplace listing names for this provider.' },
  { code: 'payto_poisoning', severity: 'DENY', layer: 'payment', description: 'The payee shares the visible prefix/suffix of a known or expected address but is a different address.' },
  { code: 'multiple_payees', severity: 'WARN', layer: 'payment', description: 'accepts[] entries pay different recipients; make sure the entry you select pays the provider.' },
  { code: 'long_payment_timeout', severity: 'WARN', layer: 'payment', description: 'maxTimeoutSeconds is unusually long, so a signed authorisation stays usable for a long time.' },
  { code: 'payment_domain_mismatch', severity: 'DENY', layer: 'payment', description: 'The URL that returned the 402 is on a different domain than the listed endpoint.' },
  { code: 'resource_host_mismatch', severity: 'WARN', layer: 'payment', description: 'The resource.url in the challenge points to a different domain than the URL the agent called.' },
  { code: 'insecure_payment_endpoint', severity: 'WARN', layer: 'payment', description: 'The paid endpoint uses plain http, so the challenge can be altered in transit.' },
  { code: 'endpoint_url_injection', severity: 'DENY', layer: 'payment', description: 'The endpoint or resource URL carries shell syntax (command separators, pipes, brace expansion, command substitution). It targets buyer agents that pass the URL to a shell, such as curl in a tool call.' },
  { code: 'challenge_field_injection', severity: 'DENY', layer: 'payment', description: 'A free-text field of the 402 challenge (extra.name, extra.version, resource.description, error) carries a shell payload such as $(...), a quote break followed by a command, or a chained curl/base64. Honest sellers never need this.' },
  { code: 'endpoint_phishing_pattern', severity: 'DENY', layer: 'payment', description: 'The paid host imitates someone (brand impersonation, typosquatting, punycode, bare IP) and no marketplace listing vouches for it.' },
  { code: 'endpoint_domain_suspicious', severity: 'WARN', layer: 'payment', description: 'The paid host imitates a brand but is the endpoint named in the marketplace listing, or it only has a weak pattern (abused TLD, phishing keyword, deep subdomains) and no listing names it. Weak patterns on a listed endpoint are ignored.' },
  { code: 'accepted_mismatch', severity: 'DENY', layer: 'payment', description: 'The signed payload\'s accepted requirement differs from the challenge (recipient, amount, asset, network or scheme).' },
  { code: 'signed_recipient_mismatch', severity: 'DENY', layer: 'payment', description: 'The signed authorisation pays a different address than the challenge payTo.' },
  { code: 'signed_amount_mismatch', severity: 'DENY', layer: 'payment', description: 'The signed authorisation allows more than the challenge amount.' },
  { code: 'signed_token_mismatch', severity: 'DENY', layer: 'payment', description: 'The signed Permit2 authorisation moves a different token than the challenge asset.' },
  { code: 'signed_spender_not_x402_proxy', severity: 'DENY', layer: 'payment', description: 'The signed Permit2 authorisation names a spender other than the canonical x402 Permit2 proxy for this scheme.' },
  { code: 'signed_network_mismatch', severity: 'DENY', layer: 'payment', description: 'The signed payload is for a different network than the challenge.' },
  { code: 'signed_validity_too_long', severity: 'WARN', layer: 'payment', description: 'The signed authorisation stays valid far longer than the challenge maxTimeoutSeconds.' },
  { code: 'signed_expired', severity: 'WARN', layer: 'payment', description: 'The signed authorisation is already expired or not yet valid; the payment will be rejected.' },
  { code: 'signed_payer_mismatch', severity: 'WARN', layer: 'payment', description: 'The signed authorisation spends from a different wallet than context.from.' },
  { code: 'signature_does_not_recover', severity: 'WARN', layer: 'payment', description: 'The EIP-3009 signature does not recover to authorization.from; the facilitator will reject it.' },
  { code: 'challenge_header_body_mismatch', severity: 'DENY', layer: 'payment', description: 'The PAYMENT-REQUIRED header (or the entries a wallet quote persisted) and the 402 JSON body describe different payments. Whoever reads the body is shown one payee or price while the wallet signs another.' },
  { code: 'quote_inconsistent', severity: 'DENY', layer: 'payment', description: 'An Onchain OS payment quote disagrees with itself: the payee, amount, token or network in its summary differs from the accepts entry that payment pay will sign.' },
  { code: 'quote_expired', severity: 'WARN', layer: 'payment', description: 'The persisted Onchain OS quote has expired; payment pay will refuse it, so quote again and check the new paymentId.' },
  { code: 'quote_partial', severity: 'WARN', layer: 'payment', description: 'The quote output does not include the full challenge (header-only seller), so the EIP-712 domain and free-text fields were not visible. Check the persisted payment state instead.' },
  { code: 'listing_not_checked', severity: 'WARN', layer: 'payment', description: 'No marketplace listing was supplied or resolved, so price, token and payee were not compared against a listing. On its own this is not a safe-to-pay result.' },
];
const RULE_INDEX = Object.fromEntries(PAYMENT_RULES.map((r) => [r.code, r]));

const RECOMMENDATIONS = {
  amount_above_listing: 'Do not pay. The seller asks for more than its marketplace listing; report the listing or pay only after the seller fixes the price.',
  amount_above_user_cap: 'Do not pay without asking the user; the amount exceeds your spending cap.',
  asset_lookalike: 'Do not pay. The token imitates a canonical stablecoin; only pay in the canonical asset for this network.',
  asset_mismatch_listing: 'Do not pay. The token differs from the listing; ask the seller to charge in the listed token.',
  asset_not_contract: 'Do not pay. The asset is not a token contract.',
  payto_mismatch_listing: 'Do not pay. The payee is not the provider wallet from the listing; the endpoint may be hijacked or impersonated.',
  payto_poisoning: 'Do not pay. The payee imitates a known address; copy the payee from the verified listing, never from history.',
  payto_zero_address: 'Do not pay. Funds sent to the zero address are burned.',
  payto_is_asset: 'Do not pay. Paying the token contract itself loses the funds.',
  payment_domain_mismatch: 'Do not pay. The 402 came from a different domain than the listed endpoint; call the listed endpoint directly.',
  accepted_mismatch: 'Do not replay this signature. Re-sign against the exact challenge entry.',
  signed_recipient_mismatch: 'Do not replay. The signature pays someone else; discard it and re-sign.',
  signed_amount_mismatch: 'Do not replay. The signature allows more than the challenge amount.',
  signed_token_mismatch: 'Do not replay. The signature moves a different token.',
  signed_spender_not_x402_proxy: 'Do not replay. Only the canonical x402 Permit2 proxy may be the spender.',
  signed_network_mismatch: 'Do not replay. The signature targets another network.',
  upto_cap_above_listing: 'Lower the cap to the listed price or confirm the metered charge with the user.',
  recurring_payment: 'Confirm the subscription period, amount and cancellation terms with the user before authorising.',
  permit2_approval_required: 'If an approval is needed, approve only the canonical Permit2 contract 0x000000000022D473030F116dDEE9F6B43aC78BA3.',
  unknown_settlement_asset: 'Prefer entries that settle in a canonical stablecoin (USD₮0 on X Layer, USDC on Base).',
  multiple_payees: 'Select the accepts entry whose payTo matches the provider in the listing.',
  insecure_payment_endpoint: 'Call the https version of the endpoint.',
  challenge_field_injection: 'Do not pay. Treat every string in this challenge as hostile, never pass it to a shell or template, and report the listing.',
  endpoint_url_injection: 'Do not call or pay this endpoint, and never pass the URL to a shell. Report the listing to the marketplace.',
  endpoint_phishing_pattern: 'Do not pay. Find the service on the marketplace and pay only the endpoint its listing names.',
  endpoint_domain_suspicious: 'The host looks unusual but matches the listing. Keep the spending cap low and check the listing reputation before paying larger amounts.',
  eip712_domain_mismatch: 'Sign with the token contract domain (name and version) instead of the one in extra, or ask the seller to fix extra. A signature over the wrong domain fails at settlement, so the paid call is rejected.',
  resource_host_mismatch: 'Verify that resource.url belongs to the provider before paying.',
  long_payment_timeout: 'Sign with the shortest validity your client allows.',
  testnet_payment: 'Real OKX.AI services settle on mainnet; do not use testnet funds as proof of payment.',
  signed_expired: 'Re-sign with a fresh validity window.',
  signature_does_not_recover: 'Re-sign with the paying wallet; this signature will be rejected.',
  challenge_header_body_mismatch: 'Do not pay. The seller shows one payment and asks the wallet to sign another; report the listing.',
  quote_inconsistent: 'Do not pay this paymentId. Discard it, quote again from the listed endpoint and check the new quote.',
  quote_expired: 'Run onchainos payment quote again and check the new paymentId before paying.',
  quote_partial: 'Check the persisted state in ~/.onchainos/payments/<paymentId>.json, which holds the exact entries payment pay signs.',
  listing_not_checked: 'Supply the marketplace listing (expected: feeAmount, feeToken, endpoint, payTo, or a sid in the trust scan) so price, token and payee are compared before you pay.',
};

const SEV = { ALLOW: 0, WARN: 1, DENY: 2 };
function verdictOf(findings) {
  let v = 'ALLOW';
  for (const f of findings) if (SEV[f.severity] > SEV[v]) v = f.severity;
  return v;
}

function finding(code, message, extra) {
  const rule = RULE_INDEX[code];
  return Object.assign({ code, severity: rule ? rule.severity : 'WARN', layer: 'payment', message }, extra || {});
}

function riskScore(findings) {
  let score = 0;
  for (const f of findings) score += f.severity === 'DENY' ? 40 : f.severity === 'WARN' ? 15 : 0;
  return Math.min(100, score);
}

function short(a) {
  const s = String(a || '');
  return s.length === 42 ? s.slice(0, 6) + '…' + s.slice(-4) : s;
}

// ---------- decoding ----------

function decodeBase64Json(raw, field) {
  const s = String(raw).trim();
  if (s.startsWith('{')) {
    try { return JSON.parse(s); } catch { throw new PaymentValidationError('"' + field + '" is not valid JSON'); }
  }
  if (s.length > 48000) throw new PaymentValidationError('"' + field + '" is too large');
  try {
    const normalized = s.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(normalized, 'base64').toString('utf8'));
  } catch {
    throw new PaymentValidationError('"' + field + '" must be a base64-encoded JSON header value or a JSON object');
  }
}

/** CAIP-2 ("eip155:196"), v1 name ("base") or numeric chainId → { network, chainId|null, evm } */
function parseNetwork(raw, chainIdHint) {
  if (chainIdHint !== undefined && chainIdHint !== null && chainIdHint !== '') {
    const n = Number(chainIdHint);
    if (Number.isInteger(n) && n > 0) return { network: 'eip155:' + n, chainId: n, evm: true };
  }
  if (typeof raw === 'number' && Number.isInteger(raw) && raw > 0) return { network: 'eip155:' + raw, chainId: raw, evm: true };
  const s = String(raw || '').trim().toLowerCase();
  const m = /^eip155:(\d{1,10})$/.exec(s);
  if (m) return { network: s, chainId: Number(m[1]), evm: true };
  if (/^\d{1,10}$/.test(s)) return { network: 'eip155:' + s, chainId: Number(s), evm: true };
  if (V1_NETWORKS[s]) return { network: 'eip155:' + V1_NETWORKS[s], chainId: V1_NETWORKS[s], evm: true, v1Name: s };
  return { network: s || null, chainId: null, evm: false };
}

function checksumOrNull(a) {
  // Lenient on EIP-55 casing: sellers and quotes often send lowercase or mis-cased addresses.
  if (typeof a !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(a.trim())) return null;
  try { return getAddress(a.trim().toLowerCase()); } catch { return null; }
}

function normalizeEntry(raw, index, v) {
  if (!raw || typeof raw !== 'object') throw new PaymentValidationError('accepts[' + index + '] must be an object');
  const amount = String(raw.amount !== undefined && raw.amount !== null && raw.amount !== '' ? raw.amount : raw.maxAmountRequired !== undefined ? raw.maxAmountRequired : '');
  if (!/^[0-9]{1,78}$/.test(amount)) throw new PaymentValidationError('accepts[' + index + '].amount must be an atomic integer string');
  const net = parseNetwork(raw.network, raw.chainId);
  const asset = checksumOrNull(raw.asset);
  const payTo = checksumOrNull(raw.payTo);
  if (net.evm && !asset) throw new PaymentValidationError('accepts[' + index + '].asset must be a valid EVM address');
  if (net.evm && !payTo) throw new PaymentValidationError('accepts[' + index + '].payTo must be a valid EVM address');
  const extra = raw.extra && typeof raw.extra === 'object' ? raw.extra : {};
  const maxTimeoutSeconds = Number.isFinite(Number(raw.maxTimeoutSeconds)) ? Number(raw.maxTimeoutSeconds) : null;
  return {
    index,
    x402Version: v,
    scheme: String(raw.scheme || 'exact'),
    transferMethod: String(extra.assetTransferMethod || (raw.scheme === 'upto' ? 'permit2' : 'eip3009')).toLowerCase(),
    network: net.network,
    chainId: net.chainId,
    evm: net.evm,
    asset: asset || (raw.asset ? String(raw.asset) : null),
    amount,
    payTo: payTo || (raw.payTo ? String(raw.payTo) : null),
    maxTimeoutSeconds,
    extra,
    resourceUrl: typeof raw.resource === 'string' ? raw.resource : null,
  };
}

function normalizeChallenge(input) {
  let pr = null;
  if (input.paymentRequired !== undefined && input.paymentRequired !== null) {
    pr = typeof input.paymentRequired === 'string' ? decodeBase64Json(input.paymentRequired, 'paymentRequired') : input.paymentRequired;
  } else if (input.payment && typeof input.payment === 'object') {
    pr = { x402Version: 2, resource: { url: input.payment.resourceUrl || input.requestUrl || null }, accepts: [input.payment] };
  }
  if (!pr || typeof pr !== 'object') throw new PaymentValidationError('Provide "paymentRequired" (the PAYMENT-REQUIRED header or 402 body) or "payment" (a flattened quote)');
  const accepts = Array.isArray(pr.accepts) ? pr.accepts : null;
  if (!accepts || accepts.length === 0) throw new PaymentValidationError('The challenge has no accepts[] entries');
  if (accepts.length > MAX_ACCEPTS) throw new PaymentValidationError('The challenge has more than ' + MAX_ACCEPTS + ' accepts[] entries');
  const v = Number(pr.x402Version) || 1;
  const entries = accepts.map((a, i) => normalizeEntry(a, i, v));
  const resourceUrl = (pr.resource && typeof pr.resource === 'object' && typeof pr.resource.url === 'string' ? pr.resource.url : null) || entries.map((e) => e.resourceUrl).find(Boolean) || null;
  // Seller-controlled free text that agents tend to log, template or pass to tools.
  const texts = [];
  const addText = (field, value) => { if (typeof value === 'string' && value) texts.push({ field, value: value.slice(0, 4096) }); };
  if (pr.resource && typeof pr.resource === 'object') addText('resource.description', pr.resource.description);
  addText('error', pr.error);
  entries.forEach((e, i) => {
    for (const [k, val] of Object.entries(e.extra)) addText('accepts[' + i + '].extra.' + k, val);
    addText('accepts[' + i + '].description', accepts[i].description);
  });
  return { x402Version: v, resourceUrl, description: pr.resource && pr.resource.description ? String(pr.resource.description).slice(0, 200) : null, entries, texts };
}

// ---------- amounts ----------

function toAtomic(human, decimals) {
  const s = String(human).trim();
  if (!/^\d+(\.\d+)?$/.test(s)) return null;
  const [int, frac = ''] = s.split('.');
  const padded = (frac + '0'.repeat(decimals)).slice(0, decimals);
  return BigInt(int + padded).toString();
}

function formatAtomic(atomic, decimals) {
  if (decimals === null || decimals === undefined) return String(atomic);
  const s = String(atomic).padStart(decimals + 1, '0');
  const int = s.slice(0, s.length - decimals);
  const frac = s.slice(s.length - decimals).replace(/0+$/, '');
  return frac ? int + '.' + frac : int;
}

function assetMeta(chainId, asset) {
  if (!chainId || !asset) return null;
  const lower = asset.toLowerCase();
  const canonical = SETTLEMENT_ASSETS[chainId] && SETTLEMENT_ASSETS[chainId][lower];
  if (canonical) return Object.assign({ address: asset, canonical: true, source: 'x402-settlement' }, canonical);
  const tok = registry.lookupToken(chainId, asset);
  if (tok) return { address: asset, symbol: tok.symbol, decimals: tok.decimals, canonical: STABLE_SYMBOLS.has(String(tok.symbol).toUpperCase()), source: 'registry' };
  return null;
}

function canonicalLookalike(chainId, asset) {
  const pools = [SETTLEMENT_ASSETS[chainId] || {}, registry.KNOWN_TOKENS[chainId] || {}];
  for (const pool of pools) {
    for (const [addr, meta] of Object.entries(pool)) {
      if (registry.isLookalike(asset, addr)) return Object.assign({ address: addr }, meta);
    }
  }
  return null;
}

/** Shell syntax inside a URL. Template placeholders such as /ping/{symbol} and matrix params such as ;v=1 stay allowed. */
const URL_SHELL_PATTERNS = [
  { re: /[|`]/, what: 'pipe or backtick' },
  { re: /\$[({]/, what: 'command or variable substitution' },
  { re: /\{[^{}\/]*,[^{}\/]*\}/, what: 'brace expansion' },
  { re: /;(?![A-Za-z0-9_.-]*=)/, what: 'command separator' },
  { re: /&&/, what: 'command chaining' },
  { re: /[<>]/, what: 'redirection' },
  { re: /[\s\u0000-\u001f\u007f]/, what: 'whitespace or control character' },
];
function urlShellSyntax(url) {
  // Raw string only: percent-encoded characters (%7C, %20, %3B) are inert in a shell and common in query values.
  if (typeof url !== 'string' || !url) return null;
  for (const p of URL_SHELL_PATTERNS) {
    const m = url.match(p.re);
    if (m) return { what: p.what, at: url.slice(Math.max(0, m.index - 12), m.index + 28) };
  }
  return null;
}

/** Shell payloads inside free-text challenge fields (names, descriptions). Plain punctuation stays allowed. */
const TEXT_SHELL_PATTERNS = [
  { re: /\$\(|\$\{|`/, what: 'command substitution or backtick' },
  { re: /['"]\s*;/, what: 'quote break followed by a command separator' },
  { re: /[;&|]\s*(?:curl|wget|bash|sh|zsh|nc|ncat|python3?|node|perl|rm|base64|eval|exec|printf)\b/i, what: 'chained shell command' },
  { re: /\{(?:curl|wget|bash|sh|base64|nc|python3?|printf),/i, what: 'brace-expanded shell command' },
];
function textShellSyntax(text) {
  for (const p of TEXT_SHELL_PATTERNS) {
    const m = text.match(p.re);
    if (m) return { what: p.what, at: text.slice(Math.max(0, m.index - 12), m.index + 28) };
  }
  return null;
}

/** Quote seller-controlled text safely inside a message: short, single line, no control characters. */
function quoteUntrusted(text, max) {
  const s = String(text).replace(/[\u0000-\u001f\u007f]/g, ' ');
  return JSON.stringify(s.length > (max || 32) ? s.slice(0, max || 32) + '…' : s);
}

/** Host of an absolute http(s) URL only; mcp://… and relative resource ids have no comparable host. */
const STRONG_HOST_PATTERNS = new Set(['brand_impersonation', 'typosquatting', 'punycode', 'ip_address_host']);

function httpHostOf(url) {
  return typeof url === 'string' && /^https?:\/\//i.test(url.trim()) ? hostOf(url.trim()) : null;
}

function hostOf(url) {
  if (typeof url !== 'string' || !url) return null;
  const d = contextAnalyzer.extractDomain(url.includes('://') ? url : 'https://' + url);
  return d && d.kind === 'url' ? d.domain : null;
}

// ---------- signed payload ----------

function decodeSigned(raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  const obj = typeof raw === 'string' ? decodeBase64Json(raw, 'paymentSignature') : raw;
  if (!obj || typeof obj !== 'object') throw new PaymentValidationError('"paymentSignature" must decode to an object');
  const v = Number(obj.x402Version) || 1;
  const accepted = obj.accepted && typeof obj.accepted === 'object' ? obj.accepted : null;
  const payload = obj.payload && typeof obj.payload === 'object' ? obj.payload : {};
  return {
    x402Version: v,
    accepted,
    scheme: accepted ? accepted.scheme : obj.scheme,
    network: accepted ? accepted.network : obj.network,
    authorization: payload.authorization && typeof payload.authorization === 'object' ? payload.authorization : null,
    permit2: payload.permit2Authorization && typeof payload.permit2Authorization === 'object' ? payload.permit2Authorization : null,
    signature: typeof payload.signature === 'string' ? payload.signature : null,
  };
}

function eqAddr(a, b) {
  return typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
}

function big(x) {
  try { return BigInt(String(x)); } catch { return null; }
}

function checkSigned(signed, entry, ctx, nowSec) {
  const out = [];
  if (!signed) return out;
  if (signed.accepted) {
    const diffs = [];
    const acc = normalizeEntry(signed.accepted, entry.index, signed.x402Version);
    if (!eqAddr(acc.payTo, entry.payTo)) diffs.push('payTo');
    if (acc.amount !== entry.amount) diffs.push('amount');
    if (!eqAddr(acc.asset, entry.asset)) diffs.push('asset');
    if (acc.network !== entry.network) diffs.push('network');
    if (acc.scheme !== entry.scheme) diffs.push('scheme');
    if (diffs.length) out.push(finding('accepted_mismatch', 'The signed payload accepted a different requirement than the challenge: ' + diffs.join(', ') + ' differ.', { fields: diffs }));
  }
  if (signed.network) {
    const sn = parseNetwork(signed.network);
    if (sn.network && entry.network && sn.network !== entry.network) out.push(finding('signed_network_mismatch', 'Signed for ' + sn.network + ' but the challenge settles on ' + entry.network + '.'));
  }
  const maxValidity = nowSec + (entry.maxTimeoutSeconds || 300) + VALIDITY_SLACK_SECONDS;
  if (signed.authorization) {
    const a = signed.authorization;
    if (!eqAddr(a.to, entry.payTo)) out.push(finding('signed_recipient_mismatch', 'authorization.to ' + short(a.to) + ' is not the challenge payTo ' + short(entry.payTo) + '.', { signedTo: a.to }));
    const value = big(a.value);
    if (value === null || value > BigInt(entry.amount)) out.push(finding('signed_amount_mismatch', 'authorization.value ' + a.value + ' exceeds the challenge amount ' + entry.amount + '.'));
    const vb = big(a.validBefore);
    const va = big(a.validAfter);
    if (vb !== null && vb <= BigInt(nowSec)) out.push(finding('signed_expired', 'authorization.validBefore is in the past.'));
    else if (vb !== null && vb > BigInt(maxValidity)) out.push(finding('signed_validity_too_long', 'authorization.validBefore is ' + (Number(vb) - nowSec) + ' s away; the challenge allows ' + (entry.maxTimeoutSeconds || 300) + ' s.'));
    if (va !== null && va > BigInt(nowSec + 60)) out.push(finding('signed_expired', 'authorization.validAfter is in the future; the payment is not usable yet.'));
    if (ctx.from && a.from && !eqAddr(a.from, ctx.from)) out.push(finding('signed_payer_mismatch', 'authorization.from ' + short(a.from) + ' is not context.from ' + short(ctx.from) + '.'));
    const meta = assetMeta(entry.chainId, entry.asset);
    const name = entry.extra.name || (meta && meta.eip712Name);
    const version = entry.extra.version || (meta && meta.eip712Version);
    if (signed.signature && a.from && name && version && entry.chainId) {
      try {
        const recovered = verifyTypedData(
          { name, version, chainId: entry.chainId, verifyingContract: entry.asset },
          { TransferWithAuthorization: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' }] },
          { from: a.from, to: a.to, value: String(a.value), validAfter: String(a.validAfter), validBefore: String(a.validBefore), nonce: a.nonce },
          signed.signature,
        );
        if (!eqAddr(recovered, a.from)) out.push(finding('signature_does_not_recover', 'The signature recovers to ' + short(recovered) + ', not authorization.from ' + short(a.from) + '.'));
      } catch {
        out.push(finding('signature_does_not_recover', 'The EIP-3009 signature could not be verified against the challenge domain.'));
      }
    }
  }
  if (signed.permit2) {
    const p = signed.permit2;
    const expectedSpender = entry.scheme === 'upto' ? X402_UPTO_PERMIT2_PROXY : X402_EXACT_PERMIT2_PROXY;
    if (!eqAddr(p.spender, expectedSpender)) out.push(finding('signed_spender_not_x402_proxy', 'Permit2 spender ' + short(p.spender) + ' is not the canonical x402 ' + (entry.scheme === 'upto' ? 'upto' : 'exact') + ' proxy ' + short(expectedSpender) + '.', { spender: p.spender }));
    const token = p.permitted && p.permitted.token;
    if (!eqAddr(token, entry.asset)) out.push(finding('signed_token_mismatch', 'Permit2 permitted.token ' + short(token) + ' is not the challenge asset ' + short(entry.asset) + '.'));
    const amt = big(p.permitted && p.permitted.amount);
    if (amt === null || amt > BigInt(entry.amount)) out.push(finding('signed_amount_mismatch', 'Permit2 permitted.amount exceeds the challenge amount ' + entry.amount + '.'));
    const to = p.witness && p.witness.to;
    if (!eqAddr(to, entry.payTo)) out.push(finding('signed_recipient_mismatch', 'Permit2 witness.to ' + short(to) + ' is not the challenge payTo ' + short(entry.payTo) + '.', { signedTo: to }));
    const dl = big(p.deadline);
    if (dl !== null && dl <= BigInt(nowSec)) out.push(finding('signed_expired', 'Permit2 deadline is in the past.'));
    else if (dl !== null && dl > BigInt(maxValidity)) out.push(finding('signed_validity_too_long', 'Permit2 deadline is ' + (Number(dl) - nowSec) + ' s away; the challenge allows ' + (entry.maxTimeoutSeconds || 300) + ' s.'));
    if (ctx.from && p.from && !eqAddr(p.from, ctx.from)) out.push(finding('signed_payer_mismatch', 'Permit2 from ' + short(p.from) + ' is not context.from ' + short(ctx.from) + '.'));
  }
  return out;
}

// ---------- entry evaluation ----------

async function evaluateEntry(entry, input, deps, shared) {
  const findings = [];
  const expected = input.expected || {};
  const ctx = input.context || {};
  const chainKnown = entry.evm && entry.chainId && (supportedChainIds().includes(entry.chainId) || process.env['RPC_URL_' + entry.chainId] || SETTLEMENT_ASSETS[entry.chainId]);

  if (!entry.evm || !entry.chainId) {
    findings.push(finding('payment_network_unsupported', 'Network "' + entry.network + '" is not an EVM chain Guardian can inspect; only structural checks ran.'));
  } else if (!chainKnown) {
    findings.push(finding('payment_network_unsupported', 'Chain ' + entry.chainId + ' is not configured for on-chain checks.'));
  }

  if (!['exact', 'upto', 'aggr_deferred', 'period'].includes(entry.scheme)) findings.push(finding('unknown_payment_scheme', 'Scheme "' + entry.scheme + '" is not a known x402 scheme.'));
  if (entry.scheme === 'period') findings.push(finding('recurring_payment', 'This is a recurring (period) authorisation, not a one-off payment.'));
  if (entry.transferMethod === 'permit2' || entry.scheme === 'upto') findings.push(finding('permit2_approval_required', 'This entry settles through Permit2 (' + entry.scheme + ').'));
  if (entry.maxTimeoutSeconds !== null && entry.maxTimeoutSeconds > LONG_TIMEOUT_SECONDS) findings.push(finding('long_payment_timeout', 'maxTimeoutSeconds is ' + entry.maxTimeoutSeconds + ' (more than ' + LONG_TIMEOUT_SECONDS + ').'));

  // asset
  const meta = entry.evm ? assetMeta(entry.chainId, entry.asset) : null;
  if (meta && meta.testnet) findings.push(finding('testnet_payment', entry.network + ' is a testnet.'));
  if (entry.evm && entry.asset) {
    if (!meta) {
      const look = canonicalLookalike(entry.chainId, entry.asset);
      if (look) findings.push(finding('asset_lookalike', 'Asset ' + entry.asset + ' imitates ' + look.symbol + ' (' + look.address + ').', { imitates: look.address }));
      else findings.push(finding('unknown_settlement_asset', 'Asset ' + entry.asset + ' is not a recognised settlement stablecoin on ' + chainName(entry.chainId) + '.'));
    } else if (!meta.canonical) {
      findings.push(finding('unknown_settlement_asset', 'Asset ' + (meta.symbol || entry.asset) + ' is a known token but not a stablecoin normally used for x402 settlement.'));
    }
    if (meta && meta.eip712Name && entry.extra && entry.extra.name && (entry.extra.name !== meta.eip712Name || (entry.extra.version && String(entry.extra.version) !== meta.eip712Version))) {
      findings.push(finding('eip712_domain_mismatch', 'extra declares the EIP-712 domain name ' + quoteUntrusted(entry.extra.name) + ' version ' + (entry.extra.version === undefined ? '(none)' : quoteUntrusted(entry.extra.version, 12)) + ', but the ' + meta.symbol + ' contract on ' + chainName(entry.chainId) + ' uses name ' + JSON.stringify(meta.eip712Name) + ' version ' + JSON.stringify(meta.eip712Version) + (meta.eip712DomainSeparator ? ' (its DOMAIN_SEPARATOR ' + meta.eip712DomainSeparator.slice(0, 10) + '… matches only that pair)' : '') + '. A TransferWithAuthorization signed with the declared domain will not verify on-chain.', { declared: { name: String(entry.extra.name).slice(0, 64), version: entry.extra.version === undefined ? null : String(entry.extra.version).slice(0, 16) }, canonical: { name: meta.eip712Name, version: meta.eip712Version, domainSeparator: meta.eip712DomainSeparator || null } }));
    }
    const expectedToken = checksumOrNull(expected.feeToken || expected.asset);
    if (expectedToken && !eqAddr(expectedToken, entry.asset)) findings.push(finding('asset_mismatch_listing', 'Challenge asset ' + short(entry.asset) + ' differs from the listed token ' + short(expectedToken) + '.'));
  }
  const decimals = meta ? meta.decimals : Number.isInteger(expected.decimals) ? expected.decimals : null;

  // amount
  const amount = BigInt(entry.amount);
  let listedMax = null;
  if (typeof expected.maxAmount === 'string' && /^\d+$/.test(expected.maxAmount)) listedMax = BigInt(expected.maxAmount);
  else if (expected.feeAmount !== undefined && expected.feeAmount !== null && decimals !== null) {
    const atomic = toAtomic(typeof expected.feeAmount === 'number' ? expected.feeAmount.toFixed(Math.min(decimals, 18)) : expected.feeAmount, decimals);
    if (atomic !== null) listedMax = BigInt(atomic);
  }
  if (listedMax !== null && amount > listedMax) {
    if (entry.scheme === 'upto') findings.push(finding('upto_cap_above_listing', 'The upto cap ' + formatAtomic(entry.amount, decimals) + ' is above the listed price ' + formatAtomic(listedMax.toString(), decimals) + '.'));
    else findings.push(finding('amount_above_listing', 'Requested ' + formatAtomic(entry.amount, decimals) + ' but the listing price is ' + formatAtomic(listedMax.toString(), decimals) + ' (' + (Number(amount * 100n / (listedMax || 1n)) / 100) + 'x).', { requested: entry.amount, listed: listedMax.toString() }));
  }
  if (ctx.max_amount !== undefined && ctx.max_amount !== null && decimals !== null) {
    const cap = toAtomic(String(ctx.max_amount), decimals);
    if (cap !== null && amount > BigInt(cap)) findings.push(finding('amount_above_user_cap', 'Requested ' + formatAtomic(entry.amount, decimals) + ' exceeds the cap ' + ctx.max_amount + '.'));
  }

  // payee
  if (entry.evm && entry.payTo) {
    if (eqAddr(entry.payTo, ZERO)) findings.push(finding('payto_zero_address', 'payTo is the zero address.'));
    if (entry.asset && eqAddr(entry.payTo, entry.asset)) findings.push(finding('payto_is_asset', 'payTo is the token contract itself.'));
    const expectedPayTo = checksumOrNull(expected.payTo);
    if (expectedPayTo && !eqAddr(expectedPayTo, entry.payTo)) {
      if (registry.isLookalike(entry.payTo, expectedPayTo)) findings.push(finding('payto_poisoning', 'payTo ' + entry.payTo + ' imitates the listed provider wallet ' + expectedPayTo + '.', { imitates: expectedPayTo }));
      else findings.push(finding('payto_mismatch_listing', 'payTo ' + short(entry.payTo) + ' is not the listed provider wallet ' + short(expectedPayTo) + '.', { listed: expectedPayTo }));
    }
    const known = Array.isArray(ctx.known_addresses) ? ctx.known_addresses.filter((a) => checksumOrNull(a)) : [];
    const poisoned = known.find((k) => registry.isLookalike(entry.payTo, k));
    if (poisoned) findings.push(finding('payto_poisoning', 'payTo ' + entry.payTo + ' imitates your known address ' + poisoned + '.', { imitates: poisoned }));
    if (chainKnown) {
      const key = entry.chainId + ':' + entry.payTo.toLowerCase();
      if (!shared.payTo.has(key)) shared.payTo.set(key, quick.checkAddress({ address: entry.payTo, chainId: entry.chainId, role: 'recipient' }, deps).catch((err) => ({ error: err.message })));
      const r = await shared.payTo.get(key);
      if (r && Array.isArray(r.details && r.details.findings)) for (const f of r.details.findings) findings.push(Object.assign({}, f, { subject: 'payTo' }));
      entry.payToCheck = r && r.details ? { verdict: r.verdict, summary: r.summary, reputation: r.details.reputation, scam_database: r.details.scam_database, threat: r.details.threat } : null;
    }
    if (chainKnown && entry.asset && !(meta && meta.canonical)) {
      const key = entry.chainId + ':' + entry.asset.toLowerCase();
      if (!shared.asset.has(key)) shared.asset.set(key, quick.checkAddress({ address: entry.asset, chainId: entry.chainId, role: 'contract' }, deps).catch((err) => ({ error: err.message })));
      const r = await shared.asset.get(key);
      if (r && r.details) {
        for (const f of r.details.findings || []) {
          if (f.code === 'calldata_to_eoa') findings.push(finding('asset_not_contract', 'Asset ' + entry.asset + ' has no contract code.'));
          else if (f.code !== 'rpc_unavailable' || !findings.some((x) => x.code === 'rpc_unavailable')) findings.push(Object.assign({}, f, { subject: 'asset' }));
        }
      }
    }
  }

  const nowSec = Math.floor((deps.now ? Number(deps.now) : Date.now()) / 1000);
  for (const f of checkSigned(shared.signed && shared.signedEntryIndex === entry.index ? shared.signed : null, entry, ctx, nowSec)) findings.push(f);

  const verdict = verdictOf(findings);
  return {
    index: entry.index,
    verdict,
    reasons: Array.from(new Set(findings.map((f) => f.code))),
    scheme: entry.scheme,
    network: entry.network,
    chainId: entry.chainId,
    chain: entry.chainId ? chainName(entry.chainId) : null,
    asset: entry.asset ? { address: entry.asset, symbol: meta ? meta.symbol : null, decimals, canonical: Boolean(meta && meta.canonical) } : null,
    amount: { atomic: entry.amount, human: decimals !== null ? formatAtomic(entry.amount, decimals) : null, listed: listedMax !== null ? listedMax.toString() : null },
    payTo: entry.payTo,
    payToCheck: entry.payToCheck || null,
    maxTimeoutSeconds: entry.maxTimeoutSeconds,
    findings,
  };
}

/** Differences between normalized entries and a second, raw accepts[] list, index by index. */
function acceptsDiff(entries, otherRaw, v) {
  const diffs = [];
  if (otherRaw.length !== entries.length) diffs.push('accepts[] has ' + entries.length + ' entries, the other copy has ' + otherRaw.length);
  const n = Math.min(entries.length, otherRaw.length);
  for (let i = 0; i < n; i++) {
    const a = entries[i];
    let b;
    try { b = normalizeEntry(otherRaw[i], i, v); } catch (err) { diffs.push('accepts[' + i + '] in the other copy is invalid (' + err.message + ')'); continue; }
    const label = 'accepts[' + i + '].';
    if (!eqAddr(a.payTo, b.payTo)) diffs.push(label + 'payTo ' + a.payTo + ' vs ' + b.payTo);
    if (a.amount !== b.amount) diffs.push(label + 'amount ' + a.amount + ' vs ' + b.amount);
    if (!eqAddr(a.asset, b.asset)) diffs.push(label + 'asset ' + a.asset + ' vs ' + b.asset);
    if (a.network !== b.network) diffs.push(label + 'network ' + a.network + ' vs ' + b.network);
    if (a.scheme !== b.scheme) diffs.push(label + 'scheme ' + quoteUntrusted(a.scheme, 24) + ' vs ' + quoteUntrusted(b.scheme, 24));
    for (const k of ['name', 'version']) {
      if (String(a.extra[k] === undefined ? '' : a.extra[k]) !== String(b.extra[k] === undefined ? '' : b.extra[k])) diffs.push(label + 'extra.' + k + ' ' + quoteUntrusted(a.extra[k] === undefined ? '' : a.extra[k], 32) + ' vs ' + quoteUntrusted(b.extra[k] === undefined ? '' : b.extra[k], 32));
    }
  }
  return diffs;
}

function pickSignedEntry(signed, entries) {
  if (!signed) return null;
  if (signed.accepted) {
    const acc = signed.accepted;
    const hit = entries.find((e) => eqAddr(e.payTo, acc.payTo) && String(acc.amount || acc.maxAmountRequired) === e.amount && eqAddr(e.asset, acc.asset));
    if (hit) return hit.index;
  }
  const to = (signed.authorization && signed.authorization.to) || (signed.permit2 && signed.permit2.witness && signed.permit2.witness.to);
  const hit = entries.find((e) => eqAddr(e.payTo, to));
  return hit ? hit.index : entries[0].index;
}

/**
 * POST /check-payment
 */
async function checkPayment(input, deps) {
  deps = deps || {};
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new PaymentValidationError('Request body must be a JSON object');
  if (input.expected !== undefined && (input.expected === null || typeof input.expected !== 'object')) throw new PaymentValidationError('"expected" must be an object');
  if (input.context !== undefined && (input.context === null || typeof input.context !== 'object')) throw new PaymentValidationError('"context" must be an object');
  const challenge = normalizeChallenge(input);
  const expected = input.expected || {};
  const store = deps.store || getStore(deps.env);
  const qdeps = { reader: deps.reader, store, env: deps.env, now: deps.now, reporter: deps.reporter, skipStats: true };

  let selectedIndex = null;
  if (input.selectedIndex !== undefined && input.selectedIndex !== null) {
    const n = Number(input.selectedIndex);
    if (!Number.isInteger(n) || n < 0 || n >= challenge.entries.length) throw new PaymentValidationError('"selectedIndex" must point at an accepts[] entry (0..' + (challenge.entries.length - 1) + ')');
    selectedIndex = n;
  }

  const signed = decodeSigned(input.paymentSignature);
  const shared = { payTo: new Map(), asset: new Map(), signed, signedEntryIndex: signed ? (selectedIndex !== null ? selectedIndex : pickSignedEntry(signed, challenge.entries)) : null };

  // challenge-wide findings (domain, payees)
  const global = [];
  const requestHost = hostOf(input.requestUrl);
  const resourceHost = httpHostOf(challenge.resourceUrl);
  const listedHost = hostOf(expected.endpoint);
  const payHost = requestHost || resourceHost;
  // Exact host, not registrable domain: hosting platforms (vercel.app, onrender.com, sslip.io, workers.dev…)
  // give every customer a subdomain, so a copycat endpoint shares the listing's registrable domain.
  if (listedHost && payHost && listedHost !== payHost) {
    global.push(finding('payment_domain_mismatch', 'The 402 came from ' + payHost + ' but the listing endpoint is on ' + listedHost + '.', { listed: listedHost, observed: payHost }));
  }
  if (requestHost && resourceHost && contextAnalyzer.registrableDomain(requestHost) !== contextAnalyzer.registrableDomain(resourceHost)) {
    global.push(finding('resource_host_mismatch', 'resource.url is on ' + resourceHost + ' but the agent called ' + requestHost + '.'));
  }
  const urlSeen = new Set();
  for (const [label, u] of [['requestUrl', input.requestUrl], ['listed endpoint', expected.endpoint], ['resource.url', challenge.resourceUrl]]) {
    if (typeof u !== 'string' || urlSeen.has(u)) continue;
    urlSeen.add(u);
    const hit = urlShellSyntax(u);
    if (hit) global.push(finding('endpoint_url_injection', 'The ' + label + ' contains ' + hit.what + ' near ' + quoteUntrusted(hit.at, 48) + '. Agents that pass this URL to a shell would run attacker commands.', { subject: 'endpoint', url: u.slice(0, 300) }));
  }
  const fieldHits = challenge.texts.map((t) => ({ field: t.field, hit: textShellSyntax(t.value) })).filter((x) => x.hit);
  if (fieldHits.length) {
    global.push(finding('challenge_field_injection', 'The challenge carries a shell payload in ' + fieldHits.map((x) => x.field).join(', ') + ' (' + fieldHits[0].hit.what + ' near ' + quoteUntrusted(fieldHits[0].hit.at, 48) + '). Never log, template or pass these fields to a tool or shell.', { subject: 'challenge', fields: fieldHits.map((x) => x.field) }));
  }
  const calledUrl = input.requestUrl || expected.endpoint || null;
  if (typeof calledUrl === 'string' && /^http:\/\//i.test(calledUrl)) global.push(finding('insecure_payment_endpoint', calledUrl.slice(0, 120) + ' uses plain http.'));
  let domainCheck = null;
  if (payHost) {
    try {
      const d = await quick.checkDomain({ domain: payHost }, { store, env: deps.env, now: deps.now, skipStats: true });
      domainCheck = { host: payHost, verdict: d.verdict, reasons: d.reasons, summary: d.summary };
      const vouched = Boolean(listedHost && listedHost === payHost);
      for (const f of d.details.findings) {
        if (f.code === 'injection_pattern') {
          // Strong patterns imitate someone; weak ones (cheap TLD, keyword, deep subdomains) are common on real seller hosts.
          const strong = STRONG_HOST_PATTERNS.has(f.pattern);
          const why = payHost + ' matches a phishing pattern (' + f.pattern + '): ' + (d.details.pattern ? d.details.pattern.detail : f.message);
          if (vouched && strong) global.push(finding('endpoint_domain_suspicious', why + '. It is the endpoint named in the listing.', { subject: 'endpoint', pattern: f.pattern }));
          else if (!vouched && strong) global.push(finding('endpoint_phishing_pattern', why + '. No listing was supplied that names this host.', { subject: 'endpoint', pattern: f.pattern }));
          else if (!vouched) global.push(finding('endpoint_domain_suspicious', why + '. No listing was supplied that names this host.', { subject: 'endpoint', pattern: f.pattern }));
          else domainCheck.note = 'Weak host pattern (' + f.pattern + ') ignored because the listing names this endpoint.';
        } else {
          global.push(Object.assign({}, f, { subject: 'endpoint' }));
        }
      }
    } catch (err) {
      domainCheck = { host: payHost, error: err.message };
    }
  }
  const payees = new Set(challenge.entries.filter((e) => e.payTo).map((e) => e.payTo.toLowerCase()));
  if (payees.size > 1) global.push(finding('multiple_payees', 'accepts[] pays ' + payees.size + ' different recipients.'));
  if (input.bodyChallenge && typeof input.bodyChallenge === 'object' && Array.isArray(input.bodyChallenge.accepts)) {
    const diffs = acceptsDiff(challenge.entries, input.bodyChallenge.accepts, challenge.x402Version);
    if (diffs.length) {
      global.push(finding('challenge_header_body_mismatch', 'The ' + (input.bodyChallengeLabel || '402 body') + ' shows a different payment than the ' + (input.challengeLabel || 'PAYMENT-REQUIRED header') + ': ' + diffs.slice(0, 3).join('; ') + '.', { subject: 'challenge', diffs: diffs.slice(0, 10) }));
    }
  }
  // Findings computed by a caller that saw more than the challenge (for example an Onchain OS quote). Never taken from the request body.
  for (const f of Array.isArray(deps.extraFindings) ? deps.extraFindings : []) global.push(finding(f.code, f.message, f.extra));

  const evaluated = [];
  for (const entry of challenge.entries) {
    const entryDeps = deps.readerFor ? Object.assign({}, qdeps, { reader: deps.readerFor(entry.chainId) }) : qdeps;
    evaluated.push(await evaluateEntry(entry, input, entryDeps, shared));
  }

  // pick the entry the agent should pay: explicit selection, else safest then cheapest canonical
  let chosen;
  if (selectedIndex !== null) chosen = evaluated[selectedIndex];
  else {
    chosen = evaluated.slice().sort((a, b) => SEV[a.verdict] - SEV[b.verdict] || Number(Boolean(b.asset && b.asset.canonical)) - Number(Boolean(a.asset && a.asset.canonical)) || (BigInt(a.amount.atomic) < BigInt(b.amount.atomic) ? -1 : 1))[0];
  }
  const findings = global.concat(chosen.findings);
  const verdict = verdictOf(findings);
  const reasons = Array.from(new Set(findings.map((f) => f.code)));
  const amountText = chosen.amount.human !== null ? chosen.amount.human + ' ' + (chosen.asset && chosen.asset.symbol ? chosen.asset.symbol : 'tokens') + ' (' + chosen.amount.atomic + ')' : chosen.amount.atomic + ' atomic units';
  const summary = 'Payment of ' + amountText + ' on ' + (chosen.chain || chosen.network) + ' to ' + short(chosen.payTo) + (payHost ? ' for ' + payHost : '') + ' (accepts[' + chosen.index + '], ' + chosen.scheme + '). ' + (verdict === 'ALLOW' ? 'No risk rules triggered.' : verdict + ': ' + reasons.join(', ') + '.');
  const recommendations = reasons.filter((c) => RECOMMENDATIONS[c]).map((code) => ({ code, action: RECOMMENDATIONS[code] }));

  try {
    await stats.record(store, { now: deps.now, verdict, kind: deps.statsKind || 'check-payment', codes: reasons, sessionId: input.context && typeof input.context.session_id === 'string' ? input.context.session_id.slice(0, 128) : null });
  } catch { /* best-effort */ }

  return {
    verdict,
    reasons,
    risk_score: riskScore(findings),
    summary,
    recommendations,
    recommended_index: chosen.index,
    details: {
      x402Version: challenge.x402Version,
      resource: { url: challenge.resourceUrl, description: challenge.description },
      requestUrl: input.requestUrl || null,
      expected: Object.keys(expected).length ? expected : null,
      endpoint: domainCheck,
      signed: signed ? { scheme: signed.scheme || null, network: signed.network || null, checkedAgainstIndex: shared.signedEntryIndex, kind: signed.authorization ? 'eip3009' : signed.permit2 ? 'permit2' : 'unknown' } : null,
      selected: chosen,
      entries: evaluated.map((e) => ({ index: e.index, verdict: e.verdict, reasons: e.reasons, scheme: e.scheme, network: e.network, asset: e.asset, amount: e.amount, payTo: e.payTo })),
      global_findings: global,
      findings,
      shared_state: { backend: store.kind, persistent: store.persistent },
      analyzedAt: new Date().toISOString(),
    },
  };
}

/**
 * Verdict for an endpoint that must not be contacted because its URL is itself an attack.
 * Same response shape as checkPayment, without challenge details. Returns null when the URL is clean.
 */
function urlOnlyVerdict(url, label) {
  const hit = urlShellSyntax(url);
  if (!hit) return null;
  const f = finding('endpoint_url_injection', 'The ' + (label || 'endpoint URL') + ' contains ' + hit.what + ' near ' + quoteUntrusted(hit.at, 48) + '. Agents that pass this URL to a shell would run attacker commands. The endpoint was not contacted.', { subject: 'endpoint', url: String(url).slice(0, 300) });
  return {
    verdict: 'DENY',
    reasons: ['endpoint_url_injection'],
    risk_score: riskScore([f]),
    summary: 'Endpoint not contacted. DENY: endpoint_url_injection.',
    recommendations: [{ code: 'endpoint_url_injection', action: RECOMMENDATIONS.endpoint_url_injection }],
    recommended_index: null,
    details: { findings: [f], global_findings: [f], selected: null, entries: [], analyzedAt: new Date().toISOString() },
  };
}

module.exports = {
  checkPayment,
  urlOnlyVerdict,
  PAYMENT_RULES,
  PaymentValidationError,
  SETTLEMENT_ASSETS,
  X402_EXACT_PERMIT2_PROXY,
  X402_UPTO_PERMIT2_PROXY,
  PERMIT2,
  _internals: { normalizeChallenge, decodeSigned, parseNetwork, toAtomic, formatAtomic, assetMeta, urlShellSyntax, textShellSyntax, quoteUntrusted, acceptsDiff },
};
