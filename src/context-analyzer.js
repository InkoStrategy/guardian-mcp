'use strict';

/**
 * Context analyzer: agent-integrity layer on top of the transaction firewall.
 *
 * Three groups of deterministic signals:
 *   1. Intent verification   - does the transaction match the declared agent goal?
 *   2. Context analysis      - was the agent exposed to untrusted / phishing content?
 *   3. Runtime signals       - tool-call ordering and per-session accumulation.
 *
 * No network calls are made here. Everything is static pattern matching plus an
 * in-memory session store with TTL. Every public function is pure except the
 * session store, which is injectable for tests.
 */

const { DEFAULT_CHAINS } = require('./rpc');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default trusted domains when TRUSTED_DOMAINS env is unset. */
const DEFAULT_TRUSTED_DOMAINS = ['coingecko.com', 'api.etherscan.io'];

/** Official domains of well-known crypto brands. Anything impersonating these is phishing. */
const OFFICIAL_BRAND_DOMAINS = {
  okx: ['okx.com', 'okx.ai', 'oklink.com', 'xlayer.tech'],
  uniswap: ['uniswap.org'],
  metamask: ['metamask.io'],
  opensea: ['opensea.io'],
  etherscan: ['etherscan.io'],
  coinbase: ['coinbase.com'],
  binance: ['binance.com'],
  pancakeswap: ['pancakeswap.finance'],
  ledger: ['ledger.com'],
  trezor: ['trezor.io'],
  phantom: ['phantom.app', 'phantom.com'],
  coingecko: ['coingecko.com'],
  coinmarketcap: ['coinmarketcap.com'],
  aave: ['aave.com'],
  curve: ['curve.fi', 'curve.finance'],
  lido: ['lido.fi'],
  '1inch': ['1inch.io'],
  sushiswap: ['sushi.com'],
  arbitrum: ['arbitrum.io', 'arbitrum.foundation'],
  optimism: ['optimism.io'],
  polygon: ['polygon.technology'],
  chainlink: ['chain.link'],
  safe: ['safe.global'],
  rabby: ['rabby.io'],
  walletconnect: ['walletconnect.com', 'walletconnect.network'],
};

/** TLDs heavily abused for phishing. Matched against the registrable domain's TLD. */
const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'icu', 'click', 'buzz', 'cam',
  'monster', 'rest', 'quest', 'surf', 'fit', 'work', 'link', 'country', 'stream', 'download',
  'racing', 'win', 'bid', 'loan', 'men', 'party', 'review', 'trade', 'date', 'kim', 'cricket',
  'science', 'gdn', 'sbs', 'cfd', 'cyou', 'lol', 'pw',
]);

/** Phrases typical of wallet-drainer / credential-phishing hostnames. */
const PHISHING_KEYWORDS = [
  'airdrop', 'claim', 'reward', 'giveaway', 'bonus', 'wallet-connect', 'walletconnect-',
  'validate', 'validation', 'verify-wallet', 'restore', 'recovery', 'unlock', 'sync', 'migrate',
  'login', 'signin', 'secure', 'support', 'helpdesk', 'kyc', 'refund', 'staking-reward',
];

/** Homoglyph / leet substitutions used in typosquatting. */
const HOMOGLYPHS = { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b', '@': 'a', $: 's', '|': 'l' };

/** Two-level public suffixes so that registrable-domain extraction is correct for them. */
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.jp', 'co.kr', 'com.br',
  'com.cn', 'com.hk', 'com.sg', 'com.tw', 'co.in', 'co.za', 'com.mx', 'com.ar', 'com.tr', 'co.nz',
]);

/** Tool names that mean "the agent ingested external content". */
const INGEST_TOOLS = new Set(['web_fetch', 'read_file', 'fetch', 'browse', 'open_url', 'http_get', 'curl', 'web_search', 'read_url', 'download']);

/** Tool names that are the transaction itself or this very check; ignored when looking at "what ran just before". */
const TX_OR_CHECK_TOOLS = new Set(['analyze', 'guardian', 'guardian_mcp', 'security_check', 'swap', 'send', 'transfer', 'sign', 'broadcast', 'contract_call', 'execute', 'approve', 'wallet_send', 'transaction']);

/** Goal synonyms -> canonical intent. */
const GOAL_SYNONYMS = {
  swap: 'swap', 'swap tokens': 'swap', trade: 'swap', exchange: 'swap', buy: 'swap', sell: 'swap', convert: 'swap',
  transfer: 'transfer', send: 'transfer', pay: 'transfer', payment: 'transfer', withdraw: 'transfer',
  approve: 'approve', approval: 'approve', allowance: 'approve', permit: 'approve',
  mint: 'mint', minting: 'mint',
  read: 'read', analyze: 'read', analyse: 'read', analysis: 'read', research: 'read', inspect: 'read', query: 'read', monitor: 'read', 'read-only': 'read', readonly: 'read',
  unknown: null, '': null,
};

/** Selector name prefixes -> transaction intent for "known" call types. */
const KNOWN_FUNCTION_INTENT = [
  { test: /^(swap|exactInput|exactOutput|unoswap|transformERC20|execute\(|multicall)/i, intent: 'swap' },
  { test: /^mint/i, intent: 'mint' },
  { test: /^(addLiquidity|removeLiquidity)/i, intent: 'liquidity' },
  { test: /^(stake|unstake|deposit|withdraw|claim)/i, intent: 'defi' },
  { test: /^burn/i, intent: 'burn' },
  { test: /^(balanceOf|allowance)/i, intent: 'read' },
];

/** Which declared goals are compatible with which transaction intents. */
const COMPATIBLE_GOALS = {
  approve: new Set(['approve', 'swap']),
  approvalForAll: new Set(['approve']),
  transfer: new Set(['transfer']),
  native: new Set(['transfer']),
  swap: new Set(['swap']),
  mint: new Set(['mint']),
  liquidity: new Set(['swap', 'defi']),
  defi: new Set(['defi', 'transfer']),
  burn: new Set(['burn']),
  read: new Set(['read']),
};

const WRITE_KINDS_FOR_ESCALATION = new Set(['approve', 'approvalForAll', 'transfer', 'native']);

const DEFAULT_SESSION_TTL_MS = 3600000;
const MAX_SESSIONS = 10000;
const MAX_SOURCES = 100;
const MAX_TOOL_CALLS = 200;
const MAX_STRING = 2048;
const MAX_KNOWN_ADDRESSES = 500;
const MEMORY_POISONING_THRESHOLD = 3; // more than this many distinct untrusted domains per session

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

function officialRpcHosts() {
  const hosts = new Set();
  for (const chain of Object.values(DEFAULT_CHAINS)) {
    for (const url of chain.rpcs) {
      try {
        hosts.add(new URL(url).hostname.toLowerCase());
      } catch {
        /* ignore malformed defaults */
      }
    }
  }
  return Array.from(hosts);
}

/** Trusted-domain whitelist: env TRUSTED_DOMAINS (comma-separated) or defaults, plus official RPC hosts. */
function getTrustedDomains(env) {
  env = env || process.env;
  const raw = (env.TRUSTED_DOMAINS || '').trim();
  const configured = raw ? raw.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean) : DEFAULT_TRUSTED_DOMAINS.slice();
  const all = new Set(configured);
  for (const h of officialRpcHosts()) all.add(h);
  for (const list of Object.values(OFFICIAL_BRAND_DOMAINS)) for (const d of list) all.add(d);
  return { domains: Array.from(all).sort(), configured, source: raw ? 'env' : 'default' };
}

function getSessionTtlMs(env) {
  env = env || process.env;
  const n = Number.parseInt(env.SESSION_TTL_MS || '', 10);
  return Number.isInteger(n) && n > 0 ? n : DEFAULT_SESSION_TTL_MS;
}

function getLargeAmountRaw(env) {
  env = env || process.env;
  const raw = (env.LARGE_AMOUNT_RAW || '').trim();
  if (/^[0-9]+$/.test(raw)) return BigInt(raw);
  return 10n ** 18n;
}

const LARGE_NATIVE_WEI = 10n ** 17n; // 0.1 ETH-equivalent

// ---------------------------------------------------------------------------
// Domain utilities (pure)
// ---------------------------------------------------------------------------

function extractDomain(source) {
  if (typeof source !== 'string') return null;
  const s = source.trim();
  if (!s) return null;
  const lower = s.toLowerCase();
  if (lower === 'user input' || lower === 'user' || lower.startsWith('user:')) return null;
  if (lower.startsWith('api:')) {
    const name = lower.slice(4).trim().replace(/[^a-z0-9.-]/g, '');
    return name ? { domain: name, kind: 'api' } : null;
  }
  if (/^(file|read_file|memory|tool|env):/i.test(lower)) return null;
  let host = null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    try {
      host = new URL(s).hostname;
    } catch {
      return { domain: null, kind: 'malformed', raw: s.slice(0, 200) };
    }
  } else if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(\/.*)?$/i.test(s) || /^\d{1,3}(\.\d{1,3}){3}(:\d+)?(\/.*)?$/.test(s)) {
    host = s.split('/')[0].split(':')[0];
  } else {
    return null;
  }
  host = host.toLowerCase().replace(/\.$/, '');
  return host ? { domain: host, kind: 'url' } : null;
}

function isIpAddress(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^\[?[0-9a-f:]+\]?$/i.test(host) && host.includes(':');
}

function registrableDomain(host) {
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.has(lastTwo) && labels.length >= 3) return labels.slice(-3).join('.');
  return lastTwo;
}

function tldOf(host) {
  const parts = host.split('.');
  return parts[parts.length - 1];
}

function matchesTrusted(host, trustedList, kind) {
  if (kind === 'api') {
    // "api:coingecko" is trusted if a trusted domain has that label, e.g. coingecko.com
    return trustedList.some((t) => t === host || t.split('.').includes(host) || t.endsWith('.' + host));
  }
  return trustedList.some((t) => host === t || host.endsWith('.' + t));
}

function normalizeHomoglyphs(label) {
  return label
    .split('')
    .map((ch) => (HOMOGLYPHS[ch] !== undefined ? HOMOGLYPHS[ch] : ch))
    .join('')
    .replace(/[^a-z0-9]/g, '');
}

function levenshtein(a, b) {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = new Array(b.length + 1);
  let curr = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j += 1) prev[j] = j;
  for (let i = 1; i <= a.length; i += 1) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[b.length];
}

function isOfficialBrandDomain(host) {
  const reg = registrableDomain(host);
  for (const list of Object.values(OFFICIAL_BRAND_DOMAINS)) {
    for (const d of list) if (reg === d || host === d || host.endsWith('.' + d)) return true;
  }
  return false;
}

/**
 * Deterministic phishing classifier for a hostname.
 * @returns {null | {pattern: string, detail: string}}
 */
function detectPhishingPattern(host) {
  if (!host) return null;
  if (isIpAddress(host)) return { pattern: 'ip_address_host', detail: 'Content served from a bare IP address instead of a domain' };
  if (host.split('.').some((l) => l.startsWith('xn--'))) return { pattern: 'punycode', detail: 'Internationalised (punycode) hostname, a classic homoglyph-attack vector' };
  if (isOfficialBrandDomain(host)) return null;

  const reg = registrableDomain(host);
  const tld = tldOf(reg);
  const labels = host.split('.');
  const sld = reg.split('.')[0];

  // Brand name appearing anywhere in a non-official hostname (okx-airdrop.com, secure.metamask.io.login.xyz ...)
  for (const brand of Object.keys(OFFICIAL_BRAND_DOMAINS)) {
    for (const label of labels) {
      const norm = normalizeHomoglyphs(label);
      if (norm === brand || (norm.length >= 4 && norm.includes(brand))) {
        return { pattern: 'brand_impersonation', detail: 'Hostname contains the brand "' + brand + '" but is not an official ' + brand + ' domain' };
      }
      if (label.includes('-')) {
        for (const piece of label.split('-')) {
          if (normalizeHomoglyphs(piece) === brand) {
            return { pattern: 'brand_impersonation', detail: 'Hostname contains the brand "' + brand + '" but is not an official ' + brand + ' domain' };
          }
        }
      }
    }
    // Typosquatting on the registrable label: uniswop.org, metamsk.io, coinbse.com
    const normSld = normalizeHomoglyphs(sld);
    if (brand.length >= 5 && normSld.length >= 4) {
      const maxDist = brand.length >= 8 ? 2 : 1;
      if (normSld !== brand && levenshtein(normSld, brand) <= maxDist) {
        return { pattern: 'typosquatting', detail: 'Registrable label "' + sld + '" is within edit distance ' + maxDist + ' of the brand "' + brand + '"' };
      }
    }
  }

  if (SUSPICIOUS_TLDS.has(tld)) return { pattern: 'suspicious_tld', detail: 'Top-level domain ".' + tld + '" is heavily abused for phishing' };

  const hostForKeywords = host.replace(/\./g, '-');
  for (const kw of PHISHING_KEYWORDS) {
    if (hostForKeywords.includes(kw)) return { pattern: 'phishing_keyword', detail: 'Hostname contains the phishing keyword "' + kw + '"' };
  }
  if (labels.length >= 5) return { pattern: 'deep_subdomain', detail: 'Hostname has ' + labels.length + ' labels; deep subdomain chains are used to hide the real domain' };
  return null;
}

// ---------------------------------------------------------------------------
// Session store (in-memory, TTL, bounded)
// ---------------------------------------------------------------------------

function createSessionStore(opts) {
  opts = opts || {};
  const ttlMs = opts.ttlMs || getSessionTtlMs(opts.env);
  const maxSessions = opts.maxSessions || MAX_SESSIONS;
  const sessions = new Map(); // sessionId -> { entries: [{domain, ts}], lastSeen }

  function prune(entry, now) {
    entry.entries = entry.entries.filter((e) => now - e.ts <= ttlMs);
  }

  function evictIfNeeded(now) {
    if (sessions.size <= maxSessions) return;
    // Drop expired sessions first, then the oldest by lastSeen.
    for (const [id, entry] of sessions) if (now - entry.lastSeen > ttlMs) sessions.delete(id);
    while (sessions.size > maxSessions) {
      let oldestId = null;
      let oldestSeen = Infinity;
      for (const [id, entry] of sessions) if (entry.lastSeen < oldestSeen) { oldestSeen = entry.lastSeen; oldestId = id; }
      if (oldestId === null) break;
      sessions.delete(oldestId);
    }
  }

  return {
    ttlMs,
    /** Record untrusted domains for a session and return the distinct set still inside the TTL window. */
    record(sessionId, domains, now) {
      now = now === undefined ? Date.now() : now;
      let entry = sessions.get(sessionId);
      if (!entry) {
        entry = { entries: [], lastSeen: now };
        sessions.set(sessionId, entry);
      }
      prune(entry, now);
      for (const d of domains) {
        if (!entry.entries.some((e) => e.domain === d)) entry.entries.push({ domain: d, ts: now });
        else entry.entries.find((e) => e.domain === d).ts = now;
      }
      entry.lastSeen = now;
      evictIfNeeded(now);
      return Array.from(new Set(entry.entries.map((e) => e.domain)));
    },
    peek(sessionId, now) {
      now = now === undefined ? Date.now() : now;
      const entry = sessions.get(sessionId);
      if (!entry) return [];
      prune(entry, now);
      return Array.from(new Set(entry.entries.map((e) => e.domain)));
    },
    size() {
      return sessions.size;
    },
    clear() {
      sessions.clear();
    },
  };
}

const defaultSessionStore = createSessionStore();

// ---------------------------------------------------------------------------
// Context validation (throws plain Error; analyzer wraps into ValidationError)
// ---------------------------------------------------------------------------

function validateContext(context) {
  if (context === undefined || context === null) return null;
  if (typeof context !== 'object' || Array.isArray(context)) throw new Error('"context" must be a JSON object');
  const out = {};
  if (context.agent_goal !== undefined && context.agent_goal !== null) {
    if (typeof context.agent_goal !== 'string') throw new Error('"context.agent_goal" must be a string');
    out.agent_goal = context.agent_goal.slice(0, MAX_STRING);
  }
  for (const key of ['recent_sources', 'recent_tool_calls']) {
    if (context[key] === undefined || context[key] === null) continue;
    if (!Array.isArray(context[key])) throw new Error('"context.' + key + '" must be an array of strings');
    const limit = key === 'recent_sources' ? MAX_SOURCES : MAX_TOOL_CALLS;
    if (context[key].length > limit) throw new Error('"context.' + key + '" may contain at most ' + limit + ' items');
    out[key] = context[key].map((v) => {
      if (typeof v !== 'string') throw new Error('"context.' + key + '" must contain only strings');
      return v.slice(0, MAX_STRING);
    });
  }
  if (context.session_id !== undefined && context.session_id !== null) {
    if (typeof context.session_id !== 'string' || context.session_id.length === 0 || context.session_id.length > 128) {
      throw new Error('"context.session_id" must be a non-empty string of at most 128 characters');
    }
    out.session_id = context.session_id;
  }
  if (context.intent_match !== undefined && context.intent_match !== null) {
    if (typeof context.intent_match !== 'boolean') throw new Error('"context.intent_match" must be a boolean');
    out.intent_match = context.intent_match;
  }
  if (context.known_addresses !== undefined && context.known_addresses !== null) {
    if (!Array.isArray(context.known_addresses)) throw new Error('"context.known_addresses" must be an array of EVM addresses');
    if (context.known_addresses.length > MAX_KNOWN_ADDRESSES) throw new Error('"context.known_addresses" may contain at most ' + MAX_KNOWN_ADDRESSES + ' items');
    out.known_addresses = context.known_addresses.map((a) => {
      if (typeof a !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(a)) throw new Error('"context.known_addresses" must contain only 0x-prefixed EVM addresses');
      return a.toLowerCase();
    });
  }
  if (context.expected_amount !== undefined && context.expected_amount !== null) {
    const s = String(context.expected_amount).trim();
    if (!/^[0-9]+(\.[0-9]+)?$/.test(s) || s.length > 40) throw new Error('"context.expected_amount" must be a decimal number in human token units, e.g. "1500.25"');
    out.expected_amount = s;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Intent helpers
// ---------------------------------------------------------------------------

function normalizeGoal(goal) {
  if (typeof goal !== 'string') return null;
  const g = goal.trim().toLowerCase();
  if (Object.prototype.hasOwnProperty.call(GOAL_SYNONYMS, g)) return GOAL_SYNONYMS[g];
  for (const [key, val] of Object.entries(GOAL_SYNONYMS)) {
    if (key && g.split(/[\s_-]+/).includes(key)) return val;
  }
  return null;
}

/** Map decoded call info to a transaction intent label. */
function transactionIntent(decoded, value) {
  switch (decoded.kind) {
    case 'approve':
      return 'approve';
    case 'approvalForAll':
      return 'approvalForAll';
    case 'transfer':
      return 'transfer';
    case 'native':
      return value > 0n ? 'native' : 'noop';
    case 'known': {
      for (const rule of KNOWN_FUNCTION_INTENT) if (rule.test.test(decoded.function || '')) return rule.intent;
      return 'known';
    }
    default:
      return 'unknown';
  }
}

function intentMatches(goal, txIntent) {
  if (!goal) return null; // no declared goal -> nothing to compare
  if (txIntent === 'unknown' || txIntent === 'known' || txIntent === 'noop') return null; // cannot determine
  const compatible = COMPATIBLE_GOALS[txIntent];
  if (!compatible) return null;
  return compatible.has(goal);
}

function isLargeTransaction(decoded, value, largeRaw) {
  if (decoded.kind === 'approvalForAll' && decoded.args.approved) return { large: true, why: 'setApprovalForAll grants unlimited control' };
  if (decoded.kind === 'approve' && decoded.amountBig !== null) {
    if (decoded.amountBig > (2n ** 255n - 1n)) return { large: true, why: 'unlimited approval' };
    if (decoded.amountBig >= largeRaw) return { large: true, why: 'approval amount >= LARGE_AMOUNT_RAW (' + largeRaw.toString() + ')' };
  }
  if (decoded.kind === 'transfer' && decoded.amountBig !== null && decoded.amountBig >= largeRaw) {
    return { large: true, why: 'transfer amount >= LARGE_AMOUNT_RAW (' + largeRaw.toString() + ')' };
  }
  if (decoded.kind === 'native' && value >= LARGE_NATIVE_WEI) return { large: true, why: 'native value >= 0.1 (1e17 wei)' };
  return { large: false, why: null };
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

function finding(code, severity, message, extra) {
  return Object.assign({ code, severity, message, layer: 'context' }, extra || {});
}

/**
 * Run the agent-integrity rules.
 * @param {object} context validated context (from validateContext)
 * @param {object} decoded decoded calldata (analyzer.decodeCalldata shape)
 * @param {bigint} value native value in wei
 * @param {{env?:object, sessionStore?:object, now?:number}} [deps]
 * @returns {{findings: object[], intent_analysis: object, context_signals: object[], sources: object}}
 */
function analyzeContext(context, decoded, value, deps) {
  deps = deps || {};
  const env = deps.env || process.env;
  const store = deps.sessionStore || defaultSessionStore;
  const now = deps.now === undefined ? Date.now() : deps.now;
  const trusted = getTrustedDomains(env);
  const largeRaw = getLargeAmountRaw(env);
  const findings = [];

  // ---- Intent verification ----
  const goal = normalizeGoal(context.agent_goal);
  const txIntent = transactionIntent(decoded, value);
  const computedMatch = intentMatches(goal, txIntent);
  const callerMatch = context.intent_match === undefined ? null : context.intent_match;
  const intentAnalysis = {
    agent_goal: context.agent_goal === undefined ? null : context.agent_goal,
    normalized_goal: goal,
    transaction_intent: txIntent,
    computed_match: computedMatch,
    caller_intent_match: callerMatch,
    match: computedMatch === false || callerMatch === false ? false : computedMatch === null && callerMatch === null ? null : true,
  };

  const writeTx = WRITE_KINDS_FOR_ESCALATION.has(txIntent);

  if (goal === 'read' && writeTx) {
    findings.push(finding('goal_escalation', 'DENY', 'Agent goal is read-only ("' + context.agent_goal + '") but the transaction performs a ' + txIntent + '. A read/analyze agent must never sign approvals or transfers.', { agent_goal: context.agent_goal, transaction_intent: txIntent }));
  } else if (computedMatch === false) {
    findings.push(finding('intent_mismatch', 'WARN', 'Declared agent goal "' + context.agent_goal + '" (' + goal + ') does not match the transaction intent "' + txIntent + '".', { agent_goal: context.agent_goal, transaction_intent: txIntent }));
  } else if (callerMatch === false) {
    findings.push(finding('intent_mismatch', 'WARN', 'Caller declared intent_match=false: the transaction was flagged by the agent itself as not matching its goal.', { agent_goal: context.agent_goal === undefined ? null : context.agent_goal, transaction_intent: txIntent, declared_by_caller: true }));
  }
  const mismatch = intentAnalysis.match === false;

  // ---- Source classification ----
  const sources = { trusted: [], untrusted: [], phishing: [], ignored: [] };
  const seen = new Set();
  for (const raw of context.recent_sources || []) {
    const parsed = extractDomain(raw);
    if (!parsed) {
      sources.ignored.push(raw);
      continue;
    }
    if (parsed.kind === 'malformed') {
      sources.untrusted.push({ source: raw, domain: null, reason: 'malformed URL' });
      continue;
    }
    const key = parsed.kind + ':' + parsed.domain;
    if (seen.has(key)) continue;
    seen.add(key);
    if (matchesTrusted(parsed.domain, trusted.domains, parsed.kind)) {
      sources.trusted.push({ source: raw, domain: parsed.domain });
      continue;
    }
    const phishing = parsed.kind === 'url' ? detectPhishingPattern(parsed.domain) : null;
    if (phishing) sources.phishing.push({ source: raw, domain: parsed.domain, pattern: phishing.pattern, detail: phishing.detail });
    else sources.untrusted.push({ source: raw, domain: parsed.domain, reason: 'not in trusted list' });
  }

  // ---- injection_pattern (DENY) ----
  if (sources.phishing.length > 0) {
    findings.push(finding('injection_pattern', 'DENY', 'Agent recently consumed content from ' + sources.phishing.length + ' hostname(s) matching phishing patterns: ' + sources.phishing.map((p) => p.domain + ' [' + p.pattern + ']').join(', ') + '. Treat the current instruction stream as compromised.', { sources: sources.phishing }));
  }

  // ---- untrusted_source_before_tx (WARN / DENY) ----
  const untrustedAll = sources.untrusted.concat(sources.phishing);
  const sensitiveTx = txIntent === 'approve' || txIntent === 'approvalForAll' || txIntent === 'transfer' || txIntent === 'native';
  if (untrustedAll.length > 0 && sensitiveTx) {
    const size = isLargeTransaction(decoded, value, largeRaw);
    const severity = size.large ? 'DENY' : 'WARN';
    findings.push(finding('untrusted_source_before_tx', severity, 'Agent consumed ' + untrustedAll.length + ' untrusted source(s) (' + untrustedAll.map((u) => u.domain || u.source).join(', ') + ') before a ' + txIntent + (size.large ? ' with a large amount (' + size.why + ')' : '') + '. Instructions from untrusted content may be driving this transaction.', { sources: untrustedAll.map((u) => u.domain || u.source), large_amount: size.large, large_reason: size.why }));
  }

  // ---- rapid_context_shift (WARN) ----
  const calls = (context.recent_tool_calls || []).map((c) => String(c).trim().toLowerCase());
  let lastRelevant = null;
  for (let i = calls.length - 1; i >= 0; i -= 1) {
    if (!TX_OR_CHECK_TOOLS.has(calls[i])) {
      lastRelevant = calls[i];
      break;
    }
  }
  const ingestedBefore = lastRelevant !== null && INGEST_TOOLS.has(lastRelevant);
  if (ingestedBefore && mismatch) {
    findings.push(finding('rapid_context_shift', 'WARN', 'The agent ingested external content ("' + lastRelevant + '") immediately before this transaction and the transaction does not match its declared goal. This is the signature of an instruction injected by that content.', { last_tool_call: lastRelevant, transaction_intent: txIntent }));
  }

  // ---- memory_poisoning_signal (WARN) ----
  let sessionDomains = null;
  if (context.session_id) {
    const newDomains = untrustedAll.map((u) => u.domain).filter(Boolean);
    sessionDomains = store.record(context.session_id, newDomains, now);
    if (sessionDomains.length > MEMORY_POISONING_THRESHOLD) {
      findings.push(finding('memory_poisoning_signal', 'WARN', 'Session ' + context.session_id + ' has consumed ' + sessionDomains.length + ' distinct untrusted domains within the last ' + Math.round(store.ttlMs / 60000) + ' minutes (' + sessionDomains.join(', ') + '). Accumulated untrusted context can poison agent memory.', { session_id: context.session_id, distinct_untrusted_domains: sessionDomains.length, domains: sessionDomains }));
    }
  }

  return {
    findings,
    intent_analysis: intentAnalysis,
    context_signals: findings.map((f) => ({ code: f.code, severity: f.severity, message: f.message })),
    sources: {
      trusted: sources.trusted.map((s) => s.domain),
      untrusted: sources.untrusted.map((s) => s.domain || s.source),
      phishing: sources.phishing,
      ignored: sources.ignored,
      session_untrusted_domains: sessionDomains,
      last_tool_call: lastRelevant,
    },
  };
}

const CONTEXT_RULES = [
  { code: 'intent_mismatch', severity: 'WARN', layer: 'intent', description: 'Declared agent_goal does not match the decoded transaction intent, or the caller set intent_match=false.' },
  { code: 'goal_escalation', severity: 'DENY', layer: 'intent', description: 'agent_goal is read/analyze but the transaction is an approve, setApprovalForAll, token transfer or native transfer.' },
  { code: 'untrusted_source_before_tx', severity: 'WARN|DENY', layer: 'context', description: 'recent_sources contains domains outside the trusted list and the transaction is an approve/transfer. DENY when the amount is large (unlimited approval, setApprovalForAll, >= LARGE_AMOUNT_RAW, or native >= 0.1).' },
  { code: 'injection_pattern', severity: 'DENY', layer: 'context', description: 'recent_sources contains a hostname matching phishing patterns: brand impersonation, typosquatting, homoglyphs, punycode, suspicious TLD, phishing keywords, bare IP, deep subdomain chain.' },
  { code: 'rapid_context_shift', severity: 'WARN', layer: 'runtime', description: 'The last tool call before the transaction was an ingest tool (web_fetch, read_file, ...) and the transaction does not match agent_goal.' },
  { code: 'memory_poisoning_signal', severity: 'WARN', layer: 'runtime', description: 'More than 3 distinct untrusted domains were consumed in the same session_id within SESSION_TTL_MS.' },
  { code: 'context_analysis_failed', severity: 'WARN', layer: 'runtime', description: 'The context analyzer threw an unexpected error. Fail-safe: verdict is at least WARN.' },
];

module.exports = {
  analyzeContext,
  validateContext,
  createSessionStore,
  defaultSessionStore,
  getTrustedDomains,
  getSessionTtlMs,
  getLargeAmountRaw,
  extractDomain,
  detectPhishingPattern,
  registrableDomain,
  normalizeGoal,
  transactionIntent,
  CONTEXT_RULES,
  SUSPICIOUS_TLDS,
  PHISHING_KEYWORDS,
  OFFICIAL_BRAND_DOMAINS,
  DEFAULT_TRUSTED_DOMAINS,
};
