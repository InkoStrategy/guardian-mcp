'use strict';

/**
 * Shared threat registry + address reputation.
 *
 * Every DENY that is attributable to a counterparty address by on-chain facts
 * and calldata alone is recorded anonymously: chainId, address, selector,
 * rule code, timestamp. Nothing about the caller (from, session, IP) is stored;
 * a salted, truncated reporter fingerprint is kept only to count distinct
 * reporters so a single spammer cannot promote an address to "drainer".
 *
 * Rules that depend on caller-supplied context (address_poisoning, goal_*,
 * injection_pattern with agent-declared sources) are never recorded, because a
 * malicious caller could otherwise poison the registry against innocent
 * addresses. Addresses present in the built-in contract/token registry are
 * never flagged either.
 */

const crypto = require('crypto');
const { getStore, hashToObject } = require('./store');
const registry = require('./registry');

const RECORDABLE_ADDRESS_RULES = {
  approval_to_eoa: 'spender',
  contract_lookalike: 'address',
  permit_spender_mismatch: 'spender',
  permit2_pull_to_third_party: 'recipient',
  permit2_domain_mismatch: 'verifyingContract',
  verifying_contract_is_eoa: 'address',
};

const RECORDABLE_DOMAIN_RULES = new Set(['siwe_phishing_domain', 'phishing_url_in_message']);

const DEFAULTS = {
  THREAT_WARN_REPORTS: 1,
  THREAT_DENY_REPORTS: 3,
  THREAT_DENY_REPORTERS: 2,
  THREAT_TTL_DAYS: 90,
};

function cfg(env) {
  env = env || process.env;
  const n = (k) => {
    const v = Number.parseInt(env[k] || '', 10);
    return Number.isInteger(v) && v > 0 ? v : DEFAULTS[k];
  };
  return { warnReports: n('THREAT_WARN_REPORTS'), denyReports: n('THREAT_DENY_REPORTS'), denyReporters: n('THREAT_DENY_REPORTERS'), ttlSeconds: n('THREAT_TTL_DAYS') * 86400 };
}

function addrKey(chainId, address) {
  return 'threat:addr:' + chainId + ':' + String(address).toLowerCase();
}
function domainKey(host) {
  return 'threat:domain:' + String(host).toLowerCase();
}

/** Daily-salted, truncated fingerprint. Not reversible, rotates every day. */
function reporterFingerprint(reporter, env) {
  const salt = (env || process.env).THREAT_SALT || 'guardian';
  const day = new Date().toISOString().slice(0, 10);
  return crypto.createHash('sha256').update(salt + '|' + day + '|' + String(reporter || 'anon')).digest('hex').slice(0, 16);
}

function parseRecord(flat) {
  const h = hashToObject(flat);
  if (!h || Object.keys(h).length === 0) return null;
  const rules = {};
  const selectors = {};
  for (const [k, v] of Object.entries(h)) {
    if (k.startsWith('rule:')) rules[k.slice(5)] = Number(v);
    if (k.startsWith('sel:')) selectors[k.slice(4)] = Number(v);
  }
  return { reports: Number(h.reports || 0), first_seen: Number(h.first_seen || 0), last_seen: Number(h.last_seen || 0), rules, selectors };
}

/**
 * Look up several addresses (same chain) and domains in one pipeline.
 * @returns {Promise<{addresses: Object<string, object>, domains: Object<string, object>}>}
 */
async function lookup(store, chainId, addresses, domains) {
  addresses = Array.from(new Set((addresses || []).map((a) => String(a).toLowerCase())));
  domains = Array.from(new Set((domains || []).map((d) => String(d).toLowerCase())));
  const cmds = [];
  for (const a of addresses) {
    cmds.push(['HGETALL', addrKey(chainId, a)]);
    cmds.push(['SCARD', addrKey(chainId, a) + ':reporters']);
  }
  for (const d of domains) {
    cmds.push(['HGETALL', domainKey(d)]);
    cmds.push(['SCARD', domainKey(d) + ':reporters']);
  }
  const out = { addresses: {}, domains: {} };
  if (cmds.length === 0) return out;
  const res = await store.pipeline(cmds);
  let i = 0;
  for (const a of addresses) {
    const rec = parseRecord(res[i]);
    if (rec) rec.reporters = Number(res[i + 1] || 0);
    out.addresses[a] = rec;
    i += 2;
  }
  for (const d of domains) {
    const rec = parseRecord(res[i]);
    if (rec) rec.reporters = Number(res[i + 1] || 0);
    out.domains[d] = rec;
    i += 2;
  }
  return out;
}

/** Severity for a looked-up record under the configured thresholds. */
function classify(rec, c) {
  if (!rec || rec.reports < c.warnReports) return null;
  if (rec.reports >= c.denyReports && (rec.reporters || 0) >= c.denyReporters) return 'DENY';
  return 'WARN';
}

/**
 * Decide which (address, rule, selector) triples in a finished analysis are
 * worth recording. Pure; returns [] when the verdict is not DENY.
 */
function extractReports(verdict, findings, chainId, selector) {
  if (verdict !== 'DENY') return { addresses: [], domains: [] };
  const addresses = [];
  const domains = [];
  for (const f of findings) {
    if (f.severity !== 'DENY') continue;
    const field = RECORDABLE_ADDRESS_RULES[f.code];
    if (field) {
      const address = f[field] || f.address || f.spender || f.recipient;
      if (address && /^0x[0-9a-fA-F]{40}$/.test(address) && !registry.lookupContract(chainId, address) && !registry.lookupToken(chainId, address)) {
        addresses.push({ address: address.toLowerCase(), rule: f.code, selector: selector || 'none' });
      }
    }
    if (RECORDABLE_DOMAIN_RULES.has(f.code)) {
      const host = f.domain || f.host;
      if (host) domains.push({ domain: String(host).toLowerCase(), rule: f.code });
    }
    if (f.code === 'injection_pattern' && Array.isArray(f.sources)) {
      // Only patterns that are objective properties of the hostname itself.
      for (const s of f.sources) if (s.domain && ['brand_impersonation', 'typosquatting', 'punycode'].includes(s.pattern)) domains.push({ domain: s.domain.toLowerCase(), rule: 'injection_pattern:' + s.pattern });
    }
  }
  return { addresses, domains };
}

async function record(store, chainId, reports, reporter, env) {
  const c = cfg(env);
  const fp = reporterFingerprint(reporter, env);
  const now = Date.now();
  const cmds = [];
  const seen = new Set();
  for (const r of reports.addresses) {
    const k = addrKey(chainId, r.address);
    const dedupe = k + '|' + r.rule;
    if (seen.has(dedupe)) continue;
    seen.add(dedupe);
    cmds.push(['HINCRBY', k, 'reports', 1], ['HINCRBY', k, 'rule:' + r.rule, 1], ['HINCRBY', k, 'sel:' + r.selector, 1], ['HSETNX', k, 'first_seen', now], ['HSET', k, 'last_seen', now], ['EXPIRE', k, c.ttlSeconds], ['SADD', k + ':reporters', fp], ['EXPIRE', k + ':reporters', c.ttlSeconds], ['ZADD', 'threat:index:' + chainId, now, r.address]);
  }
  for (const d of reports.domains) {
    const k = domainKey(d.domain);
    const dedupe = k + '|' + d.rule;
    if (seen.has(dedupe)) continue;
    seen.add(dedupe);
    cmds.push(['HINCRBY', k, 'reports', 1], ['HINCRBY', k, 'rule:' + d.rule, 1], ['HSETNX', k, 'first_seen', now], ['HSET', k, 'last_seen', now], ['EXPIRE', k, c.ttlSeconds], ['SADD', k + ':reporters', fp], ['EXPIRE', k + ':reporters', c.ttlSeconds], ['ZADD', 'threat:index:domains', now, d.domain]);
  }
  if (cmds.length) {
    cmds.push(['INCRBY', 'threat:stats:reports', reports.addresses.length + reports.domains.length]);
    await store.pipeline(cmds);
  }
  return { recorded_addresses: reports.addresses.length, recorded_domains: reports.domains.length };
}

async function stats(store) {
  const [reports, addrCount1, domainCount] = await store.pipeline([['GET', 'threat:stats:reports'], ['ZCARD', 'threat:index:1'], ['ZCARD', 'threat:index:domains']]);
  return { total_reports: Number(reports || 0), flagged_addresses_chain_1: Number(addrCount1 || 0), flagged_domains: Number(domainCount || 0), persistent: store.persistent, backend: store.kind };
}

async function recent(store, chainId, limit) {
  const members = await store.command('ZRANGE', 'threat:index:' + chainId, 0, Math.max(0, (limit || 20) - 1), 'REV');
  return members || [];
}

// ---------------------------------------------------------------------------
// Reputation (deterministic tiering from what one RPC round-trip can tell)
// ---------------------------------------------------------------------------

/**
 * @param {object} p
 * @param {object} p.state   { isContract, txCount, balance, codeSize }
 * @param {object|null} p.known  registry entry
 * @param {object|null} p.threat  registry record
 * @param {object|null} p.proxy
 * @param {number} p.chainId
 */
function reputation(p) {
  const { state, known, threat, proxy } = p;
  const out = {
    type: state.isContract ? 'contract' : 'eoa',
    activity: null,
    balance_tier: null,
    known_protocol: known ? { name: known.name, category: known.category } : null,
    proxy: proxy || null,
    threat_reports: threat ? threat.reports : 0,
    threat_reporters: threat ? threat.reporters || 0 : 0,
    threat_rules: threat ? threat.rules : {},
    threat_last_seen: threat && threat.last_seen ? new Date(threat.last_seen).toISOString() : null,
    score: 50,
    tier: 'unknown',
    limits: 'Activity is derived from nonce and balance only; first-seen date and incoming transfer counts need an indexer and are not claimed.',
  };
  const nonce = Number(state.txCount || 0);
  const balance = BigInt(state.balance || '0');
  if (state.isContract) {
    out.activity = 'contract';
  } else if (nonce === 0) out.activity = 'never-transacted';
  else if (nonce < 5) out.activity = 'low (' + nonce + ' outgoing tx)';
  else if (nonce < 50) out.activity = 'moderate (' + nonce + ' outgoing tx)';
  else out.activity = 'established (' + nonce + ' outgoing tx)';
  if (balance === 0n) out.balance_tier = 'empty';
  else if (balance < 10n ** 16n) out.balance_tier = 'dust (< 0.01 native)';
  else if (balance < 10n ** 18n) out.balance_tier = 'small (< 1 native)';
  else out.balance_tier = 'funded (>= 1 native)';

  let score = 50;
  if (known) score = 95;
  else if (state.isContract) score = 60 + (state.codeSize > 1000 ? 5 : -15) + (proxy && proxy.type && proxy.type.includes('upgradeable') ? -10 : 0);
  else score = 30 + Math.min(30, nonce) + (balance > 0n ? 10 : 0);
  if (threat) score -= Math.min(80, 25 * threat.reports + 10 * (threat.reporters || 0));
  out.score = Math.max(0, Math.min(100, score));
  out.tier = out.score >= 80 ? 'trusted' : out.score >= 55 ? 'neutral' : out.score >= 30 ? 'low' : 'hostile';
  return out;
}

const THREAT_RULES = [
  { code: 'known_drainer', severity: 'DENY', layer: 'shared-intel', description: 'Counterparty address was reported by multiple independent agents for on-chain-attributable DENY rules (approval_to_eoa, contract_lookalike, permit_spender_mismatch, permit2_pull_to_third_party). Thresholds: THREAT_DENY_REPORTS / THREAT_DENY_REPORTERS.' },
  { code: 'flagged_address', severity: 'WARN', layer: 'shared-intel', description: 'Counterparty address has at least THREAT_WARN_REPORTS report(s) in the shared threat registry.' },
  { code: 'known_phishing_domain', severity: 'DENY', layer: 'shared-intel', description: 'A source domain was previously reported as phishing (brand impersonation, typosquatting, punycode, SIWE phishing) by other agents.' },
  { code: 'threat_intel_unavailable', severity: 'WARN', layer: 'shared-intel', description: 'A persistent threat store is configured but did not answer; shared-intel checks were skipped.' },
];

module.exports = { lookup, classify, extractReports, record, stats, recent, reputation, cfg, reporterFingerprint, THREAT_RULES, RECORDABLE_ADDRESS_RULES, getStore };
