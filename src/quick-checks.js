'use strict';

/**
 * Small, precisely named checks that map one-to-one onto the questions agents
 * actually ask the marketplace: "is this address a scam / drainer?",
 * "verify address before transfer", "is this domain phishing?".
 * They reuse the same registries, on-chain intelligence and shared threat
 * registry as /analyze, without needing calldata.
 */

const { isAddress, getAddress } = require('ethers');
const { createChainReader, RpcError, supportedChainIds, chainName } = require('./rpc');
const registry = require('./registry');
const intel = require('./intel');
const threat = require('./threat-registry');
const pipeline = require('./pipeline');
const contextAnalyzer = require('./context-analyzer');
const seed = require('./seed');
const stats = require('./stats');
const { getStore } = require('./store');

class QuickValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ValidationError';
  }
}

const SEV = { ALLOW: 0, WARN: 1, DENY: 2 };
function verdictOf(findings) {
  let v = 'ALLOW';
  for (const f of findings) if (SEV[f.severity] > SEV[v]) v = f.severity;
  return v;
}

function parseChainId(raw) {
  if (raw === undefined || raw === null || raw === '') return 1;
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) throw new QuickValidationError('chainId must be a positive integer');
  if (!supportedChainIds().includes(n) && !process.env['RPC_URL_' + n]) throw new QuickValidationError('chainId ' + n + ' is not supported. Supported: ' + supportedChainIds().join(', '));
  return n;
}

/**
 * POST /check-address { address, chainId?, role? }
 * role: "recipient" (default, "can I send here?") | "spender" ("can I approve this?") | "contract" ("can I call this?")
 */
async function checkAddress(input, deps) {
  deps = deps || {};
  if (!input || typeof input !== 'object') throw new QuickValidationError('Request body must be a JSON object');
  if (typeof input.address !== 'string' || !isAddress(input.address)) throw new QuickValidationError('"address" must be a valid 0x-prefixed EVM address');
  const address = getAddress(input.address);
  const chainId = parseChainId(input.chainId);
  const role = ['recipient', 'spender', 'contract'].includes(input.role) ? input.role : 'recipient';
  const findings = [];
  const store = deps.store || getStore(deps.env);
  const known = registry.lookupContract(chainId, address) || registry.lookupToken(chainId, address);
  const lookalike = registry.findRegistryLookalike(chainId, address);
  if (lookalike) findings.push({ code: 'contract_lookalike', severity: 'DENY', message: address + ' imitates ' + lookalike.name + ' (' + lookalike.address + ') but is a different address.', imitates: lookalike.address });

  let state = null;
  let info = null;
  const rpc = { ok: true, endpoint: null, error: null };
  try {
    const reader = deps.reader || createChainReader(chainId);
    state = await reader.addressState(address);
    rpc.endpoint = reader.endpoint || null;
    info = await intel.inspectContract(reader, chainId, address, state);
    if (role === 'spender' && !state.isContract) findings.push({ code: 'approval_to_eoa', severity: 'DENY', message: address + ' is a plain wallet, not a contract. Never approve tokens to a wallet address; this is the classic drain pattern.' });
    if (role === 'contract' && !state.isContract) findings.push({ code: 'calldata_to_eoa', severity: 'WARN', message: address + ' has no contract code; calling a function on it does nothing.' });
    if (role === 'recipient' && !state.isContract && state.txCount === 0 && BigInt(state.balance) === 0n) findings.push({ code: 'fresh_recipient', severity: 'WARN', message: address + ' has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.' });
    if (role === 'spender' && state.isContract && !known && info.tiny) findings.push({ code: 'unknown_spender', severity: 'WARN', message: address + ' is an unrecognised contract with only ' + info.codeSize + ' bytes of code.' });
  } catch (err) {
    rpc.ok = false;
    rpc.error = err instanceof RpcError ? err.message : 'Unexpected RPC failure: ' + err.message;
    findings.push({ code: 'rpc_unavailable', severity: 'WARN', message: 'On-chain checks could not run (' + rpc.error + '). Fail-safe: verdict is at least WARN.' });
  }

  const ti = await pipeline.threatLookup({ store, env: deps.env, chainId, addresses: [{ role: role === 'contract' ? 'target' : role, address }], domains: [] });
  for (const f of ti.findings) findings.push(f);
  const rec = ti.intel.addresses[address.toLowerCase()] || null;
  const reputation = state ? threat.reputation({ state, known: known && known.category ? known : null, threat: rec, proxy: info && info.proxy, chainId }) : null;

  const verdict = verdictOf(findings);
  const reasons = Array.from(new Set(findings.map((f) => f.code)));
  const label = known ? known.name + (known.category ? ' (' + known.category + ')' : known.symbol ? ' (' + known.symbol + ' token)' : '') : state ? (state.isContract ? 'an unrecognised contract' : 'a wallet address') : 'an address';
  const summary = address + ' on ' + chainName(chainId) + ' is ' + label + (rec ? ', reported ' + rec.reports + ' time(s) in the shared threat registry' : '') + (ti.intel.seed && ti.intel.seed.addresses[address.toLowerCase()] ? ', listed in the ScamSniffer scam database' : '') + '. ' + (verdict === 'ALLOW' ? 'No risk rules triggered for role ' + role + '.' : verdict + ': ' + reasons.join(', ') + '.');
  try {
    if (!deps.skipStats) await stats.record(store, { now: deps.now, verdict, kind: 'check-address', codes: reasons, sessionId: null });
  } catch { /* counters are best-effort */ }
  return { verdict, reasons, summary, details: { chainId, chain: chainName(chainId), address, role, known: known || null, lookalikeOf: lookalike || null, state: state ? { isContract: state.isContract, txCount: state.txCount, balance: state.balance, codeSize: state.codeSize } : null, proxy: info ? info.proxy : null, reputation, threat: rec, scam_database: Boolean(ti.intel.seed && ti.intel.seed.addresses[address.toLowerCase()]), findings, rpc, analyzedAt: new Date().toISOString() } };
}

/**
 * POST /check-domain { domain | url }
 */
async function checkDomain(input, deps) {
  deps = deps || {};
  if (!input || typeof input !== 'object') throw new QuickValidationError('Request body must be a JSON object');
  const raw = typeof input.url === 'string' ? input.url : typeof input.domain === 'string' ? input.domain : null;
  if (!raw || raw.length > 2048) throw new QuickValidationError('"domain" or "url" is required (string up to 2048 chars)');
  const parsed = contextAnalyzer.extractDomain(raw.includes('://') || /^[a-z0-9.-]+(\/|$)/i.test(raw) ? raw : 'https://' + raw);
  if (!parsed || !parsed.domain || parsed.kind !== 'url') throw new QuickValidationError('could not extract a hostname from "' + raw.slice(0, 80) + '"');
  const host = parsed.domain;
  const findings = [];
  const trusted = contextAnalyzer.getTrustedDomains(deps.env);
  const isTrusted = trusted.domains.some((t) => host === t || host.endsWith('.' + t));
  const pattern = isTrusted ? null : contextAnalyzer.detectPhishingPattern(host);
  if (pattern) findings.push({ code: 'injection_pattern', severity: 'DENY', message: host + ' matches a phishing pattern (' + pattern.pattern + '): ' + pattern.detail, pattern: pattern.pattern });
  const store = deps.store || getStore(deps.env);
  const ti = await pipeline.threatLookup({ store, env: deps.env, chainId: 0, addresses: [], domains: [host] });
  for (const f of ti.findings) findings.push(f);
  const seedHit = ti.intel.seed && ti.intel.seed.domains[seed.normalizeHost(host)];
  const verdict = verdictOf(findings);
  const reasons = Array.from(new Set(findings.map((f) => f.code)));
  const summary = host + ' is ' + (isTrusted ? 'on the trusted list' : seedHit ? 'listed in the ScamSniffer phishing database' : pattern ? 'suspicious (' + pattern.pattern + ')' : 'not on any list') + '. ' + (verdict === 'ALLOW' ? 'No risk rules triggered.' : verdict + ': ' + reasons.join(', ') + '.');
  try {
    if (!deps.skipStats) await stats.record(store, { now: deps.now, verdict, kind: 'check-domain', codes: reasons, sessionId: null });
  } catch { /* best-effort */ }
  return { verdict, reasons, summary, details: { host, registrable: contextAnalyzer.registrableDomain(host), trusted: isTrusted, pattern, scam_database: seedHit || null, threat: ti.intel.domains[host] || null, findings, analyzedAt: new Date().toISOString() } };
}

module.exports = { checkAddress, checkDomain, QuickValidationError };
