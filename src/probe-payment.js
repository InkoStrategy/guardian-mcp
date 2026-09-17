'use strict';

/**
 * POST /probe-payment: "is it safe to pay this URL?" in one call.
 *
 * Guardian requests the endpoint once without paying (GET, POST, MCP tools/call), captures the x402
 * challenge and runs Pay-Safe on it. For agents and people that cannot capture a PAYMENT-REQUIRED
 * header themselves.
 *
 * {
 *   "url": "https://seller.example/paid",            // https, public host
 *   "method": "auto" | "GET" | "POST" | "MCP",        // default auto
 *   "params": { "symbol": "BTC" },                    // query (GET) or JSON body (POST), optional
 *   "tool": "snapshot",                               // MCP tool name, optional
 *   "expected": { feeAmount, feeToken, endpoint, payTo },
 *   "context": { max_amount, known_addresses, session_id },
 *   "selectedIndex": 0
 * }
 *
 * SSRF: https only (http only for explicitly allowed test hosts), no credentials, no private or
 * link-local hosts, DNS answers checked for private addresses, redirects not followed, 256 KB body cap,
 * 8 s per request, rate limit per caller.
 */

const dns = require('node:dns');
const paysafe = require('./paysafe');
const { fetchChallenge, challengeOf, x402In } = require('./x402-probe');
const { getStore } = require('./store');

const MAX_URL = 2048;
const RATE_LIMIT_PER_HOUR = Number.parseInt(process.env.PROBE_RATE_LIMIT_PER_HOUR || '60', 10);

class ProbeValidationError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'ValidationError';
    this.status = status || 400;
  }
}

function isPrivateIpv4(ip) {
  const m = String(ip).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
}

function isPrivateIp(ip) {
  const s = String(ip).toLowerCase();
  if (isPrivateIpv4(s)) return true;
  if (!s.includes(':')) return false;
  if (s === '::' || s === '::1') return true;
  const mapped = s.match(/::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mapped) return isPrivateIpv4(mapped[1]);
  return /^f[cd]/.test(s) || /^fe[89ab]/.test(s) || s.startsWith('ff');
}

function isBlockedHostname(host) {
  const h = String(host).toLowerCase().replace(/\.$/, '');
  if (!h || h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.home.arpa')) return true;
  if (h.startsWith('[')) return true; // IP literals in brackets (IPv6) are not accepted
  if (/^\d+$/.test(h) || /^0x[0-9a-f]+$/i.test(h)) return true; // integer / hex IPv4 forms
  return isPrivateIpv4(h);
}

function validateInput(input, deps) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new ProbeValidationError('Request body must be a JSON object');
  if (typeof input.url !== 'string' || !input.url || input.url.length > MAX_URL) throw new ProbeValidationError('"url" is required (string up to ' + MAX_URL + ' chars)');
  let u;
  try { u = new URL(input.url); } catch { throw new ProbeValidationError('"url" is not a valid URL'); }
  const allowHttp = Array.isArray(deps.allowHttpHosts) && deps.allowHttpHosts.includes(u.hostname);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && allowHttp)) throw new ProbeValidationError('"url" must use https');
  if (u.username || u.password) throw new ProbeValidationError('"url" must not embed credentials');
  if (!allowHttp && isBlockedHostname(u.hostname)) throw new ProbeValidationError('"url" must point at a public host');
  const method = input.method === undefined || input.method === null ? 'AUTO' : String(input.method).toUpperCase();
  if (!['AUTO', 'GET', 'POST', 'MCP'].includes(method)) throw new ProbeValidationError('"method" must be auto, GET, POST or MCP');
  let params = null;
  if (input.params !== undefined && input.params !== null) {
    if (typeof input.params !== 'object' || Array.isArray(input.params)) throw new ProbeValidationError('"params" must be an object');
    const entries = Object.entries(input.params);
    if (entries.length > 20) throw new ProbeValidationError('"params" accepts at most 20 keys');
    params = {};
    for (const [k, v] of entries) {
      if (k.length > 64 || (typeof v !== 'string' && typeof v !== 'number' && typeof v !== 'boolean') || String(v).length > 512) throw new ProbeValidationError('"params" values must be strings, numbers or booleans up to 512 chars');
      params[k] = v;
    }
  }
  if (input.tool !== undefined && input.tool !== null && (typeof input.tool !== 'string' || input.tool.length > 128)) throw new ProbeValidationError('"tool" must be a string up to 128 chars');
  return { url: u, raw: input.url, method: method === 'AUTO' ? 'auto' : method, params, tool: input.tool || null, allowHttp };
}

async function assertPublicDns(hostname, deps) {
  const lookup = deps.lookup || ((h) => dns.promises.lookup(h, { all: true, verbatim: true }));
  let answers;
  try {
    answers = await lookup(hostname);
  } catch (err) {
    throw new ProbeValidationError('could not resolve ' + hostname + ' (' + (err.code || err.message) + ')', 422);
  }
  const list = Array.isArray(answers) ? answers : [answers];
  if (!list.length) throw new ProbeValidationError('could not resolve ' + hostname, 422);
  for (const a of list) {
    const addr = a && typeof a === 'object' ? a.address : a;
    if (isPrivateIp(addr)) throw new ProbeValidationError('"url" resolves to a private address', 400);
  }
}

async function rateLimit(store, reporter, now) {
  const hour = Math.floor((now === undefined ? Date.now() : Number(now)) / 3600000);
  const key = 'probe:rl:' + (reporter || 'anon') + ':' + hour;
  try {
    const count = await store.command('INCRBY', key, 1);
    await store.command('EXPIRE', key, 3700);
    if (Number(count) > RATE_LIMIT_PER_HOUR) throw new ProbeValidationError('probe rate limit exceeded (' + RATE_LIMIT_PER_HOUR + ' per hour)', 429);
  } catch (err) {
    if (err instanceof ProbeValidationError) throw err;
    // store unavailable: fail open, the per-request limits still apply
  }
}

/**
 * @param {object} input see file header
 * @param {object} deps  { store, env, now, reporter, fetchImpl, lookup, allowHttpHosts, reader, readerFor }
 */
async function probePayment(input, deps) {
  deps = deps || {};
  const v = validateInput(input, deps);

  const injected = paysafe.urlOnlyVerdict(v.raw, 'endpoint URL');
  if (injected) {
    injected.details.probe = { contacted: false, reason: 'shell syntax in URL' };
    return injected;
  }

  const store = deps.store || getStore(deps.env);
  await rateLimit(store, deps.reporter, deps.now);
  if (!v.allowHttp) await assertPublicDns(v.url.hostname, deps);

  const ch = await fetchChallenge(v.raw, { method: v.method, params: v.params, tool: v.tool, timeoutMs: deps.timeoutMs || 8000, fetchImpl: deps.fetchImpl, maxBytes: 256 * 1024 });
  if (ch.error) throw new ProbeValidationError('endpoint did not answer: ' + ch.error, 502);
  const probe = { contacted: true, method: ch.method, status: ch.status, challenge_found: Boolean(challengeOf(ch)) };
  if (!probe.challenge_found) {
    return {
      verdict: null,
      reasons: [],
      risk_score: 0,
      summary: 'The endpoint did not ask for payment (HTTP ' + ch.status + ' via ' + ch.method + '). Nothing to check; try method, params or tool.',
      recommendations: [],
      recommended_index: null,
      details: { probe, findings: [], analyzedAt: new Date().toISOString() },
    };
  }
  const bodyChallenge = ch.header ? x402In(ch.body) : null;
  const result = await paysafe.checkPayment({
    paymentRequired: challengeOf(ch),
    bodyChallenge,
    requestUrl: v.raw,
    expected: input.expected,
    context: input.context,
    selectedIndex: input.selectedIndex,
  }, Object.assign({}, deps, { store }));
  result.details.probe = probe;
  return result;
}

module.exports = { probePayment, ProbeValidationError, isPrivateIp, isBlockedHostname, RATE_LIMIT_PER_HOUR };
