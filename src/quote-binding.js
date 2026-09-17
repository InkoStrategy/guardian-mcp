'use strict';

/**
 * Onchain OS quote binding, shared by the server (/check-quote), the local check-quote CLI and the agent hook.
 *
 * `onchainos payment quote` persists every quote to ~/.onchainos/payments/<paymentId>.json and
 * `onchainos payment pay --payment-id` signs from that file without re-fetching the 402. So the file is
 * the exact thing that gets signed. This module reads it, reduces the selected entry to a fingerprint,
 * and keeps a local ledger (~/.guardian/payments/<paymentId>.json) of the Guardian verdict bound to that
 * fingerprint. No network, no secrets: the state file carries no keys, and the fields that identify the
 * owner (owner_wallet, deposit address, balance) are dropped before anything is sent to Guardian.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

class QuoteValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ValidationError';
  }
}

const PAYMENT_ID_RE = /^pay_[A-Za-z0-9]{8,64}$/;

function stateDir(env) {
  env = env || process.env;
  return env.ONCHAINOS_PAYMENTS_DIR || path.join(env.USERPROFILE || env.HOME || os.homedir(), '.onchainos', 'payments');
}

function ledgerDir(env) {
  env = env || process.env;
  return env.GUARDIAN_LEDGER_DIR || path.join(env.USERPROFILE || env.HOME || os.homedir(), '.guardian', 'payments');
}

function isPaymentId(id) {
  return typeof id === 'string' && PAYMENT_ID_RE.test(id);
}

function parseMaybeJson(value) {
  if (value && typeof value === 'object') return value;
  if (typeof value !== 'string' || !value.trim()) return null;
  try { return JSON.parse(value); } catch { return null; }
}

/** The x402 challenge inside a 402 body: plain body, JSON-RPC error.data (A2MCP) or tool structuredContent. */
function challengeInBody(body) {
  if (!body || typeof body !== 'object') return null;
  if (Array.isArray(body.accepts)) return body;
  const e = body.error && body.error.data;
  if (e && Array.isArray(e.accepts)) return e;
  const r = body.result && body.result.structuredContent;
  if (r && Array.isArray(r.accepts)) return r;
  return null;
}

/**
 * Accepts the persisted state file ({payment_id, raw_accepts, ...}) or the JSON printed by
 * `onchainos payment quote` ({ok, data: {paymentId, accepts, merchantBody, ...}}).
 */
function normalizeQuote(input) {
  let q = typeof input === 'string' ? parseMaybeJson(input) : input;
  if (!q || typeof q !== 'object' || Array.isArray(q)) throw new QuoteValidationError('"quote" must be the persisted payment state or the JSON output of onchainos payment quote');
  if (q.ok === false) throw new QuoteValidationError('the quote failed: ' + String(q.error || q.message || 'unknown error').slice(0, 200));
  if (q.data && typeof q.data === 'object' && !q.payment_id) q = q.data;
  const isState = typeof q.payment_id === 'string';
  const paymentId = isState ? q.payment_id : q.paymentId;
  if (!isPaymentId(paymentId)) throw new QuoteValidationError('the quote has no valid paymentId');
  const merchantBodyRaw = isState ? q.merchant_body : q.merchantBody;
  const merchantBody = parseMaybeJson(merchantBodyRaw);
  const rawAccepts = isState && Array.isArray(q.raw_accepts) && q.raw_accepts.length ? q.raw_accepts : null;
  const accepts = Array.isArray(q.accepts) ? q.accepts : [];
  const decoded = (isState ? q.decoded_challenge : q.decodedChallenge) || null;
  const knownParams = (isState ? q.known_params : q.knownParams) || {};
  const bodyChallenge = challengeInBody(merchantBody);
  return {
    source: isState ? 'payment-state' : 'quote-output',
    paymentId,
    // Only the CLI's own record of the URL it called. Never the seller-written merchantBody.resource.url,
    // which would let a header-only seller name the listed host and pass the domain check.
    endpointUrl: typeof q.endpoint_url === 'string' ? q.endpoint_url : null,
    method: typeof q.method === 'string' ? q.method : null,
    createdAt: Number.isFinite(Number(q.created_at)) ? Number(q.created_at) : null,
    expiresAt: Number.isFinite(Number(q.expires_at)) && Number(q.expires_at) > 0 ? Number(q.expires_at) : null,
    rawAccepts,
    accepts,
    decoded,
    candidates: Array.isArray(q.candidates) ? q.candidates : [],
    resource: q.resource && typeof q.resource === 'object' ? q.resource : bodyChallenge && bodyChallenge.resource ? bodyChallenge.resource : null,
    merchantBody,
    bodyChallenge,
    knownParams: knownParams && typeof knownParams === 'object' && !Array.isArray(knownParams) ? knownParams : {},
  };
}

/** Index `payment pay` signs when --selected-index is omitted: exact > aggr_deferred > first (onchainos 4.6 help). */
function cliDefaultIndex(entries) {
  const list = Array.isArray(entries) ? entries : [];
  if (!list.length) return 0;
  // Array position only. A seller can add an `index` field to a raw_accepts entry; the CLI signs by
  // position (accepts[].index and candidates[].acceptsIndex are positions), so trusting it would let a
  // seller point Guardian's default at a cheap entry while the CLI pays an expensive one.
  for (const scheme of ['exact', 'aggr_deferred']) {
    const i = list.findIndex((e) => e && String(e.scheme || 'exact') === scheme);
    if (i >= 0) return i;
  }
  return 0;
}

/** Recursively key-sorted JSON, with 0x addresses lowercased, so an equal entry hashes equally. */
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = canonical(value[k]);
    return out;
  }
  if (typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value)) return value.toLowerCase();
  return value;
}

/**
 * Stable fingerprint of what `payment pay --payment-id <id> --selected-index <index>` will sign.
 * v2 hashes the whole selected raw entry (every field the wallet signs, including maxTimeoutSeconds and
 * every extra field), plus the resource url, x402 version, endpoint and method. Only fields publicState()
 * keeps, so the server and the local scripts compute the same value.
 */
function fingerprint(nq, index) {
  const e = nq.rawAccepts ? nq.rawAccepts[index] : null;
  if (!e) return null;
  const amount = e.amount !== undefined && e.amount !== null && e.amount !== '' ? e.amount : e.maxAmountRequired;
  const parts = {
    v: 'guardian-quote-v2',
    paymentId: nq.paymentId,
    endpoint: nq.endpointUrl || null,
    method: nq.method || null,
    index,
    entry: canonical(e),
    amount: amount === undefined ? null : String(amount),
    resource: nq.resource && typeof nq.resource.url === 'string' ? nq.resource.url : null,
    x402Version: (nq.bodyChallenge && nq.bodyChallenge.x402Version) || 2,
  };
  return crypto.createHash('sha256').update(JSON.stringify(parts)).digest('hex');
}

const CANDIDATE_PRIVATE = ['depositAddress', 'availableAmount', 'shortfall', 'requiredAmount', 'hasBalance', 'balanceStatus'];

/** State without the owner's wallet id, deposit address, balance or business params: what is sent to Guardian. */
function publicState(state) {
  const s = JSON.parse(JSON.stringify(state));
  delete s.owner_wallet;
  // The owner's business params (a URL being checked, an instrument id) are not needed for the verdict.
  delete s.known_params;
  if (Array.isArray(s.candidates)) {
    s.candidates = s.candidates.map((c) => {
      const o = Object.assign({}, c);
      for (const k of CANDIDATE_PRIVATE) delete o[k];
      return o;
    });
  }
  return s;
}

const SAFE_PARAM_KEY = /^[A-Za-z0-9_.-]{1,64}$/;
const SAFE_PARAM_VALUE = /^[A-Za-z0-9_.:/@%+=,~-]{1,256}$/;

/**
 * The `onchainos payment pay` command for this quote and index, or null when a stored business param needs
 * manual quoting. Never includes --yes: without it the wallet returns a confirming prompt and pays nothing.
 */
function payCommand(nq, index) {
  const args = ['onchainos', 'payment', 'pay', '--payment-id', nq.paymentId, '--selected-index', String(index)];
  for (const [k, v] of Object.entries(nq.knownParams || {})) {
    const value = typeof v === 'number' || typeof v === 'boolean' ? String(v) : v;
    if (!SAFE_PARAM_KEY.test(k) || typeof value !== 'string' || !SAFE_PARAM_VALUE.test(value)) {
      return { command: null, note: 'A stored business param needs manual quoting, so no command is printed. Pass the params you quoted with to payment pay yourself.' };
    }
    args.push('--param', k + '=' + value);
  }
  return { command: args.join(' '), note: 'No --yes: the wallet returns a confirming prompt (exit 2) and pays nothing until the owner approves.' };
}

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

function readPaymentState(paymentId, env) {
  if (!isPaymentId(paymentId)) return null;
  return readJson(path.join(stateDir(env), paymentId + '.json'));
}

function readLedger(paymentId, env) {
  if (!isPaymentId(paymentId)) return null;
  return readJson(path.join(ledgerDir(env), paymentId + '.json'));
}

function writeLedger(entry, env) {
  if (!entry || !isPaymentId(entry.paymentId)) throw new QuoteValidationError('ledger entry needs a valid paymentId');
  const dir = ledgerDir(env);
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, entry.paymentId + '.json');
  fs.writeFileSync(file, JSON.stringify(entry, null, 2));
  return file;
}

module.exports = {
  QuoteValidationError,
  normalizeQuote,
  challengeInBody,
  cliDefaultIndex,
  fingerprint,
  publicState,
  payCommand,
  readPaymentState,
  readLedger,
  writeLedger,
  isPaymentId,
  stateDir,
  ledgerDir,
};
