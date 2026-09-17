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
    endpointUrl: typeof q.endpoint_url === 'string' ? q.endpoint_url : bodyChallenge && bodyChallenge.resource && typeof bodyChallenge.resource.url === 'string' ? bodyChallenge.resource.url : null,
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
  const idx = (e, i) => (e && Number.isInteger(Number(e.index)) ? Number(e.index) : i);
  for (const scheme of ['exact', 'aggr_deferred']) {
    const i = list.findIndex((e) => e && String(e.scheme || 'exact') === scheme);
    if (i >= 0) return idx(list[i], i);
  }
  return idx(list[0], 0);
}

/** Stable fingerprint of what `payment pay --payment-id <id> --selected-index <index>` will sign. */
function fingerprint(nq, index) {
  const e = nq.rawAccepts ? nq.rawAccepts[index] : null;
  if (!e) return null;
  const extra = e.extra && typeof e.extra === 'object' ? e.extra : {};
  const parts = [
    'guardian-quote-v1',
    nq.paymentId,
    String(nq.endpointUrl || ''),
    String(nq.method || ''),
    String(index),
    String(e.scheme || ''),
    String(e.network || ''),
    String(e.asset || '').toLowerCase(),
    String(e.amount !== undefined ? e.amount : e.maxAmountRequired || ''),
    String(e.payTo || '').toLowerCase(),
    String(extra.name === undefined ? '' : extra.name),
    String(extra.version === undefined ? '' : extra.version),
  ];
  return crypto.createHash('sha256').update(JSON.stringify(parts)).digest('hex');
}

/** State without the owner's wallet id, deposit address or balance: what gets sent to Guardian. */
function publicState(state) {
  const s = JSON.parse(JSON.stringify(state));
  delete s.owner_wallet;
  if (Array.isArray(s.candidates)) {
    s.candidates = s.candidates.map((c) => {
      const o = Object.assign({}, c);
      delete o.depositAddress;
      delete o.availableAmount;
      return o;
    });
  }
  return s;
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
  readPaymentState,
  readLedger,
  writeLedger,
  isPaymentId,
  stateDir,
  ledgerDir,
};
