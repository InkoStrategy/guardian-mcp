'use strict';

/**
 * POST /check-quote: Pay-Safe verdict for an Onchain OS payment quote, bound to its paymentId.
 *
 * {
 *   "quote": <~/.onchainos/payments/<paymentId>.json> | <JSON output of `onchainos payment quote`>,
 *   "selectedIndex": 0,                                  // index you will pass to payment pay (default: the CLI's own pick)
 *   "expected": { feeAmount, feeToken, endpoint, payTo },  // the listing; or
 *   "sid": 39856,                                         // take price, token and endpoint from the latest trust scan
 *   "context": { max_amount, known_addresses, session_id }
 * }
 *
 * `payment pay --payment-id` signs the persisted raw_accepts entry without re-fetching the 402, so the
 * persisted state is checked, not a fresh request. On top of /check-payment rules it catches quotes that
 * disagree with themselves (quote_inconsistent), sellers whose 402 body shows another payment than the
 * one the wallet signs (challenge_header_body_mismatch), and expired quotes. `next_command` is returned
 * only on ALLOW and never contains --yes: without it the wallet returns a confirming prompt and pays nothing.
 */

const paysafe = require('./paysafe');
const binding = require('./quote-binding');

const { QuoteValidationError } = binding;
const SAFE_PARAM_KEY = /^[A-Za-z0-9_.-]{1,64}$/;
const SAFE_PARAM_VALUE = /^[A-Za-z0-9_.:\/@%+=,~-]{1,256}$/;

function eqAddr(a, b) {
  return typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
}

function expectedFromScan(sid, deps) {
  const n = Number(sid);
  if (!Number.isInteger(n) || n <= 0) throw new QuoteValidationError('"sid" must be a positive integer');
  const scan = typeof deps.trustScan === 'function' ? deps.trustScan() : null;
  const row = scan && Array.isArray(scan.results) ? scan.results.find((r) => Number(r.sid) === n) : null;
  if (!row || !row.listed) return { expected: null, source: 'sid ' + n + ' is not in the trust scan; pass "expected" from onchainos agent service-detail' };
  const expected = {};
  if (row.listed.feeAmount !== undefined) expected.feeAmount = row.listed.feeAmount;
  if (row.listed.feeToken) expected.feeToken = row.listed.feeToken;
  if (typeof row.endpoint === 'string') expected.endpoint = row.endpoint;
  return { expected, source: 'trust scan of ' + scan.generatedAt + ' (sid ' + n + ')' };
}

function nextCommand(nq, index) {
  const args = ['onchainos', 'payment', 'pay', '--payment-id', nq.paymentId, '--selected-index', String(index)];
  for (const [k, v] of Object.entries(nq.knownParams)) {
    const value = typeof v === 'number' || typeof v === 'boolean' ? String(v) : v;
    if (!SAFE_PARAM_KEY.test(k) || typeof value !== 'string' || !SAFE_PARAM_VALUE.test(value)) {
      return { command: null, note: 'A stored business param needs manual quoting, so no command is printed. Pass the params you quoted with to payment pay yourself.' };
    }
    args.push('--param', k + '=' + value);
  }
  return { command: args.join(' '), note: 'No --yes: the wallet returns a confirming prompt (exit 2) and pays nothing until the owner approves.' };
}

/**
 * @param {object} input see file header
 * @param {object} deps  checkPayment deps plus { trustScan: () => scan, now }
 */
async function checkQuote(input, deps) {
  deps = deps || {};
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new QuoteValidationError('Request body must be a JSON object');
  if (input.quote === undefined || input.quote === null) throw new QuoteValidationError('"quote" is required: the persisted payment state (~/.onchainos/payments/<paymentId>.json) or the JSON output of onchainos payment quote');
  if (input.expected !== undefined && (input.expected === null || typeof input.expected !== 'object' || Array.isArray(input.expected))) throw new QuoteValidationError('"expected" must be an object');
  const nq = binding.normalizeQuote(input.quote);
  const nowSec = Math.floor((deps.now === undefined ? Date.now() : Number(deps.now)) / 1000);

  const signedList = nq.rawAccepts || (nq.bodyChallenge ? nq.bodyChallenge.accepts : null) || nq.accepts;
  if (!signedList || !signedList.length) throw new QuoteValidationError('the quote has no accepts entries');
  const defaultIndex = binding.cliDefaultIndex(nq.rawAccepts || nq.accepts);
  let index = defaultIndex;
  if (input.selectedIndex !== undefined && input.selectedIndex !== null) {
    index = Number(input.selectedIndex);
    if (!Number.isInteger(index) || index < 0 || index >= signedList.length) throw new QuoteValidationError('"selectedIndex" must point at an accepts entry (0..' + (signedList.length - 1) + ')');
  }

  let expected = input.expected || null;
  let expectedSource = expected ? 'request' : null;
  if (!expected && input.sid !== undefined && input.sid !== null) {
    const fromScan = expectedFromScan(input.sid, deps);
    expected = fromScan.expected;
    expectedSource = fromScan.source;
  }

  const extraFindings = [];
  const add = (code, message, extra) => extraFindings.push({ code, message, extra });
  let challenge;
  let bodyChallenge = null;
  let challengeLabel;
  let bodyChallengeLabel;
  if (nq.rawAccepts) {
    challenge = { x402Version: (nq.bodyChallenge && nq.bodyChallenge.x402Version) || 2, resource: nq.resource || undefined, error: nq.bodyChallenge ? nq.bodyChallenge.error : undefined, accepts: nq.rawAccepts };
    bodyChallenge = nq.bodyChallenge;
    challengeLabel = 'persisted quote entries that payment pay signs';
    bodyChallengeLabel = 'merchant 402 body stored with the quote';
  } else if (nq.bodyChallenge) {
    challenge = nq.bodyChallenge;
  } else {
    if (!nq.accepts.length || !nq.decoded || !nq.decoded.recipient) throw new QuoteValidationError('the quote output has no challenge body and no decoded payee; pass the persisted state file instead');
    challenge = { x402Version: 2, resource: nq.endpointUrl ? { url: nq.endpointUrl } : undefined, accepts: nq.accepts.map((e) => ({ scheme: e.scheme, network: e.network, amount: e.amount, asset: e.asset, payTo: nq.decoded.recipient })) };
    add('quote_partial', 'The quote output carries no challenge body (the seller sends only the PAYMENT-REQUIRED header), so extra.name, extra.version and free-text fields were not checked.', { subject: 'quote' });
  }

  // The quote's own summary must describe the entry that will be signed.
  const signedEntries = challenge.accepts;
  const signed = signedEntries[index];
  const problems = [];
  const summaryEntry = nq.accepts.find((e) => Number(e.index) === index);
  if (summaryEntry && signed) {
    if (String(summaryEntry.amount) !== String(signed.amount)) problems.push('accepts[' + index + '].amount ' + summaryEntry.amount + ' in the summary, ' + signed.amount + ' signed');
    if (summaryEntry.asset && !eqAddr(summaryEntry.asset, signed.asset)) problems.push('accepts[' + index + '].asset ' + summaryEntry.asset + ' in the summary, ' + signed.asset + ' signed');
    if (summaryEntry.network && summaryEntry.network !== signed.network) problems.push('accepts[' + index + '].network ' + summaryEntry.network + ' in the summary, ' + signed.network + ' signed');
    if (summaryEntry.scheme && signed.scheme && summaryEntry.scheme !== signed.scheme) problems.push('accepts[' + index + '].scheme differs between summary and signed entry');
  }
  const cand = nq.candidates.find((c) => Number(c.acceptsIndex) === index);
  if (cand && signed && cand.amount !== undefined && String(cand.amount) !== String(signed.amount)) problems.push('candidate amount ' + cand.amount + ', signed ' + signed.amount);
  if (nq.decoded && (nq.decoded.recipient || nq.decoded.amount !== undefined)) {
    const rec = nq.candidates.find((c) => c.recommended);
    const di = rec && Number.isInteger(Number(rec.acceptsIndex)) ? Number(rec.acceptsIndex) : defaultIndex;
    const d = signedEntries[di];
    if (d) {
      const decodedProblems = [];
      if (nq.decoded.recipient && !eqAddr(nq.decoded.recipient, d.payTo)) decodedProblems.push('the wallet decoded payee ' + nq.decoded.recipient + ', the entry pays ' + d.payTo);
      if (nq.decoded.amount !== undefined && String(nq.decoded.amount) !== String(d.amount)) decodedProblems.push('the wallet decoded amount ' + nq.decoded.amount + ', the entry asks ' + d.amount);
      if (decodedProblems.length && nq.rawAccepts) problems.push.apply(problems, decodedProblems);
      else if (decodedProblems.length) add('challenge_header_body_mismatch', 'The 402 body shows a different payment than the challenge the wallet decoded: ' + decodedProblems.join('; ') + '.', { subject: 'challenge' });
    }
  }
  if (problems.length && nq.rawAccepts) add('quote_inconsistent', 'Quote ' + nq.paymentId + ' disagrees with itself: ' + problems.slice(0, 3).join('; ') + '.', { subject: 'quote', problems });
  else if (problems.length) add('challenge_header_body_mismatch', 'The 402 body shows a different payment than the challenge the wallet decoded: ' + problems.slice(0, 3).join('; ') + '.', { subject: 'challenge', problems });
  const expired = Boolean(nq.expiresAt && nowSec > nq.expiresAt);
  if (expired) add('quote_expired', 'Quote ' + nq.paymentId + ' expired at ' + new Date(nq.expiresAt * 1000).toISOString() + '.', { subject: 'quote' });

  const result = await paysafe.checkPayment({
    paymentRequired: challenge,
    bodyChallenge,
    challengeLabel,
    bodyChallengeLabel,
    requestUrl: nq.endpointUrl || undefined,
    expected: expected || undefined,
    context: input.context,
    selectedIndex: index,
  }, Object.assign({}, deps, { extraFindings, statsKind: 'check-quote' }));

  const fp = binding.fingerprint(nq, index);
  const next = result.verdict === 'ALLOW' && !expired ? nextCommand(nq, index) : { command: null, note: result.verdict === 'ALLOW' ? 'Quote again; this one expired.' : 'No pay command on ' + result.verdict + '.' };
  result.summary = 'Quote ' + nq.paymentId + ': ' + result.summary;
  result.next_command = next.command;
  result.binding = fp ? { paymentId: nq.paymentId, selectedIndex: index, fingerprint: fp, verdict: result.verdict, expiresAt: nq.expiresAt } : null;
  result.details.quote = {
    source: nq.source,
    paymentId: nq.paymentId,
    endpoint: nq.endpointUrl,
    method: nq.method,
    selectedIndex: index,
    cliDefaultIndex: defaultIndex,
    expiresAt: nq.expiresAt ? new Date(nq.expiresAt * 1000).toISOString() : null,
    balanceStatus: cand ? cand.balanceStatus || null : null,
    expectedSource,
    note: next.note,
  };
  if (!fp) result.details.quote.bindingNote = 'Bind a verdict with the persisted state file; the quote output does not include the signed entries.';
  return result;
}

module.exports = { checkQuote, QuoteValidationError };
