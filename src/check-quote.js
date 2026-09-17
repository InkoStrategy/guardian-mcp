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

function eqAddr(a, b) {
  return typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
}

// x402 v1 entries carry maxAmountRequired and a v1 network name ("x-layer"); v2 carry amount and eip155:196.
const amountOf = (e) => (e && e.amount !== undefined && e.amount !== null && e.amount !== '' ? e.amount : e && e.maxAmountRequired);
const netOf = (n) => paysafe._internals.parseNetwork(n).network;

/** A listing with something to compare (price, token or payee), not just an endpoint. NaN price does not count. */
function listingHasChecks(expected) {
  return Boolean(expected && (Number.isFinite(Number(expected.feeAmount)) || Number.isFinite(Number(expected.maxAmount)) || expected.feeToken || expected.payTo));
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

/**
 * @param {object} input see file header
 * @param {object} deps  checkPayment deps plus { trustScan: () => scan, now }
 */
async function checkQuote(input, deps) {
  try {
    return await checkQuoteInner(input, deps);
  } catch (err) {
    if (err && err.name === 'ValidationError') throw err;
    // Any other throw on caller-supplied quote fields is bad input, not a server fault: 400, not 500.
    throw new QuoteValidationError('the quote could not be checked: ' + String(err && err.message).slice(0, 200));
  }
}

async function checkQuoteInner(input, deps) {
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
  if (!listingHasChecks(expected) && input.sid !== undefined && input.sid !== null) {
    const fromScan = expectedFromScan(input.sid, deps);
    if (fromScan.expected) { expected = fromScan.expected; }
    expectedSource = fromScan.source;
  }

  const extraFindings = [];
  const add = (code, message, extra) => extraFindings.push({ code, message, extra });
  // No listing to compare (no expected, or a sid that resolved to nothing) is never a clean ALLOW: price,
  // token and payee went unchecked, so the best verdict is WARN and no pay command is offered.
  const listingCompared = listingHasChecks(expected);
  if (!listingCompared) add('listing_not_checked', 'No marketplace listing was compared for ' + nq.paymentId + (input.sid !== undefined && input.sid !== null ? ' (' + expectedSource + ')' : '') + '; price, token and payee were not checked against a listing.', { subject: 'quote' });
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
    // Quote output, no persisted entries. Drop the seller-written resource so checkPayment does not use
    // resource.url as the pay host, and mark it partial: only the persisted state is what pay signs.
    challenge = Object.assign({}, nq.bodyChallenge, { resource: undefined });
    add('quote_partial', 'The quote output does not include the URL the CLI called or the entries payment pay signs, so the endpoint and non-recommended payees were not verified. Check the persisted state file ~/.onchainos/payments/' + nq.paymentId + '.json.', { subject: 'quote' });
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
    if (String(amountOf(summaryEntry)) !== String(amountOf(signed))) problems.push('accepts[' + index + '].amount ' + amountOf(summaryEntry) + ' in the summary, ' + amountOf(signed) + ' signed');
    if (summaryEntry.asset && !eqAddr(summaryEntry.asset, signed.asset)) problems.push('accepts[' + index + '].asset ' + summaryEntry.asset + ' in the summary, ' + signed.asset + ' signed');
    if (summaryEntry.network && netOf(summaryEntry.network) !== netOf(signed.network)) problems.push('accepts[' + index + '].network ' + summaryEntry.network + ' in the summary, ' + signed.network + ' signed');
    if (summaryEntry.scheme && signed.scheme && summaryEntry.scheme !== signed.scheme) problems.push('accepts[' + index + '].scheme differs between summary and signed entry');
  }
  const cand = nq.candidates.find((c) => Number(c.acceptsIndex) === index);
  if (cand && signed && cand.amount !== undefined && String(cand.amount) !== String(amountOf(signed))) problems.push('candidate amount ' + cand.amount + ', signed ' + amountOf(signed));
  if (nq.decoded && (nq.decoded.recipient || nq.decoded.amount !== undefined)) {
    // The wallet's decodedChallenge names one payee/amount. With raw_accepts we know every entry's payee,
    // so only complain when no signed entry matches the decoded pair (not just the recommended one).
    const decodedMatches = (e) => e && (!nq.decoded.recipient || eqAddr(nq.decoded.recipient, e.payTo)) && (nq.decoded.amount === undefined || String(nq.decoded.amount) === String(amountOf(e)));
    const rec = nq.candidates.find((c) => c.recommended);
    const di = rec && Number.isInteger(Number(rec.acceptsIndex)) ? Number(rec.acceptsIndex) : defaultIndex;
    const d = nq.rawAccepts && signedEntries.some(decodedMatches) ? null : signedEntries[di];
    if (d) {
      const decodedProblems = [];
      if (nq.decoded.recipient && !eqAddr(nq.decoded.recipient, d.payTo)) decodedProblems.push('the wallet decoded payee ' + nq.decoded.recipient + ', the entry pays ' + d.payTo);
      if (nq.decoded.amount !== undefined && String(nq.decoded.amount) !== String(amountOf(d))) decodedProblems.push('the wallet decoded amount ' + nq.decoded.amount + ', the entry asks ' + amountOf(d));
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
  // A pay command is offered only for the persisted state, whose raw_accepts is what payment pay signs.
  const next = result.verdict === 'ALLOW' && !expired && nq.rawAccepts ? binding.payCommand(nq, index)
    : { command: null, note: result.verdict !== 'ALLOW' ? 'No pay command on ' + result.verdict + '.' : expired ? 'Quote again; this one expired.' : 'No pay command: pass the persisted state file, not the quote output, to bind and pay.' };
  result.summary = 'Quote ' + nq.paymentId + ': ' + result.summary;
  result.next_command = next.command;
  result.binding = fp ? { paymentId: nq.paymentId, selectedIndex: index, fingerprint: fp, verdict: result.verdict, expiresAt: nq.expiresAt, listingCompared } : null;
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
    listingCompared,
    note: next.note,
  };
  if (!fp) result.details.quote.bindingNote = 'Bind a verdict with the persisted state file; the quote output does not include the signed entries.';
  return result;
}

module.exports = { checkQuote, QuoteValidationError };
