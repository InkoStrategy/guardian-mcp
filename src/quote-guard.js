'use strict';

/**
 * Time-of-check / time-of-use guard for Onchain OS payments.
 *
 * `onchainos payment quote` re-requests the 402 and persists a paymentId. A seller can serve one challenge
 * to the check and another to the quote. Compare what the quote will sign with the accepts entry Guardian
 * checked: payee, atomic amount, token and network must be identical.
 *
 * Quote fields: the payee is `decodedChallenge.recipient`. `candidates[].depositAddress` is the buyer's own
 * wallet (where to top up), never the payee.
 *
 * @param {object} quote   parsed JSON of `onchainos payment quote`
 * @param {object} checked { index, payTo, amount: { atomic }, asset: { address }, network }
 * @returns {{ok: boolean, kind: 'match'|'mismatch'|'unavailable', problems: string[], paymentId?: string, balanceStatus?: string, shortfall?: string, recipient?: string}}
 */
function compareQuote(quote, checked) {
  if (!quote || quote.ok === false || !quote.data) {
    return { ok: false, kind: 'unavailable', problems: ['quote failed: ' + (quote && quote.error ? String(quote.error).slice(0, 200) : 'no response')] };
  }
  const d = quote.data;
  if (!Array.isArray(d.candidates) || d.candidates.length === 0) return { ok: false, kind: 'unavailable', problems: ['quote returned no payable candidates'] };
  const cand = d.candidates.find((c) => Number(c.acceptsIndex) === checked.index);
  if (!cand) return { ok: false, kind: 'mismatch', problems: ['quote has no candidate for the checked accepts[' + checked.index + ']'] };
  const acc = Array.isArray(d.accepts) ? d.accepts.find((a) => Number(a.index) === checked.index) : null;
  const dc = d.decodedChallenge || {};
  const recipient = dc.recipient || null;
  const problems = [];
  if (!recipient) problems.push('quote does not expose the payee, so it cannot be compared');
  else if (String(recipient).toLowerCase() !== String(checked.payTo || '').toLowerCase()) problems.push('payee changed: checked ' + checked.payTo + ', quote pays ' + recipient);
  if (String(cand.amount) !== String(checked.amount.atomic)) problems.push('amount changed: checked ' + checked.amount.atomic + ', quote ' + cand.amount);
  if (dc.amount !== undefined && String(dc.amount) !== String(checked.amount.atomic)) problems.push('challenge amount changed: checked ' + checked.amount.atomic + ', quote challenge ' + dc.amount);
  if (acc && checked.asset && String(acc.asset || '').toLowerCase() !== String(checked.asset.address).toLowerCase()) problems.push('token changed: checked ' + checked.asset.address + ', quote ' + acc.asset);
  if (acc && acc.network && checked.network && acc.network !== checked.network) problems.push('network changed: checked ' + checked.network + ', quote ' + acc.network);
  return { ok: problems.length === 0, kind: problems.length ? 'mismatch' : 'match', problems, paymentId: d.paymentId, balanceStatus: cand.balanceStatus, shortfall: cand.shortfall, recipient };
}

module.exports = { compareQuote };
