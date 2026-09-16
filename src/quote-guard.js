'use strict';

/**
 * Time-of-check / time-of-use guard for Onchain OS payments.
 *
 * `onchainos payment quote` re-requests the 402 and persists a paymentId. A seller can serve one challenge
 * to the check and another to the quote. Compare the quote candidate that will be signed with the accepts
 * entry Guardian checked: payee, atomic amount, token and network must be identical.
 *
 * @param {object} quote   parsed JSON of `onchainos payment quote`
 * @param {object} checked { index, payTo, amount: { atomic }, asset: { address }, network }
 * @returns {{ok: boolean, problems: string[], paymentId?: string, balanceStatus?: string, shortfall?: string, candidate?: object}}
 */
function compareQuote(quote, checked) {
  const d = quote && quote.data;
  if (!d || !Array.isArray(d.candidates)) return { ok: false, problems: ['quote returned no candidates'] };
  const cand = d.candidates.find((c) => Number(c.acceptsIndex) === checked.index);
  if (!cand) return { ok: false, problems: ['quote has no candidate for accepts[' + checked.index + ']'] };
  const acc = Array.isArray(d.accepts) ? d.accepts.find((a) => Number(a.index) === checked.index) : null;
  const problems = [];
  if (String(cand.depositAddress || '').toLowerCase() !== String(checked.payTo || '').toLowerCase()) problems.push('payee changed: checked ' + checked.payTo + ', quote pays ' + cand.depositAddress);
  if (String(cand.amount) !== String(checked.amount.atomic)) problems.push('amount changed: checked ' + checked.amount.atomic + ', quote ' + cand.amount);
  if (acc && checked.asset && String(acc.asset || '').toLowerCase() !== String(checked.asset.address).toLowerCase()) problems.push('token changed: checked ' + checked.asset.address + ', quote ' + acc.asset);
  if (acc && acc.network && checked.network && acc.network !== checked.network) problems.push('network changed: checked ' + checked.network + ', quote ' + acc.network);
  return { ok: problems.length === 0, problems, paymentId: d.paymentId, balanceStatus: cand.balanceStatus, shortfall: cand.shortfall, candidate: cand };
}

module.exports = { compareQuote };
