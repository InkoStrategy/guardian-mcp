'use strict';

/**
 * Differential check: compare the proposed transaction with a reference
 * template the agent received from a trusted source (context.reference_tx).
 * An agent that follows a template but drifts from it is a red flag.
 *
 * Both sides are passed already decoded: { to, chainId, value (bigint), decoded, nested }.
 */

const CRITICAL = 'critical';
const NOTABLE = 'notable';
const INFO = 'info';

function lower(a) {
  return a ? String(a).toLowerCase() : null;
}

function isUnlimited(big) {
  return big !== null && big !== undefined && big > 2n ** 255n - 1n;
}

function innerApprovalSet(nested) {
  const out = new Set();
  if (!nested) return out;
  for (const i of nested.inner || []) if (i.kind === 'approve' || i.kind === 'approvalForAll') out.add((i.kind + ':' + (i.args.spender || i.args.operator || '')).toLowerCase());
  for (const p of nested.permits || []) out.add(('permit2:' + p.spender).toLowerCase());
  return out;
}

function thirdPartyRecipients(nested) {
  const out = new Set();
  if (!nested) return out;
  for (const r of nested.recipients || []) if (r.thirdParty) out.add(lower(r.address));
  return out;
}

function planCommands(nested) {
  return nested && nested.routerPlan ? nested.routerPlan.map((s) => s.command) : null;
}

/**
 * @returns {{matches:boolean, changes:object[], critical:number, notable:number}}
 */
function compare(ref, cur) {
  const changes = [];
  const push = (field, level, expected, actual, note) => changes.push({ field, level, expected, actual, note });

  if (ref.chainId !== cur.chainId) push('chainId', CRITICAL, ref.chainId, cur.chainId, 'transaction moved to a different chain');
  if (lower(ref.to) !== lower(cur.to)) push('to', CRITICAL, ref.to, cur.to, 'target contract or recipient differs from the template');
  if ((ref.decoded.selector || null) !== (cur.decoded.selector || null)) {
    push('function', CRITICAL, ref.decoded.function || ref.decoded.selector || 'native transfer', cur.decoded.function || cur.decoded.selector || 'native transfer', 'a different function is being called');
  }

  const rk = ref.decoded.kind;
  const ck = cur.decoded.kind;
  if (rk === ck) {
    if (ck === 'approve') {
      if (lower(ref.decoded.args.spender) !== lower(cur.decoded.args.spender)) push('spender', CRITICAL, ref.decoded.args.spender, cur.decoded.args.spender, 'approval spender differs from the template');
      const ra = ref.decoded.amountBig;
      const ca = cur.decoded.amountBig;
      if (ra !== null && ca !== null) {
        if (!isUnlimited(ra) && isUnlimited(ca)) push('amount', CRITICAL, ra.toString(), ca.toString(), 'template approved a bounded amount, proposal is unlimited');
        else if (ca > ra) push('amount', NOTABLE, ra.toString(), ca.toString(), 'approval amount increased');
        else if (ca < ra) push('amount', INFO, ra.toString(), ca.toString(), 'approval amount decreased');
      }
    } else if (ck === 'approvalForAll') {
      if (lower(ref.decoded.args.operator) !== lower(cur.decoded.args.operator)) push('operator', CRITICAL, ref.decoded.args.operator, cur.decoded.args.operator, 'operator differs from the template');
      if (!ref.decoded.args.approved && cur.decoded.args.approved) push('approved', CRITICAL, false, true, 'template revoked, proposal grants');
    } else if (ck === 'transfer') {
      if (lower(ref.decoded.args.recipient) !== lower(cur.decoded.args.recipient)) push('recipient', CRITICAL, ref.decoded.args.recipient, cur.decoded.args.recipient, 'transfer recipient differs from the template');
      const ra = ref.decoded.amountBig;
      const ca = cur.decoded.amountBig;
      if (ra !== null && ca !== null) {
        if (ca > ra) push('amount', NOTABLE, ra.toString(), ca.toString(), 'transfer amount increased');
        else if (ca < ra) push('amount', INFO, ra.toString(), ca.toString(), 'transfer amount decreased');
      }
    }
  }

  if (ref.value !== cur.value) {
    if (cur.value > ref.value) push('value', ref.value === 0n ? CRITICAL : NOTABLE, ref.value.toString(), cur.value.toString(), ref.value === 0n ? 'template sent no native value, proposal does' : 'native value increased');
    else push('value', INFO, ref.value.toString(), cur.value.toString(), 'native value decreased');
  }

  // Nested structure
  const refApprovals = innerApprovalSet(ref.nested);
  const curApprovals = innerApprovalSet(cur.nested);
  for (const a of curApprovals) if (!refApprovals.has(a)) push('nested_approval', CRITICAL, Array.from(refApprovals), a, 'an approval or permit appeared inside the call that the template does not have');
  const refOut = thirdPartyRecipients(ref.nested);
  const curOut = thirdPartyRecipients(cur.nested);
  for (const r of curOut) if (!refOut.has(r)) push('nested_recipient', CRITICAL, Array.from(refOut), r, 'router output now goes to an address the template does not send to');
  const refPlan = planCommands(ref.nested);
  const curPlan = planCommands(cur.nested);
  if (refPlan && curPlan && refPlan.join(',') !== curPlan.join(',')) {
    const added = curPlan.filter((c) => !refPlan.includes(c));
    const dangerous = added.filter((c) => /TRANSFER|SWEEP|PERMIT2|PAY_PORTION|SUB_PLAN/.test(c));
    push('router_plan', dangerous.length ? CRITICAL : NOTABLE, refPlan, curPlan, dangerous.length ? 'router plan gained money-moving commands: ' + dangerous.join(', ') : 'router plan differs from the template');
  }
  if (ref.nested && cur.nested) {
    for (let i = 0; i < Math.min(ref.nested.permits.length, cur.nested.permits.length); i += 1) {
      const rp = ref.nested.permits[i];
      const cp = cur.nested.permits[i];
      if (lower(rp.spender) !== lower(cp.spender)) push('permit_spender', CRITICAL, rp.spender, cp.spender, 'Permit2 spender inside the router call changed');
      if (!rp.unlimited && cp.unlimited) push('permit_amount', CRITICAL, rp.amount, cp.amount, 'Permit2 permit became unlimited');
    }
  }

  const critical = changes.filter((c) => c.level === CRITICAL).length;
  const notable = changes.filter((c) => c.level === NOTABLE).length;
  return { matches: changes.length === 0, changes, critical, notable };
}

function toFinding(diff) {
  if (!diff || diff.matches) return null;
  const describe = (c) => c.field + ' (' + c.note + ')';
  if (diff.critical > 0) {
    const crit = diff.changes.filter((c) => c.level === CRITICAL);
    return { code: 'template_critical_deviation', severity: 'DENY', message: 'Proposal deviates from the trusted template in ' + diff.critical + ' critical way(s): ' + crit.map(describe).join('; ') + '.', layer: 'differential', changes: crit };
  }
  if (diff.notable > 0) {
    const nb = diff.changes.filter((c) => c.level === NOTABLE);
    return { code: 'template_deviation', severity: 'WARN', message: 'Proposal deviates from the trusted template: ' + nb.map(describe).join('; ') + '.', layer: 'differential', changes: nb };
  }
  return null; // only informational differences (amounts decreased)
}

const DIFF_RULES = [
  { code: 'template_critical_deviation', severity: 'DENY', layer: 'differential', description: 'Compared with context.reference_tx: target, function, recipient, spender or operator changed; bounded approval became unlimited; native value appeared; an approval/permit or a new output recipient appeared inside the call; router plan gained money-moving commands.' },
  { code: 'template_deviation', severity: 'WARN', layer: 'differential', description: 'Compared with context.reference_tx: amount or native value increased, or the router plan differs in non-money-moving commands.' },
];

module.exports = { compare, toFinding, DIFF_RULES };
