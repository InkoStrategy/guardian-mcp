'use strict';

/**
 * Usage statistics for the public dashboard and the pricing trigger.
 * Everything is counters in the shared store; no request payloads are kept.
 */

const { hashToObject } = require('./store');

const DAYS_SHOWN = 14;

function day(ts) {
  return new Date(ts === undefined ? Date.now() : ts).toISOString().slice(0, 10);
}

/** Build the commands that record one analysed request. */
function usageCommands(p) {
  const d = day(p.now);
  const ttl = 400 * 86400;
  const cmds = [
    ['INCRBY', 'stats:calls:total', 1],
    ['INCRBY', 'stats:calls:' + d, 1],
    ['EXPIRE', 'stats:calls:' + d, ttl],
    ['INCRBY', 'stats:verdict:' + p.verdict, 1],
    ['INCRBY', 'stats:verdict:' + d + ':' + p.verdict, 1],
    ['EXPIRE', 'stats:verdict:' + d + ':' + p.verdict, ttl],
    ['INCRBY', 'stats:kind:' + p.kind, 1],
    ['SET', 'stats:first_call_ts', String(p.now === undefined ? Date.now() : p.now), 'NX'],
    ['SET', 'stats:last_call_ts', String(p.now === undefined ? Date.now() : p.now)],
  ];
  for (const code of p.codes || []) cmds.push(['INCRBY', 'stats:rule:' + code, 1]);
  if (p.sessionId) {
    cmds.push(['PFADD', 'stats:sessions:total', p.sessionId]);
    cmds.push(['PFADD', 'stats:sessions:' + d, p.sessionId], ['EXPIRE', 'stats:sessions:' + d, ttl]);
  }
  if (p.premium) cmds.push(['INCRBY', 'stats:premium:total', 1]);
  if (p.paid) cmds.push(['INCRBY', 'stats:paid:total', 1]);
  return cmds;
}

async function record(store, p) {
  return store.pipeline(usageCommands(p));
}

async function snapshot(store, opts) {
  opts = opts || {};
  const now = opts.now === undefined ? Date.now() : opts.now;
  const days = [];
  for (let i = DAYS_SHOWN - 1; i >= 0; i -= 1) days.push(day(now - i * 86400000));
  const ruleCodes = opts.ruleCodes || [];
  const cmds = [
    ['GET', 'stats:calls:total'],
    ['GET', 'stats:verdict:ALLOW'], ['GET', 'stats:verdict:WARN'], ['GET', 'stats:verdict:DENY'],
    ['GET', 'stats:kind:transaction'], ['GET', 'stats:kind:signature'],
    ['PFCOUNT', 'stats:sessions:total'],
    ['GET', 'stats:first_call_ts'], ['GET', 'stats:last_call_ts'],
    ['GET', 'stats:premium:total'], ['GET', 'stats:paid:total'],
    ['GET', 'threat:stats:reports'], ['ZCARD', 'threat:index:1'], ['ZCARD', 'threat:index:domains'],
    ['SCARD', 'seed:addresses'], ['SCARD', 'seed:domains'], ['HGETALL', 'seed:meta'],
  ];
  const fixed = cmds.length;
  for (const d of days) cmds.push(['GET', 'stats:calls:' + d], ['GET', 'stats:verdict:' + d + ':WARN'], ['GET', 'stats:verdict:' + d + ':DENY'], ['PFCOUNT', 'stats:sessions:' + d]);
  for (const c of ruleCodes) cmds.push(['GET', 'stats:rule:' + c], ['GET', 'feedback:rule:' + c + ':correct'], ['GET', 'feedback:rule:' + c + ':false']);
  cmds.push(['GET', 'feedback:total'], ['GET', 'feedback:correct'], ['GET', 'feedback:false'], ['GET', 'feedback:verdict:ALLOW:false']);
  const r = await store.pipeline(cmds);
  const n = (v) => Number(v || 0);
  const seedMeta = hashToObject(r[16]);
  const out = {
    generated_at: new Date(now).toISOString(),
    backend: store.kind,
    persistent: store.persistent,
    calls: { total: n(r[0]), transactions: n(r[4]), signatures: n(r[5]), premium: n(r[9]), paid: n(r[10]) },
    verdicts: { ALLOW: n(r[1]), WARN: n(r[2]), DENY: n(r[3]) },
    blocked_share: n(r[0]) ? Math.round((n(r[3]) / n(r[0])) * 1000) / 10 : 0,
    distinct_sessions: n(r[6]),
    first_call_at: r[7] ? new Date(Number(r[7])).toISOString() : null,
    last_call_at: r[8] ? new Date(Number(r[8])).toISOString() : null,
    threat_registry: { agent_reports: n(r[11]), flagged_addresses_chain_1: n(r[12]), flagged_domains: n(r[13]), seeded_addresses: n(r[14]), seeded_domains: n(r[15]), seed_source: seedMeta.source || null, seed_updated_at: seedMeta.updated_at || null },
    daily: [],
    rules: [],
    feedback: { total: 0, correct: 0, false: 0, false_share: 0, missed_attacks: 0 },
  };
  let i = fixed;
  for (const d of days) {
    out.daily.push({ day: d, calls: n(r[i]), warn: n(r[i + 1]), deny: n(r[i + 2]), sessions: n(r[i + 3]) });
    i += 4;
  }
  for (const c of ruleCodes) {
    const hits = n(r[i]);
    const correct = n(r[i + 1]);
    const wrong = n(r[i + 2]);
    i += 3;
    if (hits || correct || wrong) out.rules.push({ code: c, hits, feedback_correct: correct, feedback_false: wrong, false_share: correct + wrong ? Math.round((wrong / (correct + wrong)) * 1000) / 10 : null });
  }
  out.rules.sort((a, b) => b.hits - a.hits);
  out.feedback.total = n(r[i]);
  out.feedback.correct = n(r[i + 1]);
  out.feedback.false = n(r[i + 2]);
  out.feedback.false_share = out.feedback.total ? Math.round((out.feedback.false / out.feedback.total) * 1000) / 10 : 0;
  out.feedback.missed_attacks = n(r[i + 3]);
  if (!opts.internal) {
    // Public view: aggregates only. Per-rule hit counts and false shares would tell attackers which rules are weak.
    delete out.rules;
    out.feedback = { total: out.feedback.total };
  }
  return out;
}

module.exports = { record, usageCommands, snapshot, day };
