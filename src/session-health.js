'use strict';

/**
 * Session health: a rolling risk profile per session_id.
 *
 * Prompt injection rarely shows up as one huge transaction; it shows up as a
 * series of small suspicious ones. Every analysed transaction or signature is
 * appended to the session's event log (kept in the shared store), and the
 * verdict of the *current* request takes the accumulated picture into account.
 */

const { hashToObject } = require('./store');

const DEFAULTS = { SESSION_TTL_MS: 3600000, SESSION_WARN_THRESHOLD: 3, SESSION_DENY_THRESHOLD: 2, SESSION_RISK_THRESHOLD: 150, SESSION_EVENTS_KEEP: 50 };

function cfg(env) {
  env = env || process.env;
  const n = (k) => {
    const v = Number.parseInt(env[k] || '', 10);
    return Number.isInteger(v) && v > 0 ? v : DEFAULTS[k];
  };
  return { ttlMs: n('SESSION_TTL_MS'), warnThreshold: n('SESSION_WARN_THRESHOLD'), denyThreshold: n('SESSION_DENY_THRESHOLD'), riskThreshold: n('SESSION_RISK_THRESHOLD'), keep: n('SESSION_EVENTS_KEEP') };
}

function key(sessionId) {
  return 'session:' + sessionId;
}

function summarize(hash, events, c, now) {
  const h = hashToObject(hash);
  const parsed = [];
  for (const e of events || []) {
    try {
      parsed.push(JSON.parse(e));
    } catch {
      /* skip corrupt entry */
    }
  }
  const windowStart = now - c.ttlMs;
  const inWindow = parsed.filter((e) => e.ts >= windowStart);
  const warns = inWindow.filter((e) => e.verdict === 'WARN').length;
  const denies = inWindow.filter((e) => e.verdict === 'DENY').length;
  const riskInWindow = inWindow.reduce((s, e) => s + (Number(e.risk) || 0), 0);
  let status = 'healthy';
  const reasons = [];
  if (warns >= c.warnThreshold) reasons.push(warns + ' WARN verdicts in the last ' + Math.round(c.ttlMs / 60000) + ' min (threshold ' + c.warnThreshold + ')');
  if (denies >= c.denyThreshold) reasons.push(denies + ' DENY verdicts in the last ' + Math.round(c.ttlMs / 60000) + ' min (threshold ' + c.denyThreshold + ')');
  if (riskInWindow >= c.riskThreshold) reasons.push('cumulative risk ' + riskInWindow + ' in window (threshold ' + c.riskThreshold + ')');
  if (reasons.length) status = 'compromised_likely';
  else if (warns >= 2 || denies >= 1 || riskInWindow >= 60) status = 'elevated';
  const codeCounts = {};
  for (const e of inWindow) for (const code of e.codes || []) codeCounts[code] = (codeCounts[code] || 0) + 1;
  return {
    status,
    status_reasons: reasons,
    window_minutes: Math.round(c.ttlMs / 60000),
    tx_count_total: Number(h.tx_count || 0),
    warn_count_total: Number(h.warn_count || 0),
    deny_count_total: Number(h.deny_count || 0),
    cumulative_risk_total: Number(h.risk_sum || 0),
    tx_count_window: inWindow.length,
    warn_count_window: warns,
    deny_count_window: denies,
    cumulative_risk_window: riskInWindow,
    avg_risk_window: inWindow.length ? Math.round(riskInWindow / inWindow.length) : 0,
    top_rules_window: Object.entries(codeCounts).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([code, count]) => ({ code, count })),
    first_seen: h.first_seen ? new Date(Number(h.first_seen)).toISOString() : null,
    last_seen: h.last_seen ? new Date(Number(h.last_seen)).toISOString() : null,
    recent_events: parsed.slice(-10).map((e) => ({ ts: new Date(e.ts).toISOString(), kind: e.kind, verdict: e.verdict, risk: e.risk, codes: e.codes, to: e.to || null, selector: e.selector || null })),
  };
}

/** Append the current result to the session and return the updated profile. */
async function record(store, sessionId, event, env, now) {
  const c = cfg(env);
  now = now === undefined ? Date.now() : now;
  const k = key(sessionId);
  const entry = JSON.stringify({ ts: now, kind: event.kind, verdict: event.verdict, risk: event.risk, codes: (event.codes || []).slice(0, 12), to: event.to || null, selector: event.selector || null });
  const ttl = Math.ceil(c.ttlMs / 1000) * 2;
  const res = await store.pipeline([
    ['HINCRBY', k, 'tx_count', 1],
    ['HINCRBY', k, event.verdict === 'WARN' ? 'warn_count' : event.verdict === 'DENY' ? 'deny_count' : 'allow_count', 1],
    ['HINCRBY', k, 'risk_sum', Number(event.risk) || 0],
    ['HSETNX', k, 'first_seen', now],
    ['HSET', k, 'last_seen', now],
    ['EXPIRE', k, ttl],
    ['RPUSH', k + ':events', entry],
    ['LTRIM', k + ':events', -c.keep, -1],
    ['EXPIRE', k + ':events', ttl],
    ['HGETALL', k],
    ['LRANGE', k + ':events', 0, -1],
  ]);
  return summarize(res[9], res[10], c, now);
}

async function profile(store, sessionId, env, now) {
  const c = cfg(env);
  now = now === undefined ? Date.now() : now;
  const k = key(sessionId);
  const [hash, events] = await store.pipeline([['HGETALL', k], ['LRANGE', k + ':events', 0, -1]]);
  const h = hashToObject(hash);
  if (!h || Object.keys(h).length === 0) return null;
  return summarize(hash, events, c, now);
}

/** Turn a profile into a finding for the current request (or null). */
function evaluate(p) {
  if (!p) return null;
  if (p.status === 'compromised_likely') {
    return { code: 'session_compromised_likely', severity: 'DENY', message: 'Session health is compromised_likely: ' + p.status_reasons.join('; ') + '. A series of suspicious actions is the signature of an injected instruction stream; stop and hand control back to the user.', layer: 'session', status: p.status, warn_count_window: p.warn_count_window, deny_count_window: p.deny_count_window, cumulative_risk_window: p.cumulative_risk_window };
  }
  if (p.status === 'elevated') {
    return { code: 'session_risk_elevated', severity: 'WARN', message: 'Session risk is elevated: ' + p.warn_count_window + ' WARN and ' + p.deny_count_window + ' DENY verdicts, cumulative risk ' + p.cumulative_risk_window + ' in the last ' + p.window_minutes + ' min.', layer: 'session', status: p.status, warn_count_window: p.warn_count_window, deny_count_window: p.deny_count_window, cumulative_risk_window: p.cumulative_risk_window };
  }
  return null;
}

const SESSION_RULES = [
  { code: 'session_compromised_likely', severity: 'DENY', layer: 'session', description: 'Within SESSION_TTL_MS the session accumulated >= SESSION_WARN_THRESHOLD WARN verdicts, >= SESSION_DENY_THRESHOLD DENY verdicts, or cumulative risk >= SESSION_RISK_THRESHOLD. Stop signal for the agent.' },
  { code: 'session_risk_elevated', severity: 'WARN', layer: 'session', description: 'Session has 2+ WARN, 1+ DENY or cumulative risk >= 60 within the window.' },
];

module.exports = { record, profile, evaluate, cfg, SESSION_RULES };
