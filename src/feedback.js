'use strict';

/**
 * Verdict feedback: agents or owners mark a verdict as correct or a false
 * positive/negative, per rule code. Produces the false-positive share per rule
 * that decides whether thresholds need tuning before anything is priced.
 */

const RATE_LIMIT_PER_HOUR = 60;
const KEEP_RECENT = 500;

class FeedbackValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ValidationError';
  }
}

function normalize(input, knownRules) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new FeedbackValidationError('Request body must be a JSON object');
  const out = {};
  if (input.request_id !== undefined && input.request_id !== null) {
    if (typeof input.request_id !== 'string' || !/^[A-Za-z0-9-]{8,64}$/.test(input.request_id)) throw new FeedbackValidationError('"request_id" must be the id returned in details.request_id');
    out.request_id = input.request_id;
  }
  if (!['ALLOW', 'WARN', 'DENY'].includes(input.verdict)) throw new FeedbackValidationError('"verdict" must be ALLOW, WARN or DENY (the verdict you received)');
  out.verdict = input.verdict;
  if (typeof input.correct !== 'boolean') throw new FeedbackValidationError('"correct" must be true (verdict was right) or false (false positive / false negative)');
  out.correct = input.correct;
  let codes = input.rule_codes !== undefined ? input.rule_codes : input.rule_code !== undefined ? [input.rule_code] : [];
  if (!Array.isArray(codes)) throw new FeedbackValidationError('"rule_codes" must be an array of rule codes');
  if (codes.length > 12) throw new FeedbackValidationError('"rule_codes" may contain at most 12 codes');
  out.rule_codes = codes.map((c) => {
    if (typeof c !== 'string' || !knownRules.has(c)) throw new FeedbackValidationError('unknown rule code "' + c + '"; see GET /rules');
    return c;
  });
  if (out.verdict !== 'ALLOW' && out.rule_codes.length === 0) throw new FeedbackValidationError('"rule_codes" is required for WARN/DENY feedback');
  if (input.comment !== undefined && input.comment !== null) {
    if (typeof input.comment !== 'string' || input.comment.length > 500) throw new FeedbackValidationError('"comment" must be a string of at most 500 characters');
    out.comment = input.comment;
  }
  if (input.session_id !== undefined && input.session_id !== null) {
    if (typeof input.session_id !== 'string' || input.session_id.length > 128) throw new FeedbackValidationError('"session_id" must be a string of at most 128 characters');
    out.session_id = input.session_id;
  }
  return out;
}

async function submit(store, fb, reporter, now) {
  now = now === undefined ? Date.now() : now;
  const hour = Math.floor(now / 3600000);
  const rlKey = 'feedback:rl:' + (reporter || 'anon') + ':' + hour;
  const count = await store.command('INCRBY', rlKey, 1);
  await store.command('EXPIRE', rlKey, 3700);
  if (Number(count) > RATE_LIMIT_PER_HOUR) {
    const err = new Error('feedback rate limit exceeded (' + RATE_LIMIT_PER_HOUR + ' per hour)');
    err.status = 429;
    throw err;
  }
  const outcome = fb.correct ? 'correct' : 'false';
  const cmds = [['INCRBY', 'feedback:total', 1], ['INCRBY', 'feedback:' + outcome, 1], ['INCRBY', 'feedback:verdict:' + fb.verdict + ':' + outcome, 1]];
  for (const code of fb.rule_codes) cmds.push(['INCRBY', 'feedback:rule:' + code + ':' + outcome, 1]);
  const entry = JSON.stringify({ ts: now, verdict: fb.verdict, correct: fb.correct, rule_codes: fb.rule_codes, request_id: fb.request_id || null, comment: fb.comment || null, session_id: fb.session_id || null });
  cmds.push(['RPUSH', 'feedback:recent', entry], ['LTRIM', 'feedback:recent', -KEEP_RECENT, -1]);
  await store.pipeline(cmds);
  return { accepted: true, outcome, rule_codes: fb.rule_codes };
}

async function recent(store, limit) {
  const items = await store.command('LRANGE', 'feedback:recent', -(limit || 50), -1);
  return (items || []).map((s) => { try { return JSON.parse(s); } catch { return null; } }).filter(Boolean).reverse();
}

module.exports = { normalize, submit, recent, FeedbackValidationError, RATE_LIMIT_PER_HOUR };
