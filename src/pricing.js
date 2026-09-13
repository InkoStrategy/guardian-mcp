'use strict';

/**
 * Layered pricing.
 *
 *   Basic /analyze (transaction firewall, nested calls, counterparty intel,
 *   simulation, shared-registry reads) is free forever: every free call feeds
 *   the shared threat registry, which is the moat.
 *
 *   Premium layers are what operators pay for: session health (session_id),
 *   owner alerts (alert_webhook), differential check (reference_tx) and the
 *   signature analyzer.
 *
 * PRICING_MODE:
 *   free     - nothing is ever charged (default)
 *   premium  - premium layers are charged via x402 (X402_PREMIUM_PRICE or X402_PRICE)
 *   auto     - charging switches on by usage, not by date: once calls >= FREE_CALLS
 *              or distinct sessions >= FREE_SESSIONS, AND FREE_DAYS have passed since
 *              the first real call. The switch is recorded (pricing:premium_since) and
 *              never flips back.
 *
 * GRANDFATHERED_PAYERS: comma-separated payer addresses that stay free for life
 * (early adopters who gave feedback). Their payment is verified but never settled.
 */

const DEFAULTS = { FREE_CALLS: 1000, FREE_SESSIONS: 20, FREE_DAYS: 30 };

function cfg(env) {
  env = env || process.env;
  const n = (k) => {
    const v = Number.parseInt(env[k] || '', 10);
    return Number.isInteger(v) && v >= 0 ? v : DEFAULTS[k];
  };
  const mode = String(env.PRICING_MODE || 'free').toLowerCase();
  return {
    mode: ['free', 'premium', 'auto'].includes(mode) ? mode : 'free',
    freeCalls: n('FREE_CALLS'),
    freeSessions: n('FREE_SESSIONS'),
    freeDays: n('FREE_DAYS'),
    premiumPrice: (env.X402_PREMIUM_PRICE || env.X402_PRICE || '0').trim(),
    grandfathered: new Set((env.GRANDFATHERED_PAYERS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)),
  };
}

/** Which request features are premium. */
function premiumFeatures(kind, body) {
  const ctx = body && body.context && typeof body.context === 'object' ? body.context : {};
  const features = [];
  if (kind === 'signature') features.push('signature_analysis');
  if (ctx.session_id) features.push('session_health');
  if (ctx.alert_webhook) features.push('owner_alerts');
  if (ctx.reference_tx) features.push('differential_check');
  return features;
}

/**
 * Decide whether premium layers are charged right now.
 * @returns {Promise<{mode:string, charging:boolean, reason:string, price:string, progress:object|null}>}
 */
async function resolve(store, env, now) {
  const c = cfg(env);
  now = now === undefined ? Date.now() : now;
  const base = { mode: c.mode, price: c.premiumPrice, progress: null };
  if (c.mode === 'free') return Object.assign(base, { charging: false, reason: 'PRICING_MODE=free: everything is free' });
  if (!(/^[0-9]+$/.test(c.premiumPrice) && BigInt(c.premiumPrice) > 0n)) return Object.assign(base, { charging: false, reason: 'no X402_PREMIUM_PRICE / X402_PRICE configured; premium layers stay free' });
  if (c.mode === 'premium') return Object.assign(base, { charging: true, reason: 'PRICING_MODE=premium' });

  const [since, calls, sessions, firstTs] = await store.pipeline([['GET', 'pricing:premium_since'], ['GET', 'stats:calls:total'], ['PFCOUNT', 'stats:sessions:total'], ['GET', 'stats:first_call_ts']]);
  const progress = { calls: Number(calls || 0), free_calls: c.freeCalls, sessions: Number(sessions || 0), free_sessions: c.freeSessions, first_call_at: firstTs ? new Date(Number(firstTs)).toISOString() : null, free_days: c.freeDays, premium_since: since ? new Date(Number(since)).toISOString() : null };
  base.progress = progress;
  if (since) return Object.assign(base, { charging: true, reason: 'auto: premium charging active since ' + progress.premium_since });
  const usageReached = progress.calls >= c.freeCalls || progress.sessions >= c.freeSessions;
  const daysPassed = firstTs ? (now - Number(firstTs)) / 86400000 : 0;
  if (usageReached && daysPassed >= c.freeDays) {
    await store.command('SET', 'pricing:premium_since', String(now), 'NX');
    return Object.assign(base, { charging: true, reason: 'auto: usage threshold reached and ' + c.freeDays + ' days passed; premium charging switched on now' });
  }
  const parts = [];
  if (!usageReached) parts.push('usage ' + progress.calls + '/' + c.freeCalls + ' calls, ' + progress.sessions + '/' + c.freeSessions + ' sessions');
  if (daysPassed < c.freeDays) parts.push(Math.floor(daysPassed) + '/' + c.freeDays + ' days since first call');
  return Object.assign(base, { charging: false, reason: 'auto: still in the free period (' + parts.join('; ') + ')' });
}

function isGrandfathered(payer, env) {
  if (!payer) return false;
  return cfg(env).grandfathered.has(String(payer).toLowerCase());
}

module.exports = { cfg, premiumFeatures, resolve, isGrandfathered, DEFAULTS };
