'use strict';

/**
 * Owner alerts: when a verdict is DENY (or WARN, if requested) Guardian POSTs a
 * short JSON event to context.alert_webhook so the human behind the agent sees
 * the block in real time instead of in tomorrow's logs.
 *
 * SSRF-safe: https only, public hostnames only. Payloads carry no secrets and
 * are optionally HMAC-signed with ALERT_SIGNING_SECRET.
 */

const crypto = require('crypto');

const ALERT_TIMEOUT_MS = Number.parseInt(process.env.ALERT_TIMEOUT_MS || '2500', 10);
const MAX_URL = 512;

function isPrivateHost(host) {
  const h = host.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h === '0.0.0.0') return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  if (h.startsWith('[') || h.includes(':')) return true; // IPv6 literals are not accepted
  return false;
}

/** @returns {{ok:boolean, url?:string, error?:string}} */
function validateWebhook(raw) {
  if (raw === undefined || raw === null) return { ok: true, url: null };
  if (typeof raw !== 'string' || raw.length > MAX_URL) return { ok: false, error: '"context.alert_webhook" must be an https URL of at most ' + MAX_URL + ' characters' };
  let u;
  try {
    u = new URL(raw);
  } catch {
    return { ok: false, error: '"context.alert_webhook" is not a valid URL' };
  }
  if (u.protocol !== 'https:') return { ok: false, error: '"context.alert_webhook" must use https' };
  if (u.username || u.password) return { ok: false, error: '"context.alert_webhook" must not embed credentials' };
  if (isPrivateHost(u.hostname)) return { ok: false, error: '"context.alert_webhook" must point at a public host' };
  return { ok: true, url: u.toString() };
}

function buildPayload(p) {
  return {
    event: 'guardian.' + p.verdict.toLowerCase(),
    service: 'guardian-mcp',
    version: p.version || null,
    timestamp: new Date().toISOString(),
    verdict: p.verdict,
    risk_score: p.riskScore,
    reasons: p.reasons,
    summary: p.summary,
    message: 'Your agent tried to ' + (p.actionText || 'perform an on-chain action') + '; ' + (p.verdict === 'DENY' ? 'blocked' : 'flagged') + ' by ' + p.reasons.join(', ') + '.',
    kind: p.kind,
    chainId: p.chainId,
    to: p.to || null,
    selector: p.selector || null,
    session_id: p.sessionId || null,
    session_status: p.sessionStatus || null,
    agent_goal: p.agentGoal || null,
  };
}

async function send(url, payload, env) {
  env = env || process.env;
  const body = JSON.stringify(payload);
  const headers = { 'content-type': 'application/json', 'user-agent': 'guardian-mcp-alerts/1', 'x-guardian-event': payload.event };
  const secret = env.ALERT_SIGNING_SECRET;
  if (secret) headers['x-guardian-signature'] = 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ALERT_TIMEOUT_MS);
  const started = Date.now();
  try {
    const res = await fetch(url, { method: 'POST', headers, body, signal: controller.signal, redirect: 'manual' });
    return { sent: res.ok, status: res.status, error: res.ok ? null : 'webhook responded ' + res.status, duration_ms: Date.now() - started, signed: Boolean(secret) };
  } catch (err) {
    return { sent: false, status: null, error: err.name === 'AbortError' ? 'webhook timed out after ' + ALERT_TIMEOUT_MS + 'ms' : err.message, duration_ms: Date.now() - started, signed: Boolean(secret) };
  } finally {
    clearTimeout(timer);
  }
}

function shouldAlert(verdict, alertOn) {
  if (verdict === 'DENY') return true;
  if (verdict === 'WARN' && alertOn === 'warn') return true;
  return false;
}

module.exports = { validateWebhook, buildPayload, send, shouldAlert, isPrivateHost, ALERT_TIMEOUT_MS };
