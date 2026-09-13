'use strict';

const { analyze, ValidationError, RULES, RULE_CATALOG } = require('../src/analyzer');
const { supportedChainIds, chainName } = require('../src/rpc');
const { getTrustedDomains, getSessionTtlMs, getLargeAmountRaw } = require('../src/context-analyzer');
const { analyzeSignature, SIGNATURE_RULES } = require('../src/signature');
const registry = require('../src/registry');
const threat = require('../src/threat-registry');
const sessionHealth = require('../src/session-health');
const { getStore } = require('../src/store');
const stats = require('../src/stats');
const feedback = require('../src/feedback');
const seed = require('../src/seed');
const pricing = require('../src/pricing');
const dashboard = require('../src/dashboard');
const premium = require('../src/premium');
const x402 = require('../src/x402');
const crypto = require('crypto');

const RULE_CODES = new Set(RULE_CATALOG.map((r) => r.code).concat(SIGNATURE_RULES.map((r) => r.code)));

function timingSafeEqual(a, b) {
  const x = Buffer.from(String(a || ''));
  const y = Buffer.from(String(b || ''));
  return x.length > 0 && x.length === y.length && crypto.timingSafeEqual(x, y);
}

function isAdmin(req) {
  const token = process.env.ADMIN_TOKEN;
  if (!token) return false;
  const header = req.headers['x-admin-token'] || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  return timingSafeEqual(header, token);
}

function isCron(req) {
  const secret = process.env.CRON_SECRET;
  if (!secret) return false;
  return timingSafeEqual((req.headers.authorization || '').replace(/^Bearer\s+/i, ''), secret);
}

const ALL_RULES = RULE_CATALOG.concat(SIGNATURE_RULES);
const pkg = require('../package.json');

const MAX_BODY_BYTES = 64 * 1024;

function send(res, status, payload) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(JSON.stringify(payload));
}

function setCors(res) {
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-methods', 'GET, POST, OPTIONS');
  res.setHeader('access-control-allow-headers', 'content-type, PAYMENT-SIGNATURE, X-PAYMENT');
  res.setHeader('access-control-expose-headers', 'PAYMENT-REQUIRED, PAYMENT-RESPONSE');
}

async function readBody(req) {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'object') return req.body;
    if (typeof req.body === 'string') {
      if (req.body.trim() === '') return {};
      return JSON.parse(req.body);
    }
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new ValidationError('Request body exceeds ' + MAX_BODY_BYTES + ' bytes');
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  return text.trim() === '' ? {} : JSON.parse(text);
}

function resourceUrl(req) {
  const proto = (req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  const host = (req.headers['x-forwarded-host'] || req.headers.host || 'localhost').split(',')[0].trim();
  const path = (req.url || '/').split('?')[0];
  return proto + '://' + host + path;
}

/** Anonymous reporter identity for the shared registry: salted + truncated hash of the client IP. */
function reporterOf(req) {
  const ip = ((req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || (req.socket && req.socket.remoteAddress) || '') + '').split(',')[0].trim();
  return crypto.createHash('sha256').update((process.env.THREAT_SALT || 'guardian') + '|' + ip).digest('hex').slice(0, 24);
}

function info(req) {
  const cfg = x402.readConfig();
  const store = getStore();
  return {
    ok: true,
    service: 'Guardian MCP',
    version: pkg.version,
    description: 'Deterministic security verdicts (ALLOW / WARN / DENY) for EVM transactions.',
    endpoint: {
      method: 'POST',
      path: '/analyze',
      body: {
        to: '0x...',
        data: '0x...',
        chainId: 1,
        value: '0',
        from: '0x... (optional; enables eth_call simulation, balance and allowance checks)',
        context: {
          agent_goal: 'swap tokens | transfer | approve | mint | read | unknown',
          recent_sources: ['https://example.com/doc.pdf', 'user input', 'api:coingecko'],
          recent_tool_calls: ['read_file', 'web_fetch', 'analyze', 'swap'],
          session_id: 'uuid',
          intent_match: true,
          known_addresses: ['0x... addresses the agent has verified before (address-poisoning detection)'],
          expected_amount: '1500.25 (human units; returns a bounded approve calldata as safe_alternative)',
        },
      },
      optional: ['data', 'chainId', 'value', 'from', 'context'],
    },
    signatureEndpoint: {
      method: 'POST',
      path: '/analyze-signature',
      body: { type: 'eip712 | personal_sign | eth_sign', chainId: 1, from: '0x...', typedData: '{types, primaryType, domain, message} for eip712', message: 'text or 0x-hex for personal_sign', context: '(same as /analyze)' },
    },
    layers: ['transaction', 'nested-calls', 'counterparty-intel', 'reputation', 'simulation', 'signature', 'shared-threat-registry', 'session-health', 'owner-alerts', 'differential', 'intent', 'context', 'runtime'],
    sharedState: { backend: store.kind, persistent: store.persistent, note: store.persistent ? 'Shared threat registry and session profiles are persisted across all instances.' : 'No persistent store configured (set UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN or KV_REST_API_*); registry and sessions live in the memory of a single warm instance.' },
    rules: RULES,
    signatureRules: SIGNATURE_RULES.map((r) => r.code),
    registry: { contracts: Object.values(registry.KNOWN_CONTRACTS).reduce((n, m) => n + Object.keys(m).length, 0), tokens: Object.values(registry.KNOWN_TOKENS).reduce((n, m) => n + Object.keys(m).length, 0) },
    routes: { rules: 'GET /rules', trustedDomains: 'GET /trusted-domains', health: 'GET /health', analyze: 'POST /analyze', analyzeSignature: 'POST /analyze-signature', threatStats: 'GET /threats/stats', threatLookup: 'GET /threats/{chainId}/{address}', threatDomain: 'GET /threats/domain/{host}', session: 'GET /session/{session_id}', stats: 'GET /stats', dashboard: 'GET /dashboard', feedback: 'POST /feedback { request_id?, verdict, correct, rule_codes[], comment? }' },
    pricing: { mode: pricing.cfg().mode, basic_analyze: 'free forever', basic_signature: 'free', premium: premium.status(), premium_layers: ['session_health', 'owner_alerts', 'differential_check', 'signature_analysis', 'shared_threat_intel'] },
    chains: supportedChainIds().map((id) => ({ chainId: id, name: chainName(id) })),
    payment: cfg.enabled
      ? { protocol: 'x402', x402Version: x402.X402_VERSION, price: cfg.price, asset: cfg.asset, network: cfg.network }
      : { protocol: 'x402', enabled: false, price: '0' },
    docs: 'https://github.com/' + (process.env.VERCEL_GIT_REPO_OWNER && process.env.VERCEL_GIT_REPO_SLUG ? process.env.VERCEL_GIT_REPO_OWNER + '/' + process.env.VERCEL_GIT_REPO_SLUG : 'your-org/guardian-mcp'),
  };
}

module.exports = async function handler(req, res) {
  setCors(res);
  const method = (req.method || 'GET').toUpperCase();
  const path = (req.url || '/').split('?')[0].replace(/\/+$/, '') || '/';

  if (method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  if (method === 'GET' && (path === '/' || path === '/health' || path === '/api' || path === '/api/index')) {
    return send(res, 200, info(req));
  }
  if (method === 'GET' && (path === '/rules' || path === '/api/rules')) {
    return send(res, 200, {
      ok: true,
      count: ALL_RULES.length,
      verdictPolicy: 'verdict = highest severity among triggered rules; risk_score = 15 per WARN + 40 per DENY + 20 for intent_mismatch + 50 for injection_pattern, capped at 100',
      rules: ALL_RULES,
    });
  }
  const apiPath = path.replace(/^\/api(?=\/)/, '');
  if (method === 'GET' && apiPath === '/dashboard') {
    res.statusCode = 200;
    res.setHeader('content-type', 'text/html; charset=utf-8');
    res.setHeader('cache-control', 'public, max-age=60');
    return res.end(dashboard.html());
  }
  if (method === 'GET' && (apiPath === '/stats' || apiPath === '/admin/stats')) {
    const internal = apiPath === '/admin/stats';
    if (internal && !isAdmin(req)) return send(res, 401, { ok: false, error: 'admin token required (X-Admin-Token)' });
    try {
      const store = getStore();
      const snap = await stats.snapshot(store, { internal, ruleCodes: internal ? Array.from(RULE_CODES) : [] });
      if (internal) {
        snap.recent_feedback = await feedback.recent(store, 50);
        snap.pricing = await pricing.resolve(store, process.env);
      }
      res.setHeader('cache-control', internal ? 'no-store' : 'public, max-age=60');
      return send(res, 200, Object.assign({ ok: true }, snap));
    } catch (err) {
      return send(res, 503, { ok: false, error: 'stats unavailable: ' + err.message });
    }
  }
  if ((method === 'GET' || method === 'POST') && apiPath === '/cron/seed') {
    if (!isCron(req) && !isAdmin(req)) return send(res, 401, { ok: false, error: 'CRON_SECRET bearer or admin token required' });
    try {
      const result = await seed.run(getStore(), { force: (req.url || '').includes('force=1') });
      return send(res, 200, Object.assign({ ok: true }, result));
    } catch (err) {
      console.error('seed failed', err);
      return send(res, 502, { ok: false, error: 'seed failed: ' + err.message });
    }
  }
  if (method === 'POST' && apiPath === '/feedback') {
    let body;
    try {
      body = await readBody(req);
    } catch (err) {
      return send(res, 400, { error: 'Invalid JSON body: ' + err.message });
    }
    try {
      const fb = feedback.normalize(body, RULE_CODES);
      const result = await feedback.submit(getStore(), fb, reporterOf(req));
      return send(res, 200, Object.assign({ ok: true, thanks: 'Recorded. False positives and missed attacks tune the rules; verdicts themselves never change retroactively.' }, result));
    } catch (err) {
      if (err.name === 'ValidationError') return send(res, 400, { ok: false, error: err.message });
      if (err.status === 429) return send(res, 429, { ok: false, error: err.message });
      return send(res, 503, { ok: false, error: 'feedback unavailable: ' + err.message });
    }
  }
  if (method === 'GET' && apiPath === '/threats/stats') {
    try {
      return send(res, 200, Object.assign({ ok: true }, await threat.stats(getStore())));
    } catch (err) {
      return send(res, 503, { ok: false, error: 'threat store unavailable: ' + err.message });
    }
  }
  let m = method === 'GET' && apiPath.match(/^\/threats\/domain\/([a-z0-9.-]{1,253})$/i);
  if (m) {
    try {
      const store = getStore();
      const host = decodeURIComponent(m[1]).toLowerCase();
      const r = await threat.lookup(store, 0, [], [host]);
      const rec = r.domains[host];
      return send(res, 200, { ok: true, domain: host, flagged: Boolean(rec), record: rec, severity: threat.classify(rec, threat.cfg()), backend: store.kind, persistent: store.persistent });
    } catch (err) {
      return send(res, 503, { ok: false, error: 'threat store unavailable: ' + err.message });
    }
  }
  m = method === 'GET' && apiPath.match(/^\/threats\/(\d{1,10})\/(0x[0-9a-fA-F]{40})$/);
  if (m) {
    try {
      const store = getStore();
      const chainId = Number(m[1]);
      const address = m[2].toLowerCase();
      const r = await threat.lookup(store, chainId, [address], []);
      const rec = r.addresses[address];
      return send(res, 200, { ok: true, chainId, address, flagged: Boolean(rec), severity: threat.classify(rec, threat.cfg()), record: rec, known: registry.lookupContract(chainId, address) || registry.lookupToken(chainId, address) || null, backend: store.kind, persistent: store.persistent });
    } catch (err) {
      return send(res, 503, { ok: false, error: 'threat store unavailable: ' + err.message });
    }
  }
  m = method === 'GET' && apiPath.match(/^\/session\/([A-Za-z0-9_.:@+-]{1,128})$/);
  if (m) {
    try {
      const store = getStore();
      const p = await sessionHealth.profile(store, decodeURIComponent(m[1]));
      if (!p) return send(res, 404, { ok: false, error: 'session not found (or expired)', backend: store.kind, persistent: store.persistent });
      return send(res, 200, Object.assign({ ok: true, session_id: decodeURIComponent(m[1]), backend: store.kind, persistent: store.persistent }, p));
    } catch (err) {
      return send(res, 503, { ok: false, error: 'session store unavailable: ' + err.message });
    }
  }
  if (method === 'GET' && (path === '/trusted-domains' || path === '/api/trusted-domains')) {
    const trusted = getTrustedDomains();
    return send(res, 200, {
      ok: true,
      source: trusted.source,
      configured: trusted.configured,
      domains: trusted.domains,
      count: trusted.domains.length,
      sessionTtlMs: getSessionTtlMs(),
      largeAmountRaw: getLargeAmountRaw().toString(),
    });
  }

  if (method !== 'POST') {
    return send(res, 405, { error: 'Method not allowed. Use POST /analyze with JSON { "to": "0x...", "data": "0x..." }' });
  }

  const isSignature = path === '/analyze-signature' || path === '/api/analyze-signature';
  const isPremium = path === '/guard' || path === '/api/guard';
  if (!isSignature && !isPremium && !(path === '/' || path === '/analyze' || path === '/api' || path === '/api/index' || path === '/api/analyze')) {
    return send(res, 404, { error: 'Not found. POST /analyze, POST /analyze-signature or POST /guard (premium)' });
  }

  if (isPremium) {
    let body;
    try {
      body = await readBody(req);
    } catch (err) {
      return send(res, 400, { error: err instanceof ValidationError ? err.message : 'Invalid JSON body: ' + err.message });
    }
    let pay;
    try {
      pay = await premium.gate(req, res, body, module.exports.premiumOptions);
    } catch (err) {
      console.error('premium gate failed', err);
      return send(res, 503, { ok: false, error: 'Premium payment gate failed: ' + err.message });
    }
    if (!pay.ok) return undefined;
    const kind = body && body.kind === 'signature' ? 'signature' : 'transaction';
    let result;
    try {
      const deps = { reporter: reporterOf(req), premium: true, paid: Boolean(pay.payer) };
      result = kind === 'signature' ? await analyzeSignature(body, deps) : await analyze(body, deps);
    } catch (err) {
      if (err instanceof ValidationError || (err && err.name === 'ValidationError')) return send(res, 400, { error: err.message });
      console.error('premium analyze failed', err);
      return send(res, 500, { error: 'Internal error during analysis' });
    }
    try {
      const settled = await pay.settle();
      if (settled && settled.success === false) {
        const r = settled.response || { status: 402, headers: settled.headers || {} };
        for (const [k, v] of Object.entries(r.headers || {})) res.setHeader(k, v);
        const bodyOut = r.body && typeof r.body === 'object' && Object.keys(r.body).length ? r.body : { error: 'Payment settlement failed: ' + (settled.errorReason || 'unknown') + (settled.errorMessage ? ' (' + settled.errorMessage + ')' : ''), errorReason: settled.errorReason || null };
        return send(res, r.status || 402, bodyOut);
      }
      if (settled && settled.headers) for (const [k, v] of Object.entries(settled.headers)) res.setHeader(k, v);
      result.details.payment = settled ? { settled: settled.success !== false, transaction: settled.transaction || null, network: settled.network || null, payer: pay.payer } : null;
    } catch (err) {
      console.error('premium settle failed', err);
      return send(res, 402, { error: 'Payment settlement failed: ' + err.message });
    }
    result.details.premium = true;
    return send(res, 200, result);
  }

  let payment;
  try {
    payment = await x402.gate(req, res, { resourceUrl: resourceUrl(req) });
  } catch (err) {
    return send(res, 500, { error: 'Payment gate misconfigured: ' + err.message });
  }
  if (!payment.ok) return undefined;

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return send(res, 400, { error: err instanceof ValidationError ? err.message : 'Invalid JSON body: ' + err.message });
  }

  let result;
  try {
    const deps = { reporter: reporterOf(req) };
    result = isSignature ? await analyzeSignature(body, deps) : await analyze(body, deps);
  } catch (err) {
    if (err instanceof ValidationError || (err && err.name === 'ValidationError')) return send(res, 400, { error: err.message });
    console.error('analyze failed', err);
    return send(res, 500, { error: 'Internal error during analysis' });
  }

  if (payment.settle) {
    try {
      await payment.settle();
    } catch (err) {
      console.error('x402 settle failed', err);
      return send(res, 402, { error: 'Payment settlement failed: ' + err.message });
    }
  }

  return send(res, 200, result);
};
