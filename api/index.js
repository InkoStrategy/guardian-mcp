'use strict';

const { analyze, ValidationError, RULES, RULE_CATALOG } = require('../src/analyzer');
const { supportedChainIds, chainName } = require('../src/rpc');
const { getTrustedDomains, getSessionTtlMs, getLargeAmountRaw } = require('../src/context-analyzer');
const x402 = require('../src/x402');
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

function info(req) {
  const cfg = x402.readConfig();
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
        context: {
          agent_goal: 'swap tokens | transfer | approve | mint | read | unknown',
          recent_sources: ['https://example.com/doc.pdf', 'user input', 'api:coingecko'],
          recent_tool_calls: ['read_file', 'web_fetch', 'analyze', 'swap'],
          session_id: 'uuid',
          intent_match: true,
        },
      },
      optional: ['data', 'chainId', 'value', 'context'],
    },
    layers: ['transaction', 'intent', 'context', 'runtime'],
    rules: RULES,
    routes: { rules: 'GET /rules', trustedDomains: 'GET /trusted-domains', health: 'GET /health' },
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
      count: RULE_CATALOG.length,
      verdictPolicy: 'verdict = highest severity among triggered rules; risk_score = 15 per WARN + 40 per DENY + 20 for intent_mismatch + 50 for injection_pattern, capped at 100',
      rules: RULE_CATALOG,
    });
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

  if (!(path === '/' || path === '/analyze' || path === '/api' || path === '/api/index' || path === '/api/analyze')) {
    return send(res, 404, { error: 'Not found. POST /analyze' });
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
    result = await analyze(body);
  } catch (err) {
    if (err instanceof ValidationError) return send(res, 400, { error: err.message });
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
