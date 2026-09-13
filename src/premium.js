'use strict';

/**
 * Premium endpoint (POST /guard) paid per call through the OKX Payment SDK.
 *
 * The OKX facilitator (https://web3.okx.com/facilitator) verifies and settles
 * x402 "exact" payments; its client signs every request with OKX Developer API
 * credentials. Without OKX_API_KEY / OKX_SECRET_KEY / OKX_PASSPHRASE the
 * endpoint answers 503 instead of 402 so that no buyer ever signs a payment
 * that could not be settled.
 *
 * Env:
 *   PREMIUM_PRICE      "$0.099"   USD price, converted by the SDK to the network stablecoin
 *   PREMIUM_NETWORK    eip155:196 X Layer (USDT0). Must be supported by the facilitator.
 *   PREMIUM_PAY_TO     0x…        receiving address (falls back to X402_PAY_TO)
 *   PREMIUM_ENABLED    true|false explicit kill switch (default: enabled when credentials exist)
 */

const { x402ResourceServer, x402HTTPResourceServer } = require('@okxweb3/x402-core/server');
const { OKXFacilitatorClient } = require('@okxweb3/x402-core');
const { ExactEvmScheme } = require('@okxweb3/x402-evm/exact/server');
const pkg = require('../package.json');

const ROUTE = 'POST /guard';
const DEFAULTS = { price: '$0.099', network: 'eip155:196' };

function config(env) {
  env = env || process.env;
  const cfg = {
    apiKey: (env.OKX_API_KEY || '').trim(),
    secretKey: (env.OKX_SECRET_KEY || '').trim(),
    passphrase: (env.OKX_PASSPHRASE || '').trim(),
    price: (env.PREMIUM_PRICE || DEFAULTS.price).trim(),
    network: (env.PREMIUM_NETWORK || DEFAULTS.network).trim(),
    payTo: (env.PREMIUM_PAY_TO || env.X402_PAY_TO || '').trim(),
    enabled: String(env.PREMIUM_ENABLED || 'auto').toLowerCase(),
    syncSettle: String(env.PREMIUM_SYNC_SETTLE || 'false').toLowerCase() === 'true',
  };
  const hasCreds = Boolean(cfg.apiKey && cfg.secretKey && cfg.passphrase);
  const hasPayTo = /^0x[0-9a-fA-F]{40}$/.test(cfg.payTo);
  cfg.ready = cfg.enabled !== 'false' && hasCreds && hasPayTo;
  cfg.reason = cfg.enabled === 'false' ? 'PREMIUM_ENABLED=false' : !hasCreds ? 'OKX Developer API credentials (OKX_API_KEY / OKX_SECRET_KEY / OKX_PASSPHRASE) are not configured' : !hasPayTo ? 'PREMIUM_PAY_TO is not a valid EVM address' : null;
  return cfg;
}

/** Minimal HTTPAdapter over Node's IncomingMessage. */
function nodeAdapter(req, body) {
  const url = new URL(req.url || '/', 'https://' + (req.headers['x-forwarded-host'] || req.headers.host || 'localhost'));
  return {
    getHeader: (name) => {
      const v = req.headers[String(name).toLowerCase()];
      return Array.isArray(v) ? v[0] : v;
    },
    getMethod: () => (req.method || 'GET').toUpperCase(),
    getPath: () => url.pathname,
    getUrl: () => url.toString(),
    getAcceptHeader: () => req.headers.accept || '',
    getUserAgent: () => req.headers['user-agent'] || '',
    getQueryParams: () => Object.fromEntries(url.searchParams.entries()),
    getQueryParam: (name) => url.searchParams.get(name) || undefined,
    getBody: () => body,
  };
}

let cached = null;

/**
 * Build (or reuse) the resource server. `opts.facilitatorClient` lets tests
 * inject a fake facilitator; a new instance is created whenever opts are given.
 */
async function getServer(opts) {
  opts = opts || {};
  const cfg = config(opts.env);
  if (!cfg.ready && !opts.facilitatorClient) return { ready: false, reason: cfg.reason, cfg };
  if (cached && !opts.facilitatorClient && !opts.env) return cached;
  const facilitator = opts.facilitatorClient || new OKXFacilitatorClient({ apiKey: cfg.apiKey, secretKey: cfg.secretKey, passphrase: cfg.passphrase, syncSettle: cfg.syncSettle });
  const resourceServer = new x402ResourceServer(facilitator).register(cfg.network, new ExactEvmScheme());
  const routes = {
    [ROUTE]: {
      accepts: { scheme: 'exact', network: cfg.network, payTo: cfg.payTo || opts.payTo, price: cfg.price, maxTimeoutSeconds: 300 },
      description: 'Guardian MCP premium: transaction or signature verdict with session health, owner alerts, differential check and shared threat intelligence (' + pkg.version + ')',
      mimeType: 'application/json',
    },
  };
  const httpServer = new x402HTTPResourceServer(resourceServer, routes);
  await httpServer.initialize();
  const built = { ready: true, reason: null, cfg, httpServer, facilitator };
  if (!opts.facilitatorClient && !opts.env) cached = built;
  return built;
}

/**
 * Enforce payment for POST /guard.
 * @returns {Promise<{ok:boolean, payer?:string, settle?:Function}>}; ok=false means the response was already written.
 */
async function gate(req, res, body, opts) {
  const server = await getServer(opts);
  if (!server.ready) {
    res.statusCode = 503;
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.setHeader('retry-after', '3600');
    res.end(JSON.stringify({ ok: false, error: 'Premium payments are not available yet: ' + server.reason + '. The free endpoints /analyze and /analyze-signature keep working.' }));
    return { ok: false };
  }
  const adapter = nodeAdapter(req, body);
  const paymentHeader = adapter.getHeader('payment-signature') || adapter.getHeader('x-payment');
  const context = { adapter, path: '/guard', method: 'POST', paymentHeader };
  const result = await server.httpServer.processHTTPRequest(context);
  if (result.type === 'payment-error') {
    const r = result.response;
    res.statusCode = r.status;
    for (const [k, v] of Object.entries(r.headers || {})) res.setHeader(k, v);
    if (!r.headers || !Object.keys(r.headers).some((k) => k.toLowerCase() === 'content-type')) res.setHeader('content-type', r.isHtml ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8');
    let bodyOut = r.body;
    if ((bodyOut === undefined || bodyOut === null || (typeof bodyOut === 'object' && Object.keys(bodyOut).length === 0)) && !r.isHtml) {
      // Mirror the PAYMENT-REQUIRED header into the body for clients that only read JSON.
      const hdr = Object.entries(r.headers || {}).find(([k]) => k.toLowerCase() === 'payment-required');
      if (hdr) {
        try {
          bodyOut = Object.assign({ error: 'Payment required' }, JSON.parse(Buffer.from(hdr[1], 'base64').toString('utf8')));
        } catch {
          bodyOut = { error: 'Payment required' };
        }
      } else {
        bodyOut = { error: 'Payment rejected' };
      }
    }
    res.end(typeof bodyOut === 'string' ? bodyOut : JSON.stringify(bodyOut || {}));
    return { ok: false };
  }
  if (result.type === 'no-payment-required') return { ok: true, payer: null, settle: async () => null };
  return {
    ok: true,
    payer: (result.paymentPayload && result.paymentPayload.payload && (result.paymentPayload.payload.authorization || {}).from) || null,
    requirements: result.paymentRequirements,
    settle: async () => {
      const s = await server.httpServer.processSettlement(result.paymentPayload, result.paymentRequirements, result.declaredExtensions, { request: context });
      return s;
    },
  };
}

function status(env) {
  const cfg = config(env);
  return { route: ROUTE, ready: cfg.ready, reason: cfg.reason, price: cfg.price, network: cfg.network, payTo: cfg.payTo ? cfg.payTo : null, facilitator: 'https://web3.okx.com/facilitator' };
}

module.exports = { gate, getServer, config, status, nodeAdapter, ROUTE };
