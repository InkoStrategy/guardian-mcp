'use strict';

/**
 * x402 payment gate (protocol v2, "exact" scheme).
 *
 * Disabled (free service) while X402_PRICE is "0" or unset.
 * When enabled, every request without a valid payment gets HTTP 402 with a
 * base64 PAYMENT-REQUIRED header; a request carrying PAYMENT-SIGNATURE (or the
 * legacy X-PAYMENT header) is verified against the facilitator, the handler
 * runs, and the settlement receipt is returned in PAYMENT-RESPONSE.
 *
 * Wire names (PAYMENT-REQUIRED, PAYMENT-SIGNATURE, PAYMENT-RESPONSE, X-PAYMENT,
 * x402Version) are protocol literals and must not be renamed.
 */

const X402_VERSION = 2;

function readConfig(env) {
  env = env || process.env;
  const price = (env.X402_PRICE || '0').trim();
  const enabled = /^[0-9]+$/.test(price) && BigInt(price) > 0n;
  const cfg = {
    enabled,
    price,
    payTo: (env.X402_PAY_TO || '').trim(),
    network: (env.X402_NETWORK || 'eip155:8453').trim(),
    asset: (env.X402_ASSET || '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913').trim(),
    assetName: (env.X402_ASSET_NAME || 'USD Coin').trim(),
    assetVersion: (env.X402_ASSET_VERSION || '2').trim(),
    facilitatorUrl: (env.X402_FACILITATOR_URL || 'https://x402.org/facilitator').trim().replace(/\/+$/, ''),
    maxTimeoutSeconds: Number.parseInt(env.X402_MAX_TIMEOUT_SECONDS || '300', 10),
  };
  if (cfg.enabled && !/^0x[0-9a-fA-F]{40}$/.test(cfg.payTo)) {
    throw new Error('x402 is enabled (X402_PRICE > 0) but X402_PAY_TO is not a valid EVM address');
  }
  return cfg;
}

function b64encode(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64');
}

function b64decode(str) {
  const normalized = str.replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(Buffer.from(normalized, 'base64').toString('utf8'));
}

function buildRequirements(cfg, resourceUrl, description) {
  return {
    scheme: 'exact',
    network: cfg.network,
    maxAmountRequired: cfg.price,
    amount: cfg.price,
    resource: resourceUrl,
    description,
    mimeType: 'application/json',
    payTo: cfg.payTo,
    maxTimeoutSeconds: cfg.maxTimeoutSeconds,
    asset: cfg.asset,
    extra: { name: cfg.assetName, version: cfg.assetVersion },
  };
}

function buildPaymentRequired(cfg, resourceUrl, description, error) {
  const body = {
    x402Version: X402_VERSION,
    resource: { url: resourceUrl, description, mimeType: 'application/json' },
    accepts: [buildRequirements(cfg, resourceUrl, description)],
  };
  if (error) body.error = error;
  return body;
}

async function postJson(url, payload, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    const text = await res.text();
    let json;
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      json = { raw: text };
    }
    if (!res.ok) {
      const err = new Error('facilitator ' + res.status + ': ' + (json.error || json.invalidReason || text || 'error'));
      err.status = res.status;
      throw err;
    }
    return json;
  } finally {
    clearTimeout(timer);
  }
}

function getHeader(req, name) {
  const v = req.headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

/**
 * Enforce payment for a request.
 * @returns {Promise<{ok:boolean, settle?: () => Promise<object|null>}>}
 *   ok=false means a 402 has already been written to `res`.
 */
async function gate(req, res, opts) {
  const cfg = readConfig(opts && opts.env);
  if (!cfg.enabled) return { ok: true, settle: async () => null };

  const resourceUrl = opts.resourceUrl;
  const description = opts.description || 'Guardian MCP transaction security analysis';
  const requirements = buildRequirements(cfg, resourceUrl, description);

  const respond402 = (error) => {
    const body = buildPaymentRequired(cfg, resourceUrl, description, error);
    res.statusCode = 402;
    res.setHeader('PAYMENT-REQUIRED', b64encode(body));
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.end(JSON.stringify(body));
    return { ok: false };
  };

  const rawHeader = getHeader(req, 'PAYMENT-SIGNATURE') || getHeader(req, 'X-PAYMENT');
  if (!rawHeader) return respond402('Payment required');

  let paymentPayload;
  try {
    paymentPayload = b64decode(rawHeader);
  } catch {
    return respond402('Malformed payment header');
  }

  let verification;
  try {
    verification = await postJson(cfg.facilitatorUrl + '/verify', { x402Version: X402_VERSION, paymentPayload, paymentRequirements: requirements }, 8000);
  } catch (err) {
    return respond402('Payment verification failed: ' + err.message);
  }
  if (!verification || verification.isValid !== true) {
    return respond402('Invalid payment: ' + ((verification && verification.invalidReason) || 'rejected by facilitator'));
  }

  return {
    ok: true,
    payer: verification.payer || null,
    settle: async () => {
      const settlement = await postJson(cfg.facilitatorUrl + '/settle', { x402Version: X402_VERSION, paymentPayload, paymentRequirements: requirements }, 15000);
      res.setHeader('PAYMENT-RESPONSE', b64encode(settlement));
      return settlement;
    },
  };
}

module.exports = { gate, readConfig, buildPaymentRequired, X402_VERSION };
