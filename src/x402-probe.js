'use strict';

/**
 * Capture an x402 challenge from a paid endpoint WITHOUT paying.
 *
 * Order: GET, then POST {}, then MCP streamable HTTP (initialize, tools/list, tools/call on up to
 * three tools). Returns the first response that carries a PAYMENT-REQUIRED header or an x402 body
 * (plain 402 body, JSON-RPC error.data, or result.structuredContent).
 *
 * Nothing is signed. Tool calls are sent with empty arguments, the same request any MCP client makes
 * before it knows the price.
 */

const USER_AGENT = 'guardian-mcp-pay-safe/1.0 (no payment; x402 challenge probe)';

function x402In(body) {
  if (!body || typeof body !== 'object') return null;
  if (Array.isArray(body.accepts)) return body;
  const e = body.error && body.error.data;
  if (e && Array.isArray(e.accepts)) return e;
  const res = body.result && body.result.structuredContent;
  if (res && Array.isArray(res.accepts)) return res;
  return null;
}

function hasChallenge(r) {
  return Boolean(r && (r.header || x402In(r.body)));
}

/** The challenge to hand to /check-payment: the raw base64 header when present, else the body object. */
function challengeOf(r) {
  if (!r) return null;
  return r.header || x402In(r.body);
}

function decodeHeader(header) {
  try {
    return JSON.parse(Buffer.from(String(header).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

/** Decoded challenge object regardless of transport. */
function decodedChallengeOf(r) {
  if (!r) return null;
  if (r.header) return decodeHeader(r.header);
  return x402In(r.body);
}

const MAX_RESPONSE_BYTES = 256 * 1024;

/** Read at most maxBytes of the body; a 402 challenge is small, anything larger is truncated. */
async function readCapped(res, maxBytes) {
  if (!res.body || typeof res.body.getReader !== 'function') return (await res.text()).slice(0, maxBytes);
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
    if (size >= maxBytes) {
      try { await reader.cancel(); } catch { /* ignore */ }
      break;
    }
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).subarray(0, maxBytes).toString('utf8');
}

async function request(url, { method, headers, body, timeoutMs, fetchImpl, maxBytes }) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await (fetchImpl || fetch)(url, { method, headers, body, signal: ctrl.signal, redirect: 'manual' });
    const text = await readCapped(res, maxBytes || MAX_RESPONSE_BYTES);
    let parsed = null;
    try {
      parsed = JSON.parse(text);
    } catch {
      const line = text.split(/\r?\n/).find((l) => l.startsWith('data:'));
      if (line) {
        try { parsed = JSON.parse(line.slice(5)); } catch { parsed = null; }
      }
    }
    return { status: res.status, header: res.headers.get('payment-required'), body: parsed, headers: res.headers };
  } finally {
    clearTimeout(t);
  }
}

async function mcpProbe(url, opts) {
  const o = Object.assign({ timeoutMs: 12000, maxTools: 3, tool: null, args: {} }, opts || {});
  const rpc = async (method, params, sessionId, id) => {
    const headers = { accept: 'application/json, text/event-stream', 'content-type': 'application/json', 'user-agent': USER_AGENT };
    if (sessionId) headers['mcp-session-id'] = sessionId;
    const r = await request(url, { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id, method, params }), timeoutMs: o.timeoutMs, fetchImpl: o.fetchImpl, maxBytes: o.maxBytes });
    return { status: r.status, header: r.header, body: r.body, method: 'MCP ' + method + (params && params.name ? ' ' + params.name : ''), sessionId: r.headers.get('mcp-session-id') || sessionId };
  };
  const init = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'guardian-mcp-pay-safe', version: '1.0' } }, null, 1);
  if (hasChallenge(init)) return init;
  if (!init.body || !init.body.result) return null;
  const names = [];
  if (o.tool) names.push(o.tool);
  else {
    const list = await rpc('tools/list', {}, init.sessionId, 2);
    if (hasChallenge(list)) return list;
    const tools = list.body && list.body.result && Array.isArray(list.body.result.tools) ? list.body.result.tools : [];
    for (const t of tools.slice(0, o.maxTools)) if (t && typeof t.name === 'string') names.push(t.name);
  }
  let id = 3;
  for (const name of names) {
    const call = await rpc('tools/call', { name, arguments: o.args || {} }, init.sessionId, id++);
    if (hasChallenge(call)) return call;
  }
  return null;
}

/**
 * @param {string} url
 * @param {object} [opts] { method: 'GET'|'POST'|'MCP'|'auto', params: object, tool: string, timeoutMs, fetchImpl }
 * @returns {Promise<{status, header, body, method, sessionId?}|{error: string}>}
 */
async function fetchChallenge(url, opts) {
  const o = Object.assign({ method: 'auto', params: null, tool: null, timeoutMs: 12000 }, opts || {});
  const base = { accept: 'application/json', 'content-type': 'application/json', 'user-agent': USER_AGENT };
  const attempt = async (method) => {
    let target = url;
    let body;
    if (method === 'GET' && o.params && Object.keys(o.params).length) {
      const u = new URL(url);
      for (const [k, v] of Object.entries(o.params)) u.searchParams.set(k, String(v));
      target = u.toString();
    }
    if (method === 'POST') body = JSON.stringify(o.params || {});
    const r = await request(target, { method, headers: base, body, timeoutMs: o.timeoutMs, fetchImpl: o.fetchImpl, maxBytes: o.maxBytes });
    return { status: r.status, header: r.header, body: r.body, method };
  };
  const want = String(o.method || 'auto').toUpperCase();
  let first;
  try {
    if (want === 'MCP') {
      const m = await mcpProbe(url, o);
      return m || { error: 'no x402 challenge from MCP tools/call' };
    }
    first = await attempt(want === 'POST' ? 'POST' : 'GET');
  } catch (e) {
    return { error: e.name === 'AbortError' ? 'timeout' : e.message };
  }
  if (hasChallenge(first) || want === 'GET' || want === 'POST') return first;
  try {
    const p = await attempt('POST');
    if (hasChallenge(p)) return p;
  } catch { /* keep GET result */ }
  try {
    const m = await mcpProbe(url, o);
    if (m && hasChallenge(m)) return m;
  } catch { /* not an MCP server */ }
  return first;
}

module.exports = { fetchChallenge, mcpProbe, x402In, hasChallenge, challengeOf, decodedChallengeOf, decodeHeader, USER_AGENT };
