'use strict';

/**
 * POST /mcp: GuardianMCP as a real Model Context Protocol server (Streamable HTTP, stateless).
 *
 * JSON-RPC 2.0 over POST. initialize, ping, tools/list and tools/call. Notifications get 202.
 * Replies are JSON, or a single SSE "message" event when the client accepts text/event-stream.
 *
 * Free tools: check_payment, probe_payment, check_quote, verify_settlement, check_address, check_domain,
 * analyze_transaction, analyze_signature. Paid tool: guard (premium verdict, x402 exact on X Layer,
 * settled by the OKX facilitator). The paywall sits at tools/call, the way Onchain OS A2MCP clients
 * expect: an unpaid tools/call for guard returns HTTP 402 with PAYMENT-REQUIRED, and the client replays
 * the same tools/call with PAYMENT-SIGNATURE.
 */

const PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];

const obj = (description, properties, required) => ({ type: 'object', description, properties: properties || {}, required: required || [], additionalProperties: true });
const str = (description) => ({ type: 'string', description });
const int = (description) => ({ type: 'integer', description });

const EXPECTED = obj('What the marketplace listing promised.', {
  feeAmount: { type: 'number', description: 'Listed price in human units, e.g. 0.005' },
  feeToken: str('Listed token address, e.g. USD₮0 0x779ded0c9e1022225f8e0630b35a9b54be713736'),
  endpoint: str('Listed endpoint URL'),
  payTo: str('Wallet the buyer expects to pay'),
  maxAmount: str('Maximum atomic amount'),
});
const CONTEXT = obj('Agent context.', {
  max_amount: str('Spending cap in human units'),
  known_addresses: { type: 'array', items: { type: 'string' }, description: 'Verified address book' },
  from: str('Paying wallet'),
  session_id: str('Stable session id'),
});

const TOOLS = [
  {
    name: 'check_payment',
    title: 'Check an x402 payment before paying',
    description: 'Pay-Safe verdict (ALLOW / WARN / DENY) for an x402 402 challenge: price, token and endpoint against the listing, payee against the expected wallet, EIP-712 domain against the token contract, shell payloads, signed EIP-3009 / Permit2 payloads. Nothing is signed or paid. Free.',
    inputSchema: obj('Pass paymentRequired (PAYMENT-REQUIRED header or 402 body) or payment (flattened quote).', {
      paymentRequired: { type: ['string', 'object'], description: 'Base64 PAYMENT-REQUIRED header or the 402 JSON body' },
      payment: obj('Flattened quote: network or chainId, asset, amount (atomic), payTo, scheme, maxTimeoutSeconds, extra'),
      requestUrl: str('URL that returned 402'),
      selectedIndex: int('accepts[] entry you intend to pay'),
      paymentSignature: { type: ['string', 'object'], description: 'Signed PAYMENT-SIGNATURE / X-PAYMENT to verify before replay' },
      expected: EXPECTED,
      context: CONTEXT,
    }),
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'probe_payment',
    title: 'Probe a paid endpoint and check its payment',
    description: 'Guardian requests the paid URL once without paying (GET, POST or MCP tools/call), captures the x402 challenge and returns the Pay-Safe verdict. URLs with shell syntax are never contacted. Free.',
    inputSchema: obj('Paid endpoint to probe.', {
      url: str('https URL of the paid endpoint'),
      method: { type: 'string', enum: ['auto', 'GET', 'POST', 'MCP'], description: 'Request style, default auto' },
      params: obj('Business params: query for GET, JSON body for POST'),
      tool: str('MCP tool name when the endpoint is an MCP server'),
      expected: EXPECTED,
      context: CONTEXT,
    }, ['url']),
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'check_quote',
    title: 'Check an Onchain OS payment quote before paying',
    description: 'Pay-Safe verdict bound to an Onchain OS paymentId. Pass the persisted state ~/.onchainos/payments/<paymentId>.json (what payment pay signs, without re-fetching the 402) or the JSON output of onchainos payment quote. Adds quote_inconsistent, challenge_header_body_mismatch and quote_expired to the check_payment rules. Returns next_command only on ALLOW, never with --yes, and a fingerprint of the signed entry. Free.',
    inputSchema: obj('Quote to check.', {
      quote: { type: ['object', 'string'], description: 'Persisted payment state or onchainos payment quote output' },
      selectedIndex: int('Index you will pass to payment pay --selected-index (default: the CLI pick)'),
      sid: int('OKX.AI service id: take price, token and endpoint from the latest trust scan when expected is omitted'),
      expected: EXPECTED,
      context: CONTEXT,
    }, ['quote']),
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'verify_settlement',
    title: 'Verify a settled payment on-chain',
    description: 'Reads the transaction receipt and confirms the ERC-20 Transfer matches the checked payee, atomic amount and token (x402 settlement is submitted by a facilitator). Default chain X Layer (196), default token USD₮0. Free.',
    inputSchema: obj('Settlement to verify.', {
      txHash: str('Transaction hash'),
      payTo: str('Payee that was checked'),
      amount: str('Atomic amount that was checked, e.g. "5000"'),
      token: str('Token address, default USD₮0 on X Layer'),
      payer: str('Paying wallet, optional'),
      chainId: int('Chain id, default 196'),
    }, ['txHash', 'payTo', 'amount']),
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'check_listing',
    title: 'Look up an OKX.AI listing in the trust scan',
    description: 'Latest Pay-Safe trust-scan result for an OKX.AI marketplace service id (sid): verdict, reasons and findings of its x402 challenge against its own listing, with the scan date. Free.',
    inputSchema: obj('Marketplace service id.', { sid: int('OKX.AI service id, e.g. 39856') }, ['sid']),
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: 'check_address',
    title: 'Check an address',
    description: 'Is it safe to send to, approve or call this address? Contract code, history, lookalikes of known contracts, shared threat registry and the ScamSniffer database. Free.',
    inputSchema: obj('Address to check.', { address: str('0x address'), chainId: int('Chain id, default 1'), role: { type: 'string', enum: ['recipient', 'spender', 'contract'] } }, ['address']),
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'check_domain',
    title: 'Check a domain',
    description: 'Phishing patterns, trusted list, shared threat registry and the ScamSniffer phishing database for a domain or URL. Free.',
    inputSchema: obj('Pass domain or url.', { domain: str('Hostname'), url: str('Full URL') }),
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'analyze_transaction',
    title: 'Analyze a transaction before signing',
    description: 'Security verdict for an EVM transaction: unlimited or wallet-targeted approvals, address poisoning, drains hidden in multicall and router plans, known drainers, optional simulation when from is given. Free.',
    inputSchema: obj('Unsigned transaction.', { to: str('Target address'), data: str('0x calldata'), chainId: int('Chain id, default 1'), value: str('Wei'), from: str('Sender, enables simulation'), context: obj('Agent context: agent_goal, recent_sources, recent_tool_calls, session_id, known_addresses, expected_amount') }, ['to']),
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'analyze_signature',
    title: 'Analyze a signature request',
    description: 'Security verdict for EIP-712 (permit, Permit2, Seaport, SIWE), personal_sign and eth_sign requests. Free.',
    inputSchema: obj('Signature request.', { type: { type: 'string', enum: ['eip712', 'eth_signTypedData_v4', 'personal_sign', 'eth_sign'] }, typedData: { type: ['object', 'string'] }, message: str('Text or 0x hex'), chainId: int('Chain id'), from: str('Signer'), context: obj('Agent context') }, ['type']),
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'guard',
    title: 'Premium guard verdict (paid)',
    description: 'Premium transaction or signature verdict with session health, owner alerts, reference-template diff and shared threat intelligence. Paid per call over x402 on X Layer (exact scheme, USD₮0), settled by the OKX facilitator. Same arguments as analyze_transaction, or kind "signature" with analyze_signature arguments.',
    inputSchema: obj('Transaction (default) or signature request.', { kind: { type: 'string', enum: ['transaction', 'signature'] }, to: str('Target address'), data: str('0x calldata'), chainId: int('Chain id'), value: str('Wei'), from: str('Sender'), type: str('Signature type when kind is signature'), typedData: { type: ['object', 'string'] }, message: str('Message when kind is signature'), context: obj('Agent context') }),
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
];

class RpcError extends Error {
  constructor(code, message, data) {
    super(message);
    this.code = code;
    this.data = data;
  }
}

function wantsSse(req) {
  const accept = String(req.headers.accept || '');
  return accept.includes('text/event-stream') && !accept.includes('application/json');
}

function writeRpc(req, res, status, payload, extraHeaders) {
  res.statusCode = status;
  res.setHeader('cache-control', 'no-store');
  for (const [k, v] of Object.entries(extraHeaders || {})) res.setHeader(k, v);
  if (wantsSse(req) && status === 200) {
    res.setHeader('content-type', 'text/event-stream; charset=utf-8');
    res.end('event: message\ndata: ' + JSON.stringify(payload) + '\n\n');
    return;
  }
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(payload));
}

function toolResult(value, isError) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  const out = { content: [{ type: 'text', text }], isError: Boolean(isError) };
  if (!isError && value && typeof value === 'object') out.structuredContent = value;
  return out;
}

/**
 * @param {object} h helpers from api/index.js:
 *   { version, reporterOf, analyze, analyzeSignature, quick, paysafe, probePayment, verifySettlement, premium, options: () => ({ quick, probe, premium, settlement }) }
 */
function createMcpHandler(h) {
  async function callFreeTool(name, args, req) {
    const opts = h.options();
    const base = Object.assign({ reporter: h.reporterOf(req) }, opts.quick || {});
    switch (name) {
      case 'check_payment': return h.paysafe.checkPayment(args, base);
      case 'probe_payment': return h.probePayment.probePayment(args, Object.assign({}, base, opts.probe || {}));
      case 'check_quote': return h.checkQuote(args, Object.assign({ trustScan: h.trustScan }, base));
      case 'verify_settlement': return h.verifySettlement({ txHash: args.txHash, payTo: args.payTo, amount: args.amount === undefined ? undefined : String(args.amount), asset: args.token || '0x779ded0c9e1022225f8e0630b35a9b54be713736', payer: args.payer, chainId: args.chainId || 196, fetchImpl: (opts.settlement || {}).fetchImpl, rpcUrls: (opts.settlement || {}).rpcUrls });
      case 'check_listing': {
        const sid = Number(args.sid);
        if (!Number.isInteger(sid) || sid <= 0) { const e = new Error('sid must be a positive integer'); e.name = 'ValidationError'; throw e; }
        const scan = h.trustScan();
        const row = scan && Array.isArray(scan.results) ? scan.results.find((r) => Number(r.sid) === sid) : null;
        if (!row) return { sid, found: false, scannedAt: scan ? scan.generatedAt : null, note: 'This sid was not among the paid A2MCP services in the latest scan.' };
        return { sid, found: true, scannedAt: scan.generatedAt, service: row.service, seller: row.asp, sellerAgentId: row.aspAgentId, listed: row.listed, probe: row.probe, verdict: row.verdict || null, reasons: row.reasons || [], summary: row.summary || null, findings: row.findings || [] };
      }
      case 'check_address': return h.quick.checkAddress(args, base);
      case 'check_domain': return h.quick.checkDomain(args, base);
      case 'analyze_transaction': return h.analyze(args, { reporter: h.reporterOf(req) });
      case 'analyze_signature': return h.analyzeSignature(args, { reporter: h.reporterOf(req) });
      default: throw new RpcError(-32602, 'Unknown tool: ' + name, { tools: TOOLS.map((t) => t.name) });
    }
  }

  /** Paid tool. Returns { status, payload, headers } for the whole HTTP response. */
  async function callGuard(id, args, req, rawBody) {
    const opts = h.options();
    const server = await h.premium.getServer(opts.premium);
    if (!server.ready) {
      return { status: 200, payload: { jsonrpc: '2.0', id, result: toolResult('Premium payments are not available yet: ' + server.reason + '. The free tools keep working.', true) } };
    }
    const adapter = h.premium.nodeAdapter(req, rawBody);
    const paymentHeader = adapter.getHeader('payment-signature') || adapter.getHeader('x-payment');
    const context = { adapter, path: '/mcp', method: 'POST', paymentHeader };
    const processed = await server.httpServer.processHTTPRequest(context);
    if (processed.type === 'payment-error') {
      const r = processed.response;
      const headers = r.headers || {};
      const hdr = Object.entries(headers).find(([k]) => k.toLowerCase() === 'payment-required');
      let challenge = null;
      if (hdr) {
        try { challenge = JSON.parse(Buffer.from(hdr[1], 'base64').toString('utf8')); } catch { challenge = null; }
      }
      if (!challenge && r.body && typeof r.body === 'object') challenge = r.body;
      return { status: r.status || 402, headers, payload: { jsonrpc: '2.0', id, error: { code: 402, message: paymentHeader ? 'Payment rejected' : 'Payment required', data: challenge } } };
    }
    const kind = args && args.kind === 'signature' ? 'signature' : 'transaction';
    const payer = processed.paymentPayload && processed.paymentPayload.payload && (processed.paymentPayload.payload.authorization || {}).from || null;
    const deps = { reporter: h.reporterOf(req), premium: true, paid: Boolean(payer) };
    let result;
    try {
      result = kind === 'signature' ? await h.analyzeSignature(args, deps) : await h.analyze(args, deps);
    } catch (err) {
      if (err && err.name === 'ValidationError') return { status: 200, payload: { jsonrpc: '2.0', id, result: toolResult(err.message, true) } };
      throw err;
    }
    let headers = {};
    if (processed.type !== 'no-payment-required') {
      const settled = await server.httpServer.processSettlement(processed.paymentPayload, processed.paymentRequirements, processed.declaredExtensions, { request: context });
      if (settled && settled.success === false) {
        return { status: 402, headers: settled.headers || {}, payload: { jsonrpc: '2.0', id, error: { code: 402, message: 'Payment settlement failed: ' + (settled.errorReason || 'unknown'), data: { errorReason: settled.errorReason || null } } } };
      }
      headers = (settled && settled.headers) || {};
      result.details.payment = settled ? { settled: settled.success !== false, transaction: settled.transaction || null, network: settled.network || null, payer } : null;
    }
    result.details.premium = true;
    return { status: 200, headers, payload: { jsonrpc: '2.0', id, result: toolResult(result, false) } };
  }

  async function dispatch(msg, req, rawBody) {
    if (!msg || typeof msg !== 'object' || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
      return { status: 400, payload: { jsonrpc: '2.0', id: msg && msg.id !== undefined ? msg.id : null, error: { code: -32600, message: 'Invalid Request' } } };
    }
    const isNotification = msg.id === undefined || msg.id === null;
    const id = isNotification ? null : msg.id;
    const params = msg.params && typeof msg.params === 'object' ? msg.params : {};
    if (isNotification) return { status: 202, payload: null };
    try {
      switch (msg.method) {
        case 'initialize': {
          const asked = String(params.protocolVersion || '');
          return { status: 200, payload: { jsonrpc: '2.0', id, result: {
            protocolVersion: PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0],
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: 'guardian-mcp', title: 'GuardianMCP Pay-Safe', version: h.version },
            instructions: 'Call check_payment or probe_payment before paying any x402 402 challenge, verify_settlement after paying, and analyze_transaction / analyze_signature before signing. DENY means do not pay or sign; WARN means ask the user.',
          } } };
        }
        case 'ping':
          return { status: 200, payload: { jsonrpc: '2.0', id, result: {} } };
        case 'tools/list':
          return { status: 200, payload: { jsonrpc: '2.0', id, result: { tools: TOOLS } } };
        case 'tools/call': {
          const name = String(params.name || '');
          const args = params.arguments && typeof params.arguments === 'object' ? params.arguments : {};
          if (name === 'guard') return callGuard(id, args, req, rawBody);
          if (!TOOLS.some((t) => t.name === name)) throw new RpcError(-32602, 'Unknown tool: ' + name, { tools: TOOLS.map((t) => t.name) });
          try {
            const value = await callFreeTool(name, args, req);
            return { status: 200, payload: { jsonrpc: '2.0', id, result: toolResult(value, false) } };
          } catch (err) {
            if (err instanceof RpcError) throw err;
            if (err && (err.name === 'ValidationError' || /must|required|invalid/i.test(err.message || ''))) return { status: 200, payload: { jsonrpc: '2.0', id, result: toolResult(err.message, true) } };
            throw err;
          }
        }
        default:
          throw new RpcError(-32601, 'Method not found: ' + msg.method);
      }
    } catch (err) {
      if (err instanceof RpcError) return { status: 200, payload: { jsonrpc: '2.0', id, error: { code: err.code, message: err.message, data: err.data } } };
      console.error('mcp tool failed', err);
      return { status: 200, payload: { jsonrpc: '2.0', id, error: { code: -32603, message: 'Internal error' } } };
    }
  }

  return async function handleMcp(req, res, rawBody) {
    if (Array.isArray(rawBody)) {
      // MCP 2025-06-18 removed JSON-RPC batching.
      return writeRpc(req, res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request: send one JSON-RPC message per POST' } });
    }
    const r = await dispatch(rawBody, req, rawBody);
    if (rawBody && rawBody.method === 'tools/call' && h.recordStat) h.recordStat('mcp:' + String((rawBody.params && rawBody.params.name) || 'unknown').slice(0, 40), r);
    if (r.status === 202) { res.statusCode = 202; res.setHeader('cache-control', 'no-store'); return res.end(); }
    return writeRpc(req, res, r.status, r.payload, r.headers);
  };
}

module.exports = { createMcpHandler, TOOLS, PROTOCOL_VERSIONS };
