'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { fetchChallenge, challengeOf, decodedChallengeOf } = require('../src/x402-probe');
const { compareQuote } = require('../src/quote-guard');

const CHALLENGE = {
  x402Version: 2,
  resource: { url: 'mcp://radar/snapshot', description: 'snapshot' },
  accepts: [{ scheme: 'exact', network: 'eip155:196', amount: '2000', asset: '0x779ded0c9e1022225f8e0630b35a9b54be713736', payTo: '0xe1c6f89df50fb68282d52e34d6001d65005ff67b', maxTimeoutSeconds: 120, extra: { name: 'USD₮0', version: '1' } }],
};

function serve(handler) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (d) => { body += d; });
      req.on('end', () => handler(req, res, body));
    }).listen(0, '127.0.0.1', () => resolve({ server, url: 'http://127.0.0.1:' + server.address().port }));
  });
}

test('x402-probe: GET 402 with PAYMENT-REQUIRED header is captured and decoded', async () => {
  const header = Buffer.from(JSON.stringify(CHALLENGE)).toString('base64');
  const { server, url } = await serve((req, res) => { res.writeHead(402, { 'payment-required': header, 'content-type': 'application/json' }); res.end('{}'); });
  try {
    const r = await fetchChallenge(url + '/paid');
    assert.equal(r.method, 'GET');
    assert.equal(challengeOf(r), header);
    assert.equal(decodedChallengeOf(r).accepts[0].amount, '2000');
  } finally { server.close(); }
});

test('x402-probe: MCP server that asks for payment on tools/call is captured', async () => {
  const calls = [];
  const { server, url } = await serve((req, res, raw) => {
    if (req.method !== 'POST') { res.writeHead(405); res.end(); return; }
    let msg = {};
    try { msg = JSON.parse(raw); } catch { /* empty POST {} probe */ }
    calls.push(msg.method || 'plain');
    res.setHeader('content-type', 'application/json');
    if (!msg.method) { res.writeHead(400); res.end('{"error":"jsonrpc required"}'); return; }
    if (msg.method === 'initialize') { res.setHeader('mcp-session-id', 's1'); res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2025-06-18', capabilities: {} } })); return; }
    if (msg.method === 'tools/list') { res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { tools: [{ name: 'snapshot' }] } })); return; }
    if (msg.method === 'tools/call') {
      assert.equal(req.headers['mcp-session-id'], 's1');
      res.writeHead(402);
      res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: 402, message: 'Payment required', data: CHALLENGE } }));
      return;
    }
    res.end('{}');
  });
  try {
    const r = await fetchChallenge(url + '/mcp');
    assert.equal(r.method, 'MCP tools/call snapshot');
    assert.equal(challengeOf(r).accepts[0].payTo, CHALLENGE.accepts[0].payTo);
    assert.deepEqual(calls, ['plain', 'initialize', 'tools/list', 'tools/call']);
  } finally { server.close(); }
});

test('x402-probe: free endpoint returns the response without a challenge', async () => {
  const { server, url } = await serve((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}'); });
  try {
    const r = await fetchChallenge(url + '/free', { method: 'GET' });
    assert.equal(r.status, 200);
    assert.equal(challengeOf(r), null);
  } finally { server.close(); }
});

const CHECKED = { index: 0, payTo: '0xE1c6F89df50Fb68282d52e34d6001d65005ff67b', amount: { atomic: '2000' }, asset: { address: '0x779Ded0c9e1022225f8E0630b35a9b54bE713736' }, network: 'eip155:196' };
const QUOTE = { ok: true, data: { paymentId: 'pay_1', accepts: [{ index: 0, amount: '2000', asset: '0x779ded0c9e1022225f8e0630b35a9b54be713736', network: 'eip155:196', scheme: 'exact' }], candidates: [{ acceptsIndex: 0, amount: '2000', depositAddress: '0xe1c6f89df50fb68282d52e34d6001d65005ff67b', balanceStatus: 'sufficient' }] } };

test('quote-guard: quote that pays exactly what was checked passes', () => {
  const r = compareQuote(QUOTE, CHECKED);
  assert.equal(r.ok, true, r.problems.join('; '));
  assert.equal(r.paymentId, 'pay_1');
});

test('quote-guard: seller swapping payee, amount or token between check and quote is caught', () => {
  const swapped = JSON.parse(JSON.stringify(QUOTE));
  swapped.data.candidates[0].depositAddress = '0x1111111111111111111111111111111111111111';
  swapped.data.candidates[0].amount = '2000000';
  swapped.data.accepts[0].asset = '0x74b7f16337b8972027f6196a17a631ac6de26d22';
  const r = compareQuote(swapped, CHECKED);
  assert.equal(r.ok, false);
  assert.equal(r.problems.length, 3, r.problems.join('; '));
  assert.equal(compareQuote({ data: {} }, CHECKED).ok, false);
});
