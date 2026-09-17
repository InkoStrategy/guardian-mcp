'use strict';

/**
 * Thin wrapper around the Onchain OS CLI for the local scripts (safe-pay, check-quote).
 * Runs without a shell: listing text is untrusted and never reaches a command line.
 */

const { spawnSync } = require('node:child_process');
const path = require('node:path');

const ONCHAINOS = process.env.ONCHAINOS_BIN || (process.platform === 'win32' ? path.join(process.env.USERPROFILE || '', '.local', 'bin', 'onchainos.exe') : 'onchainos');

function run(args) {
  const r = spawnSync(ONCHAINOS, args, { encoding: 'utf8', maxBuffer: 32e6, windowsHide: true, shell: false });
  const text = (r.stdout || '') + (r.stderr || '');
  const i = text.indexOf('{');
  let json = null;
  try { json = i >= 0 ? JSON.parse(text.slice(i)) : null; } catch { json = null; }
  return { code: r.status, json, text };
}

/**
 * Printable argv. Plain tokens as-is; anything else is single-quoted (POSIX and PowerShell both treat a
 * single-quoted string as literal), so seller-controlled text cannot run command substitution if pasted.
 * This is for display only; the CLI itself is always run without a shell.
 */
function formatArgv(args) {
  return ['onchainos'].concat(args.map((a) => {
    const s = String(a);
    if (/^[A-Za-z0-9_.:/@%+=,-]+$/.test(s)) return s;
    return "'" + s.replace(/'/g, "'\\''") + "'";
  })).join(' ');
}

/** Listing of an OKX.AI service: endpoint, price, token, seller agent and its wallet. */
function serviceListing(sid, agent, log) {
  const say = typeof log === 'function' ? log : () => {};
  if (!agent) {
    say('             $ ' + formatArgv(['agent', 'get-my-agents']));
    const mine = run(['agent', 'get-my-agents']);
    const acct = mine.json && Array.isArray(mine.json.data) ? mine.json.data[0] : null;
    agent = acct && acct.agentList && acct.agentList[0] ? acct.agentList[0].agentId : null;
    if (!agent) throw new Error('could not find your agent id; pass --agent <id>');
  }
  const detailArgs = ['agent', 'service-detail', '--sid', String(Number(sid)), '--agentic-id', String(agent)];
  say('             $ ' + formatArgv(detailArgs));
  const d = run(detailArgs);
  const s = d.json && d.json.data;
  if (!s || !s.endpoint) throw new Error('service-detail returned no endpoint for sid ' + sid + (s && s.serviceType ? ' (type ' + s.serviceType + ')' : ''));
  let sellerWallet = null;
  if (s.asp && s.asp.aspAgentId) {
    const agentsArgs = ['agent', 'get-agents', '--agent-ids', String(s.asp.aspAgentId)];
    say('             $ ' + formatArgv(agentsArgs));
    const g = run(agentsArgs);
    const found = [];
    (function walk(o) { if (Array.isArray(o)) o.forEach(walk); else if (o && typeof o === 'object') { if (String(o.agentId) === String(s.asp.aspAgentId) && o.agentWalletAddress) found.push(o.agentWalletAddress); Object.values(o).forEach(walk); } })(g.json && g.json.data);
    sellerWallet = found[0] || null;
  }
  return { source: 'okx.ai', sid: s.sid, serviceName: s.serviceName, serviceType: s.serviceType, endpoint: s.endpoint, feeAmount: s.feeAmount, feeToken: s.feeToken, feeTokenSymbol: s.feeTokenSymbol, asp: s.asp || null, sellerWallet };
}

module.exports = { ONCHAINOS, run, formatArgv, serviceListing };
