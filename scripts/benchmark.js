#!/usr/bin/env node
'use strict';

/**
 * Real-world benchmark: would Guardian have stopped the victim?
 *
 * Attack set: real Ethereum mainnet approve() transactions signed by victims
 * towards drainer addresses listed in the ScamSniffer scam-database, found via
 * the public Blockscout API (drainer's incoming ERC-20 loot -> victim -> the
 * victim's earlier approve to that drainer).
 *
 * Control set: real approve() transactions towards canonical protocol contracts
 * (Permit2, Uniswap routers, 1inch) found via eth_getLogs on recent blocks.
 *
 * Every case is replayed twice:
 *   - rules only: local analyzer, empty memory store (no seeded registry)
 *   - as deployed: the production API with the seeded shared registry
 *
 *   node scripts/benchmark.js [--attacks 30] [--controls 30] [--base https://guardian-mcp-rho.vercel.app]
 */

const fs = require('fs');
const path = require('path');
const { JsonRpcProvider, Interface, id, zeroPadValue } = require('ethers');

const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf('--' + name); return i === -1 ? def : args[i + 1]; };
const WANT_ATTACKS = Number(opt('attacks', 30));
const WANT_CONTROLS = Number(opt('controls', 30));
const BASE = opt('base', 'https://guardian-mcp-rho.vercel.app');
const BLOCKSCOUT = 'https://eth.blockscout.com/api/v2';
const RPC = 'https://ethereum-rpc.publicnode.com';
const SCAMSNIFFER = 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json';
const APPROVE = '0x095ea7b3';
const SET_APPROVAL_FOR_ALL = '0xa22cb465';
const CONTROL_SPENDERS = {
  '0x000000000022d473030f116ddee9f6b43ac78ba3': 'Permit2',
  '0x7a250d5630b4cf539739df2c5dacb4c659f2488d': 'Uniswap V2 Router02',
  '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45': 'Uniswap V3 SwapRouter02',
  '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad': 'Uniswap Universal Router',
  '0x111111125421ca6dc452d289314280a0f8842a65': '1inch AggregationRouter V6',
};

const erc20 = new Interface(['function approve(address spender, uint256 amount)', 'function setApprovalForAll(address operator, bool approved)']);

async function getJson(url, tries) {
  tries = tries || 3;
  for (let i = 0; i < tries; i += 1) {
    try {
      const res = await fetch(url, { headers: { accept: 'application/json', 'user-agent': 'guardian-mcp-benchmark/1' } });
      if (res.status === 429) { await sleep(1500 * (i + 1)); continue; }
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return await res.json();
    } catch (err) {
      if (i === tries - 1) throw err;
      await sleep(800 * (i + 1));
    }
  }
  return null;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function decodeSpender(data) {
  if (!data || data.length < 10) return null;
  const sel = data.slice(0, 10).toLowerCase();
  try {
    if (sel === APPROVE) { const d = erc20.decodeFunctionData('approve', data); return { kind: 'approve', spender: d[0].toLowerCase(), amount: d[1].toString() }; }
    if (sel === SET_APPROVAL_FOR_ALL) { const d = erc20.decodeFunctionData('setApprovalForAll', data); return d[1] ? { kind: 'setApprovalForAll', spender: d[0].toLowerCase(), amount: 'all' } : null; }
  } catch { return null; }
  return null;
}

// ---------------------------------------------------------------------------
// Attack set
// ---------------------------------------------------------------------------

async function collectAttacks(drainers, want) {
  const cases = [];
  const seenTx = new Set();
  let scanned = 0;
  for (const drainer of drainers) {
    if (cases.length >= want) break;
    scanned += 1;
    let loot;
    try {
      loot = await getJson(BLOCKSCOUT + '/addresses/' + drainer + '/token-transfers?type=ERC-20&filter=to');
    } catch { continue; }
    const items = (loot && loot.items) || [];
    if (!items.length) continue;
    const victims = new Map();
    for (const t of items) {
      const from = t.from && t.from.hash ? t.from.hash.toLowerCase() : null;
      const token = t.token && t.token.address ? t.token.address.toLowerCase() : null;
      if (!from || !token || from === drainer) continue;
      // transferFrom pulled by the drainer: tx sender is the drainer, token sender is the victim
      const txFrom = t.transaction_hash ? null : null;
      if (!victims.has(from)) victims.set(from, { token, txHash: t.transaction_hash, symbol: t.token.symbol, value: t.total && t.total.value, decimals: t.token.decimals });
      if (victims.size >= 6) break;
    }
    for (const [victim, loot1] of victims) {
      if (cases.length >= want) break;
      let txs;
      try {
        txs = await getJson(BLOCKSCOUT + '/addresses/' + victim + '/transactions?filter=from');
      } catch { continue; }
      const list = (txs && txs.items) || [];
      const approveTx = list.find((tx) => {
        const to = tx.to && tx.to.hash ? tx.to.hash.toLowerCase() : null;
        const dec = decodeSpender(tx.raw_input);
        return to === loot1.token && dec && dec.spender === drainer && tx.status === 'ok';
      }) || list.find((tx) => { const dec = decodeSpender(tx.raw_input); return dec && dec.spender === drainer && tx.status === 'ok'; });
      if (!approveTx || seenTx.has(approveTx.hash)) continue;
      seenTx.add(approveTx.hash);
      const dec = decodeSpender(approveTx.raw_input);
      cases.push({ set: 'attack', hash: approveTx.hash, block: approveTx.block_number || approveTx.block, timestamp: approveTx.timestamp, from: victim, to: approveTx.to.hash, data: approveTx.raw_input, drainer, kind: dec.kind, amount: dec.amount, lootTx: loot1.txHash, lootSymbol: loot1.symbol, lootValue: loot1.value, lootDecimals: loot1.decimals });
      process.stderr.write('attack ' + cases.length + '/' + want + ' (' + dec.kind + ' -> ' + drainer.slice(0, 10) + ') scanned ' + scanned + ' drainers\n');
    }
    await sleep(250);
  }
  return { cases, scanned };
}

// ---------------------------------------------------------------------------
// Control set
// ---------------------------------------------------------------------------

async function collectControls(want) {
  const provider = new JsonRpcProvider(RPC, 1, { staticNetwork: true });
  const latest = await provider.getBlockNumber();
  const topicApproval = id('Approval(address,address,uint256)');
  const cases = [];
  const seen = new Set();
  const spenders = Object.keys(CONTROL_SPENDERS);
  let from = latest - 400;
  while (cases.length < want && from > latest - 20000) {
    const to = from + 399;
    let logs = [];
    try {
      logs = await provider.getLogs({ fromBlock: from, toBlock: to, topics: [topicApproval, null, spenders.map((s) => zeroPadValue(s, 32))] });
    } catch (err) {
      process.stderr.write('getLogs ' + from + '-' + to + ' failed: ' + err.message + '\n');
    }
    for (const log of logs) {
      if (cases.length >= want) break;
      if (seen.has(log.transactionHash)) continue;
      seen.add(log.transactionHash);
      let tx;
      try { tx = await provider.getTransaction(log.transactionHash); } catch { continue; }
      if (!tx || !tx.to || tx.to.toLowerCase() !== log.address.toLowerCase()) continue; // only top-level approve calls on the token
      const dec = decodeSpender(tx.data);
      if (!dec || !CONTROL_SPENDERS[dec.spender]) continue;
      cases.push({ set: 'control', hash: tx.hash, block: tx.blockNumber, from: tx.from, to: tx.to, data: tx.data, spender: dec.spender, spenderName: CONTROL_SPENDERS[dec.spender], kind: dec.kind, amount: dec.amount });
      process.stderr.write('control ' + cases.length + '/' + want + ' (' + CONTROL_SPENDERS[dec.spender] + ')\n');
    }
    from -= 400;
    await sleep(150);
  }
  return cases;
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

async function replayRulesOnly(c) {
  const { analyze } = require('../src/analyzer');
  const { createMemoryStore } = require('../src/store');
  const r = await analyze({ to: c.to, data: c.data, chainId: 1, context: { share_threat_intel: false } }, { store: createMemoryStore(), env: {} });
  return { verdict: r.verdict, reasons: r.reasons };
}

async function replayDeployed(c) {
  const res = await fetch(BASE + '/analyze', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ to: c.to, data: c.data, chainId: 1, context: { share_threat_intel: false, session_id: 'benchmark-' + c.set } }) });
  const j = await res.json();
  return { verdict: j.verdict, reasons: j.reasons, status: res.status };
}

function pct(n, d) { return d ? Math.round((n / d) * 1000) / 10 : 0; }

(async () => {
  const started = Date.now();
  process.stderr.write('fetching ScamSniffer addresses…\n');
  const drainers = (await getJson(SCAMSNIFFER)).map((a) => String(a).toLowerCase()).filter((a) => /^0x[0-9a-f]{40}$/.test(a));
  // Newest entries are appended at the end of the list; scan from the end for recent, active drainers.
  const { cases: attacks, scanned } = await collectAttacks(drainers.slice().reverse(), WANT_ATTACKS);
  const controls = await collectControls(WANT_CONTROLS);
  const all = attacks.concat(controls);
  process.stderr.write('replaying ' + all.length + ' cases…\n');
  for (const c of all) {
    c.rulesOnly = await replayRulesOnly(c);
    c.deployed = await replayDeployed(c);
    await sleep(120);
  }

  const summary = (set, key, blocked) => { const xs = all.filter((c) => c.set === set); return xs.filter((c) => blocked(c[key].verdict)).length; };
  const nA = attacks.length;
  const nC = controls.length;
  const out = {
    generated_at: new Date().toISOString(),
    duration_ms: Date.now() - started,
    sources: { attacks: 'ScamSniffer scam-database addresses + Blockscout victim transactions', controls: 'eth_getLogs Approval events to canonical protocol contracts, last ~20k blocks' },
    drainers_scanned: scanned,
    attacks: { n: nA, rules_only: { deny: summary('attack', 'rulesOnly', (v) => v === 'DENY'), warn: summary('attack', 'rulesOnly', (v) => v === 'WARN'), allow: summary('attack', 'rulesOnly', (v) => v === 'ALLOW') }, deployed: { deny: summary('attack', 'deployed', (v) => v === 'DENY'), warn: summary('attack', 'deployed', (v) => v === 'WARN'), allow: summary('attack', 'deployed', (v) => v === 'ALLOW') } },
    controls: { n: nC, rules_only: { deny: summary('control', 'rulesOnly', (v) => v === 'DENY'), warn: summary('control', 'rulesOnly', (v) => v === 'WARN'), allow: summary('control', 'rulesOnly', (v) => v === 'ALLOW') }, deployed: { deny: summary('control', 'deployed', (v) => v === 'DENY'), warn: summary('control', 'deployed', (v) => v === 'WARN'), allow: summary('control', 'deployed', (v) => v === 'ALLOW') } },
    cases: all,
  };
  fs.mkdirSync(path.join(__dirname, '..', 'docs'), { recursive: true });
  fs.writeFileSync(path.join(__dirname, '..', 'docs', 'benchmark.json'), JSON.stringify(out, null, 2));

  const a = out.attacks; const cc = out.controls;
  const md = [];
  md.push('# Benchmark: real drain approvals vs. real legitimate approvals', '');
  md.push('Generated ' + out.generated_at.slice(0, 16).replace('T', ' ') + ' UTC. Every case is a real Ethereum mainnet transaction; hashes link to Etherscan.', '');
  md.push('**Attack set** (' + nA + '): approve / setApprovalForAll transactions signed by real victims towards drainer addresses listed in the public ScamSniffer scam-database, located through the drainer\'s incoming ERC-20 loot on Blockscout. ' + scanned + ' listed addresses were scanned to find them.', '');
  md.push('**Control set** (' + nC + '): approve transactions to canonical protocol contracts (Permit2, Uniswap V2/V3/Universal Router, 1inch v6) from recent blocks.', '');
  md.push('Two replays per case: **rules only** (local analyzer, empty registry, no ScamSniffer seed) and **as deployed** (production API with the seeded shared registry).', '');
  md.push('| | rules only | as deployed |', '|---|---|---|');
  md.push('| Attacks blocked (DENY) | ' + a.rules_only.deny + ' / ' + nA + ' (' + pct(a.rules_only.deny, nA) + '%) | ' + a.deployed.deny + ' / ' + nA + ' (' + pct(a.deployed.deny, nA) + '%) |');
  md.push('| Attacks flagged (WARN) | ' + a.rules_only.warn + ' | ' + a.deployed.warn + ' |');
  md.push('| Attacks missed (ALLOW) | ' + a.rules_only.allow + ' | ' + a.deployed.allow + ' |');
  md.push('| Legit approvals blocked (false DENY) | ' + cc.rules_only.deny + ' / ' + nC + ' (' + pct(cc.rules_only.deny, nC) + '%) | ' + cc.deployed.deny + ' / ' + nC + ' (' + pct(cc.deployed.deny, nC) + '%) |');
  md.push('| Legit approvals warned | ' + cc.rules_only.warn + ' | ' + cc.deployed.warn + ' |');
  md.push('| Legit approvals allowed | ' + cc.rules_only.allow + ' | ' + cc.deployed.allow + ' |', '');
  md.push('WARN on a legitimate approval is expected when the approval is unlimited (`unlimited_approval`); the agent is asked to confirm or to sign the bounded `safe_alternative` instead. A false DENY is the number that matters for usability.', '');
  md.push('## Attack cases', '', '| # | Victim tx | Kind | Drainer | Loot | Rules only | As deployed |', '|---|---|---|---|---|---|---|');
  attacks.forEach((c, i) => md.push('| ' + (i + 1) + ' | [' + c.hash.slice(0, 12) + '…](https://etherscan.io/tx/' + c.hash + ') | ' + c.kind + ' | [' + c.drainer.slice(0, 10) + '…](https://etherscan.io/address/' + c.drainer + ') | ' + (c.lootSymbol || '?') + ' | ' + c.rulesOnly.verdict + ' (' + c.rulesOnly.reasons.join(', ') + ') | ' + c.deployed.verdict + ' (' + c.deployed.reasons.join(', ') + ') |'));
  md.push('', '## Control cases', '', '| # | Tx | Spender | Amount | Rules only | As deployed |', '|---|---|---|---|---|---|');
  controls.forEach((c, i) => md.push('| ' + (i + 1) + ' | [' + c.hash.slice(0, 12) + '…](https://etherscan.io/tx/' + c.hash + ') | ' + c.spenderName + ' | ' + (c.amount === '115792089237316195423570985008687907853269984665640564039457584007913129639935' ? 'unlimited' : 'bounded') + ' | ' + c.rulesOnly.verdict + ' (' + c.rulesOnly.reasons.join(', ') + ') | ' + c.deployed.verdict + ' (' + c.deployed.reasons.join(', ') + ') |'));
  md.push('', '## Method and limits', '', '- Attack cases are the victim-side approval that enabled the drain, which is exactly the moment Guardian is meant to intervene. The drain itself (the drainer\'s transferFrom) is not analysed.', '- The ScamSniffer list is also the seed of the shared registry, so the "as deployed" column includes registry hits by construction; the "rules only" column shows what the deterministic rules catch without any list.', '- Sampling is by list order (newest entries first) and by whatever Blockscout returns; it is not a random sample of all drains and says nothing about drains that used permits, Permit2 or signatures.', '- Reproduce: `node scripts/benchmark.js`. Raw data: `docs/benchmark.json`.');
  fs.writeFileSync(path.join(__dirname, '..', 'docs', 'benchmark.md'), md.join('\n') + '\n');
  console.log(JSON.stringify({ attacks: out.attacks, controls: out.controls, drainers_scanned: scanned, duration_ms: out.duration_ms }, null, 1));
})().catch((err) => { console.error('benchmark failed:', err); process.exit(1); });
