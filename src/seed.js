'use strict';

/**
 * Seed the shared registry with public scam databases so that known drainers
 * and phishing domains are blocked from day one, before any agent reports.
 *
 * Source: ScamSniffer scam-database (MIT), refreshed daily by the Vercel cron
 * in vercel.json (GET /cron/seed) or manually via scripts/seed-threats.js.
 *
 * Storage layout (cheap on Upstash: a few hundred commands per full refresh):
 *   seed:addresses        SET of lowercase EVM addresses (chain-agnostic)
 *   seed:domains          SET of lowercase hostnames (www. stripped)
 *   seed:meta             HASH { source, updated_at, addresses, domains, list_sha }
 */

const crypto = require('crypto');
const registry = require('./registry');

const SOURCES = {
  scamsniffer: {
    name: 'ScamSniffer scam-database',
    url: 'https://github.com/scamsniffer/scam-database',
    addresses: 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json',
    domains: 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json',
  },
};

const BATCH = 1000;
const PIPELINE_BATCHES = 10;
const FETCH_TIMEOUT_MS = 45000;
const BULK_TIMEOUT_MS = Number.parseInt(process.env.SEED_STORE_TIMEOUT_MS || '30000', 10);
const KEY_ADDR = 'seed:addresses';
const KEY_DOM = 'seed:domains';
const KEY_META = 'seed:meta';

async function fetchJson(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { 'user-agent': 'guardian-mcp-seed/1' } });
    if (!res.ok) throw new Error('fetch ' + url + ' -> ' + res.status);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

function normalizeHost(h) {
  return String(h).trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0].replace(/^www\./, '').replace(/\.$/, '');
}

/** Download and normalise the lists. Pure I/O; no store access. */
async function fetchLists(source) {
  const src = SOURCES[source || 'scamsniffer'];
  const [rawAddr, rawDom] = await Promise.all([fetchJson(src.addresses), fetchJson(src.domains)]);
  const addresses = Array.from(new Set((Array.isArray(rawAddr) ? rawAddr : []).map((a) => String(a).trim().toLowerCase()).filter((a) => /^0x[0-9a-f]{40}$/.test(a))));
  const domains = Array.from(new Set((Array.isArray(rawDom) ? rawDom : []).map(normalizeHost).filter((d) => d && d.length <= 253 && /^[a-z0-9.-]+$/.test(d) && d.includes('.'))));
  // Never seed canonical protocol addresses even if a list is wrong.
  const safeAddresses = addresses.filter((a) => !registry.lookupContract(1, a) && !Object.values(registry.KNOWN_TOKENS).some((m) => m[a]));
  const sha = crypto.createHash('sha256').update(safeAddresses.join('\n') + '\n---\n' + domains.join('\n')).digest('hex');
  return { source: src.name, addresses: safeAddresses, domains, sha };
}

/** Write the lists into the store with an atomic swap. */
async function applySeed(store, lists, opts) {
  opts = opts || {};
  const meta = await store.command('HGETALL', KEY_META);
  const current = {};
  if (Array.isArray(meta)) for (let i = 0; i < meta.length; i += 2) current[meta[i]] = meta[i + 1];
  else if (meta && typeof meta === 'object') Object.assign(current, meta);
  if (!opts.force && current.list_sha === lists.sha) {
    return { changed: false, addresses: Number(current.addresses || 0), domains: Number(current.domains || 0), updated_at: current.updated_at || null };
  }
  const tmpA = KEY_ADDR + ':new';
  const tmpD = KEY_DOM + ':new';
  await store.pipeline([['DEL', tmpA], ['DEL', tmpD]]);
  let commands = 0;
  const bulk = { timeoutMs: BULK_TIMEOUT_MS };
  const addrBatches = [];
  for (let i = 0; i < lists.addresses.length; i += BATCH) addrBatches.push(['SADD', tmpA, ...lists.addresses.slice(i, i + BATCH)]);
  for (let i = 0; i < addrBatches.length; i += PIPELINE_BATCHES) {
    await store.pipeline(addrBatches.slice(i, i + PIPELINE_BATCHES), bulk);
    commands += Math.min(PIPELINE_BATCHES, addrBatches.length - i);
  }
  const domainBatches = [];
  for (let i = 0; i < lists.domains.length; i += BATCH) domainBatches.push(['SADD', tmpD, ...lists.domains.slice(i, i + BATCH)]);
  for (let i = 0; i < domainBatches.length; i += PIPELINE_BATCHES) {
    await store.pipeline(domainBatches.slice(i, i + PIPELINE_BATCHES), bulk);
    commands += Math.min(PIPELINE_BATCHES, domainBatches.length - i);
  }
  const now = new Date().toISOString();
  const swap = [];
  if (lists.addresses.length) swap.push(['RENAME', tmpA, KEY_ADDR]);
  if (lists.domains.length) swap.push(['RENAME', tmpD, KEY_DOM]);
  swap.push(['HSET', KEY_META, 'source', lists.source, 'updated_at', now, 'addresses', lists.addresses.length, 'domains', lists.domains.length, 'list_sha', lists.sha]);
  await store.pipeline(swap, bulk);
  return { changed: true, addresses: lists.addresses.length, domains: lists.domains.length, updated_at: now, commands: commands + swap.length + 2 };
}

/** Fetch + apply. Used by the cron route and the CLI script. */
async function run(store, opts) {
  const lists = await fetchLists(opts && opts.source);
  return applySeed(store, lists, opts);
}

async function meta(store) {
  const h = await store.command('HGETALL', KEY_META);
  const out = {};
  if (Array.isArray(h)) for (let i = 0; i < h.length; i += 2) out[h[i]] = h[i + 1];
  else if (h && typeof h === 'object') Object.assign(out, h);
  return Object.keys(out).length ? { source: out.source, updated_at: out.updated_at, addresses: Number(out.addresses || 0), domains: Number(out.domains || 0) } : null;
}

function domainCandidates(host) {
  const h = normalizeHost(host);
  const parts = h.split('.');
  const out = new Set([h]);
  // registrable-ish suffixes: a.b.c.d -> b.c.d, c.d
  for (let i = 1; i < parts.length - 1; i += 1) out.add(parts.slice(i).join('.'));
  return Array.from(out);
}

/**
 * Membership check for addresses and domains.
 * @returns {Promise<{addresses: Object<string, boolean>, domains: Object<string, string|null>}>}
 *   domains maps input host -> matched seed entry (or null)
 */
async function lookup(store, addresses, domains) {
  addresses = Array.from(new Set((addresses || []).map((a) => String(a).toLowerCase())));
  domains = Array.from(new Set((domains || []).map(normalizeHost).filter(Boolean)));
  const out = { addresses: {}, domains: {} };
  const cmds = [];
  for (const a of addresses) cmds.push(['SISMEMBER', KEY_ADDR, a]);
  const domainPlan = domains.map((d) => domainCandidates(d));
  for (const cands of domainPlan) for (const c of cands) cmds.push(['SISMEMBER', KEY_DOM, c]);
  if (!cmds.length) return out;
  const res = await store.pipeline(cmds);
  let i = 0;
  for (const a of addresses) out.addresses[a] = Number(res[i++]) === 1;
  domains.forEach((d, idx) => {
    let hit = null;
    for (const c of domainPlan[idx]) {
      if (Number(res[i++]) === 1 && !hit) hit = c;
    }
    out.domains[d] = hit;
  });
  return out;
}

const SEED_RULES = [
  { code: 'scam_database_address', severity: 'DENY', layer: 'shared-intel', description: 'Counterparty address is listed in a public scam database (ScamSniffer). Capped at WARN for the recipient role of a plain transfer.' },
  { code: 'scam_database_domain', severity: 'DENY', layer: 'shared-intel', description: 'A source domain (or its parent domain) is listed in a public phishing database (ScamSniffer).' },
];

module.exports = { fetchLists, applySeed, run, meta, lookup, normalizeHost, domainCandidates, SOURCES, SEED_RULES, KEY_ADDR, KEY_DOM, KEY_META };
