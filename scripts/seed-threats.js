#!/usr/bin/env node
'use strict';

/**
 * Manual seeding of the shared registry from public scam databases.
 *
 *   node scripts/seed-threats.js            # uses .env.local / environment for the store
 *   node scripts/seed-threats.js --force    # re-apply even if the lists did not change
 *
 * The production cron (vercel.json -> GET /cron/seed) does the same daily.
 */

const fs = require('fs');
const path = require('path');

function loadDotEnv(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m || process.env[m[1]] !== undefined) continue;
    let v = m[2];
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    process.env[m[1]] = v;
  }
}

loadDotEnv(path.join(__dirname, '..', '.env.local'));
loadDotEnv(path.join(__dirname, '..', '.env'));

const { getStore, storeConfig } = require('../src/store');
const seed = require('../src/seed');

(async () => {
  const store = getStore();
  console.log('store:', store.kind, store.persistent ? '(persistent)' : '(memory, nothing will survive this process)', storeConfig() ? '' : '- set UPSTASH_REDIS_REST_URL/TOKEN or KV_REST_API_URL/TOKEN');
  const started = Date.now();
  const lists = await seed.fetchLists();
  console.log('fetched', lists.source + ':', lists.addresses.length, 'addresses,', lists.domains.length, 'domains in', Date.now() - started, 'ms');
  const result = await seed.applySeed(store, lists, { force: process.argv.includes('--force') });
  console.log(result.changed ? 'applied' : 'unchanged (same list hash)', JSON.stringify(result));
  const m = await seed.meta(store);
  console.log('meta:', JSON.stringify(m));
})().catch((err) => {
  console.error('seed failed:', err.message);
  process.exit(1);
});
