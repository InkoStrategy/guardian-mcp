'use strict';

/**
 * Daily OKX.AI marketplace trust scan, meant to run unattended from Task Scheduler.
 *
 *   node scripts/daily-scan.cjs            scan + snapshot + rebuild history, commit locally
 *   node scripts/daily-scan.cjs --push     also push (so /trust updates for readers)
 *   node scripts/daily-scan.cjs --dry-run  scan and validate only, touch nothing
 *
 * It refuses to record or publish a scan that looks broken (expired CLI login, network failure),
 * because /trust and DEVDAY cite these files: a bad snapshot is worse than a missing one.
 */

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const DOCS = path.join(ROOT, 'docs');
const SNAPS = path.join(DOCS, 'trust-scans');
const LOG = path.join(ROOT, 'docs', 'daily-scan.log');
const PUSH = process.argv.includes('--push');
const DRY = process.argv.includes('--dry-run');

/** A scan with fewer services than this means the CLI failed, not that the marketplace shrank. */
const MIN_SERVICES = 40;

function log(msg) {
  const line = new Date().toISOString() + ' ' + msg;
  try { fs.appendFileSync(LOG, line + '\n'); } catch { /* logging must never break the run */ }
  console.log(line);
}

function run(cmd, args, opts) {
  const r = spawnSync(cmd, args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 64e6, windowsHide: true, ...opts });
  return { code: r.status, out: (r.stdout || '').trim(), err: (r.stderr || '').trim() };
}

function today() {
  const d = new Date();
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}

function main() {
  log('--- daily scan start' + (DRY ? ' (dry run)' : '') + ' ---');

  const scan = run(process.execPath, ['scripts/okxai-trust-scan.js']);
  if (scan.code !== 0) { log('ABORT: scan exited ' + scan.code + ' :: ' + (scan.err || scan.out).slice(0, 300)); return 1; }

  const latest = path.join(DOCS, 'trust-scan.json');
  if (!fs.existsSync(latest)) { log('ABORT: scan produced no docs/trust-scan.json'); return 1; }

  let data;
  try { data = JSON.parse(fs.readFileSync(latest, 'utf8')); }
  catch (e) { log('ABORT: docs/trust-scan.json is not valid JSON :: ' + e.message); return 1; }

  const t = data.totals || {};
  if (!t.services || t.services < MIN_SERVICES) {
    log('ABORT: only ' + (t.services || 0) + ' services (min ' + MIN_SERVICES + ') — the CLI login has probably expired. Nothing written.');
    return 1;
  }
  if (!t.challenge) { log('ABORT: no 402 challenges probed — network or Guardian is down. Nothing written.'); return 1; }

  const date = today();
  log('scan ok: ' + t.services + ' services, ' + t.challenge + ' challenges, ' +
      (t.allow || 0) + ' allow / ' + (t.warn || 0) + ' warn / ' + (t.deny || 0) + ' deny');

  if (DRY) { log('dry run — stopping before any write'); return 0; }

  fs.mkdirSync(SNAPS, { recursive: true });
  const snap = path.join(SNAPS, date + '.json');
  const isNew = !fs.existsSync(snap);
  fs.writeFileSync(snap, JSON.stringify(data, null, 1));
  log((isNew ? 'wrote' : 'refreshed') + ' docs/trust-scans/' + date + '.json');

  const hist = run(process.execPath, ['scripts/build-trust-history.js']);
  if (hist.code !== 0) { log('ABORT: build-trust-history failed :: ' + (hist.err || hist.out).slice(0, 300)); return 1; }

  const outreach = run(process.execPath, ['scripts/eip712-outreach.js', date]);
  if (outreach.code === 0) log('eip712 outreach list refreshed for ' + date);

  // Only ever touch the scan artefacts — never code.
  const paths = ['docs/trust-scan.json', 'docs/trust-scan.md', 'docs/trust-scans/' + date + '.json',
                 'docs/trust-history.json', 'docs/trust-listings.json', 'docs/eip712-outreach-' + date + '.json'];
  run('git', ['add', '--'].concat(paths.filter((p) => fs.existsSync(path.join(ROOT, p)))));

  const staged = run('git', ['diff', '--cached', '--name-only']);
  if (!staged.out) { log('nothing changed since the last scan — no commit'); return 0; }

  const msg = 'chore(scan): OKX.AI marketplace scan ' + date + ' (' + t.services + ' services, ' +
              (t.deny || 0) + ' DENY, ' + (t.warn || 0) + ' WARN)\n\nAutomated daily scan.\n\n' +
              'Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>';
  const commit = run('git', ['commit', '-q', '-m', msg]);
  if (commit.code !== 0) { log('commit failed :: ' + (commit.err || commit.out).slice(0, 300)); return 1; }
  log('committed: ' + staged.out.split('\n').join(', '));

  if (PUSH) {
    const push = run('git', ['push', '-q', 'origin', 'HEAD']);
    if (push.code !== 0) { log('PUSH FAILED (commit is kept locally) :: ' + (push.err || push.out).slice(0, 300)); return 1; }
    log('pushed — waiting for Vercel to serve it');
    return verifyPublished(t.services);
  }
  log('committed locally only (pass --push to publish)');
  return 0;
}

/**
 * Pushing is not publishing: a deploy can succeed and still serve a stale bundle (Vercel's build cache
 * rebuilt nothing when only docs/ changed, which silently served old scans for hours). So confirm the live
 * site actually reports this run's numbers, and say so in the log when it does not.
 */
async function verifyPublished(expectedServices) {
  const url = 'https://guardian-mcp-rho.vercel.app/trust-scan';
  for (let i = 1; i <= 20; i++) {
    await new Promise((r) => setTimeout(r, 30000));
    try {
      const res = await fetch(url, { headers: { 'cache-control': 'no-cache' } });
      const j = await res.json();
      const live = j && j.totals && j.totals.services;
      if (live === expectedServices) { log('published: the live site reports ' + live + ' services'); return 0; }
      if (i % 5 === 0) log('  still serving ' + live + ' (want ' + expectedServices + ') after ' + (i * 30) + 's');
    } catch (e) { if (i % 5 === 0) log('  live check failed: ' + e.message); }
  }
  log('WARNING: pushed, but the live site still does not report ' + expectedServices +
      ' services after 10 min. The commit is safe in git; check the Vercel deployment.');
  return 0;
}

main2();
async function main2() {
  const code = main();
  process.exit(code instanceof Promise ? await code : code);
}
