#!/usr/bin/env node
'use strict';

/**
 * Build docs/trust-history.json — a compact, bundle-safe index of every dated trust-scan snapshot in
 * docs/trust-scans/<YYYY-MM-DD>.json. GET /trust-scans serves it, and GET /trust renders it. Keeping the
 * history in one required file avoids reading a directory at runtime on serverless.
 *
 *   node scripts/build-trust-history.js
 */

const fs = require('node:fs');
const path = require('node:path');

const DOCS = path.join(__dirname, '..', 'docs');
const SNAP = path.join(DOCS, 'trust-scans');

function summarize(scan, date) {
  const results = Array.isArray(scan.results) ? scan.results : [];
  const deny = results.filter((r) => r.verdict === 'DENY').map((r) => ({
    sid: r.sid, service: String(r.service || '').slice(0, 80), seller: r.asp || null,
    endpointHost: hostOf(r.endpoint), reasons: r.reasons || [],
  }));
  const warnCodes = {};
  for (const r of results) if (r.verdict === 'WARN') for (const c of r.reasons || []) warnCodes[c] = (warnCodes[c] || 0) + 1;
  return { date, generatedAt: scan.generatedAt || null, totals: scan.totals || {}, denyCount: deny.length, deny, warnCodes };
}

function hostOf(url) {
  if (typeof url !== 'string') return null;
  try { return new URL(url.includes('://') ? url : 'https://' + url).host; } catch { return null; }
}

function main() {
  const files = fs.existsSync(SNAP) ? fs.readdirSync(SNAP).filter((f) => /^\d{4}-\d{2}-\d{2}\.json$/.test(f)).sort() : [];
  const snapshots = files.map((f) => {
    const scan = JSON.parse(fs.readFileSync(path.join(SNAP, f), 'utf8'));
    return summarize(scan, f.replace(/\.json$/, ''));
  });
  const history = {
    generatedAt: snapshots.length ? snapshots[snapshots.length - 1].generatedAt : null,
    source: 'OKX.AI paid A2MCP services, probed without paying (Pay-Safe trust scan)',
    latestDate: snapshots.length ? snapshots[snapshots.length - 1].date : null,
    snapshots,
  };
  fs.writeFileSync(path.join(DOCS, 'trust-history.json'), JSON.stringify(history, null, 1));

  // Cross-snapshot index: sid -> its most recent full result, WITH the date it was last seen. This keeps a
  // listing that later dropped off the marketplace (like the malicious sid 39876) checkable via check_listing.
  const bySid = {};
  for (const f of files) {
    const scan = JSON.parse(fs.readFileSync(path.join(SNAP, f), 'utf8'));
    const date = f.replace(/\.json$/, '');
    for (const r of scan.results || []) {
      if (r.sid === undefined || r.sid === null || !r.verdict) continue;
      // Files are sorted ascending, so the last write wins = the most recent scan that saw this sid.
      bySid[r.sid] = Object.assign({}, r, { scanDate: date, scannedAt: scan.generatedAt || null });
    }
  }
  fs.writeFileSync(path.join(DOCS, 'trust-listings.json'), JSON.stringify(bySid, null, 1));
  console.log('trust-history.json:', snapshots.length, 'snapshot(s) —', snapshots.map((s) => s.date + ' (' + s.denyCount + ' DENY)').join(', '));
  console.log('trust-listings.json:', Object.keys(bySid).length, 'sids indexed across snapshots');
}

main();
