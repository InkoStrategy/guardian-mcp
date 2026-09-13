'use strict';

/** Public statistics page. Self-contained HTML; fetches GET /stats on load. */
function html() {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Guardian MCP · live stats</title>
<style>
:root{--bg:#0b0d10;--card:#13171c;--line:#222831;--txt:#e6e9ee;--muted:#8a93a0;--ok:#3ecf8e;--warn:#f5b849;--deny:#f0574f;--acc:#6aa9ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 60px}h1{font-size:26px;margin:0 0 4px}h1 small{color:var(--muted);font-weight:400;font-size:14px;margin-left:10px}
.sub{color:var(--muted);margin:0 0 24px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}.card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}.card .v{font-size:30px;font-weight:600;margin-top:4px}.card .n{color:var(--muted);font-size:12px;margin-top:4px}
.v.ok{color:var(--ok)}.v.warn{color:var(--warn)}.v.deny{color:var(--deny)}
h2{font-size:16px;margin:28px 0 10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.bars{display:flex;gap:6px;align-items:flex-end;height:140px;padding:10px;background:var(--card);border:1px solid var(--line);border-radius:12px}
.bar{flex:1;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;gap:2px;min-width:0}.bar .st{width:100%;display:flex;flex-direction:column;justify-content:flex-end}
.bar .a{background:#2c3440}.bar .w{background:var(--warn)}.bar .d{background:var(--deny)}.bar .lbl{font-size:10px;color:var(--muted);white-space:nowrap}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);font-size:14px}th{color:var(--muted);font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
td.num{text-align:right;font-variant-numeric:tabular-nums}.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid var(--line)}.pill.deny{color:var(--deny)}.pill.warn{color:var(--warn)}
.foot{color:var(--muted);font-size:13px;margin-top:30px}.foot a{color:var(--acc);text-decoration:none}code{background:#1b2027;padding:1px 6px;border-radius:6px;font-size:13px}
</style></head><body><div class="wrap">
<h1>Guardian MCP <small id="ver"></small></h1>
<p class="sub">Live, unaudited counters from the shared store. No request payloads are stored; only verdict, rule and session counters.</p>
<div class="grid" id="kpi"></div>
<h2>Last 14 days · calls by verdict</h2><div class="bars" id="bars"></div>
<h2>Shared threat registry</h2><div class="grid" id="threat"></div>
<p class="foot">API: <code>POST /analyze</code> · <code>POST /analyze-signature</code> · <code>GET /rules</code> · <code>GET /threats/{chainId}/{address}</code> · <code>GET /session/{id}</code> · JSON of this page: <a href="/stats">/stats</a> · <a id="repo" href="#">source</a></p>
</div>
<script>
(async function(){
  const r = await fetch('/stats'); const s = await r.json();
  const h = await fetch('/health').then(x=>x.json()).catch(()=>({}));
  document.getElementById('ver').textContent = h.version ? 'v'+h.version+(s.persistent?' · persistent store':' · memory store') : '';
  if (h.docs) document.getElementById('repo').href = h.docs;
  const kpi = [
    ['Total calls', s.calls.total, s.calls.transactions+' tx · '+s.calls.signatures+' signatures',''],
    ['Blocked (DENY)', s.verdicts.DENY, s.blocked_share+'% of all calls','deny'],
    ['Warned', s.verdicts.WARN, '', 'warn'],
    ['Allowed', s.verdicts.ALLOW, '', 'ok'],
    ['Distinct sessions', s.distinct_sessions, s.first_call_at ? 'since '+s.first_call_at.slice(0,10) : 'no calls yet',''],
    ['Registry entries', s.threat_registry.seeded_addresses+s.threat_registry.seeded_domains+s.threat_registry.flagged_addresses_chain_1+s.threat_registry.flagged_domains, 'drainers and phishing domains',''],
  ];
  document.getElementById('kpi').innerHTML = kpi.map(([k,v,n,c])=>'<div class="card"><div class="k">'+k+'</div><div class="v '+c+'">'+v.toLocaleString()+'</div><div class="n">'+n+'</div></div>').join('');
  const max = Math.max(1, ...s.daily.map(d=>d.calls));
  document.getElementById('bars').innerHTML = s.daily.map(d=>{const a=d.calls-d.warn-d.deny;const px=v=>Math.round(v/max*110)+'px';return '<div class="bar" title="'+d.day+': '+d.calls+' calls, '+d.warn+' warn, '+d.deny+' deny, '+d.sessions+' sessions"><div class="st"><div class="d" style="height:'+px(d.deny)+'"></div><div class="w" style="height:'+px(d.warn)+'"></div><div class="a" style="height:'+px(a)+'"></div></div><div class="lbl">'+d.day.slice(5)+'</div></div>'}).join('');
  const t = s.threat_registry;
  const th = [['Seeded drainer addresses', t.seeded_addresses, t.seed_source||''],['Seeded phishing domains', t.seeded_domains, t.seed_updated_at ? 'updated '+t.seed_updated_at.slice(0,10) : 'not seeded yet'],['Agent reports', t.agent_reports, 'anonymous, fact-based DENY rules'],['Flagged by agents', t.flagged_addresses_chain_1+t.flagged_domains, t.flagged_addresses_chain_1+' addresses · '+t.flagged_domains+' domains']];
  document.getElementById('threat').innerHTML = th.map(([k,v,n])=>'<div class="card"><div class="k">'+k+'</div><div class="v">'+Number(v).toLocaleString()+'</div><div class="n">'+n+'</div></div>').join('');
})().catch(e=>{document.getElementById('kpi').innerHTML='<div class="card">Failed to load /stats: '+e.message+'</div>'});
</script></body></html>`;
}

module.exports = { html };
