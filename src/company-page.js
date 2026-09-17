'use strict';

/**
 * GET /company: the Build-a-Company case for GuardianMCP Pay-Safe. Honest — no revenue or users are claimed
 * (0 paid calls today); the "cost of the gap" panel is computed live from our own marketplace scans via
 * GET /trust-scans, so every number is traceable.
 */
function html() {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GuardianMCP — the company</title>
<meta name="description" content="The business case for GuardianMCP Pay-Safe: the one safety check before every agent x402 payment on OKX.AI. Who pays, why it defends, and how it grows.">
<style>
:root{--bg:#0b0d10;--card:#13171c;--line:#232a33;--txt:#e6e9ee;--muted:#8d96a3;--ok:#3ecf8e;--warn:#f5b849;--deny:#f0574f;--acc:#6aa9ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:30px;margin:0 0 6px;letter-spacing:-.01em}
h2{font-size:13px;margin:34px 0 12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.lead{color:var(--muted);margin:0 0 8px;max-width:760px;font-size:17px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.grid{display:grid;grid-template-columns:1fr;gap:12px}
@media(min-width:720px){.grid.two{grid-template-columns:1fr 1fr}.grid.three{grid-template-columns:1fr 1fr 1fr}}
.card h3{margin:0 0 6px;font-size:16px}.card p{margin:0;color:var(--muted);font-size:14px}
.cost{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}
@media(min-width:720px){.cost{grid-template-columns:repeat(4,1fr)}}
.stat .v{font-size:30px;font-weight:600}.stat .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.v.warn{color:var(--warn)}.v.deny{color:var(--deny)}.v.ok{color:var(--ok)}
ul{margin:6px 0 0;padding-left:18px;color:var(--muted)}li{margin:4px 0}
.tier{border:1px solid var(--line);border-radius:12px;padding:16px}.tier.paid{border-color:var(--acc)}
.tier .price{font-size:22px;font-weight:600;margin:2px 0 8px}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;border:1px solid currentColor;margin-left:6px}
.badge.live{color:var(--ok)}.badge.plan{color:var(--muted)}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.foot{color:var(--muted);font-size:13px;margin-top:40px}
.note{color:var(--muted);font-size:13px}
</style></head><body><div class="wrap">
<h1>The one check before every agent payment</h1>
<p class="lead">On OKX.AI, an AI agent discovers a paid service, receives an x402 <span class="code">402</span> challenge written by the seller, and pays it through Onchain OS. Nothing between the challenge and the signature checks that it matches the listing the agent chose. GuardianMCP Pay-Safe is that check.</p>
<p class="note">This is the company case, told honestly: the product is live and the checks are free today, with <strong>0 paid calls so far</strong>. Every number below is computed from our own OKX.AI marketplace scans.</p>

<h2>The cost of the gap</h2>
<div class="card"><div class="cost" id="cost">
  <div class="stat"><div class="v" id="c1">—</div><div class="k">paid services scanned</div></div>
  <div class="stat"><div class="v warn" id="c2">—</div><div class="k">of checked challenges we flagged</div></div>
  <div class="stat"><div class="v deny" id="c3">—</div><div class="k">outright attack listing (16 Sep)</div></div>
  <div class="stat"><div class="v warn" id="c4">—</div><div class="k">declared a wrong signing domain</div></div>
</div>
<p class="note" id="costnote" style="margin-top:10px"></p></div>
<p class="note">Each unguarded payment is an uncapped loss: a swapped payee sends funds to an attacker, a wrong EIP-712 domain means the buyer pays and the call still fails at settlement, and a shell payload in a listing turns a naive buyer agent into remote code execution. The check costs nothing to run and nothing is signed to run it.</p>

<h2>Who it is for</h2>
<div class="grid three">
  <div class="card"><h3>Buyer agents &amp; their operators</h3><p>The ones who lose the funds. One call — an Onchain OS skill, an MCP tool, or a Claude Code hook — before every x402 payment.</p></div>
  <div class="card"><h3>Agent frameworks &amp; wallets</h3><p>Anyone shipping autonomous payments wants a drop-in safety layer they don't have to build or maintain.</p></div>
  <div class="card"><h3>OKX.AI, the marketplace</h3><p>A public, dated trust scan of paid services raises the floor for everyone and makes the marketplace safer to build on.</p></div>
</div>

<h2>How it makes money</h2>
<div class="grid two">
  <div class="tier"><h3>Free <span class="badge live">live</span></h3><div class="price">Per-call checks</div>
    <p class="note">Stateless verdicts: <span class="code">check_payment</span>, <span class="code">probe_payment</span>, <span class="code">check_quote</span>, <span class="code">check_listing</span>, address/domain/transaction/signature. Land everywhere; every fact-based DENY feeds the shared registry.</p></div>
  <div class="tier paid"><h3>Premium <span class="badge live">live</span></h3><div class="price">0.099 USD₮0 / call · x402 on X Layer</div>
    <p class="note">The <span class="code">guard</span> tool: session health across a task, owner alerts, reference-template diff, and priority in the shared threat registry. Paid the OKX-native way — over x402, gasless for the payer. <span class="badge plan">next</span> hosted SLA tier for frameworks and wallets.</p></div>
</div>

<h2>Why it defends</h2>
<div class="grid two">
  <div class="card"><h3>A shared threat registry</h3><p>Every agent's fact-based DENY protects the others. The value compounds with usage — a network effect a single-agent tool can't copy.</p></div>
  <div class="card"><h3>Deterministic &amp; auditable</h3><p>Rules with evidence, not a black-box score. A verdict cites the exact reason and the on-chain fact behind it, so operators can trust and defend it.</p></div>
  <div class="card"><h3>Wired into the payment path</h3><p>Not advice on a page — a check inside OKX's own CLI flow and a hook on the pay command itself. It runs where the money moves.</p></div>
  <div class="card"><h3>A public data moat</h3><p>The dated marketplace trust scan is both distribution (buyers find us) and a growing dataset of real attack shapes seen on OKX.AI.</p></div>
</div>

<h2>Go to market on OKX.AI</h2>
<div class="card"><ul>
  <li><strong>Land free, where agents already are.</strong> Ship as an Onchain OS agent skill, a Streamable-HTTP MCP server, and a Claude Code hook — all live today, one line to add.</li>
  <li><strong>Distribute through the trust scan.</strong> Publish it as a public good at <a href="/trust">/trust</a>; buyers arrive, sellers get pressure to fix their 402s.</li>
  <li><strong>Expand to premium</strong> for operators running many payments (session health, alerts), then to hosted/SLA tiers for frameworks and wallets.</li>
  <li><strong>Why now:</strong> x402 and Onchain OS just made agent-to-agent payments real on X Layer. The safety layer for them does not exist yet.</li>
</ul></div>

<p class="foot">See it work: <a href="/pay-safe">/pay-safe</a> (try a payment) · <a href="/trust">/trust</a> (live marketplace scan) · <a href="https://github.com/InkoStrategy/guardian-mcp">source</a> · MCP server at <span class="code">/mcp</span>. GuardianMCP · OKX.AI agent #13730 (identity registered; marketplace listing under review) · Team LNO Alpha.</p>
</div>
<script>
fetch('/trust-scans').then(function(r){return r.json()}).then(function(h){
  var snaps=h.snapshots||[];
  var byDate={};snaps.forEach(function(s){byDate[s.date]=s});
  var base=byDate['2026-09-16']||snaps[0];         // the scan the demo cites
  var latest=snaps.length?snaps[snaps.length-1]:base;
  if(!base)return;
  var t=base.totals||{};var chal=t.challenge||0;var flagged=(t.warn||0)+(t.deny||0);
  document.getElementById('c1').textContent=String((latest.totals||{}).services||t.services||'—');
  document.getElementById('c2').textContent=chal?Math.round(flagged/chal*100)+'%':'—';
  document.getElementById('c3').textContent=String(t.deny==null?'—':t.deny);
  // wrong-signing-domain count across ALL verdicts (the DENY attack listing carried it too)
  var eip=base.eip712Count||(base.warnCodes&&base.warnCodes.eip712_domain_mismatch)||0;
  document.getElementById('c4').textContent=String(eip||'—');
  document.getElementById('costnote').textContent='From the '+base.date+' scan: '+chal+' of '+ (t.services||'—') +' paid services returned a challenge; '+flagged+' of those '+chal+' ('+(chal?Math.round(flagged/chal*100):0)+'%) drew a WARN or DENY, including '+(t.deny||0)+' outright attack listing. Re-scanned '+(latest?latest.date:base.date)+'.';
}).catch(function(){});
</script></body></html>`;
}

module.exports = { html };
