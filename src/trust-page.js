'use strict';

/**
 * GET /trust: a public dashboard of the OKX.AI marketplace Pay-Safe trust scan.
 *
 * Self-contained HTML. Every value that comes from a listing, a challenge or a scan result (service names,
 * seller names, endpoint hosts, findings) is written with textContent, never innerHTML, because that text
 * is attacker-controlled. Data is fetched from GET /trust-scan (latest full scan) and GET /trust-scans
 * (compact dated history).
 */
function html() {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Guardian Trust Scan</title>
<meta name="description" content="A dated, public trust scan of paid OKX.AI services: each one probed without paying, its x402 challenge checked against its own listing. ALLOW / WARN / DENY.">
<style>
:root{--bg:#0b0d10;--card:#13171c;--line:#232a33;--txt:#e6e9ee;--muted:#8d96a3;--ok:#3ecf8e;--warn:#f5b849;--deny:#f0574f;--acc:#6aa9ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:28px;margin:0 0 6px;letter-spacing:-.01em}h2{font-size:13px;margin:34px 0 12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.lead{color:var(--muted);margin:0 0 8px;max-width:820px}
.kpis{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}
@media (min-width:760px){.kpis{grid-template-columns:repeat(5,1fr)}}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}
.kpi .v{font-size:30px;font-weight:600}.kpi .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.v.ok{color:var(--ok)}.v.warn{color:var(--warn)}.v.deny{color:var(--deny)}
.bar{display:flex;height:14px;border-radius:8px;overflow:hidden;border:1px solid var(--line);margin:6px 0 2px}
.bar span{display:block}.bar .a{background:var(--ok)}.bar .w{background:var(--warn)}.bar .d{background:var(--deny)}.bar .n{background:#2a323c}
.legend{display:flex;flex-wrap:wrap;gap:14px;color:var(--muted);font-size:13px;margin-top:6px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:middle}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:9px 10px;border-top:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.05em;border-top:0}
.badge{font-weight:700;font-size:12px;padding:2px 9px;border-radius:6px;border:1px solid currentColor;white-space:nowrap}
.ALLOW{color:var(--ok)}.WARN{color:var(--warn)}.DENY{color:var(--deny)}
.code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;overflow-wrap:anywhere}
.reasons{color:var(--muted);font-size:13px;margin-top:3px}
.deny-card{border-left:3px solid var(--deny)}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.foot{color:var(--muted);font-size:13px;margin-top:40px}
.muted{color:var(--muted)}
.pill{background:var(--card);border:1px solid var(--line);border-radius:999px;padding:3px 10px;font-size:12px;color:var(--muted)}
.hist td .tots{color:var(--muted);font-size:12px}
</style></head><body><div class="wrap">
<h1>OKX.AI trust scan</h1>
<p class="lead">Every paid A2MCP service we can find on OKX.AI, requested once <strong>without paying</strong>. Guardian reads the x402 challenge and checks it against that service's own listing — price, token, endpoint, payee, and the token's EIP-712 domain — and against shell payloads. Verdict <span class="ALLOW">ALLOW</span> / <span class="WARN">WARN</span> / <span class="DENY">DENY</span>. Nothing is signed or paid.</p>
<div id="hero" class="card deny-card" style="display:none;margin:14px 0 4px"></div>
<div id="asof" class="muted" style="margin:8px 0 18px"></div>

<h2>Check any OKX.AI listing by sid</h2>
<form id="sidForm" class="card" style="display:flex;gap:10px;flex-wrap:wrap;align-items:end">
  <div style="flex:1;min-width:200px"><label for="sid" style="display:block;font-size:12px;color:var(--muted);margin-bottom:4px">OKX.AI service id (sid)</label><input id="sid" inputmode="numeric" placeholder="39876" style="width:100%;background:#0f1318;color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:9px 10px;font:inherit"></div>
  <button class="go" id="sidGo" style="background:var(--acc);color:#081018;border:0;border-radius:8px;padding:10px 16px;font-weight:600;cursor:pointer">Check</button>
</form>
<div id="sidResult" style="margin-top:12px"></div>

<h2>Latest scan</h2>
<div class="kpis" id="kpis"></div>
<div class="bar" id="bar" style="display:none"><span class="a"></span><span class="w"></span><span class="d"></span><span class="n"></span></div>
<div class="legend" id="legend"></div>

<h2>Flagged listings</h2>
<div id="deny"><div class="card muted">Loading…</div></div>

<div id="goneWrap" style="display:none">
<h2>Previously flagged, gone from the latest scan</h2>
<div id="gone"></div>
</div>

<h2>Scan history</h2>
<table class="hist"><thead><tr><th>Date</th><th>Services</th><th>Challenges</th><th>ALLOW</th><th>WARN</th><th>DENY</th></tr></thead><tbody id="hist"></tbody></table>

<h2>All results</h2>
<p class="muted" id="allnote"></p>
<table><thead><tr><th>Service</th><th>Seller</th><th>Endpoint host</th><th>Verdict</th></tr></thead><tbody id="rows"></tbody></table>

<p class="foot">Raw data: <a href="/trust-scan">GET /trust-scan</a> (latest, JSON) · <a href="/trust-scans">GET /trust-scans</a> (dated history) · check a single listing with the <span class="code">check_listing</span> MCP tool at <span class="code">/mcp</span>. Try a payment yourself at <a href="/pay-safe">/pay-safe</a>.</p>
</div>
<script>
var $=function(id){return document.getElementById(id)};
function el(tag,cls,text){var e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=text;return e}
function host(h){return h||'—'}

// Live check any OKX.AI listing by sid via the check_listing MCP tool (read-only, nothing paid).
function checkSid(){
  var sid=Number(($('sid').value||'').trim());
  var box=$('sidResult');box.textContent='';
  if(!Number.isInteger(sid)||sid<=0){box.appendChild(el('div','card muted','Enter a numeric sid, e.g. 39876.'));return}
  $('sidGo').disabled=true;box.appendChild(el('div','card muted','Checking sid '+sid+' …'));
  fetch('/mcp',{method:'POST',headers:{'content-type':'application/json',accept:'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'check_listing',arguments:{sid:sid}}})})
  .then(function(r){return r.json()}).then(function(j){
    $('sidGo').disabled=false;box.textContent='';
    var c=j&&j.result&&j.result.structuredContent;
    if(!c){box.appendChild(el('div','card muted','No result.'));return}
    var card=el('div','card'+(c.verdict==='DENY'?' deny-card':''));
    var top=el('div');top.style.display='flex';top.style.gap='10px';top.style.alignItems='baseline';top.style.flexWrap='wrap';
    if(!c.found){top.appendChild(el('span','pill','sid '+sid));top.appendChild(el('span','muted',c.note||'Not found in the scan.'));card.appendChild(top);box.appendChild(card);return}
    if(c.verdict)top.appendChild(el('span','badge '+c.verdict,c.verdict));
    var nm=el('strong');nm.textContent=c.service||('sid '+sid);top.appendChild(nm);
    if(c.seller)top.appendChild(el('span','muted','· seller '+c.seller));
    top.appendChild(el('span','pill','sid '+sid));
    if(c.scanDate)top.appendChild(el('span','pill',(c.current===false?'last seen ':'scanned ')+c.scanDate));
    card.appendChild(top);
    if(c.current===false&&c.note)card.appendChild(el('div','muted',c.note));
    if(c.reasons&&c.reasons.length)card.appendChild(el('div','reasons','reasons: '+c.reasons.join(', ')));
    if(c.summary)card.appendChild(el('div','muted',c.summary));
    (c.findings||[]).forEach(function(f){var d=el('div','reasons');d.textContent='• '+(f.severity||'')+' '+(f.code||'')+': '+(f.message||'');card.appendChild(d)});
    box.appendChild(card);
  }).catch(function(){$('sidGo').disabled=false;box.textContent='';box.appendChild(el('div','card muted','Request failed. Try again.'))});
}
document.getElementById('sidForm').addEventListener('submit',function(e){e.preventDefault();checkSid()});
function kpi(v,k,cls){var c=el('div','card kpi');var vv=el('div','v'+(cls?' '+cls:''),String(v));c.appendChild(vv);c.appendChild(el('div','k',k));return c}

var LATEST_DENY_SIDS={};
fetch('/trust-scans').then(function(r){return r.json()}).then(function(h){
  var snaps=(h.snapshots||[]).slice();
  // Listings flagged DENY in some snapshot but not in the latest one: removed or changed since.
  var latest=snaps.length?snaps[snaps.length-1]:null;
  var latestSids={};if(latest)(latest.deny||[]).forEach(function(d){latestSids[d.sid]=1});
  var goneBySid={};
  snaps.forEach(function(s){(s.deny||[]).forEach(function(d){if(!latestSids[d.sid])goneBySid[d.sid]={d:d,date:s.date}})});
  var gone=Object.keys(goneBySid).map(function(k){return goneBySid[k]});
  // All-time count of malicious listings caught (any DENY in any snapshot), for the hero line.
  var caughtSids={};snaps.forEach(function(s){(s.deny||[]).forEach(function(d){caughtSids[d.sid]=d})});
  var caught=Object.keys(caughtSids);
  var hero=$('hero');
  if(caught.length){
    hero.style.display='';
    var first=caughtSids[caught[0]];
    var strong=el('div');strong.style.fontSize='17px';strong.style.marginBottom='4px';
    strong.appendChild(el('span','badge DENY','CAUGHT'));
    strong.appendChild(document.createTextNode(' '+caught.length+' malicious OKX.AI listing'+(caught.length>1?'s':'')+' flagged across our scans.'));
    hero.appendChild(strong);
    var sub=el('div','muted');
    sub.textContent=(first.service||('sid '+first.sid))+' (sid '+first.sid+', seller '+(first.seller||'?')+') hid a shell payload on '+(first.endpointHost||'its endpoint')+' — DENY '+(first.reasons||[]).slice(0,2).join(', ')+'. It has since left the marketplace; the verdict below is re-derived live from the saved challenge.';
    hero.appendChild(sub);
    // Show the caught attack immediately: pre-fill and run the live check for the first caught sid.
    var si=$('sid');if(si){si.value=caught[0];try{checkSid()}catch(e){}}
  }
  if(gone.length){
    $('goneWrap').style.display='';
    var g=$('gone');
    gone.forEach(function(x){
      var c=el('div','card deny-card');var top=el('div');top.style.display='flex';top.style.gap='10px';top.style.alignItems='baseline';top.style.flexWrap='wrap';
      top.appendChild(el('span','badge DENY','DENY '+x.date));
      var nm=el('strong');nm.textContent=x.d.service||('sid '+x.d.sid);top.appendChild(nm);
      if(x.d.seller)top.appendChild(el('span','muted','· seller '+x.d.seller));
      top.appendChild(el('span','pill','sid '+x.d.sid));
      c.appendChild(top);
      if(x.d.endpointHost)c.appendChild(el('div','code','endpoint host: '+x.d.endpointHost));
      c.appendChild(el('div','reasons',(x.d.reasons||[]).join(', ')));
      c.appendChild(el('div','muted','Not in the latest scan. Still checkable by sid via the check_listing tool.'));
      g.appendChild(c);
    });
  }
  var tb=$('hist');
  snaps.slice().reverse().forEach(function(s){
    var tr=el('tr');var t=s.totals||{};
    tr.appendChild(el('td',null,s.date));
    tr.appendChild(el('td',null,String(t.services==null?'—':t.services)));
    tr.appendChild(el('td',null,String(t.challenge==null?'—':t.challenge)));
    tr.appendChild(el('td',null,String(t.allow==null?'—':t.allow)));
    tr.appendChild(el('td',null,String(t.warn==null?'—':t.warn)));
    var d=el('td');var b=el('span','badge DENY',String(t.deny==null?'—':t.deny));if((t.deny||0)>0)d.appendChild(b);else d.textContent=String(t.deny==null?'—':t.deny);
    tr.appendChild(d);
    tb.appendChild(tr);
  });
  if(!snaps.length)tb.appendChild(el('tr').appendChild(el('td','muted','No snapshots yet.'))&&tb.lastChild);
}).catch(function(){});

fetch('/trust-scan').then(function(r){return r.json()}).then(function(s){
  var t=s.totals||{};
  var when=s.generatedAt?new Date(s.generatedAt):null;
  $('asof').textContent='Latest run '+(when?when.toISOString().slice(0,10)+' ('+when.toISOString().slice(11,16)+' UTC)':'—')+' · '+(s.source||'OKX.AI paid services');
  var k=$('kpis');
  k.appendChild(kpi(t.services==null?'—':t.services,'services scanned'));
  k.appendChild(kpi(t.challenge==null?'—':t.challenge,'returned a challenge'));
  k.appendChild(kpi(t.allow==null?'—':t.allow,'ALLOW','ok'));
  k.appendChild(kpi(t.warn==null?'—':t.warn,'WARN','warn'));
  k.appendChild(kpi(t.deny==null?'—':t.deny,'DENY','deny'));
  var tot=(t.allow||0)+(t.warn||0)+(t.deny||0)+((t.challenge||0)-(t.allow||0)-(t.warn||0)-(t.deny||0));
  var chal=t.challenge||0;
  if(chal>0){
    var bar=$('bar');bar.style.display='flex';
    bar.querySelector('.a').style.flex=(t.allow||0);
    bar.querySelector('.w').style.flex=(t.warn||0);
    bar.querySelector('.d').style.flex=(t.deny||0);
    bar.querySelector('.n').style.flex=Math.max(0,chal-(t.allow||0)-(t.warn||0)-(t.deny||0));
    var lg=$('legend');
    [['--ok','ALLOW '+(t.allow||0)],['--warn','WARN '+(t.warn||0)],['--deny','DENY '+(t.deny||0)]].forEach(function(p){
      var s2=el('span');var d=el('span','dot');d.style.background='var('+p[0]+')';s2.appendChild(d);s2.appendChild(document.createTextNode(p[1]));lg.appendChild(s2);
    });
    lg.appendChild(el('span',null,(t.no_challenge||0)+' returned no challenge to an unpaid request · '+(t.unreachable||0)+' unreachable'));
  }
  var results=(s.results||[]);
  var denies=results.filter(function(r){return r.verdict==='DENY'});
  var dv=$('deny');dv.textContent='';
  if(!denies.length){dv.appendChild(el('div','card muted','No DENY in the latest scan.'));}
  denies.forEach(function(r){
    var c=el('div','card deny-card');
    var top=el('div');top.style.display='flex';top.style.gap='10px';top.style.alignItems='baseline';top.style.flexWrap='wrap';
    top.appendChild(el('span','badge DENY','DENY'));
    var name=el('strong');name.textContent=r.service||('sid '+r.sid);top.appendChild(name);
    if(r.asp)top.appendChild(el('span','muted','· seller '+r.asp));
    top.appendChild(el('span','pill','sid '+r.sid));
    c.appendChild(top);
    if(r.endpoint)c.appendChild(el('div','code','endpoint host: '+host(hostOf(r.endpoint))));
    c.appendChild(el('div','reasons',(r.reasons||[]).join(', ')));
    if(r.summary)c.appendChild(el('div','muted',r.summary));
    dv.appendChild(c);
  });
  var rows=$('rows');
  results.slice().sort(function(a,b){return sev(b.verdict)-sev(a.verdict)}).forEach(function(r){
    if(!r.verdict)return;
    var tr=el('tr');
    tr.appendChild(el('td',null,r.service||('sid '+r.sid)));
    tr.appendChild(el('td','muted',r.asp||'—'));
    tr.appendChild(el('td','code',host(hostOf(r.endpoint))));
    var vd=el('td');vd.appendChild(el('span','badge '+r.verdict,r.verdict));tr.appendChild(vd);
    rows.appendChild(tr);
  });
  $('allnote').textContent=results.filter(function(r){return r.verdict}).length+' services returned a challenge and were checked. '+(t.no_challenge||0)+' returned none to an unpaid request without business parameters.';
}).catch(function(e){$('deny').textContent='Could not load the scan.'});

function sev(v){return v==='DENY'?3:v==='WARN'?2:v==='ALLOW'?1:0}
function hostOf(u){if(typeof u!=='string')return null;try{return new URL(u.indexOf('://')>=0?u:'https://'+u).host}catch(e){return u.slice(0,60)}}
</script></body></html>`;
}

module.exports = { html };
