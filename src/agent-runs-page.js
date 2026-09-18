'use strict';

/**
 * GET /agent-runs: unedited headless-agent transcripts, rendered from docs/agent-runs.json (bundle-safe;
 * the full .md/.jsonl transcripts live in the repo). All content is our own, but rendered via textContent.
 */
function html() {
  let data;
  try { data = require('../docs/agent-runs.json'); } catch { data = { runs: [], repoBase: '', note: '' }; }
  const j = JSON.stringify(data).replace(/</g, '\\u003c');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Guardian — agent runs</title>
<meta name="description" content="Unedited headless AI-agent runs on the real Onchain OS CLI: the Guardian hook blocks a scam payment in real time, lets a good one through, and the agent refuses a shell-injection listing.">
<style>
:root{--bg:#0b0d10;--card:#13171c;--line:#232a33;--txt:#e6e9ee;--muted:#8d96a3;--ok:#3ecf8e;--warn:#f5b849;--deny:#f0574f;--acc:#6aa9ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:28px;margin:0 0 6px}.lead{color:var(--muted);max-width:760px;margin:0 0 8px}
.run{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:16px 0}
.run.DENY{border-left:3px solid var(--deny)}.run.ALLOW{border-left:3px solid var(--ok)}.run.REFUSED{border-left:3px solid var(--warn)}
.run h2{font-size:18px;margin:0 0 4px}
.badge{font-weight:700;font-size:12px;padding:2px 9px;border-radius:6px;border:1px solid currentColor;margin-right:8px}
.DENY .badge,.b-DENY{color:var(--deny)}.ALLOW .badge,.b-ALLOW{color:var(--ok)}.REFUSED .badge,.b-REFUSED{color:var(--warn)}
.story{color:var(--muted);font-size:14px;margin:2px 0 10px}
.step{border-top:1px solid var(--line);padding:9px 0}
.cmd{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;color:var(--acc);overflow-wrap:anywhere}
.cmd::before{content:"$ ";color:var(--muted)}
.out{font-size:14px;color:var(--txt);margin-top:3px;overflow-wrap:anywhere}
.concl{margin-top:10px;font-size:14px}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.foot{color:var(--muted);font-size:13px;margin-top:32px}
.tag{color:var(--muted);font-size:12px}
</style></head><body><div class="wrap">
<h1>Unedited agent runs</h1>
<p class="lead" id="note"></p>
<video controls preload="metadata" src="/demo-v61.webm" style="width:100%;border:1px solid var(--line);border-radius:12px;background:#000;margin:6px 0 18px"><track kind="subtitles" srclang="en" label="English" src="/demo-v61.en.vtt" default></video>
<p class="lead" style="margin-top:-10px">The full 3:56 demo (opens on the live agent's pay being blocked). The three runs below are the raw transcripts behind it.</p>
<div id="runs"></div>
<p class="foot">These are the raw runs behind scene S9B of the <a href="/pay-safe">demo</a>. Full transcripts (.md + stream-json .jsonl) are in the repo. See also the live <a href="/trust">marketplace scan</a> and the <a href="/company">company case</a>.</p>
</div>
<script>
var DATA=${j};
var $=function(id){return document.getElementById(id)};
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
$('note').textContent=DATA.note||'';
var box=$('runs');
(DATA.runs||[]).forEach(function(r){
  var d=el('div','run '+(r.verdict||''));
  var h=el('h2');h.appendChild(el('span','badge',r.verdict||''));h.appendChild(document.createTextNode(r.title||r.id));d.appendChild(h);
  if(r.story)d.appendChild(el('div','story',r.story));
  (r.steps||[]).forEach(function(s){
    var st=el('div','step');st.appendChild(el('div','cmd',s.cmd));st.appendChild(el('div','out',s.out));d.appendChild(st);
  });
  if(r.conclusion){var c=el('div','concl');c.appendChild(el('strong',null,'Outcome: '));c.appendChild(document.createTextNode(r.conclusion));d.appendChild(c);}
  if(DATA.repoBase){var a=el('a',null,'full transcript \\u2192');a.href=DATA.repoBase+r.id+'.md';var p=el('div','tag');p.style.marginTop='8px';p.appendChild(a);d.appendChild(p);}
  box.appendChild(d);
});
</script></body></html>`;
}

module.exports = { html };
