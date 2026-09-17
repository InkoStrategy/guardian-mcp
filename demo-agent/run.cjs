#!/usr/bin/env node
'use strict';

/**
 * Records unedited headless Claude Code runs of a buyer agent that uses the real Onchain OS CLI.
 *
 *   node demo-agent/run.cjs <scenario-id> [--model sonnet]
 *
 * Safety, layered (see demo-agent/README.md):
 * - Runs from a CLEAN COPY of the repo under the OS temp dir with no .env*, .vercel or .git, so the agent
 *   cannot read the project's secrets even if a tool would let it. node_modules is linked in for the hook.
 * - Per-scenario allow list (scenario.allow) plus permission mode dontAsk: only those exact read commands
 *   run; everything else, including payment pay and all fund-moving commands, is refused without a prompt.
 * - Deny rules for curl/wget/id/base64/nc/cat/head/sed/awk/node -e and Read/Grep/Glob, and --guardian on
 *   check-quote, so exfiltration helpers and file reads are blocked even when a shell auto-allows them.
 * - The malicious-listing run allows only service-detail and wallet balance, so the attacker host is never
 *   contacted. The Guardian hook (when scenario.hook) runs before the permission rules.
 * - Backstop: the transcript is scanned for any value from the real .env* before it is written; if one
 *   appears (raw, base64 or url-encoded) the run's output is discarded.
 *
 * Output: demo-video/captures/agent-runs/<id>.jsonl (stream-json) and <id>.md (readable), in the real repo.
 */

const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(ROOT, 'demo-video', 'captures', 'agent-runs');
const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, 'scenarios.json'), 'utf8'));

const argv = process.argv.slice(2);
const id = argv.find((a) => !a.startsWith('--'));
const opt = (k, d) => { const i = argv.indexOf('--' + k); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : d; };
const scenario = cfg.scenarios.find((s) => s.id === id);
if (!scenario) {
  console.error('usage: node demo-agent/run.cjs <' + cfg.scenarios.map((s) => s.id).join('|') + '> [--model sonnet]');
  process.exit(1);
}

// ---- clean copy of the repo, without secrets ----
const WORK = path.join(os.tmpdir(), 'guardian-demo-' + scenario.id + '-' + process.pid);
const COPY_DIRS = ['src', 'scripts', 'hooks', 'docs', 'api', 'skills'];
const COPY_FILES = ['package.json', 'package-lock.json'];
fs.rmSync(WORK, { recursive: true, force: true });
fs.mkdirSync(WORK, { recursive: true });
for (const d of COPY_DIRS) { if (fs.existsSync(path.join(ROOT, d))) fs.cpSync(path.join(ROOT, d, ''), path.join(WORK, d), { recursive: true }); }
for (const f of COPY_FILES) { if (fs.existsSync(path.join(ROOT, f))) fs.copyFileSync(path.join(ROOT, f), path.join(WORK, f)); }
// Link node_modules so the hook (guard-policy -> paysafe -> ethers) loads; never copy .env*, .vercel, .git.
try {
  const target = path.join(ROOT, 'node_modules');
  if (process.platform === 'win32') spawnSync('cmd', ['/c', 'mklink', '/J', path.join(WORK, 'node_modules'), target], { windowsHide: true });
  else fs.symlinkSync(target, path.join(WORK, 'node_modules'), 'dir');
} catch { /* the hook will fail closed if node_modules is missing */ }
for (const leak of ['.env', '.env.local', '.vercel', '.git']) {
  if (fs.existsSync(path.join(WORK, leak))) { console.error('refusing to run: secret ' + leak + ' leaked into the work copy'); process.exit(1); }
}

const HOME = os.homedir();
const hookCommand = 'node ' + path.join(WORK, 'hooks', 'claude-code-pretooluse.js').split(path.sep).join('/');
const allow = Array.isArray(scenario.allow) ? scenario.allow : [];
const settings = {
  permissions: { allow, deny: cfg.denyRules },
  hooks: scenario.hook ? { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: hookCommand }] }] } : {},
};
fs.mkdirSync(OUT, { recursive: true });
const ledgerDir = path.join(WORK, '.guardian', 'payments');

const args = [
  '-p', scenario.prompt,
  '--output-format', 'stream-json',
  '--verbose',
  '--model', opt('model', 'sonnet'),
  '--permission-mode', 'dontAsk',
  '--setting-sources', '',
  '--settings', JSON.stringify(settings),
  '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}',
  '--allowedTools', ...allow,
  '--disallowedTools', 'PowerShell', 'WebFetch', 'WebSearch', 'Edit', 'Write', 'NotebookEdit', 'Agent', 'Read', 'Grep', 'Glob',
  '--no-session-persistence',
  '--max-budget-usd', opt('budget', '3'),
];

const env = Object.assign({}, process.env, { GUARDIAN_LEDGER_DIR: ledgerDir });
delete env.GUARDIAN_ALLOW_AUTOPAY;

const scrub = (text) => String(text).split(HOME).join('~').split(HOME.split(path.sep).join('/')).join('~').split(WORK).join('~work~');
const startedAt = new Date().toISOString();
const lines = [];
const child = spawn('claude', args, { cwd: WORK, env, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
let buf = '';
child.stdout.on('data', (d) => {
  buf += d.toString('utf8');
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    let ev;
    try { ev = JSON.parse(line); } catch { continue; }
    if (ev.type === 'system' && ev.subtype === 'init') {
      ev = { type: 'system', subtype: 'init', model: ev.model, permissionMode: ev.permissionMode, claude_code_version: ev.claude_code_version, tools: ev.tools };
    }
    lines.push(ev);
    if (ev.type === 'assistant') {
      for (const b of ev.message.content || []) {
        if (b.type === 'tool_use') console.log('  tool  ' + (b.input && b.input.command ? b.input.command : JSON.stringify(b.input)).slice(0, 200));
        if (b.type === 'text') console.log('  text  ' + b.text.slice(0, 200).replace(/\n/g, ' '));
      }
    }
  }
});
let stderr = '';
child.stderr.on('data', (d) => { stderr += d.toString('utf8'); });
child.on('close', (code) => {
  const jsonl = lines.map((ev) => scrub(JSON.stringify(ev))).join('\n') + '\n';
  const md = render(scenario, lines.map((ev) => JSON.parse(scrub(JSON.stringify(ev)))), { startedAt, code, model: opt('model', 'sonnet'), hookCommand: scrub(hookCommand) });
  const leak = secretLeak(jsonl + md);
  if (leak) {
    console.error('SECRET LEAK detected (' + leak + '); discarding this run output, nothing written.');
  } else {
    fs.writeFileSync(path.join(OUT, scenario.id + '.jsonl'), jsonl);
    fs.writeFileSync(path.join(OUT, scenario.id + '.md'), md);
    console.log('exit ' + code + ', ' + lines.length + ' events -> ' + path.join(OUT, scenario.id + '.md'));
  }
  fs.rmSync(WORK, { recursive: true, force: true });
  if (stderr.trim()) console.error(scrub(stderr).slice(0, 2000));
});

/** Every value from the real .env files, so the transcript can be refused if one appears. */
function secretLeak(text) {
  const values = [];
  for (const f of ['.env', '.env.local']) {
    const p = path.join(ROOT, f);
    if (!fs.existsSync(p)) continue;
    for (const raw of fs.readFileSync(p, 'utf8').split(/\r?\n/)) {
      const m = raw.match(/^\s*[A-Za-z0-9_]+\s*=\s*(.+)$/);
      if (!m) continue;
      const v = m[1].trim().replace(/^["']|["']$/g, '');
      if (v.length >= 8) values.push(v);
    }
  }
  for (const v of values) {
    for (const form of [v, Buffer.from(v).toString('base64'), encodeURIComponent(v)]) {
      if (form.length >= 8 && text.includes(form)) return v.slice(0, 4) + '…';
    }
  }
  return null;
}

function fence(text) {
  const t = String(text);
  const ticks = t.includes('```') ? '````' : '```';
  return ticks + '\n' + t + '\n' + ticks;
}

function resultText(block) {
  const c = block.content;
  if (typeof c === 'string') return c;
  if (Array.isArray(c)) return c.map((x) => (x.type === 'text' ? x.text : '[' + x.type + ']')).join('\n');
  return JSON.stringify(c);
}

function render(s, events, meta) {
  const md = [];
  md.push('# Agent run: ' + s.id, '');
  md.push(s.title, '');
  md.push('- Recorded: ' + meta.startedAt + ' with `claude -p` (Claude Code headless), model `' + meta.model + '`, permission mode `dontAsk`');
  md.push('- Ran from a clean copy of the repo under the temp dir, with no `.env*`, `.vercel` or `.git`');
  md.push('- Guardian hook: ' + (s.hook ? '`' + meta.hookCommand + '` (matcher `*`, runs before the permission rules)' : 'not installed'));
  md.push('- Allowed commands: ' + (s.allow || []).map((t) => '`' + t + '`').join(', '));
  md.push('- Denied: `payment pay` and every fund-moving command, `curl`/`wget`/`id`/`base64`/`nc`, file-read commands, `Read`/`Grep`/`Glob`, and `--guardian` on check-quote');
  md.push('- Unedited: every tool call and result below is rendered from `' + s.id + '.jsonl` in order; long results are cut at 2000 characters.', '');
  md.push('## Prompt', '', fence(s.prompt), '', '## Transcript', '');
  const pending = new Map();
  let n = 0;
  for (const ev of events) {
    if (ev.type === 'assistant') {
      for (const b of ev.message.content || []) {
        if (b.type === 'text' && b.text.trim()) md.push('**Agent:** ' + b.text.trim(), '');
        if (b.type === 'tool_use') {
          n += 1;
          pending.set(b.id, n);
          md.push('**Tool call ' + n + ' (' + b.name + '):**', '', fence(b.input && b.input.command ? '$ ' + b.input.command : JSON.stringify(b.input, null, 2)), '');
        }
      }
    } else if (ev.type === 'user' && ev.message && Array.isArray(ev.message.content)) {
      for (const b of ev.message.content) {
        if (b.type !== 'tool_result') continue;
        const text = resultText(b);
        md.push('**Result of call ' + (pending.get(b.tool_use_id) || '?') + (b.is_error ? ' (refused or failed)' : '') + ':**', '', fence(text.length > 2000 ? text.slice(0, 2000) + '\n[cut at 2000 characters]' : text), '');
      }
    } else if (ev.type === 'result') {
      md.push('## Outcome', '');
      md.push('- Result: `' + ev.subtype + '`' + (ev.num_turns !== undefined ? ', turns: ' + ev.num_turns : '') + (ev.duration_ms !== undefined ? ', duration: ' + Math.round(ev.duration_ms / 1000) + ' s' : ''));
      if (Array.isArray(ev.permission_denials) && ev.permission_denials.length) {
        md.push('- Refused tool calls: ' + ev.permission_denials.length);
        for (const d of ev.permission_denials) md.push('  - `' + String((d.tool_input && d.tool_input.command) || JSON.stringify(d.tool_input)).slice(0, 300) + '`');
      }
      md.push('');
    }
  }
  return md.join('\n');
}
