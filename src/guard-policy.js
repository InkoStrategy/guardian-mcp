'use strict';

/**
 * Policy for agent shell commands that drive the Onchain OS CLI. Used by hooks/claude-code-pretooluse.js.
 *
 * It only ever makes things stricter: the result is 'deny', 'ask' or null (no opinion, normal permissions apply).
 *
 * - URLs with shell syntax anywhere in an onchainos command: deny (endpoint_url_injection).
 * - agent a2mcp-probe --routing-base64: endpoint URLs in the routing payload with shell syntax: deny.
 * - payment pay --payment-id: deny unless a Guardian verdict is bound to that paymentId, selected index and
 *   the fingerprint of the persisted entry (see src/quote-binding.js). DENY → deny, WARN → ask,
 *   ALLOW with --yes → ask (the owner approves moving funds) unless GUARDIAN_ALLOW_AUTOPAY=1.
 * - payment pay --payload (sign-only) and pay-local: deny, nothing binds what they sign.
 * - charge, session, subscription, a2a-pay payments: ask, Guardian does not check them yet.
 *
 * Limits: an agent that deliberately forges ~/.guardian/payments files or the payment state can get past it.
 * It targets confused or prompt-injected agents, not a sandbox escape.
 */

const binding = require('./quote-binding');
const { _internals: { urlShellSyntax, textShellSyntax } } = require('./paysafe');

const ONCHAINOS_RE = /(?:^|[\\/])onchainos(?:\.exe)?$/i;
const BOOLEAN_FLAGS = new Set(['--yes', '--force', '-h', '--help', '--json', '--dry-run']);
const ESCAPABLE = new Set([' ', '\t', '"', "'", '\\', '$', ';', '&', '|', '<', '>', '(', ')', '`', '\n']);

/** Minimal shell lexer: segments split on unquoted ; & | && || and newlines, tokens on unquoted whitespace. */
function lex(command) {
  const segments = [];
  let tokens = [];
  let raw = '';
  let value = '';
  let quote = null;
  let depth = 0;
  const pushToken = () => {
    if (raw) tokens.push({ raw, value });
    raw = '';
    value = '';
  };
  const pushSegment = () => {
    pushToken();
    if (tokens.length) segments.push(tokens);
    tokens = [];
  };
  const s = String(command || '');
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote === "'") {
      raw += c;
      if (c === "'") quote = null; else value += c;
      continue;
    }
    if (c === '$' && s[i + 1] === '(') {
      depth++;
      raw += '$(';
      value += '$(';
      i++;
      continue;
    }
    if (depth > 0) {
      raw += c;
      value += c;
      if (c === '(') depth++;
      else if (c === ')') depth--;
      continue;
    }
    if (quote === '"') {
      raw += c;
      if (c === '"') quote = null;
      else if (c === '\\' && ['"', '\\', '$', '`'].includes(s[i + 1])) { raw += s[i + 1]; value += s[i + 1]; i++; } else value += c;
      continue;
    }
    if (c === '\\' && ESCAPABLE.has(s[i + 1])) { raw += c + s[i + 1]; value += s[i + 1]; i++; continue; }
    if (c === "'" || c === '"') { quote = c; raw += c; continue; }
    if (c === ' ' || c === '\t' || c === '\r') { pushToken(); continue; }
    if (c === '\n' || c === ';' || c === '&' || c === '|') {
      pushSegment();
      if ((c === '&' || c === '|') && s[i + 1] === c) i++;
      continue;
    }
    raw += c;
    value += c;
  }
  pushSegment();
  return segments;
}

function parseArgs(tokens) {
  const positionals = [];
  const flags = {};
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i].value;
    if (t.startsWith('-') && t.length > 1) {
      const eq = t.indexOf('=');
      const name = eq > 0 ? t.slice(0, eq) : t;
      if (eq > 0) flags[name] = t.slice(eq + 1);
      else if (BOOLEAN_FLAGS.has(name)) flags[name] = true;
      else if (i + 1 < tokens.length) { flags[name] = tokens[i + 1].value; i++; } else flags[name] = true;
    } else positionals.push(t);
  }
  return { positionals, flags };
}

function onchainosInvocations(command) {
  const out = [];
  for (const seg of lex(command)) {
    const at = seg.findIndex((t) => ONCHAINOS_RE.test(t.value));
    if (at >= 0) out.push(parseArgs(seg.slice(at + 1)));
  }
  return out;
}

function decodeRouting(b64) {
  try {
    const text = Buffer.from(String(b64).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function walkStrings(o, visit, keyPath) {
  if (typeof o === 'string') visit(o, keyPath || '');
  else if (Array.isArray(o)) o.forEach((v, i) => walkStrings(v, visit, (keyPath || '') + '[' + i + ']'));
  else if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) walkStrings(v, visit, keyPath ? keyPath + '.' + k : k);
}

const deny = (rule, reason) => ({ decision: 'deny', rule, reason: 'GuardianMCP: ' + reason });
const ask = (rule, reason) => ({ decision: 'ask', rule, reason: 'GuardianMCP: ' + reason });

function checkPay(inv, opts) {
  const f = inv.flags;
  if (f['--payload'] !== undefined) return deny('pay_sign_only', 'payment pay --payload signs a raw challenge that no Guardian check is bound to. Use onchainos payment quote, then node scripts/check-quote.js --payment-id <id>, then payment pay --payment-id.');
  const id = f['--payment-id'];
  if (id === undefined) return null;
  if (!binding.isPaymentId(id)) return deny('pay_invalid_id', 'payment pay has an invalid --payment-id.');
  const state = opts.readState(id);
  if (!state) return deny('pay_no_state', 'no persisted quote found for ' + id + '. Quote it with onchainos payment quote and check it first.');
  let nq;
  try { nq = binding.normalizeQuote(state); } catch (err) { return deny('pay_bad_state', 'the persisted quote ' + id + ' could not be read (' + err.message + ').'); }
  if (!nq.rawAccepts) return deny('pay_bad_state', 'the persisted quote ' + id + ' has no signed entries to check.');
  let index = binding.cliDefaultIndex(nq.rawAccepts);
  if (f['--selected-index'] !== undefined) {
    index = Number(f['--selected-index']);
    if (!Number.isInteger(index) || index < 0 || index >= nq.rawAccepts.length) return deny('pay_bad_index', '--selected-index ' + String(f['--selected-index']).slice(0, 12) + ' does not point at an entry of ' + id + '.');
  }
  const ledger = opts.readLedger(id);
  const checkCmd = 'node scripts/check-quote.js --payment-id ' + id + ' --selected-index ' + index + ' --sid <listing sid>';
  if (!ledger) return deny('pay_unchecked', 'no Guardian verdict is bound to ' + id + '. Run: ' + checkCmd);
  if (Number(ledger.selectedIndex) !== index) return deny('pay_index_changed', 'Guardian checked accepts[' + ledger.selectedIndex + '] of ' + id + ', but this command pays accepts[' + index + ']. Run: ' + checkCmd);
  const fp = binding.fingerprint(nq, index);
  if (!fp || fp !== ledger.fingerprint) return deny('pay_state_changed', 'the persisted quote ' + id + ' no longer matches what Guardian checked. Quote again and check the new paymentId.');
  const summary = String(ledger.summary || '').slice(0, 400);
  if (ledger.verdict === 'DENY') return deny('pay_denied', 'DENY ' + (ledger.reasons || []).join(', ') + '. ' + summary);
  if (ledger.verdict === 'WARN') return ask('pay_warn', 'WARN ' + (ledger.reasons || []).join(', ') + '. ' + summary + ' Pay only if the wallet owner accepts these findings.');
  if (ledger.verdict !== 'ALLOW') return deny('pay_unchecked', 'the Guardian record for ' + id + ' has no verdict. Run: ' + checkCmd);
  if ((f['--yes'] || f['--force']) && !opts.allowAutopay) return ask('pay_approve', 'ALLOW. ' + summary + ' This moves funds; approve only if you asked for this payment.');
  return null;
}

/**
 * @param {string} command shell command the agent wants to run
 * @param {object} [opts] { env, readState(id), readLedger(id), allowAutopay }
 * @returns {{decision: 'deny'|'ask', rule: string, reason: string} | null}
 */
function evaluateCommand(command, opts) {
  opts = Object.assign({}, opts);
  const env = opts.env || process.env;
  opts.readState = opts.readState || ((id) => binding.readPaymentState(id, env));
  opts.readLedger = opts.readLedger || ((id) => binding.readLedger(id, env));
  if (opts.allowAutopay === undefined) opts.allowAutopay = env.GUARDIAN_ALLOW_AUTOPAY === '1';

  const invocations = onchainosInvocations(command);
  if (!invocations.length) return null;

  const urls = String(command).match(/https?:\/\/[^\s'"]+/gi) || [];
  for (const u of urls) {
    const hit = urlShellSyntax(u);
    if (hit) return deny('endpoint_url_injection', 'a URL in this onchainos command carries ' + hit.what + ' (' + JSON.stringify(hit.at) + '). A listing that puts shell syntax in its endpoint is an attack; do not call or pay it.');
  }

  let result = null;
  const stricter = (r) => {
    if (r && (!result || (r.decision === 'deny' && result.decision !== 'deny'))) result = r;
  };
  for (const inv of invocations) {
    const [group, sub, action] = inv.positionals;
    if (group === 'agent' && sub === 'a2mcp-probe') {
      const b64 = inv.flags['--routing-base64'];
      if (b64 === undefined) continue;
      const routing = decodeRouting(b64);
      if (!routing) { stricter(ask('routing_unreadable', 'the --routing-base64 payload could not be decoded, so its endpoint was not checked.')); continue; }
      let hit = null;
      walkStrings(routing, (v, k) => {
        if (hit) return;
        if (/^https?:\/\//i.test(v.trim()) || /url|endpoint/i.test(k)) {
          const h = urlShellSyntax(v);
          if (h) hit = deny('endpoint_url_injection', 'the routing payload field ' + k + ' carries ' + h.what + ' (' + JSON.stringify(h.at) + '). Do not probe or pay this service.');
        } else if (textShellSyntax(v)) {
          hit = ask('routing_text_injection', 'the routing payload field ' + k + ' looks like a shell payload. Treat this service as hostile unless the owner confirms.');
        }
      });
      stricter(hit);
    } else if (group === 'payment' && sub === 'pay-local') {
      stricter(deny('pay_local', 'payment pay-local signs with a raw private key from the environment; Guardian cannot bind a verdict to it.'));
    } else if (group === 'payment' && sub === 'pay') {
      stricter(checkPay(inv, opts));
    } else if (group === 'payment' && (sub === 'charge' || (sub === 'session' && ['open', 'voucher', 'topup'].includes(action)) || (sub === 'subscription' && ['subscribe', 'change'].includes(action)) || (sub === 'a2a-pay' && action === 'pay'))) {
      stricter(ask('payment_unchecked_type', 'onchainos payment ' + sub + (action ? ' ' + action : '') + ' moves funds and Guardian does not check this payment type yet.'));
    }
  }
  return result;
}

module.exports = { evaluateCommand, lex, onchainosInvocations };
