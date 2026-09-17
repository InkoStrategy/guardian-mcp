#!/usr/bin/env node
'use strict';

/**
 * Claude Code PreToolUse hook: GuardianMCP policy for Onchain OS payment commands.
 *
 * Reads the hook event from stdin. For any tool call that runs a shell command touching onchainos
 * (Bash, PowerShell, and command-running tools such as Monitor), prints a permissionDecision of "deny"
 * or "ask" with the reason; prints nothing otherwise, so normal permission rules apply. If the policy
 * itself fails on an onchainos command — including a missing dependency because the repo was checked out
 * without `npm install` — it denies (fail closed). See hooks/README.md for installation.
 */

function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (d) => { data += d; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', () => resolve(data));
  });
}

function emit(decision, reason) {
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: decision, permissionDecisionReason: reason } }));
}

/** Any string field of tool_input that could carry a shell command (command, script, code, cmd…). */
function commandOf(input) {
  if (!input || typeof input !== 'object') return '';
  const parts = [];
  for (const k of ['command', 'cmd', 'script', 'code', 'shellCommand', 'run']) {
    if (typeof input[k] === 'string') parts.push(input[k]);
  }
  return parts.join('\n');
}

readStdin().then((raw) => {
  let event;
  try { event = JSON.parse(raw); } catch { return; }
  if (!event || typeof event !== 'object') return;
  const command = commandOf(event.tool_input);
  // Match by command content, not tool name: covers Bash, PowerShell and any command-running tool (Monitor).
  if (!command || !/onchainos/i.test(command)) return;
  try {
    // Required inside try: if the repo has no node_modules yet, requiring guard-policy (via paysafe → ethers)
    // throws, and this must become a deny, not a silent pass that lets the payment through.
    const { evaluateCommand } = require('../src/guard-policy');
    const r = evaluateCommand(command);
    if (r) emit(r.decision, r.reason);
  } catch (err) {
    emit('deny', 'GuardianMCP: the payment policy could not run (' + String(err && err.message).slice(0, 200) + '); run `npm install` in the guardian-mcp repo. This onchainos command is blocked.');
  }
});
