#!/usr/bin/env node
'use strict';

/**
 * Claude Code PreToolUse hook: GuardianMCP policy for Onchain OS payment commands.
 *
 * Reads the hook event from stdin. For Bash and PowerShell tool calls that run onchainos, prints a
 * permissionDecision of "deny" or "ask" with the reason; prints nothing otherwise, so normal permission
 * rules apply. If the policy itself fails on an onchainos command, it denies (fail closed).
 * See hooks/README.md for installation.
 */

const { evaluateCommand } = require('../src/guard-policy');

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

readStdin().then((raw) => {
  let event;
  try { event = JSON.parse(raw); } catch { return; }
  if (!event || !['Bash', 'PowerShell'].includes(event.tool_name)) return;
  const command = event.tool_input && typeof event.tool_input.command === 'string' ? event.tool_input.command : '';
  if (!/onchainos/i.test(command)) return;
  try {
    const r = evaluateCommand(command);
    if (r) emit(r.decision, r.reason);
  } catch (err) {
    emit('deny', 'GuardianMCP: the payment policy failed (' + String(err && err.message).slice(0, 200) + '), so this onchainos command is blocked.');
  }
});
