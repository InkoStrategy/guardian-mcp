# GuardianMCP hook for Claude Code

`claude-code-pretooluse.js` is a Claude Code `PreToolUse` hook for agents that pay with the Onchain OS CLI.
It is not installed automatically, and it covers Claude Code only. Other agent runtimes can call
`evaluateCommand()` from `src/guard-policy.js` the same way.

## What it does

The hook reads each Bash or PowerShell command before it runs. If the command does not call `onchainos`, the hook
does nothing. Otherwise:

| Command | Decision |
|---|---|
| Any `onchainos` command with a URL that carries shell syntax (`$(…)`, backticks, `;`, `\|`, brace expansion) | deny |
| `onchainos agent a2mcp-probe … --routing-base64 <payload>` whose endpoint carries shell syntax | deny |
| `onchainos payment pay --payment-id <id>` with no Guardian verdict bound to that paymentId | deny |
| … bound verdict is DENY, or the selected index or the persisted entry changed after the check | deny |
| … bound verdict is WARN | ask |
| … bound verdict is ALLOW, with `--yes` or `--force` | ask (set `GUARDIAN_ALLOW_AUTOPAY=1` to skip) |
| … bound verdict is ALLOW, without `--yes` | no decision (the wallet itself returns a confirmation prompt and pays nothing) |
| `onchainos payment pay --payload` (sign-only) and `payment pay-local` | deny |
| `payment charge`, `session open/voucher/topup`, `subscription subscribe/change`, `a2a-pay pay` | ask |

The hook never returns "allow", so it cannot loosen your permission rules. If the policy fails on an
`onchainos` command, the hook denies it.

## How a verdict gets bound

`onchainos payment quote` saves every quote to `~/.onchainos/payments/<paymentId>.json`, and
`onchainos payment pay --payment-id` signs from that file without fetching the 402 again. So Guardian checks
that file:

```bash
onchainos payment quote https://seller.example/paid
node scripts/check-quote.js --payment-id pay_… --sid 39856
```

`check-quote.js` sends the saved quote to `POST /check-quote`, after dropping the owner wallet id, the deposit
address, the balance fields and the business params. (The atomic amount and required amount are the payment
itself, so the balance is still inferable from them; the drop removes the wallet's own totals, not the price.)
It writes the verdict and a SHA-256 fingerprint of the whole selected entry — payee, amount, token, network,
scheme, every `extra` field, `maxTimeoutSeconds`, the resource url, endpoint and method — plus the verdict
source and whether a listing was compared, to `~/.guardian/payments/<paymentId>.json`. At pay time the hook
recomputes the fingerprint from the quote file and denies if anything changed. `node scripts/safe-pay.js`
binds the verdict the same way. The MCP `check_quote` tool and `POST /check-quote` return the same verdict and
fingerprint, but only these local scripts write the ledger the hook reads; a bare tool call does not bind.

## Install

First install dependencies in the repo (the hook fails closed and blocks every payment until this is done):

```bash
npm ci --omit=dev
```

Then add the hook to `.claude/settings.json` in your project, or to `~/.claude/settings.json`. Match all tools
(or at least every command-running tool), so a payment started through Bash, PowerShell or another runner is
still seen:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [{ "type": "command", "command": "node /path/to/guardian-mcp/hooks/claude-code-pretooluse.js" }]
      }
    ]
  }
}
```

It needs Node 20 or newer, this repository checked out and `npm install` run. It works offline: the verdict
comes from the local ledger, not from a network call at pay time. Only a verdict from the Guardian named in
`GUARDIAN_URL` (or the default deployment), or a `--local` check, is honored; a verdict a command sourced from
some other `--guardian` URL is refused.

Environment: `ONCHAINOS_PAYMENTS_DIR` and `GUARDIAN_LEDGER_DIR` override the two directories, and
`GUARDIAN_ALLOW_AUTOPAY=1` lets an ALLOW payment with `--yes` run without asking.

## Limits

- It guards against confused or prompt-injected agents. An agent that deliberately edits the ledger or the
  quote files can get around it. For hard isolation, run the agent without write access to `~/.guardian`.
- It reads commands as text. A payment started from a script file the agent wrote, or through another
  program, is not seen.
- Guardian checks x402 `exact`, `upto` and Permit2 payments. Charge, session, subscription and A2A payments
  only get the ask prompt.
