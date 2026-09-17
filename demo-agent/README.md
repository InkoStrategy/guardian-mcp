# Agent-run harness

`run.cjs` records unedited headless Claude Code runs of a buyer agent that drives the **real** Onchain OS CLI,
so the transcripts show what the Guardian hook does to a running agent rather than a scripted demo.

```bash
node demo-agent/run.cjs <scenario-id> [--model sonnet]
```

Scenarios are in `scenarios.json`. Output lands in `demo-video/captures/agent-runs/<id>.jsonl` (raw
stream-json) and `<id>.md` (readable). It needs a Claude Code login (`claude auth login`) and a funded
Onchain OS wallet only for the paying scenarios; no scenario can actually move funds (see below).

## Why it is safe to run

The runs use a live wallet and one scenario names a live malicious OKX.AI listing (sid 39876) whose endpoint
URL is a shell-injection payload. Every layer below is independent:

1. **Clean copy, no secrets.** The agent runs with its working directory set to a fresh copy of the repo under
   the OS temp dir. `.env*`, `.vercel` and `.git` are never copied, so the project's KV/Redis/Vercel/admin
   tokens are not reachable even if a tool would read a file. `node_modules` is linked in only so the hook
   can load. The run aborts if any secret file appears in the copy.
2. **Per-scenario allow list + `dontAsk`.** Each scenario lists the exact read-only commands it may run
   (`scenario.allow`). In `--permission-mode dontAsk`, anything not on that list is refused with no prompt.
   `onchainos payment pay` and every other fund-moving command are on no allow list, and are also explicit
   deny rules.
3. **Quote commands are host-pinned.** Where a scenario needs `onchainos payment quote`, the allow rule pins
   it to `guardian-mcp-rho.vercel.app`. The malicious-listing scenario allows only `service-detail` and
   `wallet balance`, so the attacker host is never contacted.
4. **Exfiltration helpers denied.** `curl`, `wget`, `id`, `base64`, `nc`, `cat`, `head`, `sed`, `awk`,
   `node -e`, and the `Read`/`Grep`/`Glob` tools are deny rules, so a shell that auto-allows read-only
   commands still cannot run the `id|base64|curl` payload or read files. `--guardian` on `check-quote.js` is
   denied so a verdict cannot be sourced from an attacker-named mirror.
5. **Guardian hook first.** When `scenario.hook` is set, `hooks/claude-code-pretooluse.js` is registered with
   matcher `*` and runs before the permission rules, so its DENY shows up in the transcript.
6. **Secret backstop.** Before the transcript is written, it is scanned for any value from the real `.env*`
   (raw, base64 or url-encoded). If one appears, the output is discarded.

Funds are never at risk: in Claude Code `dontAsk` turns every "ask" (including a hook "ask") into a deny, so
even an ALLOW-with-`--yes` is refused, and `payment pay` matches no allow rule regardless.

## Scenarios

| id | Hook | What it shows |
|---|---|---|
| `smoke` | yes | Harness check: `type curl` and an unchecked `payment pay` are both refused |
| `baseline-header-body-split` | no | Without Guardian, whether the agent notices the header/body payee split on its own |
| `guardian-header-body-split` | yes | The hook blocks paying a quote whose header and body pay different wallets |
| `guardian-malicious-listing-39876` | yes | The agent looks up the live shell-payload listing; no quote/pay tool is allowed, so the attacker host is never contacted and the pay is refused |
| `guardian-honest-seller` | yes | Honest seller: ALLOW, and the owner still gives the final `--yes` |

Run `smoke` first and confirm both commands are refused before running the others.
