# Guardian MCP API reference (for agents)

Base URL: `https://guardian-mcp-rho.vercel.app`. All bodies are JSON. Errors: `400` with `{ "error": "…" }`.

## POST /analyze

| Field | Type | Required | Notes |
|---|---|---|---|
| `to` | string | yes | `0x` + 40 hex; mixed case must be a valid EIP-55 checksum, lowercase always accepted |
| `data` | string | no | `0x` hex calldata; empty or `0x` = native transfer |
| `chainId` | number | no | default 1; supported 1, 10, 56, 137, 196, 250, 8453, 42161, 43114 |
| `value` | string | no | wei, decimal or `0x` hex |
| `from` | string | no | enables `eth_call` simulation, gas estimate, ERC-20 balance and allowance |
| `context` | object | no | see SKILL.md; extra keys: `intent_match` (bool), `alert_webhook` (https URL), `alert_on` (`deny`|`warn`), `reference_tx` (`{to,data?,value?,chainId?}`), `share_threat_intel` (bool) |

Response:

```json
{
  "verdict": "ALLOW | WARN | DENY",
  "reasons": ["rule_code", "…"],
  "summary": "one sentence for humans",
  "details": {
    "request_id": "uuid",
    "chainId": 1, "chain": "ethereum", "to": "0x…", "from": null, "value": "0",
    "selector": "0x095ea7b3", "function": "approve(address,uint256)", "callType": "approve",
    "decoded": { "spender": "0x…", "amount": "…" },
    "amount": "150.5 USDC",
    "token": { "symbol": "USDC", "decimals": 6, "name": "USD Coin", "source": "static-registry | onchain" },
    "counterparties": { "0x…": { "known": { "name": "Uniswap V2 Router02", "category": "dex-router" }, "isContract": true, "proxy": null, "reputation": { "tier": "trusted", "score": 95 }, "threat": null } },
    "nested_calls": { "inner": [], "recipients": [], "permits": [], "routerPlan": null },
    "simulation": { "ran": true, "ok": true, "reverted": false, "revert": null, "gasEstimate": "52000" },
    "findings": [ { "code": "…", "severity": "WARN", "message": "…" } ],
    "risk_score": 15,
    "recommendations": [ { "code": "unlimited_approval", "action": "…" } ],
    "safe_alternative": { "available": true, "kind": "bounded_approval", "to": "0x…", "data": "0x…", "amount": "150.5 USDC", "revoke": { "to": "0x…", "data": "0x…" } },
    "threat_intel": { "persistent": true, "addresses": {}, "domains": {}, "seed": { "addresses": {}, "domains": {} }, "report": { "recorded_addresses": 0, "recorded_domains": 0 } },
    "session_health": { "status": "healthy | elevated | compromised_likely", "warn_count_window": 0, "deny_count_window": 0, "cumulative_risk_window": 0 },
    "alert": null,
    "diff": null,
    "context_analyzed": true,
    "intent_analysis": { "normalized_goal": "swap", "transaction_intent": "approve", "match": true }
  }
}
```

## POST /analyze-signature

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | `eip712` (also `eth_signTypedData_v4`), `personal_sign`, `eth_sign` |
| `typedData` | object or JSON string | for eip712 | `{ types, primaryType, domain, message }` |
| `message` | string | for personal_sign / eth_sign | UTF-8 text or `0x` hex |
| `chainId` | number | no | default `domain.chainId` or 1 |
| `from` | string | no | signer address; used for SIWE and owner checks |
| `context` | object | no | same as /analyze |

Recognised: ERC-2612 `Permit` (incl. DAI style), Permit2 `PermitSingle` / `PermitBatch` / `PermitTransferFrom` / `PermitBatchTransferFrom` / `PermitWitnessTransferFrom`, Seaport `OrderComponents`, SIWE. Unknown typed data is scanned for authority fields (`spender`, `operator`, `delegate`, `recipient`, …).

## POST /check-payment (Pay-Safe)

| Field | Type | Required | Notes |
|---|---|---|---|
| `paymentRequired` | string or object | one of the two | base64 `PAYMENT-REQUIRED` header, or the `402` JSON body (x402 v1 or v2, up to 20 `accepts`) |
| `payment` | object | one of the two | flattened quote `{ network or chainId, asset, amount (atomic), payTo, scheme?, maxTimeoutSeconds?, extra? }` |
| `requestUrl` | string | recommended | the URL that returned `402` |
| `selectedIndex` | number | no | the `accepts` entry you intend to pay; default is the safest, then canonical, then cheapest |
| `paymentSignature` | string or object | no | base64 `PAYMENT-SIGNATURE` / `X-PAYMENT` to verify before replay (EIP-3009 or Permit2) |
| `expected` | object | recommended | listing terms: `feeAmount` (human units), `feeToken`, `endpoint`, `payTo`, `maxAmount` (atomic), `decimals` |
| `context` | object | no | `max_amount` (human units), `known_addresses`, `from` (payer), `session_id` |

Response:

```json
{
  "verdict": "ALLOW | WARN | DENY",
  "reasons": ["rule_code"],
  "risk_score": 0,
  "summary": "Payment of 0.002 USDT0 (2000) on xlayer to 0xE1c6…f67b for seller.example (accepts[0], exact). No risk rules triggered.",
  "recommendations": [ { "code": "…", "action": "…" } ],
  "recommended_index": 0,
  "details": {
    "x402Version": 2,
    "resource": { "url": "…", "description": "…" },
    "endpoint": { "host": "seller.example", "verdict": "ALLOW", "reasons": [] },
    "signed": null,
    "selected": { "index": 0, "verdict": "ALLOW", "scheme": "exact", "chainId": 196, "asset": { "address": "0x…", "symbol": "USDT0", "decimals": 6, "canonical": true }, "amount": { "atomic": "2000", "human": "0.002", "listed": "2000" }, "payTo": "0x…", "payToCheck": { "verdict": "ALLOW" }, "findings": [] },
    "entries": [ { "index": 0, "verdict": "ALLOW", "reasons": [] } ],
    "global_findings": [],
    "findings": [ { "code": "…", "severity": "WARN", "message": "…", "subject": "endpoint | payTo | asset" } ]
  }
}
```

## POST /check-address, POST /check-domain

`/check-address`: `{ "address": "0x…", "chainId": 196, "role": "recipient | spender | contract" }`. `/check-domain`: `{ "domain": "example.com" }` or `{ "url": "https://…" }`. Both return `{ verdict, reasons, summary, details }`.

## POST /guard (premium, 0.099 USDT per call on X Layer)

Same body as `/analyze`; add `"kind": "signature"` with the `/analyze-signature` fields for signatures. Without payment the response is `402` with a `PAYMENT-REQUIRED` header (x402 v2, `exact`); Onchain OS clients pay automatically. Response adds `details.premium: true` and `details.payment`.

## POST /feedback

`{ "request_id"?: string, "verdict": "ALLOW|WARN|DENY", "correct": boolean, "rule_codes"?: string[], "comment"?: string, "session_id"?: string }`. 60 per hour per source.

## Rule codes by severity

DENY: `zero_address`, `set_approval_for_all`, `approval_to_eoa`, `address_poisoning`, `contract_lookalike`, `permit_spender_mismatch`, `permit2_pull_to_third_party`, `known_drainer`, `known_phishing_domain`, `scam_database_address` (WARN for plain transfers), `scam_database_domain`, `session_compromised_likely`, `template_critical_deviation`, `goal_escalation`, `injection_pattern`, `untrusted_source_before_tx` (DENY only for large amounts), `eth_sign_deprecated`, `blind_hash_signing`, `seaport_zero_consideration`, `permit2_domain_mismatch`, `verifying_contract_is_eoa`, `siwe_phishing_domain`, `phishing_url_in_message`.

WARN: `unlimited_approval`, `unknown_spender`, `router_output_to_third_party`, `fresh_recipient`, `unknown_selector`, `calldata_to_eoa`, `simulation_reverted`, `simulation_unavailable`, `insufficient_balance`, `rpc_unavailable`, `flagged_address`, `session_risk_elevated`, `template_deviation`, `shared_state_unavailable`, `intent_mismatch`, `rapid_context_shift`, `memory_poisoning_signal`, `context_analysis_failed`, `signature_transfer_authorization`, `far_deadline`, `expired_deadline`, `opaque_hex_message`, `siwe_domain_mismatch`, `siwe_address_mismatch`, `authorization_text_in_message`, `unrecognized_authorization`, `authority_is_eoa`, `domain_chain_mismatch`.

Payment DENY (`/check-payment`): `amount_above_listing`, `amount_above_user_cap`, `asset_mismatch_listing`, `asset_lookalike`, `asset_not_contract`, `payto_mismatch_listing`, `payto_poisoning`, `payto_zero_address`, `payto_is_asset`, `payment_domain_mismatch`, `endpoint_url_injection`, `challenge_field_injection`, `endpoint_phishing_pattern`, `accepted_mismatch`, `signed_recipient_mismatch`, `signed_amount_mismatch`, `signed_token_mismatch`, `signed_spender_not_x402_proxy`, `signed_network_mismatch`.

Payment WARN: `endpoint_domain_suspicious`, `eip712_domain_mismatch`, `upto_cap_above_listing`, `recurring_payment`, `permit2_approval_required`, `unknown_settlement_asset`, `unknown_payment_scheme`, `payment_network_unsupported`, `testnet_payment`, `multiple_payees`, `long_payment_timeout`, `resource_host_mismatch`, `insecure_payment_endpoint`, `signed_validity_too_long`, `signed_expired`, `signed_payer_mismatch`, `signature_does_not_recover`.

Full descriptions: `GET /rules`.
