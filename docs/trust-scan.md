# OKX.AI Pay-Safe trust scan

Generated 2026-10-10T08:01:15.106Z. One unpaid request per endpoint to capture the x402 challenge; Pay-Safe /check-payment against the listing. No payments, no signatures.

| Metric | Count |
|---|---|
| services | 80 |
| challenge | 31 |
| allow | 8 |
| warn | 23 |
| deny | 0 |
| no_challenge | 48 |
| unreachable | 1 |
| invalid | 0 |

## Reasons

| Rule | Services |
|---|---|
| `fresh_recipient` | 16 |
| `eip712_domain_mismatch` | 5 |
| `long_payment_timeout` | 1 |
| `endpoint_domain_suspicious` | 1 |

## Findings

- **WARN fresh_recipient** in Otto Hyperliquid Market (sid 4357): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Yield Markets (sid 4359): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Market Alpha (sid 4340): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Market News (sid 40011): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Sniffer Alpha Feed (sid 34716): 0x94D53c7814Be8D40f9196551bC598DDce47F686C has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in Commodity Top & Bottom Signal (sid 34606): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in Crypto Top / Bottom, Signal (sid 19874): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN fresh_recipient** in Entropy Signal API (sid 40780): 0x19f090a52a6fa82640442D7eed7eB9ce5f5cf9ED has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in US Stock Top / Bottom Signal (sid 34150): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN fresh_recipient** in Otto DeFi Analytics (sid 4347): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Smart Money (sid 40012): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Company Research (sid 40010): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Crypto News (sid 4343): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Twitter Summary (sid 4349): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Yield Alpha (sid 4351): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Sub-Wallet Resolve (sid 4367): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Idle Capital Scan (sid 4362): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Portfolio Balances (sid 4354): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in RoseIntel Evidence API (sid 17723): extra declares the EIP-712 domain name "USD₮0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN fresh_recipient** in Otto TradFi Macro Data (sid 4352): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN long_payment_timeout** in 查询经济日历 (sid 40802): maxTimeoutSeconds is 86400 (more than 3600).
- **WARN endpoint_domain_suspicious** in Fusion Strategy Analysis (sid 33556): okxaiagent.vercel.app matches a phishing pattern (brand_impersonation): Hostname contains the brand "okx" but is not an official okx domain. It is the endpoint named in the listing.
- **WARN eip712_domain_mismatch** in Recent Market Insights Feed (sid 17911): extra declares the EIP-712 domain name "USDT0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.

## Services

| Verdict | Service | Listed | Challenge | Reasons |
|---|---|---|---|---|
| WARN | Otto Hyperliquid Market (sid 4357) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Yield Markets (sid 4359) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Market Alpha (sid 4340) | 0.005 USDT | 0.005 USDT0 on eip155:196 | fresh_recipient |
| WARN | Market News (sid 40011) | 0.02 USDT | 0.02 USDT0 on eip155:196 | fresh_recipient |
| WARN | Sniffer Alpha Feed (sid 34716) | 0.39 USDT | 0.39 USDT0 on eip155:196 | fresh_recipient |
| WARN | Commodity Top & Bottom Signal (sid 34606) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Crypto Top / Bottom, Signal (sid 19874) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Entropy Signal API (sid 40780) | 0.02 USDT | 0.02 USDT0 on eip155:196 | fresh_recipient |
| WARN | US Stock Top / Bottom Signal (sid 34150) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Otto DeFi Analytics (sid 4347) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Smart Money (sid 40012) | 0.03 USDT | 0.03 USDT0 on eip155:196 | fresh_recipient |
| WARN | Company Research (sid 40010) | 0.05 USDT | 0.05 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Crypto News (sid 4343) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Twitter Summary (sid 4349) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Yield Alpha (sid 4351) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Sub-Wallet Resolve (sid 4367) | 0.01 USDT | 0.01 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Idle Capital Scan (sid 4362) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Portfolio Balances (sid 4354) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | RoseIntel Evidence API (sid 17723) | 0.5 USDT | 0.5 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Otto TradFi Macro Data (sid 4352) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | 查询经济日历 (sid 40802) | 0.02 USDT | 0.02 USDT0 on eip155:196 | long_payment_timeout |
| WARN | Fusion Strategy Analysis (sid 33556) | 1 USDT | 0.01 USDT0 on eip155:196 | endpoint_domain_suspicious |
| WARN | Recent Market Insights Feed (sid 17911) | 0.02 USDT | 0.02 USDT0 on eip155:196 | eip712_domain_mismatch |
| ALLOW | MoonFinder 市场信号扫描 (sid 25864) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | Japan Market Ledger (sid 38405) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Crypto analysis team (sid 36980) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Token Approval Checker (sid 41195) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | Meme 交易情报扫描 (sid 33200) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | 钱包签名风险提醒 (sid 35352) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | TradeDesk 指标体验引流 (sid 39830) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | URL Change Check API (sid 39856) | 0.005 USDT | 0.005 USDT0 on eip155:196 |  |
| no_payment_challenge | Crypto Market Context Feed (sid 7494) | 0.1 USDT | — |  |
| no_payment_challenge | X Layer Token Analysis (sid 39824) | 0.05 USDT | — |  |
| no_payment_challenge | Token Security Pulse (sid 40595) | 0.01 USDT | — |  |
| no_payment_challenge | Drawdown Analysis (sid 41264) | 0.01 USDT | — |  |
| no_payment_challenge | Drawdown Analysis (sid 41375) | 0.01 USDT | — |  |
| no_payment_challenge | Supplied Shock Stress Analysis (sid 41271) | 0.01 USDT | — |  |
| no_payment_challenge | Token Security Scan (sid 16632) | 0.03 USDT | — |  |
| no_payment_challenge | Wallet Reputation (sid 16633) | 0.01 USDT | — |  |
| no_payment_challenge | Sniffer Risk Check (sid 34717) | 0.1 USDT | — |  |
| no_payment_challenge | Otto Token Security Audit (sid 4337) | 0.001 USDT | — |  |
| unreachable | Token Risk Analysis (sid 40014) | 1 USDT | — | timeout |
| no_payment_challenge | MistEye Security Gate Scan (sid 17126) | 0.0001 USDT | — |  |
| no_payment_challenge | Otto LLM Research (sid 4339) | 0.1 USDT | — |  |
| no_payment_challenge | Otto Token Alpha (sid 4344) | 0.001 USDT | — |  |
| no_payment_challenge | AI Security Copilot Router (sid 34987) | 1 USDT | — |  |
| no_payment_challenge | RWA Research Report (sid 40671) | 0.25 USDT | — |  |
| no_payment_challenge | Otto Filtered News (sid 4348) | 0.001 USDT | — |  |
| no_payment_challenge | Portfolio Health (sid 16634) | 0.01 USDT | — |  |
| no_payment_challenge | Wallet Risk Allowance Audit (sid 34986) | 1 USDT | — |  |
| no_payment_challenge | X Layer Wallet Activity (sid 39848) | 0.05 USDT | — |  |
| no_payment_challenge | Custos Decision Engine (sid 36308) | 0.01 USDT | — |  |
| no_payment_challenge | Source Reliability Check (sid 17907) | 0.02 USDT | — |  |
| no_payment_challenge | Claim Fact-Check Service (sid 17905) | 0.1 USDT | — |  |
| no_payment_challenge | API Response Regression Diff (sid 41231) | 0.01 USDT | — |  |
| no_payment_challenge | Service List (sid 3054) | 0.000001 USDT | — |  |
| no_payment_challenge | Health Check (sid 3053) | 0.000001 USDT | — |  |
| no_payment_challenge | Structured Data Chart (sid 41247) | 0.01 USDT | — |  |
| no_payment_challenge | OHLCV Data Gap Check (sid 41189) | 0.01 USDT | — |  |
| no_payment_challenge | EIP-712 Typed Data Explainer (sid 41196) | 0.01 USDT | — |  |
| no_payment_challenge | Check Yield (sid 33550) | 0.1 USDT | — |  |
| no_payment_challenge | EVM Transaction Guardrail (sid 34985) | 1 USDT | — |  |
| no_payment_challenge | Otto Generate Meme (sid 4338) | 0.15 USDT | — |  |
| no_payment_challenge | AI饮食运动助手 (sid 30754) | 0.01 USDT | — |  |
| no_payment_challenge | 美股AI半导体5分钟信号日报 (sid 39799) | 2.98 USDT | — |  |
| no_payment_challenge | 草台班子检测器 (sid 29539) | 0.05 USDT | — |  |
| no_payment_challenge | Prediction Market Insight (sid 17906) | 0.05 USDT | — |  |
| no_payment_challenge | Candlestick Chart Image (sid 41191) | 0.01 USDT | — |  |
| no_payment_challenge | Bubble Image (sid 3055) | 0.5 USDT | — |  |
| no_payment_challenge | Candlestick Chart Image (sid 41372) | 0.01 USDT | — |  |
| no_payment_challenge | Image Layer Composition (sid 41250) | 0.01 USDT | — |  |
| no_payment_challenge | Image Metadata Remover (sid 41244) | 0.01 USDT | — |  |
| no_payment_challenge | Target Size Image Compressor (sid 41243) | 0.01 USDT | — |  |
| no_payment_challenge | Image Batch Convert Resize (sid 41242) | 0.01 USDT | — |  |
| no_payment_challenge | Near Duplicate Image Finder (sid 41245) | 0.01 USDT | — |  |
| no_payment_challenge | Otto DEX Approval Calldata (sid 4342) | 0.005 USDT | — |  |
| no_payment_challenge | Social Preview Validator (sid 41209) | 0.01 USDT | — |  |
| no_payment_challenge | Otto Token Price (sid 4334) | 0.002 USDT | — |  |
| no_payment_challenge | X Layer Proof Verifier (sid 41109) | 0.01 USDT | — |  |
| no_payment_challenge | X Layer Contract Risk Scanner (sid 39842) | 0.05 USDT | — |  |
