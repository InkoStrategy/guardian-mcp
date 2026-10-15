# OKX.AI Pay-Safe trust scan

Generated 2026-10-15T08:01:25.136Z. One unpaid request per endpoint to capture the x402 challenge; Pay-Safe /check-payment against the listing. No payments, no signatures.

| Metric | Count |
|---|---|
| services | 81 |
| challenge | 32 |
| allow | 15 |
| warn | 17 |
| deny | 0 |
| no_challenge | 46 |
| unreachable | 3 |
| invalid | 0 |

## Reasons

| Rule | Services |
|---|---|
| `fresh_recipient` | 13 |
| `eip712_domain_mismatch` | 2 |
| `endpoint_domain_suspicious` | 1 |
| `long_payment_timeout` | 1 |

## Findings

- **WARN fresh_recipient** in Otto Yield Markets (sid 4359): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Hyperliquid Market (sid 4357): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Market Alpha (sid 4340): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto DeFi Analytics (sid 4347): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN endpoint_domain_suspicious** in Fusion Strategy Analysis (sid 33556): okxaiagent.vercel.app matches a phishing pattern (brand_impersonation): Hostname contains the brand "okx" but is not an official okx domain. It is the endpoint named in the listing.
- **WARN fresh_recipient** in Otto Crypto News (sid 4343): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Twitter Summary (sid 4349): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto KOL Sentiment (sid 4336): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Yield Alpha (sid 4351): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Sub-Wallet Resolve (sid 4367): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Idle Capital Scan (sid 4362): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Portfolio Balances (sid 4354): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in RoseIntel Evidence API (sid 17723): extra declares the EIP-712 domain name "USD₮0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN long_payment_timeout** in 查询经济日历 (sid 40802): maxTimeoutSeconds is 86400 (more than 3600).
- **WARN fresh_recipient** in Otto TradFi Macro Data (sid 4352): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in Recent Market Insights Feed (sid 17911): extra declares the EIP-712 domain name "USDT0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN fresh_recipient** in Otto All Tokens (sid 4341): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.

## Services

| Verdict | Service | Listed | Challenge | Reasons |
|---|---|---|---|---|
| WARN | Otto Yield Markets (sid 4359) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Hyperliquid Market (sid 4357) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Market Alpha (sid 4340) | 0.005 USDT | 0.005 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto DeFi Analytics (sid 4347) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Fusion Strategy Analysis (sid 33556) | 1 USDT | 0.01 USDT0 on eip155:196 | endpoint_domain_suspicious |
| WARN | Otto Crypto News (sid 4343) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Twitter Summary (sid 4349) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto KOL Sentiment (sid 4336) | 0.003 USDT | 0.003 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Yield Alpha (sid 4351) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Sub-Wallet Resolve (sid 4367) | 0.01 USDT | 0.01 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Idle Capital Scan (sid 4362) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Portfolio Balances (sid 4354) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | RoseIntel Evidence API (sid 17723) | 0.5 USDT | 0.5 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | 查询经济日历 (sid 40802) | 0.02 USDT | 0.02 USDT0 on eip155:196 | long_payment_timeout |
| WARN | Otto TradFi Macro Data (sid 4352) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Recent Market Insights Feed (sid 17911) | 0.02 USDT | 0.02 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Otto All Tokens (sid 4341) | 0.002 USDT | 0.002 USDT0 on eip155:196 | fresh_recipient |
| ALLOW | Marketplace Niche Scan (sid 33278) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | MoonFinder 市场信号扫描 (sid 25864) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | Stablecoin Market Trend (sid 27361) | 0.001 USDT | 0.001 USDT0 on eip155:196 |  |
| ALLOW | Stablecoin Market Overview (sid 27360) | 0.001 USDT | 0.001 USDT0 on eip155:196 |  |
| ALLOW | Multi-Asset Signal Scan (sid 16721) | 0.02 USDT | 0.02 USDT0 on eip155:196 |  |
| ALLOW | Korea Defense Chain Analysis (sid 35435) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Korea Power Chain Analysis (sid 35436) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Token Approval Checker (sid 41195) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | Market Regime Read (sid 16720) | 0.02 USDT | 0.02 USDT0 on eip155:196 |  |
| ALLOW | Stablecoin Yield Radar (sid 27359) | 0.001 USDT | 0.001 USDT0 on eip155:196 |  |
| ALLOW | Barker Yield Advisor (sid 27362) | 0.03 USDT | 0.03 USDT0 on eip155:196 |  |
| ALLOW | Barker Execution Quote (sid 27368) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| ALLOW | 钱包签名风险提醒 (sid 35352) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | Kerb Exit Check (sid 40920) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | 草台班子检测器 (sid 29539) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| no_payment_challenge | Crypto Market Context Feed (sid 7494) | 0.1 USDT | — |  |
| no_payment_challenge | Technical Indicators (sid 41550) | 0.001 USDT | — |  |
| no_payment_challenge | 地址行为分析服务 (sid 17483) | 0.5 USDT | — |  |
| no_payment_challenge | Token Security Pulse (sid 40595) | 0.01 USDT | — |  |
| no_payment_challenge | Drawdown Analysis (sid 41264) | 0.01 USDT | — |  |
| no_payment_challenge | Supplied Shock Stress Analysis (sid 41271) | 0.01 USDT | — |  |
| no_payment_challenge | Token Security Scan (sid 16632) | 0.03 USDT | — |  |
| no_payment_challenge | Wallet Reputation (sid 16633) | 0.01 USDT | — |  |
| no_payment_challenge | Otto Token Security Audit (sid 4337) | 0.001 USDT | — |  |
| no_payment_challenge | Sniffer Risk Check (sid 34717) | 0.1 USDT | — |  |
| no_payment_challenge | MistEye Security Gate Scan (sid 17126) | 0.0001 USDT | — |  |
| no_payment_challenge | Token Risk Gate (sid 41527) | 0.01 USDT | — |  |
| no_payment_challenge | Otto LLM Research (sid 4339) | 0.1 USDT | — |  |
| no_payment_challenge | Otto Token Alpha (sid 4344) | 0.001 USDT | — |  |
| no_payment_challenge | RWA Research Report (sid 40671) | 0.25 USDT | — |  |
| no_payment_challenge | Otto Filtered News (sid 4348) | 0.001 USDT | — |  |
| no_payment_challenge | Otto Generate Meme (sid 4338) | 0.15 USDT | — |  |
| unreachable | AI Security Copilot Router (sid 34987) | 1 USDT | — | timeout |
| no_payment_challenge | Portfolio Health (sid 16634) | 0.01 USDT | — |  |
| no_payment_challenge | Custos Decision Engine (sid 36308) | 0.01 USDT | — |  |
| no_payment_challenge | Source Reliability Check (sid 17907) | 0.02 USDT | — |  |
| no_payment_challenge | Claim Fact-Check Service (sid 17905) | 0.1 USDT | — |  |
| no_payment_challenge | API Response Regression Diff (sid 41231) | 0.01 USDT | — |  |
| no_payment_challenge | Health Check (sid 3053) | 0.000001 USDT | — |  |
| no_payment_challenge | Service List (sid 3054) | 0.000001 USDT | — |  |
| unreachable | Wallet Risk Allowance Audit (sid 34986) | 1 USDT | — | timeout |
| no_payment_challenge | Asset Identifier (sid 40673) | 0.08 USDT | — |  |
| no_payment_challenge | RWA Asset Comparison (sid 40672) | 0.5 USDT | — |  |
| no_payment_challenge | OpenAPI to MCP Tool Defs (sid 41223) | 0.01 USDT | — |  |
| no_payment_challenge | Structured Data Chart (sid 41247) | 0.01 USDT | — |  |
| no_payment_challenge | OHLCV Data Gap Check (sid 41189) | 0.01 USDT | — |  |
| no_payment_challenge | EIP-712 Typed Data Explainer (sid 41196) | 0.01 USDT | — |  |
| no_payment_challenge | Check Yield (sid 33550) | 0.1 USDT | — |  |
| no_payment_challenge | AI饮食运动助手 (sid 30754) | 0.01 USDT | — |  |
| no_payment_challenge | 美股AI半导体5分钟信号日报 (sid 39799) | 2.98 USDT | — |  |
| no_payment_challenge | Prediction Market Insight (sid 17906) | 0.05 USDT | — |  |
| unreachable | EVM Transaction Guardrail (sid 34985) | 1 USDT | — | timeout |
| no_payment_challenge | Candlestick Chart Image (sid 41191) | 0.01 USDT | — |  |
| no_payment_challenge | Bubble Image (sid 3055) | 0.5 USDT | — |  |
| no_payment_challenge | Image Layer Composition (sid 41250) | 0.01 USDT | — |  |
| no_payment_challenge | Image Metadata Remover (sid 41244) | 0.01 USDT | — |  |
| no_payment_challenge | Audio Waveform Image (sid 41261) | 0.1 USDT | — |  |
| no_payment_challenge | Target Size Image Compressor (sid 41243) | 0.01 USDT | — |  |
| no_payment_challenge | Image Batch Convert Resize (sid 41242) | 0.01 USDT | — |  |
| no_payment_challenge | Near Duplicate Image Finder (sid 41245) | 0.01 USDT | — |  |
| no_payment_challenge | Social Preview Validator (sid 41209) | 0.01 USDT | — |  |
| no_payment_challenge | Otto DEX Approval Calldata (sid 4342) | 0.005 USDT | — |  |
| no_payment_challenge | Otto Token Price (sid 4334) | 0.002 USDT | — |  |
| no_payment_challenge | X Layer Proof Verifier (sid 41109) | 0.01 USDT | — |  |
