# OKX.AI Pay-Safe trust scan

Generated 2026-10-24T08:01:15.875Z. One unpaid request per endpoint to capture the x402 challenge; Pay-Safe /check-payment against the listing. No payments, no signatures.

| Metric | Count |
|---|---|
| services | 90 |
| challenge | 44 |
| allow | 20 |
| warn | 24 |
| deny | 0 |
| no_challenge | 46 |
| unreachable | 0 |
| invalid | 0 |

## Reasons

| Rule | Services |
|---|---|
| `fresh_recipient` | 18 |
| `eip712_domain_mismatch` | 5 |
| `endpoint_domain_suspicious` | 1 |

## Findings

- **WARN fresh_recipient** in Otto Yield Markets (sid 4359): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Hyperliquid Market (sid 4357): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Market Alpha (sid 4340): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Market News (sid 40011): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Entropy Signal API (sid 40780): 0x19f090a52a6fa82640442D7eed7eB9ce5f5cf9ED has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto DeFi Analytics (sid 4347): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN endpoint_domain_suspicious** in Fusion Strategy Analysis (sid 33556): okxaiagent.vercel.app matches a phishing pattern (brand_impersonation): Hostname contains the brand "okx" but is not an official okx domain. It is the endpoint named in the listing.
- **WARN fresh_recipient** in Smart Money (sid 40012): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Company Research (sid 40010): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Crypto News (sid 4343): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Twitter Summary (sid 4349): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto KOL Sentiment (sid 4336): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in Crypto Top / Bottom, Signal (sid 19874): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN fresh_recipient** in Otto Yield Alpha (sid 4351): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Sub-Wallet Resolve (sid 4367): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Idle Capital Scan (sid 4362): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Portfolio Balances (sid 4354): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Otto Yield Farming Active (sid 4360): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in RoseIntel Evidence API (sid 17723): extra declares the EIP-712 domain name "USD₮0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in Source Reliability Check (sid 17907): extra declares the EIP-712 domain name "USDT0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in Claim Fact-Check Service (sid 17905): extra declares the EIP-712 domain name "USDT0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN fresh_recipient** in Otto TradFi Macro Data (sid 4352): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in Recent Market Insights Feed (sid 17911): extra declares the EIP-712 domain name "USDT0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN fresh_recipient** in Otto All Tokens (sid 4341): 0xa3dB6825DE8222E9f8BaC136eEb2F65D49a88fcF has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.

## Services

| Verdict | Service | Listed | Challenge | Reasons |
|---|---|---|---|---|
| WARN | Otto Yield Markets (sid 4359) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Hyperliquid Market (sid 4357) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Market Alpha (sid 4340) | 0.005 USDT | 0.005 USDT0 on eip155:196 | fresh_recipient |
| WARN | Market News (sid 40011) | 0.02 USDT | 0.02 USDT0 on eip155:196 | fresh_recipient |
| WARN | Entropy Signal API (sid 40780) | 0.02 USDT | 0.02 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto DeFi Analytics (sid 4347) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Fusion Strategy Analysis (sid 33556) | 1 USDT | 0.01 USDT0 on eip155:196 | endpoint_domain_suspicious |
| WARN | Smart Money (sid 40012) | 0.03 USDT | 0.03 USDT0 on eip155:196 | fresh_recipient |
| WARN | Company Research (sid 40010) | 0.05 USDT | 0.05 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Crypto News (sid 4343) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Twitter Summary (sid 4349) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto KOL Sentiment (sid 4336) | 0.003 USDT | 0.003 USDT0 on eip155:196 | fresh_recipient |
| WARN | Crypto Top / Bottom, Signal (sid 19874) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Otto Yield Alpha (sid 4351) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Sub-Wallet Resolve (sid 4367) | 0.01 USDT | 0.01 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Idle Capital Scan (sid 4362) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Portfolio Balances (sid 4354) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Otto Yield Farming Active (sid 4360) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | RoseIntel Evidence API (sid 17723) | 0.5 USDT | 0.5 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Source Reliability Check (sid 17907) | 0.02 USDT | 0.02 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Claim Fact-Check Service (sid 17905) | 0.05 USDT | 0.05 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Otto TradFi Macro Data (sid 4352) | 0.001 USDT | 0.001 USDT0 on eip155:196 | fresh_recipient |
| WARN | Recent Market Insights Feed (sid 17911) | 0.02 USDT | 0.02 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Otto All Tokens (sid 4341) | 0.002 USDT | 0.002 USDT0 on eip155:196 | fresh_recipient |
| ALLOW | Stablecoin Market Overview (sid 27360) | 0.001 USDT | 0.001 USDT0 on eip155:196 |  |
| ALLOW | MoonFinder 市场信号扫描 (sid 25864) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | Stablecoin Market Trend (sid 27361) | 0.001 USDT | 0.001 USDT0 on eip155:196 |  |
| ALLOW | Multi-Asset Signal Scan (sid 16721) | 0.02 USDT | 0.02 USDT0 on eip155:196 |  |
| ALLOW | Crypto analysis team (sid 36980) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Korea Defense Chain Analysis (sid 35435) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Token Approval Checker (sid 41195) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | Token DD Verdict (sid 11171) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| ALLOW | Meme 交易情报扫描 (sid 33200) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Candlestick Star (sid 36978) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Asia Session Regime Report (sid 33714) | 0.03 USDT | 0.03 USDT0 on eip155:196 |  |
| ALLOW | Market Regime Read (sid 16720) | 0.02 USDT | 0.02 USDT0 on eip155:196 |  |
| ALLOW | Stablecoin Yield Radar (sid 27359) | 0.001 USDT | 0.001 USDT0 on eip155:196 |  |
| ALLOW | Barker Yield Advisor (sid 27362) | 0.03 USDT | 0.03 USDT0 on eip155:196 |  |
| ALLOW | DeFi Opportunity Rank API (sid 33686) | 0.03 USDT | 0.03 USDT0 on eip155:196 |  |
| ALLOW | Yield Pool Risk Score API (sid 33682) | 0.03 USDT | 0.03 USDT0 on eip155:196 |  |
| ALLOW | Barker Execution Quote (sid 27368) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| ALLOW | Korea Semiconductor Chain (sid 35434) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | 草台班子检测器 (sid 29539) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| ALLOW | 随机小姐姐视频地址 (sid 41475) | 0.2 USDT | 0.2 USDT0 on eip155:196 |  |
| no_payment_challenge | Prediction Market Insight (sid 17906) | 0.05 USDT | — |  |
| no_payment_challenge | Technical Indicators (sid 41550) | 0.001 USDT | — |  |
| no_payment_challenge | Onchain Risk Analysis (sid 34778) | 0.5 USDT | — |  |
| no_payment_challenge | X Layer Token Analysis (sid 39824) | 0.05 USDT | — |  |
| no_payment_challenge | Token Security Pulse (sid 40595) | 0.01 USDT | — |  |
| no_payment_challenge | Drawdown Analysis (sid 41264) | 0.01 USDT | — |  |
| no_payment_challenge | Supplied Shock Stress Analysis (sid 41271) | 0.01 USDT | — |  |
| no_payment_challenge | Address Trust Check API (sid 32683) | 0.01 USDT | — |  |
| no_payment_challenge | Otto Token Security Audit (sid 4337) | 0.001 USDT | — |  |
| no_payment_challenge | URL Drain Risk API (sid 32686) | 0.02 USDT | — |  |
| no_payment_challenge | MistEye Security Gate Scan (sid 17126) | 0.0001 USDT | — |  |
| no_payment_challenge | Stablecoin Peg Risk API (sid 33683) | 0.02 USDT | — |  |
| no_payment_challenge | Otto LLM Research (sid 4339) | 0.1 USDT | — |  |
| no_payment_challenge | Otto Token Alpha (sid 4344) | 0.001 USDT | — |  |
| no_payment_challenge | Token Risk Gate (sid 41527) | 0.01 USDT | — |  |
| no_payment_challenge | Luc Daily Asset Brief (sid 41549) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Trend State (sid 41587) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Market Regime (sid 41586) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Correlation State (sid 41590) | 0.1 USDT | — |  |
| no_payment_challenge | RWA Research Report (sid 40671) | 0.25 USDT | — |  |
| no_payment_challenge | Otto Filtered News (sid 4348) | 0.001 USDT | — |  |
| no_payment_challenge | Chain Momentum API (sid 33684) | 0.01 USDT | — |  |
| no_payment_challenge | Custos Decision Engine (sid 36308) | 0.01 USDT | — |  |
| no_payment_challenge | Approval Exposure Check API (sid 32682) | 0.02 USDT | — |  |
| no_payment_challenge | Preflight Risk Check API (sid 32681) | 0.01 USDT | — |  |
| no_payment_challenge | Protocol Health Score API (sid 33681) | 0.02 USDT | — |  |
| no_payment_challenge | Protocol Revenue Signal API (sid 33685) | 0.02 USDT | — |  |
| no_payment_challenge | API Response Regression Diff (sid 41231) | 0.01 USDT | — |  |
| no_payment_challenge | Structured Data Chart (sid 41247) | 0.01 USDT | — |  |
| no_payment_challenge | OHLCV Data Gap Check (sid 41189) | 0.01 USDT | — |  |
| no_payment_challenge | EIP-712 Typed Data Explainer (sid 41196) | 0.01 USDT | — |  |
| no_payment_challenge | JSON-LD Structured Data (sid 41274) | 0.01 USDT | — |  |
| no_payment_challenge | Otto Generate Meme (sid 4338) | 0.15 USDT | — |  |
| no_payment_challenge | Check Yield (sid 33550) | 0.1 USDT | — |  |
| no_payment_challenge | 美股AI半导体5分钟信号日报 (sid 39799) | 2.98 USDT | — |  |
| no_payment_challenge | Candlestick Chart Image (sid 41191) | 0.01 USDT | — |  |
| no_payment_challenge | Image Layer Composition (sid 41250) | 0.01 USDT | — |  |
| no_payment_challenge | Image Metadata Remover (sid 41244) | 0.01 USDT | — |  |
| no_payment_challenge | Audio Waveform Image (sid 41261) | 0.1 USDT | — |  |
| no_payment_challenge | Target Size Image Compressor (sid 41243) | 0.01 USDT | — |  |
| no_payment_challenge | Near Duplicate Image Finder (sid 41245) | 0.01 USDT | — |  |
| no_payment_challenge | Image Batch Convert Resize (sid 41242) | 0.01 USDT | — |  |
| no_payment_challenge | Social Preview Validator (sid 41209) | 0.01 USDT | — |  |
| no_payment_challenge | Visual Page Comparison (sid 41204) | 0.03 USDT | — |  |
| no_payment_challenge | Otto DEX Approval Calldata (sid 4342) | 0.005 USDT | — |  |
| no_payment_challenge | Otto Token Price (sid 4334) | 0.002 USDT | — |  |
