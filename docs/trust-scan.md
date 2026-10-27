# OKX.AI Pay-Safe trust scan

Generated 2026-10-27T09:12:15.831Z. One unpaid request per endpoint to capture the x402 challenge; Pay-Safe /check-payment against the listing. No payments, no signatures.

| Metric | Count |
|---|---|
| services | 59 |
| challenge | 24 |
| allow | 13 |
| warn | 11 |
| deny | 0 |
| no_challenge | 35 |
| unreachable | 0 |
| invalid | 0 |

## Reasons

| Rule | Services |
|---|---|
| `eip712_domain_mismatch` | 6 |
| `fresh_recipient` | 4 |
| `endpoint_domain_suspicious` | 1 |

## Findings

- **WARN fresh_recipient** in Market News (sid 40011): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in Recent Market Insights Feed (sid 17911): extra declares the EIP-712 domain name "USDT0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in US Stock Top / Bottom Signal (sid 34150): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN fresh_recipient** in Website Growth Audit (sid 31680): 0xA7a2a00D24982c9eBeB16effFd58cEB5DfC94591 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in Media Transcription Service (sid 17909): extra declares the EIP-712 domain name "USDT0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN endpoint_domain_suspicious** in Fusion Strategy Analysis (sid 33556): okxaiagent.vercel.app matches a phishing pattern (brand_impersonation): Hostname contains the brand "okx" but is not an official okx domain. It is the endpoint named in the listing.
- **WARN fresh_recipient** in Company Research (sid 40010): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Smart Money (sid 40012): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in RoseIntel Evidence API (sid 17723): extra declares the EIP-712 domain name "USD₮0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in Claim Fact-Check Service (sid 17905): extra declares the EIP-712 domain name "USDT0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in Source Reliability Check (sid 17907): extra declares the EIP-712 domain name "USDT0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.

## Services

| Verdict | Service | Listed | Challenge | Reasons |
|---|---|---|---|---|
| WARN | Market News (sid 40011) | 0.02 USDT | 0.02 USDT0 on eip155:196 | fresh_recipient |
| WARN | Recent Market Insights Feed (sid 17911) | 0.02 USDT | 0.02 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | US Stock Top / Bottom Signal (sid 34150) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Website Growth Audit (sid 31680) | 0.35 USDT | 0.35 USDT0 on eip155:196 | fresh_recipient |
| WARN | Media Transcription Service (sid 17909) | 0.1 USDT | 0.1 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Fusion Strategy Analysis (sid 33556) | 1 USDT | 0.01 USDT0 on eip155:196 | endpoint_domain_suspicious |
| WARN | Company Research (sid 40010) | 0.05 USDT | 0.05 USDT0 on eip155:196 | fresh_recipient |
| WARN | Smart Money (sid 40012) | 0.03 USDT | 0.03 USDT0 on eip155:196 | fresh_recipient |
| WARN | RoseIntel Evidence API (sid 17723) | 0.5 USDT | 0.5 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Claim Fact-Check Service (sid 17905) | 0.05 USDT | 0.05 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Source Reliability Check (sid 17907) | 0.02 USDT | 0.02 USDT0 on eip155:196 | eip712_domain_mismatch |
| ALLOW | 交易洞察分析 (sid 36394) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | MoonFinder 市场信号扫描 (sid 25864) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | Meme 交易情报扫描 (sid 33200) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Market Regime Read (sid 16720) | 0.02 USDT | 0.02 USDT0 on eip155:196 |  |
| ALLOW | 玄学智慧投研 (sid 36392) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Multi-Asset Signal Scan (sid 16721) | 0.02 USDT | 0.02 USDT0 on eip155:196 |  |
| ALLOW | Crypto analysis team (sid 36980) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Candlestick Star (sid 36978) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Perp Trade-Call Verdict (sid 16719) | 0.02 USDT | 0.02 USDT0 on eip155:196 |  |
| ALLOW | Yield Pool Risk Score API (sid 33682) | 0.03 USDT | 0.03 USDT0 on eip155:196 |  |
| ALLOW | DeFi Opportunity Rank API (sid 33686) | 0.03 USDT | 0.03 USDT0 on eip155:196 |  |
| ALLOW | 随机小姐姐视频地址 (sid 41475) | 0.2 USDT | 0.2 USDT0 on eip155:196 |  |
| ALLOW | 草台班子检测器 (sid 29539) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| no_payment_challenge | Luc Market Regime (sid 41586) | 0.1 USDT | — |  |
| no_payment_challenge | Prediction Market Insight (sid 17906) | 0.05 USDT | — |  |
| no_payment_challenge | Luc Correlation State (sid 41590) | 0.1 USDT | — |  |
| no_payment_challenge | Token Security Pulse (sid 40595) | 0.01 USDT | — |  |
| no_payment_challenge | Drawdown Analysis (sid 41264) | 0.01 USDT | — |  |
| no_payment_challenge | Supplied Shock Stress Analysis (sid 41271) | 0.01 USDT | — |  |
| no_payment_challenge | URL Drain Risk API (sid 32686) | 0.02 USDT | — |  |
| no_payment_challenge | Address Trust Check API (sid 32683) | 0.01 USDT | — |  |
| no_payment_challenge | Approval Exposure Check API (sid 32682) | 0.02 USDT | — |  |
| no_payment_challenge | Token Tradeability Check API (sid 32684) | 0.03 USDT | — |  |
| no_payment_challenge | MistEye Security Gate Scan (sid 17126) | 0.0001 USDT | — |  |
| no_payment_challenge | Stablecoin Peg Risk API (sid 33683) | 0.02 USDT | — |  |
| no_payment_challenge | Luc Daily Asset Brief (sid 41549) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Trend State (sid 41587) | 0.1 USDT | — |  |
| no_payment_challenge | RWA Research Report (sid 40671) | 0.25 USDT | — |  |
| no_payment_challenge | Luc Drawdown & Recovery (sid 41589) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Asset Risk (sid 41591) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Historical Extremeness (sid 41592) | 0.1 USDT | — |  |
| no_payment_challenge | Chain Momentum API (sid 33684) | 0.01 USDT | — |  |
| no_payment_challenge | Custos Decision Engine (sid 36308) | 0.01 USDT | — |  |
| no_payment_challenge | Preflight Risk Check API (sid 32681) | 0.01 USDT | — |  |
| no_payment_challenge | Protocol Health Score API (sid 33681) | 0.02 USDT | — |  |
| no_payment_challenge | Protocol Revenue Signal API (sid 33685) | 0.02 USDT | — |  |
| no_payment_challenge | JSON-LD Structured Data (sid 41274) | 0.01 USDT | — |  |
| no_payment_challenge | OHLCV Data Gap Check (sid 41189) | 0.01 USDT | — |  |
| no_payment_challenge | Check Yield (sid 33550) | 0.1 USDT | — |  |
| no_payment_challenge | 美股AI半导体5分钟信号日报 (sid 39799) | 2.98 USDT | — |  |
| no_payment_challenge | TxPreflight Onchain Tx Guard (sid 40832) | 0.04 USDT | — |  |
| no_payment_challenge | Candlestick Chart Image (sid 41191) | 0.01 USDT | — |  |
| no_payment_challenge | Audio Waveform Image (sid 41261) | 0.1 USDT | — |  |
| no_payment_challenge | Social Preview Validator (sid 41209) | 0.01 USDT | — |  |
| no_payment_challenge | Visual Page Comparison (sid 41204) | 0.03 USDT | — |  |
| no_payment_challenge | Full Page Screenshot (sid 41202) | 0.03 USDT | — |  |
| no_payment_challenge | Asset Identifier (sid 40673) | 0.08 USDT | — |  |
| no_payment_challenge | RWA Asset Comparison (sid 40672) | 0.5 USDT | — |  |
