# OKX.AI Pay-Safe trust scan

Generated 2026-11-04T08:01:01.839Z. One unpaid request per endpoint to capture the x402 challenge; Pay-Safe /check-payment against the listing. No payments, no signatures.

| Metric | Count |
|---|---|
| services | 63 |
| challenge | 35 |
| allow | 15 |
| warn | 20 |
| deny | 0 |
| no_challenge | 28 |
| unreachable | 0 |
| invalid | 0 |

## Reasons

| Rule | Services |
|---|---|
| `fresh_recipient` | 15 |
| `eip712_domain_mismatch` | 3 |
| `endpoint_domain_suspicious` | 1 |
| `multiple_payees` | 1 |

## Findings

- **WARN fresh_recipient** in Market News (sid 40011): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Hyperliquid Slippage Data (sid 41760): 0x19f090a52a6fa82640442D7eed7eB9ce5f5cf9ED has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Hyperliquid Slippage Final (sid 41831): 0x19f090a52a6fa82640442D7eed7eB9ce5f5cf9ED has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Hyperliquid Market Regime (sid 41761): 0x19f090a52a6fa82640442D7eed7eB9ce5f5cf9ED has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Closure Discount by Duration (sid 40894): 0x277cA91276A3801667B76C97Da3872Ccb6E96068 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Entropy Signal API (sid 40780): 0x19f090a52a6fa82640442D7eed7eB9ce5f5cf9ED has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in Crypto Top / Bottom, Signal (sid 19874): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in US Stock Top / Bottom Signal (sid 34150): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN fresh_recipient** in Asset Correlation Matrix (sid 41691): 0x19f090a52a6fa82640442D7eed7eB9ce5f5cf9ED has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Website Growth Audit (sid 31680): 0xA7a2a00D24982c9eBeB16effFd58cEB5DfC94591 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN endpoint_domain_suspicious** in Fusion Strategy Analysis (sid 33556): okxaiagent.vercel.app matches a phishing pattern (brand_impersonation): Hostname contains the brand "okx" but is not an official okx domain. It is the endpoint named in the listing.
- **WARN fresh_recipient** in Sniffer Deep Report (sid 34718): 0x94D53c7814Be8D40f9196551bC598DDce47F686C has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Sniffer Risk Check (sid 34717): 0x94D53c7814Be8D40f9196551bC598DDce47F686C has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Smart Money (sid 40012): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Company Research (sid 40010): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in RoseIntel Evidence API (sid 17723): extra declares the EIP-712 domain name "USD₮0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN multiple_payees** in Commitment Verification (sid 38350): accepts[] pays 2 different recipients.
- **WARN fresh_recipient** in Closure Calendar (sid 40892): 0x277cA91276A3801667B76C97Da3872Ccb6E96068 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Reopen Price Accuracy Record (sid 40893): 0x277cA91276A3801667B76C97Da3872Ccb6E96068 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Sniffer Alpha Feed (sid 34716): 0x94D53c7814Be8D40f9196551bC598DDce47F686C has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.

## Services

| Verdict | Service | Listed | Challenge | Reasons |
|---|---|---|---|---|
| WARN | Market News (sid 40011) | 0.02 USDT | 0.02 USDT0 on eip155:196 | fresh_recipient |
| WARN | Hyperliquid Slippage Data (sid 41760) | 0.05 USDT | 0.05 USDT0 on eip155:196 | fresh_recipient |
| WARN | Hyperliquid Slippage Final (sid 41831) | 0.05 USDT | 0.05 USDT0 on eip155:196 | fresh_recipient |
| WARN | Hyperliquid Market Regime (sid 41761) | 0.02 USDT | 0.02 USDT0 on eip155:196 | fresh_recipient |
| WARN | Closure Discount by Duration (sid 40894) | 0.1 USDT | 0.1 USDT0 on eip155:196 | fresh_recipient |
| WARN | Entropy Signal API (sid 40780) | 0.02 USDT | 0.02 USDT0 on eip155:196 | fresh_recipient |
| WARN | Crypto Top / Bottom, Signal (sid 19874) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | US Stock Top / Bottom Signal (sid 34150) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Asset Correlation Matrix (sid 41691) | 0.02 USDT | 0.02 USDT0 on eip155:196 | fresh_recipient |
| WARN | Website Growth Audit (sid 31680) | 0.35 USDT | 0.35 USDT0 on eip155:196 | fresh_recipient |
| WARN | Fusion Strategy Analysis (sid 33556) | 1 USDT | 0.01 USDT0 on eip155:196 | endpoint_domain_suspicious |
| WARN | Sniffer Deep Report (sid 34718) | 1.99 USDT | 1.99 USDT0 on eip155:196 | fresh_recipient |
| WARN | Sniffer Risk Check (sid 34717) | 0.1 USDT | 0.1 USDT0 on eip155:196 | fresh_recipient |
| WARN | Smart Money (sid 40012) | 0.03 USDT | 0.03 USDT0 on eip155:196 | fresh_recipient |
| WARN | Company Research (sid 40010) | 0.05 USDT | 0.05 USDT0 on eip155:196 | fresh_recipient |
| WARN | RoseIntel Evidence API (sid 17723) | 0.5 USDT | 0.5 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Commitment Verification (sid 38350) | 1 USDT | 1 USDT0 on eip155:196 | multiple_payees |
| WARN | Closure Calendar (sid 40892) | 0.01 USDT | 0.01 USDT0 on eip155:196 | fresh_recipient |
| WARN | Reopen Price Accuracy Record (sid 40893) | 0.05 USDT | 0.05 USDT0 on eip155:196 | fresh_recipient |
| WARN | Sniffer Alpha Feed (sid 34716) | 0.39 USDT | 0.39 USDT0 on eip155:196 | fresh_recipient |
| ALLOW | MoonFinder 市场信号扫描 (sid 25864) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | Japan Market Ledger (sid 38405) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Market Regime Read (sid 16720) | 0.02 USDT | 0.02 USDT0 on eip155:196 |  |
| ALLOW | Multi-Asset Signal Scan (sid 16721) | 0.02 USDT | 0.02 USDT0 on eip155:196 |  |
| ALLOW | Korea Defense Chain Analysis (sid 35435) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Korea Power Chain Analysis (sid 35436) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Perp Trade-Call Verdict (sid 16719) | 0.02 USDT | 0.02 USDT0 on eip155:196 |  |
| ALLOW | Asia Session Regime Report (sid 33714) | 0.03 USDT | 0.03 USDT0 on eip155:196 |  |
| ALLOW | DeFi Opportunity Rank API (sid 33686) | 0.03 USDT | 0.03 USDT0 on eip155:196 |  |
| ALLOW | Yield Pool Risk Score API (sid 33682) | 0.03 USDT | 0.03 USDT0 on eip155:196 |  |
| ALLOW | 钱包签名风险提醒 (sid 35352) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | Korea Semiconductor Chain (sid 35434) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Web3 推文发布前检查 (sid 35353) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | 随机小姐姐视频地址 (sid 41475) | 0.2 USDT | 0.2 USDT0 on eip155:196 |  |
| ALLOW | 草台班子检测器 (sid 29539) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| no_payment_challenge | Luc Market Regime (sid 41586) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Correlation State (sid 41590) | 0.1 USDT | — |  |
| no_payment_challenge | Token Security Pulse (sid 40595) | 0.01 USDT | — |  |
| no_payment_challenge | URL Drain Risk API (sid 32686) | 0.02 USDT | — |  |
| no_payment_challenge | Approval Exposure Check API (sid 32682) | 0.02 USDT | — |  |
| no_payment_challenge | Address Trust Check API (sid 32683) | 0.01 USDT | — |  |
| no_payment_challenge | Token Tradeability Check API (sid 32684) | 0.03 USDT | — |  |
| no_payment_challenge | Preflight Risk Check API (sid 32681) | 0.01 USDT | — |  |
| no_payment_challenge | MistEye Security Gate Scan (sid 17126) | 0.0001 USDT | — |  |
| no_payment_challenge | Stablecoin Peg Risk API (sid 33683) | 0.02 USDT | — |  |
| no_payment_challenge | Luc Daily Asset Brief (sid 41549) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Trend State (sid 41587) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Drawdown & Recovery (sid 41589) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Asset Risk (sid 41591) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Historical Extremeness (sid 41592) | 0.1 USDT | — |  |
| no_payment_challenge | Chain Momentum API (sid 33684) | 0.01 USDT | — |  |
| no_payment_challenge | Custos Decision Engine (sid 36308) | 0.01 USDT | — |  |
| no_payment_challenge | Open Interest Anomaly API (sid 33719) | 0.02 USDT | — |  |
| no_payment_challenge | Long Short Crowding API (sid 33720) | 0.01 USDT | — |  |
| no_payment_challenge | Liquidation Risk Pulse API (sid 33721) | 0.03 USDT | — |  |
| no_payment_challenge | Volatility Regime Score API (sid 33722) | 0.02 USDT | — |  |
| no_payment_challenge | CEX Price Divergence API (sid 33723) | 0.01 USDT | — |  |
| no_payment_challenge | Trend Strength Score API (sid 33724) | 0.02 USDT | — |  |
| no_payment_challenge | Breakout Fakeout Risk API (sid 33725) | 0.02 USDT | — |  |
| no_payment_challenge | Protocol Revenue Signal API (sid 33685) | 0.02 USDT | — |  |
| no_payment_challenge | Check Yield (sid 33550) | 0.1 USDT | — |  |
| no_payment_challenge | 美股AI半导体5分钟信号日报 (sid 39799) | 2.98 USDT | — |  |
| no_payment_challenge | Funding Rate Stress Score API (sid 33718) | 0.01 USDT | — |  |
