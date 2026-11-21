# OKX.AI Pay-Safe trust scan

Generated 2026-11-21T08:01:05.371Z. One unpaid request per endpoint to capture the x402 challenge; Pay-Safe /check-payment against the listing. No payments, no signatures.

| Metric | Count |
|---|---|
| services | 66 |
| challenge | 39 |
| allow | 21 |
| warn | 18 |
| deny | 0 |
| no_challenge | 27 |
| unreachable | 0 |
| invalid | 0 |

## Reasons

| Rule | Services |
|---|---|
| `fresh_recipient` | 9 |
| `eip712_domain_mismatch` | 6 |
| `endpoint_domain_suspicious` | 1 |
| `resource_host_mismatch` | 1 |
| `multiple_payees` | 1 |

## Findings

- **WARN fresh_recipient** in Market News (sid 40011): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Closure Discount by Duration (sid 40894): 0x277cA91276A3801667B76C97Da3872Ccb6E96068 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in Dubai Property Signal (sid 34610): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN endpoint_domain_suspicious** in Fusion Strategy Analysis (sid 33556): okxaiagent.vercel.app matches a phishing pattern (brand_impersonation): Hostname contains the brand "okx" but is not an official okx domain. It is the endpoint named in the listing.
- **WARN fresh_recipient** in Sniffer Alpha Feed (sid 34716): 0x94D53c7814Be8D40f9196551bC598DDce47F686C has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in Korea Stock Top/Bottom Signal (sid 34176): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in Crypto Top / Bottom, Signal (sid 19874): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in Commodity Top & Bottom Signal (sid 34606): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in US Stock Top / Bottom Signal (sid 34150): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN fresh_recipient** in Website Growth Audit (sid 31680): 0xA7a2a00D24982c9eBeB16effFd58cEB5DfC94591 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Company Research (sid 40010): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Smart Money (sid 40012): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in RoseIntel Evidence API (sid 17723): extra declares the EIP-712 domain name "USD₮0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN resource_host_mismatch** in Blockchain Trend Content (sid 34742): resource.url is on agent-node.du5kse.top but the agent called agent.sigmanode.ai.
- **WARN multiple_payees** in Commitment Verification (sid 38350): accepts[] pays 2 different recipients.
- **WARN fresh_recipient** in Sniffer Deep Report (sid 34718): 0x94D53c7814Be8D40f9196551bC598DDce47F686C has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Sniffer Risk Check (sid 34717): 0x94D53c7814Be8D40f9196551bC598DDce47F686C has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Closure Calendar (sid 40892): 0x277cA91276A3801667B76C97Da3872Ccb6E96068 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.

## Services

| Verdict | Service | Listed | Challenge | Reasons |
|---|---|---|---|---|
| WARN | Market News (sid 40011) | 0.02 USDT | 0.02 USDT0 on eip155:196 | fresh_recipient |
| WARN | Closure Discount by Duration (sid 40894) | 0.1  | 0.1 USDT0 on eip155:196 | fresh_recipient |
| WARN | Dubai Property Signal (sid 34610) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Fusion Strategy Analysis (sid 33556) | 1 USDT | 0.01 USDT0 on eip155:196 | endpoint_domain_suspicious |
| WARN | Sniffer Alpha Feed (sid 34716) | 0.39 USDT | 0.39 USDT0 on eip155:196 | fresh_recipient |
| WARN | Korea Stock Top/Bottom Signal (sid 34176) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Crypto Top / Bottom, Signal (sid 19874) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Commodity Top & Bottom Signal (sid 34606) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | US Stock Top / Bottom Signal (sid 34150) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Website Growth Audit (sid 31680) | 0.35 USDT | 0.35 USDT0 on eip155:196 | fresh_recipient |
| WARN | Company Research (sid 40010) | 0.05 USDT | 0.05 USDT0 on eip155:196 | fresh_recipient |
| WARN | Smart Money (sid 40012) | 0.03 USDT | 0.03 USDT0 on eip155:196 | fresh_recipient |
| WARN | RoseIntel Evidence API (sid 17723) | 0.5 USDT | 0.5 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Blockchain Trend Content (sid 34742) | 1 USDT | 1 USDT0 on eip155:196 | resource_host_mismatch |
| WARN | Commitment Verification (sid 38350) | 1 USDT | 1 USDT0 on eip155:196 | multiple_payees |
| WARN | Sniffer Deep Report (sid 34718) | 1.99 USDT | 1.99 USDT0 on eip155:196 | fresh_recipient |
| WARN | Sniffer Risk Check (sid 34717) | 0.1 USDT | 0.1 USDT0 on eip155:196 | fresh_recipient |
| WARN | Closure Calendar (sid 40892) | 0.01  | 0.01 USDT0 on eip155:196 | fresh_recipient |
| ALLOW | Japan Market Ledger (sid 38405) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | 交易洞察分析 (sid 36394) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | 玄学智慧投研 (sid 36392) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Candlestick Star (sid 36978) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Korea Power Chain Analysis (sid 35436) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Korea Defense Chain Analysis (sid 35435) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Crypto analysis team (sid 36980) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Contract DeepLint — Deep Contract Static Analysis (sid 42126) | 0.05  | 0.05 USDT0 on eip155:196 |  |
| ALLOW | Token QuickScan (EVM) (sid 41735) | 0.05  | 0.05 USDT0 on eip155:196 |  |
| ALLOW | Asia Session Regime Report (sid 33714) | 0.03 USDT | 0.03 USDT0 on eip155:196 |  |
| ALLOW | DeFi Opportunity Rank API (sid 33686) | 0.03 USDT | 0.03 USDT0 on eip155:196 |  |
| ALLOW | Yield Pool Risk Score API (sid 33682) | 0.03 USDT | 0.03 USDT0 on eip155:196 |  |
| ALLOW | 钱包签名风险提醒 (sid 35352) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | SafeCheck — Multisig / Safe Wallet Inspector (sid 44129) | 0.02  | 0.02 USDT0 on eip155:196 |  |
| ALLOW | Korea Semiconductor Chain (sid 35434) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | SignGuard — EIP-712 Signing Risk Explainer (sid 41750) | 0.02  | 0.02 USDT0 on eip155:196 |  |
| ALLOW | BridgeQuote — Cross-Chain Route Quote (sid 44132) | 0.01  | 0.01 USDT0 on eip155:196 |  |
| ALLOW | Address Profile — Multi-Chain Address Dossier (sid 41751) | 0.02  | 0.02 USDT0 on eip155:196 |  |
| ALLOW | TradeDesk 指标体验引流 (sid 39830) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | 随机小姐姐视频地址 (sid 41475) | 0.2 USDT | 0.2 USDT0 on eip155:196 |  |
| ALLOW | Gas Lens — Multi-Chain Fee Snapshot (sid 42308) | 0.01  | 0.01 USDT0 on eip155:196 |  |
| no_payment_challenge | Luc Market Regime (sid 41586) | 0.1 USDT | — |  |
| no_payment_challenge | Token Security Pulse (sid 40595) | 0.01 USDT | — |  |
| no_payment_challenge | URL Drain Risk API (sid 32686) | 0.02 USDT | — |  |
| no_payment_challenge | Address Trust Check API (sid 32683) | 0.01 USDT | — |  |
| no_payment_challenge | Approval Exposure Check API (sid 32682) | 0.02 USDT | — |  |
| no_payment_challenge | Stablecoin Peg Risk API (sid 33683) | 0.02 USDT | — |  |
| no_payment_challenge | MistEye Security Gate Scan (sid 17126) | 0.0001 USDT | — |  |
| no_payment_challenge | Token Risk Gate (sid 41527) | 0.01 USDT | — |  |
| no_payment_challenge | Luc Daily Asset Brief (sid 41549) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Trend State (sid 41587) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Correlation State (sid 41590) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Drawdown & Recovery (sid 41589) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Asset Risk (sid 41591) | 0.1 USDT | — |  |
| no_payment_challenge | Chain Momentum API (sid 33684) | 0.01 USDT | — |  |
| no_payment_challenge | Custos Decision Engine (sid 36308) | 0.01 USDT | — |  |
| no_payment_challenge | Long Short Crowding API (sid 33720) | 0.01 USDT | — |  |
| no_payment_challenge | Open Interest Anomaly API (sid 33719) | 0.02 USDT | — |  |
| no_payment_challenge | Liquidation Risk Pulse API (sid 33721) | 0.03 USDT | — |  |
| no_payment_challenge | Volatility Regime Score API (sid 33722) | 0.02 USDT | — |  |
| no_payment_challenge | CEX Price Divergence API (sid 33723) | 0.01 USDT | — |  |
| no_payment_challenge | Trend Strength Score API (sid 33724) | 0.02 USDT | — |  |
| no_payment_challenge | Breakout Fakeout Risk API (sid 33725) | 0.02 USDT | — |  |
| no_payment_challenge | Protocol Health Score API (sid 33681) | 0.02 USDT | — |  |
| no_payment_challenge | Protocol Revenue Signal API (sid 33685) | 0.02 USDT | — |  |
| no_payment_challenge | Check Yield (sid 33550) | 0.1 USDT | — |  |
| no_payment_challenge | 美股AI半导体5分钟信号日报 (sid 39799) | 2.98 USDT | — |  |
| no_payment_challenge | Funding Rate Stress Score API (sid 33718) | 0.01 USDT | — |  |
