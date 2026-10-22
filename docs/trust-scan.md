# OKX.AI Pay-Safe trust scan

Generated 2026-10-22T08:01:13.877Z. One unpaid request per endpoint to capture the x402 challenge; Pay-Safe /check-payment against the listing. No payments, no signatures.

| Metric | Count |
|---|---|
| services | 72 |
| challenge | 18 |
| allow | 12 |
| warn | 6 |
| deny | 0 |
| no_challenge | 52 |
| unreachable | 2 |
| invalid | 0 |

## Reasons

| Rule | Services |
|---|---|
| `fresh_recipient` | 3 |
| `eip712_domain_mismatch` | 2 |
| `endpoint_domain_suspicious` | 1 |

## Findings

- **WARN fresh_recipient** in Closure Discount by Duration (sid 40894): 0x277cA91276A3801667B76C97Da3872Ccb6E96068 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Entropy Signal API (sid 40780): 0x19f090a52a6fa82640442D7eed7eB9ce5f5cf9ED has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN endpoint_domain_suspicious** in Fusion Strategy Analysis (sid 33556): okxaiagent.vercel.app matches a phishing pattern (brand_impersonation): Hostname contains the brand "okx" but is not an official okx domain. It is the endpoint named in the listing.
- **WARN fresh_recipient** in Asset Correlation Matrix (sid 41691): 0x19f090a52a6fa82640442D7eed7eB9ce5f5cf9ED has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in Crypto Top / Bottom, Signal (sid 19874): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in RoseIntel Evidence API (sid 17723): extra declares the EIP-712 domain name "USD₮0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.

## Services

| Verdict | Service | Listed | Challenge | Reasons |
|---|---|---|---|---|
| WARN | Closure Discount by Duration (sid 40894) | 0.1 USDT | 0.1 USDT0 on eip155:196 | fresh_recipient |
| WARN | Entropy Signal API (sid 40780) | 0.02 USDT | 0.02 USDT0 on eip155:196 | fresh_recipient |
| WARN | Fusion Strategy Analysis (sid 33556) | 1 USDT | 0.01 USDT0 on eip155:196 | endpoint_domain_suspicious |
| WARN | Asset Correlation Matrix (sid 41691) | 0.02 USDT | 0.02 USDT0 on eip155:196 | fresh_recipient |
| WARN | Crypto Top / Bottom, Signal (sid 19874) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | RoseIntel Evidence API (sid 17723) | 0.5 USDT | 0.5 USDT0 on eip155:196 | eip712_domain_mismatch |
| ALLOW | Market Regime Read (sid 16720) | 0.02 USDT | 0.02 USDT0 on eip155:196 |  |
| ALLOW | MoonFinder 市场信号扫描 (sid 25864) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | Token DD Verdict (sid 11171) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| ALLOW | Perp Trade-Call Verdict (sid 16719) | 0.02 USDT | 0.02 USDT0 on eip155:196 |  |
| ALLOW | DeFi Opportunity Rank API (sid 33686) | 0.03 USDT | 0.03 USDT0 on eip155:196 |  |
| ALLOW | Yield Pool Risk Score API (sid 33682) | 0.03 USDT | 0.03 USDT0 on eip155:196 |  |
| ALLOW | 钱包签名风险提醒 (sid 35352) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | URL Change Check API (sid 39856) | 0.005 USDT | 0.005 USDT0 on eip155:196 |  |
| ALLOW | TradeDesk 指标体验引流 (sid 39830) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | TxPreflight Onchain Tx Guard (sid 40832) | 0.04 USDT | 0.04 USDT0 on eip155:196 |  |
| ALLOW | 草台班子检测器 (sid 29539) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| ALLOW | Waypoint Plan (sid 41342) | 0.02 USDT | 0.02 USDT0 on eip155:196 |  |
| no_payment_challenge | Luc Market Regime (sid 41586) | 0.1 USDT | — |  |
| no_payment_challenge | Technical Indicators (sid 41550) | 0.001 USDT | — |  |
| no_payment_challenge | X Layer Token Analysis (sid 39824) | 0.05 USDT | — |  |
| no_payment_challenge | X Layer Wallet Activity (sid 39848) | 0.05 USDT | — |  |
| no_payment_challenge | Luc Correlation State (sid 41590) | 0.1 USDT | — |  |
| unreachable | Onchain Risk Analysis (sid 34778) | 0.5 USDT | — | timeout |
| no_payment_challenge | Token Security Pulse (sid 40595) | 0.01 USDT | — |  |
| unreachable | Token Risk Analysis (sid 40014) | 1 USDT | — | timeout |
| no_payment_challenge | Spot Futures Basis (sid 41185) | 0.01 USDT | — |  |
| no_payment_challenge | URL Drain Risk API (sid 32686) | 0.02 USDT | — |  |
| no_payment_challenge | Address Trust Check API (sid 32683) | 0.01 USDT | — |  |
| no_payment_challenge | Approval Exposure Check API (sid 32682) | 0.02 USDT | — |  |
| no_payment_challenge | Token Tradeability Check API (sid 32684) | 0.03 USDT | — |  |
| no_payment_challenge | Preflight Risk Check API (sid 32681) | 0.01 USDT | — |  |
| no_payment_challenge | MistEye Security Gate Scan (sid 17126) | 0.0001 USDT | — |  |
| no_payment_challenge | Stablecoin Peg Risk API (sid 33683) | 0.02 USDT | — |  |
| no_payment_challenge | Luc Trend State (sid 41587) | 0.1 USDT | — |  |
| no_payment_challenge | Luc Daily Asset Brief (sid 41549) | 0.1 USDT | — |  |
| no_payment_challenge | RWA Research Report (sid 40671) | 0.25 USDT | — |  |
| no_payment_challenge | Luc Drawdown & Recovery (sid 41589) | 0.1 USDT | — |  |
| no_payment_challenge | Chain Momentum API (sid 33684) | 0.01 USDT | — |  |
| no_payment_challenge | Custos Decision Engine (sid 36308) | 0.01 USDT | — |  |
| no_payment_challenge | Open Interest Anomaly API (sid 33719) | 0.02 USDT | — |  |
| no_payment_challenge | Long Short Crowding API (sid 33720) | 0.01 USDT | — |  |
| no_payment_challenge | Liquidation Risk Pulse API (sid 33721) | 0.03 USDT | — |  |
| no_payment_challenge | Volatility Regime Score API (sid 33722) | 0.02 USDT | — |  |
| no_payment_challenge | Protocol Health Score API (sid 33681) | 0.02 USDT | — |  |
| no_payment_challenge | API Response Regression Diff (sid 41231) | 0.01 USDT | — |  |
| no_payment_challenge | Protocol Revenue Signal API (sid 33685) | 0.02 USDT | — |  |
| no_payment_challenge | Structured Data Chart (sid 41247) | 0.01 USDT | — |  |
| no_payment_challenge | OHLCV Data Gap Check (sid 41189) | 0.01 USDT | — |  |
| no_payment_challenge | Check Yield (sid 33550) | 0.1 USDT | — |  |
| no_payment_challenge | AI饮食运动助手 (sid 30754) | 0.01 USDT | — |  |
| no_payment_challenge | X Layer Contract Risk Scanner (sid 39842) | 0.05 USDT | — |  |
| no_payment_challenge | 美股AI半导体5分钟信号日报 (sid 39799) | 2.98 USDT | — |  |
| no_payment_challenge | Candlestick Chart Image (sid 41191) | 0.01 USDT | — |  |
| no_payment_challenge | Image Layer Composition (sid 41250) | 0.01 USDT | — |  |
| no_payment_challenge | Image Metadata Remover (sid 41244) | 0.01 USDT | — |  |
| no_payment_challenge | Audio Waveform Image (sid 41261) | 0.1 USDT | — |  |
| no_payment_challenge | Target Size Image Compressor (sid 41243) | 0.01 USDT | — |  |
| no_payment_challenge | Image Batch Convert Resize (sid 41242) | 0.01 USDT | — |  |
| no_payment_challenge | Near Duplicate Image Finder (sid 41245) | 0.01 USDT | — |  |
| no_payment_challenge | Social Preview Validator (sid 41209) | 0.01 USDT | — |  |
| no_payment_challenge | Visual Page Comparison (sid 41204) | 0.03 USDT | — |  |
| no_payment_challenge | QR Code Generator Checker (sid 41249) | 0.01 USDT | — |  |
| no_payment_challenge | Funding Rate Comparison (sid 41184) | 0.01 USDT | — |  |
| no_payment_challenge | Realized Volatility (sid 41187) | 0.01 USDT | — |  |
| no_payment_challenge | Candle Resampling (sid 41190) | 0.01 USDT | — |  |
| no_payment_challenge | Technical Indicator Report (sid 41182) | 0.01 USDT | — |  |
| no_payment_challenge | Cross-Asset Correlation (sid 41188) | 0.01 USDT | — |  |
| no_payment_challenge | Volume Anomaly Detection (sid 41186) | 0.01 USDT | — |  |
| no_payment_challenge | Order Book Slippage (sid 41183) | 0.01 USDT | — |  |
| no_payment_challenge | Asset Identifier (sid 40673) | 0.08 USDT | — |  |
| no_payment_challenge | RWA Asset Comparison (sid 40672) | 0.5 USDT | — |  |
