# OKX.AI Pay-Safe trust scan

Generated 2026-09-17T20:41:20.476Z. One unpaid request per endpoint to capture the x402 challenge; Pay-Safe /check-payment against the listing. No payments, no signatures.

| Metric | Count |
|---|---|
| services | 67 |
| challenge | 29 |
| allow | 16 |
| warn | 13 |
| deny | 0 |
| no_challenge | 34 |
| unreachable | 4 |
| invalid | 0 |

## Reasons

| Rule | Services |
|---|---|
| `eip712_domain_mismatch` | 7 |
| `fresh_recipient` | 4 |
| `endpoint_domain_suspicious` | 2 |

## Findings

- **WARN fresh_recipient** in Market News (sid 40011): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in Crypto Top / Bottom, Signal (sid 19874): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in Commodity Top & Bottom Signal (sid 34606): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in Korea Stock Top/Bottom Signal (sid 34176): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in US Stock Top / Bottom Signal (sid 34150): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN endpoint_domain_suspicious** in Fusion Strategy Analysis (sid 33556): okxaiagent.vercel.app matches a phishing pattern (brand_impersonation): Hostname contains the brand "okx" but is not an official okx domain. It is the endpoint named in the listing.
- **WARN fresh_recipient** in SC Security & Legal Audit (sid 38037): 0xC8a8973Cf7FE41bDC9a85f70C279c9Bdc2EB8D0C has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Company Research (sid 40010): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Smart Money (sid 40012): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN endpoint_domain_suspicious** in 网站 SEO 健康检查 (sid 40665): okx-seo-ai.vercel.app matches a phishing pattern (brand_impersonation): Hostname contains the brand "okx" but is not an official okx domain. It is the endpoint named in the listing.
- **WARN eip712_domain_mismatch** in RoseIntel Evidence API (sid 17723): extra declares the EIP-712 domain name "USD₮0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in Token Unlock Risk Check (sid 35287): extra declares the EIP-712 domain name "USDT" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in DAO Treasury Infographic Pack (sid 35305): extra declares the EIP-712 domain name "USDT" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.

## Services

| Verdict | Service | Listed | Challenge | Reasons |
|---|---|---|---|---|
| WARN | Market News (sid 40011) | 0.02 USDT | 0.02 USDT0 on eip155:196 | fresh_recipient |
| WARN | Crypto Top / Bottom, Signal (sid 19874) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Commodity Top & Bottom Signal (sid 34606) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Korea Stock Top/Bottom Signal (sid 34176) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | US Stock Top / Bottom Signal (sid 34150) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Fusion Strategy Analysis (sid 33556) | 1 USDT | 0.01 USDT0 on eip155:196 | endpoint_domain_suspicious |
| WARN | SC Security & Legal Audit (sid 38037) | 10 USDT | 10 USDT0 on eip155:196 | fresh_recipient |
| WARN | Company Research (sid 40010) | 0.05 USDT | 0.05 USDT0 on eip155:196 | fresh_recipient |
| WARN | Smart Money (sid 40012) | 0.03 USDT | 0.03 USDT0 on eip155:196 | fresh_recipient |
| WARN | 网站 SEO 健康检查 (sid 40665) | 0.01 USDT | 0.01 USDT0 on eip155:196 | endpoint_domain_suspicious |
| WARN | RoseIntel Evidence API (sid 17723) | 0.5 USDT | 0.5 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Token Unlock Risk Check (sid 35287) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | DAO Treasury Infographic Pack (sid 35305) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| ALLOW | Marketplace Niche Scan (sid 33278) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | MoonFinder 市场信号扫描 (sid 25864) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | 美股市场研究 (sid 39937) | 0.5 USDT | 0.5 USDT0 on eip155:196 |  |
| ALLOW | 加密与 Meme 市场研究 (sid 39938) | 0.5 USDT | 0.5 USDT0 on eip155:196 |  |
| ALLOW | Ecosystem Fit Analyzer (sid 39139) | 2 USDT | 2 USDT0 on eip155:196 |  |
| ALLOW | Token DD Verdict (sid 11171) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| ALLOW | Meme 交易情报扫描 (sid 33200) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | 冲前风险检查卡 (sid 35351) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | HANGANG Korea GTM Intelligence (sid 34080) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | 聪明钱共振信心分报告 (sid 30379) | 0.005 USDT | 0.005 USDT0 on eip155:196 |  |
| ALLOW | 钱包签名风险提醒 (sid 35352) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | URL Change Check API (sid 39856) | 0.005 USDT | 0.005 USDT0 on eip155:196 |  |
| ALLOW | Listing Format Preflight (sid 33279) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| ALLOW | Project Failure Autopsy (sid 40042) | 0.5 USDT | 0.5 USDT0 on eip155:196 |  |
| ALLOW | Bounded OPEN Card (sid 36109) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| ALLOW | Bounded Manager Card (sid 36366) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| no_payment_challenge | Crypto Market Context Feed (sid 7494) | 0.1 USDT | — |  |
| no_payment_challenge | Governed market signal (sid 39343) | 0.01 USDT | — |  |
| no_payment_challenge | X Layer AMM 深度分析 (sid 38787) | 0.01 USDT | — |  |
| no_payment_challenge | X Layer Token Analysis (sid 39824) | 0.05 USDT | — |  |
| no_payment_challenge | 美股与ETF牛气趋势分析 (sid 39551) | 0.1 USDT | — |  |
| no_payment_challenge | X Layer Wallet Activity (sid 39848) | 0.05 USDT | — |  |
| unreachable | Token Risk Analysis (sid 40014) | 1 USDT | — | timeout |
| no_payment_challenge | Risk Guard (sid 36550) | 0.2 USDT | — |  |
| no_payment_challenge | Token Security Scan (sid 16632) | 0.03 USDT | — |  |
| no_payment_challenge | Wallet Reputation (sid 16633) | 0.01 USDT | — |  |
| no_payment_challenge | MistEye Security Gate Scan (sid 17126) | 0.0001 USDT | — |  |
| unreachable | AI Security Copilot Router (sid 34987) | 1 USDT | — | timeout |
| no_payment_challenge | Global Quick → Spot (sid 36548) | 0.2 USDT | — |  |
| no_payment_challenge | Global Pro → Spot (sid 36549) | 0.3 USDT | — |  |
| no_payment_challenge | Verified Public Evidence Brief (sid 38271) | 0.2 USDT | — |  |
| no_payment_challenge | Crypto Calendar 加密日历 (sid 38009) | 0.03 USDT | — |  |
| no_payment_challenge | Portfolio Health (sid 16634) | 0.01 USDT | — |  |
| no_payment_challenge | Wallet Risk Allowance Audit (sid 34986) | 1 USDT | — |  |
| no_payment_challenge | Custos Decision Engine (sid 36308) | 0.01 USDT | — |  |
| no_payment_challenge | Prediction Quick (sid 36551) | 0.2 USDT | — |  |
| no_payment_challenge | Prediction Pro (sid 40590) | 0.3 USDT | — |  |
| no_payment_challenge | Health Check (sid 3053) | 0.000001 USDT | — |  |
| no_payment_challenge | Service List (sid 3054) | 0.000001 USDT | — |  |
| no_payment_challenge | Poker Eval Open (sid 39196) | 3 USDT | — |  |
| no_payment_challenge | Check Yield (sid 33550) | 0.1 USDT | — |  |
| no_payment_challenge | EVM Transaction Guardrail (sid 34985) | 1 USDT | — |  |
| no_payment_challenge | Landing Page (sid 39940) | 25 USDT | — |  |
| no_payment_challenge | AI饮食运动助手 (sid 30754) | 0.01 USDT | — |  |
| unreachable | Consumer Risk Report (sid 36025) | 0.05 USDT | — | timeout |
| unreachable | 草台班子检测器 (sid 29539) | 0.05 USDT | — | fetch failed |
| no_payment_challenge | 美股AI半导体5分钟信号日报 (sid 39799) | 2.98 USDT | — |  |
| no_payment_challenge | Bubble Image (sid 3055) | 0.5 USDT | — |  |
| no_payment_challenge | Start Autopilot 24h (sid 40591) | 1.5 USDT | — |  |
| no_payment_challenge | X Layer Uniswap 池子参与者 (sid 38749) | 0.05 USDT | — |  |
| no_payment_challenge | X Layer Uniswap 交易对池子查询 (sid 26673) | 0.1 USDT | — |  |
| no_payment_challenge | X Layer Uniswap 地址做市盈亏 (sid 38905) | 0.5 USDT | — |  |
| no_payment_challenge | X Layer Uniswap NFT 仓位收益 (sid 38955) | 0.05 USDT | — |  |
| no_payment_challenge | X Layer Contract Risk Scanner (sid 39842) | 0.05 USDT | — |  |
