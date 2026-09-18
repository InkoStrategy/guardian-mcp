# OKX.AI Pay-Safe trust scan

Generated 2026-09-18T20:04:51.091Z. One unpaid request per endpoint to capture the x402 challenge; Pay-Safe /check-payment against the listing. No payments, no signatures.

| Metric | Count |
|---|---|
| services | 80 |
| challenge | 38 |
| allow | 24 |
| warn | 14 |
| deny | 0 |
| no_challenge | 42 |
| unreachable | 0 |
| invalid | 0 |

## Reasons

| Rule | Services |
|---|---|
| `eip712_domain_mismatch` | 7 |
| `fresh_recipient` | 6 |
| `endpoint_domain_suspicious` | 1 |

## Findings

- **WARN fresh_recipient** in Market News (sid 40011): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Sniffer Alpha Feed (sid 34716): 0x94D53c7814Be8D40f9196551bC598DDce47F686C has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in Commodity Top & Bottom Signal (sid 34606): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in Crypto Top / Bottom, Signal (sid 19874): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in Korea Stock Top/Bottom Signal (sid 34176): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN fresh_recipient** in Entropy Signal API (sid 40780): 0x19f090a52a6fa82640442D7eed7eB9ce5f5cf9ED has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in US Stock Top / Bottom Signal (sid 34150): extra declares the EIP-712 domain name "USDT₀" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN endpoint_domain_suspicious** in Fusion Strategy Analysis (sid 33556): okxaiagent.vercel.app matches a phishing pattern (brand_impersonation): Hostname contains the brand "okx" but is not an official okx domain. It is the endpoint named in the listing.
- **WARN fresh_recipient** in Company Research (sid 40010): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in SC Security & Legal Audit (sid 38037): 0xC8a8973Cf7FE41bDC9a85f70C279c9Bdc2EB8D0C has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN fresh_recipient** in Smart Money (sid 40012): 0x7347860D9F0e917e4523021Df909C0D1c5D41826 has no transaction history and zero balance. Verify it out-of-band; typos and address poisoning look exactly like this.
- **WARN eip712_domain_mismatch** in RoseIntel Evidence API (sid 17723): extra declares the EIP-712 domain name "USD₮0" version "2", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in Token Unlock Risk Check (sid 35287): extra declares the EIP-712 domain name "USDT" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.
- **WARN eip712_domain_mismatch** in DAO Treasury Infographic Pack (sid 35305): extra declares the EIP-712 domain name "USDT" version "1", but the USDT0 contract on xlayer uses name "USD₮0" version "1" (its DOMAIN_SEPARATOR 0xd591d9ba… matches only that pair). A TransferWithAuthorization signed with the declared domain will not verify on-chain.

## Services

| Verdict | Service | Listed | Challenge | Reasons |
|---|---|---|---|---|
| WARN | Market News (sid 40011) | 0.02 USDT | 0.02 USDT0 on eip155:196 | fresh_recipient |
| WARN | Sniffer Alpha Feed (sid 34716) | 0.39 USDT | 0.39 USDT0 on eip155:196 | fresh_recipient |
| WARN | Commodity Top & Bottom Signal (sid 34606) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Crypto Top / Bottom, Signal (sid 19874) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Korea Stock Top/Bottom Signal (sid 34176) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Entropy Signal API (sid 40780) | 0.02 USDT | 0.02 USDT0 on eip155:196 | fresh_recipient |
| WARN | US Stock Top / Bottom Signal (sid 34150) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Fusion Strategy Analysis (sid 33556) | 1 USDT | 0.01 USDT0 on eip155:196 | endpoint_domain_suspicious |
| WARN | Company Research (sid 40010) | 0.05 USDT | 0.05 USDT0 on eip155:196 | fresh_recipient |
| WARN | SC Security & Legal Audit (sid 38037) | 10 USDT | 10 USDT0 on eip155:196 | fresh_recipient |
| WARN | Smart Money (sid 40012) | 0.03 USDT | 0.03 USDT0 on eip155:196 | fresh_recipient |
| WARN | RoseIntel Evidence API (sid 17723) | 0.5 USDT | 0.5 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | Token Unlock Risk Check (sid 35287) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| WARN | DAO Treasury Infographic Pack (sid 35305) | 0.01 USDT | 0.01 USDT0 on eip155:196 | eip712_domain_mismatch |
| ALLOW | Marketplace Niche Scan (sid 33278) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Japan Market Ledger (sid 38405) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | 美股市场研究 (sid 39937) | 0.5 USDT | 0.5 USDT0 on eip155:196 |  |
| ALLOW | MoonFinder 市场信号扫描 (sid 25864) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | 加密与 Meme 市场研究 (sid 39938) | 0.5 USDT | 0.5 USDT0 on eip155:196 |  |
| ALLOW | Korea Defense Chain Analysis (sid 35435) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Korea Power Chain Analysis (sid 35436) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Crypto analysis team (sid 36980) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | 交易洞察分析 (sid 36394) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | 玄学智慧投研 (sid 36392) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Token DD Verdict (sid 11171) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| ALLOW | Meme 交易情报扫描 (sid 33200) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | 冲前风险检查卡 (sid 35351) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | Candlestick Star (sid 36978) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | HANGANG Korea GTM Intelligence (sid 34080) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Blockchain Trend Content (sid 34742) | 1 USDT | 1 USDT0 on eip155:196 |  |
| ALLOW | 聪明钱共振信心分报告 (sid 30379) | 0.005 USDT | 0.005 USDT0 on eip155:196 |  |
| ALLOW | 钱包签名风险提醒 (sid 35352) | 0.01 USDT | 0.01 USDT0 on eip155:196 |  |
| ALLOW | URL Change Check API (sid 39856) | 0.005 USDT | 0.005 USDT0 on eip155:196 |  |
| ALLOW | Listing Format Preflight (sid 33279) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| ALLOW | 草台班子检测器 (sid 29539) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| ALLOW | Bounded OPEN Card (sid 36109) | 0.05 USDT | 0.05 USDT0 on eip155:196 |  |
| ALLOW | Bounded Manager Card (sid 36366) | 0.1 USDT | 0.1 USDT0 on eip155:196 |  |
| ALLOW | Ecosystem Fit Analyzer (sid 39139) | 2 USDT | 2 USDT0 on eip155:196 |  |
| no_payment_challenge | Facebook市场商品 (sid 40752) | 0.05 USDT | — |  |
| no_payment_challenge | Facebook市场详情 (sid 40758) | 0.08 USDT | — |  |
| no_payment_challenge | Governed market signal (sid 39343) | 0.01 USDT | — |  |
| no_payment_challenge | Crypto Market Context Feed (sid 7494) | 0.1 USDT | — |  |
| no_payment_challenge | DEX Pair Health Scan (sid 40013) | 1 USDT | — |  |
| no_payment_challenge | 美股AI半导体5分钟信号日报 (sid 39799) | 2.98 USDT | — |  |
| no_payment_challenge | X Layer Token Analysis (sid 39824) | 0.05 USDT | — |  |
| no_payment_challenge | Token Risk Analysis (sid 40014) | 1 USDT | — |  |
| no_payment_challenge | Token Security Scan (sid 16632) | 0.03 USDT | — |  |
| no_payment_challenge | Wallet Reputation (sid 16633) | 0.01 USDT | — |  |
| no_payment_challenge | Sniffer Deep Report (sid 34718) | 1.99 USDT | — |  |
| no_payment_challenge | Sniffer Risk Check (sid 34717) | 0.1 USDT | — |  |
| no_payment_challenge | MistEye Security Gate Scan (sid 17126) | 0.0001 USDT | — |  |
| no_payment_challenge | AI Security Copilot Router (sid 34987) | 1 USDT | — |  |
| no_payment_challenge | Verified Public Evidence Brief (sid 38271) | 0.2 USDT | — |  |
| no_payment_challenge | Crypto Calendar 加密日历 (sid 38009) | 0.03 USDT | — |  |
| no_payment_challenge | TikTok话题视频链接 (sid 40507) | 0.05 USDT | — |  |
| no_payment_challenge | Zillow房源介绍 (sid 40519) | 0.05 USDT | — |  |
| no_payment_challenge | Booking住宿评价 (sid 40533) | 0.05 USDT | — |  |
| no_payment_challenge | Instagram粉丝样本 (sid 40735) | 0.06 USDT | — |  |
| no_payment_challenge | Instagram用户搜索 (sid 40530) | 0.05 USDT | — |  |
| no_payment_challenge | Amazon分类商品详情 (sid 40757) | 0.06 USDT | — |  |
| no_payment_challenge | Portfolio Health (sid 16634) | 0.01 USDT | — |  |
| no_payment_challenge | Wallet Risk Allowance Audit (sid 34986) | 1 USDT | — |  |
| no_payment_challenge | X Layer Wallet Activity (sid 39848) | 0.05 USDT | — |  |
| no_payment_challenge | Custos Decision Engine (sid 36308) | 0.01 USDT | — |  |
| no_payment_challenge | Health Check (sid 3053) | 0.000001 USDT | — |  |
| no_payment_challenge | Service List (sid 3054) | 0.000001 USDT | — |  |
| no_payment_challenge | Poker Eval Open (sid 39196) | 3 USDT | — |  |
| no_payment_challenge | Check Yield (sid 33550) | 0.1 USDT | — |  |
| no_payment_challenge | EVM Transaction Guardrail (sid 34985) | 1 USDT | — |  |
| no_payment_challenge | Transaction Policy Gate (sid 39175) | 0.02 USDT | — |  |
| no_payment_challenge | AI饮食运动助手 (sid 30754) | 0.01 USDT | — |  |
| no_payment_challenge | Consumer Risk Report (sid 36025) | 0.05 USDT | — |  |
| no_payment_challenge | Project Failure Autopsy (sid 40042) | 0.5 USDT | — |  |
| no_payment_challenge | Bubble Image (sid 3055) | 0.5 USDT | — |  |
| no_payment_challenge | X Layer AMM 深度分析 (sid 38787) | 0.01 USDT | — |  |
| no_payment_challenge | X Layer Uniswap 池子参与者 (sid 38749) | 0.05 USDT | — |  |
| no_payment_challenge | X Layer Uniswap 交易对池子查询 (sid 26673) | 0.1 USDT | — |  |
| no_payment_challenge | X Layer Uniswap 地址做市盈亏 (sid 38905) | 0.5 USDT | — |  |
| no_payment_challenge | X Layer Uniswap NFT 仓位收益 (sid 38955) | 0.05 USDT | — |  |
| no_payment_challenge | X Layer Uniswap LP 收益与资金排行榜 (sid 39030) | 0.1 USDT | — |  |
