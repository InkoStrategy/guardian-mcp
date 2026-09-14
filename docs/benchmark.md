# Benchmark: real drain transactions vs. real legitimate approvals

Generated 2026-09-14 05:03 UTC. Every case is a real Ethereum mainnet transaction; hashes link to Etherscan.

**Attack set** (40): approve / setApprovalForAll transactions signed by real victims towards drainer addresses listed in the public ScamSniffer scam-database, located through the drainer's incoming ERC-20 loot on Blockscout. 26 listed addresses were scanned to find them.

**Control set** (30): approve transactions to canonical protocol contracts (Permit2, Uniswap V2/V3/Universal Router, 1inch v6) from recent blocks.

Two replays per case: **rules only** (local analyzer, empty registry, no ScamSniffer seed) and **as deployed** (production API with the seeded shared registry).

| | rules only | as deployed |
|---|---|---|
| Attacks blocked (DENY) | 0 / 40 (0%) | 31 / 40 (77.5%) |
| Attacks flagged (WARN) | 9 | 9 |
| Attacks missed (ALLOW) | 31 | 0 |
| Legit approvals blocked (false DENY) | 0 / 30 (0%) | 0 / 30 (0%) |
| Legit approvals warned | 19 | 19 |
| Legit approvals allowed | 11 | 11 |

WARN on a legitimate approval is expected when the approval is unlimited (`unlimited_approval`); the agent is asked to confirm or to sign the bounded `safe_alternative` instead. A false DENY is the number that matters for usability.

## Attack cases

| # | Victim tx | Victim action | Drainer | Loot | Rules only | As deployed |
|---|---|---|---|---|---|---|
| 1 | [0x83862db471…](https://etherscan.io/tx/0x83862db4717f5a2ac0132d74ac32bd42ab4a8859dc09c21533cbbfa4299a46a5) | native transfer | [0x7fb2224c…](https://etherscan.io/address/0x7fb2224cc00a8d9106ac9280abde1e2f480f4f41) | ETH | ALLOW () | DENY (scam_database_address) |
| 2 | [0x6cfccf4406…](https://etherscan.io/tx/0x6cfccf44067d98377a4c9e51663b81f5f537d976004176c5eed094c0209773a7) | native transfer | [0x7fb2224c…](https://etherscan.io/address/0x7fb2224cc00a8d9106ac9280abde1e2f480f4f41) | ETH | ALLOW () | DENY (scam_database_address) |
| 3 | [0x68930d0b7f…](https://etherscan.io/tx/0x68930d0b7f78fb575e06007f54a8a0197ba8698658c89561231a814841aaa54d) | call 0x512d7cfd | [0x9ce67dc9…](https://etherscan.io/address/0x9ce67dc9856c9f887ef5a80ae2178d5903864155) | LUNA 2.0 (lunav2.io) | WARN (unknown_selector) | WARN (unknown_selector) |
| 4 | [0xa5d977dbd5…](https://etherscan.io/tx/0xa5d977dbd52670b4f87f32f91bd8a62dda2c81d0c9949b4eae5f63652baa1bbd) | call 0x512d7cfd | [0x9ce67dc9…](https://etherscan.io/address/0x9ce67dc9856c9f887ef5a80ae2178d5903864155) | LUNA 2.0 (lunav2.io) | WARN (unknown_selector) | WARN (unknown_selector) |
| 5 | [0xe808585dd1…](https://etherscan.io/tx/0xe808585dd1aae0751d0a35806fe44b5bbe69164f5ae743f314fed95e0e665b11) | native transfer | [0x9d488e33…](https://etherscan.io/address/0x9d488e334bb32fb3f397c768ce54c50a506e6e0a) | ETH | ALLOW () | DENY (scam_database_address) |
| 6 | [0xd6fcba75d8…](https://etherscan.io/tx/0xd6fcba75d879341b70395848294068efb2bf44146e0f3779719d0e2e676c505f) | native transfer | [0x9d488e33…](https://etherscan.io/address/0x9d488e334bb32fb3f397c768ce54c50a506e6e0a) | ETH | ALLOW () | DENY (scam_database_address) |
| 7 | [0xbf1768917a…](https://etherscan.io/tx/0xbf1768917abf4b4b1237aed7856b12e088593cf9d6782b8f48104b1a2d4b696d) | native transfer | [0xe455395b…](https://etherscan.io/address/0xe455395bd3468069e0f506e22e13f61666eba36a) | ETH | ALLOW () | DENY (scam_database_address) |
| 8 | [0x9079e5b9e3…](https://etherscan.io/tx/0x9079e5b9e36bcfcd03210fdca9b309e9df81270c642c17a603b1fac334338743) | native transfer | [0xe455395b…](https://etherscan.io/address/0xe455395bd3468069e0f506e22e13f61666eba36a) | ETH | ALLOW () | DENY (scam_database_address) |
| 9 | [0x8933262058…](https://etherscan.io/tx/0x893326205835f3a68d013f7cffca461757f072437189c10c2ebc84baa5b01cf5) | native transfer | [0x97ee8829…](https://etherscan.io/address/0x97ee8829546b083b21eb47b10a9c8d440361693b) | ETH | ALLOW () | DENY (scam_database_address) |
| 10 | [0xdaf31c14bb…](https://etherscan.io/tx/0xdaf31c14bb40d6bb15d782010e0aa99c0431eef4b52a6b608cbde295e1bf37d6) | native transfer | [0x97ee8829…](https://etherscan.io/address/0x97ee8829546b083b21eb47b10a9c8d440361693b) | ETH | ALLOW () | DENY (scam_database_address) |
| 11 | [0xed1f26185f…](https://etherscan.io/tx/0xed1f26185f65aa69987ea0420e251f4c87bc2b3c6588fc96eecf5e8aee00d2d8) | native transfer | [0x40881dd5…](https://etherscan.io/address/0x40881dd5b6482854fc01d010ed99fd346f0608b1) | ETH | ALLOW () | DENY (scam_database_address) |
| 12 | [0x10804cc989…](https://etherscan.io/tx/0x10804cc989d8be4883b452e0425893efafb8dd86cbfe30f34afc9e204c446ad0) | native transfer | [0x40881dd5…](https://etherscan.io/address/0x40881dd5b6482854fc01d010ed99fd346f0608b1) | ETH | ALLOW () | DENY (scam_database_address) |
| 13 | [0x3e884fdb74…](https://etherscan.io/tx/0x3e884fdb7468c5db733e74eba491c12cbff1605bd503942be7f38f66d1066c71) | transfer | [0x9307d073…](https://etherscan.io/address/0x9307d0730bbe0e2df8f747e3f693772ad83debcb) | USDT | ALLOW () | DENY (scam_database_address) |
| 14 | [0x5210dd350e…](https://etherscan.io/tx/0x5210dd350ed4dfea9c8c6762af100732237fa65c49e85add53619b0b86fe5abf) | call 0x9a2b8115 | [0x9307d073…](https://etherscan.io/address/0x9307d0730bbe0e2df8f747e3f693772ad83debcb) | WETH | WARN (unknown_selector) | WARN (unknown_selector) |
| 15 | [0x38abf2b471…](https://etherscan.io/tx/0x38abf2b471574ea8465a37a95fa7cf8757cfafbef5a80e754f0fd25b7dd94f5c) | native transfer | [0x4721fcf9…](https://etherscan.io/address/0x4721fcf90fe83f86bffa4e5f224694299b075c32) | ETH | ALLOW () | DENY (scam_database_address) |
| 16 | [0xf46544df1d…](https://etherscan.io/tx/0xf46544df1da1b1271ab4b6f770d27a988c3ee75ac53de77a2fc49a0163778f55) | native transfer | [0x4721fcf9…](https://etherscan.io/address/0x4721fcf90fe83f86bffa4e5f224694299b075c32) | ETH | ALLOW () | DENY (scam_database_address) |
| 17 | [0x8d09f76447…](https://etherscan.io/tx/0x8d09f76447ea92c00d2e24d551fc9075a131fade521303b6d0a0a1f5a2fcc407) | native transfer | [0x7e4384ad…](https://etherscan.io/address/0x7e4384ad48860ae13107b8c8a2b877191edfe2a6) | ETH | ALLOW () | DENY (scam_database_address) |
| 18 | [0x4c54efcf00…](https://etherscan.io/tx/0x4c54efcf00d575ad1b2888633da660fb5660290fa58bb18e5e55774bea83bc2a) | native transfer | [0x7e4384ad…](https://etherscan.io/address/0x7e4384ad48860ae13107b8c8a2b877191edfe2a6) | ETH | ALLOW () | DENY (scam_database_address) |
| 19 | [0xd408a454aa…](https://etherscan.io/tx/0xd408a454aaf7971eda4c913547b83d211bbe865fc5541251830fdf826896d412) | native transfer | [0x880693f6…](https://etherscan.io/address/0x880693f6fa17395914a9c6f280f6af6eec6ea195) | ETH | ALLOW () | DENY (scam_database_address) |
| 20 | [0xef1148797d…](https://etherscan.io/tx/0xef1148797d421b050f3984828d79920509622d6a61253ea85599905c5344fc21) | native transfer | [0x880693f6…](https://etherscan.io/address/0x880693f6fa17395914a9c6f280f6af6eec6ea195) | ETH | ALLOW () | DENY (scam_database_address) |
| 21 | [0xaed88f2e49…](https://etherscan.io/tx/0xaed88f2e49effc8f3517a62d52f198b8ff03d41d7df3a19cb2a69b5b6368fbf1) | native transfer | [0x4dba22c6…](https://etherscan.io/address/0x4dba22c61b8818c94de797680840d25b1e2623b4) | ETH | ALLOW () | DENY (scam_database_address) |
| 22 | [0xaf1b274a9c…](https://etherscan.io/tx/0xaf1b274a9c03f793faf89714c29bf20670a82238be5fddf9a372c284d4891475) | native transfer | [0x4dba22c6…](https://etherscan.io/address/0x4dba22c61b8818c94de797680840d25b1e2623b4) | ETH | ALLOW () | DENY (scam_database_address) |
| 23 | [0x0703907742…](https://etherscan.io/tx/0x0703907742ae209062436274da3a02910658bd2c35d58820ce7b9d10f043326f) | native transfer | [0x2f35c798…](https://etherscan.io/address/0x2f35c7983d7bd79fbab2c58c684cd050c41abba8) | ETH | ALLOW () | DENY (scam_database_address) |
| 24 | [0x4414665ecf…](https://etherscan.io/tx/0x4414665ecf4430366c48bbda9f80371b8a937a009ff5c3addaa834e595317d2e) | native transfer | [0x2f35c798…](https://etherscan.io/address/0x2f35c7983d7bd79fbab2c58c684cd050c41abba8) | ETH | ALLOW () | DENY (scam_database_address) |
| 25 | [0x3db6497192…](https://etherscan.io/tx/0x3db6497192c70d57cc87b63206dfef4d31c7fe3fd713379b3e4bf239d2925fe4) | native transfer | [0x2cbac16b…](https://etherscan.io/address/0x2cbac16b230dd3bfa0463785977ea0ef954c4bde) | ETH | ALLOW () | DENY (scam_database_address) |
| 26 | [0x3ab349ebae…](https://etherscan.io/tx/0x3ab349ebae4eee28ad4b032ed681cbe5714dc4a157889c8690432d40e6455cdd) | native transfer | [0x92c582a5…](https://etherscan.io/address/0x92c582a59582ae1c150e69125b2ea08e7594b6c9) | ETH | ALLOW () | DENY (scam_database_address) |
| 27 | [0xb4e4707150…](https://etherscan.io/tx/0xb4e4707150785dee8bff95887328b11487c7010a033844dbd05e354abee604f5) | native transfer | [0x92c582a5…](https://etherscan.io/address/0x92c582a59582ae1c150e69125b2ea08e7594b6c9) | ETH | ALLOW () | DENY (scam_database_address) |
| 28 | [0x70d446c726…](https://etherscan.io/tx/0x70d446c7266325db773cbd6cc7c8567874613d4bb2f0fb65ba8d40eb7513181a) | native transfer | [0xcc0b488d…](https://etherscan.io/address/0xcc0b488dba202cb0945df6c49a1edd69705cb2b8) | ETH | ALLOW () | DENY (scam_database_address) |
| 29 | [0xeebd0a0439…](https://etherscan.io/tx/0xeebd0a0439a550eb62ae233af71eb4b0264fb7c3c8d54ea124a31fbaf5665edc) | native transfer | [0xcc0b488d…](https://etherscan.io/address/0xcc0b488dba202cb0945df6c49a1edd69705cb2b8) | ETH | ALLOW () | DENY (scam_database_address) |
| 30 | [0x1bc58edc4a…](https://etherscan.io/tx/0x1bc58edc4ab120a2081f967fe986983a50c27276dcf32f4d90fee312d29807b1) | call 0xb4e4b296 | [0x42b168ea…](https://etherscan.io/address/0x42b168ea09ba9f1657b5334ec1ce0f3b7d1b7de6) | WETH | WARN (unknown_selector) | WARN (unknown_selector) |
| 31 | [0x1684c10522…](https://etherscan.io/tx/0x1684c105223c951ff319e345349f8b6b8a774ab0d164ad9cfb3c473938e9c0d9) | call 0xb4e4b296 | [0x42b168ea…](https://etherscan.io/address/0x42b168ea09ba9f1657b5334ec1ce0f3b7d1b7de6) | WETH | WARN (unknown_selector) | WARN (unknown_selector) |
| 32 | [0x740dca08c3…](https://etherscan.io/tx/0x740dca08c345c20d43947d6153bad21d313cc895a6c4897f46e0ce9d34a28ab8) | native transfer | [0x013c72cf…](https://etherscan.io/address/0x013c72cfa8cd9f3291d683c579df6cfeb397a7c4) | ETH | ALLOW () | DENY (scam_database_address) |
| 33 | [0x2f7550b747…](https://etherscan.io/tx/0x2f7550b747f4baaf1a990943753ca8f96725eab1d4b6b9b9d70e0cb2f81bcd03) | native transfer | [0x013c72cf…](https://etherscan.io/address/0x013c72cfa8cd9f3291d683c579df6cfeb397a7c4) | ETH | ALLOW () | DENY (scam_database_address) |
| 34 | [0x73e2562e0e…](https://etherscan.io/tx/0x73e2562e0e71de2ae21fae1d5ab72a540ed8b8e15a3e09b4eeea3cb90fe54b34) | call 0xc204642c | [0xd3ed4e39…](https://etherscan.io/address/0xd3ed4e39917805550a3fe4bfbc02455fee945e9d) | KEY (OPENSEA-ROULETTE.IO) | WARN (unknown_selector) | WARN (unknown_selector) |
| 35 | [0x055d5a532c…](https://etherscan.io/tx/0x055d5a532c483292b1d650fb8ab8b566da71da373e0d16c99eb3e1ff35c44b2c) | native transfer | [0xd3ed4e39…](https://etherscan.io/address/0xd3ed4e39917805550a3fe4bfbc02455fee945e9d) | ETH | ALLOW () | DENY (scam_database_address) |
| 36 | [0xb60200628c…](https://etherscan.io/tx/0xb60200628ce3e47f812559248932a3af316863343bbd3d6f2cf38ae50c1f3895) | native transfer | [0x6a2142b6…](https://etherscan.io/address/0x6a2142b66b8d5c991c3699955e254a8b804d3e44) | ETH | ALLOW () | DENY (scam_database_address) |
| 37 | [0x42006bf5ce…](https://etherscan.io/tx/0x42006bf5ce0d1cae112b9dadc7dbb14da1315cfdc8084421498671918bf1e5c9) | native transfer | [0x6a2142b6…](https://etherscan.io/address/0x6a2142b66b8d5c991c3699955e254a8b804d3e44) | ETH | ALLOW () | DENY (scam_database_address) |
| 38 | [0xda7386232e…](https://etherscan.io/tx/0xda7386232e14f7d7d3bb60cb444ecee82a9cef583ebfe943ee1e58676f20aae8) | call 0x8416a693 | [0x04ee62c9…](https://etherscan.io/address/0x04ee62c90fec42d98fc21a882dcb40de70d43166) | USDC | WARN (unknown_selector) | WARN (unknown_selector) |
| 39 | [0xa7305a2f6b…](https://etherscan.io/tx/0xa7305a2f6b10c8df857e993b31768d13a6be164a6c8d29ef25b4408316a0a98f) | call 0x3fe561cf | [0x04ee62c9…](https://etherscan.io/address/0x04ee62c90fec42d98fc21a882dcb40de70d43166) | 880$ Visit https://acbonus.site to claim reward. | WARN (unknown_selector) | WARN (unknown_selector) |
| 40 | [0x7f331e2efd…](https://etherscan.io/tx/0x7f331e2efd5ee5938efb23268b703444836522b67904a020a4666512879500b1) | call 0x55a2ba68 | [0xc61248fd…](https://etherscan.io/address/0xc61248fd95d00853e04031221403b5a2275b6906) | USDC | WARN (unknown_selector) | WARN (unknown_selector) |

## Control cases

| # | Tx | Spender | Amount | Rules only | As deployed |
|---|---|---|---|---|---|
| 1 | [0xd1db7e1b29…](https://etherscan.io/tx/0xd1db7e1b2919c0ed048a910d8674bd38b4afe70fc8d3efe64b74e53e91a8ba2d) | Uniswap V3 SwapRouter02 | bounded | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 2 | [0x081ff383ce…](https://etherscan.io/tx/0x081ff383ce3a918faa4d7e516e1869cda6c957a7866ac6d742afd6c9fb623aa4) | 1inch AggregationRouter V6 | bounded | ALLOW () | ALLOW () |
| 3 | [0x41edf4a588…](https://etherscan.io/tx/0x41edf4a58833e2ac986c850c629d3be8babd3768b15f058a76e328d96e76a63b) | Permit2 | bounded | ALLOW () | ALLOW () |
| 4 | [0x202f73d9e6…](https://etherscan.io/tx/0x202f73d9e60c9ce7c66c2f72edcf4e33be8997222feb31710ec977cfcf13ee4b) | Permit2 | bounded | ALLOW () | ALLOW () |
| 5 | [0x66cd4b0f39…](https://etherscan.io/tx/0x66cd4b0f397e24898281816c50c517200b72ae23f7f180eabc98445214cdb4f2) | Permit2 | unlimited | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 6 | [0x30f0dafee8…](https://etherscan.io/tx/0x30f0dafee84d579761403adb45464e344a39f24871fdb3c1602f14b9eeb52e39) | Permit2 | unlimited | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 7 | [0xcc7b390d70…](https://etherscan.io/tx/0xcc7b390d7079bb8413f88b32d04ff9e60e226a4cad37d6fec2490eff0225b9ab) | Permit2 | unlimited | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 8 | [0x69b85cd8b8…](https://etherscan.io/tx/0x69b85cd8b8334aaa38c9c9e7ab37ebd949f5df93ed772a8ec8a79b45b1191700) | 1inch AggregationRouter V6 | bounded | ALLOW () | ALLOW () |
| 9 | [0x486932f075…](https://etherscan.io/tx/0x486932f07554f3ca3d6ee362ab6e3a92bfa01fa9c31a3a56b61cdb83766b5812) | Uniswap V3 SwapRouter02 | bounded | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 10 | [0x04c703a194…](https://etherscan.io/tx/0x04c703a194f514d39e4bb03fc4b8219839ac803259ee484dd33877fd8b9a6355) | Permit2 | unlimited | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 11 | [0x92173707cc…](https://etherscan.io/tx/0x92173707cc73f881f0b4e5b2953253d37b71382abc11b54f452a062bbd0bf777) | Permit2 | unlimited | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 12 | [0x5cac04ecdb…](https://etherscan.io/tx/0x5cac04ecdb9f0eef63d4282710e3e765bb6106c4581c6314c2611f8ec7572b2f) | Permit2 | bounded | ALLOW () | ALLOW () |
| 13 | [0x0fe392336e…](https://etherscan.io/tx/0x0fe392336ea274ad876a94f0d3d6997d1d6a87a196397d426f448acded8fbe25) | Uniswap V3 SwapRouter02 | bounded | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 14 | [0xcf62b9c950…](https://etherscan.io/tx/0xcf62b9c950ae326e6257eb4e71f7cde9e506ac193b551419cbc03f6d1870df7f) | Uniswap V3 SwapRouter02 | bounded | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 15 | [0xda14a5a85d…](https://etherscan.io/tx/0xda14a5a85dc2f85a35a0a8d807abcdaa30d04c24bda90b9b496510985d243ac2) | Permit2 | unlimited | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 16 | [0xc6dfd4e06a…](https://etherscan.io/tx/0xc6dfd4e06ab55d590bbba3edc0dfb48cd4382cfd48cfc58cb3de3cab4c38af26) | Permit2 | unlimited | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 17 | [0x5b8c4edcdc…](https://etherscan.io/tx/0x5b8c4edcdc2574b49630badd1b84e53d248c7d2b07dc4836e5ed22f4f39cb12f) | Permit2 | bounded | ALLOW () | ALLOW () |
| 18 | [0x54a7e00a7f…](https://etherscan.io/tx/0x54a7e00a7fd0afae17177bc29d03b4c6e76f8438031da406388dadd81b8ff38b) | Uniswap V3 SwapRouter02 | bounded | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 19 | [0xf3525b5652…](https://etherscan.io/tx/0xf3525b56520864538a970d64b374d0b84788bea4d9d6b552e85a666c2173fe14) | 1inch AggregationRouter V6 | bounded | ALLOW () | ALLOW () |
| 20 | [0x9b4298c880…](https://etherscan.io/tx/0x9b4298c88042517f5a5f9a5a119ad71650540b0e99ab476333a28a177d4ac3fb) | Permit2 | unlimited | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 21 | [0x5baa47823a…](https://etherscan.io/tx/0x5baa47823abc74f95300563dfc063a75f979704a0ffd11a5085f35958d5a7851) | 1inch AggregationRouter V6 | bounded | ALLOW () | ALLOW () |
| 22 | [0x7d7e414e2d…](https://etherscan.io/tx/0x7d7e414e2dbc5f451154bcd535ed6220fce0296eef72074990bb1838a8fd8aad) | Uniswap V3 SwapRouter02 | bounded | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 23 | [0x132bdfa397…](https://etherscan.io/tx/0x132bdfa397d2fb72e72cade4e2f5158e09bb4e0abd751d143d2357446c35a79d) | Permit2 | unlimited | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 24 | [0xa221a2d35a…](https://etherscan.io/tx/0xa221a2d35a7030256e068419aeff64f994f617fe7b25b8accb869d04211a9d50) | Uniswap V3 SwapRouter02 | bounded | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 25 | [0x03ab2747d2…](https://etherscan.io/tx/0x03ab2747d21e38270c9959ce837e2a9525f4ce66b7e1ab468556b3e239fe0e70) | Uniswap V3 SwapRouter02 | bounded | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 26 | [0x99d5e72051…](https://etherscan.io/tx/0x99d5e720513657f8d116f66b38a4e07c005556bdcde7e55d4ec59a527e4567c0) | Permit2 | bounded | ALLOW () | ALLOW () |
| 27 | [0xea8a045724…](https://etherscan.io/tx/0xea8a045724f6e2d5c8a7838dae0d32791d7da2f259a53b6c25003c7cc2f59516) | Permit2 | unlimited | WARN (unlimited_approval) | WARN (unlimited_approval) |
| 28 | [0x65a256fa57…](https://etherscan.io/tx/0x65a256fa5713fe2f0da99c54088e91b6846ece3175d7d106125f4a398ed8fe8f) | Uniswap V3 SwapRouter02 | bounded | ALLOW () | ALLOW () |
| 29 | [0x6002d15030…](https://etherscan.io/tx/0x6002d150309ccea110bb60f6883cfb9dc53720e9b0ad9ccd8fcb694a3b3a715f) | Permit2 | bounded | ALLOW () | ALLOW () |
| 30 | [0x34c92486c7…](https://etherscan.io/tx/0x34c92486c730da28fc2a00676c71290fbb28cce498040222625ab00de01193b5) | Permit2 | unlimited | WARN (unlimited_approval) | WARN (unlimited_approval) |

## Method and limits

- Attack cases are the victim-signed transactions that delivered the funds (transfers, native sends, calls to drainer contracts), which is exactly the moment Guardian is meant to intervene. Drainer-signed transferFrom pulls are excluded because the victim never sees them.
- The ScamSniffer list is also the seed of the shared registry, so the "as deployed" column includes registry hits by construction; the "rules only" column shows what the deterministic rules catch without any list.
- Sampling is by list order (newest entries first) and by whatever Blockscout returns; it is not a random sample of all drains and says nothing about drains that used permits, Permit2 or signatures.
- Replays carry no `from` (simulation would run against the current state, not the historical one) and no `session_id` (the session stop signal would otherwise cascade across unrelated cases); the numbers measure transaction rules and registries only.
- Reproduce: `node scripts/benchmark.js`. Raw data: `docs/benchmark.json`.
