# Guardian MCP

Система контроля целостности AI‑агента для on‑chain действий. Принимает транзакцию (`to` + `data`) или запрос
на подпись и, опционально, контекст агента. Возвращает вердикт **ALLOW / WARN / DENY**, причины, риск‑скор 0–100,
однострочное объяснение на человеческом языке, рекомендации и, где возможно, готовую безопасную замену
транзакции. Готов к публикации как A2MCP‑сервис на OKX.AI, поддерживает платежи x402 (по умолчанию выключены,
сервис бесплатный).

Восемь слоёв защиты, все детерминированные, без внешних API (только RPC):

| Слой | Что делает |
|---|---|
| **Transaction firewall** | Безлимитные approve, approve на кошелёк, `setApprovalForAll`, нулевой адрес, свежий получатель, неизвестный селектор, calldata на кошелёк |
| **Nested calls** | Разбирает `multicall`, Uniswap Universal Router `execute` (план команд), `sweepToken` / `unwrapWETH9` / `exactInput*` / V2‑свопы. Видит approve, спрятанный в multicall, Permit2‑permit на чужой spender и вывод результата свопа третьему лицу |
| **Counterparty intel** | Реестр 48 канонических контрактов и 29 токенов по 9 сетям, on‑chain `symbol/decimals/name`, определение EIP‑1967 / EIP‑1167 прокси и «пустых» контрактов, безлимитный approve на нераспознанный контракт |
| **Address poisoning** | Получатель или spender, совпадающий по первым и последним символам с адресом из адресной книги агента (`context.known_addresses`) или с адресом из реестра, но отличающийся в середине |
| **Simulation** | При наличии `from`: `eth_call` с расшифровкой причины revert (`Error(string)`, `Panic`, custom error), `eth_estimateGas`, проверка баланса и текущего allowance |
| **Signature analysis** | `POST /analyze-signature`: ERC‑2612 permit, Permit2 (`PermitSingle`, `PermitBatch`, `PermitTransferFrom`), ордера Seaport с нулевым consideration, слепая подпись хэша, `eth_sign`, SIWE с фишингового домена |
| **Intent verification** | Соответствует ли действие заявленной цели агента (`context.agent_goal`); эскалация read‑only агента до approve/transfer |
| **Context & runtime** | Недоверенные и фишинговые источники перед транзакцией (белый список, тайпосквоттинг, гомоглифы, punycode, TLD), `web_fetch` прямо перед подписанием, накопление недоверенных доменов за сессию |

## API

### `POST /analyze`

| Поле      | Тип                  | Обязательно | Описание |
|-----------|----------------------|-------------|----------|
| `to`      | string               | да          | Адрес назначения транзакции, `0x` + 40 hex. Смешанный регистр проверяется по EIP‑55 |
| `data`    | string               | нет         | Calldata, `0x`‑hex. Пусто или `0x` = нативный перевод |
| `chainId` | number \| string     | нет         | По умолчанию `1`. Поддерживаются: 1, 10, 56, 137, 196, 250, 8453, 42161, 43114 |
| `value`   | string \| number     | нет         | Сумма нативной монеты в wei. По умолчанию `0` |
| `from`    | string               | нет         | Адрес отправителя. Включает симуляцию `eth_call`, оценку газа, проверку баланса и allowance. Без него эти проверки не выполняются и `details.simulation.ran = false` |
| `context` | object               | нет         | Контекст агента (см. ниже). Без него сервис работает как firewall, `details.context_analyzed = false` |

Поля `context` (все опциональны):

| Поле                | Тип       | Описание |
|---------------------|-----------|----------|
| `agent_goal`        | string    | Цель: `swap tokens`, `transfer`, `approve`, `mint`, `read` / `analyze`, `unknown`. Понимает синонимы |
| `recent_sources`    | string[]  | Источники, которые агент недавно читал: URL, `api:coingecko`, `user input`. До 100 |
| `recent_tool_calls` | string[]  | Инструменты в порядке вызова, например `["read_file","web_fetch","analyze","swap"]`. До 200 |
| `session_id`        | string    | Идентификатор сессии для накопления сигналов (TTL `SESSION_TTL_MS`) |
| `intent_match`      | boolean   | Собственная оценка агента. `false` даёт `intent_mismatch` |
| `known_addresses`   | string[]  | Адресная книга агента: ранее проверенные адреса. Включает детектор address poisoning. До 500 |
| `expected_amount`   | string    | Сумма операции в человеческих единицах (`"150.5"`). Для безлимитного approve сервис вернёт готовый calldata ограниченного approve в `safe_alternative` |

Ответ:

```json
{
  "verdict": "WARN",
  "reasons": ["unlimited_approval"],
  "summary": "Approve UNLIMITED USDC (USD Coin) to Uniswap V2 Router02 (dex-router, 0x7a25…488D) on ethereum. WARN: unlimited_approval.",
  "details": {
    "chainId": 1, "chain": "ethereum", "to": "0xA0b8…", "from": null, "value": "0",
    "selector": "0x095ea7b3", "function": "approve(address,uint256)", "callType": "approve",
    "decoded": { "spender": "0x7a25…", "amount": "1157…9935" },
    "amount": "115792089237316195423570985008687907853269984665640564039457584007913129639935 raw units",
    "token": { "symbol": "USDC", "decimals": 6, "name": "USD Coin", "source": "static-registry" },
    "counterparties": { "0x7a25…": { "known": { "name": "Uniswap V2 Router02", "category": "dex-router" }, "isContract": true, "proxy": null, "codeSize": 8760, "tiny": false, "fresh": false } },
    "nested_calls": null,
    "simulation": { "ran": false, "reason": "no \"from\" supplied" },
    "erc20State": null,
    "findings": [ { "code": "unlimited_approval", "severity": "WARN", "message": "…", "spender": "0x7a25…" } ],
    "addressChecks": { "target": { "isContract": true }, "spender": { "isContract": true, "txCount": 1 } },
    "rpc": { "ok": true, "endpoint": "https://ethereum-rpc.publicnode.com", "error": null },
    "enrichment": { "ran": true, "skipped": null, "errors": [] },
    "risk_score": 15,
    "recommendations": [ { "code": "unlimited_approval", "action": "Approve only the amount this operation needs and revoke the allowance afterwards." } ],
    "safe_alternative": { "available": true, "kind": "bounded_approval", "to": "0xA0b8…", "spender": "0x7a25…", "data": "0x095ea7b3…", "amountRaw": "150500000", "amount": "150.5 USDC", "revoke": { "to": "0xA0b8…", "data": "0x095ea7b3…0000" } },
    "context_analyzed": true, "intent_analysis": { "…": "…" }, "context_signals": [], "context_sources": { "…": "…" }, "session_risk_score": 0,
    "analyzedAt": "2026-09-13T12:00:00.000Z"
  }
}
```

Ошибки: `400` (невалидный вход, поле `error`), `405` (не POST), `402` (когда включён x402).

### `POST /analyze-signature`

| Поле        | Тип    | Описание |
|-------------|--------|----------|
| `type`      | string | `eip712` (он же `eth_signTypedData_v4`), `personal_sign`, `eth_sign` |
| `typedData` | object \| string | Для `eip712`: `{ types, primaryType, domain, message }` (объект или JSON‑строка) |
| `message`   | string | Для `personal_sign` / `eth_sign`: текст или `0x`‑hex |
| `chainId`   | number | По умолчанию из `domain.chainId`, иначе `1` |
| `from`      | string | Адрес подписанта (для SIWE и проверки owner) |
| `context`   | object | То же, что в `/analyze` |

Распознаются: ERC‑2612 `Permit` (включая DAI‑стиль), Permit2 `PermitSingle` / `PermitBatch` /
`PermitTransferFrom` / `PermitBatchTransferFrom` / `PermitWitnessTransferFrom`, Seaport `OrderComponents`, SIWE.
Для нераспознанных typed data ищутся поля‑полномочия (`spender`, `operator`, `delegate`, `recipient`…) с чужими
адресами. Spender и `verifyingContract` проверяются on‑chain (кошелёк, прокси, реестр, подделка адреса).

### `GET /health`, `GET /rules`, `GET /trusted-domains`

Информация о сервисе; полный каталог из 41 правила с серьёзностью, слоем и описанием; текущий белый список
доменов и настройки.

## Правила

### Транзакция

| Код | Вердикт | Условие |
|---|---|---|
| `zero_address` | DENY | `to`, получатель, spender или operator = `0x0…0` или `0x…dEaD` |
| `set_approval_for_all` | DENY | `setApprovalForAll(operator, true)` |
| `approval_to_eoa` | DENY | approve / increaseAllowance / permit / setApprovalForAll на адрес без кода |
| `address_poisoning` | DENY | Получатель или spender имитирует адрес из `context.known_addresses` (совпадают 4 первых и 4 последних hex‑символа, адрес другой) |
| `contract_lookalike` | DENY | Адрес имитирует контракт или токен из встроенного реестра |
| `permit_spender_mismatch` | DENY | Permit2‑permit внутри Universal Router даёт allowance не роутеру |
| `permit2_pull_to_third_party` | DENY | `PERMIT2_TRANSFER_FROM` внутри роутера отправляет ваши токены третьему лицу |
| `unlimited_approval` | WARN | Сумма approve = `MAX_UINT256` или > 2^255, включая Permit2‑permit внутри роутера |
| `unknown_spender` | WARN | Безлимитный approve на контракт вне реестра. В сообщении отмечаются upgradeable‑прокси и контракты < 64 байт кода |
| `router_output_to_third_party` | WARN | Своп / sweep / unwrap / transfer внутри роутера отдаёт результат не вам и не роутеру. `PAY_PORTION` ≤ 1 % считается комиссией и не флагуется |
| `fresh_recipient` | WARN | Получатель без истории: nonce 0, баланс 0, не контракт |
| `unknown_selector` | WARN | Селектор не распознан или calldata не декодируется |
| `calldata_to_eoa` | WARN | Есть calldata, но `to` не контракт |
| `simulation_reverted` | WARN | `eth_call` от `from` падает; причина расшифрована |
| `simulation_unavailable` | WARN | Симуляция запрошена (`from`), но RPC не ответил |
| `insufficient_balance` | WARN | Баланс ERC‑20 у `from` меньше суммы перевода |
| `rpc_unavailable` | WARN | Блокчейн не ответил. **Fail‑safe: никогда не ALLOW** |

### Подпись

| Код | Вердикт | Условие |
|---|---|---|
| `eth_sign_deprecated` | DENY | `eth_sign` произвольного хэша |
| `blind_hash_signing` | DENY | `personal_sign` ровно 32 байт не‑текста |
| `seaport_zero_consideration` | DENY | Ордер Seaport отдаёт предметы, а offerer не получает ничего |
| `permit2_domain_mismatch` | DENY | Permit2‑сообщение, у которого `verifyingContract` не канонический Permit2 |
| `verifying_contract_is_eoa` | DENY | `domain.verifyingContract` без кода |
| `siwe_phishing_domain` | DENY | Домен Sign‑In‑With‑Ethereum совпадает с фишинговым паттерном |
| `phishing_url_in_message` | DENY | Текст сообщения содержит ссылку на фишинговый хост |
| `approval_to_eoa`, `unlimited_approval`, `unknown_spender`, `contract_lookalike` | как в транзакциях | Применяются к spender из permit |
| `signature_transfer_authorization` | WARN | Permit2 `PermitTransferFrom`: подпись равна переводу |
| `far_deadline` | WARN | Срок permit / ордера больше `PERMIT_MAX_DEADLINE_DAYS` (30) или бесконечный |
| `expired_deadline` | WARN | Срок уже прошёл |
| `opaque_hex_message` | WARN | `personal_sign` над нетекстовыми байтами |
| `siwe_domain_mismatch`, `siwe_address_mismatch` | WARN | Домен и URI не совпадают; аккаунт в сообщении не подписант |
| `authorization_text_in_message` | WARN | Текст содержит слова authorisation и адрес |
| `unrecognized_authorization`, `authority_is_eoa` | WARN | Нераспознанные typed data с полями‑полномочиями |
| `domain_chain_mismatch` | WARN | `domain.chainId` не совпадает с запрошенным |

### Целостность агента (только при наличии `context`)

| Код | Вердикт | Условие |
|---|---|---|
| `goal_escalation` | DENY | `agent_goal` = `read` / `analyze`, а действие — approve, `setApprovalForAll`, перевод |
| `injection_pattern` | DENY | В `recent_sources` есть хост с фишинговым паттерном: имя бренда в неофициальном домене, тайпосквоттинг, гомоглифы, punycode, IP, подозрительный TLD, фишинговые слова, 5+ поддоменов |
| `untrusted_source_before_tx` | WARN / DENY | Домены вне белого списка **и** approve/transfer. `DENY` при крупной сумме (безлимит, `setApprovalForAll`, ≥ `LARGE_AMOUNT_RAW`, нативный ≥ 0.1) |
| `intent_mismatch` | WARN | Цель не совместима с типом действия или `intent_match: false`. `swap tokens` совместим с approve |
| `rapid_context_shift` | WARN | Последний инструмент перед транзакцией — `web_fetch` / `read_file` **и** цель не совпадает |
| `memory_poisoning_signal` | WARN | Больше 3 разных недоверенных доменов за сессию в пределах `SESSION_TTL_MS` |
| `context_analysis_failed` | WARN | Контекст‑анализатор упал. Fail‑safe |

Вердикт = максимальная серьёзность среди сработавших правил. **Риск‑скор** (`risk_score`, 0–100, не влияет на
вердикт): +15 за `WARN`, +40 за `DENY`, +20 за `intent_mismatch`, +50 за `injection_pattern`, кэп 100.

## Реестр контрактов и токенов

`src/registry.js` содержит канонические адреса: Permit2, Uniswap V2/V3/Universal Router, 1inch v5/v6, 0x, Aave V3,
Sushi, Lido, PancakeSwap, QuickSwap, Aerodrome, Trader Joe, Seaport 1.5/1.6, OpenSea Conduit, Multicall3 и основные
токены (WETH, USDC, USDT, DAI, WBTC, стейблкоины на L2, WOKB/USDT/USDC на X Layer). Реестр статический и служит
трём целям: подписи контрагентов в `summary`, снижение ложных срабатываний для обычных DeFi‑потоков и детекция
подделок под известные адреса. Неизвестные токены читаются с цепочки и кэшируются в памяти.

## Структура

```
guardian-mcp/
├── api/index.js                  # Vercel Serverless Function: маршрутизация, CORS, x402, все эндпоинты
├── src/analyzer.js               # Оркестратор: статические правила, вложенные вызовы, on-chain роли, enrichment, вердикт
├── src/nested.js                 # multicall / Universal Router / router helpers: куда уходят деньги внутри вызова
├── src/intel.js                  # Метаданные токенов, прокси, симуляция, revert reason, баланс/allowance, bounded approve
├── src/registry.js               # Канонические контракты и токены по сетям, детектор look-alike адресов
├── src/signature.js              # EIP-712 / personal_sign / eth_sign: permit, Permit2, Seaport, SIWE, blind signing
├── src/summary.js                # Человеческое резюме, рекомендации, safe_alternative
├── src/context-analyzer.js       # Intent / context / runtime сигналы, фишинг-паттерны, сессионное хранилище
├── src/rpc.js                    # RPC: таймауты, фолбэки по 9 сетям, бюджет времени, revert ≠ сбой
├── src/x402.js                   # Платёжный шлюз x402 v2 (exact); выключен при X402_PRICE=0
├── test/analyzer.test.js         # 15 тестов слоя транзакции
├── test/context-analyzer.test.js # 18 тестов слоя целостности агента
├── test/intel.test.js            # 18 тестов реестра, вложенных вызовов, симуляции, подписей, совместимости
├── vercel.json, package.json, .env.example, .gitignore
```

## Локальный запуск

```bash
npm install
```

```bash
npm test
```

Локальный сервер без Vercel CLI:

```bash
node -e "require('http').createServer(require('./api/index.js')).listen(3000, () => console.log('http://localhost:3000'))"
```

## Деплой на Vercel

```bash
npm i -g vercel
```

```bash
vercel login
```

```bash
vercel --prod
```

Запускать из папки проекта. На вопросы: `Set up and deploy?` → **Y**; `Which project?` → **Create a new project**;
`Name?` → `guardian-mcp`; `Code directory?` → `./`; `Customize settings?` → **N**. Повторный `vercel --prod`
обновляет тот же проект. Через GitHub: импортируйте репозиторий на [vercel.com/new](https://vercel.com/new),
Framework Preset **Other**, Deploy.

### Переменные окружения (необязательно)

Vercel → проект → **Settings → Environment Variables**. Полный список в `.env.example`.

- `RPC_URL_<chainId>` — свои RPC (через запятую = порядок фолбэка). Рекомендуется для продакшена.
- `RPC_TIMEOUT_MS`, `RPC_BUDGET_MS` — таймауты (4000 / 7000 мс по умолчанию, укладываются в лимит функции 10 с).
- `TRUSTED_DOMAINS` — белый список доменов для `context.recent_sources`.
- `SESSION_TTL_MS` — время жизни сессионных сигналов (1 час).
- `LARGE_AMOUNT_RAW` — порог «крупной суммы» в сырых единицах (10^18).
- `PERMIT_MAX_DEADLINE_DAYS` — допустимый срок permit / ордера (30 дней).

## Включение платежей x402

Сервис стартует бесплатным. Чтобы брать оплату за вызов, задайте переменные и передеплойте:

| Переменная | Пример | Смысл |
|---|---|---|
| `X402_PRICE` | `10000` | Цена в атомарных единицах токена (0.01 USDC) |
| `X402_PAY_TO` | `0x…` | Ваш адрес получателя |
| `X402_NETWORK` | `eip155:8453` | Сеть CAIP‑2 (Base по умолчанию) |
| `X402_ASSET` | `0x8335…2913` | Адрес токена (USDC на Base по умолчанию) |
| `X402_ASSET_NAME` / `_VERSION` | `USD Coin` / `2` | EIP‑712 домен токена |
| `X402_FACILITATOR_URL` | `https://x402.org/facilitator` | Facilitator для `/verify` и `/settle` |

Запрос без `PAYMENT-SIGNATURE` получает `402` с `PAYMENT-REQUIRED` (`x402Version: 2`, схема `exact`); запрос
с подписью проверяется через facilitator, чек возвращается в `PAYMENT-RESPONSE`. Клиенты OKX Onchain OS
оплачивают такие вызовы автоматически.

## Примеры

Безлимитный approve USDC для Uniswap V2 Router (ожидается `WARN`, `unlimited_approval`):

```bash
curl -s -X POST https://guardian-mcp-rho.vercel.app/analyze -H "Content-Type: application/json" -d '{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0x095ea7b30000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","chainId":1,"context":{"expected_amount":"150.5"}}'
```

В ответе `details.safe_alternative.data` содержит approve ровно на 150.5 USDC, а `details.safe_alternative.revoke.data`
отзыв allowance.

С симуляцией и адресной книгой (ожидается `DENY`, `address_poisoning`, если получатель имитирует известный адрес):

```bash
curl -s -X POST https://guardian-mcp-rho.vercel.app/analyze -H "Content-Type: application/json" -d '{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0xa9059cbb000000000000000000000000abcdffffffffffffffffffffffffffffffff123400000000000000000000000000000000000000000000000000000000000f4240","from":"0x1111111111111111111111111111111111111111","context":{"agent_goal":"transfer","known_addresses":["0xabcd000000000000000000000000000000001234"]}}'
```

Подпись: слепая подпись 32‑байтового хэша (ожидается `DENY`, `blind_hash_signing`):

```bash
curl -s -X POST https://guardian-mcp-rho.vercel.app/analyze-signature -H "Content-Type: application/json" -d '{"type":"personal_sign","message":"0xabababababababababababababababababababababababababababababababab"}'
```

Агент с целью «проанализировать» прочитал PDF с фишингового домена и пытается сделать безлимитный approve
(ожидается `DENY`, `risk_score = 100`):

```bash
curl -s -X POST https://guardian-mcp-rho.vercel.app/analyze -H "Content-Type: application/json" -d '{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0x095ea7b30000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","chainId":1,"context":{"agent_goal":"analyze","recent_sources":["https://okx-airdrop-claim.xyz/doc.pdf","user input","api:coingecko"],"recent_tool_calls":["read_file","web_fetch","analyze"],"session_id":"11111111-2222-3333-4444-555555555555"}}'
```

## Безопасность и ограничения

- Никаких моков: код контракта, nonce, баланс, метаданные токена, слоты прокси и симуляция читаются из сети при
  каждом запросе. Сбой RPC понижает вердикт до `WARN`, а не до `ALLOW`.
- Сервис не хранит данные, не подписывает и не отправляет транзакции. Тело запроса ограничено 64 KB.
- Реестр статический: адрес вне реестра не означает «опасный», он означает «нераспознанный». Сервис никогда не
  утверждает, что контракт безопасен.
- Сессионное хранилище и кэш токенов живут в памяти инстанса функции; интерфейс `sessionStore` инжектируемый.
- Симуляция это `eth_call` на текущем состоянии, без трассировки изменений баланса; она ловит revert и
  нехватку средств, но не показывает всех побочных эффектов.
