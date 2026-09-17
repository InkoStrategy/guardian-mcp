# Guardian MCP

Система контроля целостности AI‑агента для on‑chain действий. Принимает транзакцию (`to` + `data`) или запрос
на подпись и, опционально, контекст агента. Возвращает вердикт **ALLOW / WARN / DENY**, причины, риск‑скор 0–100,
однострочное объяснение на человеческом языке, рекомендации и, где возможно, готовую безопасную замену
транзакции. Готов к публикации как A2MCP‑сервис на OKX.AI, поддерживает платежи x402 (по умолчанию выключены,
сервис бесплатный).

Репозиторий: https://github.com/InkoStrategy/guardian-mcp. Каждый push в `main` автоматически деплоится в production.

English overview for OKX Dev Day judges: [DEVDAY.md](DEVDAY.md). Live Pay-Safe demo: https://guardian-mcp-rho.vercel.app/pay-safe

Семнадцать слоёв защиты, все детерминированные, без внешних API (только RPC и общее хранилище):

| Слой | Что делает |
|---|---|
| **Pay-Safe (x402)** | `POST /check-payment`: проверка x402‑платежа **до оплаты**. Сверяет вызов 402 с объявлением на маркетплейсе (цена, токен, кошелёк продавца, домен), ловит завышение цены, подмену получателя и токена, поддельные стейблкоины, отравление адресов, неверный EIP‑712 домен, shell‑инъекцию в URL эндпоинта и в полях самого вызова. Проверяет уже подписанный EIP‑3009 или Permit2 платёж перед отправкой. Запускался на живом маркетплейсе OKX.AI: [docs/trust-scan.md](docs/trust-scan.md) |
| **Shared threat registry** | Каждый `DENY`, выведенный из фактов цепочки и calldata, анонимно записывается в общий реестр: chainId, адрес, селектор, код правила, время. Другой агент, который обращается к тому же адресу или читает тот же фишинговый домен, получает `flagged_address` / `known_drainer` / `known_phishing_domain`, даже если формально всё «чисто». Сетевой эффект: чем больше агентов, тем сильнее защита |
| **Seeded scam database** | Реестр засеян открытыми списками ScamSniffer (2,5 тысячи адресов дрейнеров, 350 тысяч фишинговых доменов) и обновляется ежедневно по cron. `scam_database_address` / `scam_database_domain` работают с первого вызова, до любых отчётов агентов |
| **Stats & feedback** | Публичные агрегаты на `/dashboard` и `/stats`; внутренняя разбивка по правилам с долями ложных срабатываний и пропущенных атак за админ‑токеном; `POST /feedback` для пометки вердикта как верного или ошибочного |
| **Session health** | Скользящий риск‑профиль по `session_id`: сколько действий, сколько WARN/DENY, накопленный риск. 3+ WARN или 2+ DENY за час → `session_compromised_likely`, сессия блокируется до перезапуска. Серия мелких подозрительных действий становится видимой |
| **Owner alerts** | При `DENY` (или `WARN`, если попросили) POST на `context.alert_webhook`: «Твой агент пытался сделать X, заблокировано по Y». HMAC‑подпись, SSRF‑защита. Владелец видит проблему сразу, а не из логов через сутки |
| **Reputation** | По каждому контрагенту: тип, активность по nonce, уровень баланса, известный протокол, прокси, отчёты из общего реестра, скор 0–100 и уровень trusted / neutral / low / hostile. Честно указано, чего один RPC‑запрос не даёт |
| **Differential** | Сравнение с эталонной транзакцией от доверенного источника (`context.reference_tx`): изменился ли получатель, spender, сумма, появился ли approve или Permit2 внутри, изменился ли план роутера |
| **Transaction firewall** | Безлимитные approve, approve на кошелёк, `setApprovalForAll`, нулевой адрес, свежий получатель, неизвестный селектор, calldata на кошелёк |
| **Nested calls** | Разбирает `multicall`, Uniswap Universal Router `execute` (план команд), `sweepToken` / `unwrapWETH9` / `exactInput*` / V2‑свопы. Видит approve, спрятанный в multicall, Permit2‑permit на чужой spender и вывод результата свопа третьему лицу |
| **Counterparty intel** | Реестр 48 канонических контрактов и 29 токенов по 9 сетям, on‑chain `symbol/decimals/name`, определение EIP‑1967 / EIP‑1167 прокси и «пустых» контрактов, безлимитный approve на нераспознанный контракт |
| **Address poisoning** | Получатель или spender, совпадающий по первым и последним символам с адресом из адресной книги агента (`context.known_addresses`) или с адресом из реестра, но отличающийся в середине |
| **Asset flow** | При наличии `from`: `eth_simulateV1` с трассировкой переводов и переопределением баланса отправителя показывает, у кого в итоге оказываются ETH, ERC‑20 и NFT. Каждый конечный получатель проверяется по реестрам (`funds_flow_to_flagged`), а вызов неизвестной функции, после которого отправитель отдаёт ценность кошельку и ничего не получает, даёт `funds_flow_no_return`. Работает на публичных узлах, платный RPC не нужен |
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
| `alert_webhook`     | string    | Публичный https‑URL владельца. При `DENY` туда уходит JSON‑событие с человеческим сообщением. Приватные хосты, http и URL с учётными данными отклоняются |
| `alert_on`          | string    | `deny` (по умолчанию) или `warn` |
| `share_threat_intel`| boolean   | `false` отключает запись в общий реестр угроз для этого запроса (чтение остаётся) |
| `reference_tx`      | object    | Эталон `{ to, data?, value?, chainId? }` от доверенного источника. Включает дифференциальную проверку |

Новые поля в `details`: `threat_intel` (записи реестра по контрагентам и доменам, что было записано), `session_health`
(профиль сессии), `alert` (результат доставки), `diff` (список изменений относительно эталона), `shared_state`
(бэкенд хранилища и ошибки), `counterparties[*].reputation`.

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

### `POST /check-address`, `POST /check-domain`

Быстрые проверки без calldata. `/check-address`: `{ address, chainId?, role? }`, где `role` = `recipient`
(по умолчанию, «можно сюда отправить?»), `spender` («можно сюда approve?») или `contract` («можно это вызвать?»).
Смотрит код и историю адреса, реестр контрактов, подделку адреса, общий реестр угроз и базу ScamSniffer.
`/check-domain`: `{ domain }` или `{ url }`, проверяет белый список, фишинговые паттерны, общий реестр и базу
фишинговых доменов. Оба возвращают `{ verdict, reasons, summary, details }`.

### `POST /check-payment` (Pay-Safe)

Проверка x402‑платежа до того, как агент заплатит. Агент вызывает платный эндпоинт, получает `402`, передаёт
вызов в Guardian и платит только при `ALLOW`.

| Поле | Тип | Описание |
|---|---|---|
| `paymentRequired` | string \| object | Заголовок `PAYMENT-REQUIRED` (base64) или тело `402` (x402 v1 или v2, до 20 записей `accepts`) |
| `payment` | object | Вместо `paymentRequired`: плоская котировка `{ network \| chainId, asset, amount, payTo, scheme?, maxTimeoutSeconds?, extra? }` |
| `requestUrl` | string | URL, который вернул `402` |
| `selectedIndex` | number | Какую запись `accepts` агент собирается оплатить. Без него Guardian сам выбирает самую безопасную |
| `paymentSignature` | string \| object | Необязательно: уже подписанный `PAYMENT-SIGNATURE` / `X-PAYMENT` для проверки перед отправкой |
| `expected` | object | Что обещает объявление на маркетплейсе: `{ feeAmount, feeToken, endpoint, payTo, maxAmount, decimals }` |
| `context` | object | `{ known_addresses, max_amount, from, session_id }` |

Что проверяется:

- **Объявление против вызова.** Сумма выше цены в объявлении, другой токен, другой кошелёк продавца, другой домен.
- **Актив.** Канонический стейблкоин сети (USD₮0, USDT, USDC на X Layer; USDC на Base), подделка под него,
  адрес без кода, EIP‑712 домен из `extra` против настоящего домена токена.
- **Получатель.** Нулевой адрес, сам токен, отравление адреса, общий реестр угроз, база ScamSniffer.
- **Эндпоинт и поля вызова.** Shell‑синтаксис в URL и в текстовых полях вызова, фишинговые паттерны хоста, http вместо https, `resource.url` на чужом домене.
- **Подписанный платёж.** Для EIP‑3009 восстановление подписанта, получатель, сумма, срок действия. Для Permit2
  токен, сумма, spender только канонический x402‑прокси, `witness.to`, срок.

Ответ: `{ verdict, reasons, risk_score, summary, recommendations, recommended_index, details }`. В `details`
лежат выбранная запись, разбор всех `accepts`, проверка эндпоинта и все находки. Ничего не платится и не
подписывается.

```bash
curl -s -X POST https://guardian-mcp-rho.vercel.app/check-payment -H "Content-Type: application/json" -d '{"paymentRequired":"<PAYMENT-REQUIRED header>","requestUrl":"https://seller.example/paid","expected":{"feeAmount":0.002,"feeToken":"0x779ded0c9e1022225f8e0630b35a9b54be713736","endpoint":"https://seller.example/paid","payTo":"0x…"}}'
```

Проверка перед оплатой через Onchain OS: `node scripts/safe-pay.js --sid <sid услуги>` (или `--url`, `--fee`, `--token`).
Скрипт берёт объявление через `onchainos agent service-detail`, делает один неоплаченный запрос (GET, POST или MCP
`tools/call`), получает вердикт `/check-payment`, затем вызывает `onchainos payment quote` и сверяет, что котировка
платит тому же получателю ту же сумму в том же токене, что проверил Guardian. Продавец не может подменить вызов
между проверкой и оплатой. Оплата только с `--pay`, а `--yes` кошельку передаётся, только если его указал владелец.
Коды выхода: 0 можно платить, 2 WARN, 3 DENY или подмена котировки.

```bash
node scripts/safe-pay.js --sid 33342 --param scoutMode=best --max 0.5
```
Скан маркетплейса OKX.AI: `node scripts/okxai-trust-scan.js` собирает платные A2MCP‑сервисы через `onchainos`,
делает один неоплаченный запрос к каждому, прогоняет вызов 402 через Pay-Safe и пишет
[docs/trust-scan.md](docs/trust-scan.md).

### `POST /mcp` (MCP-сервер)

GuardianMCP работает как MCP-сервер (Streamable HTTP, без состояния) по адресу `https://guardian-mcp-rho.vercel.app/mcp`.
Поддерживаются `initialize`, `ping`, `tools/list` и `tools/call`; ответ JSON или SSE, если клиент принимает только
`text/event-stream`.

| Инструмент | Что делает | Цена |
|---|---|---|
| `check_payment` | Вердикт Pay-Safe по x402-вызову | бесплатно |
| `probe_payment` | Запрос платного URL без оплаты и вердикт | бесплатно |
| `verify_settlement` | Сверка оплаченной транзакции в сети | бесплатно |
| `check_listing` | Результат скана OKX.AI по sid объявления | бесплатно |
| `check_quote` | Вердикт по сохранённой котировке Onchain OS, привязанный к paymentId | бесплатно |
| `check_address`, `check_domain` | Быстрые проверки адреса и домена | бесплатно |
| `analyze_transaction`, `analyze_signature` | Проверка транзакции и подписи | бесплатно |
| `guard` | Премиум-вердикт | 0.099 USD₮0 за вызов, x402 в X Layer |

Платный инструмент совместим с клиентами Onchain OS A2MCP: неоплаченный `tools/call` для `guard` получает HTTP 402
с `PAYMENT-REQUIRED`, клиент повторяет тот же вызов с `PAYMENT-SIGNATURE`. Проверено командой
`onchainos payment quote https://guardian-mcp-rho.vercel.app/mcp`: клиент находит все 10 инструментов, получает результаты
бесплатных и котировку платного.

`POST /verify-settlement` `{ txHash, payTo, amount, token?, payer?, chainId? }`: та же сверка расчёта без MCP.

### `POST /check-quote` (котировка Onchain OS)

`onchainos payment quote` сохраняет котировку в `~/.onchainos/payments/<paymentId>.json`, а `onchainos payment pay --payment-id`
подписывает именно этот файл и не запрашивает 402 повторно. Поэтому Guardian проверяет сам файл.

Тело запроса: `{ quote, selectedIndex?, expected? | sid?, context? }`. `quote` — сохранённый файл или JSON-вывод `payment quote`.
Сверх правил `/check-payment` добавлены:

- `challenge_header_body_mismatch` (DENY): тело ответа 402 показывает другой платёж, чем тот, что подпишет кошелёк;
- `quote_inconsistent` (DENY): сводка котировки расходится с подписываемой записью;
- `quote_expired`, `quote_partial` (WARN).

Ответ содержит `binding` с SHA-256 отпечатком подписываемой записи. `next_command` выдаётся только при ALLOW и никогда не содержит `--yes`.

`node scripts/check-quote.js --payment-id pay_… --sid 39856` отправляет котировку (без id кошелька владельца, адреса пополнения и баланса)
и записывает вердикт в `~/.guardian/payments`. Хук Claude Code `hooks/claude-code-pretooluse.js` блокирует `payment pay` без привязанного
вердикта, при DENY или изменённой записи и спрашивает владельца при WARN и при `--yes`. Установка описана в `hooks/README.md`.

### `GET /threats/stats`, `GET /threats/{chainId}/{address}`, `GET /threats/domain/{host}`

Статистика общего реестра; запись по адресу (число отчётов, независимых репортёров, правила, селекторы, первое и
последнее появление, серьёзность по текущим порогам); запись по домену.

### `GET /session/{session_id}`

Профиль сессии: статус `healthy` / `elevated` / `compromised_likely`, счётчики за окно и за всё время,
накопленный риск, топ правил, последние события. `404`, если сессия не найдена или истекла.

### `POST /guard` (премиум, платный)

Тот же вход, что у `/analyze`, плюс `"kind": "signature"` с полями `/analyze-signature`. Оплата за вызов через
OKX Payment SDK: без заголовка `PAYMENT-SIGNATURE` ответ `402` с `PAYMENT-REQUIRED` (x402 v2, схема `exact`,
`PREMIUM_PRICE`, по умолчанию 0.099 USDT0 на X Layer, `payTo` из `PREMIUM_PAY_TO`), тело дублирует заголовок.
Оплаченный повтор проверяется и сеттлится через facilitator OKX (`https://web3.okx.com/facilitator`), квитанция
возвращается в `PAYMENT-RESPONSE`, а в `details.payment` попадают payer и транзакция. Клиенты Onchain OS
платят автоматически. Пока учётные данные OKX Developer API не заданы, эндпоинт отвечает `503`, а не `402`.
Бесплатные `/analyze` и `/analyze-signature` не меняются.

### `GET /stats`, `GET /dashboard`

Публичная статистика только в агрегатах: всего вызовов, распределение вердиктов, доля заблокированных,
число сессий, размер реестра, динамика за 14 дней. Разбивки по правилам нет намеренно: она подсказывала бы
атакующим, какие правила слабые. `/dashboard` это HTML‑страница поверх `/stats`.

### `POST /feedback`

```json
{ "request_id": "…из details.request_id…", "verdict": "WARN", "correct": false, "rule_codes": ["fresh_recipient"], "comment": "это мой новый кошелёк" }
```

`correct: false` при `WARN`/`DENY` фиксирует ложное срабатывание по указанным правилам; `correct: false` при
`ALLOW` фиксирует пропущенную атаку. Лимит 60 отзывов в час с одного источника. Отзывы не меняют вердикты,
они только показывают, какие правила требуют уточняющих условий.

### `GET /admin/stats`, `GET|POST /cron/seed`

Служебные. Первый отдаёт полную статистику с разбивкой по правилам, долями ложных и пропущенных, последними
50 отзывами и состоянием тарификации; нужен заголовок `X-Admin-Token`. Второй запускает засев реестра;
принимает `Authorization: Bearer CRON_SECRET` (Vercel Cron подставляет сам) или админ‑токен, `?force=1`
переписывает списки даже при неизменном хэше.

### `GET /health`, `GET /rules`, `GET /trusted-domains`

Информация о сервисе, включая бэкенд общего хранилища и его персистентность; полный каталог из 94 правил
с серьёзностью, слоем и описанием; текущий белый список доменов и настройки.

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

### Платёж x402 (Pay-Safe, `POST /check-payment`)

| Код | Вердикт | Условие |
|---|---|---|
| `amount_above_listing` | DENY | Сумма в вызове больше цены в объявлении |
| `amount_above_user_cap` | DENY | Сумма больше лимита агента `context.max_amount` |
| `asset_mismatch_listing` | DENY | Токен отличается от токена в объявлении |
| `asset_lookalike` | DENY | Токен подделывается под канонический стейблкоин: те же первые и последние символы адреса |
| `asset_not_contract` | DENY | У адреса токена нет кода |
| `payto_mismatch_listing` | DENY | Получатель не кошелёк продавца из объявления |
| `payto_poisoning` | DENY | Получатель похож на кошелёк из объявления или адресной книги, но отличается в середине |
| `payto_zero_address`, `payto_is_asset` | DENY | Оплата на нулевой адрес или на сам контракт токена |
| `payment_domain_mismatch` | DENY | `402` пришёл с другого домена, чем эндпоинт в объявлении |
| `endpoint_url_injection` | DENY | В URL эндпоинта shell‑синтаксис: `;`, `\|`, обратные кавычки, `$(`, `{a,b}`, пробелы. Атака на агентов, которые передают URL в shell |
| `challenge_field_injection` | DENY | В текстовом поле вызова 402 (`extra.name`, `extra.version`, `resource.description`, `error`) shell‑нагрузка: `$(...)`, выход из кавычек с командой, цепочка `curl` / `base64` |
| `endpoint_phishing_pattern` | DENY | Хост имитирует кого‑то (бренд, тайпосквоттинг, punycode, IP), и никакое объявление его не подтверждает |
| `accepted_mismatch` | DENY | Подписанный `accepted` отличается от вызова |
| `signed_recipient_mismatch`, `signed_amount_mismatch`, `signed_token_mismatch`, `signed_network_mismatch` | DENY | Подпись платит другому, больше, другим токеном или в другой сети |
| `signed_spender_not_x402_proxy` | DENY | Permit2‑подпись на spender, который не канонический x402‑прокси |
| `endpoint_domain_suspicious` | WARN | Хост имитирует бренд, но это эндпоинт из объявления; или у хоста только слабый паттерн (TLD, ключевое слово, глубокие поддомены) без объявления. Слабый паттерн у эндпоинта из объявления игнорируется |
| `eip712_domain_mismatch` | WARN | `extra.name` / `extra.version` не совпадают с EIP‑712 доменом токена, подпись не пройдёт |
| `upto_cap_above_listing` | WARN | Лимит схемы `upto` выше цены в объявлении |
| `recurring_payment` | WARN | Схема `period`, регулярные списания |
| `permit2_approval_required` | WARN | Нужен разовый approve на Permit2 |
| `unknown_settlement_asset`, `unknown_payment_scheme`, `payment_network_unsupported`, `testnet_payment` | WARN | Нестандартный актив, схема, сеть или тестнет |
| `multiple_payees` | WARN | Записи `accepts` платят разным получателям |
| `long_payment_timeout`, `signed_validity_too_long` | WARN | Авторизация действует слишком долго |
| `resource_host_mismatch`, `insecure_payment_endpoint` | WARN | `resource.url` на чужом домене; http вместо https |
| `signed_expired`, `signed_payer_mismatch`, `signature_does_not_recover` | WARN | Подпись истекла, платит другой кошелёк или не восстанавливается |

### Общий реестр, сессия, эталон

| Код | Вердикт | Условие |
|---|---|---|
| `scam_database_address` | DENY | Адрес есть в открытом списке ScamSniffer. Для получателя перевода `WARN` |
| `scam_database_domain` | DENY | Домен из `recent_sources` (или его родительский домен) есть в открытом списке фишинга ScamSniffer |
| `known_drainer` | DENY | Spender или целевой контракт набрал ≥ `THREAT_DENY_REPORTS` (3) отчётов от ≥ `THREAT_DENY_REPORTERS` (2) независимых репортёров. Для роли получателя перевода серьёзность ограничена `WARN`, чтобы нельзя было заблокировать чужие переводы фальшивыми отчётами |
| `flagged_address` | WARN | Адрес имеет ≥ `THREAT_WARN_REPORTS` (1) отчёт в общем реестре |
| `known_phishing_domain` | DENY | Домен из `recent_sources` (или домен SIWE) ранее был отмечен другими агентами как фишинг |
| `session_compromised_likely` | DENY | За `SESSION_TTL_MS`: ≥ `SESSION_WARN_THRESHOLD` (3) WARN, или ≥ `SESSION_DENY_THRESHOLD` (2) DENY, или накопленный риск ≥ `SESSION_RISK_THRESHOLD` (150) |
| `session_risk_elevated` | WARN | 2+ WARN, 1+ DENY или риск ≥ 60 за окно |
| `template_critical_deviation` | DENY | Относительно `reference_tx`: сменились target, функция, получатель, spender, operator; ограниченный approve стал безлимитным; появился нативный value; внутри появился approve/permit или новый получатель; план роутера получил денежные команды |
| `template_deviation` | WARN | Сумма или value выросли; план роутера отличается в неденежных командах |
| `shared_state_unavailable` | WARN | Настроено персистентное хранилище, но оно не ответило |

В общий реестр записываются только правила, выведенные из фактов цепочки и calldata: `approval_to_eoa`,
`contract_lookalike`, `permit_spender_mismatch`, `permit2_pull_to_third_party`, `permit2_domain_mismatch`,
`verifying_contract_is_eoa`, а из доменных паттернов только имперсонация бренда, тайпосквоттинг и punycode.
Правила, зависящие от данных клиента (`address_poisoning`, цели агента, TLD‑эвристики), не записываются, чтобы
клиент не мог отравить реестр. Адреса из встроенного реестра контрактов не записываются никогда. От клиента
хранится только суточно‑солёный усечённый отпечаток для подсчёта независимых репортёров.

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

## Бенчмарк на реальных транзакциях

[docs/benchmark.md](docs/benchmark.md): 40 реальных транзакций жертв к адресам из списка ScamSniffer и 30 реальных
approve к Permit2, Uniswap и 1inch, каждая с ссылкой на Etherscan, прогнаны через продакшен. Воспроизводится
командой `node scripts/benchmark.js`. Две колонки: только правила без списков и как задеплоено с засеянным реестром.

## Общее хранилище (обязательно для сетевого эффекта)

Реестр угроз и профили сессий живут в key‑value хранилище. Без настройки используется память инстанса
функции: всё работает, но данные не разделяются между инстансами и не переживают холодный старт. `GET /health`
показывает `sharedState.persistent`.

Для продакшена подключите Upstash Redis (бесплатный тариф достаточен):

1. Vercel → проект `guardian-mcp` → вкладка **Storage** → **Create Database** → **Upstash Redis** (или
   [Marketplace](https://vercel.com/marketplace/upstash)) → регион ближе к функции → **Create** → **Connect Project**.
2. Vercel сам добавит переменные `UPSTASH_REDIS_REST_URL` и `UPSTASH_REDIS_REST_TOKEN` (или `KV_REST_API_URL` /
   `KV_REST_API_TOKEN`). Сервис понимает обе пары.
3. Передеплойте (`vercel --prod`). `GET /health` должен показать `"backend": "upstash", "persistent": true`.

Работа идёт через REST API Upstash без SDK: `HINCRBY`, `SADD`, `ZADD`, `RPUSH` в пайплайнах, все операции
атомарны на уровне команды. Таймаут `STORE_TIMEOUT_MS` (2500 мс). Записи реестра живут `THREAT_TTL_DAYS` (90).

## Засев реестра из открытых баз

Источник: репозиторий [scamsniffer/scam-database](https://github.com/scamsniffer/scam-database) (MIT), сырые
JSON `blacklist/address.json` и `blacklist/domains.json` через raw.githubusercontent.com. Без API и парсинга страниц.

- **Расписание.** Vercel Cron дергает `GET /cron/seed` ежедневно в 03:00 UTC. Списки сравниваются по SHA‑256,
  без изменений запись пропускается. Вручную: `node scripts/seed-threats.js [--force]` с переменными хранилища
  в `.env.local`.
- **Валидация.** Адреса: строго `0x` + 40 hex, нижний регистр, дедупликация. Домены: нижний регистр, без схемы,
  `www.`, пути и порта, только `[a-z0-9.-]`, обязательна точка, ≤ 253 символов. Адреса из встроенного реестра
  канонических контрактов и токенов не засеваются никогда.
- **Атомарность.** Списки пишутся во временные множества и подменяются через `RENAME`; неудачная загрузка
  оставляет предыдущий реестр целым. Хранение: два множества и хэш метаданных, полное обновление стоит
  около 360 команд Redis.
- **Матчинг.** Точный хост и родительские домены (`login.evil.com` матчится на `evil.com`), TLD никогда.

Добавить другой источник можно в `SOURCES` в `src/seed.js`.

## Тарификация

Базовые `/analyze` и `/analyze-signature` бесплатны навсегда, потому что каждый бесплатный вызов кормит общий
реестр. Премиум это отдельный платный эндпоинт `/guard` и отдельный сервис в OKX.AI со своей регистрацией и ревью;
валюта листинга задаётся платформой (USDT на X Layer). `PRICING_MODE` управляет только будущим переводом
премиум‑слоёв внутри бесплатных эндпоинтов и сейчас равен `free`. Режим `auto` включает
тарификацию не по дате, а по использованию: `FREE_CALLS` (1000) вызовов или `FREE_SESSIONS` (20) сессий **и**
`FREE_DAYS` (30) дней с первого реального вызова. `GRANDFATHERED_PAYERS` остаются бесплатными пожизненно.

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
├── src/store.js                  # Redis-подобное хранилище: Upstash / Vercel KV через REST или память
├── src/threat-registry.js        # Общий реестр угроз (запись, поиск, пороги, отпечатки) и репутация адресов
├── src/session-health.js         # Скользящий риск-профиль сессии
├── src/alerts.js                 # Вебхук владельцу: SSRF-защита, HMAC, таймаут
├── src/diff.js                   # Дифференциальная проверка против эталона
├── src/pipeline.js               # Общий пост-процессор: threat lookup, сессия, запись, алерт, счётчики
├── src/seed.js                   # Засев реестра из ScamSniffer: загрузка, валидация, атомарная подмена, поиск
├── src/stats.js                  # Счётчики использования, публичный и внутренний снимки
├── src/feedback.js               # Обратная связь по вердиктам, доли ложных и пропущенных, rate limit
├── src/pricing.js                # Тарификация по слоям и режим auto (выключено в волне 1)
├── src/dashboard.js              # Публичная HTML-страница статистики
├── src/premium.js                # POST /guard: платёжный шлюз на OKX Payment SDK (x402 exact, facilitator OKX)
├── scripts/seed-threats.js       # Ручной засев с локальной машины
├── src/context-analyzer.js       # Intent / context / runtime сигналы, фишинг-паттерны, сессионное хранилище
├── src/rpc.js                    # RPC: таймауты, фолбэки по 9 сетям, бюджет времени, revert ≠ сбой
├── src/x402.js                   # Платёжный шлюз x402 v2 (exact); выключен при X402_PRICE=0
├── test/analyzer.test.js         # 15 тестов слоя транзакции
├── test/context-analyzer.test.js # 18 тестов слоя целостности агента
├── test/intel.test.js            # 18 тестов реестра, вложенных вызовов, симуляции, подписей, совместимости
├── test/shared-layers.test.js    # 14 тестов общего реестра, сессии, алертов, репутации, дифф-проверки, HTTP
├── test/growth.test.js           # 6 тестов засева, статистики, обратной связи, тарификации, HTTP
├── test/premium.test.js          # 5 тестов платного эндпоинта с подменённым facilitator
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
- `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` (или `KV_REST_API_URL`, `KV_REST_API_TOKEN`) — общее хранилище.
- `THREAT_WARN_REPORTS`, `THREAT_DENY_REPORTS`, `THREAT_DENY_REPORTERS`, `THREAT_TTL_DAYS`, `THREAT_SALT` — пороги и соль реестра.
- `SESSION_WARN_THRESHOLD`, `SESSION_DENY_THRESHOLD`, `SESSION_RISK_THRESHOLD` — пороги сессии.
- `ALERT_SIGNING_SECRET` — HMAC‑подпись вебхуков (заголовок `X-Guardian-Signature: sha256=…`), `ALERT_TIMEOUT_MS` (2500).
- `ADMIN_TOKEN` — доступ к `/admin/stats` и ручному `/cron/seed`. Даёт только чтение агрегатов и запуск засева.
- `CRON_SECRET` — Vercel Cron подставляет его в `Authorization: Bearer` при вызове `/cron/seed`.
- `PRICING_MODE`, `X402_PREMIUM_PRICE`, `FREE_CALLS`, `FREE_SESSIONS`, `FREE_DAYS`, `GRANDFATHERED_PAYERS` — тарификация (см. ниже).

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

Сессия, алерт владельцу и эталон одним запросом: агент следует шаблону перевода другу, но подставил другого
получателя (ожидается `DENY`, `template_critical_deviation`, вебхук получит событие `guardian.deny`):

```bash
curl -s -X POST https://guardian-mcp-rho.vercel.app/analyze -H "Content-Type: application/json" -d '{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0xa9059cbb000000000000000000000000999999999999999999999999999999999999999900000000000000000000000000000000000000000000000000000000000003e8","context":{"session_id":"agent-42","alert_webhook":"https://hooks.example.com/guardian","reference_tx":{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0xa9059cbb000000000000000000000000333333333333333333333333333333333333333300000000000000000000000000000000000000000000000000000000000003e8"}}}'
```

Затем `GET /session/agent-42` покажет профиль сессии, а `GET /threats/1/0x9999…9999` останется пустым: смена
получателя это правило, зависящее от данных клиента, и в общий реестр оно не пишется.

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
