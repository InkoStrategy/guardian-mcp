# Guardian MCP

Детерминированный анализ безопасности EVM‑транзакций. Принимает `to` + `data`, возвращает вердикт
**ALLOW / WARN / DENY** с причинами и подробностями. Готов к публикации как A2MCP‑сервис на OKX.AI,
поддерживает платежи x402 (по умолчанию выключены, сервис бесплатный).

## API

### `POST /analyze`

Запрос (JSON):

| Поле      | Тип                  | Обязательно | Описание                                                                 |
|-----------|----------------------|-------------|--------------------------------------------------------------------------|
| `to`      | string               | да          | Адрес назначения транзакции, `0x` + 40 hex                               |
| `data`    | string               | нет         | Calldata, `0x`‑hex. Пусто или `0x` = нативный перевод                    |
| `chainId` | number \| string     | нет         | По умолчанию `1`. Поддерживаются: 1, 10, 56, 137, 196, 8453, 42161      |
| `value`   | string \| number     | нет         | Сумма нативной монеты в wei (десятичная строка или `0x`‑hex). По умолчанию `0` |

Ответ (JSON):

```json
{
  "verdict": "WARN",
  "reasons": ["unlimited_approval"],
  "details": {
    "chainId": 1,
    "to": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "value": "0",
    "selector": "0x095ea7b3",
    "function": "approve(address,uint256)",
    "callType": "approve",
    "decoded": { "spender": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "amount": "115792089237316195423570985008687907853269984665640564039457584007913129639935" },
    "findings": [ { "code": "unlimited_approval", "severity": "WARN", "message": "..." } ],
    "addressChecks": { "target": { "isContract": true }, "spender": { "isContract": true, "txCount": 1, "balance": "0" } },
    "rpc": { "ok": true, "endpoint": "https://ethereum-rpc.publicnode.com", "error": null },
    "analyzedAt": "2026-09-13T12:00:00.000Z"
  }
}
```

Ошибки: `400` (невалидный вход, поле `error`), `405` (не POST), `402` (когда включён x402).

### `GET /health`

Информация о сервисе: версия, список правил, поддерживаемые сети, статус платёжного шлюза.

## Правила

| Код                    | Вердикт | Условие                                                                                   |
|------------------------|---------|-------------------------------------------------------------------------------------------|
| `zero_address`         | DENY    | `to`, получатель перевода, spender или operator = `0x0…0` или `0x…dEaD`                   |
| `set_approval_for_all` | DENY    | `setApprovalForAll(operator, true)` — полный контроль над коллекцией NFT                   |
| `approval_to_eoa`      | DENY    | `approve` / `increaseAllowance` / `permit` / `setApprovalForAll` на адрес **без кода** (обычный кошелёк) |
| `unlimited_approval`   | WARN    | Сумма approve = `MAX_UINT256` или > 2^255 (фактически безлимит)                           |
| `fresh_recipient`      | WARN    | Получатель (ERC‑20/721/1155 или нативный перевод) без истории: nonce = 0, баланс = 0, не контракт |
| `unknown_selector`     | WARN    | Селектор функции не распознан или calldata не декодируется                                |
| `calldata_to_eoa`      | WARN    | Есть calldata, но `to` — не контракт (скорее всего, ошибочный адрес)                       |
| `rpc_unavailable`      | WARN    | Блокчейн не ответил. **Fail‑safe: никогда не ALLOW**                                      |

Итоговый вердикт = максимальная серьёзность среди сработавших правил. Правила без сработок → `ALLOW`.

Декодируются: `approve`, `increaseAllowance`, `permit`, `setApprovalForAll`, `transfer`,
`transferFrom`, `safeTransferFrom` (ERC‑721/1155), `safeBatchTransferFrom`. Популярные селекторы DEX,
стейкинга и минта считаются известными и не дают `unknown_selector`.

## Структура

```
guardian-mcp/
├── api/index.js          # Vercel Serverless Function: маршрутизация, CORS, x402, ответы
├── src/analyzer.js       # Движок правил: валидация, декодирование calldata, вердикт
├── src/rpc.js            # RPC‑слой: таймауты, фолбэки, общий бюджет времени, RpcError
├── src/x402.js           # Платёжный шлюз x402 v2 (exact); выключен при X402_PRICE=0
├── test/analyzer.test.js # 15 тестов node:test с инжектируемым читателем цепочки
├── vercel.json           # rewrite всех путей на функцию, maxDuration 10 с
├── package.json
├── .env.example
└── .gitignore
```

## Локальный запуск

```bash
npm install
npm test
```

Локальный сервер без Vercel CLI:

```bash
node -e "require('http').createServer(require('./api/index.js')).listen(3000, () => console.log('http://localhost:3000'))"
```

## Деплой на Vercel

### Вариант A — через CLI (быстрее всего)

```bash
npm i -g vercel
```

```bash
vercel login
```

```bash
vercel --prod
```

На вопросы CLI: `Set up and deploy?` → **Y**; `Which scope?` → ваш аккаунт; `Link to existing project?` → **N**;
`Project name?` → `guardian-mcp`; `In which directory is your code located?` → `./`; настройки сборки
менять не нужно (**N**). После деплоя CLI выведет production‑URL вида
`https://guardian-mcp-<hash>.vercel.app` и алиас `https://guardian-mcp.vercel.app` (если имя свободно).

### Вариант B — через GitHub

1. Создайте пустой репозиторий на GitHub и запушьте код:

```bash
git remote add origin https://github.com/<you>/guardian-mcp.git && git push -u origin main
```

2. На [vercel.com/new](https://vercel.com/new) нажмите **Import** рядом с репозиторием, Framework Preset оставьте
   **Other**, нажмите **Deploy**. Каждый push в `main` будет деплоиться автоматически.

### Переменные окружения (необязательно)

Vercel → проект → **Settings → Environment Variables**. Полный список в `.env.example`.

- `RPC_URL_<chainId>` — свои RPC (через запятую = порядок фолбэка). Рекомендуется для продакшена:
  публичные RPC могут ограничивать частоту запросов.
- `RPC_TIMEOUT_MS`, `RPC_BUDGET_MS` — таймауты (по умолчанию 4000 / 7000 мс, укладываются в лимит функции 10 с).

## Включение платежей x402

Сервис стартует бесплатным. Чтобы брать оплату за вызов, задайте переменные и передеплойте:

| Переменная               | Пример                                        | Смысл                                         |
|--------------------------|-----------------------------------------------|-----------------------------------------------|
| `X402_PRICE`             | `10000`                                       | Цена в атомарных единицах токена (0.01 USDC) |
| `X402_PAY_TO`            | `0xe1c6…f67b`                                 | Ваш адрес получателя                          |
| `X402_NETWORK`           | `eip155:8453`                                 | Сеть в формате CAIP‑2 (Base по умолчанию)     |
| `X402_ASSET`             | `0x8335…2913`                                 | Адрес токена (USDC на Base по умолчанию)      |
| `X402_ASSET_NAME` / `_VERSION` | `USD Coin` / `2`                        | EIP‑712 домен токена                          |
| `X402_FACILITATOR_URL`   | `https://x402.org/facilitator`                | Facilitator для `/verify` и `/settle`         |

Поведение при включённом шлюзе: запрос без заголовка `PAYMENT-SIGNATURE` получает `402` с заголовком и телом
`PAYMENT-REQUIRED` (`x402Version: 2`, схема `exact`). Запрос с подписью проверяется через facilitator
`/verify`, после успешного анализа выполняется `/settle`, чек возвращается в заголовке `PAYMENT-RESPONSE`.
Клиенты OKX Onchain OS оплачивают такие вызовы автоматически.

## Пример запроса

```bash
curl -s -X POST https://guardian-mcp.vercel.app/analyze \
  -H "Content-Type: application/json" \
  -d '{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0x095ea7b30000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}'
```

Ожидаемый ответ: `"verdict": "WARN"`, `"reasons": ["unlimited_approval"]` — безлимитный approve USDC для
Uniswap V2 Router.

## Безопасность

- Никаких моков: код контракта, nonce и баланс читаются из сети при каждом запросе.
- Сбой или таймаут RPC понижает вердикт до `WARN`, а не до `ALLOW`.
- Сервис не хранит данные, не подписывает и не отправляет транзакции.
- Ограничение размера тела запроса 64 KB, только JSON.
