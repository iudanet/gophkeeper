# План проекта GophKeeper — Краткий обзор и приоритеты

## Технологии и подходы
- Go 1.22+, SQLite (modernc.org/sqlite), BoltDB клиент, Argon2id, AES-256-GCM, JWT, TLS (Let's Encrypt), net/http.ServeMux, log/slog, Cobra CLI
- Слоистая архитектура (HTTP/CLI → Service → Storage)
- TDD, table-driven tests, testify, gomock, минимум 80% покрытия тестами

---

## Статус проекта (на 2025-10-15)

### Завершено (10 фаз):
- Инициализация, модели данных, валидация
- Криптография, SQLite storage (80.3% coverage) с MaxOpenConns=1 ✅
- CRDT (94.7% coverage)
- Sync endpoints с 100% тестами
- AuthMiddleware (100% coverage)
- **✅ Client Auth Storage с шифрованием (store_test.go ~90% coverage)**
- **✅ Client CLI: register, login, logout, status команды**
- **✅ Server Auth Handlers тесты (82.5% coverage)**
- **✅ Client CRDT Storage + Data Service + CLI data commands (add, list, get, delete)**
- **✅ Версионирование (--version флаг с Version, BuildDate, GitCommit через ldflags)**

### Частично (3 фазы):
- API (~70%) — ✅ auth handlers с тестами, sync endpoints готовы
- Сервер (~70%) — ✅ Recovery/Logging/RateLimit middleware с тестами (100% coverage), ✅ auth handlers с тестами, ❌ отсутствует TLS
- Клиент (~92%) — ✅ register/login/logout с шифрованием токенов, ✅ CRDT storage с тестами, ✅ data service с тестами, ✅ CLI: add/list/get/delete/sync для всех типов (credentials/text/binary/card), ✅ sync logic с тестами (90.4% coverage), ✅ client/api тесты (87.4% coverage), ❌ refresh token auto-renewal

### Не начато (4+ фаз):
- Тестирование, документация, CI/CD, Docker, TLS конфигурация, client sync и др.

### Критические проблемы:
- Отсутствует TLS (HTTPS)
- Отсутствует автоматическое обновление access token через refresh token

---

## Ключевые сделанные шаги
- CRDT (LWW-Element-Set + Lamport Clock) реализованы
- Полные тесты sync handlers
- Полная валидация username, модели данных, криптоядро
- **✅ SQLite storage с миграциями, WAL mode и MaxOpenConns=1** (подтверждено в storage.go:39)
- **✅ JWT + refresh tokens реализованы с полными тестами (82.5% coverage)**
- **✅ CLI команды: register, login, logout, status**
- **✅ Client auth архитектура с тремя слоями: CLI → Service (API) → AuthService (crypto) → Storage (BoltDB)**
- **✅ Токены шифруются AES-256-GCM перед сохранением в BoltDB**
- **✅ Тесты для auth.AuthService с полным циклом шифрования-дешифрования**
- **✅ Comprehensive тесты для всех auth handlers: Register, GetSalt, Login, Refresh, Logout**
- **✅ Client CRDT Storage (BoltDB) — 337 строк, 9 методов для CRDT операций**
- **✅ Client CRDT Storage тесты — comprehensive coverage для всех CRDT операций**
- **✅ Client Data Service — 158 строк, шифрование/дешифрование данных, CRDT metadata**
- **✅ Client Data Service тесты — 20+ тестов, покрывают все методы, шифрование, edge cases, ошибки**
- **✅ CLI data commands: add credential, list credentials, get credential, delete credential, sync**
- **✅ Zero-knowledge архитектура: master password → Argon2id → encryption_key (не хранится)**
- **✅ Soft delete для CRDT sync: DeleteEntry помечает записи, не удаляет физически**
- **✅ Client Sync Service — полная реализация синхронизации с сервером (push/pull/merge)**
- **✅ Client Sync Service тесты — 10 comprehensive тестов, 90.4% coverage**
- **✅ Metadata Storage — сохранение lastSyncTimestamp для оптимизации синхронизации**
- **✅ Server Middleware — Recovery, Logging, RateLimit с comprehensive тестами (100% coverage)**
- **✅ RateLimit защита для auth endpoints (10 req/min для login/register/getSalt)**
- **✅ Client API тесты — 14 comprehensive тестов для всех API методов (87.4% coverage)**
- **✅ CLI commands для всех типов данных (credentials, text, binary, card) — add/list/get/delete**
- **✅ Safe card number masking — защита от IndexOutOfRange для коротких номеров**
- **✅ Binary file support — сохранение filename в metadata, MIME type detection**
- **✅ Версионирование (--version)** — реализовано для клиента и сервера (main.go с ldflags, Makefile:7)

---

## Основные оставшиеся задачи (приоритет)

1. ✅ ~~**Middleware**~~ (ЗАВЕРШЕНО - 100% coverage):
   - ✅ RateLimit (10 req/min для login, register, getSalt) с token bucket алгоритмом
   - ✅ Logging (структурированное логирование без sensitive данных)
   - ✅ Recovery (перехват паник с полным stack trace)
2. **TLS конфигурация для сервера и клиента** (Let's Encrypt)
3. **Client-side**:
   - ✅ ~~Полная реализация sync logic (fetch, merge, push)~~ (ЗАВЕРШЕНО - 90.4% coverage)
   - ✅ ~~CLI команды управления credentials: add, list, get, delete, sync~~ (ЗАВЕРШЕНО)
   - ✅ ~~CLI команды для других типов данных: text, binary, card~~ (ЗАВЕРШЕНО)
   - Автоматическое обновление access token (refresh)
   - ✅ ~~Хранение токенов в BoltDB с шифрованием~~ (ЗАВЕРШЕНО)
   - ✅ ~~CRDT Storage (BoltDB) с 9 методами~~ (ЗАВЕРШЕНО)
   - ✅ ~~Data Service с шифрованием данных~~ (ЗАВЕРШЕНО)
   - ✅ ~~Metadata Storage для lastSyncTimestamp~~ (ЗАВЕРШЕНО)
4. **Расширение тестового покрытия клиентских модулей** (>80%)
   - ✅ auth.AuthService тесты завершены (~90% coverage)
   - ✅ server auth handlers тесты завершены (82.5% coverage)
   - ✅ **client/api тесты завершены** (client_test.go с 14 тестами: Register, GetSalt, Login, Logout, Sync — 87.4% coverage)
   - ✅ client/storage/boltdb тесты завершены (crdt_test.go с comprehensive тестами)
   - ✅ **client/data тесты завершены** (service_test.go с 20+ тестами: AddCredential, GetCredential, ListCredentials, DeleteCredential, шифрование/дешифрование, edge cases, ошибки)
   - ✅ **client/sync тесты завершены** (service_test.go с 10 comprehensive тестами: push, pull, merge, CRDT conflicts, errors — 90.4% coverage)
5. **Конфигурация через файлы/env (config.yaml, env vars)**
6. **Документация** (README, API, USAGE, SECURITY)
7. **CI/CD, Docker, Makefile доработка**
8. **Дополнительные middleware и производительность**

---

## Краткий план ближайших шагов разработки

| Шаг | Описание | Статус |
|------|-----------|--------|
| 1 | ✅ Покрыть тестами auth handlers | **Завершено** (82.5% coverage) |
| 2 | ✅ Реализовать RateLimit, Logging, Recovery middleware | **Завершено** (100% coverage) |
| 3 | Реализовать TLS (сервер + клиент) | Не сделано |
| 4 | ✅ Разработать CRDT Storage + Data Service для клиента | **Завершено** (с тестами, >80% coverage) |
| 5 | ✅ Реализовать CLI команды для credentials (add/list/get/delete) | **Завершено** (~350 строк) |
| 6 | ✅ Разработать клиентскую sync логику (fetch, merge, push) | **Завершено** (90.4% coverage) |
| 7 | ✅ Реализовать client auth storage с шифрованием | **Завершено** (90% coverage) |
| 8 | ✅ Добавить CLI команды: logout, status | **Завершено** |
| 9 | Расширить тесты клиентской части (auth, api, storage, data) | **Завершено** (auth ✅, storage ✅, data ✅, api ✅ 87.4% coverage) |
| 10 | Обновить конфигурацию (env и config.yaml) | Частично |
| 11 | Создать документацию и пример использования | Не сделано |
| 12 | Настроить CI/CD, сборку, Docker | Не сделано |

---

## Основные риски и рекомендации

| Риск | Статус | Митигация |
|-------|--------|-----------|
| CRDT сложность | ✅ Решено | LWW-Element-Set реализован, 94.7% coverage |
| Недостижение 80% coverage | ✅ Решено | Большинство модулей >80% coverage |
| SQLite "database is locked" | ✅ Решено | WAL + MaxOpenConns=1 подтверждено (storage.go:39) |
| Argon2id медленный | ⚠️ Активно | Текущие параметры: 1 iter, 64MB, 4 threads — приемлемо |
| Отсутствие TLS | ❌ Критично | Внедрить TLS как приоритетный элемент |
| Отсутствие middleware защиты | ✅ Решено | RateLimit, Logging, Recovery реализованы (100% coverage) |

---

## Итоговые цели для MVP

- ✅ Master password + Argon2id, AES-256-GCM шифрование, JWT авторизация с refresh token
- ✅ SQLite сервер с WAL + max connections = 1
- ✅ BoltDB клиентское хранилище
- ✅ Полный CRDT на сервере и клиенте для конфликтоустойчивой синхронизации
- ✅ Базовые API и CLI команды для auth и data
- ✅ Минимум 80% покрытие тестами
- ❌ TLS HTTPS для сервера и клиента
- ✅ Минимум middleware (Auth, RateLimit, Logging, Recovery)
- ⚠️ Документация (API.md устарел, нет USAGE.md, SECURITY.md)
- ❌ CI/CD

---

## Необязательные функции (из ТЗ)

| Функция | Статус | Примечание |
|---------|--------|-----------|
| OTP (One Time Password) support | ❌ Не реализовано | Можно добавить как новый тип данных |
| TUI (Terminal User Interface) | ❌ Не реализовано | CLI полностью реализован |
| Бинарный протокол (gRPC) | ❌ Не реализовано | Используется HTTP REST |
| Функциональные/интеграционные тесты | ⚠️ Частично | Есть unit-тесты (>80%), нет integration |
| Swagger/OpenAPI документация | ⚠️ Частично | Есть API.md (требует обновления) |

---

## Корреляция документов (проверка 2025-10-17)

### ✅ Согласованность между ТЗ, README, CLAUDE.md и планом:
- Все обязательные требования из README.MD отражены в плане
- TECHNICAL_SPEC.md полностью коррелирует с реализацией
- CLAUDE.md содержит актуальные инструкции по разработке
- Большинство функций из ТЗ реализованы и протестированы (>80% coverage)

### ⚠️ Выявленные расхождения:

1. **API.md устарел:**
   - Описывает "stub responses" и TODO
   - Отсутствуют sync endpoints (`GET/POST /api/v1/sync`)
   - Не отражает фактическую реализацию с тестами (82.5% coverage)
   - **Действие:** Обновить API.md с актуальными endpoints и примерами

2. **Отсутствие USAGE.md и SECURITY.md:**
   - ТЗ требует "исчерпывающую документацию"
   - Нет руководства пользователя (USAGE.md)
   - Нет описания security-практик (SECURITY.md)
   - **Действие:** Создать USAGE.md и SECURITY.md

3. **TLS отсутствует (критично):**
   - ТЗ п.12: "TLS 1.3 обязателен"
   - README требует TLS для продакшена
   - **Действие:** Реализовать TLS как приоритет #1

4. **Нет автоматического refresh token renewal:**
   - ТЗ подразумевает автообновление (JWT 15 мин, refresh 30 дней)
   - Токены генерируются, но автообновление не реализовано
   - **Действие:** Добавить логику автообновления в client

5. **Конфигурация частично реализована:**
   - ТЗ п.9: приоритет `GOPHKEEPER_MASTER_PASSWORD` из env
   - Нет config.yaml для сервера
   - **Действие:** Добавить config.yaml и env vars
