# План проекта GophKeeper — Краткий обзор и приоритеты

## Технологии и подходы
- Go 1.22+, SQLite (modernc.org/sqlite), BoltDB клиент, Argon2id, AES-256-GCM, JWT, TLS (Let's Encrypt), net/http.ServeMux, log/slog, Cobra CLI
- Слоистая архитектура (HTTP/CLI → Service → Storage)
- TDD, table-driven tests, testify, gomock, минимум 80% покрытия тестами

---

## Статус проекта (на 2025-10-15)

### Завершено (9 фаз):
- Инициализация, модели данных, валидация
- Криптография, SQLite storage (80.3% coverage)
- CRDT (94.7% coverage)
- Sync endpoints с 100% тестами
- AuthMiddleware (100% coverage)
- **✅ Client Auth Storage с шифрованием (store_test.go ~90% coverage)**
- **✅ Client CLI: register, login, logout, status команды**
- **✅ Server Auth Handlers тесты (82.5% coverage)**
- **✅ Client CRDT Storage + Data Service + CLI data commands (add, list, get, delete)**

### Частично (3 фазы):
- API (~70%) — ✅ auth handlers с тестами, sync endpoints готовы
- Сервер (~50%) — отсутствует TLS, частично middleware, ✅ auth handlers с тестами
- Клиент (~65%) — ✅ register/login/logout с шифрованием токенов, ✅ CRDT storage + data service, ✅ CLI: add/list/get/delete для credentials, ❌ sync logic, ❌ text/binary/card types

### Не начато (4+ фаз):
- Тестирование, документация, CI/CD, Docker, TLS конфигурация, client sync и др.

### Критические проблемы:
- Отсутствует TLS (HTTPS)
- Middleware: нет rate limiting, логирования, recovery
- Клиентская синхронизация с сервером не реализована
- Низкий coverage для client модулей (api, storage/boltdb, data service)
- Реализован только тип данных credential (нужны: text, binary, card)

---

## Ключевые сделанные шаги
- CRDT (LWW-Element-Set + Lamport Clock) реализованы
- Полные тесты sync handlers
- Полная валидация username, модели данных, криптоядро
- SQLite storage с миграциями, WAL mode и MaxOpenConns=1 (требует проверки)
- **✅ JWT + refresh tokens реализованы с полными тестами (82.5% coverage)**
- **✅ CLI команды: register, login, logout, status**
- **✅ Client auth архитектура с тремя слоями: CLI → Service (API) → AuthService (crypto) → Storage (BoltDB)**
- **✅ Токены шифруются AES-256-GCM перед сохранением в BoltDB**
- **✅ Тесты для auth.AuthService с полным циклом шифрования-дешифрования**
- **✅ Comprehensive тесты для всех auth handlers: Register, GetSalt, Login, Refresh, Logout**
- **✅ Client CRDT Storage (BoltDB) — 337 строк, 9 методов для CRDT операций**
- **✅ Client Data Service — 158 строк, шифрование/дешифрование данных, CRDT metadata**
- **✅ CLI data commands: add credential, list credentials, get credential, delete credential**
- **✅ Zero-knowledge архитектура: master password → Argon2id → encryption_key (не хранится)**
- **✅ Soft delete для CRDT sync: DeleteEntry помечает записи, не удаляет физически**

---

## Основные оставшиеся задачи (приоритет)

1. **Middleware**:
   - RateLimit (login, register, getSalt)
   - Logging (без sensitive)
   - Recovery
2. **TLS конфигурация для сервера и клиента** (Let's Encrypt)
3. **Client-side**:
   - Полная реализация sync logic (fetch, merge, push)
   - ✅ ~~CLI команды управления credentials: add, list, get, delete~~ (ЗАВЕРШЕНО)
   - CLI команды для других типов данных: text, binary, card
   - CLI команда sync для синхронизации с сервером
   - Автоматическое обновление access token (refresh)
   - ✅ ~~Хранение токенов в BoltDB с шифрованием~~ (ЗАВЕРШЕНО)
   - ✅ ~~CRDT Storage (BoltDB) с 9 методами~~ (ЗАВЕРШЕНО)
   - ✅ ~~Data Service с шифрованием данных~~ (ЗАВЕРШЕНО)
4. **Расширение тестового покрытия клиентских модулей** (>80%)
   - ✅ auth.AuthService тесты завершены (~90% coverage)
   - ✅ server auth handlers тесты завершены (82.5% coverage)
   - ❌ client/api тесты отсутствуют
   - ❌ client/storage/boltdb тесты отсутствуют (crdt.go 337 строк без тестов)
   - ❌ client/data тесты отсутствуют (service.go 158 строк без тестов)
5. **Конфигурация через файлы/env (config.yaml, env vars)**
6. **Документация** (README, API, USAGE, SECURITY)
7. **CI/CD, Docker, Makefile доработка**
8. **Дополнительные middleware и производительность**

---

## Краткий план ближайших шагов разработки

| Шаг | Описание | Статус |
|------|-----------|--------|
| 1 | ✅ Покрыть тестами auth handlers | **Завершено** (82.5% coverage) |
| 2 | Реализовать RateLimit, Logging, Recovery middleware | Не сделано |
| 3 | Реализовать TLS (сервер + клиент) | Не сделано |
| 4 | ✅ Разработать CRDT Storage + Data Service для клиента | **Завершено** (495 строк, без тестов) |
| 5 | ✅ Реализовать CLI команды для credentials (add/list/get/delete) | **Завершено** (~350 строк) |
| 6 | Разработать клиентскую sync логику (fetch, merge, push) | Не сделано |
| 7 | ✅ Реализовать client auth storage с шифрованием | **Завершено** (90% coverage) |
| 8 | ✅ Добавить CLI команды: logout, status | **Завершено** |
| 9 | Расширить тесты клиентской части (auth, api, storage, data) | Частично (auth ✅, api ❌, storage ❌, data ❌) |
| 10 | Обновить конфигурацию (env и config.yaml) | Частично |
| 11 | Создать документацию и пример использования | Не сделано |
| 12 | Настроить CI/CD, сборку, Docker | Не сделано |

---

## Основные риски и рекомендации

| Риск | Митигация |
|-------|-----------|
| CRDT сложность | Начинать с базового LWW, добавлять функциональность по шагам |
| Недостижение 80% coverage | Писать тесты параллельно с кодом (TDD) |
| SQLite "database is locked" | Проверить и гарантировать WAL + MaxOpenConns=1 |
| Argon2id медленный | Можно адаптировать параметры |
| Отсутствие TLS | Внедрить TLS как приоритетный элемент |
| Отсутствие middleware защиты | Реализовать rate limiting и логирование |

---

## Итоговые цели для MVP

- Master password + Argon2id, AES-256-GCM шифрование, JWT авторизация с refresh token
- SQLite сервер с WAL + max connections = 1
- BoltDB клиентское хранилище
- Полный CRDT на сервере и клиенте для конфликтоустойчивой синхронизации
- Базовые API и CLI команды для auth и data
- Минимум 80% покрытие тестами
- TLS HTTPS для сервера и клиента
- Минимум middleware (Auth, RateLimit, Logging, Recovery)
- Документация и CI/CD
