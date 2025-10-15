# План проекта GophKeeper — Краткий обзор и приоритеты

## Технологии и подходы
- Go 1.22+, SQLite (modernc.org/sqlite), BoltDB клиент, Argon2id, AES-256-GCM, JWT, TLS (Let's Encrypt), net/http.ServeMux, log/slog, Cobra CLI
- Слоистая архитектура (HTTP/CLI → Service → Storage)
- TDD, table-driven tests, testify, gomock, минимум 80% покрытия тестами

---

## Статус проекта (на 2025-10-15)

### Завершено (6 фаз):
- Инициализация, модели данных, валидация
- Криптография, SQLite storage (80.3% coverage)
- CRDT (94.7% coverage)
- Sync endpoints с 100% тестами
- AuthMiddleware (100% coverage)

### Частично (4 фазы):
- API (~60%) — auth работающего, sync не до конца
- Аутентификация (~50%) — handlers есть, middleware не хватает, 0% coverage на handlers
- Сервер (~40%) — отсутствует TLS, частично middleware
- Клиент (~20%) — базовые register/login, без данных и sync, 0% coverage

### Не начато (4+ фаз):
- Тестирование, документация, CI/CD, Docker, TLS конфигурация, client sync и др.

### Критические проблемы:
- Низкий coverage для auth handlers и client модулей (auth, api, storage)
- Отсутствует TLS (HTTPS)
- Middleware: нет rate limiting, логирования, recovery
- Клиентская синхронизация и управление данными не реализованы полностью

---

## Ключевые сделанные шаги
- CRDT (LWW-Element-Set + Lamport Clock) реализованы
- Полные тесты sync handlers
- Полная валидация username, модели данных, криптоядро
- SQLite storage с миграциями, WAL mode и MaxOpenConns=1 (требует проверки)
- JWT + refresh tokens реализованы (но без тестов handlers)
- CLI базовые команды register/login

---

## Основные оставшиеся задачи (приоритет)

1. **Тесты для auth handlers** (Register, Login, GetSalt, Refresh, Logout) — покрытие 0%
2. **Middleware**:
   - RateLimit (login, register, getSalt)
   - Logging (без sensitive)
   - Recovery
3. **TLS конфигурация для сервера и клиента** (Let's Encrypt)
4. **Client-side**:
   - Полная реализация sync logic (fetch, merge, push)
   - CLI команды управления данными: add, list, get, update, delete, sync
   - Автоматическое обновление access token (refresh)
   - Хранение токенов и данных в BoltDB с шифрованием
5. **Расширение тестового покрытия клиентских и серверных модулей** (>80%)
6. **Конфигурация через файлы/env (config.yaml, env vars)**
7. **Документация** (README, API, USAGE, SECURITY)
8. **CI/CD, Docker, Makefile доработка**
9. **Дополнительные middleware и производительность**

---

## Краткий план ближайших шагов разработки

| Шаг | Описание | Статус |
|------|-----------|--------|
| 1 | Покрыть тестами auth handlers | Не сделано (0%) |
| 2 | Реализовать RateLimit, Logging, Recovery middleware | Не сделано |
| 3 | Реализовать TLS (сервер + клиент) | Не сделано |
| 4 | Разработать клиентскую sync логику и команды CLI для данных | Не сделано |
| 5 | Расширить тесты клиентской части (auth, api, storage) | Не сделано |
| 6 | Обновить конфигурацию (env и config.yaml) | Частично |
| 7 | Создать документацию и пример использования | Не сделано |
| 8 | Настроить CI/CD, сборку, Docker | Не сделано |

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
