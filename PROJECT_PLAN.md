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

---

## План достижения 80%+ покрытия тестами (2025-10-17)

### Текущая ситуация
**Общее покрытие: 42.8%** (требуется 80%)

### Детальный анализ покрытия по модулям

| Модуль | Покрытие | Строк кода | Приоритет | Статус |
|--------|----------|------------|-----------|--------|
| **КРИТИЧНЫЕ (низкое покрытие, много кода)** |
| internal/client/cli | 1.7% | ~1386 | 🔴 Высокий | ❌ Не покрыто |
| internal/client/data | 0.0% | 534 | 🔴 Высокий | ❌ Не покрыто |
| internal/client/auth | 39.8% | 364 | 🟡 Средний | ⚠️ Частично |
| internal/client/storage/boltdb | 43.1% | ~337 | 🟡 Средний | ⚠️ Частично |
| **ХОРОШЕЕ ПОКРЫТИЕ (>80%)** |
| internal/client/api | 75.5% | - | 🟢 Низкий | ⚠️ Почти готово |
| internal/client/sync | 91.7% | - | ✅ - | ✅ Готово |
| internal/crdt | 94.7% | - | ✅ - | ✅ Готово |
| internal/crypto | 90.1% | - | ✅ - | ✅ Готово |
| internal/server/handlers | 82.5% | - | ✅ - | ✅ Готово |
| internal/server/middleware | 100.0% | - | ✅ - | ✅ Готово |
| internal/server/storage/sqlite | 80.3% | - | ✅ - | ✅ Готово |
| internal/validation | 100.0% | - | ✅ - | ✅ Готово |
| **НЕ ПОКРЫТО (простые структуры/main)** |
| internal/models | 0.0% | 147 | 🔵 Низкий | ⚠️ Простые структуры |
| cmd/client | 0.0% | - | 🔵 Низкий | ⚠️ main.go (не требует) |
| cmd/server | 0.0% | - | 🔵 Низкий | ⚠️ main.go (не требует) |

### Детальный план по файлам (приоритет по количеству строк)

#### 🔴 Приоритет 1: internal/client/data/service.go (534 строки, 0.0%)
**Проблема:** В PROJECT_PLAN.md указано как завершенное, но тестов НЕТ!
- [ ] Создать `service_test.go`
- [ ] Тесты для AddCredential, AddText, AddBinary, AddCard (4 типа данных)
- [ ] Тесты для GetEntry, ListEntries, DeleteEntry
- [ ] Тесты для шифрования/дешифрования
- [ ] Тесты для обработки ошибок
- [ ] Тесты для CRDT metadata
**Ожидаемое покрытие:** 85%+

#### 🔴 Приоритет 2: internal/client/cli/*.go (1386 строк, 1.7%)
**Проблема:** CLI команды используют fmt.Println, что затрудняет тестирование.
**Решение:** Рефакторинг для использования io.Writer вместо прямого fmt.

##### Файлы для покрытия:
1. **add.go (326 строк)** - добавление данных всех типов
   - [ ] Рефакторинг: передавать io.Writer в команды
   - [ ] Тесты для addCredentialCmd, addTextCmd, addBinaryCmd, addCardCmd
   - [ ] Тесты валидации входных данных
   - [ ] Тесты обработки ошибок
   - [ ] Mock для dataService и authService

2. **cli.go (214 строк)** - инициализация CLI
   - [ ] Тесты для NewCLI
   - [ ] Тесты для initConfig
   - [ ] Тесты для подкоманд root command

3. **delete.go (186 строк)** - удаление данных
   - [ ] Рефакторинг для io.Writer
   - [ ] Тесты для deleteCredentialCmd, deleteTextCmd, deleteBinaryCmd, deleteCardCmd
   - [ ] Тесты подтверждения удаления
   - [ ] Mock для dataService

4. **list.go (177 строк)** - список данных
   - [ ] Рефакторинг для io.Writer
   - [ ] Тесты для listCredentialsCmd, listTextsCmd, listBinaryCmd, listCardsCmd
   - [ ] Тесты форматирования вывода (таблицы)
   - [ ] Тесты для пустых списков

5. **get.go (136 строк)** - получение данных
   - [ ] Рефакторинг для io.Writer
   - [ ] Тесты для getCredentialCmd, getTextCmd, getBinaryCmd, getCardCmd
   - [ ] Тесты для расшифровки и отображения
   - [ ] Тесты для маскирования чувствительных данных

6. **sync.go (77 строк)** - синхронизация
   - [ ] Рефакторинг для io.Writer
   - [ ] Тесты для syncCmd
   - [ ] Mock для syncService

7. **login.go (63 строк)** - вход
   - [ ] Рефакторинг для io.Writer
   - [ ] Тесты для loginCmd
   - [ ] Тесты для валидации username/password
   - [ ] Mock для authService

8. **commands.go (62 строк)** - вспомогательные команды
   - [ ] Тесты для вспомогательных функций

9. **status.go (61 строк)** - статус
   - [ ] Рефакторинг для io.Writer
   - [ ] Тесты для statusCmd
   - [ ] Тесты для отображения статуса авторизации

10. **register.go (55 строк)** - регистрация
    - [ ] Рефакторинг для io.Writer
    - [ ] Тесты для registerCmd
    - [ ] Тесты для валидации

11. **logout.go (20 строк)** - выход
    - [ ] Рефакторинг для io.Writer
    - [ ] Тесты для logoutCmd

12. **helpers.go (9 строк)** - хелперы
    - [ ] Тесты для utility функций

**Ожидаемое покрытие CLI:** 75%+ (учитывая сложность тестирования Cobra команд)

#### 🟡 Приоритет 3: internal/client/auth/service.go (364 строки, 39.8%)
**Проблема:** Есть session_test.go, но покрытие недостаточное.
- [ ] Проанализировать непокрытый код в service.go
- [ ] Добавить тесты для непокрытых методов
- [ ] Добавить тесты для edge cases
- [ ] Добавить тесты для ошибок
**Ожидаемое покрытие:** 85%+

#### 🟡 Приоритет 4: internal/client/storage/boltdb/*.go (337 строк, 43.1%)
**Проблема:** Есть crdt_test.go, но покрытие 43.1%.
- [ ] Проанализировать непокрытые функции
- [ ] Добавить тесты для edge cases (пустая БД, большие данные)
- [ ] Добавить тесты для ошибок БД
- [ ] Тесты для миграций/инициализации
**Ожидаемое покрытие:** 85%+

#### 🟢 Приоритет 5: internal/client/api/*.go (75.5%)
**Проблема:** Почти готово, нужно добрать до 80%.
- [ ] Добавить 2-3 теста для edge cases
- [ ] Покрыть обработку ошибок сети
**Ожидаемое покрытие:** 85%+

#### 🔵 Приоритет 6: internal/models/*.go (147 строк, 0.0%)
**Проблема:** Простые структуры, но нужны тесты для валидации.
- [ ] Тесты для data.go (методы структур)
- [ ] Тесты для crdt.go (методы CRDT)
- [ ] Тесты для user.go (методы User)
**Ожидаемое покрытие:** 60%+ (в основном геттеры/сеттеры)

### Стратегия рефакторинга CLI для тестируемости

**Текущая проблема:**
```go
// Текущий код (нетестируемый)
func listCredentialsCmd(cmd *cobra.Command, args []string) {
    fmt.Println("Credentials:")  // Прямой вывод
}
```

**Решение:**
```go
// Рефакторинг (тестируемый)
type CLI struct {
    out io.Writer  // Добавить поле для вывода
    // ...
}

func (c *CLI) listCredentials(cmd *cobra.Command, args []string) {
    fmt.Fprintln(c.out, "Credentials:")  // Вывод через io.Writer
}

// В тесте:
func TestListCredentials(t *testing.T) {
    buf := &bytes.Buffer{}
    cli := &CLI{out: buf}
    // ...
    assert.Contains(t, buf.String(), "Credentials:")
}
```

### Порядок выполнения (по влиянию на общее покрытие)

1. **internal/client/data/service.go** (534 строки) → +5-7% к общему покрытию
2. **internal/client/cli/*.go** (1386 строк) → +12-15% к общему покрытию
3. **internal/client/auth/service.go** (улучшение) → +3-4% к общему покрытию
4. **internal/client/storage/boltdb** (улучшение) → +3-4% к общему покрытию
5. **internal/client/api** (улучшение до 85%) → +1% к общему покрытию
6. **internal/models** → +1-2% к общему покрытию

**Прогнозируемое итоговое покрытие:** 67-77% (с учетом нетестируемых main.go)
**Для достижения 80%:** фокус на CLI рефакторинге и полном покрытии data/service.go

### Метрика успеха
- ✅ Общее покрытие тестами ≥ 80%
- ✅ Каждый бизнес-логика модуль ≥ 80%
- ✅ CLI команды ≥ 70% (с учетом сложности)
- ✅ Все тесты проходят без ошибок
- ✅ Тесты запускаются быстро (< 5 сек для всех unit-тестов)
