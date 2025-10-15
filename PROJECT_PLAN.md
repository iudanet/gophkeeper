# План выполнения проекта GophKeeper

> Обновлено на основе TECHNICAL_SPEC.md (версия 2)

## Технологический стек и подходы

### Ключевые технологии:
- **Go 1.22+** - для использования новых возможностей net/http.ServeMux
- **SQLite** (modernc.org/sqlite) + **goose** - pure Go SQLite без CGO, миграции embed.FS
- **BoltDB** - key-value хранилище на клиенте
- **Argon2id** - key derivation
- **AES-256-GCM** - шифрование
- **JWT** - аутентификация
- **TLS** - Let's Encrypt для production, опция --insecure для dev
- **net/http.ServeMux** - HTTP роутер (Go 1.22+)
- **log/slog** - структурированное логирование
- **Cobra** - CLI framework

### Подходы к разработке:
- **Слоистая архитектура** (3 слоя):
  - Access Layer (HTTP handlers / CLI commands)
  - Service Layer (бизнес-логика)
  - Storage Layer (работа с БД)
- **Table-driven tests** (табличные тесты)
- **testify** - assertions в тестах
- **gomock** - моки интерфейсов
- **TDD workflow**: модуль → тест → запуск → следующий тест
- **80%+ coverage** обязательно

---

## 📊 ТЕКУЩЕЕ СОСТОЯНИЕ ПРОЕКТА (обновлено: 2025-10-15)

### ✅ Полностью выполнено (6 фаз):
- **Фаза 1:** Инициализация проекта (100%)
- **Фаза 2.1:** Валидация (100% coverage)
- **Фаза 2.2:** Модели данных (100% - ЗАВЕРШЕНО!) 🎉
- **Фаза 3:** Криптография (90.1% coverage - отлично!)
- **Фаза 4:** Хранилище SQLite (80.3% coverage - ЗАВЕРШЕНО!) 🎉
- **Фаза 5:** CRDT (94.7% coverage - ЗАВЕРШЕНО!) 🎉

### ⚠️ Частично выполнено (4 фазы):
- ~~**Фаза 2.2:** Модели данных - ПЕРЕНЕСЕНО В ЗАВЕРШЁННЫЕ! ✅~~
- ~~**Фаза 4:** Хранилище - ПЕРЕНЕСЕНО В ЗАВЕРШЁННЫЕ! ✅~~
- **Фаза 6:** API (~60%) - только auth endpoints, нет sync
- **Фаза 7:** Аутентификация (~50%) - handlers есть, middleware нет, **0% coverage** ❌
- **Фаза 8:** Сервер (~40%) - работает HTTP, нет TLS и sync
- **Фаза 9:** Клиент (~20%) - только register/login, нет работы с данными

### ❌ Не начато (4+ фаз):
- **Фаза 10-14:** Тестирование, документация, CI/CD

### 🔴 Критические проблемы:
1. ~~**CRDT не реализован**~~ ✅ **ИСПРАВЛЕНО!** CRDT реализован с 94.7% coverage
2. ~~**Нет моделей данных**~~ ✅ **ИСПРАВЛЕНО!** Все модели созданы и протестированы
3. ~~**Нет таблицы user_data**~~ ✅ **ИСПРАВЛЕНО!** Миграция создана и применена
4. ~~**Нет DataRepository**~~ ✅ **ИСПРАВЛЕНО!** DataRepository реализован с CRDT conflict resolution
5. ~~**Низкий coverage для storage**~~ ✅ **ИСПРАВЛЕНО!** internal/server/storage достиг 80.3% coverage
6. **Нет синхронизации** - нужны sync endpoints и handlers для работы с данными
7. **Низкий coverage для остальных модулей** - 5/9 модулей протестированы (handlers, jwt, client/* - 0%)
8. **Нет TLS** - сервер работает по HTTP (требование: HTTPS)
9. **Нет middleware** - Auth, RateLimit, Logging директория пустая

### 📈 Прогресс по coverage:
| Модуль | Coverage | Требование | Статус |
|--------|----------|------------|--------|
| internal/crypto | 90.1% | 80%+ | ✅ Отлично |
| internal/validation | 100% | 80%+ | ✅ Отлично |
| **internal/crdt** | **94.7%** | **80%+** | **✅ Отлично** 🎉 |
| **internal/server/storage** | **80.3%** | **80%+** | **✅ Отлично** 🎉 |
| internal/server/handlers | 0% | 80%+ | ❌ Критично |
| internal/server/jwt | 0% | 80%+ | ❌ Критично |
| internal/client/auth | 0% | 80%+ | ❌ Критично |
| internal/client/api | 0% | 80%+ | ❌ Критично |
| internal/client/storage | 0% | 80%+ | ❌ Критично |

### 🎯 Следующие шаги (приоритет):
1. ~~**CRDT реализация** (Фаза 5)~~ ✅ **ЗАВЕРШЕНО!**
2. ~~**Модели данных** (Credential, TextData, BinaryData, CardData)~~ ✅ **ЗАВЕРШЕНО!**
3. ~~**Миграция user_data таблицы**~~ ✅ **ЗАВЕРШЕНО!** - создана и применена при старте
4. ~~**DataRepository интерфейс и реализация**~~ ✅ **ЗАВЕРШЕНО!** - реализован с CRDT conflict resolution
5. ~~**Тесты для storage (Фаза 4)**~~ ✅ **ЗАВЕРШЕНО!** - 80.3% coverage достигнуто
6. **Sync endpoints и handlers** (GET/POST /api/v1/sync) - ВЫСОКИЙ ПРИОРИТЕТ
7. **Middleware** (Auth, RateLimit, Logging) - нужно для sync endpoints
8. **Тесты для handlers и JWT** - покрыть 80%+
9. TLS конфигурация
10. CLI команды для работы с данными (add, list, get, update, delete, sync)

---

## Фаза 1: Инициализация проекта и базовая инфраструктура ✅

### 1.1 Настройка проекта ✅
- [x] Инициализация Go модуля (`go mod init github.com/iudanet/gophkeeper`)
- [x] Установка зависимостей:
  ```bash
  # CLI и базовые утилиты
  go get github.com/spf13/cobra@latest

  # База данных (pure Go, без CGO!)
  go get modernc.org/sqlite@latest           # SQLite без CGO ✅
  go get github.com/pressly/goose/v3@latest   # миграции ✅
  go get go.etcd.io/bbolt@latest              # BoltDB для клиента ✅

  # Криптография
  go get golang.org/x/crypto/argon2@latest    # ✅
  go get github.com/golang-jwt/jwt/v5@latest  # ✅ используется

  # Тестирование
  go get github.com/stretchr/testify@latest   # ✅
  go install go.uber.org/mock/mockgen@latest  # для генерации моков
  ```
- [x] Создание структуры директорий (слоистая архитектура):
  ```
  cmd/{server,client}/                        # ✅
  internal/server/{handlers,storage,jwt}/     # ✅ (middleware пустая)
  internal/client/{api,auth,storage}/         # ✅
  internal/{crypto,crdt,models,validation}/   # ✅ (crdt пустая)
  pkg/api/                                    # ✅
  migrations/                                 # ✅
  docs/                                       # ❌ нет
  ```
- [x] Настройка `.gitignore` (бинарники, *.db, .env, coverage.out, mocks/)
- [ ] Настройка golangci-lint конфигурации
- [x] Создание Makefile с командами build, test, lint, generate-mocks

### 1.2 Базовая структура кода и логирование ✅
- [x] Создание `cmd/server/main.go`:
  - Инициализация slog logger (JSON handler для production) ✅
  - Graceful shutdown с context ✅
  - Чтение конфигурации (через флаги) ✅
- [x] Создание `cmd/client/main.go`:
  - Базовый CLI (без Cobra, на флагах) ✅
  - Команды register и login ✅
  - slog logger пока не используется в клиенте
- [x] Настройка версионирования (buildVersion, buildDate через ldflags) ✅
- [x] Реализация `--version` флага для клиента ✅
- [ ] Базовая конфигурация (config.yaml, env variables) - только флаги
- [x] Создание helper функций для slog:
  - `initLogger(level slog.Level)` - инициализация ✅
  - [ ] Middleware для логирования HTTP запросов - middleware директория пустая
  - [ ] Context-aware логирование

## Фаза 2: Валидация и вспомогательные утилиты

### 2.1 Валидация (`internal/validation/`) ✅
- [x] Реализация `ValidateUsername()` - regex `^[a-zA-Z0-9_]{3,32}$` ✅
- [ ] Реализация `ValidatePassword()` - минимум 12 символов (есть в auth, но не выделено)
- [x] **Тесты (testify + table-driven):** ✅
  - [x] TestValidateUsername - табличный тест с 6+ cases ✅
  - [ ] TestValidatePassword - табличный тест с 5+ cases
  - [x] Запуск: `go test -v ./internal/validation/` ✅
  - [x] Coverage check: **100% coverage** ✅ ✅ ✅

### 2.2 Модели данных (`internal/models/`, `pkg/api/`) ✅ (ЗАВЕРШЕНО!)
- [x] Структура `User` (в internal/models/user.go) ✅
- [x] Структура `RegisterRequest/Response`, `LoginRequest/Response` (в pkg/api/auth.go) ✅
- [x] Структура `Credential` (name, login, password, url, notes, metadata) ✅
- [x] Структура `TextData` (name, content, metadata) ✅
- [x] Структура `BinaryData` (name, data, mime_type, metadata) ✅
- [x] Структура `CardData` (name, number, holder, expiry, cvv, pin, metadata) ✅
- [x] Структура `Metadata` (tags, category, favorite, notes, custom_fields) ✅
- [x] Структура `CRDTEntry` (id, user_id, type, data, version, timestamp, node_id, deleted) ✅
- [x] JSON сериализация/десериализация для типов данных ✅
- [x] Тесты для моделей (11 test cases, все проходят) ✅

## Фаза 3: Криптография ✅ (core crypto done, TLS pending)

### 3.1 Key Derivation (`internal/crypto/keys.go`) ✅
- [x] Реализация `DeriveKeys()` с Argon2id ✅
  - Параметры: 1 iteration, 64MB memory, 4 parallelism, 32 bytes output ✅
  - Генерация auth_key (context string: "auth") ✅
  - Генерация encryption_key (context string: "encrypt") ✅
- [x] Генерация случайного public_salt (32 bytes) ✅
- [x] Структура `Keys` с полями AuthKey, EncryptionKey ✅
- [x] Тесты: одинаковые input → одинаковые keys, разные salt → разные keys ✅

### 3.2 Шифрование/дешифрование (`internal/crypto/cipher.go`) ✅
- [x] Реализация `Encrypt()` с AES-256-GCM ✅
  - Генерация случайного nonce (12 bytes) ✅
  - Формат результата: nonce + ciphertext + auth_tag ✅
  - Base64 кодирование для передачи ✅
- [x] Реализация `Decrypt()` с AES-256-GCM ✅
  - Извлечение nonce из первых 12 bytes ✅
  - Проверка auth tag ✅
  - Возврат plaintext ✅
- [x] Тесты: encrypt → decrypt = исходные данные, неверный ключ → ошибка ✅

### 3.3 Хеширование (`internal/crypto/hash.go`) ✅
- [x] Реализация для SHA256 хеширования auth_key ✅
- [x] Тесты для хеширования ✅
- [x] **Coverage: 90.1%** ✅ ✅

### 3.4 TLS конфигурация ❌ (не реализовано)
- [ ] **Сервер - поддержка валидных сертификатов:**
  - [ ] Конфигурация для указания cert_file и key_file ❌
  - [ ] TLS 1.3 минимальная версия ❌
  - [ ] Документация по использованию Let's Encrypt ❌
  - [ ] Пример с certbot в README ❌
- [ ] **Клиент - работа с валидными сертификатами:**
  - [ ] По умолчанию: доверие системным CA (без настройки) ❌
  - [ ] Опция `--ca-cert` для кастомного CA ❌
  - [ ] Опция `--insecure` для dev (с WARNING в логах) ❌
  - [ ] Реализация `NewHTTPClient(cfg Config)` с TLS config ❌
- [ ] **Development режим:**
  - [ ] Makefile target для генерации самоподписанного сертификата ❌
  - [ ] Предупреждение при использовании `--insecure` ❌
- [ ] **Тесты:**
  - [ ] Test TLS connection с валидным сертификатом (mock) ❌
  - [ ] Test insecure mode работает ❌

## Фаза 4: Хранилище данных ⚠️ (реализовано без тестов)

### 4.1 Серверное хранилище - SQLite + goose миграции (`internal/server/storage/`) ⚠️
- [x] **Инициализация SQLite с правильными настройками:** ✅
  - [x] Создать `internal/server/storage/sqlite/storage.go` ✅
    - Реализован OpenDB с DSN и pragma настройками ✅
  - ⚠️ **ВАЖНО: MaxOpenConns = 1** - нужно проверить реализацию
  - ⚠️ **WAL mode** - видны файлы .db-wal, но нужно проверить код
  - ⚠️ **busy_timeout = 5000ms** - нужно проверить
  - ⚠️ **foreign_keys = ON** - нужно проверить
- [x] **Создание goose миграций (migrations/*.sql):** ✅
  - [x] `00001_create_users_table.sql` - создание таблицы users ✅
  - [x] `00002_create_refresh_tokens_table.sql` - создание таблицы tokens ✅
  - [x] `00003_create_user_data_table.sql` - создание таблицы user_data для CRDT данных ✅
- [x] **Встраивание миграций в бинарник:** ✅
  - [x] Миграции встроены через `//go:embed` ✅
  - [x] `RunMigrations()` вызывается при старте сервера ✅
- [x] **Тесты:** ✅
  - [ ] Тест миграций: проверка Up/Down ❌
  - [ ] Тест что WAL режим активирован: `PRAGMA journal_mode;` ❌
  - [ ] Тест connection pool: db.Stats().OpenConnections <= 1 ❌
  - [x] **Coverage: 80.3%** ✅ **ДОСТИГНУТО!**
- [x] **Storage Layer - Интерфейсы (для gomock):** ✅
  - [x] `UserRepository` interface определен ✅
  - [x] `TokenRepository` interface определен ✅
  - [x] `DataRepository` interface определен ✅
  - [ ] Генерация моков: `make generate-mocks` - не настроено ❌
- [x] **Реализация SQLite storage (реальная имплементация):** ✅
  - [x] `userStorage` - имплементирует `UserRepository` ✅
  - [x] `tokenStorage` - имплементирует `TokenRepository` ✅
  - [x] `dataStorage` - имплементирует `DataRepository` ✅
- [x] **Тесты для storage (с in-memory SQLite):** ✅
  - [x] TestUserStorage_* - все методы ✅
    - [x] TestUserStorage_CreateUser (2 test cases) ✅
    - [x] TestUserStorage_CreateUser_DuplicateUsername ✅
    - [x] TestUserStorage_GetUserByUsername (2 test cases) ✅
    - [x] TestUserStorage_GetUserByID (2 test cases) ✅
    - [x] TestUserStorage_UpdateUser (2 test cases) ✅
    - [x] TestUserStorage_DeleteUser (2 test cases) ✅
    - [x] TestUserStorage_UpdateLastLogin (2 test cases) ✅
  - [x] TestTokenStorage_* - все методы ✅
    - [x] TestTokenStorage_SaveRefreshToken (2 test cases) ✅
    - [x] TestTokenStorage_GetRefreshToken (2 test cases) ✅
    - [x] TestTokenStorage_GetUserTokens (3 test cases) ✅
    - [x] TestTokenStorage_GetUserTokens_OrderedByCreatedAt ✅
    - [x] TestTokenStorage_DeleteRefreshToken (2 test cases) ✅
    - [x] TestTokenStorage_DeleteUserTokens (2 test cases) ✅
    - [x] TestTokenStorage_DeleteExpiredTokens ✅
    - [x] TestTokenStorage_DeleteExpiredTokens_NoExpired ✅
  - [x] TestDataStorage_* - тесты CRUD операций ✅
    - [x] TestDataStorage_SaveEntry_Create (3 test cases) ✅
    - [x] TestDataStorage_SaveEntry_CRDT_Conflict (4 test cases) ✅
    - [x] TestDataStorage_GetUserEntries ✅
    - [x] TestDataStorage_GetUserEntriesSince (4 test cases) ✅
    - [x] TestDataStorage_GetUserEntriesByType (3 test cases) ✅
    - [x] TestDataStorage_DeleteEntry ✅
    - [x] TestDataStorage_GetEntry_NotFound ✅
    - [x] TestDataStorage_DeleteEntry_NotFound ✅
  - [x] **Coverage: 80.3%** ✅ **ДОСТИГНУТО!** (требование >80%)

### 4.2 Клиентское хранилище - BoltDB (`internal/client/storage/`) ⚠️
- [x] Создание buckets структуры: ✅
  - `auth/` - username, public_salt, user_id, access_token, refresh_token, token_expiry ✅
  - `secrets/` - зашифрованные данные ✅
  - ⚠️ `crdt/` - CRDT метаданные (вероятно не реализовано)
  - ⚠️ `meta/` - last_sync timestamp (вероятно не реализовано)
- [x] Реализация `Open(path)` - инициализация BoltDB, создание buckets ✅
- [x] Реализация `AuthStorage`: ⚠️
  - [x] Методы для auth bucket реализованы ✅
  - ⚠️ Но нужно проверить соответствие требованиям (шифрование токенов, etc)
- [ ] Реализация `DataStorage` (для secrets): ⚠️
  - Реализовано в `boltdb/secrets.go`, но нужно проверить
- [ ] Реализация `CRDTStorage`: ❌
  - [ ] `SaveVectorClock(clock)` ❌
  - [ ] `GetVectorClock()` → clock ❌
  - [ ] `SaveLastSync(timestamp)` ❌
  - [ ] `GetLastSync()` → timestamp ❌
- [ ] **Тесты для BoltDB storage:** ❌
  - [ ] **Coverage: 0%** (требование >80%) ❌ ❌ ❌

## Фаза 5: CRDT для синхронизации ✅ (ЗАВЕРШЕНО!)

### 5.1 Реализация Lamport Clock (`internal/crdt/clock.go`) ✅
- [x] Структура `LamportClock` (Counter, NodeID) ✅
- [x] Метод `Tick()` - инкремент счетчика, возврат нового timestamp ✅
- [x] Метод `Update(remoteTimestamp)` - синхронизация с удаленным timestamp ✅
- [x] Генерация уникального `NodeID` для каждого клиента (UUID) ✅
- [x] Метод `GetTimestamp()`, `GetNodeID()`, `SetTimestamp()` ✅
- [x] Потокобезопасность (sync.Mutex) ✅
- [x] **Тесты: монотонность, корректная синхронизация** ✅
  - [x] TestLamportClock_Tick - табличные тесты ✅
  - [x] TestLamportClock_Update - табличные тесты ✅
  - [x] TestLamportClock_ConcurrentTick - тест потокобезопасности ✅
  - [x] TestLamportClock_ConcurrentUpdate - тест потокобезопасности ✅
  - [x] **Coverage: 100%** ✅ ✅ ✅

### 5.2 Реализация LWW-Element-Set CRDT (`internal/crdt/lww.go`) ✅
- [x] Структура `LWWSet` для хранения элементов с timestamp + node_id ✅
- [x] Метод `Add(entry)` - добавление элемента ✅
- [x] Метод `Update(entry)` - обновление элемента (алиас для Add) ✅
- [x] Метод `Remove(entry)` - удаление (soft delete) ✅
- [x] Метод `Merge(other)` - слияние двух состояний: ✅
  - Сравнение по timestamp (больший выигрывает) ✅
  - При равных timestamp - сравнение по nodeID (лексикографически) ✅
- [x] Метод `Get(id)` - получение текущего состояния элемента ✅
- [x] Методы `GetAll()`, `GetAllIncludingDeleted()`, `Contains()`, `Size()`, `Clear()` ✅
- [x] Потокобезопасность (sync.RWMutex) ✅
- [x] **Тесты:** ✅
  - [x] Конфликт: два обновления одного элемента → корректное разрешение ✅
  - [x] Идемпотентность merge: merge(a, b) = merge(merge(a, b), b) ✅
  - [x] Коммутативность: merge(a, b) = merge(b, a) ✅
  - [x] Тесты потокобезопасности (ConcurrentAdd, ConcurrentMerge) ✅
  - [x] **Coverage: 94.7%** ✅ ✅ ✅

### 5.3 Интеграция CRDT с моделями данных ✅
- [x] Модель `CRDTEntry` для всех типов данных (credential, text, binary, card) ✅
  - Поля: ID, UserID, Type, Data, Metadata, Version, Timestamp, NodeID, Deleted ✅
  - Константы DataType* для типов ✅
- [x] Метод `IsNewerThan(other)` для сравнения записей ✅
- [x] Метод `Clone()` для создания глубокой копии ✅
- [x] Версионирование записей через поле Version ✅
- [ ] Методы ToEntry/FromEntry для конкретных типов данных (будут реализованы при создании моделей Credential, Text, Binary, Card)

**✅ CRDT РЕАЛИЗОВАН! Ключевая функция проекта завершена с отличным coverage (94.7%+)**

**Что сделано:**
- ✅ Lamport Clock для упорядочивания событий (100% coverage)
- ✅ LWW-Element-Set для разрешения конфликтов (94.7% coverage)
- ✅ Модель CRDTEntry для хранения данных
- ✅ Полная потокобезопасность
- ✅ Комплексные тесты (табличные, конкурентные, свойства CRDT)

## Фаза 6: API и протокол взаимодействия (REST) ⚠️ (частично)

### 6.1 API типы и структуры (`pkg/api/`) ⚠️
- [x] Request/Response структуры для auth endpoints ✅
- [x] `RegisterRequest` (username, auth_key_hash, public_salt) ✅
- [x] `LoginRequest` (username, auth_key_hash) ✅
- [x] `TokenResponse` (access_token, refresh_token, expires_in) ✅
- [ ] `SyncRequest` (entries []CRDTEntry) ❌
- [ ] `SyncResponse` (entries []CRDTEntry, conflicts, current_timestamp) ❌
- [x] Валидация и сериализация JSON ✅

### 6.2 Эндпоинты API (REST) ⚠️
- [x] `POST /api/v1/auth/register` - регистрация пользователя ✅
- [x] `GET /api/v1/auth/salt/{username}` - получение public_salt ✅
- [x] `POST /api/v1/auth/login` - аутентификация, возврат токенов ✅
- [x] `POST /api/v1/auth/refresh` - обновление access токена ✅
- [x] `POST /api/v1/auth/logout` - удаление refresh токена ✅
- [ ] `GET /api/v1/sync?since=<timestamp>` - pull изменений с сервера ❌
- [ ] `POST /api/v1/sync` - push изменений на сервер ❌
- [x] `GET /api/v1/health` - health check (для мониторинга) ✅

### 6.3 Документация API (опционально) ❌
- [ ] OpenAPI спецификация (swagger.yaml) ❌
- [ ] Примеры запросов/ответов ❌
- [ ] Описание кодов ошибок ❌

## Фаза 7: Аутентификация и авторизация ⚠️ (handlers done, middleware missing, no tests)

### 7.1 Серверная аутентификация (`internal/server/jwt/`, `internal/server/handlers/`) ⚠️
- [x] Реализация JWT генерации (`internal/server/jwt/jwt.go`): ✅
  - Access token (15 минут TTL) ✅
  - Claims: user_id, username, issued_at, expires_at ✅
- [x] Реализация refresh token: ✅
  - Генерация случайного токена ✅
  - Сохранение в БД ✅
  - TTL: 30 дней ✅
- [x] Handler `Register` (`internal/server/handlers/auth.go`): ✅
  - Валидация username (regex, уникальность) ✅
  - Сохранение user + auth_key_hash + public_salt ✅
  - Возврат user_id ✅
- [x] Handler `GetSalt`: ✅
  - Получение public_salt по username ✅
  - Возврат 404 если пользователь не найден ✅
- [x] Handler `Login`: ✅
  - Проверка auth_key_hash ✅
  - Генерация access + refresh tokens ✅
  - Сохранение refresh token в БД ✅
  - Возврат токенов ✅
- [x] Handler `RefreshToken`: ✅
  - Проверка refresh token ✅
  - Генерация новой пары токенов ✅
  - Обновление refresh token в БД ✅
- [x] Handler `Logout`: ✅
  - Удаление refresh token из БД ✅
- [ ] **Тесты для всех handlers:** ❌
  - [ ] **Coverage: 0%** ❌ ❌ ❌

### 7.2 Middleware (`internal/server/middleware/`) ❌ (директория пустая!)
- [ ] `AuthMiddleware` - проверка JWT access token в header Authorization ❌
- [ ] `RateLimitMiddleware`: ❌
  - Login: 5 попыток / 15 минут ❌
  - Register: 3 попытки / 1 час ❌
  - GetSalt: 10 запросов / 1 минута ❌
- [ ] `LoggingMiddleware` - логирование запросов (без sensitive данных) ❌
- [ ] `RecoveryMiddleware` - обработка паник ❌
- [ ] `CORSMiddleware` (если нужно для будущего web интерфейса) ❌
- [ ] Тесты для middleware ❌

### 7.3 Клиентская аутентификация (`internal/client/auth/`) ⚠️
- [x] Реализовано в `internal/client/auth/auth.go` ✅
  - [x] Register(username, masterPassword) ✅
  - [x] Login(username, masterPassword) ✅
- [ ] Функция `GetMasterPassword()`: ⚠️
  - Проверка переменной среды `GOPHKEEPER_MASTER_PASSWORD` - возможно есть
  - Интерактивный запрос через `term.ReadPassword()` - реализовано в main.go, но не в отдельной функции
- [ ] Сохранение токенов (зашифрованных) локально - нужно проверить ⚠️
- [ ] Функция `Logout()`: ❌
- [ ] Автоматическое обновление access token при истечении (через refresh token) ❌
- [ ] **Тесты для auth функций:** ❌
  - [ ] **Coverage: 0%** ❌ ❌ ❌

## Фаза 8: Серверная реализация ⚠️ (partial)

### 8.1 HTTP сервер (`cmd/server/main.go`, `internal/server/`) ⚠️
- [x] Настройка HTTP сервера с **net/http.ServeMux** (Go 1.22+) ✅
- [ ] Настройка TLS (cert, key из конфигурации, поддержка Let's Encrypt) ❌
- [x] Роутинг с методами: ⚠️
  ```
  POST   /api/v1/auth/register     ✅
  GET    /api/v1/auth/salt/:username  ✅ (использует {username})
  POST   /api/v1/auth/login        ✅
  POST   /api/v1/auth/refresh      ✅
  POST   /api/v1/auth/logout       ✅
  GET    /api/v1/sync              ❌ НЕ РЕАЛИЗОВАНО
  POST   /api/v1/sync              ❌ НЕ РЕАЛИЗОВАНО
  GET    /api/v1/health            ✅
  ```
- [ ] Подключение middleware (в правильном порядке): ❌
  - [ ] Recovery ❌
  - [ ] Logging ❌
  - [ ] RateLimit ❌
  - [ ] Auth (для защищенных endpoints) ❌
- [x] Graceful shutdown (context, signal handling) ✅
- [ ] Конфигурация через config.yaml + env variables - только флаги ⚠️
- [x] Структурированное логирование (slog) ✅

### 8.2 Handlers для синхронизации (`internal/server/handlers/sync.go`) ❌
- [ ] Handler `GetSync`: ❌
  - Получение `since` timestamp из query params ❌
  - Получение user_id из JWT ❌
  - Получение всех entries пользователя после `since` ❌
  - Возврат entries + current_timestamp ❌
- [ ] Handler `PostSync`: ❌
  - Получение entries из request body ❌
  - Получение user_id из JWT ❌
  - Для каждого entry: ❌
    - Проверка существования в БД ❌
    - Если существует - conflict resolution (CRDT merge) ❌
    - Если не существует - insert ❌
  - Возврат conflicts (если были) + synced count ❌
- [ ] Тесты для sync handlers ❌

### 8.3 Конфигурация и deployment ⚠️
- [ ] Создание config.yaml с параметрами: ⚠️
  - Сейчас используются только флаги командной строки
- [ ] Dockerfile для сервера ❌
- [ ] docker-compose для локальной разработки ❌
- [x] Healthcheck endpoint для мониторинга ✅

## Фаза 9: Клиентская реализация ⚠️ (basic auth only, no data management)

### 9.1 CLI интерфейс - Базовый (`cmd/client/main.go`) ⚠️
- [ ] Настройка Cobra с подкомандами ❌ (используются простые флаги)
- [x] Команда `register`: ✅
  - Интерактивный ввод username и master password ✅
  - Вызов auth.Register() ✅
- [x] Команда `login`: ✅
  - Интерактивный ввод username и master password ✅
  - Вызов auth.Login() ✅
- [ ] Команда `logout`: ❌
- [ ] Команда `status`: ❌
- [ ] Команда `add`: ❌
  - Подкоманды: `credential`, `text`, `binary`, `card` ❌
- [ ] Команда `list`: ❌
- [ ] Команда `get <id>`: ❌
- [ ] Команда `update <id>`: ❌
- [ ] Команда `delete <id>`: ❌
- [ ] Команда `search <query>`: ❌
- [ ] Команда `sync`: ❌
- [ ] Команда `config`: ❌
- [x] **Глобальные флаги:** ⚠️
  - [x] `--version` - вывод buildVersion и buildDate ✅
  - [x] `--server <url>` - переопределить URL сервера ✅
  - [ ] `--insecure` - отключить проверку TLS ❌
  - [ ] `--ca-cert <path>` - указать кастомный CA сертификат ❌

### 9.2 HTTP клиент (`internal/client/api/`) ⚠️
- [x] Реализован в `internal/client/api/client.go` ✅
- [ ] **Конфигурация клиента:** ⚠️
  - Структура простая, без TLS конфигурации
- [x] **API методы:** ⚠️
  - [x] `Register(username, authKeyHash, publicSalt)` → user_id ✅
  - [x] `GetSalt(username)` → public_salt ✅
  - [x] `Login(username, authKeyHash)` → tokens ✅
  - [ ] `RefreshToken(refreshToken)` → new tokens ❌
  - [ ] `Logout(accessToken)` ❌
  - [ ] `GetSync(accessToken, since)` → entries ❌
  - [ ] `PostSync(accessToken, entries)` → conflicts ❌
- [ ] **Дополнительная логика:** ❌
  - [ ] Автоматическое добавление Authorization header ❌
  - [ ] Автоматический refresh при 401 ошибке ❌
  - [ ] User-friendly ошибки для TLS проблем ❌
- [ ] **Тесты:** ❌
  - [ ] **Coverage: 0%** ❌ ❌ ❌

### 9.3 Синхронизация (`internal/client/sync/`) ❌
- [ ] Функция `Sync()`: ❌
  - Получение last_sync timestamp ❌
  - Pull: GET /api/v1/sync?since=<timestamp> ❌
  - Merge полученных entries с локальными (CRDT) ❌
  - Сохранение в BoltDB ❌
  - Сбор локальных изменений (новые/измененные) ❌
  - Push: POST /api/v1/sync с локальными изменениями ❌
  - Обработка conflicts ❌
  - Обновление last_sync timestamp ❌
- [ ] Функция `AutoSync()` - периодическая синхронизация в фоне (опционально) ❌
- [ ] Обработка offline режима (отложенная синхронизация) ❌
- [ ] Тесты для синхронизации ❌

### 9.4 Бизнес-логика данных (`internal/client/data/`) ❌
- [ ] Функция `AddCredential(name, login, password, ...)`: ❌
  - Создание Credential модели ❌
  - Сериализация в JSON ❌
  - Шифрование с encryption_key ❌
  - Создание CRDTEntry (timestamp from Lamport clock) ❌
  - Сохранение в BoltDB ❌
  - Пометка для синхронизации ❌
- [ ] Аналогичные функции для text, binary, card ❌
- [ ] Функция `ListEntries(filter)` → []Entry ❌
- [ ] Функция `GetEntry(id)` → Entry (расшифрованный) ❌
- [ ] Функция `UpdateEntry(id, updates)` - новая версия с новым timestamp ❌
- [ ] Функция `DeleteEntry(id)` - soft delete с timestamp ❌
- [ ] Тесты для бизнес-логики ❌

## Фаза 10: Тестирование

### 10.1 Unit тесты
- [ ] Тесты для `internal/crypto/` (>80% coverage):
  - Key derivation с разными параметрами
  - Шифрование/дешифрование
  - Граничные случаи (пустые данные, некорректный ключ)
- [ ] Тесты для `internal/crdt/` (>80% coverage):
  - Lamport clock tick/update
  - CRDT merge в конфликтных сценариях
  - Идемпотентность и коммутативность
- [ ] Тесты для `internal/validation/` (>80% coverage):
  - Корректные и некорректные username
  - Password валидация
- [ ] Тесты для `internal/models/` (>80% coverage):
  - Сериализация/десериализация всех типов
- [ ] Тесты для storage layers (>80% coverage):
  - Server SQLite storage
  - Client BoltDB storage
- [ ] Тесты для auth логики (>80% coverage):
  - JWT генерация/валидация
  - Token refresh
  - Master password flow
- [ ] Общий coverage отчет: `go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out`
- [ ] Проверка минимального порога: coverage >= 80%

### 10.2 Интеграционные тесты (`tests/integration/`)
- [ ] Тесты для API эндпоинтов с реальным SQLite (in-memory):
  - POST /api/v1/auth/register → 201 Created
  - GET /api/v1/auth/salt/:username → 200 OK с salt
  - POST /api/v1/auth/login → 200 OK с токенами
  - POST /api/v1/auth/refresh → 200 OK с новыми токенами
  - GET /api/v1/sync → 200 OK с entries
  - POST /api/v1/sync → 200 OK с conflicts
  - Negative cases: invalid data, unauthorized, rate limiting
- [ ] Тесты для клиент-сервер взаимодействия:
  - Запуск тестового сервера
  - Клиент регистрируется
  - Клиент добавляет данные
  - Клиент синхронизирует
  - Проверка данных на сервере
- [ ] Тесты для CRDT синхронизации между двумя клиентами:
  - Клиент 1 добавляет credential A
  - Клиент 2 добавляет credential B
  - Оба синхронизируют
  - Проверка, что оба клиента имеют A и B
- [ ] Тесты для конфликтов:
  - Оба клиента изменяют одну запись offline
  - Оба синхронизируют
  - Проверка корректного разрешения (по timestamp + nodeID)

### 10.3 E2E тесты (`tests/e2e/`)
- [ ] Тестовый сценарий: новый пользователь
  ```
  1. Register alice
  2. Login alice
  3. Add credential "GitHub"
  4. Sync
  5. Verify credential на сервере
  ```
- [ ] Тестовый сценарий: несколько клиентов
  ```
  1. Client1: Register alice
  2. Client1: Add credential "GitHub"
  3. Client1: Sync
  4. Client2: Login alice (тот же username/password)
  5. Client2: Sync
  6. Verify Client2 имеет "GitHub"
  7. Client2: Add text "Note"
  8. Client2: Sync
  9. Client1: Sync
  10. Verify Client1 имеет "GitHub" и "Note"
  ```
- [ ] Тестовый сценарий: offline → online
  ```
  1. Client: Login
  2. Stop server
  3. Client: Add credential (сохраняется локально)
  4. Start server
  5. Client: Sync
  6. Verify data на сервере
  ```
- [ ] Тестовый сценарий: конфликтное изменение
  ```
  1. Both clients: Login
  2. Both clients: Sync (получают credential A)
  3. Stop server
  4. Client1: Update credential A (password = "pass1")
  5. Client2: Update credential A (password = "pass2")
  6. Start server
  7. Client1: Sync (push pass1)
  8. Client2: Sync (push pass2, conflict resolution)
  9. Verify winner based on timestamp
  ```

## Фаза 11: Документация

### 11.1 Godoc документация
- [ ] Package documentation для каждого пакета (doc.go):
  - `internal/crypto` - "Package crypto provides encryption and key derivation functions"
  - `internal/crdt` - "Package crdt implements LWW-Element-Set CRDT for data synchronization"
  - `internal/models` - "Package models defines data structures for stored items"
  - И т.д. для всех пакетов
- [ ] Godoc комментарии для всех exported функций:
  - Описание что делает функция
  - Описание параметров
  - Описание возвращаемых значений
  - Примеры использования (если сложная функция)
- [ ] Godoc комментарии для всех exported типов и их полей
- [ ] Godoc комментарии для всех exported констант и переменных
- [ ] Проверка документации: `go doc -all ./...`
- [ ] Генерация HTML документации: `godoc -http=:6060`

### 11.2 Пользовательская документация
- [ ] Обновление README.md:
  - Описание проекта
  - Требования (Go 1.21+)
  - Инструкции по установке
  - Инструкции по сборке (make build)
  - Инструкции по запуску сервера
  - Инструкции по использованию клиента
  - Примеры команд
- [ ] Создание docs/USAGE.md с подробными примерами:
  - Регистрация и первый логин
  - Добавление разных типов данных
  - Синхронизация
  - Работа с несколькими устройствами
- [ ] Создание docs/ARCHITECTURE.md:
  - Диаграмма компонентов
  - Описание zero-knowledge архитектуры
  - Описание CRDT синхронизации
  - Схемы БД
- [ ] Создание docs/API.md:
  - Описание всех endpoints
  - Примеры запросов/ответов curl
  - Коды ошибок
- [ ] Создание docs/SECURITY.md:
  - Описание криптографии
  - Master password подход
  - Что сервер знает / не знает
  - Best practices для пользователей

## Фаза 12: Опциональные функции (Nice to Have)

### 12.1 OTP (One Time Password) support
- [ ] Добавить новый тип данных `OTPData`:
  - Name (e.g., "Google Account")
  - Secret (base32 encoded)
  - Issuer
  - Algorithm (SHA1/SHA256)
  - Digits (6/8)
  - Period (30s default)
- [ ] Реализация TOTP генерации:
  - Библиотека: `github.com/pquerna/otp`
  - Функция `GenerateTOTP(secret)` → current code
  - Показ remaining time до следующего кода
- [ ] CLI команды:
  - `gophkeeper add otp --name "Google" --secret "BASE32SECRET"`
  - `gophkeeper get-otp <id>` → показать текущий код + countdown
  - `gophkeeper list otp` → список всех OTP
- [ ] Тесты для TOTP генерации

### 12.2 TUI (Terminal User Interface)
- [ ] Интеграция Bubble Tea framework
- [ ] Главный экран с списком записей:
  - Таблица с колонками: Type, Name, Tags
  - Навигация: ↑↓ для перемещения, Enter для открытия
  - Фильтрация: / для поиска, Tab для фильтра по типу
- [ ] Экран просмотра записи:
  - Показ всех полей (с маскированием паролей)
  - Клавиши: e для edit, d для delete, ESC для возврата
- [ ] Экран редактирования:
  - Форма с полями
  - Навигация: Tab между полями
  - Сохранение: Ctrl+S
- [ ] Hot keys:
  - q - выход
  - a - add new entry
  - s - sync
  - ? - help
- [ ] Тесты для TUI компонентов

### 12.3 gRPC вместо REST
- [ ] Создание proto файлов:
  - `api/proto/auth.proto` (Register, Login, GetSalt, Refresh)
  - `api/proto/sync.proto` (GetSync, PostSync)
  - `api/proto/models.proto` (CRDTEntry, Credential, etc.)
- [ ] Генерация Go кода: `protoc --go_out=. --go-grpc_out=. api/proto/*.proto`
- [ ] Реализация gRPC сервера:
  - Замена HTTP handlers на gRPC methods
  - TLS для gRPC
  - Interceptors для auth, logging, rate limiting
- [ ] Реализация gRPC клиента:
  - Замена HTTP client на gRPC client
  - Connection pooling
- [ ] Сравнение производительности: REST vs gRPC

### 12.4 Swagger/OpenAPI документация
- [ ] Установка swaggo: `go install github.com/swaggo/swag/cmd/swag@latest`
- [ ] Аннотации в handlers:
  ```go
  // @Summary Register new user
  // @Tags auth
  // @Accept json
  // @Produce json
  // @Param request body api.RegisterRequest true "Register Request"
  // @Success 200 {object} api.RegisterResponse
  // @Router /api/v1/auth/register [post]
  ```
- [ ] Генерация swagger.json: `swag init`
- [ ] Интеграция Swagger UI:
  - Endpoint GET /swagger/index.html
  - Статичные файлы swagger-ui
- [ ] Документация всех endpoints

## Фаза 13: Сборка и дистрибуция

### 13.1 Makefile
- [ ] Создание Makefile с командами:
  ```makefile
  build-server:     # Сборка сервера
  build-client:     # Сборка клиента
  build-all:        # Сборка всех бинарников
  test:             # Запуск всех тестов
  test-coverage:    # Тесты с coverage отчетом
  lint:             # Запуск golangci-lint
  clean:            # Очистка бинарников и кеша
  docker-build:     # Сборка Docker образа
  docker-run:       # Запуск в Docker
  ```
- [ ] Cross-compilation для клиента:
  ```makefile
  build-client-all:
    GOOS=linux GOARCH=amd64 go build -ldflags "..." -o bin/gophkeeper-client-linux-amd64
    GOOS=darwin GOARCH=amd64 go build -ldflags "..." -o bin/gophkeeper-client-darwin-amd64
    GOOS=darwin GOARCH=arm64 go build -ldflags "..." -o bin/gophkeeper-client-darwin-arm64
    GOOS=windows GOARCH=amd64 go build -ldflags "..." -o bin/gophkeeper-client-windows-amd64.exe
  ```
- [ ] Интеграция версионирования:
  ```makefile
  VERSION := $(shell git describe --tags --always --dirty)
  BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
  LDFLAGS := -X main.buildVersion=$(VERSION) -X main.buildDate=$(BUILD_DATE)
  ```

### 13.2 Docker
- [ ] Dockerfile для сервера:
  ```dockerfile
  FROM golang:1.21 AS builder
  WORKDIR /app
  COPY . .
  RUN make build-server

  FROM alpine:latest
  RUN apk --no-cache add ca-certificates
  COPY --from=builder /app/bin/gophkeeper-server /usr/local/bin/
  EXPOSE 8080
  CMD ["gophkeeper-server"]
  ```
- [ ] .dockerignore файл
- [ ] docker-compose.yml для локальной разработки:
  ```yaml
  version: '3.8'
  services:
    server:
      build: .
      ports:
        - "8080:8080"
      volumes:
        - ./data:/data
      environment:
        - DB_PATH=/data/gophkeeper.db
        - JWT_SECRET=dev_secret
  ```

### 13.3 CI/CD (GitHub Actions)
- [ ] `.github/workflows/test.yml`:
  - Запуск на push и PR
  - Запуск тестов
  - Проверка coverage (минимум 80%)
  - Запуск linter
- [ ] `.github/workflows/release.yml`:
  - Триггер на git tag (v*)
  - Сборка бинарников для всех платформ
  - Создание GitHub Release
  - Загрузка артефактов
  - Опционально: публикация Docker образа в registry
- [ ] `.github/workflows/lint.yml`:
  - Запуск golangci-lint
  - Проверка форматирования (gofmt)

### 13.4 Установка и распространение
- [ ] Скрипт установки для Linux/macOS:
  ```bash
  curl -sSL https://raw.githubusercontent.com/.../install.sh | bash
  ```
- [ ] Инструкции для Windows (скачать .exe из Releases)
- [ ] Опционально: Homebrew formula
- [ ] Опционально: apt/yum репозитории

## Фаза 14: Финальная проверка и запуск

### 14.1 Проверка обязательных требований
- [ ] **Функциональность:**
  - [ ] Регистрация пользователей работает
  - [ ] Аутентификация с master password работает
  - [ ] Все 4 типа данных поддерживаются (credential, text, binary, card)
  - [ ] Синхронизация между клиентами работает
  - [ ] CRDT корректно разрешает конфликты
  - [ ] Шифрование/дешифрование работает
  - [ ] Username сохраняется локально для удобства
  - [ ] Master password из env переменной работает
- [ ] **Тестирование:**
  - [ ] Unit тесты: `go test ./...` проходят
  - [ ] Coverage: `go test -cover ./...` >= 80%
  - [ ] Интеграционные тесты проходят
  - [ ] E2E сценарий с двумя клиентами работает
- [ ] **Кросс-платформенность:**
  - [ ] CLI собирается для Linux (amd64)
  - [ ] CLI собирается для macOS (amd64, arm64)
  - [ ] CLI собирается для Windows (amd64)
  - [ ] Тестирование на всех платформах
- [ ] **Версионирование:**
  - [ ] `gophkeeper-client --version` показывает версию
  - [ ] `gophkeeper-client --version` показывает дату сборки
- [ ] **Документация:**
  - [ ] Все exported функции имеют godoc комментарии
  - [ ] Все exported типы имеют godoc комментарии
  - [ ] Все пакеты имеют package documentation
  - [ ] README.md актуален и содержит примеры

### 14.2 Проверка безопасности
- [ ] Master password никогда не логируется
- [ ] Encryption key никогда не сохраняется
- [ ] Токены шифруются перед сохранением на клиенте
- [ ] TLS настроен корректно (минимум TLS 1.3)
- [ ] Rate limiting работает на всех критичных endpoints
- [ ] SQL injection защита (prepared statements)
- [ ] Sensitive данные не попадают в логи
- [ ] Проверка на типичные уязвимости (OWASP Top 10)

### 14.3 Code quality
- [ ] `golangci-lint run` проходит без ошибок
- [ ] `gofmt -s -w .` - код отформатирован
- [ ] `go vet ./...` - нет предупреждений
- [ ] Нет TODO/FIXME в production коде
- [ ] Нет закомментированного кода
- [ ] Нет magic numbers (использование констант)
- [ ] Обработка всех ошибок (no ignored errors)
- [ ] Graceful shutdown сервера работает

### 14.4 SQLite конфигурация (критически важно)
- [ ] **Проверка WAL режима:**
  - [ ] Запрос `PRAGMA journal_mode;` возвращает `wal`
  - [ ] Файлы `*.db-wal` и `*.db-shm` создаются
- [ ] **Проверка connection pool:**
  - [ ] `db.Stats().OpenConnections` всегда <= 1
  - [ ] Код содержит `db.SetMaxOpenConns(1)`
  - [ ] Нет ошибок "database is locked" при нагрузке
- [ ] **Проверка других pragma:**
  - [ ] `PRAGMA busy_timeout;` возвращает 5000
  - [ ] `PRAGMA foreign_keys;` возвращает 1 (ON)
- [ ] **Нагрузочное тестирование:**
  - [ ] 100 параллельных запросов без ошибок блокировки
  - [ ] Проверка что одно соединение справляется с нагрузкой

### 14.5 Performance
- [ ] Синхронизация 1000 записей < 5 секунд
- [ ] Регистрация/логин < 2 секунд (Argon2 медленный, это ожидаемо)
- [ ] Шифрование/дешифрование 1MB файла < 1 секунда
- [ ] Сервер выдерживает 100 одновременных подключений (с MaxOpenConns=1)
- [ ] Нет memory leaks (проверка с pprof)

### 14.6 Финальный рефакторинг
- [ ] Удаление неиспользуемого кода
- [ ] Оптимизация импортов
- [ ] Упрощение сложных функций (cyclomatic complexity)
- [ ] Улучшение читаемости кода
- [ ] Добавление недостающих комментариев

## Оценка времени (обновленная)

| Фаза | Описание | Дни | Сложность |
|------|----------|-----|-----------|
| 1 | Инициализация проекта | 1-2 | Низкая |
| 2 | Валидация и модели | 2-3 | Низкая |
| 3 | Криптография | 3-5 | Средняя |
| 4 | Хранилища (SQLite + BoltDB) | 4-6 | Средняя |
| 5 | CRDT | 5-7 | **Высокая** |
| 6 | API определение | 2-3 | Низкая |
| 7 | Аутентификация | 4-6 | Средняя |
| 8 | Серверная реализация | 3-5 | Средняя |
| 9 | Клиентская реализация | 5-7 | Средняя |
| 10 | Тестирование (80%+) | 7-10 | **Высокая** |
| 11 | Документация | 2-3 | Низкая |
| 12 | Опциональные функции | 5-10 | Средняя (опционально) |
| 13 | Сборка и CI/CD | 2-3 | Низкая |
| 14 | Финальная проверка | 2-3 | Средняя |

**Итого:**
- **MVP (без опциональных функций)**: 42-57 дней (6-8 недель)
- **Полная версия (с опциональными)**: 47-67 дней (7-10 недель)

## Приоритизация (MoSCoW)

### Must Have (Обязательно для MVP)
1. ✅ Master password authentication с Argon2
2. ✅ AES-256-GCM шифрование
3. ✅ BoltDB клиент, SQLite сервер (modernc.org/sqlite - pure Go)
4. ✅ **SQLite: WAL mode + MaxOpenConns=1** (критично!)
5. ✅ CRDT (LWW-Element-Set) с Lamport clock
6. ✅ REST API (8 endpoints)
7. ✅ 4 типа данных: credential, text, binary, card
8. ✅ Metadata поддержка
9. ✅ CLI интерфейс (все основные команды)
10. ✅ Username сохранение локально
11. ✅ Master password из env переменной
12. ✅ TLS с Let's Encrypt (production), --insecure для dev
13. ✅ Rate limiting
14. ✅ JWT + refresh tokens
15. ✅ Валидация username (regex)
16. ✅ 80%+ test coverage
17. ✅ Cross-platform (Win/Linux/macOS) без CGO
18. ✅ Godoc для всех exported
19. ✅ net/http.ServeMux (Go 1.22+), log/slog
20. ✅ Слоистая архитектура (3 слоя)
21. ✅ testify + gomock + табличные тесты

### Should Have (Важно, но не критично)
1. 📋 Интеграционные тесты
2. 📋 E2E тесты
3. 📋 Docker для сервера
4. 📋 CI/CD (GitHub Actions)
5. 📋 Детальная документация (USAGE, ARCHITECTURE, API, SECURITY)
6. 📋 Makefile с автоматизацией
7. 📋 Graceful shutdown
8. 📋 Структурированное логирование

### Could Have (Желательно)
1. 💡 OTP (TOTP) поддержка
2. 💡 TUI (Bubble Tea)
3. 💡 Search функциональность
4. 💡 Auto-sync в фоне
5. 💡 Offline mode улучшения

### Won't Have (Не в этой версии, но возможно в будущем)
1. ❌ gRPC (начинаем с REST)
2. ❌ Swagger UI (OpenAPI spec можно)
3. ❌ Web интерфейс
4. ❌ Mobile клиенты
5. ❌ Плагины / расширения
6. ❌ Sharing между пользователями
7. ❌ Резервное копирование

## Следующие шаги

1. **Начать с Фазы 1** - инициализация проекта
2. **Создать ветку** `develop` для разработки
3. **Коммитить часто** - маленькие, логичные коммиты
4. **Тесты сразу** - TDD подход где возможно
5. **Code review** - самопроверка перед каждым коммитом
6. **Документация по ходу** - не откладывать на потом
7. **Регулярная синхронизация** с TECHNICAL_SPEC.md

## Риски и митигация

| Риск | Вероятность | Влияние | Митигация |
|------|-------------|---------|-----------|
| CRDT оказался сложнее | Средняя | Высокое | Начать с простой LWW, усложнять постепенно |
| 80% coverage не достигнут | Средняя | Высокое | Писать тесты параллельно с кодом (TDD) |
| SQLite "database is locked" | **Высокая** | **Критическое** | **WAL mode + MaxOpenConns=1 ОБЯЗАТЕЛЬНО** |
| Забыли настроить MaxOpenConns | Средняя | Высокое | Code review, тесты проверяют db.Stats() |
| Argon2 слишком медленный | Низкая | Среднее | Настроить параметры (memory, iterations) |
| Проблемы с BoltDB | Низкая | Среднее | Хорошо протестировать, fallback на SQLite |
| TLS сертификаты в продакшене | Низкая | Среднее | Let's Encrypt автоматический, документация |
| Cross-platform баги без CGO | Низкая | Среднее | modernc.org/sqlite pure Go, CI на всех платформах |
