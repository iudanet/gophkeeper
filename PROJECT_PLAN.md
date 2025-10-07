# План выполнения проекта GophKeeper

> Обновлено на основе TECHNICAL_SPEC.md (версия 2)

## Технологический стек и подходы

### Ключевые технологии:
- **Go 1.22+** - для использования новых возможностей net/http.ServeMux
- **SQLite** + **goose** - база данных сервера с миграциями (embed.FS)
- **BoltDB** - key-value хранилище на клиенте
- **Argon2id** - key derivation
- **AES-256-GCM** - шифрование
- **JWT** - аутентификация
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

## Фаза 1: Инициализация проекта и базовая инфраструктура

### 1.1 Настройка проекта
- [ ] Инициализация Go модуля (`go mod init github.com/username/gophkeeper`)
- [ ] Установка зависимостей:
  ```bash
  go get github.com/spf13/cobra
  go get github.com/pressly/goose/v3
  go get github.com/stretchr/testify
  go get go.uber.org/mock/mockgen
  go get go.etcd.io/bbolt
  go get github.com/mattn/go-sqlite3
  go get golang.org/x/crypto/argon2
  go get github.com/golang-jwt/jwt/v5
  ```
- [ ] Создание структуры директорий (слоистая архитектура):
  ```
  cmd/{server,client}/
  internal/server/{handlers,service,storage,middleware}/
  internal/client/{cli,service,storage}/
  internal/{crypto,crdt,models,validation}/
  pkg/api/
  migrations/
  docs/
  ```
- [ ] Настройка `.gitignore` (бинарники, *.db, .env, coverage.out, mocks/)
- [ ] Настройка golangci-lint конфигурации
- [ ] Создание Makefile с командами build, test, lint, generate-mocks

### 1.2 Базовая структура кода и логирование
- [ ] Создание `cmd/server/main.go`:
  - Инициализация slog logger (JSON handler для production)
  - Graceful shutdown с context
  - Чтение конфигурации
- [ ] Создание `cmd/client/main.go`:
  - Инициализация Cobra CLI
  - Настройка root command
  - Инициализация slog logger (Text handler для CLI)
- [ ] Настройка версионирования (buildVersion, buildDate через ldflags)
- [ ] Реализация `--version` флага для клиента
- [ ] Базовая конфигурация (config.yaml, env variables)
- [ ] Создание helper функций для slog:
  - `initLogger(level slog.Level)` - инициализация
  - Middleware для логирования HTTP запросов
  - Context-aware логирование

## Фаза 2: Валидация и вспомогательные утилиты

### 2.1 Валидация (`internal/validation/`)
- [ ] Реализация `ValidateUsername()` - regex `^[a-zA-Z0-9_]{3,32}$`
- [ ] Реализация `ValidatePassword()` - минимум 12 символов
- [ ] **Тесты (testify + table-driven):**
  - [ ] TestValidateUsername - табличный тест с 6+ cases
  - [ ] TestValidatePassword - табличный тест с 5+ cases
  - [ ] Запуск: `go test -v ./internal/validation/`
  - [ ] Coverage check: `go test -cover ./internal/validation/` (цель: >85%)

### 2.2 Модели данных (`internal/models/`, `pkg/api/`)
- [ ] Структура `Credential` (name, login, password, url, notes, metadata)
- [ ] Структура `TextData` (name, content, metadata)
- [ ] Структура `BinaryData` (name, data, mime_type, metadata)
- [ ] Структура `CardData` (name, number, holder, expiry, cvv, pin, metadata)
- [ ] Структура `Metadata` (tags, category, favorite, notes, custom_fields)
- [ ] Структура `CRDTEntry` (id, user_id, type, data, version, timestamp, node_id, deleted)
- [ ] JSON сериализация/десериализация
- [ ] Тесты для моделей

## Фаза 3: Криптография

### 3.1 Key Derivation (`internal/crypto/keys.go`)
- [ ] Реализация `DeriveKeys()` с Argon2id
  - Параметры: 1 iteration, 64MB memory, 4 parallelism, 32 bytes output
  - Генерация auth_key (context string: "auth")
  - Генерация encryption_key (context string: "encrypt")
- [ ] Генерация случайного public_salt (32 bytes)
- [ ] Структура `Keys` с полями AuthKey, EncryptionKey
- [ ] Тесты: одинаковые input → одинаковые keys, разные salt → разные keys

### 3.2 Шифрование/дешифрование (`internal/crypto/cipher.go`)
- [ ] Реализация `Encrypt()` с AES-256-GCM
  - Генерация случайного nonce (12 bytes)
  - Формат результата: nonce + ciphertext + auth_tag
  - Base64 кодирование для передачи
- [ ] Реализация `Decrypt()` с AES-256-GCM
  - Извлечение nonce из первых 12 bytes
  - Проверка auth tag
  - Возврат plaintext
- [ ] Тесты: encrypt → decrypt = исходные данные, неверный ключ → ошибка

### 3.3 Хеширование (`internal/crypto/hash.go`)
- [ ] Обертка для `bcrypt.GenerateFromPassword()` для auth_key_hash
- [ ] Обертка для `bcrypt.CompareHashAndPassword()` для проверки
- [ ] Тесты для хеширования

### 3.4 TLS конфигурация
- [ ] Генерация самоподписанных сертификатов для разработки (скрипт/Makefile)
- [ ] Настройка TLS 1.3 для сервера (MinVersion, CipherSuites)
- [ ] Настройка TLS для клиента (проверка сертификатов)

## Фаза 4: Хранилище данных

### 4.1 Серверное хранилище - SQLite + goose миграции (`internal/server/storage/`)
- [ ] **Создание goose миграций (migrations/*.sql):**
  - [ ] `migrations/001_init.sql` - создание таблиц:
    ```sql
    -- +goose Up
    CREATE TABLE users (...);
    CREATE TABLE refresh_tokens (...);
    CREATE TABLE user_data (...);
    CREATE INDEX idx_users_username ON users(username);

    -- +goose Down
    DROP TABLE user_data;
    DROP TABLE refresh_tokens;
    DROP TABLE users;
    ```
- [ ] **Встраивание миграций в бинарник:**
  - [ ] Создать `internal/server/storage/migrations.go`:
    ```go
    //go:embed migrations/*.sql
    var embedMigrations embed.FS

    func RunMigrations(db *sql.DB) error {
        goose.SetBaseFS(embedMigrations)
        goose.SetDialect("sqlite3")
        return goose.Up(db, "migrations")
    }
    ```
  - [ ] Вызвать `RunMigrations()` при старте сервера в `cmd/server/main.go`
- [ ] Тест миграций: проверка Up/Down
- [ ] **Storage Layer - Интерфейсы (для gomock):**
  - [ ] Определить `UserRepository` interface:
    ```go
    type UserRepository interface {
        Create(user *User) error
        GetByUsername(username string) (*User, error)
        GetByID(id string) (*User, error)
    }
    ```
  - [ ] Определить `TokenRepository` interface
  - [ ] Определить `DataRepository` interface
  - [ ] Генерация моков: `make generate-mocks`
- [ ] **Реализация SQLite storage (реальная имплементация):**
  - [ ] `userStorage` - имплементирует `UserRepository`
  - [ ] `tokenStorage` - имплементирует `TokenRepository`
  - [ ] `dataStorage` - имплементирует `DataRepository`
- [ ] **Тесты для storage (с in-memory SQLite):**
  - [ ] TestUserStorage_Create - табличный тест
  - [ ] TestUserStorage_GetByUsername - табличный тест
  - [ ] TestTokenStorage_* - тесты с cleanup
  - [ ] TestDataStorage_* - тесты CRUD операций
  - [ ] Coverage: >85% для storage layer

### 4.2 Клиентское хранилище - BoltDB (`internal/client/storage/`)
- [ ] Создание buckets структуры:
  - `auth/` - username, public_salt, user_id, access_token, refresh_token, token_expiry
  - `data/` - зашифрованные данные (ключ = id)
  - `crdt/` - CRDT метаданные (vector_clock, версии)
  - `meta/` - last_sync timestamp
- [ ] Реализация `Open(path)` - инициализация BoltDB, создание buckets
- [ ] Реализация `AuthStorage`:
  - `SaveLoginInfo(username, publicSalt)`
  - `GetUsername()` → username
  - `GetPublicSalt()` → salt
  - `SaveTokens(accessToken, refreshToken, expiresIn, encryptionKey)` - шифрует токены
  - `GetAccessToken(encryptionKey)` → token (расшифрованный)
  - `GetRefreshToken(encryptionKey)` → token (расшифрованный)
  - `ClearAuth()` - логаут
- [ ] Реализация `DataStorage`:
  - `SaveEntry(id, encryptedData, metadata)`
  - `GetEntry(id)` → encryptedData
  - `GetAllEntries()` → []entry
  - `DeleteEntry(id)`
  - `UpdateEntry(id, encryptedData)`
- [ ] Реализация `CRDTStorage`:
  - `SaveVectorClock(clock)`
  - `GetVectorClock()` → clock
  - `SaveLastSync(timestamp)`
  - `GetLastSync()` → timestamp
- [ ] Тесты для BoltDB storage (>80% coverage)

## Фаза 5: CRDT для синхронизации

### 5.1 Реализация Lamport Clock (`internal/crdt/clock.go`)
- [ ] Структура `LamportClock` (Counter, NodeID)
- [ ] Метод `Tick()` - инкремент счетчика, возврат нового timestamp
- [ ] Метод `Update(remoteTimestamp)` - синхронизация с удаленным timestamp
- [ ] Генерация уникального `NodeID` для каждого клиента (UUID)
- [ ] Тесты: монотонность, корректная синхронизация

### 5.2 Реализация LWW-Element-Set CRDT (`internal/crdt/lww.go`)
- [ ] Структура для хранения элементов с timestamp + node_id
- [ ] Метод `Add(element, timestamp, nodeID)` - добавление элемента
- [ ] Метод `Update(element, timestamp, nodeID)` - обновление элемента
- [ ] Метод `Remove(element, timestamp, nodeID)` - удаление (soft delete)
- [ ] Метод `Merge(local, remote)` - слияние двух состояний:
  - Сравнение по timestamp (больший выигрывает)
  - При равных timestamp - сравнение по nodeID (лексикографически)
- [ ] Метод `Get(id)` - получение текущего состояния элемента
- [ ] Тесты:
  - Конфликт: два обновления одного элемента → корректное разрешение
  - Идемпотентность merge: merge(a, b) = merge(merge(a, b), b)
  - Коммутативность: merge(a, b) = merge(b, a)

### 5.3 Интеграция CRDT с моделями данных
- [ ] Обертка `CRDTEntry` для всех типов данных (credential, text, binary, card)
- [ ] Метод `ToEntry()` для преобразования модели в CRDT entry
- [ ] Метод `FromEntry()` для восстановления модели из CRDT entry
- [ ] Версионирование записей (монотонно растущая версия)
- [ ] Тесты для преобразований

## Фаза 6: API и протокол взаимодействия (REST)

### 6.1 API типы и структуры (`pkg/api/`)
- [ ] Request/Response структуры для всех endpoints
- [ ] `RegisterRequest` (username, auth_key_hash, public_salt)
- [ ] `LoginRequest` (username, auth_key_hash)
- [ ] `TokenResponse` (access_token, refresh_token, expires_in)
- [ ] `SyncRequest` (entries []CRDTEntry)
- [ ] `SyncResponse` (entries []CRDTEntry, conflicts, current_timestamp)
- [ ] Валидация и сериализация JSON

### 6.2 Эндпоинты API (REST)
- [ ] `POST /api/v1/auth/register` - регистрация пользователя
- [ ] `GET /api/v1/auth/salt/:username` - получение public_salt
- [ ] `POST /api/v1/auth/login` - аутентификация, возврат токенов
- [ ] `POST /api/v1/auth/refresh` - обновление access токена
- [ ] `POST /api/v1/auth/logout` - удаление refresh токена
- [ ] `GET /api/v1/sync?since=<timestamp>` - pull изменений с сервера
- [ ] `POST /api/v1/sync` - push изменений на сервер
- [ ] `GET /api/v1/health` - health check (для мониторинга)

### 6.3 Документация API (опционально)
- [ ] OpenAPI спецификация (swagger.yaml)
- [ ] Примеры запросов/ответов
- [ ] Описание кодов ошибок

## Фаза 7: Аутентификация и авторизация

### 7.1 Серверная аутентификация (`internal/server/auth/`)
- [ ] Реализация JWT генерации:
  - Access token (15 минут TTL)
  - Claims: user_id, username, issued_at, expires_at
- [ ] Реализация refresh token:
  - Генерация случайного токена (32 bytes)
  - Хеширование bcrypt перед сохранением в БД
  - TTL: 30 дней
- [ ] Handler `Register`:
  - Валидация username (regex, уникальность)
  - Сохранение user + auth_key_hash + public_salt
  - Возврат user_id
- [ ] Handler `GetSalt`:
  - Получение public_salt по username
  - Возврат 404 если пользователь не найден
- [ ] Handler `Login`:
  - Проверка auth_key_hash с bcrypt
  - Генерация access + refresh tokens
  - Сохранение refresh token в БД
  - Возврат токенов
- [ ] Handler `RefreshToken`:
  - Проверка refresh token
  - Генерация новой пары токенов
  - Удаление старого, сохранение нового refresh token
- [ ] Handler `Logout`:
  - Удаление refresh token из БД
- [ ] Тесты для всех handlers

### 7.2 Middleware (`internal/server/middleware/`)
- [ ] `AuthMiddleware` - проверка JWT access token в header Authorization
- [ ] `RateLimitMiddleware`:
  - Login: 5 попыток / 15 минут
  - Register: 3 попытки / 1 час
  - GetSalt: 10 запросов / 1 минута
- [ ] `LoggingMiddleware` - логирование запросов (без sensitive данных)
- [ ] `RecoveryMiddleware` - обработка паник
- [ ] `CORSMiddleware` (если нужно для будущего web интерфейса)
- [ ] Тесты для middleware

### 7.3 Клиентская аутентификация (`internal/client/auth/`)
- [ ] Функция `GetMasterPassword()`:
  - Проверка переменной среды `GOPHKEEPER_MASTER_PASSWORD`
  - Если нет - интерактивный запрос через `term.ReadPassword()`
- [ ] Функция `Register(username, masterPassword)`:
  - Генерация salt
  - Derivation ключей (auth_key, encryption_key)
  - Хеширование auth_key
  - Отправка на сервер
  - Сохранение username + salt локально
- [ ] Функция `Login(username, masterPassword)`:
  - Получение salt с сервера (или из локального хранилища)
  - Derivation ключей
  - Отправка auth_key_hash на сервер
  - Получение токенов
  - Сохранение токенов (зашифрованных) + username + salt локально
- [ ] Функция `Logout()`:
  - Отправка logout на сервер
  - Очистка локальных токенов
- [ ] Автоматическое обновление access token при истечении (через refresh token)
- [ ] Тесты для auth функций

## Фаза 8: Серверная реализация

### 8.1 HTTP сервер (`cmd/server/main.go`, `internal/server/`)
- [ ] Настройка HTTP сервера (chi router или аналог)
- [ ] Настройка TLS (cert, key из конфигурации)
- [ ] Роутинг:
  ```
  POST   /api/v1/auth/register
  GET    /api/v1/auth/salt/:username
  POST   /api/v1/auth/login
  POST   /api/v1/auth/refresh
  POST   /api/v1/auth/logout
  GET    /api/v1/sync
  POST   /api/v1/sync
  GET    /api/v1/health
  ```
- [ ] Подключение middleware (в правильном порядке):
  - Recovery
  - Logging
  - RateLimit
  - Auth (для защищенных endpoints)
- [ ] Graceful shutdown (context, signal handling)
- [ ] Конфигурация через config.yaml + env variables
- [ ] Структурированное логирование (zerolog/zap)

### 8.2 Handlers для синхронизации (`internal/server/handlers/sync.go`)
- [ ] Handler `GetSync`:
  - Получение `since` timestamp из query params
  - Получение user_id из JWT
  - Получение всех entries пользователя после `since`
  - Возврат entries + current_timestamp
- [ ] Handler `PostSync`:
  - Получение entries из request body
  - Получение user_id из JWT
  - Для каждого entry:
    - Проверка существования в БД
    - Если существует - conflict resolution (CRDT merge)
    - Если не существует - insert
  - Возврат conflicts (если были) + synced count
- [ ] Тесты для sync handlers

### 8.3 Конфигурация и deployment
- [ ] Создание config.yaml с параметрами:
  - server (port, host, tls_cert, tls_key)
  - database (path к SQLite файлу)
  - jwt (secret, access_token_ttl, refresh_token_ttl)
  - rate_limiting (настройки лимитов)
- [ ] Dockerfile для сервера
- [ ] docker-compose для локальной разработки
- [ ] Healthcheck endpoint для мониторинга

## Фаза 9: Клиентская реализация

### 9.1 CLI интерфейс - Cobra (`cmd/client/main.go`, `internal/client/cli/`)
- [ ] Настройка Cobra с подкомандами
- [ ] Команда `register`:
  - Флаги: `--username` (опционально)
  - Интерактивный ввод username и master password
  - Вызов auth.Register()
- [ ] Команда `login`:
  - Флаги: `--username` (опционально)
  - Предложение сохраненного username
  - Интерактивный ввод master password
  - Вызов auth.Login()
- [ ] Команда `logout`:
  - Флаги: `--clear-data` (удалить все локальные данные)
  - Вызов auth.Logout()
- [ ] Команда `status`:
  - Показать текущего пользователя
  - Показать статус токена (истекает через...)
  - Показать last_sync timestamp
- [ ] Команда `add`:
  - Подкоманды: `credential`, `text`, `binary`, `card`
  - Флаги для каждого типа данных
  - Интерактивный ввод полей
  - Шифрование и сохранение локально + пометка для синхронизации
- [ ] Команда `list`:
  - Флаги: `--type`, `--tag`
  - Вывод таблицы всех записей
- [ ] Команда `get <id>`:
  - Флаги: `--show-password` (для credential)
  - Вывод подробной информации о записи
- [ ] Команда `update <id>`:
  - Интерактивное редактирование полей
  - Шифрование и сохранение + пометка для синхронизации
- [ ] Команда `delete <id>`:
  - Подтверждение удаления
  - Soft delete + пометка для синхронизации
- [ ] Команда `search <query>`:
  - Поиск по имени, тегам, metadata
- [ ] Команда `sync`:
  - Флаги: `--force` (полная синхронизация)
  - Вызов sync.Sync()
- [ ] Флаг `--version`:
  - Вывод buildVersion и buildDate

### 9.2 HTTP клиент (`internal/client/api/`)
- [ ] Структура `Client` с базовым URL и HTTP client
- [ ] Метод `Register(username, authKeyHash, publicSalt)` → user_id
- [ ] Метод `GetSalt(username)` → public_salt
- [ ] Метод `Login(username, authKeyHash)` → tokens
- [ ] Метод `RefreshToken(refreshToken)` → new tokens
- [ ] Метод `Logout(accessToken)`
- [ ] Метод `GetSync(accessToken, since)` → entries
- [ ] Метод `PostSync(accessToken, entries)` → conflicts
- [ ] Автоматическое добавление Authorization header
- [ ] Автоматический refresh при 401 ошибке
- [ ] Обработка сетевых ошибок
- [ ] Тесты с mock сервером

### 9.3 Синхронизация (`internal/client/sync/`)
- [ ] Функция `Sync()`:
  - Получение last_sync timestamp
  - Pull: GET /api/v1/sync?since=<timestamp>
  - Merge полученных entries с локальными (CRDT)
  - Сохранение в BoltDB
  - Сбор локальных изменений (новые/измененные)
  - Push: POST /api/v1/sync с локальными изменениями
  - Обработка conflicts
  - Обновление last_sync timestamp
- [ ] Функция `AutoSync()` - периодическая синхронизация в фоне (опционально)
- [ ] Обработка offline режима (отложенная синхронизация)
- [ ] Тесты для синхронизации

### 9.4 Бизнес-логика данных (`internal/client/data/`)
- [ ] Функция `AddCredential(name, login, password, ...)`:
  - Создание Credential модели
  - Сериализация в JSON
  - Шифрование с encryption_key
  - Создание CRDTEntry (timestamp from Lamport clock)
  - Сохранение в BoltDB
  - Пометка для синхронизации
- [ ] Аналогичные функции для text, binary, card
- [ ] Функция `ListEntries(filter)` → []Entry
- [ ] Функция `GetEntry(id)` → Entry (расшифрованный)
- [ ] Функция `UpdateEntry(id, updates)` - новая версия с новым timestamp
- [ ] Функция `DeleteEntry(id)` - soft delete с timestamp
- [ ] Тесты для бизнес-логики

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

### 14.4 Performance
- [ ] Синхронизация 1000 записей < 5 секунд
- [ ] Регистрация/логин < 2 секунд (Argon2 медленный, это ожидаемо)
- [ ] Шифрование/дешифрование 1MB файла < 1 секунда
- [ ] Сервер выдерживает 100 одновременных подключений
- [ ] Нет memory leaks (проверка с pprof)

### 14.5 Финальный рефакторинг
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
3. ✅ BoltDB клиент, SQLite сервер
4. ✅ CRDT (LWW-Element-Set) с Lamport clock
5. ✅ REST API (8 endpoints)
6. ✅ 4 типа данных: credential, text, binary, card
7. ✅ Metadata поддержка
8. ✅ CLI интерфейс (все основные команды)
9. ✅ Username сохранение локально
10. ✅ Master password из env переменной
11. ✅ TLS 1.3
12. ✅ Rate limiting
13. ✅ JWT + refresh tokens
14. ✅ Валидация username (regex)
15. ✅ 80%+ test coverage
16. ✅ Cross-platform (Win/Linux/macOS)
17. ✅ Godoc для всех exported

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
| Argon2 слишком медленный | Низкая | Среднее | Настроить параметры (memory, iterations) |
| Проблемы с BoltDB | Низкая | Среднее | Хорошо протестировать, fallback на SQLite |
| TLS сертификаты в продакшене | Средняя | Среднее | Let's Encrypt, документация |
| Cross-platform баги | Средняя | Среднее | Тестирование на всех платформах в CI |
