# Техническое задание GophKeeper

## 1. Общее описание

GophKeeper - клиент-серверная система для безопасного хранения и синхронизации приватных данных (учетные записи, пароли, банковские карты, текстовая и бинарная информация).

**Ключевые принципы:**
- Zero-knowledge архитектура - сервер не может расшифровать данные пользователя
- Master password - единственный способ доступа к данным
- CRDT для синхронизации между несколькими клиентами
- End-to-end шифрование всех данных

## 2. Архитектура аутентификации

### 2.1. Master Password подход

**Схема генерации ключей:**
```
Master Password + Username + Public Salt →
├─ Auth Key (для аутентификации на сервере)
└─ Encryption Key (для шифрования данных)
```

**Алгоритм:**
- Key Derivation Function: Argon2id
- Параметры: 1 iteration, 64MB memory, 4 parallelism, 32 bytes output
- Salt: 32 bytes, генерируется при регистрации
- Два независимых ключа с разными context strings ("auth" и "encrypt")

### 2.2. Регистрация нового пользователя

**Процесс (клиент):**
1. Пользователь вводит username и master password
2. Клиент генерирует случайный public_salt (32 bytes)
3. Клиент вычисляет:
   - `auth_key = Argon2(master_password + username + "auth", salt)`
   - `encryption_key = Argon2(master_password + username + "encrypt", salt)`
4. Клиент хеширует auth_key: `auth_key_hash = bcrypt(auth_key)`
5. Клиент отправляет на сервер: username, auth_key_hash, public_salt
6. Клиент сохраняет локально: username, public_salt

**Процесс (сервер):**
1. Валидация username (уникальность, формат)
2. Сохранение в БД: username, auth_key_hash, public_salt
3. Возврат user_id

**API endpoint:**
```
POST /api/v1/auth/register
Request:
{
  "username": "alice",
  "auth_key_hash": "bcrypt_hash",
  "public_salt": "base64_encoded_32_bytes"
}

Response:
{
  "user_id": "uuid",
  "message": "User registered successfully"
}
```

### 2.3. Аутентификация (логин)

**Процесс (клиент):**
1. Пользователь вводит username и master password
2. Клиент запрашивает public_salt с сервера по username
3. Клиент вычисляет auth_key и encryption_key (как при регистрации)
4. Клиент хеширует auth_key и отправляет на сервер
5. Клиент получает JWT токены
6. Клиент сохраняет локально: username, public_salt, токены (зашифрованные)

**Процесс (сервер):**
1. Получение username и auth_key_hash
2. Проверка auth_key_hash с сохраненным в БД
3. Генерация JWT access_token (15 минут) и refresh_token (30 дней)
4. Возврат токенов

**API endpoints:**
```
GET /api/v1/auth/salt/:username
Response:
{
  "public_salt": "base64_encoded_salt"
}

POST /api/v1/auth/login
Request:
{
  "username": "alice",
  "auth_key_hash": "bcrypt_hash"
}

Response:
{
  "access_token": "jwt_token",
  "refresh_token": "random_token",
  "expires_in": 900
}
```

### 2.4. Обновление токенов

```
POST /api/v1/auth/refresh
Authorization: Bearer <refresh_token>

Response:
{
  "access_token": "new_jwt",
  "refresh_token": "new_refresh",
  "expires_in": 900
}
```

### 2.5. Логаут

```
POST /api/v1/auth/logout
Authorization: Bearer <access_token>

Response:
{
  "message": "Logged out successfully"
}
```

**Клиент:**
- Удаляет токены из локального хранилища
- Опционально: удаляет username и все локальные данные

## 3. Валидация данных

### 3.1. Username
- Формат: только латинские буквы (a-z, A-Z), цифры (0-9), нижнее подчеркивание (_)
- Длина: 3-32 символа
- Без точек, дефисов, спецсимволов
- Регулярное выражение: `^[a-zA-Z0-9_]{3,32}$`
- Примеры: ✅ `alice`, `john_doe`, `user123` | ❌ `alice@email.com`, `user.name`, `ab`

### 3.2. Master Password
- Минимальная длина: 12 символов
- Рекомендуется: буквы, цифры, спецсимволы
- Проверка на слабые пароли (опционально)

## 4. Хранение данных

### 4.1. Клиент (BoltDB)

**Путь к файлу:** `~/.gophkeeper/data.db`

**Buckets:**
```
auth/           - Учетные данные и токены
  ├─ username         (plaintext)
  ├─ public_salt      (plaintext, 32 bytes)
  ├─ user_id          (plaintext, UUID)
  ├─ access_token     (encrypted with encryption_key)
  ├─ refresh_token    (encrypted with encryption_key)
  └─ token_expiry     (plaintext, unix timestamp)

data/           - Зашифрованные данные пользователя
  ├─ <id>_credential  (encrypted)
  ├─ <id>_text        (encrypted)
  ├─ <id>_binary      (encrypted)
  └─ <id>_card        (encrypted)

crdt/           - CRDT метаданные
  ├─ vector_clock     (CRDT state)
  └─ <id>_version     (версии для синхронизации)

meta/           - Метаинформация
  └─ last_sync        (unix timestamp)
```

**Особенности:**
- Username и salt хранятся в plaintext для удобства повторного логина
- Токены шифруются encryption_key перед сохранением
- Master password НИКОГДА не сохраняется
- Encryption key НИКОГДА не сохраняется (генерируется каждый раз)
- Без миграций (key-value хранилище)

### 4.2. Сервер (SQLite)

**Путь к файлу:** конфигурируется, по умолчанию `./data/gophkeeper.db`

**Миграции:**
- Использование **goose** для управления миграциями
- Файлы миграций встроены в бинарник через `embed.FS`
- Автоматический запуск миграций при старте сервера
- Расположение: `migrations/*.sql`
- Формат файлов: `001_init.sql`, `002_add_index.sql`, и т.д.

**Пример структуры:**
```go
//go:embed migrations/*.sql
var embedMigrations embed.FS

func RunMigrations(db *sql.DB) error {
    goose.SetBaseFS(embedMigrations)
    if err := goose.SetDialect("sqlite3"); err != nil {
        return err
    }
    if err := goose.Up(db, "migrations"); err != nil {
        return err
    }
    return nil
}
```

**Схема БД:**
```sql
-- Пользователи
CREATE TABLE users (
    id TEXT PRIMARY KEY,                -- UUID
    username TEXT UNIQUE NOT NULL,      -- уникальный логин
    auth_key_hash TEXT NOT NULL,        -- bcrypt хеш auth_key
    public_salt TEXT NOT NULL,          -- base64 encoded salt (32 bytes)
    created_at INTEGER NOT NULL,        -- unix timestamp
    updated_at INTEGER NOT NULL         -- unix timestamp
);

CREATE INDEX idx_users_username ON users(username);

-- Refresh токены
CREATE TABLE refresh_tokens (
    id TEXT PRIMARY KEY,                -- UUID
    user_id TEXT NOT NULL,              -- ссылка на users.id
    token_hash TEXT NOT NULL,           -- bcrypt хеш токена
    expires_at INTEGER NOT NULL,        -- unix timestamp
    created_at INTEGER NOT NULL,        -- unix timestamp
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);

-- Данные пользователей (зашифрованные)
CREATE TABLE user_data (
    id TEXT PRIMARY KEY,                -- UUID
    user_id TEXT NOT NULL,              -- ссылка на users.id
    type TEXT NOT NULL,                 -- 'credential', 'text', 'binary', 'card'
    data BLOB NOT NULL,                 -- зашифрованные данные
    metadata TEXT,                      -- JSON с метаданными (тоже зашифрован)
    version INTEGER NOT NULL,           -- версия для CRDT
    timestamp INTEGER NOT NULL,         -- Lamport timestamp для CRDT
    deleted INTEGER DEFAULT 0,          -- soft delete флаг
    created_at INTEGER NOT NULL,        -- unix timestamp
    updated_at INTEGER NOT NULL,        -- unix timestamp
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_data_user ON user_data(user_id);
CREATE INDEX idx_user_data_version ON user_data(user_id, version);
CREATE INDEX idx_user_data_timestamp ON user_data(user_id, timestamp);
```

## 5. Типы данных

### 5.1. Credential (логин/пароль)
```go
type Credential struct {
    ID       string    `json:"id"`
    Name     string    `json:"name"`      // название (например, "GitHub")
    Login    string    `json:"login"`     // логин/email
    Password string    `json:"password"`  // пароль
    URL      string    `json:"url"`       // опционально: URL сайта
    Notes    string    `json:"notes"`     // опционально: заметки
    Metadata Metadata  `json:"metadata"`  // метаданные
}
```

### 5.2. Text (текстовые данные)
```go
type TextData struct {
    ID       string    `json:"id"`
    Name     string    `json:"name"`      // название
    Content  string    `json:"content"`   // текстовое содержимое
    Metadata Metadata  `json:"metadata"`  // метаданные
}
```

### 5.3. Binary (бинарные данные)
```go
type BinaryData struct {
    ID       string    `json:"id"`
    Name     string    `json:"name"`      // название файла
    Data     []byte    `json:"data"`      // бинарные данные
    MimeType string    `json:"mime_type"` // тип файла
    Metadata Metadata  `json:"metadata"`  // метаданные
}
```

### 5.4. Card (банковская карта)
```go
type CardData struct {
    ID       string    `json:"id"`
    Name     string    `json:"name"`      // название (например, "Visa Gold")
    Number   string    `json:"number"`    // номер карты
    Holder   string    `json:"holder"`    // имя держателя
    Expiry   string    `json:"expiry"`    // срок действия (MM/YY)
    CVV      string    `json:"cvv"`       // CVV код
    PIN      string    `json:"pin"`       // опционально: PIN
    Metadata Metadata  `json:"metadata"`  // метаданные
}
```

### 5.5. Metadata (метаданные)
```go
type Metadata struct {
    Tags       []string  `json:"tags"`        // теги для поиска
    Category   string    `json:"category"`    // категория
    Favorite   bool      `json:"favorite"`    // избранное
    Notes      string    `json:"notes"`       // дополнительные заметки
    CustomFields map[string]string `json:"custom_fields"` // кастомные поля
}
```

## 6. Шифрование данных

### 6.1. Алгоритм шифрования
- **Алгоритм:** AES-256-GCM (Authenticated Encryption)
- **Ключ:** encryption_key (32 bytes, производный от master password)
- **Nonce:** 12 bytes, генерируется случайно для каждой операции шифрования
- **Формат зашифрованных данных:** `nonce (12 bytes) + ciphertext + auth_tag (16 bytes)`

### 6.2. Процесс шифрования (клиент → сервер)
```
1. Сериализация данных в JSON
2. Генерация случайного nonce (12 bytes)
3. Шифрование: ciphertext = AES-256-GCM.Encrypt(json, encryption_key, nonce)
4. Результат: nonce + ciphertext + auth_tag
5. Кодирование в base64 для передачи
6. Отправка на сервер
```

### 6.3. Процесс дешифрования (сервер → клиент)
```
1. Получение зашифрованных данных с сервера
2. Декодирование из base64
3. Извлечение nonce (первые 12 bytes)
4. Дешифрование: plaintext = AES-256-GCM.Decrypt(ciphertext, encryption_key, nonce)
5. Десериализация JSON
```

### 6.4. Что шифруется
- ✅ Все поля данных (credential, text, binary, card)
- ✅ Metadata
- ✅ Токены в локальном хранилище
- ❌ Username (plaintext)
- ❌ Public salt (plaintext)
- ❌ ID записей (plaintext)
- ❌ Тип данных (plaintext для индексации)

## 7. Синхронизация (CRDT)

### 7.1. Тип CRDT
- **Выбранный тип:** LWW-Element-Set (Last-Write-Wins Element Set)
- **Conflict resolution:** По Lamport timestamp + node_id для детерминизма

### 7.2. Структура CRDT
```go
type CRDTEntry struct {
    ID        string `json:"id"`         // UUID записи
    UserID    string `json:"user_id"`    // UUID пользователя
    Type      string `json:"type"`       // тип данных
    Data      []byte `json:"data"`       // зашифрованные данные
    Metadata  []byte `json:"metadata"`   // зашифрованные метаданные
    Version   int64  `json:"version"`    // монотонно растущая версия
    Timestamp int64  `json:"timestamp"`  // Lamport timestamp
    NodeID    string `json:"node_id"`    // ID клиента (для разрешения конфликтов)
    Deleted   bool   `json:"deleted"`    // флаг удаления (soft delete)
}
```

### 7.3. Lamport Clock
```go
type LamportClock struct {
    Counter int64  // монотонный счетчик
    NodeID  string // уникальный ID клиента
}

// При каждом изменении:
func (lc *LamportClock) Tick() int64 {
    lc.Counter++
    return lc.Counter
}

// При получении данных от другого узла:
func (lc *LamportClock) Update(remoteTimestamp int64) {
    if remoteTimestamp > lc.Counter {
        lc.Counter = remoteTimestamp
    }
    lc.Counter++
}
```

### 7.4. Разрешение конфликтов
```
При конфликте (две записи с одним ID):
1. Сравнить timestamp: выбрать запись с большим timestamp
2. Если timestamp равны: сравнить node_id лексикографически
3. Проигравшая запись отбрасывается
```

### 7.5. Синхронизация (push/pull)

**Pull (клиент → сервер):**
```
GET /api/v1/sync?since=<timestamp>
Authorization: Bearer <access_token>

Response:
{
  "entries": [
    {
      "id": "uuid",
      "type": "credential",
      "data": "base64_encrypted",
      "metadata": "base64_encrypted",
      "version": 5,
      "timestamp": 1696789234,
      "node_id": "client2",
      "deleted": false
    },
    ...
  ],
  "current_timestamp": 1696789500
}
```

**Push (клиент → сервер):**
```
POST /api/v1/sync
Authorization: Bearer <access_token>

Request:
{
  "entries": [
    {
      "id": "uuid",
      "type": "text",
      "data": "base64_encrypted",
      "metadata": "base64_encrypted",
      "version": 3,
      "timestamp": 1696789100,
      "node_id": "client1",
      "deleted": false
    },
    ...
  ]
}

Response:
{
  "conflicts": [
    {
      "id": "uuid",
      "server_version": {...},
      "resolution": "server_wins"
    }
  ],
  "synced": 5
}
```

### 7.6. Алгоритм синхронизации
```
1. Клиент получает last_sync_timestamp из локального хранилища
2. Клиент отправляет GET /api/v1/sync?since=<last_sync_timestamp>
3. Сервер возвращает все изменения после этого timestamp
4. Клиент применяет изменения с разрешением конфликтов
5. Клиент собирает свои локальные изменения (новые/измененные)
6. Клиент отправляет POST /api/v1/sync со своими изменениями
7. Сервер применяет изменения с разрешением конфликтов
8. Клиент обновляет last_sync_timestamp
```

## 8. CLI команды

### 8.1. Аутентификация
```bash
# Регистрация
gophkeeper register
gophkeeper register --username alice

# Логин
gophkeeper login
gophkeeper login --username alice
GOPHKEEPER_MASTER_PASSWORD="password" gophkeeper login

# Логаут
gophkeeper logout
gophkeeper logout --clear-data  # удалить все локальные данные

# Статус
gophkeeper status

# Версия
gophkeeper --version
```

### 8.2. Управление данными
```bash
# Добавление
gophkeeper add credential --name "GitHub" --login "alice" --password "pass123"
gophkeeper add text --name "Note" --content "My note"
gophkeeper add binary --name "passport.jpg" --file ./passport.jpg
gophkeeper add card --name "Visa" --number "4111111111111111"

# Просмотр
gophkeeper list
gophkeeper list --type credential
gophkeeper list --tag work
gophkeeper get <id>
gophkeeper get <id> --show-password

# Редактирование
gophkeeper update <id> --password "new_password"
gophkeeper edit <id>  # открыть в редакторе

# Удаление
gophkeeper delete <id>
gophkeeper delete <id> --force  # без подтверждения

# Поиск
gophkeeper search "github"
gophkeeper search --tag personal
```

### 8.3. Синхронизация
```bash
# Синхронизация
gophkeeper sync
gophkeeper sync --force  # принудительная полная синхронизация
```

## 9. Получение master password

### 9.1. Приоритет источников
```
1. Переменная среды GOPHKEEPER_MASTER_PASSWORD
2. Интерактивный ввод (terminal prompt)
```

### 9.2. Реализация
```go
func GetMasterPassword() (string, error) {
    // 1. Проверяем переменную среды
    if password := os.Getenv("GOPHKEEPER_MASTER_PASSWORD"); password != "" {
        return password, nil
    }

    // 2. Запрашиваем у пользователя
    fmt.Print("Enter master password: ")
    passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
    if err != nil {
        return "", err
    }
    fmt.Println()

    password := strings.TrimSpace(string(passwordBytes))
    if password == "" {
        return "", errors.New("password cannot be empty")
    }

    return password, nil
}
```

**Примечание:** В Linux нет системного keyring по умолчанию, поэтому не используем его.

## 10. Сохранение username на клиенте

### 10.1. Цель
Упростить повторный логин - не требовать ввода username каждый раз.

### 10.2. Реализация
```
При успешной регистрации/логине:
- Сохраняем username в BoltDB bucket "auth" (plaintext)
- Сохраняем public_salt в BoltDB bucket "auth" (plaintext)

При следующем логине:
- Предлагаем использовать сохраненный username
- Позволяем ввести другой username (смена пользователя)
```

### 10.3. CLI flow
```bash
# Первый раз
$ gophkeeper login
Enter username: alice
Enter master password: ********
✓ Logged in successfully

# Второй раз
$ gophkeeper login
Saved username: alice
Press Enter to use it, or type new username:
Enter master password: ********
✓ Logged in successfully

# Смена пользователя
$ gophkeeper login
Saved username: alice
Press Enter to use it, or type new username: bob
Enter master password: ********
✓ Logged in as bob
```

## 11. Мультиклиентская поддержка

### 11.1. Проблема
Пользователь может использовать несколько устройств (desktop, laptop, phone). Все клиенты должны иметь доступ к одним и тем же данным.

### 11.2. Решение
**Единый public_salt для всех клиентов пользователя.**

### 11.3. Схема работы

**Клиент 1 (регистрация):**
```
1. Пользователь: alice + master_password_123
2. Генерируется: SALT_A (случайный, 32 bytes)
3. Вычисляется: encryption_key_1 = Argon2(master_password_123 + alice + SALT_A + "encrypt")
4. На сервер: alice, auth_key_hash, SALT_A
5. Сервер сохраняет: alice → SALT_A
```

**Клиент 2 (логин на новом устройстве):**
```
1. Пользователь: alice + master_password_123
2. Запрос к серверу: GET /api/v1/auth/salt/alice
3. Сервер возвращает: SALT_A (тот же самый!)
4. Вычисляется: encryption_key_2 = Argon2(master_password_123 + alice + SALT_A + "encrypt")
5. Результат: encryption_key_1 == encryption_key_2 ✅
6. Клиент 2 может расшифровать все данные клиента 1!
```

### 11.4. Безопасность
```
Сервер знает:
✅ username (alice)
✅ public_salt (SALT_A) - публичная информация, не секрет
✅ auth_key_hash - bcrypt хеш, не может быть использован для расшифровки
✅ encrypted_data - зашифрованные данные

Сервер НЕ знает:
❌ master_password
❌ encryption_key - генерируется только на клиенте
❌ plaintext данные

Вывод: Сервер НЕ МОЖЕТ расшифровать данные даже при компрометации БД!
```

## 12. Архитектура приложения

### 12.1. Слоистая архитектура (Layered Architecture)

Проект использует **трехслойную архитектуру** для разделения ответственности:

```
┌─────────────────────────────────────┐
│   Access Layer (HTTP/CLI)           │  ← Handlers, Commands
├─────────────────────────────────────┤
│   Service Layer (Business Logic)    │  ← Services, CRDT, Crypto
├─────────────────────────────────────┤
│   Storage Layer (Data Access)       │  ← Repositories, DB
└─────────────────────────────────────┘
```

**Слой доступа (Access Layer):**
- **Сервер:** HTTP handlers (`internal/server/handlers/`)
  - Парсинг HTTP запросов
  - Валидация входных данных
  - Вызов service layer
  - Формирование HTTP ответов
  - Не содержит бизнес-логики
- **Клиент:** CLI commands (`internal/client/cli/`)
  - Парсинг аргументов командной строки
  - Интерактивный ввод
  - Вызов service layer
  - Вывод результатов пользователю

**Слой сервисов (Service Layer):**
- **Сервер:** `internal/server/service/`
  - Бизнес-логика регистрации/аутентификации
  - JWT генерация и валидация
  - Логика синхронизации данных
  - CRDT merge операции
  - Координация между storage layer
- **Клиент:** `internal/client/service/`
  - Бизнес-логика работы с данными
  - Шифрование/дешифрование
  - Логика синхронизации
  - CRDT операции на клиенте

**Слой хранения (Storage Layer):**
- **Сервер:** `internal/server/storage/`
  - CRUD операции с БД (SQLite)
  - Работа с транзакциями
  - Не содержит бизнес-логики
- **Клиент:** `internal/client/storage/`
  - CRUD операции с BoltDB
  - Работа с buckets
  - Не содержит бизнес-логики

**Пример структуры (Сервер):**
```
internal/server/
├── handlers/          # Access Layer
│   ├── auth.go        # HTTP handlers для auth endpoints
│   ├── sync.go        # HTTP handlers для sync endpoints
│   └── health.go      # Health check handler
├── service/           # Service Layer
│   ├── auth.go        # Логика регистрации/логина
│   ├── sync.go        # Логика синхронизации
│   └── token.go       # JWT генерация/валидация
├── storage/           # Storage Layer
│   ├── users.go       # Репозиторий пользователей
│   ├── tokens.go      # Репозиторий токенов
│   └── data.go        # Репозиторий данных
└── middleware/        # HTTP middleware
    ├── auth.go
    ├── ratelimit.go
    └── logging.go
```

**Пример структуры (Клиент):**
```
internal/client/
├── cli/               # Access Layer
│   ├── auth.go        # Команды register, login, logout
│   ├── data.go        # Команды add, list, get, update, delete
│   └── sync.go        # Команда sync
├── service/           # Service Layer
│   ├── auth.go        # Логика аутентификации
│   ├── data.go        # Логика работы с данными
│   └── sync.go        # Логика синхронизации
└── storage/           # Storage Layer
    ├── auth.go        # Работа с auth bucket
    ├── data.go        # Работа с data bucket
    └── crdt.go        # Работа с crdt bucket
```

**Правила взаимодействия:**
1. Access Layer → Service Layer (✅ разрешено)
2. Service Layer → Storage Layer (✅ разрешено)
3. Access Layer → Storage Layer (❌ запрещено, должен идти через Service)
4. Storage Layer → Service Layer (❌ запрещено, хранилище не вызывает сервисы)
5. Зависимости через интерфейсы для тестируемости

**Пример:**
```go
// Storage Layer (интерфейс)
type UserRepository interface {
    Create(user *User) error
    GetByUsername(username string) (*User, error)
}

// Service Layer (использует storage через интерфейс)
type AuthService struct {
    userRepo UserRepository
}

func (s *AuthService) Register(username, authKeyHash, publicSalt string) (string, error) {
    // Бизнес-логика регистрации
    user := &User{
        ID: uuid.New().String(),
        Username: username,
        AuthKeyHash: authKeyHash,
        PublicSalt: publicSalt,
        CreatedAt: time.Now(),
    }
    return user.ID, s.userRepo.Create(user)
}

// Access Layer (использует service через интерфейс)
type AuthHandler struct {
    authService *AuthService
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
    // Парсинг запроса
    var req RegisterRequest
    json.NewDecoder(r.Body).Decode(&req)

    // Валидация
    if err := validateUsername(req.Username); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Вызов service layer
    userID, err := h.authService.Register(req.Username, req.AuthKeyHash, req.PublicSalt)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Формирование ответа
    json.NewEncoder(w).Encode(RegisterResponse{UserID: userID})
}
```

### 12.2. HTTP роутер (Сервер)

**Использование:** `net/http.ServeMux` из Go 1.22+

**Новые возможности Go 1.22:**
- Поддержка методов в паттернах: `"POST /api/v1/auth/login"`
- Path parameters: `"GET /api/v1/users/{id}"`
- Более точное сопоставление паттернов

**Пример использования:**
```go
// cmd/server/main.go
func main() {
    mux := http.NewServeMux()

    // Auth endpoints
    mux.HandleFunc("POST /api/v1/auth/register", authHandler.Register)
    mux.HandleFunc("GET /api/v1/auth/salt/{username}", authHandler.GetSalt)
    mux.HandleFunc("POST /api/v1/auth/login", authHandler.Login)
    mux.HandleFunc("POST /api/v1/auth/refresh", authHandler.Refresh)
    mux.HandleFunc("POST /api/v1/auth/logout", authHandler.Logout)

    // Sync endpoints (защищены auth middleware)
    mux.HandleFunc("GET /api/v1/sync", authMiddleware(syncHandler.GetSync))
    mux.HandleFunc("POST /api/v1/sync", authMiddleware(syncHandler.PostSync))

    // Health check
    mux.HandleFunc("GET /api/v1/health", healthHandler.Health)

    // Middleware stack
    handler := loggingMiddleware(
        recoveryMiddleware(
            rateLimitMiddleware(mux),
        ),
    )

    // TLS сервер
    server := &http.Server{
        Addr:      ":8080",
        Handler:   handler,
        TLSConfig: tlsConfig,
    }

    log.Println("Starting server on :8080")
    if err := server.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
        log.Fatal(err)
    }
}
```

**Middleware pattern:**
```go
// Middleware signature
type Middleware func(http.Handler) http.Handler

// Chain multiple middlewares
func Chain(h http.Handler, middlewares ...Middleware) http.Handler {
    for i := len(middlewares) - 1; i >= 0; i-- {
        h = middlewares[i](h)
    }
    return h
}
```

### 12.3. Логирование

**Использование:** `log/slog` (стандартная библиотека Go 1.21+)

**Уровни логирования:**
- `DEBUG` - детальная информация для отладки
- `INFO` - общая информация о работе приложения
- `WARN` - предупреждения
- `ERROR` - ошибки

**Структурированное логирование:**
```go
// Инициализация (cmd/server/main.go)
func initLogger() *slog.Logger {
    opts := &slog.HandlerOptions{
        Level: slog.LevelInfo,
    }
    handler := slog.NewJSONHandler(os.Stdout, opts)
    logger := slog.New(handler)
    slog.SetDefault(logger)
    return logger
}

// Использование в коде
logger.Info("user registered",
    slog.String("username", username),
    slog.String("user_id", userID),
)

logger.Error("failed to save user",
    slog.String("username", username),
    slog.Any("error", err),
)

// С контекстом
logger.InfoContext(ctx, "processing request",
    slog.String("method", r.Method),
    slog.String("path", r.URL.Path),
    slog.Int("status", status),
    slog.Duration("duration", duration),
)
```

**Middleware для логирования запросов:**
```go
func LoggingMiddleware(logger *slog.Logger) Middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            start := time.Now()

            // Wrap response writer to capture status code
            wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

            next.ServeHTTP(wrapped, r)

            logger.Info("http request",
                slog.String("method", r.Method),
                slog.String("path", r.URL.Path),
                slog.Int("status", wrapped.statusCode),
                slog.Duration("duration", time.Since(start)),
                slog.String("remote_addr", r.RemoteAddr),
            )
        })
    }
}
```

**Важно:**
- НЕ логировать sensitive данные (пароли, токены, ключи)
- Использовать структурированное логирование для удобного анализа
- Логировать request_id для трассировки запросов

## 13. Безопасность

### 13.1. TLS/HTTPS
- Все коммуникации клиент-сервер только через TLS 1.3
- Минимальная версия TLS: 1.3
- Рекомендуемые cipher suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256

### 13.2. Rate Limiting
```
- Логин: максимум 5 попыток за 15 минут с одного IP
- Регистрация: максимум 3 попытки за час с одного IP
- Получение salt: максимум 10 запросов в минуту с одного IP
```

### 13.3. Логирование с slog
См. раздел 12.3 для детальной информации о структурированном логировании.

```
Логировать:
✅ Попытки логина (успешные/неуспешные)
✅ Регистрации
✅ API запросы (метод, путь, статус код, duration)
✅ Ошибки с контекстом

НЕ логировать:
❌ Master password
❌ Auth key / auth key hash
❌ Encryption key
❌ Токены (access, refresh)
❌ Расшифрованные данные
❌ Любую sensitive информацию
```

### 13.4. Восстановление пароля
**НЕ ПРЕДУСМОТРЕНО.**

Если пользователь забыл master password, данные потеряны безвозвратно. Это цена zero-knowledge архитектуры.

Возможное решение для будущего:
- Emergency Kit при регистрации (экспорт encryption_key в файл)
- Предупреждение пользователя при регистрации

## 14. Требования к тестированию

### 14.1. Инструменты тестирования

**Testing framework:**
- **testify** - assertion библиотека и test suites
  - `github.com/stretchr/testify/assert` - assertions
  - `github.com/stretchr/testify/require` - assertions с остановкой теста
  - `github.com/stretchr/testify/suite` - test suites (опционально)

**Mocking:**
- **gomock** - генерация моков из интерфейсов
  - `go install go.uber.org/mock/mockgen@latest`
  - Генерация: `mockgen -source=interface.go -destination=mocks/mock.go`

**Стиль тестов:**
- **Табличные тесты (table-driven tests)** - предпочтительный подход
- Один тест за раз - запускаем и проверяем перед следующим
- Тесты пишутся после завершения модуля

### 14.2. Табличные тесты

**Структура табличного теста:**
```go
func TestValidateUsername(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        wantErr bool
        errMsg  string
    }{
        {
            name:    "valid username - lowercase",
            input:   "alice",
            wantErr: false,
        },
        {
            name:    "valid username - with underscore",
            input:   "alice_smith",
            wantErr: false,
        },
        {
            name:    "valid username - with numbers",
            input:   "alice123",
            wantErr: false,
        },
        {
            name:    "invalid - too short",
            input:   "ab",
            wantErr: true,
            errMsg:  "username must be 3-32 characters",
        },
        {
            name:    "invalid - with dot",
            input:   "alice.smith",
            wantErr: true,
            errMsg:  "username can only contain letters, numbers, and underscores",
        },
        {
            name:    "invalid - with special chars",
            input:   "alice@email",
            wantErr: true,
            errMsg:  "username can only contain letters, numbers, and underscores",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateUsername(tt.input)

            if tt.wantErr {
                require.Error(t, err)
                assert.Contains(t, err.Error(), tt.errMsg)
            } else {
                require.NoError(t, err)
            }
        })
    }
}
```

**Пример с testify assertions:**
```go
func TestDeriveKeys(t *testing.T) {
    masterPassword := "super_secret_password"
    username := "alice"
    salt := make([]byte, 32)
    rand.Read(salt)

    keys, err := DeriveKeys(masterPassword, username, salt)

    // Базовые проверки
    require.NoError(t, err)
    require.NotNil(t, keys)

    // Проверка длины ключей
    assert.Len(t, keys.AuthKey, 32, "auth key should be 32 bytes")
    assert.Len(t, keys.EncryptionKey, 32, "encryption key should be 32 bytes")

    // Ключи должны быть разными
    assert.NotEqual(t, keys.AuthKey, keys.EncryptionKey, "keys must be different")

    // Детерминизм - одинаковые входы должны давать одинаковые ключи
    keys2, _ := DeriveKeys(masterPassword, username, salt)
    assert.Equal(t, keys.AuthKey, keys2.AuthKey)
    assert.Equal(t, keys.EncryptionKey, keys2.EncryptionKey)
}
```

### 14.3. Использование gomock

**Пример интерфейса:**
```go
// internal/server/storage/users.go
type UserRepository interface {
    Create(user *User) error
    GetByUsername(username string) (*User, error)
    GetByID(id string) (*User, error)
}
```

**Генерация мока:**
```bash
mockgen -source=internal/server/storage/users.go \
        -destination=internal/server/storage/mocks/mock_users.go \
        -package=mocks
```

**Использование в тесте:**
```go
func TestAuthService_Register(t *testing.T) {
    ctrl := gomock.NewController(t)
    defer ctrl.Finish()

    mockRepo := mocks.NewMockUserRepository(ctrl)
    service := &AuthService{
        userRepo: mockRepo,
    }

    tests := []struct {
        name          string
        username      string
        authKeyHash   string
        publicSalt    string
        mockSetup     func()
        wantErr       bool
    }{
        {
            name:        "successful registration",
            username:    "alice",
            authKeyHash: "hash123",
            publicSalt:  "salt123",
            mockSetup: func() {
                mockRepo.EXPECT().
                    Create(gomock.Any()).
                    Return(nil).
                    Times(1)
            },
            wantErr: false,
        },
        {
            name:        "duplicate username",
            username:    "alice",
            authKeyHash: "hash123",
            publicSalt:  "salt123",
            mockSetup: func() {
                mockRepo.EXPECT().
                    Create(gomock.Any()).
                    Return(errors.New("UNIQUE constraint failed")).
                    Times(1)
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            tt.mockSetup()

            userID, err := service.Register(tt.username, tt.authKeyHash, tt.publicSalt)

            if tt.wantErr {
                require.Error(t, err)
            } else {
                require.NoError(t, err)
                assert.NotEmpty(t, userID)
            }
        })
    }
}
```

### 14.4. Workflow тестирования

**Порядок разработки:**
1. Реализовать модуль (функцию, структуру, интерфейс)
2. Написать **первый тест** (happy path)
3. Запустить тест: `go test -v -run TestFunctionName`
4. Если тест проходит → написать **второй тест** (edge case)
5. Запустить тест
6. Повторять пункты 4-5 для всех случаев
7. Проверить coverage: `go test -cover`
8. Цель: минимум 80% coverage

**Пример workflow:**
```bash
# 1. Реализовали функцию ValidateUsername()

# 2. Написали первый тест (happy path)
# TestValidateUsername с одним case "valid username"

# 3. Запускаем
go test -v -run TestValidateUsername
# PASS

# 4. Добавляем второй тест case "too short"

# 5. Запускаем
go test -v -run TestValidateUsername
# PASS

# 6. Добавляем остальные cases...

# 7. Проверяем coverage
go test -cover ./internal/validation/
# coverage: 85.7% of statements
```

### 14.5. Coverage требования

- **Минимум 80% coverage** для всех пакетов
- Обязательные тесты для:
  - Все exported функции
  - Все криптографические функции
  - Все storage операции
  - Все service методы
  - Критическая бизнес-логика

**Проверка coverage:**
```bash
# Coverage для всего проекта
go test -coverprofile=coverage.out ./...

# Просмотр coverage в браузере
go tool cover -html=coverage.out

# Coverage по пакетам
go test -cover ./...
```

### 14.6. Интеграционные тесты
- Полный flow регистрации
- Полный flow логина
- Синхронизация между двумя клиентами
- Разрешение конфликтов CRDT
- Используют in-memory SQLite для изоляции

### 14.7. E2E тесты (опционально)
- Регистрация → добавление данных → логин на втором клиенте → синхронизация
- Offline работа → online синхронизация
- Конфликтные изменения на двух клиентах

## 15. Документация

### 15.1. Код
- Godoc комментарии для всех exported функций, типов, переменных
- Godoc комментарии на уровне пакетов (package documentation)

### 15.2. Пользовательская
- README.md с инструкциями по установке и использованию
- Примеры использования CLI команд
- Описание архитектуры безопасности

## 16. Опциональные функции

### 16.1. OTP (One Time Password)
- Поддержка TOTP (Time-based OTP)
- Генерация 6-значных кодов
- Совместимость с Google Authenticator / Authy

### 16.2. TUI (Terminal User Interface)
- Интерактивный интерфейс в терминале
- Библиотека: bubbletea или tview
- Navigation, hot keys, live search

### 16.3. Binary Protocol
- gRPC вместо REST
- Protobuf для сериализации
- Лучшая производительность

### 16.4. Swagger документация
- OpenAPI спецификация
- Swagger UI для API
- Автогенерация из кода

## 17. Deployment

### 17.1. Сборка клиента
```bash
# Cross-compilation для разных платформ
make build-all

# Windows
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.buildVersion=v1.0.0 -X 'main.buildDate=$(date)'" -o gophkeeper-client.exe ./cmd/client

# Linux
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.buildVersion=v1.0.0 -X 'main.buildDate=$(date)'" -o gophkeeper-client ./cmd/client

# macOS
GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.buildVersion=v1.0.0 -X 'main.buildDate=$(date)'" -o gophkeeper-client-mac ./cmd/client
```

### 17.2. Сборка сервера
```bash
# Docker образ
docker build -t gophkeeper-server .
docker run -p 8080:8080 -v ./data:/data gophkeeper-server

# Бинарник
go build -o gophkeeper-server ./cmd/server
./gophkeeper-server --port 8080 --db /data/gophkeeper.db
```

### 17.3. Конфигурация сервера
```yaml
# config.yaml
server:
  port: 8080
  host: 0.0.0.0
  tls_cert: /path/to/cert.pem
  tls_key: /path/to/key.pem

database:
  path: ./data/gophkeeper.db

jwt:
  secret: "random_secret_key_here"
  access_token_ttl: 900      # 15 минут
  refresh_token_ttl: 2592000 # 30 дней

rate_limiting:
  login_attempts: 5
  login_window: 900          # 15 минут
  register_attempts: 3
  register_window: 3600      # 1 час
```

## 17. Структура проекта

```
gophkeeper/
├── cmd/
│   ├── server/
│   │   └── main.go
│   └── client/
│       └── main.go
├── internal/
│   ├── server/
│   │   ├── handlers/      # HTTP handlers
│   │   ├── middleware/    # Auth, logging, rate limiting
│   │   ├── storage/       # SQLite storage
│   │   └── auth/          # JWT, bcrypt
│   ├── client/
│   │   ├── cli/           # Cobra commands
│   │   ├── storage/       # BoltDB storage
│   │   ├── sync/          # Синхронизация
│   │   └── auth/          # Аутентификация
│   ├── crypto/            # AES-GCM, Argon2
│   ├── crdt/              # CRDT implementation
│   ├── models/            # Данные (credential, text, binary, card)
│   └── validation/        # Валидация username, password
├── pkg/
│   └── api/               # Общие API типы (клиент-сервер)
├── migrations/            # SQL миграции для сервера
├── api/                   # API specs (опционально: proto, OpenAPI)
├── docs/                  # Документация
├── CLAUDE.md
├── PROJECT_PLAN.md
├── TECHNICAL_SPEC.md      # этот файл
├── README.md
├── Makefile
├── go.mod
└── go.sum
```
