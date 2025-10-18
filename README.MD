[![Go Coverage](https://github.com/iudanet/gophkeeper/wiki/coverage.svg)](https://raw.githack.com/wiki/iudanet/gophkeeper/coverage.html) [![godoc](https://godoc.org/github.com/iudanet/gophkeeper?status.svg)](https://godoc.org/github.com/iudanet/gophkeeper)

# GophKeeper

**GophKeeper** — защищенная клиент-серверная система для хранения и синхронизации приватных данных (учетные данные, пароли, текстовые заметки, банковские карты, файлы).

## Возможности

### Типы данных
- **Credentials** — пары логин/пароль с URL и заметками
- **Text** — произвольные текстовые данные (секретные ключи, recovery-фразы, заметки)
- **Binary** — файлы любого формата (документы, фотографии, сертификаты)
- **Card** — данные банковских карт (номер, CVV, PIN, срок действия)

### Безопасность
- **Шифрование**: AES-256-GCM для всех данных
- **Key Derivation**: Argon2id с параметрами (time=1, memory=64MB, threads=4)
- **Хеширование**: SHA256 для authentication keys
- **Два независимых ключа**: AuthKey (для аутентификации) и EncryptionKey (для шифрования данных)
- **Zero-knowledge архитектура**: сервер никогда не имеет доступа к расшифрованным данным
- **JWT токены**: Access token (15 минут) + Refresh token (30 дней)

### Синхронизация
- **CRDT** (Conflict-free Replicated Data Type) с алгоритмом Last-Write-Wins
- **Lamport Clock** для упорядочивания событий в распределенной системе
- **Автоматическое разрешение конфликтов** при одновременном редактировании с разных устройств
- **Soft delete** для безопасного удаления данных

### Архитектура
- **Клиент**: CLI приложение с BoltDB для локального хранилища
- **Сервер**: HTTP REST API с SQLite для серверного хранилища
- **Middleware**: Rate limiting, logging, recovery, authentication
- **Кроссплатформенность**: Windows, Linux, macOS

---

## Установка

### Требования
- Go 1.25+
- SQLite3 (для сервера)

### Сборка

#### Сервер
```bash
go build -o gophkeeper-server ./cmd/server
```

С информацией о версии:
```bash
go build -ldflags "-X main.Version=v1.0.0 -X 'main.BuildDate=$(date)' -X main.GitCommit=$(git rev-parse HEAD)" \
    -o gophkeeper-server ./cmd/server
```

#### Клиент
```bash
go build -o gophkeeper-client ./cmd/client
```

С информацией о версии:
```bash
go build -ldflags "-X main.Version=v1.0.0 -X 'main.BuildDate=$(date)' -X main.GitCommit=$(git rev-parse HEAD)" \
    -o gophkeeper-client ./cmd/client
```

---

## Использование

### Запуск сервера

#### Production (с TLS)

```bash
./gophkeeper-server \
  --port 8443 \
  --db gophkeeper.db \
  --jwt-secret YOUR_SECRET_KEY \
  --tls-cert ./certs/server-cert.pem \
  --tls-key ./certs/server-key.pem
```

#### Development (без TLS)

```bash
./gophkeeper-server --port 8080 --db gophkeeper.db --insecure
```

Параметры:
- `--port` — порт сервера (по умолчанию 8080)
- `--db` — путь к файлу базы данных SQLite (по умолчанию gophkeeper.db)
- `--jwt-secret` — секретный ключ для JWT (если не указан, генерируется автоматически)
- `--log-level` — уровень логирования: debug, info, warn, error (по умолчанию info)
- `--tls-cert` — путь к TLS сертификату сервера (обязательно без `--insecure`)
- `--tls-key` — путь к приватному ключу TLS сервера (обязательно без `--insecure`)
- `--insecure` — запуск без TLS (только для разработки!)
- `--version` — показать версию и информацию о сборке

**⚠️ Важно:** В production всегда используйте TLS! Флаг `--insecure` предназначен только для локальной разработки.

### Клиент

#### Глобальные параметры

```bash
gophkeeper [OPTIONS] COMMAND
```

Опции:
- `--server URL` — адрес сервера (по умолчанию http://localhost:8080)
- `--db PATH` — путь к локальной базе данных (по умолчанию gophkeeper-client.db)
- `--master-password PASSWORD` — мастер-пароль (не рекомендуется, используйте переменную окружения или файл)
- `--master-password-file PATH` — путь к файлу с мастер-паролем
- `--tls-ca PATH` — путь к CA сертификату для проверки самоподписанного сертификата сервера
- `--insecure` — отключить проверку TLS сертификата (только для разработки!)
- `--version` — показать версию и информацию о сборке

#### Примеры подключения к серверу

**Production с публичным сертификатом:**
```bash
gophkeeper --server https://gophkeeper.example.com:8443 login
```

**Development с самоподписанным сертификатом:**
```bash
# Генерируем сертификаты
make certs

# Подключаемся с CA сертификатом
gophkeeper --server https://localhost:8443 --tls-ca ./certs/ca-cert.pem login
```

**Development без TLS (insecure mode):**
```bash
# Сервер запущен с --insecure
gophkeeper --server http://localhost:8080 login

# Или игнорируем ошибки TLS (не рекомендуется!)
gophkeeper --server https://localhost:8443 --insecure login
```

#### Приоритет источников мастер-пароля

1. Переменная окружения `GOPHKEEPER_MASTER_PASSWORD` (рекомендуется)
2. Файл указанный в `--master-password-file`
3. Параметр командной строки `--master-password`
4. Интерактивный ввод (по умолчанию)

---

## Команды клиента

### 1. Регистрация нового пользователя

```bash
gophkeeper register
```

Пример:
```bash
$ gophkeeper register
=== Registration ===

Username: alice
Master password (min 12 chars): ****************
Confirm master password: ****************

Registering user...

✓ Registration successful!
User ID: 123e4567-e89b-12d3-a456-426614174000
Username: alice
Device ID: 987fcdeb-51a2-43f8-b123-9876543210ab

⚠️  IMPORTANT: Remember your master password!
   If you lose it, you will NOT be able to recover your data.

Please run 'gophkeeper login' to start using the service.
```

**Что происходит при регистрации:**
1. Генерируется уникальная публичная соль (32 байта)
2. Из мастер-пароля + username + соль деривируются два ключа через Argon2id:
   - **AuthKey** — для аутентификации на сервере
   - **EncryptionKey** — для шифрования данных
3. AuthKey хешируется через SHA256 и отправляется на сервер
4. Сервер сохраняет username, хеш AuthKey, публичную соль
5. **Сервер никогда не получает и не хранит мастер-пароль или EncryptionKey**

### 2. Вход в систему

```bash
gophkeeper login
```

Пример:
```bash
$ gophkeeper login
=== Login ===

Username: alice
Master password: ****************

Authenticating...

✓ Login successful!
Username: alice
Access token expires in: 900 seconds

Your session has been saved securely.
```

**Что происходит при входе:**
1. Клиент запрашивает публичную соль у сервера
2. Деривирует AuthKey и EncryptionKey из мастер-пароля + username + соль
3. Хеширует AuthKey и отправляет на сервер для аутентификации
4. Сервер проверяет хеш и возвращает JWT токены
5. Токены шифруются EncryptionKey и сохраняются локально в BoltDB

### 3. Добавление данных

#### Добавить credentials (логин/пароль)

```bash
gophkeeper add credential [--sync]
```

Флаг `--sync` автоматически синхронизирует данные с сервером после добавления.

Пример:
```bash
$ gophkeeper add credential --sync
=== Add Credential ===

Enter credential details:

Name (e.g., 'GitHub', 'Gmail'): GitHub
Login/Email: alice@example.com
Password: ****************
URL (optional): https://github.com
Notes (optional): Work account

✓ Credential added successfully!
Name: GitHub
Login: alice@example.com

Syncing with server...
=== Synchronization ===

Starting synchronization with server...

✓ Synchronization completed successfully!

Pushed to server:   1 entries
Pulled from server: 0 entries
Merged locally:     0 entries

Your data is now synchronized with the server.
```

#### Добавить текстовые данные

```bash
gophkeeper add text [--sync]
```

Пример:
```bash
$ gophkeeper add text
=== Add Text Data ===

Enter text data details:

Name (e.g., 'Secret Note'): API Key
Content: sk-1234567890abcdef

✓ Text data added successfully!
Name: API Key

Note: Data is stored locally. Run 'gophkeeper sync' to sync with server.
```

#### Добавить бинарные данные (файлы)

```bash
gophkeeper add binary [--sync]
```

Пример:
```bash
$ gophkeeper add binary
=== Add Binary Data ===

Enter binary file details:

Name (e.g., 'Passport Scan'): Passport Scan
File path: /home/alice/Documents/passport.pdf

✓ File added successfully!
Name:     Passport Scan
Filename: passport.pdf
Size:     245678 bytes

Note: File is stored locally. Run 'gophkeeper sync' to sync with server.
```

**MIME type определяется автоматически** по расширению файла и содержимому.

#### Добавить банковскую карту

```bash
gophkeeper add card [--sync]
```

Пример:
```bash
$ gophkeeper add card
=== Add Card Data ===

Enter card details:

Card Name (e.g., 'Visa Gold'): My Visa
Card Number: 4532123456789012
Card Holder: ALICE SMITH
Expiry (MM/YY): 12/25
CVV: ***
PIN (optional): ****

✓ Card added successfully!
Name: My Visa

Note: Card is stored locally. Run 'gophkeeper sync' to sync with server.
```

### 4. Просмотр данных

#### Список всех credentials

```bash
gophkeeper list credentials
```

Пример:
```bash
$ gophkeeper list credentials
=== Saved Credentials ===
Found 2 credential(s):

1. GitHub
   ID:    a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d
   Login: alice@example.com
   URL:   https://github.com
   Notes: Work account

2. Gmail
   ID:    f6e5d4c3-b2a1-4c5d-9e8f-7a6b5c4d3e2f
   Login: alice.work@gmail.com

Note: Passwords are hidden for security. Use 'gophkeeper get <id>' to view full details.
```

#### Список текстовых данных

```bash
gophkeeper list text
```

#### Список бинарных данных

```bash
gophkeeper list binary
```

#### Список карт

```bash
gophkeeper list cards
```

Пример:
```bash
$ gophkeeper list cards
=== Saved Card Data ===
Found 1 card(s):

1. My Visa
   ID:     c5d4e3f2-a1b0-4d5e-8f9a-6b7c8d9e0f1a
   Number: **** **** **** 9012
   Holder: ALICE SMITH
   Expiry: 12/25

Note: Card details are masked. Use 'gophkeeper get <id>' to view full details.
```

### 5. Получение полных данных записи

```bash
gophkeeper get <ID>
```

Пример:
```bash
$ gophkeeper get a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d
=== Credential Details ===

ID:       a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d
Name:     GitHub
Login:    alice@example.com
Password: MySecretPassword123!
URL:      https://github.com
Notes:    Work account
```

Для бинарных файлов команда позволяет сохранить файл:
```bash
$ gophkeeper get f1e2d3c4-b5a6-4c7d-9e8f-0a1b2c3d4e5f
=== Binary Data Details ===

ID:       f1e2d3c4-b5a6-4c7d-9e8f-0a1b2c3d4e5f
Name:     Passport Scan
Filename: passport.pdf
Size:     245678 bytes
Type:     application/pdf

Save file? (y/n): y
Output path: ./passport.pdf

✓ File saved successfully!
```

### 6. Удаление данных

```bash
gophkeeper delete <ID>
```

Пример:
```bash
$ gophkeeper delete a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d
Are you sure you want to delete this entry? (y/n): y

✓ Entry deleted successfully!

Note: Entry is marked as deleted locally. Run 'gophkeeper sync' to sync deletion with server.
```

**Примечание:** Используется soft delete — запись помечается как удаленная, но физически остается в базе для корректной синхронизации.

### 7. Синхронизация с сервером

```bash
gophkeeper sync
```

Пример:
```bash
$ gophkeeper sync
=== Synchronization ===

Starting synchronization with server...

✓ Synchronization completed successfully!

Pushed to server:   3 entries
Pulled from server: 1 entries
Merged locally:     1 entries
Conflicts resolved: 0

Your data is now synchronized with the server.
```

**Как работает синхронизация:**
1. Клиент собирает все локальные изменения (новые/измененные/удаленные записи)
2. Отправляет их на сервер вместе с timestamp последней синхронизации
3. Сервер применяет изменения и возвращает изменения от других устройств
4. Клиент применяет изменения с сервера используя CRDT merge (Last-Write-Wins)
5. Конфликты разрешаются автоматически по timestamp и node ID

**Автоматическое обновление токена:** Если access token истек или скоро истечет (осталось меньше 60 секунд), клиент автоматически обновит его через refresh token перед синхронизацией.

### 8. Проверка статуса авторизации

```bash
gophkeeper status
```

Пример:
```bash
$ gophkeeper status
=== Authentication Status ===

Status:       Authenticated ✓
Username:     alice
User ID:      123e4567-e89b-12d3-a456-426614174000
Device ID:    987fcdeb-51a2-43f8-b123-9876543210ab
Token valid:  Yes
Expires at:   2025-10-17 15:30:45

Local storage: 15 entries (12 credentials, 2 text, 1 binary, 0 cards)
Pending sync:  3 entries
```

### 9. Выход из системы

```bash
gophkeeper logout
```

Пример:
```bash
$ gophkeeper logout
Are you sure you want to logout? (y/n): y

✓ Logged out successfully!

Your local data remains encrypted. Login again to access it.
```

**Примечание:** Локальные данные остаются в зашифрованном виде в BoltDB. При повторном входе с тем же мастер-паролем вы получите к ним доступ.

---

## Примеры работы с разных устройств

### Сценарий 1: Синхронизация между устройствами

**Устройство 1 (рабочий компьютер):**
```bash
# Регистрация
gophkeeper register
# Username: alice, Password: MySecurePass123!

# Добавление credentials
gophkeeper add credential --sync
# Добавляем GitHub account
```

**Устройство 2 (домашний компьютер):**
```bash
# Вход с тем же username и password
gophkeeper login
# Username: alice, Password: MySecurePass123!

# Синхронизация данных
gophkeeper sync
# Получаем GitHub account с устройства 1

# Добавляем новый credential
gophkeeper add credential --sync
# Добавляем Gmail account
```

**Обратно на Устройство 1:**
```bash
# Синхронизация
gophkeeper sync
# Получаем Gmail account с устройства 2
```

### Сценарий 2: Разрешение конфликтов

**Устройство 1 (офлайн):**
```bash
gophkeeper add text
# Name: Shopping List
# Content: Milk, Bread
```

**Устройство 2 (офлайн):**
```bash
gophkeeper add text
# Name: Todo
# Content: Call dentist
```

**Устройство 1 (онлайн):**
```bash
gophkeeper sync
# Pushed to server: 1 entries
# Pulled from server: 0 entries
```

**Устройство 2 (онлайн):**
```bash
gophkeeper sync
# Pushed to server: 1 entries
# Pulled from server: 1 entries
# Merged locally: 1 entries
# Conflicts: 0
```

Оба изменения сохраняются без конфликтов благодаря CRDT.

---

## Безопасность и криптография

### Архитектура Zero-Knowledge

GophKeeper использует архитектуру zero-knowledge, что означает:
- Сервер **никогда** не получает мастер-пароль
- Сервер **никогда** не получает ключ шифрования (EncryptionKey)
- Сервер **не может расшифровать** данные пользователя
- Даже при компрометации сервера данные остаются защищенными

### Процесс деривации ключей

```
Master Password + Username + Public Salt
            ↓
       Argon2id (time=1, memory=64MB, threads=4)
            ↓
    ┌───────┴────────┐
    ↓                ↓
AuthKey      EncryptionKey
(32 bytes)     (32 bytes)
    ↓
 SHA256
    ↓
AuthKeyHash
(сохраняется на сервере для аутентификации)
```

**Параметры Argon2id:**
- **Time cost**: 1 итерация
- **Memory**: 64 MB (65536 KB)
- **Threads**: 4 параллельных потока
- **Output**: 32 bytes (256 bits)
- **Mode**: Argon2id (защита от GPU и side-channel атак)

### Шифрование данных

Все данные шифруются на клиенте перед отправкой на сервер:

```
Plaintext Data (JSON)
        ↓
AES-256-GCM Encryption (EncryptionKey)
        ↓
Nonce (12 bytes) + Ciphertext + Auth Tag (16 bytes)
        ↓
Base64 Encoding
        ↓
Хранение/Передача
```

**Параметры AES-256-GCM:**
- **Алгоритм**: AES-256-GCM (Galois/Counter Mode)
- **Ключ**: 32 bytes (256 bits) — EncryptionKey
- **Nonce**: 12 bytes (случайный, уникальный для каждого шифрования)
- **Auth Tag**: 16 bytes (аутентификация целостности)

**Преимущества GCM mode:**
- Authenticated encryption (защита от изменений)
- Parallel encryption/decryption (быстрее чем CBC)
- Встроенная проверка целостности

### JWT токены

**Access Token** (время жизни: 15 минут):
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "username": "alice",
  "exp": 1697555445
}
```

**Refresh Token** (время жизни: 30 дней):
- Случайная строка (256 bits)
- Хранится на сервере в БД
- Используется для обновления access token

### Хранение токенов на клиенте

Токены хранятся **зашифрованными** в BoltDB:

```
Access/Refresh Token (plaintext)
           ↓
  AES-256-GCM (EncryptionKey)
           ↓
     Base64 Encoding
           ↓
   BoltDB (auth bucket)
```

### Защита от атак

1. **TLS/HTTPS**: обязательное использование TLS 1.2+ в production для защиты от перехвата трафика
2. **Rate Limiting**: 10 запросов/минуту на auth endpoints (защита от brute-force)
3. **Password Policy**: минимум 12 символов для мастер-пароля
4. **Username Policy**: 3-32 символа, alphanumeric + underscore
5. **Token Rotation**: автоматическая ротация refresh tokens
6. **Middleware Recovery**: перехват паник в HTTP handlers

### TLS конфигурация

**Сервер:**
- Минимальная версия TLS: 1.2
- Поддерживаемые cipher suites:
  - `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
  - `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
  - `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
  - `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`

**Клиент:**
- Автоматическая проверка сертификата через системные CA (для публичных сертификатов)
- Поддержка кастомного CA сертификата (для самоподписанных сертификатов)
- Минимальная версия TLS: 1.2

---

## Архитектура проекта

```
GophKeeper/
├── cmd/
│   ├── server/         # Сервер entry point
│   └── client/         # Клиент entry point
├── internal/
│   ├── client/         # Клиентская логика
│   │   ├── api/        # HTTP API клиент
│   │   ├── auth/       # Авторизация и управление сессией
│   │   ├── cli/        # CLI команды и интерфейс
│   │   ├── data/       # Управление данными (CRUD)
│   │   ├── storage/    # Интерфейсы и BoltDB
│   │   └── sync/       # Синхронизация с сервером
│   ├── server/         # Серверная логика
│   │   ├── handlers/   # HTTP handlers (auth, sync, health)
│   │   ├── middleware/ # Middleware (auth, logging, rate limit, recovery)
│   │   └── storage/    # Интерфейсы и SQLite
│   ├── crdt/           # CRDT алгоритмы (LWW, Lamport Clock)
│   ├── crypto/         # Криптография (AES, Argon2, SHA256)
│   ├── models/         # Общие модели данных
│   └── validation/     # Валидация входных данных
├── pkg/
│   └── api/            # Публичные API модели (request/response)
├── CLAUDE.md           # Инструкции для разработки
├── go.mod
└── README.MD
```

### Слои архитектуры

1. **CLI Layer** (`internal/client/cli/`) — интерфейс командной строки
2. **Service Layer** (`internal/client/auth/`, `data/`, `sync/`) — бизнес-логика
3. **Storage Layer** (`internal/client/storage/`, `internal/server/storage/`) — работа с БД
4. **API Layer** (`internal/client/api/`, `internal/server/handlers/`) — HTTP коммуникация
5. **Crypto Layer** (`internal/crypto/`) — криптографические операции
6. **CRDT Layer** (`internal/crdt/`) — алгоритмы синхронизации

---

## API Endpoints

### Authentication

#### POST `/api/v1/auth/register`
Регистрация нового пользователя.

**Request:**
```json
{
  "username": "alice",
  "auth_key_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "public_salt": "MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6"
}
```

**Response (201):**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "message": "User registered successfully"
}
```

#### GET `/api/v1/auth/salt/{username}`
Получение public salt пользователя для key derivation.

**Response (200):**
```json
{
  "public_salt": "MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6"
}
```

#### POST `/api/v1/auth/login`
Аутентификация пользователя.

**Request:**
```json
{
  "username": "alice",
  "auth_key_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

**Response (200):**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "f8e7d6c5b4a39281706f5e4d3c2b1a09",
  "expires_in": 900
}
```

#### POST `/api/v1/auth/refresh`
Обновление access token через refresh token.

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Response (200):**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "expires_in": 900
}
```

#### POST `/api/v1/auth/logout`
Выход из системы (удаление refresh tokens).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** 204 No Content

### Data Synchronization

#### GET `/api/v1/sync`
Получить изменения с сервера.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Query Parameters:**
- `since` — timestamp последней синхронизации

**Response (200):**
```json
{
  "entries": [
    {
      "id": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
      "user_id": "123e4567-e89b-12d3-a456-426614174000",
      "data_type": "credential",
      "data": "<base64_encrypted_data>",
      "metadata": "<base64_encrypted_metadata>",
      "timestamp": 1697555445,
      "deleted": false,
      "created_at": "2025-10-17T12:30:45Z",
      "updated_at": "2025-10-17T12:30:45Z"
    }
  ],
  "current_timestamp": 1697555450,
  "conflicts": 0
}
```

#### POST `/api/v1/sync`
Отправить локальные изменения на сервер.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{
  "entries": [
    {
      "id": "f6e5d4c3-b2a1-4c5d-9e8f-7a6b5c4d3e2f",
      "user_id": "123e4567-e89b-12d3-a456-426614174000",
      "data_type": "text",
      "data": "<base64_encrypted_data>",
      "metadata": "<base64_encrypted_metadata>",
      "timestamp": 1697555448,
      "deleted": false,
      "created_at": "2025-10-17T12:30:48Z",
      "updated_at": "2025-10-17T12:30:48Z"
    }
  ],
  "since": 1697555000
}
```

**Response:** Same as GET `/api/v1/sync`

### Health Check

#### GET `/api/v1/health`
Проверка работоспособности сервера.

**Response (200):**
```json
{
  "status": "ok"
}
```

---

## Разработка и тестирование

### Генерация TLS сертификатов для разработки

Для локальной разработки можно сгенерировать самоподписанные сертификаты:

```bash
# Генерация CA и серверных сертификатов
make certs
```

Эта команда создаст:
- `./certs/ca-cert.pem` — CA сертификат (для клиента)
- `./certs/ca-key.pem` — приватный ключ CA
- `./certs/server-cert.pem` — сертификат сервера
- `./certs/server-key.pem` — приватный ключ сервера

Сертификаты действительны для `localhost` и `127.0.0.1`.

**Очистка сертификатов:**
```bash
make clean-certs
```

### Запуск тестов

```bash
# Все тесты
go test ./...

# С покрытием
go test -cover ./...

# Детальный отчет покрытия
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Конкретный тест
go test -run TestName ./path/to/package

# С race detection
go test -race ./...
```

### Линтинг

```bash
# Запуск golangci-lint
golangci-lint run

# С автофиксом
golangci-lint run --fix
```

### Генерация моков (для тестов)

```bash
# Установка moq
go install github.com/matryer/moq@latest

# Генерация моков
go generate ./...
```

---

## FAQ

### Что произойдет если я забуду мастер-пароль?

К сожалению, **восстановление невозможно**. Это следствие zero-knowledge архитектуры — сервер не имеет доступа к вашим данным и не может их расшифровать. Рекомендуется надежно хранить мастер-пароль (например, в менеджере паролей).

### Можно ли использовать одинаковый username на разных серверах?

Да. Username уникален только в рамках одного сервера. Вы можете зарегистрировать "alice" на `server1.com` и на `server2.com` независимо.

### Что такое Device ID (Node ID)?

Это уникальный идентификатор клиента/устройства, используемый в CRDT для разрешения конфликтов. Он генерируется автоматически при первом входе на устройстве и сохраняется локально.

### Можно ли использовать несколько устройств одновременно?

Да! Это основная функция системы. Данные автоматически синхронизируются между всеми вашими устройствами. Конфликты разрешаются автоматически через CRDT.

### Как часто нужно синхронизировать данные?

Синхронизация не автоматическая — вызывайте `gophkeeper sync` когда хотите обновить данные. Либо используйте флаг `--sync` при добавлении данных для автоматической синхронизации.

### Что происходит при удалении?

Используется **soft delete** — запись помечается как удаленная, но остается в базе данных. Это необходимо для корректной синхронизации между устройствами. Физическое удаление записей не реализовано.

### Можно ли экспортировать данные?

Все данные хранятся в BoltDB (`gophkeeper-client.db`). Вы можете написать скрипт для экспорта данных, используя тот же encryption key (деривированный из мастер-пароля).

### Почему access token живет всего 15 минут?

Это стандартная практика безопасности. Короткий срок жизни access token ограничивает время атаки в случае его компрометации. Refresh token (30 дней) автоматически обновляет access token при необходимости.

### Что делать если access token истек?

Клиент автоматически обновляет access token через refresh token перед синхронизацией. Если refresh token тоже истек — потребуется повторный login.

---

## Производительность и ограничения

### Rate Limiting
- **Auth endpoints** (login, register, getSalt): 10 запросов/минуту на IP
- **Sync endpoints**: без ограничений (защищены JWT)

### Размеры данных
- **Binary files**: нет жесткого ограничения, но рекомендуется до 10 MB
- **Text content**: нет ограничения
- **Metadata**: рекомендуется до 1 KB

### База данных
- **BoltDB** (клиент): embedded key-value store, один файл
- **SQLite** (сервер): embedded SQL database, один файл

---

## Лицензия

MIT License

---

## Техническое задание (оригинальные требования)

Для синхронизации использовать CRDT и BoltDB.

### Краткое описание задачи

GophKeeper представляет собой клиент-серверную систему, позволяющую пользователю надёжно и безопасно хранить логины, пароли, бинарные данные и прочую приватную информацию.

**Сервер должен реализовывать следующую бизнес-логику:**
- Регистрация, аутентификация и авторизация пользователей
- Хранение приватных данных
- Синхронизация данных между несколькими авторизованными клиентами одного владельца
- Передача приватных данных владельцу по запросу

**Клиент должен реализовывать следующую бизнес-логику:**
- Аутентификация и авторизация пользователей на удалённом сервере
- Доступ к приватным данным по запросу

**Функции, реализация которых остаётся на усмотрение исполнителя:**
- Создание, редактирование и удаление данных на стороне сервера или клиента
- Формат регистрации нового пользователя
- Выбор хранилища и формат хранения данных
- Обеспечение безопасности передачи и хранения данных
- Протокол взаимодействия клиента и сервера
- Механизмы аутентификации пользователя и авторизации доступа к информации

**Дополнительные требования:**
- Клиент должен распространяться в виде CLI-приложения с возможностью запуска на платформах Windows, Linux и Mac OS
- Клиент должен давать пользователю возможность получить информацию о версии и дате сборки бинарного файла клиента

### Типы хранимой информации
- Пары логин/пароль
- Произвольные текстовые данные
- Произвольные бинарные данные
- Данные банковских карт

Для любых данных должна быть возможность хранения произвольной текстовой метаинформации (принадлежность данных к веб-сайту, личности или банку, списки одноразовых кодов активации и прочее).

### Абстрактная схема взаимодействия с системой

**Для нового пользователя:**
1. Пользователь получает клиент под необходимую ему платформу
2. Пользователь проходит процедуру первичной регистрации
3. Пользователь добавляет в клиент новые данные
4. Клиент синхронизирует данные с сервером

**Для существующего пользователя:**
1. Пользователь получает клиент под необходимую ему платформу
2. Пользователь проходит процедуру аутентификации
3. Клиент синхронизирует данные с сервером
4. Пользователь запрашивает данные
5. Клиент отображает данные для пользователя

### Тестирование и документация

Код всей системы должен быть покрыт юнит-тестами не менее чем на 80%. Каждая экспортированная функция, тип, переменная, а также пакет системы должны содержать исчерпывающую документацию.

### Необязательные функции

Перечисленные ниже функции необязательны к имплементации, однако позволяют лучше оценить степень экспертизы исполнителя:
- Поддержка данных типа OTP (one time password)
- Поддержка терминального интерфейса (TUI — terminal user interface)
- Использование бинарного протокола
- Наличие функциональных и/или интеграционных тестов
- Описание протокола взаимодействия клиента и сервера в формате Swagger
