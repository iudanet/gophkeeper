# GophKeeper - Краткое техзадание

## 1. Общие принципы
- Клиент-сервер для безопасного хранения и синхронизации приватных данных.
- Zero-knowledge, master password — единственный доступ.
- Используется Argon2id для Derive ключей.
- CRDT (LWW-Element-Set) для multi-client синхронизации.
- End-to-end AES-256-GCM шифрование данных.
- Сервер не хранит master password и encryption_key.

---

## 2. Аутентификация

### 2.1. Генерация ключей (на клиенте)

```
auth_key = Argon2id(master_password + username + "auth", salt)
encryption_key = Argon2id(master_password + username + "encrypt", salt)
auth_key_hash = SHA256(auth_key) // hex-encoded
```

Параметры Argon2id: 1 итерация, 64MB памяти, 4 параллелизма, 32 байта вывода
Salt: 32 байта, публичный, хранится на сервере.

---

### 2.2. Регистрация (клиент → сервер):

1. Ввод username + master_password
2. Генерация public_salt (32 bytes)
3. Ключи как в 2.1
4. Отправка на сервер: { username, auth_key_hash, public_salt }
5. Сервер проверяет уникальность, сохраняет данные.

API:
```POST /api/v1/auth/register```

---

### 2.3. Логин:

1. Ввод username + master_password
2. Запрос salt с сервера по username
3. Калькуляция auth_key, encryption_key
4. Отправка `auth_key_hash` на сервер
5. Сервер проверяет и возвращает JWT access и refresh токены
6. Клиент локально сохраняет username, salt, зашифрованные токены.

API:
```GET /api/v1/auth/salt/:username```
```POST /api/v1/auth/login```

---

### 2.4. Обновление и выход из системы

- Refresh токен по `POST /api/v1/auth/refresh` (Bearer refresh_token)
- Логаут по `POST /api/v1/auth/logout` (Bearer access_token)
- Клиент удаляет локальные токены и, опционально, данные.

---

## 3. Валидация

- Username:
  Регэксп `^[a-zA-Z0-9_]{3,32}$`
  Без спецсимволов, точек, дефисов; длина 3-32 символа.

- Master Password: минимум 12 символов, рекомендуется сложность.

---

## 4. Хранение данных

### 4.1. Клиент (BoltDB)

- Bucket `auth/`: username (plaintext), public_salt (plaintext), user_id, access/refresh токены (encrypted), token_expiry
- Bucket `data/`: шифрованные записи (credential, text, binary, card) + meta
- Bucket `crdt/`: vector_clock и версии
- Bucket `meta/`: last_sync timestamp

**Примечания:**
Master password и encryption_key не сохраняются локально.

---

### 4.2. Сервер (SQLite)

- Используется pure Go драйвер `modernc.org/sqlite` для кросс-компиляции.
- Включён WAL режим, busy_timeout, foreign_keys ON.
- `MaxOpenConns = 1` критично, чтобы избежать "database is locked".

**Структура таблиц:**

- `users` (id UUID, username, auth_key_hash (SHA256 hex), public_salt (base64), timestamps)
- `refresh_tokens` (id, user_id, bcrypt(token), expires_at, timestamps)
- `user_data` (id UUID, user_id, type, encrypted data, metadata, version, Lamport timestamp, deleted, timestamps)

---

## 5. Типы данных (пример: Credential, Text, Binary, Card) с полями, включая Metadata (теги, избранное, кастомные поля)

---

## 6. Шифрование (AES-256-GCM)

- Ключ: encryption_key (32 bytes)
- Nonce: 12 bytes рандом, результат = nonce + ciphertext + auth_tag
- Данные сериализуются в JSON перед шифрованием.
- Передача в base64.
- Шифруются все поля записи, включая метаданные и токены.
- Username, public_salt, ID, типы — plaintext для индексации.

---

## 7. Синхронизация (через CRDT)

- LWW-Element-Set с детерминированным разрешением конфликтов по (timestamp, node_id).
- Lamport timestamp и node_id.
- Soft delete флаг.
- Push/pull API с передачей изменений после `since` timestamp.
- Клиент обновляет `last_sync` после успешной синхронизации.

---

## 8. CLI команды

- Регистрация, логин, логаут, статус, версия.
- Управление (add, list, get, update, delete, search) для разных типов данных.
- Синхронизация с сервером (sync, sync --force).
- При логине предлагается использование сохранённого username из локального хранилища.

---

## 9. Получение master password

- Приоритет:
  1) Среда `GOPHKEEPER_MASTER_PASSWORD`
  2) Интерактивный ввод с `term.ReadPassword()`

Master password не сохраняется ни в каком виде.

---

## 10. Мультиклиентская поддержка

- Один и тот же public_salt на всех клиентах пользователя.
- Ключи `encryption_key` одинаковы на всех устройствах для одного username+password+salt.

---

## 11. Архитектура приложения (трёхслойная)

```
Access Layer (HTTP/CLI) → Service Layer (бизнес-логика) → Storage Layer (DB/BoltDB)
```

- Access → Service: разрешено
- Service → Storage: разрешено
- Access → Storage: запрещено

---

## 12. Безопасность

- TLS 1.3 обязателен (recommended cipher suites: AES256_GCM, CHACHA20_POLY1305).
- Production: Использовать Let's Encrypt.
- Self-hosted: можно кастомный CA с передачей через клиент.
- Dev: self-signed и `--insecure` флаг (не для продакшн).
- Лимиты по rate limiting для логина, регистрации и запросов salt.
- В логах НЕ указывать master password, ключи и токены.

---

## 13. Тестирование

- Использовать testify (assert, require, suite) и gomock.
- Табличные тесты — предпочтительный формат.
- Цель покрытия ≥80%.
- Интеграционные тесты с in-memory SQLite.
- Покрытие для всей критической логики, крипто и БД.

---

## 14. Основные примечания

- Master password НЕ хранится ни на клиенте, ни на сервере.
- Сервер не может расшифровать пользовательские данные.
- Логи и API исключают передачу секретов в явном виде.
- CRDT для конфликтного слияния с использованием Lamport timestamps и node_id.
- SQLite с одним соединением для предотвращения блокировок.
- BoltDB на клиенте — key-value, plaintext для соли и username.
- JWT access token 15 мин, refresh token 30 дней.
- CLI UX: удобное повторное использование сохранённого username.

---

# Ключевые API эндпоинты

| Метод | Путь                         | Описание                           |
|-------|------------------------------|----------------------------------|
| POST  | /api/v1/auth/register         | Регистрация                      |
| GET   | /api/v1/auth/salt/{username}  | Получить public_salt             |
| POST  | /api/v1/auth/login            | Логин, получить токены           |
| POST  | /api/v1/auth/refresh          | Обновление токена                |
| POST  | /api/v1/auth/logout           | Выход                           |
| GET   | /api/v1/sync?since=timestamp  | Получить изменения с сервера    |
| POST  | /api/v1/sync                  | Отправить изменения на сервер   |

---

# Итог

Сокращённое ТЗ фиксирует важные шаги, алгоритмы, структурные решения и ограничения. Сохраняется понимание бизнес-логики, крипто сигнатуры, работы с токенами и синхронизацией.
