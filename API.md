# GophKeeper API Documentation

## Base URL
```
http://localhost:8080
```

## Authentication Endpoints

### 1. Register User
**Endpoint:** `POST /api/v1/auth/register`

**Description:** Регистрация нового пользователя

**Request:**
```json
{
  "username": "alice",
  "auth_key_hash": "bcrypt_hash_of_auth_key",
  "public_salt": "base64_encoded_32_bytes_salt"
}
```

**Response:** `201 Created`
```json
{
  "user_id": "uuid",
  "message": "User registered successfully"
}
```

**Errors:**
- `400 Bad Request` - Invalid username or missing fields
- `409 Conflict` - Username already exists (TODO: not implemented yet)

---

### 2. Get Public Salt
**Endpoint:** `GET /api/v1/auth/salt/{username}`

**Description:** Получение public_salt пользователя для деривации ключей

**Response:** `200 OK`
```json
{
  "public_salt": "base64_encoded_salt"
}
```

**Errors:**
- `400 Bad Request` - Invalid username format
- `404 Not Found` - User not found (TODO: not implemented yet)

---

### 3. Login
**Endpoint:** `POST /api/v1/auth/login`

**Description:** Аутентификация пользователя

**Request:**
```json
{
  "username": "alice",
  "auth_key_hash": "bcrypt_hash_of_auth_key"
}
```

**Response:** `200 OK`
```json
{
  "access_token": "jwt_token",
  "refresh_token": "random_token",
  "expires_in": 900
}
```

**Errors:**
- `400 Bad Request` - Invalid username or missing fields
- `401 Unauthorized` - Invalid credentials (TODO: not implemented yet)

---

### 4. Refresh Token
**Endpoint:** `POST /api/v1/auth/refresh`

**Description:** Обновление access token с помощью refresh token

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Response:** `200 OK`
```json
{
  "access_token": "new_jwt_token",
  "refresh_token": "new_random_token",
  "expires_in": 900
}
```

**Errors:**
- `401 Unauthorized` - Invalid or expired refresh token

---

### 5. Logout
**Endpoint:** `POST /api/v1/auth/logout`

**Description:** Выход пользователя (удаление refresh token)

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `204 No Content`

**Errors:**
- `401 Unauthorized` - Invalid access token

---

## Health Check

### Health Status
**Endpoint:** `GET /api/v1/health`

**Description:** Проверка состояния сервера

**Response:** `200 OK`
```json
{
  "status": "ok",
  "version": "dev"
}
```

---

## Example Usage with curl

### Register new user
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "auth_key_hash": "hash123",
    "public_salt": "salt123"
  }'
```

### Get salt
```bash
curl http://localhost:8080/api/v1/auth/salt/alice
```

### Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "auth_key_hash": "hash123"
  }'
```

### Refresh token
```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Authorization: Bearer <refresh_token>"
```

### Logout
```bash
curl -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer <access_token>"
```

### Health check
```bash
curl http://localhost:8080/api/v1/health
```

---

## Server Configuration

### Command-line flags
```bash
./gophkeeper-server [OPTIONS]

Options:
  --version           Show version information
  --port PORT         Server port (default: 8080)
  --log-level LEVEL   Log level: debug, info, warn, error (default: info)
```

### Examples
```bash
# Start server on default port 8080
./gophkeeper-server

# Start server on custom port
./gophkeeper-server --port 9000

# Start server with debug logging
./gophkeeper-server --log-level debug

# Show version
./gophkeeper-server --version
```

---

## Current Implementation Status

✅ **Implemented:**
- All HTTP endpoints with stub responses
- Request validation (username, required fields)
- JSON request/response handling
- Structured logging (slog)
- Graceful shutdown
- Health check endpoint

⏳ **TODO (Stubs):**
- Database integration (SQLite)
- JWT token generation and validation
- bcrypt password verification
- Refresh token management
- Rate limiting
- Authentication middleware

---

## Error Response Format

All errors return JSON in the following format:

```json
{
  "error": "HTTP Status Text",
  "message": "Detailed error message"
}
```

Examples:
```json
{
  "error": "Bad Request",
  "message": "username can only contain letters (a-z, A-Z), numbers (0-9), and underscores (_)"
}
```

```json
{
  "error": "Unauthorized",
  "message": "Authorization header is required"
}
```
