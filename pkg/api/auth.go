package api

// RegisterRequest представляет запрос на регистрацию нового пользователя
type RegisterRequest struct {
	Username    string `json:"username"`      // username пользователя
	AuthKeyHash string `json:"auth_key_hash"` // SHA256 хеш auth_key (hex-encoded)
	PublicSalt  string `json:"public_salt"`   // base64 encoded salt (32 bytes)
}

// RegisterResponse представляет ответ на успешную регистрацию
type RegisterResponse struct {
	UserID  string `json:"user_id"` // UUID пользователя
	Message string `json:"message"` // сообщение об успешной регистрации
}

// SaltResponse представляет ответ с публичной солью пользователя
type SaltResponse struct {
	PublicSalt string `json:"public_salt"` // base64 encoded salt
}

// LoginRequest представляет запрос на аутентификацию
type LoginRequest struct {
	Username    string `json:"username"`      // username пользователя
	AuthKeyHash string `json:"auth_key_hash"` // SHA256 хеш auth_key (hex-encoded)
}

// TokenResponse представляет ответ с токенами доступа
type TokenResponse struct {
	AccessToken  string `json:"access_token"`  // JWT access token
	RefreshToken string `json:"refresh_token"` // refresh token
	ExpiresIn    int64  `json:"expires_in"`    // время жизни access token в секундах
}

// ErrorResponse представляет ответ с ошибкой
type ErrorResponse struct {
	Error   string `json:"error"`             // описание ошибки
	Message string `json:"message,omitempty"` // дополнительное сообщение
}
