package models

import "time"

// User представляет пользователя в системе
type User struct {
	ID          string    `json:"id"`            // UUID пользователя
	Username    string    `json:"username"`      // уникальный username
	AuthKeyHash string    `json:"auth_key_hash"` // bcrypt хеш auth_key
	PublicSalt  string    `json:"public_salt"`   // base64 encoded salt (32 bytes)
	CreatedAt   time.Time `json:"created_at"`    // время создания
	UpdatedAt   time.Time `json:"updated_at"`    // время последнего обновления
}

// RefreshToken представляет refresh token пользователя
type RefreshToken struct {
	ID        string    `json:"id"`         // UUID токена
	UserID    string    `json:"user_id"`    // ID пользователя
	TokenHash string    `json:"token_hash"` // bcrypt хеш токена
	ExpiresAt time.Time `json:"expires_at"` // время истечения
	CreatedAt time.Time `json:"created_at"` // время создания
}
