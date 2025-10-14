package models

import "time"

// User представляет пользователя в системе
type User struct {
	CreatedAt   time.Time  `json:"created_at"`
	LastLogin   *time.Time `json:"last_login,omitempty"`
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	AuthKeyHash string     `json:"auth_key_hash"`
	PublicSalt  string     `json:"public_salt"`
}

// RefreshToken представляет refresh token пользователя
type RefreshToken struct {
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
}
