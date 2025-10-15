package storage

import (
	"context"
)

// AuthStorage defines interface for storing authentication data on client
// This is the lowest storage layer - it works with raw data (already encrypted tokens)
// and doesn't perform any encryption/decryption itself.
type AuthStorage interface {
	// SaveAuth stores authentication data as-is (tokens should already be encrypted)
	SaveAuth(ctx context.Context, auth *AuthData) error

	// GetAuth retrieves stored authentication data as-is (tokens will be encrypted)
	// Returns ErrAuthNotFound if no auth data exists
	GetAuth(ctx context.Context) (*AuthData, error)

	// DeleteAuth removes stored authentication data (logout)
	DeleteAuth(ctx context.Context) error

	// IsAuthenticated checks if valid authentication exists (not expired)
	IsAuthenticated(ctx context.Context) (bool, error)
}

// AuthData represents authentication information in storage
// IMPORTANT: This struct is used at different layers with different token states:
// - In memory (business logic): tokens are plaintext
// - In storage (BoltDB): tokens are encrypted (base64-encoded ciphertext)
// The encryption/decryption happens in auth.AuthService layer.
type AuthData struct {
	Username     string `json:"username"`
	UserID       string `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	PublicSalt   string `json:"public_salt"`
	ExpiresAt    int64  `json:"expires_at"`
}
