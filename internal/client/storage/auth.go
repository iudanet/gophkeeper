package storage

import (
	"context"
	"time"
)

// AuthData represents stored authentication information
type AuthData struct {
	Username     string    // Username
	UserID       string    // User ID from server
	AccessToken  string    // JWT access token
	RefreshToken string    // Refresh token
	ExpiresAt    time.Time // Access token expiration time
	PublicSalt   string    // Public salt for key derivation
}

// AuthStorage defines interface for storing authentication data on client
type AuthStorage interface {
	// SaveAuth stores authentication data
	SaveAuth(ctx context.Context, auth *AuthData) error

	// GetAuth retrieves stored authentication data
	// Returns ErrAuthNotFound if no auth data exists
	GetAuth(ctx context.Context) (*AuthData, error)

	// DeleteAuth removes stored authentication data (logout)
	DeleteAuth(ctx context.Context) error

	// IsAuthenticated checks if valid authentication exists
	IsAuthenticated(ctx context.Context) (bool, error)
}
