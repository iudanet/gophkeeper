package storage

import (
	"context"

	"github.com/iudanet/gophkeeper/internal/models"
)

// TokenStorage defines interface for refresh token persistence
type TokenStorage interface {
	// SaveRefreshToken stores a new refresh token
	// If token with same token value exists, it will be replaced
	SaveRefreshToken(ctx context.Context, token *models.RefreshToken) error

	// GetRefreshToken retrieves refresh token by token value
	// Returns ErrTokenNotFound if token doesn't exist
	GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error)

	// GetUserTokens retrieves all refresh tokens for a user
	// Returns empty slice if no tokens found
	GetUserTokens(ctx context.Context, userID string) ([]*models.RefreshToken, error)

	// DeleteRefreshToken deletes refresh token by token value
	// Returns ErrTokenNotFound if token doesn't exist
	DeleteRefreshToken(ctx context.Context, token string) error

	// DeleteUserTokens deletes all refresh tokens for a user
	// Returns number of deleted tokens
	DeleteUserTokens(ctx context.Context, userID string) (int, error)

	// DeleteExpiredTokens removes all expired tokens
	// Returns number of deleted tokens
	DeleteExpiredTokens(ctx context.Context) (int, error)
}
