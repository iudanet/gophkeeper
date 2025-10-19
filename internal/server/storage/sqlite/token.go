package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/iudanet/gophkeeper/internal/models"
	"github.com/iudanet/gophkeeper/internal/server/storage"
)

// SaveRefreshToken stores a new refresh token
func (s *Storage) SaveRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	query := `
		INSERT OR REPLACE INTO refresh_tokens (token, user_id, expires_at, created_at)
		VALUES (?, ?, ?, ?)
	`

	_, err := s.db.ExecContext(ctx, query,
		token.Token,
		token.UserID,
		token.ExpiresAt,
		token.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to save refresh token: %w", err)
	}

	return nil
}

// GetRefreshToken retrieves refresh token by token value
func (s *Storage) GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	query := `
		SELECT token, user_id, expires_at, created_at
		FROM refresh_tokens
		WHERE token = ?
	`

	refreshToken := &models.RefreshToken{}

	err := s.db.QueryRowContext(ctx, query, token).Scan(
		&refreshToken.Token,
		&refreshToken.UserID,
		&refreshToken.ExpiresAt,
		&refreshToken.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrTokenNotFound
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	return refreshToken, nil
}

// GetUserTokens retrieves all refresh tokens for a user
func (s *Storage) GetUserTokens(ctx context.Context, userID string) ([]*models.RefreshToken, error) {
	query := `
		SELECT token, user_id, expires_at, created_at
		FROM refresh_tokens
		WHERE user_id = ?
		ORDER BY created_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user tokens: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var tokens []*models.RefreshToken

	for rows.Next() {
		token := &models.RefreshToken{}
		if err := rows.Scan(
			&token.Token,
			&token.UserID,
			&token.ExpiresAt,
			&token.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan token: %w", err)
		}
		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return tokens, nil
}

// DeleteRefreshToken deletes refresh token by token value
func (s *Storage) DeleteRefreshToken(ctx context.Context, token string) error {
	query := `DELETE FROM refresh_tokens WHERE token = ?`

	result, err := s.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return storage.ErrTokenNotFound
	}

	return nil
}

// DeleteUserTokens deletes all refresh tokens for a user
func (s *Storage) DeleteUserTokens(ctx context.Context, userID string) (int, error) {
	query := `DELETE FROM refresh_tokens WHERE user_id = ?`

	result, err := s.db.ExecContext(ctx, query, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to delete user tokens: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return int(rows), nil
}

// DeleteExpiredTokens removes all expired tokens
func (s *Storage) DeleteExpiredTokens(ctx context.Context) (int, error) {
	query := `DELETE FROM refresh_tokens WHERE expires_at < datetime('now')`

	result, err := s.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired tokens: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return int(rows), nil
}
