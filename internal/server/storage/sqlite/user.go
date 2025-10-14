package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/iudanet/gophkeeper/internal/models"
	"github.com/iudanet/gophkeeper/internal/server/storage"
)

// CreateUser creates a new user in the storage
func (s *Storage) CreateUser(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (id, username, auth_key_hash, public_salt, created_at, last_login)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.ExecContext(ctx, query,
		user.ID,
		user.Username,
		user.AuthKeyHash,
		user.PublicSalt,
		user.CreatedAt,
		user.LastLogin,
	)

	if err != nil {
		// Проверяем на duplicate username
		if err.Error() == "UNIQUE constraint failed: users.username" {
			return storage.ErrUserAlreadyExists
		}
		return fmt.Errorf("failed to insert user: %w", err)
	}

	return nil
}

// GetUserByUsername retrieves user by username
func (s *Storage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	query := `
		SELECT id, username, auth_key_hash, public_salt, created_at, last_login
		FROM users
		WHERE username = ?
	`

	user := &models.User{}
	var lastLogin sql.NullTime

	err := s.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID,
		&user.Username,
		&user.AuthKeyHash,
		&user.PublicSalt,
		&user.CreatedAt,
		&lastLogin,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return user, nil
}

// GetUserByID retrieves user by ID
func (s *Storage) GetUserByID(ctx context.Context, userID string) (*models.User, error) {
	query := `
		SELECT id, username, auth_key_hash, public_salt, created_at, last_login
		FROM users
		WHERE id = ?
	`

	user := &models.User{}
	var lastLogin sql.NullTime

	err := s.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID,
		&user.Username,
		&user.AuthKeyHash,
		&user.PublicSalt,
		&user.CreatedAt,
		&lastLogin,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return user, nil
}

// UpdateUser updates user information
func (s *Storage) UpdateUser(ctx context.Context, user *models.User) error {
	query := `
		UPDATE users
		SET username = ?, auth_key_hash = ?, public_salt = ?, last_login = ?
		WHERE id = ?
	`

	result, err := s.db.ExecContext(ctx, query,
		user.Username,
		user.AuthKeyHash,
		user.PublicSalt,
		user.LastLogin,
		user.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return storage.ErrUserNotFound
	}

	return nil
}

// DeleteUser deletes user by ID
func (s *Storage) DeleteUser(ctx context.Context, userID string) error {
	query := `DELETE FROM users WHERE id = ?`

	result, err := s.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return storage.ErrUserNotFound
	}

	return nil
}

// UpdateLastLogin updates the last login timestamp
func (s *Storage) UpdateLastLogin(ctx context.Context, userID string, lastLogin time.Time) error {
	query := `UPDATE users SET last_login = ? WHERE id = ?`

	result, err := s.db.ExecContext(ctx, query, lastLogin, userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return storage.ErrUserNotFound
	}

	return nil
}
