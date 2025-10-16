package storage

import (
	"context"
	"time"

	"github.com/iudanet/gophkeeper/internal/models"
)

// UserStorage defines interface for user data persistence
type UserStorage interface {
	// CreateUser creates a new user in the storage
	// Returns error if username already exists
	CreateUser(ctx context.Context, user *models.User) error

	// GetUserByUsername retrieves user by username
	// Returns ErrUserNotFound if user doesn't exist
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)

	// GetUserByID retrieves user by ID
	// Returns ErrUserNotFound if user doesn't exist
	GetUserByID(ctx context.Context, userID string) (*models.User, error)

	// UpdateUser updates user information
	// Returns ErrUserNotFound if user doesn't exist
	UpdateUser(ctx context.Context, user *models.User) error

	// DeleteUser deletes user by ID
	// Returns ErrUserNotFound if user doesn't exist
	DeleteUser(ctx context.Context, userID string) error

	// UpdateLastLogin updates the last login timestamp
	UpdateLastLogin(ctx context.Context, userID string, lastLogin time.Time) error
}
