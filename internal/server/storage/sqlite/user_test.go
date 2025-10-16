package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/gophkeeper/internal/models"
	"github.com/iudanet/gophkeeper/internal/server/storage"
)

func TestUserStorage_CreateUser(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	tests := []struct {
		wantError error
		user      *models.User
		name      string
	}{
		{
			name: "create new user successfully",
			user: &models.User{
				ID:          uuid.New().String(),
				Username:    "testuser1",
				AuthKeyHash: "hash123",
				PublicSalt:  "salt123",
				CreatedAt:   time.Now(),
				LastLogin:   nil,
			},
			wantError: nil,
		},
		{
			name: "create user with last login",
			user: &models.User{
				ID:          uuid.New().String(),
				Username:    "testuser2",
				AuthKeyHash: "hash456",
				PublicSalt:  "salt456",
				CreatedAt:   time.Now(),
				LastLogin:   timePtr(time.Now()),
			},
			wantError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.CreateUser(ctx, tt.user)
			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
			} else {
				require.NoError(t, err)

				// Verify user was created
				retrieved, err := s.GetUserByID(ctx, tt.user.ID)
				require.NoError(t, err)
				assert.Equal(t, tt.user.ID, retrieved.ID)
				assert.Equal(t, tt.user.Username, retrieved.Username)
				assert.Equal(t, tt.user.AuthKeyHash, retrieved.AuthKeyHash)
				assert.Equal(t, tt.user.PublicSalt, retrieved.PublicSalt)
			}
		})
	}
}

func TestUserStorage_CreateUser_DuplicateUsername(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	// Create first user
	user1 := &models.User{
		ID:          uuid.New().String(),
		Username:    "duplicate",
		AuthKeyHash: "hash1",
		PublicSalt:  "salt1",
		CreatedAt:   time.Now(),
	}
	err := s.CreateUser(ctx, user1)
	require.NoError(t, err)

	// Try to create second user with same username
	user2 := &models.User{
		ID:          uuid.New().String(),
		Username:    "duplicate", // Same username
		AuthKeyHash: "hash2",
		PublicSalt:  "salt2",
		CreatedAt:   time.Now(),
	}
	err = s.CreateUser(ctx, user2)
	assert.ErrorIs(t, err, storage.ErrUserAlreadyExists)
}

func TestUserStorage_GetUserByUsername(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	// Create test user
	user := &models.User{
		ID:          uuid.New().String(),
		Username:    "findme",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
		CreatedAt:   time.Now(),
		LastLogin:   timePtr(time.Now()),
	}
	err := s.CreateUser(ctx, user)
	require.NoError(t, err)

	tests := []struct {
		wantError error
		name      string
		username  string
	}{
		{
			name:      "get existing user",
			username:  "findme",
			wantError: nil,
		},
		{
			name:      "get non-existent user",
			username:  "notfound",
			wantError: storage.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrieved, err := s.GetUserByUsername(ctx, tt.username)
			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
				assert.Nil(t, retrieved)
			} else {
				require.NoError(t, err)
				assert.Equal(t, user.ID, retrieved.ID)
				assert.Equal(t, user.Username, retrieved.Username)
				assert.Equal(t, user.AuthKeyHash, retrieved.AuthKeyHash)
				assert.Equal(t, user.PublicSalt, retrieved.PublicSalt)
				assert.NotNil(t, retrieved.LastLogin)
			}
		})
	}
}

func TestUserStorage_GetUserByID(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	// Create test user
	userID := uuid.New().String()
	user := &models.User{
		ID:          userID,
		Username:    "testuser",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
		CreatedAt:   time.Now(),
		LastLogin:   nil,
	}
	err := s.CreateUser(ctx, user)
	require.NoError(t, err)

	tests := []struct {
		wantError error
		name      string
		userID    string
	}{
		{
			name:      "get existing user",
			userID:    userID,
			wantError: nil,
		},
		{
			name:      "get non-existent user",
			userID:    "nonexistent-id",
			wantError: storage.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrieved, err := s.GetUserByID(ctx, tt.userID)
			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
				assert.Nil(t, retrieved)
			} else {
				require.NoError(t, err)
				assert.Equal(t, user.ID, retrieved.ID)
				assert.Equal(t, user.Username, retrieved.Username)
				assert.Nil(t, retrieved.LastLogin)
			}
		})
	}
}

func TestUserStorage_UpdateUser(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	// Create test user
	userID := uuid.New().String()
	user := &models.User{
		ID:          userID,
		Username:    "original",
		AuthKeyHash: "hash1",
		PublicSalt:  "salt1",
		CreatedAt:   time.Now(),
		LastLogin:   nil,
	}
	err := s.CreateUser(ctx, user)
	require.NoError(t, err)

	tests := []struct {
		wantError error
		updates   *models.User
		name      string
	}{
		{
			name: "update username and hash",
			updates: &models.User{
				ID:          userID,
				Username:    "updated",
				AuthKeyHash: "newhash",
				PublicSalt:  "newsalt",
				LastLogin:   timePtr(time.Now()),
			},
			wantError: nil,
		},
		{
			name: "update non-existent user",
			updates: &models.User{
				ID:          "nonexistent",
				Username:    "foo",
				AuthKeyHash: "bar",
				PublicSalt:  "baz",
			},
			wantError: storage.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.UpdateUser(ctx, tt.updates)
			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
			} else {
				require.NoError(t, err)

				// Verify updates
				retrieved, err := s.GetUserByID(ctx, tt.updates.ID)
				require.NoError(t, err)
				assert.Equal(t, tt.updates.Username, retrieved.Username)
				assert.Equal(t, tt.updates.AuthKeyHash, retrieved.AuthKeyHash)
				assert.Equal(t, tt.updates.PublicSalt, retrieved.PublicSalt)
			}
		})
	}
}

func TestUserStorage_DeleteUser(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	// Create test user
	userID := uuid.New().String()
	user := &models.User{
		ID:          userID,
		Username:    "todelete",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
		CreatedAt:   time.Now(),
	}
	err := s.CreateUser(ctx, user)
	require.NoError(t, err)

	tests := []struct {
		wantError error
		name      string
		userID    string
	}{
		{
			name:      "delete existing user",
			userID:    userID,
			wantError: nil,
		},
		{
			name:      "delete non-existent user",
			userID:    "nonexistent",
			wantError: storage.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.DeleteUser(ctx, tt.userID)
			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
			} else {
				require.NoError(t, err)

				// Verify user is deleted
				_, err := s.GetUserByID(ctx, tt.userID)
				assert.ErrorIs(t, err, storage.ErrUserNotFound)
			}
		})
	}
}

func TestUserStorage_UpdateLastLogin(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	// Create test user
	userID := uuid.New().String()
	user := &models.User{
		ID:          userID,
		Username:    "logintest",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
		CreatedAt:   time.Now(),
		LastLogin:   nil,
	}
	err := s.CreateUser(ctx, user)
	require.NoError(t, err)

	tests := []struct {
		loginTime time.Time
		wantError error
		name      string
		userID    string
	}{
		{
			name:      "update last login for existing user",
			userID:    userID,
			loginTime: time.Now(),
			wantError: nil,
		},
		{
			name:      "update last login for non-existent user",
			userID:    "nonexistent",
			loginTime: time.Now(),
			wantError: storage.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.UpdateLastLogin(ctx, tt.userID, tt.loginTime)
			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
			} else {
				require.NoError(t, err)

				// Verify last login was updated
				retrieved, err := s.GetUserByID(ctx, tt.userID)
				require.NoError(t, err)
				require.NotNil(t, retrieved.LastLogin)
				// Compare times with 1 second tolerance
				assert.WithinDuration(t, tt.loginTime, *retrieved.LastLogin, time.Second)
			}
		})
	}
}

// Helper function
func timePtr(t time.Time) *time.Time {
	return &t
}
