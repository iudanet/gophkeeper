package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/gophkeeper/internal/models"
	"github.com/iudanet/gophkeeper/internal/server/storage"
)

func TestTokenStorage_SaveRefreshToken(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	userID := createTestUser(t, ctx, s)

	tests := []struct {
		name  string
		token *models.RefreshToken
	}{
		{
			name: "save new refresh token",
			token: &models.RefreshToken{
				Token:     "token123",
				UserID:    userID,
				ExpiresAt: time.Now().Add(24 * time.Hour),
				CreatedAt: time.Now(),
			},
		},
		{
			name: "replace existing token with same value",
			token: &models.RefreshToken{
				Token:     "token123", // Same token
				UserID:    userID,
				ExpiresAt: time.Now().Add(48 * time.Hour), // Different expiry
				CreatedAt: time.Now(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.SaveRefreshToken(ctx, tt.token)
			require.NoError(t, err)

			// Verify token was saved
			retrieved, err := s.GetRefreshToken(ctx, tt.token.Token)
			require.NoError(t, err)
			assert.Equal(t, tt.token.Token, retrieved.Token)
			assert.Equal(t, tt.token.UserID, retrieved.UserID)
		})
	}
}

func TestTokenStorage_GetRefreshToken(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	userID := createTestUser(t, ctx, s)

	// Create test token
	token := &models.RefreshToken{
		Token:     "findme",
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}
	err := s.SaveRefreshToken(ctx, token)
	require.NoError(t, err)

	tests := []struct {
		name      string
		token     string
		wantError error
	}{
		{
			name:      "get existing token",
			token:     "findme",
			wantError: nil,
		},
		{
			name:      "get non-existent token",
			token:     "notfound",
			wantError: storage.ErrTokenNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrieved, err := s.GetRefreshToken(ctx, tt.token)
			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
				assert.Nil(t, retrieved)
			} else {
				require.NoError(t, err)
				assert.Equal(t, token.Token, retrieved.Token)
				assert.Equal(t, token.UserID, retrieved.UserID)
			}
		})
	}
}

func TestTokenStorage_GetUserTokens(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	userID1 := createTestUser(t, ctx, s)
	userID2 := createTestUser(t, ctx, s)

	// Create multiple tokens for user1
	tokens := []*models.RefreshToken{
		{
			Token:     "token1",
			UserID:    userID1,
			ExpiresAt: time.Now().Add(24 * time.Hour),
			CreatedAt: time.Now(),
		},
		{
			Token:     "token2",
			UserID:    userID1,
			ExpiresAt: time.Now().Add(48 * time.Hour),
			CreatedAt: time.Now().Add(time.Minute),
		},
		{
			Token:     "token3",
			UserID:    userID2, // Different user
			ExpiresAt: time.Now().Add(24 * time.Hour),
			CreatedAt: time.Now(),
		},
	}

	for _, token := range tokens {
		err := s.SaveRefreshToken(ctx, token)
		require.NoError(t, err)
	}

	tests := []struct {
		name          string
		userID        string
		expectedCount int
	}{
		{
			name:          "get tokens for user with 2 tokens",
			userID:        userID1,
			expectedCount: 2,
		},
		{
			name:          "get tokens for user with 1 token",
			userID:        userID2,
			expectedCount: 1,
		},
		{
			name:          "get tokens for user with no tokens",
			userID:        "nonexistent",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrieved, err := s.GetUserTokens(ctx, tt.userID)
			require.NoError(t, err)
			assert.Len(t, retrieved, tt.expectedCount)

			// Verify all tokens belong to the user
			for _, token := range retrieved {
				assert.Equal(t, tt.userID, token.UserID)
			}
		})
	}
}

func TestTokenStorage_GetUserTokens_OrderedByCreatedAt(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	userID := createTestUser(t, ctx, s)

	// Create tokens with different creation times
	now := time.Now()
	tokens := []*models.RefreshToken{
		{
			Token:     "oldest",
			UserID:    userID,
			ExpiresAt: now.Add(24 * time.Hour),
			CreatedAt: now.Add(-2 * time.Hour),
		},
		{
			Token:     "newest",
			UserID:    userID,
			ExpiresAt: now.Add(24 * time.Hour),
			CreatedAt: now,
		},
		{
			Token:     "middle",
			UserID:    userID,
			ExpiresAt: now.Add(24 * time.Hour),
			CreatedAt: now.Add(-1 * time.Hour),
		},
	}

	for _, token := range tokens {
		err := s.SaveRefreshToken(ctx, token)
		require.NoError(t, err)
	}

	// Get tokens - should be ordered by created_at DESC
	retrieved, err := s.GetUserTokens(ctx, userID)
	require.NoError(t, err)
	require.Len(t, retrieved, 3)

	// Verify ordering (newest first)
	assert.Equal(t, "newest", retrieved[0].Token)
	assert.Equal(t, "middle", retrieved[1].Token)
	assert.Equal(t, "oldest", retrieved[2].Token)
}

func TestTokenStorage_DeleteRefreshToken(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	userID := createTestUser(t, ctx, s)

	// Create test token
	token := &models.RefreshToken{
		Token:     "todelete",
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}
	err := s.SaveRefreshToken(ctx, token)
	require.NoError(t, err)

	tests := []struct {
		name      string
		token     string
		wantError error
	}{
		{
			name:      "delete existing token",
			token:     "todelete",
			wantError: nil,
		},
		{
			name:      "delete non-existent token",
			token:     "notfound",
			wantError: storage.ErrTokenNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.DeleteRefreshToken(ctx, tt.token)
			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
			} else {
				require.NoError(t, err)

				// Verify token is deleted
				_, err := s.GetRefreshToken(ctx, tt.token)
				assert.ErrorIs(t, err, storage.ErrTokenNotFound)
			}
		})
	}
}

func TestTokenStorage_DeleteUserTokens(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	userID1 := createTestUser(t, ctx, s)
	userID2 := createTestUser(t, ctx, s)

	// Create tokens for both users
	tokens := []*models.RefreshToken{
		{Token: "user1_token1", UserID: userID1, ExpiresAt: time.Now().Add(24 * time.Hour), CreatedAt: time.Now()},
		{Token: "user1_token2", UserID: userID1, ExpiresAt: time.Now().Add(24 * time.Hour), CreatedAt: time.Now()},
		{Token: "user2_token1", UserID: userID2, ExpiresAt: time.Now().Add(24 * time.Hour), CreatedAt: time.Now()},
	}

	for _, token := range tokens {
		err := s.SaveRefreshToken(ctx, token)
		require.NoError(t, err)
	}

	tests := []struct {
		name          string
		userID        string
		expectedCount int
	}{
		{
			name:          "delete tokens for user with 2 tokens",
			userID:        userID1,
			expectedCount: 2,
		},
		{
			name:          "delete tokens for user with no tokens",
			userID:        "nonexistent",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, err := s.DeleteUserTokens(ctx, tt.userID)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedCount, count)

			// Verify tokens are deleted
			remaining, err := s.GetUserTokens(ctx, tt.userID)
			require.NoError(t, err)
			assert.Empty(t, remaining)
		})
	}

	// Verify user2's token still exists
	user2Tokens, err := s.GetUserTokens(ctx, userID2)
	require.NoError(t, err)
	assert.Len(t, user2Tokens, 1)
}

func TestTokenStorage_DeleteExpiredTokens(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	userID := createTestUser(t, ctx, s)

	// Use UTC time to match SQLite's datetime('now')
	now := time.Now().UTC()
	tokens := []*models.RefreshToken{
		{
			Token:     "expired1",
			UserID:    userID,
			ExpiresAt: now.Add(-2 * time.Hour), // Expired
			CreatedAt: now.Add(-3 * time.Hour),
		},
		{
			Token:     "expired2",
			UserID:    userID,
			ExpiresAt: now.Add(-1 * time.Hour), // Expired
			CreatedAt: now.Add(-2 * time.Hour),
		},
		{
			Token:     "valid1",
			UserID:    userID,
			ExpiresAt: now.Add(24 * time.Hour), // Valid
			CreatedAt: now,
		},
		{
			Token:     "valid2",
			UserID:    userID,
			ExpiresAt: now.Add(48 * time.Hour), // Valid
			CreatedAt: now,
		},
	}

	for _, token := range tokens {
		err := s.SaveRefreshToken(ctx, token)
		require.NoError(t, err)
	}

	// Delete expired tokens
	count, err := s.DeleteExpiredTokens(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "Should delete 2 expired tokens")

	// Verify only valid tokens remain
	remaining, err := s.GetUserTokens(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, remaining, 2, "Should have 2 valid tokens remaining")

	for _, token := range remaining {
		assert.True(t, token.ExpiresAt.After(now), "Remaining tokens should not be expired")
	}
}

func TestTokenStorage_DeleteExpiredTokens_NoExpired(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	userID := createTestUser(t, ctx, s)

	// Create only valid tokens
	token := &models.RefreshToken{
		Token:     "valid",
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}
	err := s.SaveRefreshToken(ctx, token)
	require.NoError(t, err)

	// Try to delete expired tokens
	count, err := s.DeleteExpiredTokens(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Should delete 0 tokens")

	// Verify token still exists
	remaining, err := s.GetUserTokens(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, remaining, 1)
}
