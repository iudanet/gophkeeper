package middleware

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/gophkeeper/internal/server/handlers"
)

// setupTestLogger creates a logger for testing
func setupTestLogger() *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: slog.LevelError,
	}
	handler := slog.NewTextHandler(os.Stdout, opts)
	return slog.New(handler)
}

// testHandler is a simple handler that checks context values
func testHandler(t *testing.T, expectedUserID, expectedUsername string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := handlers.GetUserID(r.Context())
		require.True(t, ok, "user_id should be in context")
		assert.Equal(t, expectedUserID, userID)

		username, ok := handlers.GetUsername(r.Context())
		require.True(t, ok, "username should be in context")
		assert.Equal(t, expectedUsername, username)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}
}

func TestAuthMiddleware_Success(t *testing.T) {
	logger := setupTestLogger()

	// Create JWT config
	jwtConfig := handlers.JWTConfig{
		Secret:          []byte("test-secret-key"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	// Generate valid token
	token, _, err := handlers.GenerateAccessToken(jwtConfig, "user123", "testuser")
	require.NoError(t, err)

	// Create middleware
	authMiddleware := AuthMiddleware(logger, jwtConfig)

	// Create test handler
	handler := testHandler(t, "user123", "testuser")
	wrappedHandler := authMiddleware(handler)

	// Create request with Authorization header
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestAuthMiddleware_MissingAuthHeader(t *testing.T) {
	logger := setupTestLogger()

	jwtConfig := handlers.JWTConfig{
		Secret:          []byte("test-secret-key"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	authMiddleware := AuthMiddleware(logger, jwtConfig)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called")
	})
	wrappedHandler := authMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// No Authorization header

	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "missing token")
}

func TestAuthMiddleware_InvalidAuthHeaderFormat(t *testing.T) {
	logger := setupTestLogger()

	jwtConfig := handlers.JWTConfig{
		Secret:          []byte("test-secret-key"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	authMiddleware := AuthMiddleware(logger, jwtConfig)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called")
	})
	wrappedHandler := authMiddleware(handler)

	tests := []struct {
		name   string
		header string
	}{
		{
			name:   "no Bearer prefix",
			header: "token123",
		},
		{
			name:   "wrong prefix",
			header: "Basic token123",
		},
		{
			name:   "only Bearer",
			header: "Bearer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", tt.header)

			w := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Contains(t, w.Body.String(), "invalid token format")
		})
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	logger := setupTestLogger()

	jwtConfig := handlers.JWTConfig{
		Secret:          []byte("test-secret-key"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	authMiddleware := AuthMiddleware(logger, jwtConfig)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called")
	})
	wrappedHandler := authMiddleware(handler)

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "malformed token",
			token: "invalid.token.here",
		},
		{
			name:  "empty token",
			token: "",
		},
		{
			name:  "random string",
			token: "randomstring123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)

			w := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Contains(t, w.Body.String(), "invalid token")
		})
	}
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	logger := setupTestLogger()

	// Create JWT config with very short TTL
	jwtConfig := handlers.JWTConfig{
		Secret:          []byte("test-secret-key"),
		AccessTokenTTL:  1 * time.Nanosecond, // Expired immediately
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	// Generate token that expires immediately
	token, _, err := handlers.GenerateAccessToken(jwtConfig, "user123", "testuser")
	require.NoError(t, err)

	// Wait a bit to ensure token is expired
	time.Sleep(10 * time.Millisecond)

	authMiddleware := AuthMiddleware(logger, jwtConfig)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called")
	})
	wrappedHandler := authMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid token")
}

func TestAuthMiddleware_TokenWithWrongSecret(t *testing.T) {
	logger := setupTestLogger()

	// Generate token with one secret
	jwtConfig1 := handlers.JWTConfig{
		Secret:          []byte("secret-key-1"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	token, _, err := handlers.GenerateAccessToken(jwtConfig1, "user123", "testuser")
	require.NoError(t, err)

	// Try to validate with different secret
	jwtConfig2 := handlers.JWTConfig{
		Secret:          []byte("secret-key-2"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	authMiddleware := AuthMiddleware(logger, jwtConfig2)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called")
	})
	wrappedHandler := authMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid token")
}
