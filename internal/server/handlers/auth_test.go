package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/gophkeeper/internal/models"
	"github.com/iudanet/gophkeeper/internal/server/storage"
	"github.com/iudanet/gophkeeper/pkg/api"
)

func TestAuthHandler_Register_Success(t *testing.T) {
	logger := setupTestLogger()

	users := make(map[string]*models.User)
	userStorage := &storage.UserStorageMock{
		CreateUserFunc: func(ctx context.Context, user *models.User) error {
			users[user.Username] = user
			return nil
		},
		GetUserByUsernameFunc: func(ctx context.Context, username string) (*models.User, error) {
			if user, ok := users[username]; ok {
				return user, nil
			}
			return nil, storage.ErrUserNotFound
		},
	}

	tokenStorage := &storage.TokenStorageMock{
		SaveRefreshTokenFunc: func(ctx context.Context, token *models.RefreshToken) error {
			return nil
		},
	}

	jwtConfig := JWTConfig{
		Secret:          []byte("test-secret"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	reqBody := api.RegisterRequest{
		Username:    "testuser",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.Register(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response api.RegisterResponse
	err = json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	assert.NotEmpty(t, response.UserID)

	// Verify user was created in storage
	user, err := userStorage.GetUserByUsername(context.Background(), "testuser")
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "hash123", user.AuthKeyHash)
	assert.Equal(t, "salt123", user.PublicSalt)
}

func TestAuthHandler_Register_InvalidJSON(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &storage.UserStorageMock{}
	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.Register(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_Register_InvalidUsername(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &storage.UserStorageMock{}
	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	tests := []struct {
		name     string
		username string
	}{
		{"empty username", ""},
		{"too short", "ab"},
		{"too long", "abcdefghijklmnopqrstuvwxyz1234567"},
		{"invalid chars", "user@name"},
		{"spaces", "user name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody := api.RegisterRequest{
				Username:    tt.username,
				AuthKeyHash: "hash123",
				PublicSalt:  "salt123",
			}

			body, err := json.Marshal(reqBody)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			handler.Register(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestAuthHandler_Register_DuplicateUsername(t *testing.T) {
	logger := setupTestLogger()

	users := make(map[string]*models.User)
	users["existing"] = &models.User{
		ID:          "user1",
		Username:    "existing",
		AuthKeyHash: "hash1",
		PublicSalt:  "salt1",
	}

	userStorage := &storage.UserStorageMock{
		GetUserByUsernameFunc: func(ctx context.Context, username string) (*models.User, error) {
			if user, ok := users[username]; ok {
				return user, nil
			}
			return nil, storage.ErrUserNotFound
		},
		CreateUserFunc: func(ctx context.Context, user *models.User) error {
			// Check if user already exists
			if _, exists := users[user.Username]; exists {
				return storage.ErrUserAlreadyExists
			}
			users[user.Username] = user
			return nil
		},
	}

	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	reqBody := api.RegisterRequest{
		Username:    "existing",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.Register(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestAuthHandler_Register_EmptyFields(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &storage.UserStorageMock{}
	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	tests := []struct {
		name    string
		request api.RegisterRequest
	}{
		{
			name: "empty auth_key_hash",
			request: api.RegisterRequest{
				Username:    "testuser",
				AuthKeyHash: "",
				PublicSalt:  "salt123",
			},
		},
		{
			name: "empty public_salt",
			request: api.RegisterRequest{
				Username:    "testuser",
				AuthKeyHash: "hash123",
				PublicSalt:  "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			handler.Register(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestAuthHandler_GetSalt_Success(t *testing.T) {
	logger := setupTestLogger()

	users := make(map[string]*models.User)
	users["testuser"] = &models.User{
		ID:          "user1",
		Username:    "testuser",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
	}

	userStorage := &storage.UserStorageMock{
		GetUserByUsernameFunc: func(ctx context.Context, username string) (*models.User, error) {
			if user, ok := users[username]; ok {
				return user, nil
			}
			return nil, storage.ErrUserNotFound
		},
	}

	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/salt/testuser", nil)
	req.SetPathValue("username", "testuser")

	w := httptest.NewRecorder()
	handler.GetSalt(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response api.SaltResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "salt123", response.PublicSalt)
}

func TestAuthHandler_GetSalt_UserNotFound(t *testing.T) {
	logger := setupTestLogger()

	userStorage := &storage.UserStorageMock{
		GetUserByUsernameFunc: func(ctx context.Context, username string) (*models.User, error) {
			return nil, storage.ErrUserNotFound
		},
	}

	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/salt/nonexistent", nil)
	req.SetPathValue("username", "nonexistent")

	w := httptest.NewRecorder()
	handler.GetSalt(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAuthHandler_GetSalt_EmptyUsername(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &storage.UserStorageMock{}
	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/salt/", nil)
	req.SetPathValue("username", "")

	w := httptest.NewRecorder()
	handler.GetSalt(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_Login_Success(t *testing.T) {
	logger := setupTestLogger()

	users := make(map[string]*models.User)
	users["testuser"] = &models.User{
		ID:          "user123",
		Username:    "testuser",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
	}

	userStorage := &storage.UserStorageMock{
		GetUserByUsernameFunc: func(ctx context.Context, username string) (*models.User, error) {
			if user, ok := users[username]; ok {
				return user, nil
			}
			return nil, storage.ErrUserNotFound
		},
		UpdateLastLoginFunc: func(ctx context.Context, userID string, lastLogin time.Time) error {
			return nil
		},
	}

	tokenStorage := &storage.TokenStorageMock{
		SaveRefreshTokenFunc: func(ctx context.Context, token *models.RefreshToken) error {
			return nil
		},
	}

	jwtConfig := JWTConfig{
		Secret:          []byte("test-secret"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	reqBody := api.LoginRequest{
		Username:    "testuser",
		AuthKeyHash: "hash123",
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.Login(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response api.TokenResponse
	err = json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Greater(t, response.ExpiresIn, int64(0))

	// Verify refresh token was saved
	assert.Len(t, tokenStorage.SaveRefreshTokenCalls(), 1)
	assert.Equal(t, "user123", tokenStorage.SaveRefreshTokenCalls()[0].Token.UserID)
}

func TestAuthHandler_Login_InvalidJSON(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &storage.UserStorageMock{}
	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.Login(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_Login_EmptyFields(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &storage.UserStorageMock{}
	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	tests := []struct {
		name    string
		request api.LoginRequest
	}{
		{
			name: "empty username",
			request: api.LoginRequest{
				Username:    "",
				AuthKeyHash: "hash123",
			},
		},
		{
			name: "empty auth_key_hash",
			request: api.LoginRequest{
				Username:    "testuser",
				AuthKeyHash: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			handler.Login(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestAuthHandler_Login_UserNotFound(t *testing.T) {
	logger := setupTestLogger()

	userStorage := &storage.UserStorageMock{
		GetUserByUsernameFunc: func(ctx context.Context, username string) (*models.User, error) {
			return nil, storage.ErrUserNotFound
		},
	}

	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	reqBody := api.LoginRequest{
		Username:    "nonexistent",
		AuthKeyHash: "hash123",
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.Login(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Login_WrongPassword(t *testing.T) {
	logger := setupTestLogger()

	users := make(map[string]*models.User)
	users["testuser"] = &models.User{
		ID:          "user123",
		Username:    "testuser",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
	}

	userStorage := &storage.UserStorageMock{
		GetUserByUsernameFunc: func(ctx context.Context, username string) (*models.User, error) {
			if user, ok := users[username]; ok {
				return user, nil
			}
			return nil, storage.ErrUserNotFound
		},
	}

	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	reqBody := api.LoginRequest{
		Username:    "testuser",
		AuthKeyHash: "wronghash",
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.Login(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Refresh_Success(t *testing.T) {
	logger := setupTestLogger()

	usersMap := make(map[string]*models.User)
	usersMap["user123"] = &models.User{
		ID:          "user123",
		Username:    "testuser",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
	}

	userStorage := &storage.UserStorageMock{
		GetUserByIDFunc: func(ctx context.Context, userID string) (*models.User, error) {
			if user, ok := usersMap[userID]; ok {
				return user, nil
			}
			return nil, storage.ErrUserNotFound
		},
	}

	oldRefreshToken := "old-refresh-token"
	tokensMap := make(map[string]*models.RefreshToken)
	tokensMap[oldRefreshToken] = &models.RefreshToken{
		Token:     oldRefreshToken,
		UserID:    "user123",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	tokenStorage := &storage.TokenStorageMock{
		GetRefreshTokenFunc: func(ctx context.Context, token string) (*models.RefreshToken, error) {
			if t, ok := tokensMap[token]; ok {
				return t, nil
			}
			return nil, storage.ErrTokenNotFound
		},
		SaveRefreshTokenFunc: func(ctx context.Context, token *models.RefreshToken) error {
			tokensMap[token.Token] = token
			return nil
		},
		DeleteRefreshTokenFunc: func(ctx context.Context, token string) error {
			delete(tokensMap, token)
			return nil
		},
	}

	jwtConfig := JWTConfig{
		Secret:          []byte("test-secret"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+oldRefreshToken)

	w := httptest.NewRecorder()
	handler.Refresh(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response api.TokenResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.NotEqual(t, oldRefreshToken, response.RefreshToken)

	// Verify old token was deleted
	assert.Len(t, tokenStorage.DeleteRefreshTokenCalls(), 1)
	assert.Equal(t, oldRefreshToken, tokenStorage.DeleteRefreshTokenCalls()[0].Token)

	// Verify new token was saved
	assert.Len(t, tokenStorage.SaveRefreshTokenCalls(), 1)
}

func TestAuthHandler_Refresh_EmptyToken(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &storage.UserStorageMock{}
	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer ")

	w := httptest.NewRecorder()
	handler.Refresh(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Refresh_ExpiredToken(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &storage.UserStorageMock{}

	expiredToken := "expired-token"
	tokenStorage := &storage.TokenStorageMock{
		GetRefreshTokenFunc: func(ctx context.Context, token string) (*models.RefreshToken, error) {
			if token == expiredToken {
				return &models.RefreshToken{
					Token:     expiredToken,
					UserID:    "user123",
					ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
					CreatedAt: time.Now().Add(-25 * time.Hour),
				}, nil
			}
			return nil, storage.ErrTokenNotFound
		},
	}

	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)

	w := httptest.NewRecorder()
	handler.Refresh(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Logout_Success(t *testing.T) {
	logger := setupTestLogger()

	userStorage := &storage.UserStorageMock{}

	tokenStorage := &storage.TokenStorageMock{
		DeleteUserTokensFunc: func(ctx context.Context, userID string) (int, error) {
			return 1, nil
		},
	}

	jwtConfig := JWTConfig{
		Secret:          []byte("test-secret"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	// Генерируем валидный access token для пользователя
	accessToken, _, err := GenerateAccessToken(jwtConfig, "user123", "testuser")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	w := httptest.NewRecorder()
	handler.Logout(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)

	// Проверяем, что refresh токены удалены
	assert.Len(t, tokenStorage.DeleteUserTokensCalls(), 1)
	assert.Equal(t, "user123", tokenStorage.DeleteUserTokensCalls()[0].UserID)
}

func TestAuthHandler_Logout_EmptyToken(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &storage.UserStorageMock{}
	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer")

	w := httptest.NewRecorder()
	handler.Logout(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Logout_TokenNotFound(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &storage.UserStorageMock{}
	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)

	w := httptest.NewRecorder()
	handler.Logout(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Register_StorageError(t *testing.T) {
	logger := setupTestLogger()

	userStorage := &storage.UserStorageMock{
		GetUserByUsernameFunc: func(ctx context.Context, username string) (*models.User, error) {
			return nil, storage.ErrUserNotFound
		},
		CreateUserFunc: func(ctx context.Context, user *models.User) error {
			return errors.New("database error")
		},
	}

	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	reqBody := api.RegisterRequest{
		Username:    "testuser",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.Register(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_Login_UpdateLastLoginError(t *testing.T) {
	logger := setupTestLogger()

	users := make(map[string]*models.User)
	users["testuser"] = &models.User{
		ID:          "user123",
		Username:    "testuser",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
	}

	userStorage := &storage.UserStorageMock{
		GetUserByUsernameFunc: func(ctx context.Context, username string) (*models.User, error) {
			if user, ok := users[username]; ok {
				return user, nil
			}
			return nil, storage.ErrUserNotFound
		},
		UpdateLastLoginFunc: func(ctx context.Context, userID string, lastLogin time.Time) error {
			return errors.New("update error")
		},
	}

	tokenStorage := &storage.TokenStorageMock{
		SaveRefreshTokenFunc: func(ctx context.Context, token *models.RefreshToken) error {
			return nil
		},
	}

	jwtConfig := JWTConfig{
		Secret:          []byte("test-secret"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	reqBody := api.LoginRequest{
		Username:    "testuser",
		AuthKeyHash: "hash123",
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.Login(w, req)

	// Should still succeed even if UpdateLastLogin fails
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_Login_SaveTokenError(t *testing.T) {
	logger := setupTestLogger()

	users := make(map[string]*models.User)
	users["testuser"] = &models.User{
		ID:          "user123",
		Username:    "testuser",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
	}

	userStorage := &storage.UserStorageMock{
		GetUserByUsernameFunc: func(ctx context.Context, username string) (*models.User, error) {
			if user, ok := users[username]; ok {
				return user, nil
			}
			return nil, storage.ErrUserNotFound
		},
		UpdateLastLoginFunc: func(ctx context.Context, userID string, lastLogin time.Time) error {
			return nil
		},
	}

	tokenStorage := &storage.TokenStorageMock{
		SaveRefreshTokenFunc: func(ctx context.Context, token *models.RefreshToken) error {
			return errors.New("save error")
		},
	}

	jwtConfig := JWTConfig{
		Secret:          []byte("test-secret"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	reqBody := api.LoginRequest{
		Username:    "testuser",
		AuthKeyHash: "hash123",
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.Login(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_GetSalt_DBError(t *testing.T) {
	logger := setupTestLogger()

	userStorage := &storage.UserStorageMock{
		GetUserByUsernameFunc: func(ctx context.Context, username string) (*models.User, error) {
			return nil, fmt.Errorf("db error")
		},
	}

	handler := NewAuthHandler(logger, userStorage, nil, JWTConfig{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/salt/testuser", nil)
	req.SetPathValue("username", "testuser")

	w := httptest.NewRecorder()
	handler.GetSalt(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_Refresh_SaveRefreshTokenError(t *testing.T) {
	logger := setupTestLogger()

	usersMap := make(map[string]*models.User)
	usersMap["user1"] = &models.User{ID: "user1", Username: "user1"}

	userStorage := &storage.UserStorageMock{
		GetUserByIDFunc: func(ctx context.Context, userID string) (*models.User, error) {
			if user, ok := usersMap[userID]; ok {
				return user, nil
			}
			return nil, storage.ErrUserNotFound
		},
	}

	validToken := "valid_token"
	tokenStorage := &storage.TokenStorageMock{
		GetRefreshTokenFunc: func(ctx context.Context, token string) (*models.RefreshToken, error) {
			if token == validToken {
				return &models.RefreshToken{
					Token:     validToken,
					UserID:    "user1",
					ExpiresAt: time.Now().Add(1 * time.Hour),
					CreatedAt: time.Now(),
				}, nil
			}
			return nil, storage.ErrTokenNotFound
		},
		SaveRefreshTokenFunc: func(ctx context.Context, token *models.RefreshToken) error {
			return fmt.Errorf("save error")
		},
		DeleteRefreshTokenFunc: func(ctx context.Context, token string) error {
			return nil
		},
	}

	jwtConfig := JWTConfig{
		Secret:          []byte("test-secret"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer valid_token")

	w := httptest.NewRecorder()
	handler.Refresh(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_Logout_InvalidFormat(t *testing.T) {
	logger := setupTestLogger()
	handler := NewAuthHandler(logger, nil, nil, JWTConfig{Secret: []byte("test-secret")})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer")

	w := httptest.NewRecorder()
	handler.Logout(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Refresh_GetUserByIDError(t *testing.T) {
	logger := setupTestLogger()

	userStorage := &storage.UserStorageMock{
		GetUserByIDFunc: func(ctx context.Context, userID string) (*models.User, error) {
			return nil, fmt.Errorf("db error")
		},
	}

	validToken := "valid_token"
	tokenStorage := &storage.TokenStorageMock{
		GetRefreshTokenFunc: func(ctx context.Context, token string) (*models.RefreshToken, error) {
			if token == validToken {
				return &models.RefreshToken{
					Token:     validToken,
					UserID:    "user123",
					ExpiresAt: time.Now().Add(1 * time.Hour),
					CreatedAt: time.Now(),
				}, nil
			}
			return nil, storage.ErrTokenNotFound
		},
	}

	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer valid_token")

	w := httptest.NewRecorder()
	handler.Refresh(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_Refresh_DeleteOldTokenError(t *testing.T) {
	logger := setupTestLogger()

	usersMap := make(map[string]*models.User)
	usersMap["user1"] = &models.User{ID: "user1", Username: "user1"}

	userStorage := &storage.UserStorageMock{
		GetUserByIDFunc: func(ctx context.Context, userID string) (*models.User, error) {
			if user, ok := usersMap[userID]; ok {
				return user, nil
			}
			return nil, storage.ErrUserNotFound
		},
	}

	validToken := "valid_token"
	tokenStorage := &storage.TokenStorageMock{
		GetRefreshTokenFunc: func(ctx context.Context, token string) (*models.RefreshToken, error) {
			if token == validToken {
				return &models.RefreshToken{
					Token:     validToken,
					UserID:    "user1",
					ExpiresAt: time.Now().Add(1 * time.Hour),
					CreatedAt: time.Now(),
				}, nil
			}
			return nil, storage.ErrTokenNotFound
		},
		SaveRefreshTokenFunc: func(ctx context.Context, token *models.RefreshToken) error {
			return nil
		},
		DeleteRefreshTokenFunc: func(ctx context.Context, token string) error {
			return fmt.Errorf("delete error")
		},
	}

	jwtConfig := JWTConfig{
		Secret:          []byte("test-secret"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer valid_token")

	w := httptest.NewRecorder()
	handler.Refresh(w, req)

	// Должно успешно завершиться несмотря на ошибку удаления старого токена
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_Refresh_MissingAuthHeader(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &storage.UserStorageMock{}
	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)

	w := httptest.NewRecorder()
	handler.Refresh(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Refresh_InvalidAuthHeaderFormat(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &storage.UserStorageMock{}
	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "InvalidFormat token123")

	w := httptest.NewRecorder()
	handler.Refresh(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Logout_InvalidAccessToken(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &storage.UserStorageMock{}
	tokenStorage := &storage.TokenStorageMock{}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-format")

	w := httptest.NewRecorder()
	handler.Logout(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Logout_DeleteUserTokensError(t *testing.T) {
	logger := setupTestLogger()

	userStorage := &storage.UserStorageMock{}

	tokenStorage := &storage.TokenStorageMock{
		DeleteUserTokensFunc: func(ctx context.Context, userID string) (int, error) {
			return 0, fmt.Errorf("delete error")
		},
	}

	jwtConfig := JWTConfig{
		Secret:          []byte("test-secret"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	// Генерируем валидный access token
	accessToken, _, err := GenerateAccessToken(jwtConfig, "user123", "testuser")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	w := httptest.NewRecorder()
	handler.Logout(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
