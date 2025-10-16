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

// mockUserStorage is a mock implementation of UserStorage for testing
type mockUserStorage struct {
	users           map[string]*models.User // username -> User
	createError     error
	getUserError    error
	updateLastLogin func(ctx context.Context, userID string, loginTime time.Time) error
}

func (m *mockUserStorage) CreateUser(ctx context.Context, user *models.User) error {
	if m.createError != nil {
		return m.createError
	}
	if _, exists := m.users[user.Username]; exists {
		return storage.ErrUserAlreadyExists
	}
	m.users[user.Username] = user
	return nil
}

func (m *mockUserStorage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	if m.getUserError != nil {
		return nil, m.getUserError
	}
	user, ok := m.users[username]
	if !ok {
		return nil, storage.ErrUserNotFound
	}
	return user, nil
}

func (m *mockUserStorage) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	if m.getUserError != nil {
		return nil, m.getUserError
	}
	for _, user := range m.users {
		if user.ID == id {
			return user, nil
		}
	}
	return nil, storage.ErrUserNotFound
}

func (m *mockUserStorage) UpdateUser(ctx context.Context, user *models.User) error {
	return nil
}

func (m *mockUserStorage) DeleteUser(ctx context.Context, id string) error {
	return nil
}

func (m *mockUserStorage) UpdateLastLogin(ctx context.Context, userID string, loginTime time.Time) error {
	if m.updateLastLogin != nil {
		return m.updateLastLogin(ctx, userID, loginTime)
	}
	return nil
}

// mockTokenStorage is a mock implementation of TokenStorage for testing
type mockTokenStorage struct {
	tokens        map[string]*models.RefreshToken // token -> RefreshToken
	saveError     error
	getError      error
	deleteError   error
	savedTokens   []*models.RefreshToken // Track all saved tokens
	deletedTokens []string               // Track deleted tokens
}

func (m *mockTokenStorage) SaveRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	if m.saveError != nil {
		return m.saveError
	}
	m.tokens[token.Token] = token
	m.savedTokens = append(m.savedTokens, token)
	return nil
}

func (m *mockTokenStorage) GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	rt, ok := m.tokens[token]
	if !ok {
		return nil, storage.ErrTokenNotFound
	}
	return rt, nil
}

func (m *mockTokenStorage) GetUserTokens(ctx context.Context, userID string) ([]*models.RefreshToken, error) {
	var result []*models.RefreshToken
	for _, token := range m.tokens {
		if token.UserID == userID {
			result = append(result, token)
		}
	}
	return result, nil
}

func (m *mockTokenStorage) DeleteRefreshToken(ctx context.Context, token string) error {
	if m.deleteError != nil {
		return m.deleteError
	}
	if _, ok := m.tokens[token]; !ok {
		return storage.ErrTokenNotFound
	}
	delete(m.tokens, token)
	m.deletedTokens = append(m.deletedTokens, token)
	return nil
}

func (m *mockTokenStorage) DeleteUserTokens(ctx context.Context, userID string) (int, error) {
	if m.deleteError != nil {
		return 0, m.deleteError
	}
	count := 0
	for token, rt := range m.tokens {
		if rt.UserID == userID {
			delete(m.tokens, token)
			m.deletedTokens = append(m.deletedTokens, token)
			count++
		}
	}
	return count, nil
}

func (m *mockTokenStorage) DeleteExpiredTokens(ctx context.Context) (int, error) {
	return 0, nil
}

func TestAuthHandler_Register_Success(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{
		users: map[string]*models.User{
			"existing": {
				ID:          "user1",
				Username:    "existing",
				AuthKeyHash: "hash1",
				PublicSalt:  "salt1",
			},
		},
	}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{
		users: map[string]*models.User{
			"testuser": {
				ID:          "user1",
				Username:    "testuser",
				AuthKeyHash: "hash123",
				PublicSalt:  "salt123",
			},
		},
	}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{
		users: map[string]*models.User{
			"testuser": {
				ID:          "user123",
				Username:    "testuser",
				AuthKeyHash: "hash123",
				PublicSalt:  "salt123",
			},
		},
	}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	assert.Len(t, tokenStorage.savedTokens, 1)
	assert.Equal(t, "user123", tokenStorage.savedTokens[0].UserID)
}

func TestAuthHandler_Login_InvalidJSON(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{
		users: map[string]*models.User{
			"testuser": {
				ID:          "user123",
				Username:    "testuser",
				AuthKeyHash: "hash123",
				PublicSalt:  "salt123",
			},
		},
	}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{
		users: map[string]*models.User{
			"testuser": {
				ID:          "user123",
				Username:    "testuser",
				AuthKeyHash: "hash123",
				PublicSalt:  "salt123",
			},
		},
	}

	oldRefreshToken := "old-refresh-token"
	tokenStorage := &mockTokenStorage{
		tokens: map[string]*models.RefreshToken{
			oldRefreshToken: {
				Token:     oldRefreshToken,
				UserID:    "user123",
				ExpiresAt: time.Now().Add(24 * time.Hour),
				CreatedAt: time.Now(),
			},
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
	assert.Contains(t, tokenStorage.deletedTokens, oldRefreshToken)

	// Verify new token was saved
	assert.Len(t, tokenStorage.savedTokens, 1)
}

func TestAuthHandler_Refresh_EmptyToken(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	// Если хотим проверить "empty token" в заголовке:
	req.Header.Set("Authorization", "Bearer ")

	w := httptest.NewRecorder()
	handler.Refresh(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Refresh_ExpiredToken(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}

	expiredToken := "expired-token"
	tokenStorage := &mockTokenStorage{
		tokens: map[string]*models.RefreshToken{
			expiredToken: {
				Token:     expiredToken,
				UserID:    "user123",
				ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
				CreatedAt: time.Now().Add(-25 * time.Hour),
			},
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
	userStorage := &mockUserStorage{
		users: map[string]*models.User{
			"testuser": {
				ID:          "user123",
				Username:    "testuser",
				AuthKeyHash: "hash123",
				PublicSalt:  "salt123",
			},
		},
	}

	// Создаем refresh токен
	refreshToken := "valid-refresh-token"

	tokenStorage := &mockTokenStorage{
		tokens: map[string]*models.RefreshToken{
			refreshToken: {
				Token:     refreshToken,
				UserID:    "user123",
				ExpiresAt: time.Now().Add(24 * time.Hour),
				CreatedAt: time.Now(),
			},
		},
		deletedTokens: []string{},
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

	// В заголовок Authorization кладем access token!
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	w := httptest.NewRecorder()
	handler.Logout(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)

	// Проверяем, что refresh токен удален
	assert.Contains(t, tokenStorage.deletedTokens, refreshToken)
}

func TestAuthHandler_Logout_EmptyToken(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)

	w := httptest.NewRecorder()
	handler.Logout(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Register_StorageError(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &mockUserStorage{
		users:       make(map[string]*models.User),
		createError: errors.New("database error"),
	}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{
		users: map[string]*models.User{
			"testuser": {
				ID:          "user123",
				Username:    "testuser",
				AuthKeyHash: "hash123",
				PublicSalt:  "salt123",
			},
		},
		updateLastLogin: func(ctx context.Context, userID string, loginTime time.Time) error {
			return errors.New("update error")
		},
	}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{
		users: map[string]*models.User{
			"testuser": {
				ID:          "user123",
				Username:    "testuser",
				AuthKeyHash: "hash123",
				PublicSalt:  "salt123",
			},
		},
	}
	tokenStorage := &mockTokenStorage{
		tokens:    make(map[string]*models.RefreshToken),
		saveError: errors.New("save error"),
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

	userStorage := &mockUserStorage{
		getUserError: fmt.Errorf("db error"),
		users:        make(map[string]*models.User),
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

	userStorage := &mockUserStorage{
		users: map[string]*models.User{
			"user1": {ID: "user1", Username: "user1"},
		},
	}
	tokenStorage := &mockTokenStorage{
		tokens: map[string]*models.RefreshToken{
			"valid_token": {
				Token:     "valid_token",
				UserID:    "user1",
				ExpiresAt: time.Now().Add(1 * time.Hour),
				CreatedAt: time.Now(),
			},
		},
		saveError: fmt.Errorf("save error"),
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
	handler := NewAuthHandler(logger, nil, nil, JWTConfig{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer") // без токена

	w := httptest.NewRecorder()
	handler.Logout(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Refresh_GetUserByIDError(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &mockUserStorage{
		users:        make(map[string]*models.User),
		getUserError: fmt.Errorf("db error"),
	}
	tokenStorage := &mockTokenStorage{
		tokens: map[string]*models.RefreshToken{
			"valid_token": {
				Token:     "valid_token",
				UserID:    "user123",
				ExpiresAt: time.Now().Add(1 * time.Hour),
				CreatedAt: time.Now(),
			},
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
	userStorage := &mockUserStorage{
		users: map[string]*models.User{
			"user1": {ID: "user1", Username: "user1"},
		},
	}
	tokenStorage := &mockTokenStorage{
		tokens: map[string]*models.RefreshToken{
			"valid_token": {
				Token:     "valid_token",
				UserID:    "user1",
				ExpiresAt: time.Now().Add(1 * time.Hour),
				CreatedAt: time.Now(),
			},
		},
		deleteError: fmt.Errorf("delete error"),
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
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
	jwtConfig := JWTConfig{Secret: []byte("test-secret")}

	handler := NewAuthHandler(logger, userStorage, tokenStorage, jwtConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	// Отсутствует Authorization header

	w := httptest.NewRecorder()
	handler.Refresh(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Refresh_InvalidAuthHeaderFormat(t *testing.T) {
	logger := setupTestLogger()
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{users: make(map[string]*models.User)}
	tokenStorage := &mockTokenStorage{tokens: make(map[string]*models.RefreshToken)}
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
	userStorage := &mockUserStorage{
		users: map[string]*models.User{
			"testuser": {
				ID:          "user123",
				Username:    "testuser",
				AuthKeyHash: "hash123",
				PublicSalt:  "salt123",
			},
		},
	}
	tokenStorage := &mockTokenStorage{
		tokens:      make(map[string]*models.RefreshToken),
		deleteError: fmt.Errorf("delete error"),
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
