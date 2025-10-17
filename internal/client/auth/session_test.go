package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/gophkeeper/internal/client/storage"
	pkgapi "github.com/iudanet/gophkeeper/pkg/api"
)

// mockAuthStorage implements storage.AuthStorage for testing
type mockAuthStorage struct {
	data        *storage.AuthData
	saveErr     error
	getErr      error
	deleteErr   error
	isAuthErr   error
	isAuthValue bool
}

func (m *mockAuthStorage) SaveAuth(ctx context.Context, auth *storage.AuthData) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	// Сохраняем копию данных
	m.data = &storage.AuthData{
		Username:     auth.Username,
		UserID:       auth.UserID,
		NodeID:       auth.NodeID,
		AccessToken:  auth.AccessToken,
		RefreshToken: auth.RefreshToken,
		PublicSalt:   auth.PublicSalt,
		ExpiresAt:    auth.ExpiresAt,
	}
	return nil
}

func (m *mockAuthStorage) GetAuth(ctx context.Context) (*storage.AuthData, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.data == nil {
		return nil, storage.ErrAuthNotFound
	}
	// Возвращаем копию
	return &storage.AuthData{
		Username:     m.data.Username,
		UserID:       m.data.UserID,
		NodeID:       m.data.NodeID,
		AccessToken:  m.data.AccessToken,
		RefreshToken: m.data.RefreshToken,
		PublicSalt:   m.data.PublicSalt,
		ExpiresAt:    m.data.ExpiresAt,
	}, nil
}

func (m *mockAuthStorage) DeleteAuth(ctx context.Context) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.data = nil
	return nil
}

func (m *mockAuthStorage) IsAuthenticated(ctx context.Context) (bool, error) {
	if m.isAuthErr != nil {
		return false, m.isAuthErr
	}
	return m.isAuthValue, nil
}

func TestNewAuthService(t *testing.T) {
	mockStorage := &mockAuthStorage{}

	authService := NewAuthService(nil, mockStorage)

	assert.NotNil(t, authService)
	assert.Equal(t, mockStorage, authService.storage)
}

func TestAuthService_SaveAuth(t *testing.T) {
	tests := []struct {
		auth    *storage.AuthData
		name    string
		wantErr bool
	}{
		{
			name: "successful save",
			auth: &storage.AuthData{
				Username:     "testuser",
				UserID:       "user-123",
				AccessToken:  "plaintext-access-token",
				RefreshToken: "plaintext-refresh-token",
				PublicSalt:   "salt123",
				ExpiresAt:    1234567890,
			},
			wantErr: false,
		},
		{
			name:    "nil auth data",
			auth:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &mockAuthStorage{}
			encryptionKey := make([]byte, 32)
			authService := NewAuthService(nil, mockStorage)
			authService.SetEncryptionKey(encryptionKey)

			err := authService.SaveAuth(context.Background(), tt.auth)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Проверяем, что данные были сохранены
			assert.NotNil(t, mockStorage.data)
			// Проверяем, что plaintext поля сохранились как есть
			assert.Equal(t, tt.auth.Username, mockStorage.data.Username)
			assert.Equal(t, tt.auth.UserID, mockStorage.data.UserID)
			assert.Equal(t, tt.auth.PublicSalt, mockStorage.data.PublicSalt)
			assert.Equal(t, tt.auth.ExpiresAt, mockStorage.data.ExpiresAt)

			// Проверяем, что токены были зашифрованы (не равны plaintext)
			assert.NotEqual(t, tt.auth.AccessToken, mockStorage.data.AccessToken)
			assert.NotEqual(t, tt.auth.RefreshToken, mockStorage.data.RefreshToken)
		})
	}
}

func TestAuthService_GetAuth(t *testing.T) {
	mockStorage := &mockAuthStorage{}
	encryptionKey := make([]byte, 32)
	authService := NewAuthService(nil, mockStorage)
	authService.SetEncryptionKey(encryptionKey)

	ctx := context.Background()

	// Сначала сохраняем данные
	originalAuth := &storage.AuthData{
		Username:     "testuser",
		UserID:       "user-123",
		AccessToken:  "plaintext-access-token",
		RefreshToken: "plaintext-refresh-token",
		PublicSalt:   "salt123",
		ExpiresAt:    1234567890,
	}

	err := authService.SaveAuth(ctx, originalAuth)
	require.NoError(t, err)

	// Теперь получаем данные обратно
	retrievedAuth, err := authService.GetAuthDecryptData(ctx)
	require.NoError(t, err)
	require.NotNil(t, retrievedAuth)

	// Проверяем, что все поля совпадают с оригиналом
	assert.Equal(t, originalAuth.Username, retrievedAuth.Username)
	assert.Equal(t, originalAuth.UserID, retrievedAuth.UserID)
	assert.Equal(t, originalAuth.PublicSalt, retrievedAuth.PublicSalt)
	assert.Equal(t, originalAuth.ExpiresAt, retrievedAuth.ExpiresAt)

	// Проверяем, что токены были расшифрованы корректно
	assert.Equal(t, originalAuth.AccessToken, retrievedAuth.AccessToken)
	assert.Equal(t, originalAuth.RefreshToken, retrievedAuth.RefreshToken)
}

func TestAuthService_GetAuth_NotFound(t *testing.T) {
	mockStorage := &mockAuthStorage{}
	encryptionKey := make([]byte, 32)
	authService := NewAuthService(nil, mockStorage)
	authService.SetEncryptionKey(encryptionKey)

	retrievedAuth, err := authService.GetAuthDecryptData(context.Background())

	assert.Error(t, err)
	assert.Equal(t, storage.ErrAuthNotFound, err)
	assert.Nil(t, retrievedAuth)
}

func TestAuthService_DeleteAuth(t *testing.T) {
	mockStorage := &mockAuthStorage{}
	encryptionKey := make([]byte, 32)
	authService := NewAuthService(nil, mockStorage)
	authService.SetEncryptionKey(encryptionKey)

	ctx := context.Background()

	// Сначала сохраняем данные
	auth := &storage.AuthData{
		Username:     "testuser",
		AccessToken:  "token",
		RefreshToken: "refresh",
		PublicSalt:   "salt",
		ExpiresAt:    1234567890,
	}

	err := authService.SaveAuth(ctx, auth)
	require.NoError(t, err)

	// Удаляем
	err = authService.DeleteAuth(ctx)
	require.NoError(t, err)

	// Проверяем, что данных больше нет
	assert.Nil(t, mockStorage.data)
}

func TestAuthService_IsAuthenticated(t *testing.T) {
	tests := []struct {
		isAuthErr   error
		name        string
		isAuthValue bool
		want        bool
		wantErr     bool
	}{
		{
			name:        "authenticated",
			isAuthValue: true,
			isAuthErr:   nil,
			want:        true,
			wantErr:     false,
		},
		{
			name:        "not authenticated",
			isAuthValue: false,
			isAuthErr:   nil,
			want:        false,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &mockAuthStorage{
				isAuthValue: tt.isAuthValue,
				isAuthErr:   tt.isAuthErr,
			}
			authService := NewAuthService(nil, mockStorage)

			got, err := authService.IsAuthenticated(context.Background())

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthService_EncryptionDecryption_RoundTrip(t *testing.T) {
	// Тест проверяет полный цикл шифрования-дешифрования
	mockStorage := &mockAuthStorage{}
	encryptionKey := make([]byte, 32)
	// Заполняем ключ тестовыми данными
	for i := range encryptionKey {
		encryptionKey[i] = byte(i)
	}

	authService := NewAuthService(nil, mockStorage)
	authService.SetEncryptionKey(encryptionKey)
	ctx := context.Background()

	// Тестовые данные с различными символами
	testCases := []struct {
		name         string
		accessToken  string
		refreshToken string
	}{
		{
			name:         "simple tokens",
			accessToken:  "simple-access-token",
			refreshToken: "simple-refresh-token",
		},
		{
			name:         "complex JWT tokens",
			accessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			refreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicmVmcmVzaCI6dHJ1ZX0.abc123",
		},
		{
			name:         "short tokens",
			accessToken:  "a",
			refreshToken: "b",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			original := &storage.AuthData{
				Username:     "testuser",
				UserID:       "user-id-123",
				AccessToken:  tc.accessToken,
				RefreshToken: tc.refreshToken,
				PublicSalt:   "base64-salt",
				ExpiresAt:    1234567890,
			}

			// Сохраняем
			err := authService.SaveAuth(ctx, original)
			require.NoError(t, err)

			// Получаем обратно
			retrieved, err := authService.GetAuthDecryptData(ctx)
			require.NoError(t, err)

			// Проверяем полное совпадение
			assert.Equal(t, original.Username, retrieved.Username)
			assert.Equal(t, original.UserID, retrieved.UserID)
			assert.Equal(t, original.AccessToken, retrieved.AccessToken)
			assert.Equal(t, original.RefreshToken, retrieved.RefreshToken)
			assert.Equal(t, original.PublicSalt, retrieved.PublicSalt)
			assert.Equal(t, original.ExpiresAt, retrieved.ExpiresAt)
		})
	}
}

// mockAPIClient implements APIClient interface for testing
type mockAPIClient struct {
	refreshResp *pkgapi.TokenResponse
	refreshErr  error
}

func (m *mockAPIClient) Register(ctx context.Context, req pkgapi.RegisterRequest) (*pkgapi.RegisterResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAPIClient) GetSalt(ctx context.Context, username string) (*pkgapi.SaltResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAPIClient) Login(ctx context.Context, req pkgapi.LoginRequest) (*pkgapi.TokenResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAPIClient) Refresh(ctx context.Context, refreshToken string) (*pkgapi.TokenResponse, error) {
	if m.refreshErr != nil {
		return nil, m.refreshErr
	}
	return m.refreshResp, nil
}

func (m *mockAPIClient) Logout(ctx context.Context, accessToken string) error {
	return fmt.Errorf("not implemented")
}

func TestAuthService_RefreshToken_Success(t *testing.T) {
	ctx := context.Background()

	// Setup mock storage with existing auth data
	mockStorage := &mockAuthStorage{}
	encryptionKey := make([]byte, 32)

	// Создаём mock API client с успешным ответом
	mockAPI := &mockAPIClient{
		refreshResp: &pkgapi.TokenResponse{
			UserID:       "user-123",
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			ExpiresIn:    900, // 15 минут
		},
	}

	authService := NewAuthService(mockAPI, mockStorage)
	authService.SetEncryptionKey(encryptionKey)

	// Сохраняем начальные auth данные
	initialAuth := &storage.AuthData{
		Username:     "testuser",
		UserID:       "user-123",
		NodeID:       "node-456",
		AccessToken:  "old-access-token",
		RefreshToken: "old-refresh-token",
		PublicSalt:   "salt123",
		ExpiresAt:    time.Now().Add(-10 * time.Minute).Unix(), // истёкший токен
	}

	err := authService.SaveAuth(ctx, initialAuth)
	require.NoError(t, err)

	// Вызываем RefreshToken
	err = authService.RefreshToken(ctx)
	require.NoError(t, err)

	// Проверяем, что токены были обновлены
	updatedAuth, err := authService.GetAuthDecryptData(ctx)
	require.NoError(t, err)

	assert.Equal(t, "new-access-token", updatedAuth.AccessToken)
	assert.Equal(t, "new-refresh-token", updatedAuth.RefreshToken)
	assert.Greater(t, updatedAuth.ExpiresAt, time.Now().Unix())

	// Проверяем, что другие поля остались без изменений
	assert.Equal(t, initialAuth.Username, updatedAuth.Username)
	assert.Equal(t, initialAuth.UserID, updatedAuth.UserID)
	assert.Equal(t, initialAuth.NodeID, updatedAuth.NodeID)
	assert.Equal(t, initialAuth.PublicSalt, updatedAuth.PublicSalt)
}

func TestAuthService_RefreshToken_NoEncryptionKey(t *testing.T) {
	ctx := context.Background()

	mockStorage := &mockAuthStorage{}
	mockAPI := &mockAPIClient{}

	authService := NewAuthService(mockAPI, mockStorage)
	// НЕ устанавливаем encryption key

	err := authService.RefreshToken(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encryption key not set")
}

func TestAuthService_RefreshToken_NoAuthData(t *testing.T) {
	ctx := context.Background()

	// Storage без данных
	mockStorage := &mockAuthStorage{}
	encryptionKey := make([]byte, 32)
	mockAPI := &mockAPIClient{}

	authService := NewAuthService(mockAPI, mockStorage)
	authService.SetEncryptionKey(encryptionKey)

	err := authService.RefreshToken(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get auth data")
}

func TestAuthService_RefreshToken_APIError(t *testing.T) {
	ctx := context.Background()

	mockStorage := &mockAuthStorage{}
	encryptionKey := make([]byte, 32)

	// Mock API с ошибкой
	mockAPI := &mockAPIClient{
		refreshErr: fmt.Errorf("server error: invalid refresh token"),
	}

	authService := NewAuthService(mockAPI, mockStorage)
	authService.SetEncryptionKey(encryptionKey)

	// Сохраняем начальные данные
	initialAuth := &storage.AuthData{
		Username:     "testuser",
		UserID:       "user-123",
		AccessToken:  "old-access-token",
		RefreshToken: "old-refresh-token",
		PublicSalt:   "salt123",
		ExpiresAt:    time.Now().Unix(),
	}

	err := authService.SaveAuth(ctx, initialAuth)
	require.NoError(t, err)

	// Вызываем RefreshToken - должна быть ошибка
	err = authService.RefreshToken(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to refresh token")
	assert.Contains(t, err.Error(), "invalid refresh token")
}
