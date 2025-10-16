package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/gophkeeper/internal/client/storage"
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
	encryptionKey := make([]byte, 32) // 32 bytes key

	authService := NewAuthService(mockStorage, encryptionKey)

	assert.NotNil(t, authService)
	assert.Equal(t, mockStorage, authService.storage)
	assert.Equal(t, encryptionKey, authService.encryptionKey)
}

func TestNewAuthService_PanicOnInvalidKey(t *testing.T) {
	mockStorage := &mockAuthStorage{}
	invalidKey := make([]byte, 16) // Wrong size

	assert.Panics(t, func() {
		NewAuthService(mockStorage, invalidKey)
	}, "Should panic with invalid key size")
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
			authService := NewAuthService(mockStorage, encryptionKey)

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
	authService := NewAuthService(mockStorage, encryptionKey)

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
	retrievedAuth, err := authService.GetAuth(ctx)
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
	authService := NewAuthService(mockStorage, encryptionKey)

	retrievedAuth, err := authService.GetAuth(context.Background())

	assert.Error(t, err)
	assert.Equal(t, storage.ErrAuthNotFound, err)
	assert.Nil(t, retrievedAuth)
}

func TestAuthService_DeleteAuth(t *testing.T) {
	mockStorage := &mockAuthStorage{}
	encryptionKey := make([]byte, 32)
	authService := NewAuthService(mockStorage, encryptionKey)

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
			encryptionKey := make([]byte, 32)
			authService := NewAuthService(mockStorage, encryptionKey)

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

	authService := NewAuthService(mockStorage, encryptionKey)
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
			retrieved, err := authService.GetAuth(ctx)
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
