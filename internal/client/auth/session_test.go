package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/gophkeeper/internal/client/api"
	"github.com/iudanet/gophkeeper/internal/client/storage"
	pkgapi "github.com/iudanet/gophkeeper/pkg/api"
)

func TestNewAuthService(t *testing.T) {
	mockStorage := &storage.AuthStorageMock{}

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
			// Переменная для хранения сохранённых данных внутри мока
			var savedData *storage.AuthData

			mockStorage := &storage.AuthStorageMock{
				SaveAuthFunc: func(ctx context.Context, auth *storage.AuthData) error {
					savedData = auth
					return nil
				},
				GetAuthFunc: func(ctx context.Context) (*storage.AuthData, error) {
					if savedData == nil {
						return nil, storage.ErrAuthNotFound
					}
					return savedData, nil
				},
			}

			encryptionKey := make([]byte, 32)
			authService := NewAuthService(nil, mockStorage)
			authService.SetEncryptionKey(encryptionKey)

			err := authService.SaveAuth(context.Background(), tt.auth)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, savedData)

			// Проверяем, что plaintext поля сохранились корректно
			assert.Equal(t, tt.auth.Username, savedData.Username)
			assert.Equal(t, tt.auth.UserID, savedData.UserID)
			assert.Equal(t, tt.auth.PublicSalt, savedData.PublicSalt)
			assert.Equal(t, tt.auth.ExpiresAt, savedData.ExpiresAt)

			// Проверяем, что токены были зашифрованы (не равны исходным plaintext)
			assert.NotEqual(t, tt.auth.AccessToken, savedData.AccessToken)
			assert.NotEqual(t, tt.auth.RefreshToken, savedData.RefreshToken)
		})
	}
}

func TestAuthService_GetAuth(t *testing.T) {
	var savedData *storage.AuthData

	mockStorage := &storage.AuthStorageMock{
		SaveAuthFunc: func(ctx context.Context, auth *storage.AuthData) error {
			savedData = auth
			return nil
		},
		GetAuthFunc: func(ctx context.Context) (*storage.AuthData, error) {
			if savedData == nil {
				return nil, storage.ErrAuthNotFound
			}
			return savedData, nil
		},
	}

	encryptionKey := make([]byte, 32)
	authService := NewAuthService(nil, mockStorage)
	authService.SetEncryptionKey(encryptionKey)

	ctx := context.Background()

	// Сначала сохраняем данные (SaveAuth вызывает SaveAuthFunc в мокe)
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

	// Теперь получаем данные обратно (GetAuthDecryptData вызывает GetAuthFunc мока)
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
	mockStorage := &storage.AuthStorageMock{
		GetAuthFunc: func(ctx context.Context) (*storage.AuthData, error) {
			return nil, storage.ErrAuthNotFound
		},
	}

	encryptionKey := make([]byte, 32)
	authService := NewAuthService(nil, mockStorage)
	authService.SetEncryptionKey(encryptionKey)

	retrievedAuth, err := authService.GetAuthDecryptData(context.Background())

	assert.Error(t, err)
	assert.Equal(t, storage.ErrAuthNotFound, err)
	assert.Nil(t, retrievedAuth)
}
func TestAuthService_DeleteAuth(t *testing.T) {
	// Переменная для имитации сохранённого состояния
	var storedData *storage.AuthData

	mockStorage := &storage.AuthStorageMock{
		SaveAuthFunc: func(ctx context.Context, auth *storage.AuthData) error {
			storedData = auth
			return nil
		},
		GetAuthFunc: func(ctx context.Context) (*storage.AuthData, error) {
			if storedData == nil {
				return nil, storage.ErrAuthNotFound
			}
			return storedData, nil
		},
		DeleteAuthFunc: func(ctx context.Context) error {
			storedData = nil
			return nil
		},
	}

	encryptionKey := make([]byte, 32)
	authService := NewAuthService(nil, mockStorage)
	authService.SetEncryptionKey(encryptionKey)
	ctx := context.Background()

	// Сохраняем auth данные перед удалением
	auth := &storage.AuthData{
		Username:     "testuser",
		AccessToken:  "token",
		RefreshToken: "refresh",
		PublicSalt:   "salt",
		ExpiresAt:    1234567890,
	}

	err := authService.SaveAuth(ctx, auth)
	require.NoError(t, err)

	// Убеждаемся, что данные сохранены
	require.NotNil(t, storedData)

	// Вызываем DeleteAuth
	err = authService.DeleteAuth(ctx)
	require.NoError(t, err)

	// Проверяем, что данные были удалены
	assert.Nil(t, storedData)
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
		{
			name:        "error from storage",
			isAuthValue: false,
			isAuthErr:   fmt.Errorf("storage error"),
			want:        false,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &storage.AuthStorageMock{
				IsAuthenticatedFunc: func(ctx context.Context) (bool, error) {
					return tt.isAuthValue, tt.isAuthErr
				},
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
	// Переменная для хранения состояния auth данных внутри мока
	var storedData *storage.AuthData

	mockStorage := &storage.AuthStorageMock{
		SaveAuthFunc: func(ctx context.Context, auth *storage.AuthData) error {
			storedData = auth
			return nil
		},
		GetAuthFunc: func(ctx context.Context) (*storage.AuthData, error) {
			if storedData == nil {
				return nil, storage.ErrAuthNotFound
			}
			return storedData, nil
		},
	}

	encryptionKey := make([]byte, 32)
	for i := range encryptionKey {
		encryptionKey[i] = byte(i)
	}

	authService := NewAuthService(nil, mockStorage)
	authService.SetEncryptionKey(encryptionKey)

	ctx := context.Background()

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

			// Сохраняем данные (с шифрованием внутри SaveAuthFunc)
			err := authService.SaveAuth(ctx, original)
			require.NoError(t, err)

			// Получаем данные обратно, расшифровываем
			retrieved, err := authService.GetAuthDecryptData(ctx)
			require.NoError(t, err)
			require.NotNil(t, retrieved)

			// Проверяем, что данные совпадают с оригиналом
			assert.Equal(t, original.Username, retrieved.Username)
			assert.Equal(t, original.UserID, retrieved.UserID)
			assert.Equal(t, original.AccessToken, retrieved.AccessToken)
			assert.Equal(t, original.RefreshToken, retrieved.RefreshToken)
			assert.Equal(t, original.PublicSalt, retrieved.PublicSalt)
			assert.Equal(t, original.ExpiresAt, retrieved.ExpiresAt)
		})
	}
}

func TestAuthService_RefreshToken_Success(t *testing.T) {
	ctx := context.Background()

	var savedData *storage.AuthData

	mockStorage := &storage.AuthStorageMock{
		SaveAuthFunc: func(ctx context.Context, auth *storage.AuthData) error {
			savedData = auth
			return nil
		},
		GetAuthFunc: func(ctx context.Context) (*storage.AuthData, error) {
			if savedData == nil {
				return nil, storage.ErrAuthNotFound
			}
			return savedData, nil
		},
	}

	// Создаём mock API client с успешным ответом
	mockAPI := &api.ClientAPIMock{
		RefreshFunc: func(ctx context.Context, refreshToken string) (*pkgapi.TokenResponse, error) {
			return &pkgapi.TokenResponse{
				UserID:       "user-123",
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
				ExpiresIn:    900, // 15 минут
			}, nil
		},
	}

	encryptionKey := make([]byte, 32)
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
	require.NotNil(t, updatedAuth)

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

	mockStorage := &storage.AuthStorageMock{}
	mockAPI := &api.ClientAPIMock{}

	authService := NewAuthService(mockAPI, mockStorage)
	// НЕ устанавливаем encryption key

	err := authService.RefreshToken(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encryption key not set")
}

func TestAuthService_RefreshToken_NoAuthData(t *testing.T) {
	ctx := context.Background()

	mockStorage := &storage.AuthStorageMock{
		GetAuthFunc: func(ctx context.Context) (*storage.AuthData, error) {
			return nil, storage.ErrAuthNotFound
		},
	}

	encryptionKey := make([]byte, 32)
	mockAPI := &api.ClientAPIMock{}

	authService := NewAuthService(mockAPI, mockStorage)
	authService.SetEncryptionKey(encryptionKey)

	err := authService.RefreshToken(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get auth data")
}

func TestAuthService_RefreshToken_APIError(t *testing.T) {
	ctx := context.Background()

	var savedData *storage.AuthData

	mockStorage := &storage.AuthStorageMock{
		SaveAuthFunc: func(ctx context.Context, auth *storage.AuthData) error {
			savedData = auth
			return nil
		},
		GetAuthFunc: func(ctx context.Context) (*storage.AuthData, error) {
			if savedData == nil {
				return nil, storage.ErrAuthNotFound
			}
			return savedData, nil
		},
	}

	encryptionKey := make([]byte, 32)

	// Mock API с ошибкой
	mockAPI := &api.ClientAPIMock{
		RefreshFunc: func(ctx context.Context, refreshToken string) (*pkgapi.TokenResponse, error) {
			return nil, fmt.Errorf("server error: invalid refresh token")
		},
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

func TestAuthService_Register_Success(t *testing.T) {
	ctx := context.Background()

	mockAPI := &api.ClientAPIMock{
		RegisterFunc: func(ctx context.Context, req pkgapi.RegisterRequest) (*pkgapi.RegisterResponse, error) {
			assert.Equal(t, "testuser", req.Username)
			assert.NotEmpty(t, req.AuthKeyHash)
			assert.NotEmpty(t, req.PublicSalt)

			return &pkgapi.RegisterResponse{
				UserID:  "user-123",
				Message: "Success",
			}, nil
		},
	}

	mockStorage := &storage.AuthStorageMock{}
	authService := NewAuthService(mockAPI, mockStorage)

	result, err := authService.Register(ctx, "testuser", "MySecurePass123!")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "user-123", result.UserID)
	assert.Equal(t, "testuser", result.Username)
	assert.NotEmpty(t, result.NodeID)
	assert.NotEmpty(t, result.PublicSalt)
	assert.NotEmpty(t, result.EncryptionKey)
	assert.Len(t, result.EncryptionKey, 32)
}

func TestAuthService_Register_InvalidUsername(t *testing.T) {
	authService := NewAuthService(nil, nil)

	tests := []struct {
		name     string
		username string
	}{
		{"empty username", ""},
		{"too short", "ab"},
		{"invalid chars", "user@name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := authService.Register(context.Background(), tt.username, "MySecurePass123!")

			require.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "invalid username")
		})
	}
}

func TestAuthService_Register_InvalidPassword(t *testing.T) {
	authService := NewAuthService(nil, nil)

	tests := []struct {
		name     string
		password string
	}{
		{"empty password", ""},
		{"too short", "Pass1"},
		{"no digits", "Password"},
		{"no uppercase", "password1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := authService.Register(context.Background(), "testuser", tt.password)

			require.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "invalid password")
		})
	}
}

func TestAuthService_Register_APIError(t *testing.T) {
	mockAPI := &api.ClientAPIMock{
		RegisterFunc: func(ctx context.Context, req pkgapi.RegisterRequest) (*pkgapi.RegisterResponse, error) {
			return nil, fmt.Errorf("server error: user already exists")
		},
	}

	authService := NewAuthService(mockAPI, nil)

	result, err := authService.Register(context.Background(), "testuser", "MySecurePass123!")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "registration failed")
}

func TestAuthService_Login_Success(t *testing.T) {
	ctx := context.Background()

	mockAPI := &api.ClientAPIMock{
		GetSaltFunc: func(ctx context.Context, username string) (*pkgapi.SaltResponse, error) {
			return &pkgapi.SaltResponse{
				PublicSalt: "D0azeJBxWs3Lepqo/0SwDyNbNRlSwKvoDBWcErMV6ks=", // base64
			}, nil
		},
		LoginFunc: func(ctx context.Context, req pkgapi.LoginRequest) (*pkgapi.TokenResponse, error) {
			assert.Equal(t, "testuser", req.Username)
			assert.NotEmpty(t, req.AuthKeyHash)

			return &pkgapi.TokenResponse{
				UserID:       "user-123",
				AccessToken:  "access-token",
				RefreshToken: "refresh-token",
				ExpiresIn:    900,
			}, nil
		},
	}

	mockStorage := &storage.AuthStorageMock{
		GetAuthFunc: func(ctx context.Context) (*storage.AuthData, error) {
			return nil, storage.ErrAuthNotFound // первый логин
		},
	}

	authService := NewAuthService(mockAPI, mockStorage)

	result, err := authService.Login(ctx, "testuser", "MySecurePass123!")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "user-123", result.UserID)
	assert.Equal(t, "access-token", result.AccessToken)
	assert.Equal(t, "refresh-token", result.RefreshToken)
	assert.Equal(t, "testuser", result.Username)
	assert.NotEmpty(t, result.NodeID)
	assert.NotEmpty(t, result.PublicSalt)
	assert.NotEmpty(t, result.EncryptionKey)
	assert.Equal(t, int64(900), result.ExpiresIn)
}

func TestAuthService_Login_InvalidCredentials(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
	}{
		{"invalid username", "ab", "MySecurePass123!"},
		{"invalid password", "testuser", "short"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService := NewAuthService(nil, nil)

			result, err := authService.Login(context.Background(), tt.username, tt.password)

			require.Error(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestAuthService_Login_GetSaltError(t *testing.T) {
	mockAPI := &api.ClientAPIMock{
		GetSaltFunc: func(ctx context.Context, username string) (*pkgapi.SaltResponse, error) {
			return nil, fmt.Errorf("user not found")
		},
	}

	authService := NewAuthService(mockAPI, nil)

	result, err := authService.Login(context.Background(), "testuser", "MySecurePass123!")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to get salt")
}

func TestAuthService_Login_LoginAPIError(t *testing.T) {
	mockAPI := &api.ClientAPIMock{
		GetSaltFunc: func(ctx context.Context, username string) (*pkgapi.SaltResponse, error) {
			return &pkgapi.SaltResponse{PublicSalt: "D0azeJBxWs3Lepqo/0SwDyNbNRlSwKvoDBWcErMV6ks="}, nil
		},
		LoginFunc: func(ctx context.Context, req pkgapi.LoginRequest) (*pkgapi.TokenResponse, error) {
			return nil, fmt.Errorf("invalid credentials")
		},
	}

	mockStorage := &storage.AuthStorageMock{
		GetAuthFunc: func(ctx context.Context) (*storage.AuthData, error) {
			return nil, storage.ErrAuthNotFound
		},
	}

	authService := NewAuthService(mockAPI, mockStorage)

	result, err := authService.Login(context.Background(), "testuser", "WrongPassword12!")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "login failed")
}

func TestAuthService_Logout_Success(t *testing.T) {
	ctx := context.Background()

	var savedData *storage.AuthData
	deleteCalled := false

	mockStorage := &storage.AuthStorageMock{
		SaveAuthFunc: func(ctx context.Context, auth *storage.AuthData) error {
			savedData = auth
			return nil
		},
		GetAuthFunc: func(ctx context.Context) (*storage.AuthData, error) {
			if savedData == nil {
				return nil, storage.ErrAuthNotFound
			}
			return savedData, nil
		},
		DeleteAuthFunc: func(ctx context.Context) error {
			deleteCalled = true
			savedData = nil
			return nil
		},
	}

	logoutCalled := false
	mockAPI := &api.ClientAPIMock{
		LogoutFunc: func(ctx context.Context, accessToken string) error {
			logoutCalled = true
			assert.Equal(t, "access-token", accessToken)
			return nil
		},
	}

	encryptionKey := make([]byte, 32)
	authService := NewAuthService(mockAPI, mockStorage)
	authService.SetEncryptionKey(encryptionKey)

	// Сохраняем auth data
	auth := &storage.AuthData{
		Username:     "testuser",
		UserID:       "user-123",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		PublicSalt:   "salt",
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	}

	err := authService.SaveAuth(ctx, auth)
	require.NoError(t, err)

	// Вызываем Logout
	err = authService.Logout(ctx)

	require.NoError(t, err)
	assert.True(t, logoutCalled, "Logout API должен быть вызван")
	assert.True(t, deleteCalled, "DeleteAuth должен быть вызван")
	assert.Nil(t, savedData, "Auth data должны быть удалены")
	assert.Nil(t, authService.encryptionKey, "Encryption key должен быть очищен")
}

func TestAuthService_Logout_WithoutEncryptionKey(t *testing.T) {
	deleteCalled := false

	mockStorage := &storage.AuthStorageMock{
		DeleteAuthFunc: func(ctx context.Context) error {
			deleteCalled = true
			return nil
		},
	}

	authService := NewAuthService(nil, mockStorage)
	// НЕ устанавливаем encryption key

	err := authService.Logout(context.Background())

	require.NoError(t, err)
	assert.True(t, deleteCalled, "DeleteAuth должен быть вызван даже без ключа")
}

func TestAuthService_Logout_DeleteError(t *testing.T) {
	mockStorage := &storage.AuthStorageMock{
		DeleteAuthFunc: func(ctx context.Context) error {
			return fmt.Errorf("delete error")
		},
	}

	authService := NewAuthService(nil, mockStorage)

	err := authService.Logout(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete local auth data")
}

func TestAuthService_GetAuthEncryptData_Success(t *testing.T) {
	mockAuth := &storage.AuthData{
		Username:   "testuser",
		PublicSalt: "salt",
	}

	mockStorage := &storage.AuthStorageMock{
		GetAuthFunc: func(ctx context.Context) (*storage.AuthData, error) {
			return mockAuth, nil
		},
	}

	authService := NewAuthService(nil, mockStorage)

	result, err := authService.GetAuthEncryptData(context.Background())

	require.NoError(t, err)
	assert.Equal(t, mockAuth, result)
}
