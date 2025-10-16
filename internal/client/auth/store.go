package auth

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/crypto"
)

// AuthService implements AuthStore interface and provides encryption layer
// between business logic and storage. It encrypts tokens before saving
// and decrypts them when retrieving.
type AuthService struct {
	storage storage.AuthStorage
}

// Compile-time check that AuthService implements AuthStore
var _ AuthStore = (*AuthService)(nil)

// NewAuthService creates a new AuthService with encryption layer
// encryptionKey must be exactly 32 bytes (derived from master password)
func NewAuthService(storage storage.AuthStorage) *AuthService {
	return &AuthService{
		storage: storage,
	}
}

// SaveAuth сохраняет незашифрованные auth данные,
// сервис сам зашифрует токены и передаст в хранилище
func (s *AuthService) SaveAuth(ctx context.Context, auth *storage.AuthData, encryptionKey []byte) error {
	if auth == nil {
		return fmt.Errorf("auth data is nil")
	}

	// Шифруем токены
	encryptedAccessToken, err := crypto.Encrypt([]byte(auth.AccessToken), encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %w", err)
	}

	encryptedRefreshToken, err := crypto.Encrypt([]byte(auth.RefreshToken), encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt refresh token: %w", err)
	}

	// Кодируем шифрованные токены в base64
	authCopy := *auth // копируем структуру, чтобы не менять входящую
	authCopy.AccessToken = base64.StdEncoding.EncodeToString(encryptedAccessToken)
	authCopy.RefreshToken = base64.StdEncoding.EncodeToString(encryptedRefreshToken)
	authCopy.ExpiresAt = auth.ExpiresAt

	// Сохраняем в storage (уже с зашифрованными токенами)
	return s.storage.SaveAuth(ctx, &authCopy)
}

// GetAuthDecryptData загружает данные из storage и расшифровывает токены
func (s *AuthService) GetAuthDecryptData(ctx context.Context, encryptionKey []byte) (*storage.AuthData, error) {
	storedAuth, err := s.storage.GetAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Декодируем base64 из хранилища
	encryptedAccessTokenBytes, err := base64.StdEncoding.DecodeString(storedAuth.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode access token: %w", err)
	}
	encryptedRefreshTokenBytes, err := base64.StdEncoding.DecodeString(storedAuth.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode refresh token: %w", err)
	}

	// Дешифруем
	accessTokenBytes, err := crypto.Decrypt(encryptedAccessTokenBytes, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt access token: %w", err)
	}
	refreshTokenBytes, err := crypto.Decrypt(encryptedRefreshTokenBytes, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
	}

	// Копируем все в новую структуру, возвращаем с расшифрованными токенами
	auth := *storedAuth
	auth.AccessToken = string(accessTokenBytes)
	auth.RefreshToken = string(refreshTokenBytes)
	auth.ExpiresAt = storedAuth.ExpiresAt

	return &auth, nil
}

// GetAuthEncryptData загружает данные из storage и расшифровывает токены
func (s *AuthService) GetAuthEncryptData(ctx context.Context) (*storage.AuthData, error) {
	storedAuth, err := s.storage.GetAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Копируем все в новую структуру, возвращаем с расшифрованными токенами
	auth := *storedAuth

	return &auth, nil
}

// DeleteAuth удаляет данные
func (s *AuthService) DeleteAuth(ctx context.Context) error {
	return s.storage.DeleteAuth(ctx)
}

// IsAuthenticated проверяет валидность сохраненных данных по сроку действия токена
func (s *AuthService) IsAuthenticated(ctx context.Context) (bool, error) {
	return s.storage.IsAuthenticated(ctx)

}
