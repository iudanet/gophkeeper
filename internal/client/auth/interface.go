package auth

import (
	"context"

	"github.com/iudanet/gophkeeper/internal/client/storage"
)

//go:generate moq -out service_mock.go . Service

// Service defines the main interface for authentication operations
// This service manages both authentication (register/login) and session storage.
// After successful login/register, use SetEncryptionKey to enable storage operations.
type Service interface {
	// Authentication methods (работают без ключа шифрования)

	// Register регистрирует нового пользователя
	// Возвращает результат с ключом шифрования для использования
	Register(ctx context.Context, username, masterPassword string) (*RegisterResult, error)

	// Login выполняет аутентификацию пользователя
	// Возвращает результат с токенами и ключом шифрования
	Login(ctx context.Context, username, masterPassword string) (*LoginResult, error)

	// RefreshToken обновляет access token используя refresh token
	// Автоматически сохраняет новые токены в хранилище
	// Требует установленного ключа шифрования через SetEncryptionKey
	RefreshToken(ctx context.Context) error

	// Session management methods (требуют установленного ключа через SetEncryptionKey)

	// SetEncryptionKey устанавливает ключ шифрования для работы с хранилищем
	// Должен быть вызван после успешного Login/Register
	SetEncryptionKey(key []byte)

	// SaveAuth encrypts and saves authentication data
	// Requires encryption key to be set via SetEncryptionKey
	SaveAuth(ctx context.Context, auth *storage.AuthData) error

	// GetAuthDecryptData retrieves and decrypts authentication data
	// Requires encryption key to be set via SetEncryptionKey
	GetAuthDecryptData(ctx context.Context) (*storage.AuthData, error)

	// GetAuthEncryptData retrieves authentication data without decryption (для получения salt/username)
	GetAuthEncryptData(ctx context.Context) (*storage.AuthData, error)

	// DeleteAuth removes stored authentication data
	DeleteAuth(ctx context.Context) error

	// IsAuthenticated checks if valid authentication exists
	IsAuthenticated(ctx context.Context) (bool, error)

	// Logout выполняет выход из системы
	// Удаляет локальные данные авторизации и опционально уведомляет сервер
	Logout(ctx context.Context) error
}
