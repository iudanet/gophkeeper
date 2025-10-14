package auth

import (
	"context"
	"fmt"

	"github.com/iudanet/gophkeeper/internal/client/api"
	"github.com/iudanet/gophkeeper/internal/crypto"
	"github.com/iudanet/gophkeeper/internal/validation"
	pkgapi "github.com/iudanet/gophkeeper/pkg/api"
)

// Service предоставляет функции авторизации
type Service struct {
	apiClient *api.Client
}

// NewService создает новый сервис авторизации
func NewService(apiClient *api.Client) *Service {
	return &Service{
		apiClient: apiClient,
	}
}

// RegisterResult содержит результат регистрации
type RegisterResult struct {
	UserID         string // UUID пользователя
	Username       string // username
	PublicSalt     string // public salt (base64)
	EncryptionKey  []byte // ключ шифрования (НЕ сохраняется!)
}

// Register регистрирует нового пользователя
// Возвращает результат с ключом шифрования для использования
func (s *Service) Register(ctx context.Context, username, masterPassword string) (*RegisterResult, error) {
	// Валидация входных данных
	if err := validation.ValidateUsername(username); err != nil {
		return nil, fmt.Errorf("invalid username: %w", err)
	}
	if err := validation.ValidatePassword(masterPassword); err != nil {
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	// 1. Генерируем публичную соль
	publicSaltBase64, err := crypto.GenerateSaltBase64()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// 2. Деривируем ключи из master password
	keys, err := crypto.DeriveKeysFromBase64Salt(masterPassword, username, publicSaltBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keys: %w", err)
	}

	// 3. Хешируем auth_key для отправки на сервер
	authKeyHash, err := crypto.HashAuthKey(keys.AuthKey)
	if err != nil {
		return nil, fmt.Errorf("failed to hash auth key: %w", err)
	}

	// 4. Отправляем запрос на регистрацию
	req := pkgapi.RegisterRequest{
		Username:    username,
		AuthKeyHash: authKeyHash,
		PublicSalt:  publicSaltBase64,
	}

	resp, err := s.apiClient.Register(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	// 5. Возвращаем результат
	return &RegisterResult{
		UserID:        resp.UserID,
		Username:      username,
		PublicSalt:    publicSaltBase64,
		EncryptionKey: keys.EncryptionKey,
	}, nil
}

// LoginResult содержит результат авторизации
type LoginResult struct {
	AccessToken    string // JWT access token
	RefreshToken   string // refresh token
	ExpiresIn      int64  // время жизни access token в секундах
	Username       string // username
	PublicSalt     string // public salt (base64)
	EncryptionKey  []byte // ключ шифрования (НЕ сохраняется!)
}

// Login выполняет аутентификацию пользователя
// Возвращает результат с токенами и ключом шифрования
func (s *Service) Login(ctx context.Context, username, masterPassword string) (*LoginResult, error) {
	// Валидация username
	if err := validation.ValidateUsername(username); err != nil {
		return nil, fmt.Errorf("invalid username: %w", err)
	}
	if err := validation.ValidatePassword(masterPassword); err != nil {
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	// 1. Получаем public_salt с сервера
	saltResp, err := s.apiClient.GetSalt(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("failed to get salt: %w", err)
	}

	// 2. Деривируем ключи из master password
	keys, err := crypto.DeriveKeysFromBase64Salt(masterPassword, username, saltResp.PublicSalt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keys: %w", err)
	}

	// 3. Хешируем auth_key
	authKeyHash, err := crypto.HashAuthKey(keys.AuthKey)
	if err != nil {
		return nil, fmt.Errorf("failed to hash auth key: %w", err)
	}

	// 4. Отправляем запрос на логин
	req := pkgapi.LoginRequest{
		Username:    username,
		AuthKeyHash: authKeyHash,
	}

	resp, err := s.apiClient.Login(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	// 5. Возвращаем результат
	return &LoginResult{
		AccessToken:   resp.AccessToken,
		RefreshToken:  resp.RefreshToken,
		ExpiresIn:     resp.ExpiresIn,
		Username:      username,
		PublicSalt:    saltResp.PublicSalt,
		EncryptionKey: keys.EncryptionKey,
	}, nil
}
