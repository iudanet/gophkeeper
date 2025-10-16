package auth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/iudanet/gophkeeper/internal/client/api"
	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/crypto"
	"github.com/iudanet/gophkeeper/internal/validation"
	pkgapi "github.com/iudanet/gophkeeper/pkg/api"
)

// AuthStore defines interface for storing authentication data with encryption
// This layer is responsible for encrypting/decrypting tokens before saving to storage
type AuthStore interface {
	// SaveAuth encrypts and saves authentication data
	SaveAuth(ctx context.Context, auth *storage.AuthData) error

	// GetAuth retrieves and decrypts authentication data
	GetAuth(ctx context.Context) (*storage.AuthData, error)

	// DeleteAuth removes stored authentication data
	DeleteAuth(ctx context.Context) error

	// IsAuthenticated checks if valid authentication exists
	IsAuthenticated(ctx context.Context) (bool, error)
}

// Service предоставляет функции авторизации
type Service struct {
	apiClient *api.Client
	authStore AuthStore
}

// NewService создает новый сервис авторизации
func NewService(apiClient *api.Client, authStore AuthStore) *Service {
	return &Service{
		apiClient: apiClient,
		authStore: authStore,
	}
}

// RegisterResult содержит результат регистрации
type RegisterResult struct {
	UserID        string // UUID пользователя
	Username      string // username
	NodeID        string // уникальный ID клиента/устройства для CRDT
	PublicSalt    string // public salt (base64)
	EncryptionKey []byte // ключ шифрования (НЕ сохраняется!)
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

	// 5. Генерируем уникальный NodeID для этого клиента
	nodeID := uuid.New().String()

	// 6. Возвращаем результат
	return &RegisterResult{
		UserID:        resp.UserID,
		Username:      username,
		NodeID:        nodeID,
		PublicSalt:    publicSaltBase64,
		EncryptionKey: keys.EncryptionKey,
	}, nil
}

// LoginResult содержит результат авторизации
type LoginResult struct {
	AccessToken   string
	RefreshToken  string
	Username      string
	NodeID        string // уникальный ID клиента/устройства для CRDT
	PublicSalt    string
	EncryptionKey []byte
	ExpiresIn     int64
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

	// 5. Получаем или генерируем NodeID
	nodeID, err := s.getOrCreateNodeID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get or create node ID: %w", err)
	}

	// 6. Возвращаем результат
	return &LoginResult{
		AccessToken:   resp.AccessToken,
		RefreshToken:  resp.RefreshToken,
		ExpiresIn:     resp.ExpiresIn,
		Username:      username,
		NodeID:        nodeID,
		PublicSalt:    saltResp.PublicSalt,
		EncryptionKey: keys.EncryptionKey,
	}, nil
}

// Logout выполняет выход из системы
// Удаляет локальные данные авторизации и опционально уведомляет сервер
func (s *Service) Logout(ctx context.Context) error {
	// 1. Пытаемся получить текущий access token для отправки серверу
	authData, err := s.authStore.GetAuth(ctx)
	if err != nil {
		// Если данных нет, просто логируем и продолжаем
		slog.Debug("no auth data found during logout", "error", err)
	} else {
		// 2. Пытаемся уведомить сервер о logout (best effort)
		if logoutErr := s.apiClient.Logout(ctx, authData.AccessToken); logoutErr != nil {
			// Не прерываем процесс, если сервер недоступен
			slog.Warn("failed to logout on server", "error", logoutErr)
		}
	}

	// 3. Всегда удаляем локальные данные, даже если сервер недоступен
	if err := s.authStore.DeleteAuth(ctx); err != nil {
		return fmt.Errorf("failed to delete local auth data: %w", err)
	}

	return nil
}

// getOrCreateNodeID возвращает существующий NodeID или создает новый
// NodeID должен быть уникальным для каждого физического клиента/устройства
func (s *Service) getOrCreateNodeID(ctx context.Context) (string, error) {
	// Если authStore не инициализирован (это первый login/register), создаем новый NodeID
	if s.authStore == nil {
		return uuid.New().String(), nil
	}

	// Проверяем есть ли уже сохраненный NodeID в auth data
	authData, err := s.authStore.GetAuth(ctx)
	if err != nil {
		// Если данных нет (первый login на этом устройстве), создаем новый NodeID
		if err == storage.ErrAuthNotFound {
			return uuid.New().String(), nil
		}
		return "", fmt.Errorf("failed to get auth data: %w", err)
	}

	// Если NodeID уже есть, используем его (повторный login на том же устройстве)
	if authData.NodeID != "" {
		return authData.NodeID, nil
	}

	// Если NodeID пустой (старая версия базы), создаем новый
	return uuid.New().String(), nil
}
