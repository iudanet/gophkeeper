package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/crypto"
	"github.com/iudanet/gophkeeper/internal/validation"
	pkgapi "github.com/iudanet/gophkeeper/pkg/api"
)

//go:generate moq -out apiclient_mock.go . APIClient

// APIClient определяет интерфейс для HTTP коммуникации с сервером
type APIClient interface {
	Register(ctx context.Context, req pkgapi.RegisterRequest) (*pkgapi.RegisterResponse, error)
	GetSalt(ctx context.Context, username string) (*pkgapi.SaltResponse, error)
	Login(ctx context.Context, req pkgapi.LoginRequest) (*pkgapi.TokenResponse, error)
	Refresh(ctx context.Context, refreshToken string) (*pkgapi.TokenResponse, error)
	Logout(ctx context.Context, accessToken string) error
}

// AuthService предоставляет функции авторизации и управления сессией
// Ключ шифрования устанавливается через SetEncryptionKey после успешного Login/Register
type AuthService struct {
	apiClient     APIClient
	storage       storage.AuthStorage
	encryptionKey []byte // опциональный ключ шифрования (устанавливается после login)
}

// Compile-time check that AuthService implements Service
var _ Service = (*AuthService)(nil)

// NewAuthService создает новый сервис авторизации
func NewAuthService(apiClient APIClient, storage storage.AuthStorage) *AuthService {
	return &AuthService{
		apiClient: apiClient,
		storage:   storage,
	}
}

// SetEncryptionKey устанавливает ключ шифрования для работы с хранилищем
// Должен быть вызван после успешного Login/Register
func (s *AuthService) SetEncryptionKey(key []byte) {
	s.encryptionKey = key
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
func (s *AuthService) Register(ctx context.Context, username, masterPassword string) (*RegisterResult, error) {
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
	UserID        string // User UUID from server
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
func (s *AuthService) Login(ctx context.Context, username, masterPassword string) (*LoginResult, error) {
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
		UserID:        resp.UserID,
		AccessToken:   resp.AccessToken,
		RefreshToken:  resp.RefreshToken,
		ExpiresIn:     resp.ExpiresIn,
		Username:      username,
		NodeID:        nodeID,
		PublicSalt:    saltResp.PublicSalt,
		EncryptionKey: keys.EncryptionKey,
	}, nil
}

// SaveAuth сохраняет незашифрованные auth данные,
// сервис сам зашифрует токены и передаст в хранилище
func (s *AuthService) SaveAuth(ctx context.Context, auth *storage.AuthData) error {
	if auth == nil {
		return fmt.Errorf("auth data is nil")
	}
	if s.encryptionKey == nil {
		return fmt.Errorf("encryption key not set, call SetEncryptionKey first")
	}

	// Шифруем токены
	encryptedAccessToken, err := crypto.Encrypt([]byte(auth.AccessToken), s.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %w", err)
	}

	encryptedRefreshToken, err := crypto.Encrypt([]byte(auth.RefreshToken), s.encryptionKey)
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
func (s *AuthService) GetAuthDecryptData(ctx context.Context) (*storage.AuthData, error) {
	if s.encryptionKey == nil {
		return nil, fmt.Errorf("encryption key not set, call SetEncryptionKey first")
	}

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
	accessTokenBytes, err := crypto.Decrypt(encryptedAccessTokenBytes, s.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt access token: %w", err)
	}
	refreshTokenBytes, err := crypto.Decrypt(encryptedRefreshTokenBytes, s.encryptionKey)
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

// GetAuthEncryptData загружает данные из storage БЕЗ расшифровки токенов
// Используется для получения username и public salt без необходимости в ключе
func (s *AuthService) GetAuthEncryptData(ctx context.Context) (*storage.AuthData, error) {
	return s.storage.GetAuth(ctx)
}

// DeleteAuth удаляет данные
func (s *AuthService) DeleteAuth(ctx context.Context) error {
	return s.storage.DeleteAuth(ctx)
}

// IsAuthenticated проверяет валидность сохраненных данных по сроку действия токена
func (s *AuthService) IsAuthenticated(ctx context.Context) (bool, error) {
	return s.storage.IsAuthenticated(ctx)
}

// Logout выполняет выход из системы
// Удаляет локальные данные авторизации и опционально уведомляет сервер
func (s *AuthService) Logout(ctx context.Context) error {
	// 1. Пытаемся получить текущий access token для отправки серверу
	// Используем расшифровку если ключ установлен
	var accessToken string
	if s.encryptionKey != nil {
		authData, err := s.GetAuthDecryptData(ctx)
		if err != nil {
			// Если данных нет, просто логируем и продолжаем
			slog.Debug("no auth data found during logout", "error", err)
		} else {
			accessToken = authData.AccessToken
		}
	}

	// 2. Пытаемся уведомить сервер о logout (best effort)
	if accessToken != "" {
		if logoutErr := s.apiClient.Logout(ctx, accessToken); logoutErr != nil {
			// Не прерываем процесс, если сервер недоступен
			slog.Warn("failed to logout on server", "error", logoutErr)
		}
	}

	// 3. Всегда удаляем локальные данные, даже если сервер недоступен
	if err := s.DeleteAuth(ctx); err != nil {
		return fmt.Errorf("failed to delete local auth data: %w", err)
	}

	// 4. Очищаем ключ шифрования
	s.encryptionKey = nil

	return nil
}

// RefreshToken обновляет access token используя refresh token
// Автоматически загружает текущий refresh token, запрашивает новую пару токенов
// и сохраняет их в хранилище
func (s *AuthService) RefreshToken(ctx context.Context) error {
	// Проверяем что ключ шифрования установлен
	if s.encryptionKey == nil {
		return fmt.Errorf("encryption key not set, call SetEncryptionKey first")
	}

	// Получаем текущие auth данные с расшифрованными токенами
	authData, err := s.GetAuthDecryptData(ctx)
	if err != nil {
		return fmt.Errorf("failed to get auth data: %w", err)
	}

	// Вызываем API для обновления токена
	tokenResp, err := s.apiClient.Refresh(ctx, authData.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	// Обновляем токены в auth data
	authData.AccessToken = tokenResp.AccessToken
	authData.RefreshToken = tokenResp.RefreshToken
	authData.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Unix()

	// Сохраняем обновлённые данные (токены будут зашифрованы в SaveAuth)
	if err := s.SaveAuth(ctx, authData); err != nil {
		return fmt.Errorf("failed to save refreshed tokens: %w", err)
	}

	slog.Debug("Access token refreshed successfully",
		"expires_at", time.Unix(authData.ExpiresAt, 0).Format(time.RFC3339))

	return nil
}

// getOrCreateNodeID возвращает существующий NodeID или создает новый
// NodeID должен быть уникальным для каждого физического клиента/устройства
func (s *AuthService) getOrCreateNodeID(ctx context.Context) (string, error) {
	// Проверяем есть ли уже сохраненный NodeID в auth data
	authData, err := s.storage.GetAuth(ctx)
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
