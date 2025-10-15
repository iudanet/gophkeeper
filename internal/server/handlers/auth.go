package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/iudanet/gophkeeper/internal/models"
	"github.com/iudanet/gophkeeper/internal/server/storage"
	"github.com/iudanet/gophkeeper/internal/validation"
	"github.com/iudanet/gophkeeper/pkg/api"
)

// AuthHandler обрабатывает запросы авторизации
type AuthHandler struct {
	logger       *slog.Logger
	userStorage  storage.UserStorage
	tokenStorage storage.TokenStorage
	jwtConfig    JWTConfig
}

// NewAuthHandler создает новый handler для авторизации
func NewAuthHandler(logger *slog.Logger, userStorage storage.UserStorage, tokenStorage storage.TokenStorage, jwtConfig JWTConfig) *AuthHandler {
	return &AuthHandler{
		logger:       logger,
		userStorage:  userStorage,
		tokenStorage: tokenStorage,
		jwtConfig:    jwtConfig,
	}
}

// Register обрабатывает POST /api/v1/auth/register
// Регистрация нового пользователя
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Парсим request body
	var req api.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.ErrorContext(ctx, "failed to decode register request", slog.Any("error", err))
		h.sendError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Валидация username
	if err := validation.ValidateUsername(req.Username); err != nil {
		h.logger.WarnContext(ctx, "invalid username", slog.String("username", req.Username), slog.Any("error", err))
		h.sendError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Проверка обязательных полей
	if req.AuthKeyHash == "" {
		h.sendError(w, "auth_key_hash is required", http.StatusBadRequest)
		return
	}
	if req.PublicSalt == "" {
		h.sendError(w, "public_salt is required", http.StatusBadRequest)
		return
	}

	// Генерируем UUID для пользователя
	userID := uuid.New().String()

	// Создаем пользователя
	user := &models.User{
		ID:          userID,
		Username:    req.Username,
		AuthKeyHash: req.AuthKeyHash, // SHA256 хеш auth_key от клиента
		PublicSalt:  req.PublicSalt,
		CreatedAt:   time.Now(),
	}

	// Сохраняем в БД
	if err := h.userStorage.CreateUser(ctx, user); err != nil {
		if errors.Is(err, storage.ErrUserAlreadyExists) {
			h.logger.WarnContext(ctx, "user already exists", slog.String("username", req.Username))
			h.sendError(w, "username already taken", http.StatusConflict)
			return
		}
		h.logger.ErrorContext(ctx, "failed to create user", slog.Any("error", err))
		h.sendError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.InfoContext(ctx, "user registered successfully",
		slog.String("username", req.Username),
		slog.String("user_id", userID))

	resp := api.RegisterResponse{
		UserID:  userID,
		Message: "User registered successfully",
	}

	h.sendJSON(w, resp, http.StatusCreated)
}

// GetSalt обрабатывает GET /api/v1/auth/salt/{username}
// Получение public_salt пользователя
func (h *AuthHandler) GetSalt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Извлекаем username из path parameter (Go 1.22+)
	username := r.PathValue("username")
	if username == "" {
		h.sendError(w, "username is required", http.StatusBadRequest)
		return
	}

	// Валидация username
	if err := validation.ValidateUsername(username); err != nil {
		h.logger.WarnContext(ctx, "invalid username", slog.String("username", username), slog.Any("error", err))
		h.sendError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Получаем пользователя из БД
	user, err := h.userStorage.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			h.logger.WarnContext(ctx, "user not found", slog.String("username", username))
			h.sendError(w, "user not found", http.StatusNotFound)
			return
		}
		h.logger.ErrorContext(ctx, "failed to get user", slog.Any("error", err))
		h.sendError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.InfoContext(ctx, "returning public salt", slog.String("username", username))

	resp := api.SaltResponse{
		PublicSalt: user.PublicSalt,
	}

	h.sendJSON(w, resp, http.StatusOK)
}

// Login обрабатывает POST /api/v1/auth/login
// Аутентификация пользователя
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Парсим request body
	var req api.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.ErrorContext(ctx, "failed to decode login request", slog.Any("error", err))
		h.sendError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Валидация username
	if err := validation.ValidateUsername(req.Username); err != nil {
		h.logger.WarnContext(ctx, "invalid username", slog.String("username", req.Username), slog.Any("error", err))
		h.sendError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Проверка обязательных полей
	if req.AuthKeyHash == "" {
		h.sendError(w, "auth_key_hash is required", http.StatusBadRequest)
		return
	}

	// Получаем пользователя из БД
	user, err := h.userStorage.GetUserByUsername(ctx, req.Username)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			h.logger.WarnContext(ctx, "login failed: user not found", slog.String("username", req.Username))
			h.sendError(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		h.logger.ErrorContext(ctx, "failed to get user", slog.Any("error", err))
		h.sendError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Проверяем auth_key_hash
	// Клиент отправляет SHA256 хеш от auth_key (детерминированный)
	// Сервер сравнивает с сохраненным хешем (простое строковое сравнение)
	if user.AuthKeyHash != req.AuthKeyHash {
		h.logger.WarnContext(ctx, "login failed: invalid auth key", slog.String("username", req.Username))
		h.sendError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Генерируем JWT access token
	accessToken, expiresIn, err := GenerateAccessToken(h.jwtConfig, user.ID, user.Username)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to generate access token", slog.Any("error", err))
		h.sendError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Генерируем refresh token
	refreshToken, expiresAt, err := GenerateRefreshToken(h.jwtConfig)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to generate refresh token", slog.Any("error", err))
		h.sendError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Сохраняем refresh token в БД
	token := &models.RefreshToken{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	if err := h.tokenStorage.SaveRefreshToken(ctx, token); err != nil {
		h.logger.ErrorContext(ctx, "failed to save refresh token", slog.Any("error", err))
		h.sendError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Обновляем last_login
	now := time.Now()
	if err := h.userStorage.UpdateLastLogin(ctx, user.ID, now); err != nil {
		// Не критичная ошибка, логируем но не прерываем
		h.logger.WarnContext(ctx, "failed to update last login", slog.Any("error", err))
	}

	h.logger.InfoContext(ctx, "user logged in successfully",
		slog.String("username", req.Username),
		slog.String("user_id", user.ID))

	resp := api.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
	}

	h.sendJSON(w, resp, http.StatusOK)
}

// Refresh обрабатывает POST /api/v1/auth/refresh
// Обновление access token с помощью refresh token
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Извлекаем refresh token из Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.sendError(w, "Authorization header is required", http.StatusUnauthorized)
		return
	}

	// Проверяем формат "Bearer <token>"
	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		h.sendError(w, "invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	refreshToken := authHeader[len(bearerPrefix):]
	if refreshToken == "" {
		h.sendError(w, "refresh token is required", http.StatusUnauthorized)
		return
	}

	// Проверяем refresh token в БД
	storedToken, err := h.tokenStorage.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, storage.ErrTokenNotFound) {
			h.logger.WarnContext(ctx, "refresh token not found")
			h.sendError(w, "invalid refresh token", http.StatusUnauthorized)
			return
		}
		h.logger.ErrorContext(ctx, "failed to get refresh token", slog.Any("error", err))
		h.sendError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Проверяем срок действия
	if time.Now().After(storedToken.ExpiresAt) {
		h.logger.WarnContext(ctx, "refresh token expired", slog.String("user_id", storedToken.UserID))
		h.sendError(w, "refresh token expired", http.StatusUnauthorized)
		return
	}

	// Получаем пользователя для генерации нового access token
	user, err := h.userStorage.GetUserByID(ctx, storedToken.UserID)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to get user", slog.Any("error", err))
		h.sendError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Генерируем новый access token
	newAccessToken, expiresIn, err := GenerateAccessToken(h.jwtConfig, user.ID, user.Username)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to generate access token", slog.Any("error", err))
		h.sendError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Генерируем новый refresh token
	newRefreshToken, newExpiresAt, err := GenerateRefreshToken(h.jwtConfig)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to generate refresh token", slog.Any("error", err))
		h.sendError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Удаляем старый refresh token
	if err := h.tokenStorage.DeleteRefreshToken(ctx, refreshToken); err != nil {
		h.logger.WarnContext(ctx, "failed to delete old refresh token", slog.Any("error", err))
		// Продолжаем выполнение
	}

	// Сохраняем новый refresh token
	newToken := &models.RefreshToken{
		Token:     newRefreshToken,
		UserID:    user.ID,
		ExpiresAt: newExpiresAt,
		CreatedAt: time.Now(),
	}

	if err := h.tokenStorage.SaveRefreshToken(ctx, newToken); err != nil {
		h.logger.ErrorContext(ctx, "failed to save refresh token", slog.Any("error", err))
		h.sendError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.InfoContext(ctx, "tokens refreshed successfully", slog.String("user_id", user.ID))

	resp := api.TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    expiresIn,
	}

	h.sendJSON(w, resp, http.StatusOK)
}

// Logout обрабатывает POST /api/v1/auth/logout
// Выход пользователя (удаление refresh token)
// TODO сейчас выходит из всех устройств. надо сделать выход только с 1 например через ID устройства
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Извлекаем access token из Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.sendError(w, "Authorization header is required", http.StatusUnauthorized)
		return
	}

	// Извлекаем access token из Authorization header
	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		h.sendError(w, "invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	accessToken := authHeader[len(bearerPrefix):]
	if accessToken == "" {
		h.sendError(w, "access token is required", http.StatusUnauthorized)
		return
	}

	// Валидируем и парсим access token
	claims, err := ValidateAccessToken(h.jwtConfig, accessToken)
	if err != nil {
		h.logger.WarnContext(ctx, "invalid access token", slog.Any("error", err))
		h.sendError(w, "invalid or expired access token", http.StatusUnauthorized)
		return
	}

	// Удаляем все refresh tokens пользователя
	deletedCount, err := h.tokenStorage.DeleteUserTokens(ctx, claims.UserID)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to delete user tokens", slog.Any("error", err))
		h.sendError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.InfoContext(ctx, "user logged out successfully",
		slog.String("user_id", claims.UserID),
		slog.Int("tokens_deleted", deletedCount))

	w.WriteHeader(http.StatusNoContent)
}

// sendJSON отправляет JSON ответ
func (h *AuthHandler) sendJSON(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", slog.Any("error", err))
	}
}

// sendError отправляет JSON ответ с ошибкой
func (h *AuthHandler) sendError(w http.ResponseWriter, message string, statusCode int) {
	resp := api.ErrorResponse{
		Error:   http.StatusText(statusCode),
		Message: message,
	}
	h.sendJSON(w, resp, statusCode)
}
