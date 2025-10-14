package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/iudanet/gophkeeper/internal/validation"
	"github.com/iudanet/gophkeeper/pkg/api"
)

// AuthHandler обрабатывает запросы авторизации
type AuthHandler struct {
	logger *slog.Logger
}

// NewAuthHandler создает новый handler для авторизации
func NewAuthHandler(logger *slog.Logger) *AuthHandler {
	return &AuthHandler{
		logger: logger,
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

	// TODO: Сохранить пользователя в базе данных
	// TODO: Хешировать auth_key_hash (двойное хеширование не нужно, он уже захеширован на клиенте)
	// TODO: Генерировать UUID для пользователя

	// Заглушка: возвращаем успешный ответ
	h.logger.InfoContext(ctx, "user registered successfully (stub)", slog.String("username", req.Username))

	resp := api.RegisterResponse{
		UserID:  "00000000-0000-0000-0000-000000000000", // заглушка
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

	// TODO: Получить public_salt из базы данных по username
	// TODO: Если пользователь не найден - вернуть 404

	// Заглушка: возвращаем тестовую соль
	h.logger.InfoContext(ctx, "returning public salt (stub)", slog.String("username", username))

	resp := api.GetSaltResponse{
		PublicSalt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 32 нуля в base64 (заглушка)
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

	// TODO: Получить пользователя из БД по username
	// TODO: Проверить auth_key_hash с помощью crypto.VerifyAuthKey()
	// TODO: Генерировать JWT access token (15 минут)
	// TODO: Генерировать refresh token (30 дней)
	// TODO: Сохранить refresh token в БД

	// Заглушка: возвращаем тестовые токены
	h.logger.InfoContext(ctx, "user logged in successfully (stub)", slog.String("username", req.Username))

	resp := api.TokenResponse{
		AccessToken:  "stub_access_token_jwt",
		RefreshToken: "stub_refresh_token",
		ExpiresIn:    900, // 15 минут
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

	// TODO: Проверить refresh token в БД
	// TODO: Проверить срок действия
	// TODO: Генерировать новые access и refresh токены
	// TODO: Удалить старый refresh token, сохранить новый

	// Заглушка: возвращаем новые тестовые токены
	h.logger.InfoContext(ctx, "tokens refreshed successfully (stub)")

	resp := api.TokenResponse{
		AccessToken:  "stub_new_access_token_jwt",
		RefreshToken: "stub_new_refresh_token",
		ExpiresIn:    900, // 15 минут
	}

	h.sendJSON(w, resp, http.StatusOK)
}

// Logout обрабатывает POST /api/v1/auth/logout
// Выход пользователя (удаление refresh token)
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Извлекаем access token из Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.sendError(w, "Authorization header is required", http.StatusUnauthorized)
		return
	}

	// TODO: Извлечь user_id из JWT access token
	// TODO: Удалить все refresh tokens пользователя из БД

	// Заглушка: успешный выход
	h.logger.InfoContext(ctx, "user logged out successfully (stub)")

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
