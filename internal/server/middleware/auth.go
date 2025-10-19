package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/iudanet/gophkeeper/internal/server/handlers"
)

// AuthMiddleware создает middleware для проверки JWT токена
func AuthMiddleware(logger *slog.Logger, jwtConfig handlers.JWTConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Извлекаем токен из заголовка Authorization
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logger.Warn("Missing Authorization header")
				http.Error(w, "Unauthorized: missing token", http.StatusUnauthorized)
				return
			}

			// Ожидаем формат: "Bearer <token>"
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				logger.Warn("Invalid Authorization header format", "header", authHeader)
				http.Error(w, "Unauthorized: invalid token format", http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]

			// Валидируем токен
			claims, err := handlers.ValidateAccessToken(jwtConfig, tokenString)
			if err != nil {
				logger.Warn("Invalid access token", "error", err)
				http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
				return
			}

			// Добавляем данные из токена в контекст
			ctx := context.WithValue(r.Context(), handlers.UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, handlers.UsernameKey, claims.Username)

			logger.Debug("User authenticated", "user_id", claims.UserID, "username", claims.Username)

			// Передаем запрос дальше с обновленным контекстом
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
