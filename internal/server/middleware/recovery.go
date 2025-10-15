package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
)

// RecoveryMiddleware создает middleware для восстановления после паники
// Перехватывает panic, логирует стек вызовов и возвращает 500 Internal Server Error
func RecoveryMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					// Получаем стек вызовов для диагностики
					stackTrace := debug.Stack()

					// Логируем критическую ошибку со стеком
					logger.Error("Panic recovered",
						"error", err,
						"method", r.Method,
						"path", r.URL.Path,
						"remote_addr", r.RemoteAddr,
						"stack", string(stackTrace),
					)

					// Возвращаем generic ошибку клиенту (не раскрываем детали)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()

			// Передаем управление следующему обработчику
			next.ServeHTTP(w, r)
		})
	}
}

// RecoveryWithCustomError создает middleware с кастомным сообщением об ошибке
func RecoveryWithCustomError(logger *slog.Logger, errorMessage string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					stackTrace := debug.Stack()

					logger.Error("Panic recovered",
						"error", err,
						"method", r.Method,
						"path", r.URL.Path,
						"remote_addr", r.RemoteAddr,
						"stack", string(stackTrace),
					)

					// Формируем JSON ответ с кастомным сообщением
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = fmt.Fprintf(w, `{"error":"%s"}`, errorMessage)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
