package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    int64
}

// WriteHeader captures the status code
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write captures the number of bytes written
func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.written += int64(n)
	return n, err
}

// LoggingMiddleware создает middleware для логирования HTTP запросов
// Логирует метод, путь, статус, время выполнения, размер ответа
// НЕ логирует sensitive данные (токены, пароли, ключи)
func LoggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer для захвата статуса и размера
			wrapped := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK, // default status
				written:        0,
			}

			// Обрабатываем запрос
			next.ServeHTTP(wrapped, r)

			// Вычисляем длительность
			duration := time.Since(start)

			// Определяем уровень логирования на основе статуса
			logLevel := slog.LevelInfo
			if wrapped.statusCode >= 500 {
				logLevel = slog.LevelError
			} else if wrapped.statusCode >= 400 {
				logLevel = slog.LevelWarn
			}

			// Логируем запрос (без sensitive данных)
			logger.Log(r.Context(), logLevel, "HTTP request",
				"method", r.Method,
				"path", sanitizePath(r.URL.Path),
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent(),
				"status", wrapped.statusCode,
				"duration_ms", duration.Milliseconds(),
				"bytes_written", wrapped.written,
			)
		})
	}
}

// sanitizePath удаляет sensitive части из пути (например, токены в URL)
// Например: /api/v1/auth/salt/username остается как есть
// но /api/v1/reset/TOKEN заменяется на /api/v1/reset/***
func sanitizePath(path string) string {
	// Список sensitive путей, которые могут содержать токены
	// В текущей реализации все пути безопасны для логирования
	// Но на будущее добавляем эту функцию

	// Пример: если в пути есть /token/ или /reset/, заменяем следующий сегмент
	if strings.Contains(path, "/token/") || strings.Contains(path, "/reset/") {
		parts := strings.Split(path, "/")
		for i, part := range parts {
			if (part == "token" || part == "reset") && i+1 < len(parts) && parts[i+1] != "" {
				parts[i+1] = "***"
			}
		}
		return strings.Join(parts, "/")
	}

	return path
}

// LoggingWithSkip создает middleware с возможностью пропуска определенных путей
// Полезно для health checks и других эндпоинтов с высокой частотой запросов
func LoggingWithSkip(logger *slog.Logger, skipPaths []string) func(http.Handler) http.Handler {
	skipMap := make(map[string]bool)
	for _, path := range skipPaths {
		skipMap[path] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Проверяем, нужно ли пропустить логирование
			if skipMap[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			// Используем обычный логгер
			LoggingMiddleware(logger)(next).ServeHTTP(w, r)
		})
	}
}
