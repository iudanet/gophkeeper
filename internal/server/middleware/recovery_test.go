package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecoveryMiddleware(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		handler        http.HandlerFunc
		name           string
		expectedBody   string
		expectedStatus int
		expectPanic    bool
	}{
		{
			name: "Normal handler without panic",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("success"))
			},
			expectPanic:    false,
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name: "Handler with panic (string)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic("something went wrong")
			},
			expectPanic:    true,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal Server Error",
		},
		{
			name: "Handler with panic (error)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic(http.ErrAbortHandler)
			},
			expectPanic:    true,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal Server Error",
		},
		{
			name: "Handler with panic (custom type)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic(struct{ msg string }{"critical error"})
			},
			expectPanic:    true,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal Server Error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Создаем тестовый handler с recovery middleware
			middleware := RecoveryMiddleware(logger)
			handler := middleware(tt.handler)

			// Создаем тестовый запрос
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			// Выполняем запрос
			handler.ServeHTTP(w, req)

			// Проверяем статус
			assert.Equal(t, tt.expectedStatus, w.Code, "status code mismatch")

			// Проверяем тело ответа
			body := w.Body.String()
			if tt.expectPanic {
				assert.Contains(t, body, tt.expectedBody, "response body should contain error message")
			} else {
				assert.Equal(t, tt.expectedBody, body, "response body mismatch")
			}
		})
	}
}

func TestRecoveryWithCustomError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	customMessage := "Service temporarily unavailable"

	t.Run("Panic with custom error message", func(t *testing.T) {
		middleware := RecoveryWithCustomError(logger, customMessage)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("critical failure")
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		assert.Contains(t, w.Body.String(), customMessage)
		assert.Contains(t, w.Body.String(), `{"error":"`)
	})
}

func TestRecoveryMiddleware_LogsStackTrace(t *testing.T) {
	// Создаем logger который пишет в буфер для проверки
	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	middleware := RecoveryMiddleware(logger)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic for logging")
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Проверяем что лог содержит информацию о панике
	logOutput := logBuf.String()
	assert.Contains(t, logOutput, "Panic recovered", "log should mention panic recovery")
	assert.Contains(t, logOutput, "test panic for logging", "log should contain panic message")
	assert.Contains(t, logOutput, "POST", "log should contain HTTP method")
	assert.Contains(t, logOutput, "/api/test", "log should contain path")
	// Stack trace присутствует в логе
	assert.Contains(t, logOutput, "goroutine", "log should contain stack trace")
}

func TestRecoveryMiddleware_ChainWithOtherMiddleware(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Создаем цепочку middleware
	var callOrder []string

	loggingMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callOrder = append(callOrder, "logging")
			next.ServeHTTP(w, r)
		})
	}

	recoveryMiddleware := RecoveryMiddleware(logger)

	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callOrder = append(callOrder, "handler")
		panic("test panic")
	})

	// Цепочка: recovery -> logging -> handler
	handler := recoveryMiddleware(loggingMiddleware(finalHandler))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Проверяем порядок вызовов
	require.Len(t, callOrder, 2)
	assert.Equal(t, "logging", callOrder[0])
	assert.Equal(t, "handler", callOrder[1])

	// Проверяем что паника была перехвачена
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
