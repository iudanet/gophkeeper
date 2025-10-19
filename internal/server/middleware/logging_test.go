package middleware

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoggingMiddleware(t *testing.T) {
	tests := []struct {
		handler        http.HandlerFunc
		name           string
		method         string
		path           string
		expectedStatus int
	}{
		{
			name:   "GET request with 200 OK",
			method: http.MethodGet,
			path:   "/api/v1/users",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("success"))
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "POST request with 201 Created",
			method: http.MethodPost,
			path:   "/api/v1/users",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"id":"123"}`))
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name:   "Request with 404 Not Found",
			method: http.MethodGet,
			path:   "/api/v1/nonexistent",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("not found"))
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:   "Request with 500 Internal Server Error",
			method: http.MethodPost,
			path:   "/api/v1/error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("server error"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Создаем logger с буфером для проверки логов
			var logBuf strings.Builder
			logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			}))

			// Создаем middleware
			middleware := LoggingMiddleware(logger)
			handler := middleware(tt.handler)

			// Создаем запрос
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.RemoteAddr = "192.168.1.1:12345"
			req.Header.Set("User-Agent", "TestAgent/1.0")
			w := httptest.NewRecorder()

			// Выполняем запрос
			handler.ServeHTTP(w, req)

			// Проверяем статус
			assert.Equal(t, tt.expectedStatus, w.Code)

			// Проверяем что запрос был залогирован
			logOutput := logBuf.String()
			assert.Contains(t, logOutput, "HTTP request", "log should contain request marker")
			assert.Contains(t, logOutput, tt.method, "log should contain method")
			assert.Contains(t, logOutput, tt.path, "log should contain path")
			assert.Contains(t, logOutput, "192.168.1.1:12345", "log should contain remote addr")
			assert.Contains(t, logOutput, "TestAgent/1.0", "log should contain user agent")

			// Проверяем уровень логирования в зависимости от статуса
			if tt.expectedStatus >= 500 {
				assert.Contains(t, logOutput, "ERROR", "5xx should log as ERROR")
			} else if tt.expectedStatus >= 400 {
				assert.Contains(t, logOutput, "WARN", "4xx should log as WARN")
			} else {
				assert.Contains(t, logOutput, "INFO", "2xx-3xx should log as INFO")
			}
		})
	}
}

func TestLoggingMiddleware_CapturesResponseMetrics(t *testing.T) {
	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	middleware := LoggingMiddleware(logger)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Симулируем обработку
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, World!")) // 13 bytes
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	logOutput := logBuf.String()

	// Проверяем что логируется длительность
	assert.Contains(t, logOutput, "duration_ms", "log should contain duration")

	// Проверяем что логируется размер ответа
	assert.Contains(t, logOutput, "bytes_written", "log should contain bytes written")
	assert.Contains(t, logOutput, "13", "log should show 13 bytes written")

	// Проверяем что логируется статус
	assert.Contains(t, logOutput, "status", "log should contain status")
	assert.Contains(t, logOutput, "200", "log should show 200 status")
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Normal path",
			input:    "/api/v1/users",
			expected: "/api/v1/users",
		},
		{
			name:     "Path with username parameter",
			input:    "/api/v1/auth/salt/john",
			expected: "/api/v1/auth/salt/john",
		},
		{
			name:     "Path with token (should be sanitized)",
			input:    "/api/v1/token/abc123xyz",
			expected: "/api/v1/token/***",
		},
		{
			name:     "Path with reset token (should be sanitized)",
			input:    "/api/v1/reset/secret-token-123",
			expected: "/api/v1/reset/***",
		},
		{
			name:     "Path with token at end",
			input:    "/api/v1/token/",
			expected: "/api/v1/token/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizePath(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLoggingWithSkip(t *testing.T) {
	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Пропускаем логирование для /health
	skipPaths := []string{"/health", "/metrics"}
	middleware := LoggingWithSkip(logger, skipPaths)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	t.Run("Skipped path should not be logged", func(t *testing.T) {
		logBuf.Reset()

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, logBuf.String(), "skipped path should not be logged")
	})

	t.Run("Non-skipped path should be logged", func(t *testing.T) {
		logBuf.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, logBuf.String(), "HTTP request", "non-skipped path should be logged")
		assert.Contains(t, logBuf.String(), "/api/users")
	})
}

func TestResponseWriter_CapturesStatusCode(t *testing.T) {
	tests := []struct {
		name           string
		writeHeader    bool
		statusCode     int
		expectedStatus int
	}{
		{
			name:           "Explicit 201",
			writeHeader:    true,
			statusCode:     http.StatusCreated,
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Explicit 404",
			writeHeader:    true,
			statusCode:     http.StatusNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Default 200 (no WriteHeader)",
			writeHeader:    false,
			statusCode:     0,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			rw := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			if tt.writeHeader {
				rw.WriteHeader(tt.statusCode)
			}
			_, _ = rw.Write([]byte("test"))

			assert.Equal(t, tt.expectedStatus, rw.statusCode)
		})
	}
}

func TestResponseWriter_CapturesBytesWritten(t *testing.T) {
	w := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	data1 := []byte("Hello, ")
	data2 := []byte("World!")

	n1, err1 := rw.Write(data1)
	require.NoError(t, err1)
	assert.Equal(t, len(data1), n1)

	n2, err2 := rw.Write(data2)
	require.NoError(t, err2)
	assert.Equal(t, len(data2), n2)

	assert.Equal(t, int64(len(data1)+len(data2)), rw.written)
	assert.Equal(t, int64(13), rw.written)
}
