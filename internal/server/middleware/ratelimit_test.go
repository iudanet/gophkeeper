package middleware

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewRateLimiter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rate := 10
	window := 1 * time.Minute

	limiter := NewRateLimiter(rate, window, logger)

	assert.NotNil(t, limiter)
	assert.Equal(t, rate, limiter.rate)
	assert.Equal(t, window, limiter.window)
	assert.NotNil(t, limiter.buckets)
	assert.NotNil(t, limiter.cleanupC)

	// Cleanup
	limiter.Stop()
}

func TestRateLimiter_Allow(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("First requests within limit are allowed", func(t *testing.T) {
		limiter := NewRateLimiter(5, 1*time.Minute, logger)
		defer limiter.Stop()

		key := "192.168.1.1"

		// Первые 5 запросов должны пройти
		for i := 0; i < 5; i++ {
			allowed := limiter.Allow(key)
			assert.True(t, allowed, fmt.Sprintf("request %d should be allowed", i+1))
		}
	})

	t.Run("Requests over limit are denied", func(t *testing.T) {
		limiter := NewRateLimiter(3, 1*time.Minute, logger)
		defer limiter.Stop()

		key := "192.168.1.2"

		// Первые 3 запроса проходят
		for i := 0; i < 3; i++ {
			allowed := limiter.Allow(key)
			assert.True(t, allowed)
		}

		// 4-й запрос блокируется
		allowed := limiter.Allow(key)
		assert.False(t, allowed, "request over limit should be denied")
	})

	t.Run("Different keys are tracked separately", func(t *testing.T) {
		limiter := NewRateLimiter(2, 1*time.Minute, logger)
		defer limiter.Stop()

		key1 := "192.168.1.1"
		key2 := "192.168.1.2"

		// key1: 2 запроса проходят
		assert.True(t, limiter.Allow(key1))
		assert.True(t, limiter.Allow(key1))
		assert.False(t, limiter.Allow(key1), "key1 over limit")

		// key2: независимые 2 запроса
		assert.True(t, limiter.Allow(key2))
		assert.True(t, limiter.Allow(key2))
		assert.False(t, limiter.Allow(key2), "key2 over limit")
	})

	t.Run("Tokens refill after window expires", func(t *testing.T) {
		limiter := NewRateLimiter(2, 50*time.Millisecond, logger)
		defer limiter.Stop()

		key := "192.168.1.3"

		// Используем все токены
		assert.True(t, limiter.Allow(key))
		assert.True(t, limiter.Allow(key))
		assert.False(t, limiter.Allow(key), "should be rate limited")

		// Ждем окончания window
		time.Sleep(60 * time.Millisecond)

		// Токены должны обновиться
		assert.True(t, limiter.Allow(key), "tokens should be refilled")
		assert.True(t, limiter.Allow(key), "tokens should be refilled")
	})
}

func TestRateLimitMiddleware(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("Requests within limit pass through", func(t *testing.T) {
		middleware := RateLimitMiddleware(5, 1*time.Minute, logger)
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
		}))

		// Первые 5 запросов проходят
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, fmt.Sprintf("request %d should pass", i+1))
			assert.Equal(t, "success", w.Body.String())
		}
	})

	t.Run("Requests over limit are blocked with 429", func(t *testing.T) {
		middleware := RateLimitMiddleware(3, 1*time.Minute, logger)
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
		}))

		// Первые 3 запроса проходят
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
			req.RemoteAddr = "192.168.1.2:12345"
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// 4-й запрос блокируется
		req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
		req.RemoteAddr = "192.168.1.2:12345"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		assert.Contains(t, w.Body.String(), "rate limit exceeded")
	})

	t.Run("Different IPs are tracked separately", func(t *testing.T) {
		middleware := RateLimitMiddleware(2, 1*time.Minute, logger)
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// IP 1: использует свой лимит
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// IP 2: имеет свой независимый лимит
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.2:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// Оба IP достигли лимита
		req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
		req1.RemoteAddr = "192.168.1.1:12345"
		w1 := httptest.NewRecorder()
		handler.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusTooManyRequests, w1.Code)

		req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
		req2.RemoteAddr = "192.168.1.2:12345"
		w2 := httptest.NewRecorder()
		handler.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusTooManyRequests, w2.Code)
	})
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xRealIP    string
		expectedIP string
	}{
		{
			name:       "X-Forwarded-For with single IP",
			remoteAddr: "10.0.0.1:12345",
			xff:        "192.168.1.1",
			xRealIP:    "",
			expectedIP: "192.168.1.1",
		},
		{
			name:       "X-Forwarded-For with multiple IPs",
			remoteAddr: "10.0.0.1:12345",
			xff:        "192.168.1.1, 10.0.0.2, 10.0.0.3",
			xRealIP:    "",
			expectedIP: "192.168.1.1", // Первый IP
		},
		{
			name:       "X-Real-IP when X-Forwarded-For is empty",
			remoteAddr: "10.0.0.1:12345",
			xff:        "",
			xRealIP:    "192.168.2.1",
			expectedIP: "192.168.2.1",
		},
		{
			name:       "RemoteAddr when headers are empty",
			remoteAddr: "192.168.3.1:54321",
			xff:        "",
			xRealIP:    "",
			expectedIP: "192.168.3.1:54321",
		},
		{
			name:       "X-Forwarded-For takes precedence over X-Real-IP",
			remoteAddr: "10.0.0.1:12345",
			xff:        "192.168.1.1",
			xRealIP:    "192.168.2.1",
			expectedIP: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			ip := getClientIP(req)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}

func TestRateLimitByPathMiddleware(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	limits := []PathRateLimit{
		{Path: "/api/v1/auth/login", Rate: 2, Window: 1 * time.Minute},
		{Path: "/api/v1/auth/register", Rate: 1, Window: 1 * time.Minute},
	}

	middleware := RateLimitByPathMiddleware(limits, 10, 1*time.Minute, logger)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Login endpoint has custom limit (2 req/min)", func(t *testing.T) {
		// Первые 2 запроса проходят
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// 3-й запрос блокируется
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})

	t.Run("Register endpoint has stricter limit (1 req/min)", func(t *testing.T) {
		// Первый запрос проходит
		req1 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", nil)
		req1.RemoteAddr = "192.168.1.2:12345"
		w1 := httptest.NewRecorder()
		handler.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// 2-й запрос сразу блокируется
		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", nil)
		req2.RemoteAddr = "192.168.1.2:12345"
		w2 := httptest.NewRecorder()
		handler.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusTooManyRequests, w2.Code)
	})

	t.Run("Unknown path uses default limit (10 req/min)", func(t *testing.T) {
		// Первые 10 запросов проходят
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/data", nil)
			req.RemoteAddr = "192.168.1.3:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// 11-й запрос блокируется
		req := httptest.NewRequest(http.MethodGet, "/api/v1/data", nil)
		req.RemoteAddr = "192.168.1.3:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})
}

func TestRateLimiter_CleanupOldBuckets(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	limiter := NewRateLimiter(10, 100*time.Millisecond, logger)
	defer limiter.Stop()

	// Создаем несколько buckets
	limiter.Allow("192.168.1.1")
	limiter.Allow("192.168.1.2")
	limiter.Allow("192.168.1.3")

	// Проверяем что buckets созданы
	limiter.mu.RLock()
	bucketCount := len(limiter.buckets)
	limiter.mu.RUnlock()
	assert.Equal(t, 3, bucketCount)

	// Ждем больше чем window * 2 для cleanup
	time.Sleep(250 * time.Millisecond)

	// Buckets должны быть очищены
	limiter.mu.RLock()
	bucketCountAfter := len(limiter.buckets)
	limiter.mu.RUnlock()
	assert.Equal(t, 0, bucketCountAfter, "old buckets should be cleaned up")
}

func TestRateLimitMiddleware_LogsExceededRequests(t *testing.T) {
	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))

	middleware := RateLimitMiddleware(1, 1*time.Minute, logger)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Первый запрос проходит
	req1 := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	// Второй запрос блокируется и логируется
	req2 := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusTooManyRequests, w2.Code)

	logOutput := logBuf.String()
	assert.Contains(t, logOutput, "Rate limit exceeded")
	assert.Contains(t, logOutput, "192.168.1.1:12345")
	assert.Contains(t, logOutput, "/api/login")
	assert.Contains(t, logOutput, "POST")
}
