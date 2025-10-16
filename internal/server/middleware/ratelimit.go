package middleware

import (
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// RateLimiter представляет rate limiter на основе токен-бакета (token bucket)
type RateLimiter struct {
	buckets  map[string]*bucket
	logger   *slog.Logger
	cleanupC chan struct{}
	rate     int
	window   time.Duration
	mu       sync.RWMutex
}

// bucket представляет bucket для конкретного IP/ключа
type bucket struct {
	lastRefill time.Time
	tokens     int
	mu         sync.Mutex
}

// NewRateLimiter создает новый rate limiter
// rate - максимальное количество запросов в единицу времени
// window - временное окно (например, 1 минута)
func NewRateLimiter(rate int, window time.Duration, logger *slog.Logger) *RateLimiter {
	rl := &RateLimiter{
		buckets:  make(map[string]*bucket),
		rate:     rate,
		window:   window,
		logger:   logger,
		cleanupC: make(chan struct{}),
	}

	// Запускаем периодическую очистку старых buckets
	go rl.cleanup()

	return rl
}

// cleanup периодически удаляет неактивные buckets для экономии памяти
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.window * 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanupOldBuckets()
		case <-rl.cleanupC:
			return
		}
	}
}

// cleanupOldBuckets удаляет buckets, которые не использовались дольше window
func (rl *RateLimiter) cleanupOldBuckets() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for key, b := range rl.buckets {
		b.mu.Lock()
		if now.Sub(b.lastRefill) > rl.window*2 {
			delete(rl.buckets, key)
		}
		b.mu.Unlock()
	}
}

// Stop останавливает cleanup goroutine
func (rl *RateLimiter) Stop() {
	close(rl.cleanupC)
}

// Allow проверяет, разрешен ли запрос для данного ключа (обычно IP адрес)
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.RLock()
	b, exists := rl.buckets[key]
	rl.mu.RUnlock()

	if !exists {
		// Создаем новый bucket
		b = &bucket{
			tokens:     rl.rate,
			lastRefill: time.Now(),
		}
		rl.mu.Lock()
		rl.buckets[key] = b
		rl.mu.Unlock()
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill)

	// Пополняем токены на основе прошедшего времени
	if elapsed >= rl.window {
		b.tokens = rl.rate
		b.lastRefill = now
	}

	// Проверяем, есть ли доступные токены
	if b.tokens > 0 {
		b.tokens--
		return true
	}

	return false
}

// RateLimitMiddleware создает middleware для ограничения частоты запросов
// rate - максимальное количество запросов
// window - временное окно (например, 5 минут)
func RateLimitMiddleware(rate int, window time.Duration, logger *slog.Logger) func(http.Handler) http.Handler {
	limiter := NewRateLimiter(rate, window, logger)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Используем IP адрес как ключ
			key := getClientIP(r)

			if !limiter.Allow(key) {
				logger.Warn("Rate limit exceeded",
					"ip", key,
					"method", r.Method,
					"path", r.URL.Path,
				)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limit exceeded, please try again later"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitByPath создает middleware с разными лимитами для разных путей
type PathRateLimit struct {
	Path   string
	Rate   int
	Window time.Duration
}

// RateLimitByPathMiddleware создает middleware с кастомными лимитами для путей
func RateLimitByPathMiddleware(limits []PathRateLimit, defaultRate int, defaultWindow time.Duration, logger *slog.Logger) func(http.Handler) http.Handler {
	// Создаем limiters для каждого пути
	limiters := make(map[string]*RateLimiter)
	for _, limit := range limits {
		limiters[limit.Path] = NewRateLimiter(limit.Rate, limit.Window, logger)
	}

	// Дефолтный limiter для всех остальных путей
	defaultLimiter := NewRateLimiter(defaultRate, defaultWindow, logger)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Выбираем соответствующий limiter
			limiter, exists := limiters[r.URL.Path]
			if !exists {
				limiter = defaultLimiter
			}

			key := getClientIP(r)
			if !limiter.Allow(key) {
				logger.Warn("Rate limit exceeded",
					"ip", key,
					"method", r.Method,
					"path", r.URL.Path,
				)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limit exceeded, please try again later"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP извлекает IP адрес клиента из запроса
// Проверяет заголовки X-Forwarded-For и X-Real-IP для прокси
func getClientIP(r *http.Request) string {
	// Проверяем X-Forwarded-For (для прокси/load balancers)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Берем первый IP из списка (реальный клиент)
		for idx := 0; idx < len(xff); idx++ {
			if xff[idx] == ',' {
				return xff[:idx]
			}
		}
		return xff
	}

	// Проверяем X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Используем RemoteAddr
	return r.RemoteAddr
}
