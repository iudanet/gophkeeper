package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// HealthHandler обрабатывает health check запросы
type HealthHandler struct {
	logger *slog.Logger
}

// NewHealthHandler создает новый handler для health check
func NewHealthHandler(logger *slog.Logger) *HealthHandler {
	return &HealthHandler{
		logger: logger,
	}
}

// HealthResponse представляет ответ health check
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
}

// Health обрабатывает GET /api/v1/health
// Health check endpoint для мониторинга
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	// TODO: Проверить доступность базы данных
	// TODO: Добавить информацию о версии приложения

	resp := HealthResponse{
		Status:  "ok",
		Version: "dev", // TODO: получать из build-time переменной
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("failed to encode health response", slog.Any("error", err))
	}
}
