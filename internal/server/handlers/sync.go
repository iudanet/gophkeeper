package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/iudanet/gophkeeper/internal/models"
	"github.com/iudanet/gophkeeper/pkg/api"
)

// contextKey тип для ключей контекста
type contextKey string

const (
	// UserIDKey ключ для хранения user_id в контексте
	UserIDKey contextKey = "user_id"
	// UsernameKey ключ для хранения username в контексте
	UsernameKey contextKey = "username"
)

// GetUserID извлекает user_id из контекста запроса
func GetUserID(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(UserIDKey).(string)
	return userID, ok
}

// GetUsername извлекает username из контекста запроса
func GetUsername(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(UsernameKey).(string)
	return username, ok
}

// DataStorage определяет интерфейс для работы с данными
type DataStorage interface {
	SaveEntry(ctx context.Context, entry *models.CRDTEntry) (bool, error)
	GetUserEntriesSince(ctx context.Context, userID string, since int64) ([]*models.CRDTEntry, error)
}

// SyncHandler handles synchronization requests
type SyncHandler struct {
	logger  *slog.Logger
	storage DataStorage
}

// NewSyncHandler creates a new sync handler
func NewSyncHandler(logger *slog.Logger, storage DataStorage) *SyncHandler {
	return &SyncHandler{
		logger:  logger,
		storage: storage,
	}
}

// HandleSync обрабатывает GET и POST запросы для синхронизации
func (h *SyncHandler) HandleSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Получаем user_id из контекста (установлен AuthMiddleware)
	userID, ok := GetUserID(ctx)
	if !ok {
		h.logger.Error("User ID not found in context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGetSync(w, r, ctx, userID)
	case http.MethodPost:
		h.handlePostSync(w, r, ctx, userID)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetSync обрабатывает GET /api/v1/sync?since=timestamp
// Возвращает все изменения с указанного timestamp
func (h *SyncHandler) handleGetSync(w http.ResponseWriter, r *http.Request, ctx context.Context, userID string) {
	// Парсим параметр since
	sinceStr := r.URL.Query().Get("since")
	var since int64
	if sinceStr != "" {
		var err error
		since, err = strconv.ParseInt(sinceStr, 10, 64)
		if err != nil {
			h.logger.Warn("Invalid since parameter", "since", sinceStr, "error", err)
			http.Error(w, "Invalid since parameter", http.StatusBadRequest)
			return
		}
	}

	h.logger.Info("GET sync request", "user_id", userID, "since", since)

	// Получаем записи с указанного timestamp
	entries, err := h.storage.GetUserEntriesSince(ctx, userID, since)
	if err != nil {
		h.logger.Error("Failed to get user entries", "error", err, "user_id", userID)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Конвертируем в API формат
	apiEntries := make([]api.CRDTEntry, 0, len(entries))
	maxTimestamp := since

	for _, entry := range entries {
		apiEntry := api.CRDTEntry{
			ID:        entry.ID,
			UserID:    entry.UserID,
			DataType:  entry.Type,
			Data:      entry.Data,
			Metadata:  string(entry.Metadata), // Конвертируем []byte в string
			Timestamp: entry.Timestamp,
			Deleted:   entry.Deleted,
			CreatedAt: entry.CreatedAt,
			UpdatedAt: entry.UpdatedAt,
		}
		apiEntries = append(apiEntries, apiEntry)

		// Отслеживаем максимальный timestamp
		if entry.Timestamp > maxTimestamp {
			maxTimestamp = entry.Timestamp
		}
	}

	// Формируем ответ
	response := api.SyncResponse{
		Entries:          apiEntries,
		CurrentTimestamp: maxTimestamp,
		Conflicts:        0, // GET не вызывает конфликтов
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode response", "error", err)
	}

	h.logger.Info("GET sync completed", "user_id", userID, "entries_count", len(apiEntries))
}

// handlePostSync обрабатывает POST /api/v1/sync
// Принимает изменения от клиента и возвращает изменения с сервера
func (h *SyncHandler) handlePostSync(w http.ResponseWriter, r *http.Request, ctx context.Context, userID string) {
	var req api.SyncRequest

	// Парсим request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("Failed to decode sync request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	h.logger.Info("POST sync request",
		"user_id", userID,
		"since", req.Since,
		"entries_count", len(req.Entries))

	conflicts := 0

	// Сохраняем входящие записи от клиента
	for i, apiEntry := range req.Entries {
		// Проверяем что user_id совпадает
		if apiEntry.UserID != userID {
			h.logger.Warn("Entry user_id mismatch",
				"expected", userID,
				"got", apiEntry.UserID,
				"entry_id", apiEntry.ID)
			http.Error(w, fmt.Sprintf("Entry %d: user_id mismatch", i), http.StatusForbidden)
			return
		}

		// Конвертируем в models.CRDTEntry
		entry := &models.CRDTEntry{
			ID:        apiEntry.ID,
			UserID:    apiEntry.UserID,
			Type:      apiEntry.DataType,
			Data:      apiEntry.Data,
			Metadata:  []byte(apiEntry.Metadata), // Конвертируем string в []byte
			Timestamp: apiEntry.Timestamp,
			Deleted:   apiEntry.Deleted,
			CreatedAt: apiEntry.CreatedAt,
			UpdatedAt: apiEntry.UpdatedAt,
			// NodeID и Version устанавливаются на клиенте
		}

		// Сохраняем запись
		saved, err := h.storage.SaveEntry(ctx, entry)
		if err != nil {
			h.logger.Error("Failed to save entry", "error", err, "entry_id", entry.ID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Если запись не была сохранена (существующая новее) - это конфликт
		if !saved {
			conflicts++
			h.logger.Debug("Entry not saved (existing is newer)", "entry_id", entry.ID)
		}
	}

	// Получаем записи с сервера с указанного timestamp
	entries, err := h.storage.GetUserEntriesSince(ctx, userID, req.Since)
	if err != nil {
		h.logger.Error("Failed to get user entries", "error", err, "user_id", userID)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Конвертируем в API формат
	apiEntries := make([]api.CRDTEntry, 0, len(entries))
	maxTimestamp := req.Since

	for _, entry := range entries {
		apiEntry := api.CRDTEntry{
			ID:        entry.ID,
			UserID:    entry.UserID,
			DataType:  entry.Type,
			Data:      entry.Data,
			Metadata:  string(entry.Metadata),
			Timestamp: entry.Timestamp,
			Deleted:   entry.Deleted,
			CreatedAt: entry.CreatedAt,
			UpdatedAt: entry.UpdatedAt,
		}
		apiEntries = append(apiEntries, apiEntry)

		if entry.Timestamp > maxTimestamp {
			maxTimestamp = entry.Timestamp
		}
	}

	// Формируем ответ
	response := api.SyncResponse{
		Entries:          apiEntries,
		CurrentTimestamp: maxTimestamp,
		Conflicts:        conflicts,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode response", "error", err)
	}

	h.logger.Info("POST sync completed",
		"user_id", userID,
		"received_entries", len(req.Entries),
		"returned_entries", len(apiEntries),
		"conflicts", conflicts)
}
