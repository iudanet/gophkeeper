package sync

import (
	"context"
	"fmt"
	"log/slog"

	httpClient "github.com/iudanet/gophkeeper/internal/client/api"
	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/models"
	"github.com/iudanet/gophkeeper/pkg/api"
)

//go:generate moq -out service_mock.go . Service

// Service определяет интерфейс для sync.Service
type Service interface {
	// Sync выполняет полную синхронизацию с сервером
	Sync(ctx context.Context, userID, accessToken string) (*SyncResult, error)

	// GetPendingSyncCount возвращает количество записей, ожидающих синхронизации
	GetPendingSyncCount(ctx context.Context) (int, error)
}

// Service handles synchronization between client and server
type service struct {
	apiClient       httpClient.ClientAPI
	crdtStorage     storage.CRDTStorage
	metadataStorage storage.MetadataStorage
	logger          *slog.Logger
}

// NewService creates a new sync service
func NewService(apiClient httpClient.ClientAPI, crdtStorage storage.CRDTStorage, metadataStorage storage.MetadataStorage, logger *slog.Logger) Service {
	return &service{
		apiClient:       apiClient,
		crdtStorage:     crdtStorage,
		metadataStorage: metadataStorage,
		logger:          logger,
	}
}

// SyncResult contains sync operation results
type SyncResult struct {
	PushedEntries  int // количество отправленных на сервер записей
	PulledEntries  int // количество полученных с сервера записей
	MergedEntries  int // количество успешно слитых записей
	Conflicts      int // количество разрешённых конфликтов
	SkippedEntries int // количество пропущенных записей (ошибки мержа)
}

// Sync performs full synchronization with server
// 1. Pushes local changes to server
// 2. Pulls server changes
// 3. Merges server changes into local storage using CRDT rules
func (s *service) Sync(ctx context.Context, userID, accessToken string) (*SyncResult, error) {
	s.logger.Info("Starting synchronization", "user_id", userID)

	result := &SyncResult{}

	// Получаем last known server timestamp из metadata storage
	lastSyncTimestamp, err := s.metadataStorage.GetLastSyncTimestamp(ctx)
	if err != nil {
		s.logger.Warn("Failed to get last sync timestamp, using 0", "error", err)
		lastSyncTimestamp = 0
	}

	// Получаем локальные изменения после последней синхронизации
	localEntries, err := s.crdtStorage.GetEntriesAfterTimestamp(ctx, lastSyncTimestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to get local entries: %w", err)
	}

	s.logger.Info("Collected local changes", "count", len(localEntries))
	result.PushedEntries = len(localEntries)

	// Конвертируем локальные entries в API формат
	apiEntries := make([]api.CRDTEntry, 0, len(localEntries))
	for _, entry := range localEntries {
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
	}

	// Отправляем запрос на синхронизацию
	syncReq := api.SyncRequest{
		Entries: apiEntries,
		Since:   lastSyncTimestamp,
	}

	syncResp, err := s.apiClient.Sync(ctx, accessToken, syncReq)
	if err != nil {
		return nil, fmt.Errorf("sync request failed: %w", err)
	}

	s.logger.Info("Received server response",
		"server_entries", len(syncResp.Entries),
		"conflicts", syncResp.Conflicts,
		"server_timestamp", syncResp.CurrentTimestamp)

	result.PulledEntries = len(syncResp.Entries)
	result.Conflicts = syncResp.Conflicts

	// Мержим изменения с сервера в локальное хранилище
	for _, apiEntry := range syncResp.Entries {
		// Конвертируем API entry в models.CRDTEntry
		entry := &models.CRDTEntry{
			ID:        apiEntry.ID,
			UserID:    apiEntry.UserID,
			Type:      apiEntry.DataType,
			Data:      apiEntry.Data,
			Metadata:  []byte(apiEntry.Metadata),
			Timestamp: apiEntry.Timestamp,
			Deleted:   apiEntry.Deleted,
			CreatedAt: apiEntry.CreatedAt,
			UpdatedAt: apiEntry.UpdatedAt,
			// NodeID и Version берутся из серверной записи
		}

		// Применяем CRDT merge: SaveEntry использует LWW (Last-Write-Wins) логику
		// Запись сохранится только если её timestamp больше существующей
		updated, err := s.mergeEntry(ctx, entry)
		if err != nil {
			s.logger.Warn("Failed to merge entry",
				"entry_id", entry.ID,
				"error", err)
			result.SkippedEntries++
			continue
		}

		if updated {
			result.MergedEntries++
		}
	}

	s.logger.Info("Synchronization completed",
		"pushed", result.PushedEntries,
		"pulled", result.PulledEntries,
		"merged", result.MergedEntries,
		"skipped", result.SkippedEntries,
		"conflicts", result.Conflicts)

	// Сохраняем текущий server timestamp для следующей синхронизации
	if err := s.metadataStorage.SaveLastSyncTimestamp(ctx, syncResp.CurrentTimestamp); err != nil {
		s.logger.Warn("Failed to save last sync timestamp", "error", err)
		// Не прерываем синхронизацию из-за ошибки сохранения timestamp
	}

	return result, nil
}

// mergeEntry применяет CRDT правила для слияния записи
// Использует LWW-Element-Set с (timestamp, node_id) для разрешения конфликтов
// Возвращает (updated bool, err error) где updated указывает была ли запись обновлена
func (s *service) mergeEntry(ctx context.Context, newEntry *models.CRDTEntry) (bool, error) {
	// Пытаемся получить существующую запись
	existingEntry, err := s.crdtStorage.GetEntry(ctx, newEntry.ID)
	if err != nil {
		// Если записи нет - просто сохраняем новую
		if err == storage.ErrEntryNotFound {
			return true, s.crdtStorage.SaveEntry(ctx, newEntry)
		}
		return false, fmt.Errorf("failed to get existing entry: %w", err)
	}

	// Применяем LWW правила:
	// 1. Сравниваем timestamps
	// 2. Если timestamps равны - сравниваем NodeID (детерминированно)
	shouldUpdate := false

	if newEntry.Timestamp > existingEntry.Timestamp {
		// Новая запись более свежая
		shouldUpdate = true
	} else if newEntry.Timestamp == existingEntry.Timestamp {
		// Timestamps равны - используем NodeID для детерминированного выбора
		// Используем лексикографическое сравнение NodeID
		if newEntry.NodeID > existingEntry.NodeID {
			shouldUpdate = true
		}
	}

	// Обновляем только если новая запись побеждает
	if shouldUpdate {
		s.logger.Debug("Merging entry (new wins)",
			"entry_id", newEntry.ID,
			"new_timestamp", newEntry.Timestamp,
			"old_timestamp", existingEntry.Timestamp)
		return true, s.crdtStorage.SaveEntry(ctx, newEntry)
	}

	s.logger.Debug("Skipping entry (existing is newer)",
		"entry_id", newEntry.ID,
		"new_timestamp", newEntry.Timestamp,
		"old_timestamp", existingEntry.Timestamp)

	return false, nil
}

// GetPendingSyncCount возвращает количество записей, ожидающих синхронизации
// Использует lastSyncTimestamp из metadata storage для определения несинхронизированных записей
func (s *service) GetPendingSyncCount(ctx context.Context) (int, error) {
	// Получаем last sync timestamp
	lastSyncTimestamp, err := s.metadataStorage.GetLastSyncTimestamp(ctx)
	if err != nil {
		// Если timestamp не найден (первая синхронизация), используем 0
		s.logger.Debug("No last sync timestamp found, using 0", "error", err)
		lastSyncTimestamp = 0
	}

	// Получаем все записи после последней синхронизации
	entries, err := s.crdtStorage.GetEntriesAfterTimestamp(ctx, lastSyncTimestamp)
	if err != nil {
		return 0, fmt.Errorf("failed to get pending entries: %w", err)
	}

	return len(entries), nil
}
