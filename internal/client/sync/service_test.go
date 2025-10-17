package sync

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/models"
	"github.com/iudanet/gophkeeper/pkg/api"
)

func TestNewService(t *testing.T) {
	mockAPI := &APIClientMock{
		SyncFunc: func(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error) {
			return &api.SyncResponse{}, nil
		},
	}

	entries := make(map[string]*models.CRDTEntry)
	mockStorage := &storage.CRDTStorageMock{
		GetEntriesAfterTimestampFunc: func(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
			result := []*models.CRDTEntry{}
			for _, entry := range entries {
				if entry.Timestamp > timestamp {
					result = append(result, entry)
				}
			}
			return result, nil
		},
		SaveEntryFunc: func(ctx context.Context, entry *models.CRDTEntry) error {
			entries[entry.ID] = entry
			return nil
		},
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			if entry, ok := entries[id]; ok {
				return entry, nil
			}
			return nil, storage.ErrEntryNotFound
		},
	}

	var lastSyncTimestamp int64
	mockMetadata := &MetadataStorageMock{
		GetLastSyncTimestampFunc: func(ctx context.Context) (int64, error) {
			return lastSyncTimestamp, nil
		},
		SaveLastSyncTimestampFunc: func(ctx context.Context, timestamp int64) error {
			lastSyncTimestamp = timestamp
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	service := NewService(mockAPI, mockStorage, mockMetadata, logger)

	assert.NotNil(t, service)
	assert.Equal(t, mockAPI, service.apiClient)
	assert.Equal(t, mockStorage, service.crdtStorage)
	assert.Equal(t, mockMetadata, service.metadataStorage)
	assert.Equal(t, logger, service.logger)
}

func TestSync_EmptyLocal_EmptyServer(t *testing.T) {
	mockAPI := &APIClientMock{
		SyncFunc: func(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error) {
			return &api.SyncResponse{
				Entries:          []api.CRDTEntry{},
				CurrentTimestamp: 0,
				Conflicts:        0,
			}, nil
		},
	}

	entries := make(map[string]*models.CRDTEntry)
	mockStorage := &storage.CRDTStorageMock{
		GetEntriesAfterTimestampFunc: func(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
			result := []*models.CRDTEntry{}
			for _, entry := range entries {
				if entry.Timestamp > timestamp {
					result = append(result, entry)
				}
			}
			return result, nil
		},
		SaveEntryFunc: func(ctx context.Context, entry *models.CRDTEntry) error {
			entries[entry.ID] = entry
			return nil
		},
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			if entry, ok := entries[id]; ok {
				return entry, nil
			}
			return nil, storage.ErrEntryNotFound
		},
	}

	var lastSyncTimestamp int64
	mockMetadata := &MetadataStorageMock{
		GetLastSyncTimestampFunc: func(ctx context.Context) (int64, error) {
			return lastSyncTimestamp, nil
		},
		SaveLastSyncTimestampFunc: func(ctx context.Context, timestamp int64) error {
			lastSyncTimestamp = timestamp
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockAPI, mockStorage, mockMetadata, logger)

	ctx := context.Background()
	userID := "user-123"
	accessToken := "token-abc"

	result, err := service.Sync(ctx, userID, accessToken)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.PushedEntries)
	assert.Equal(t, 0, result.PulledEntries)
	assert.Equal(t, 0, result.MergedEntries)
	assert.Equal(t, 0, result.Conflicts)
	assert.Equal(t, 0, result.SkippedEntries)
	assert.Len(t, mockAPI.SyncCalls(), 1)
}

func TestSync_PushLocalEntries(t *testing.T) {
	mockAPI := &APIClientMock{
		SyncFunc: func(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error) {
			return &api.SyncResponse{
				Entries:          []api.CRDTEntry{},
				CurrentTimestamp: 200,
				Conflicts:        0,
			}, nil
		},
	}

	userID := "user-123"
	entries := make(map[string]*models.CRDTEntry)

	// Добавляем локальные entries
	localEntry1 := &models.CRDTEntry{
		ID:        "entry-1",
		UserID:    userID,
		Type:      models.DataTypeCredential,
		Data:      []byte("encrypted-data-1"),
		Metadata:  []byte("encrypted-metadata-1"),
		Timestamp: 100,
		Deleted:   false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	localEntry2 := &models.CRDTEntry{
		ID:        "entry-2",
		UserID:    userID,
		Type:      models.DataTypeCredential,
		Data:      []byte("encrypted-data-2"),
		Metadata:  []byte("encrypted-metadata-2"),
		Timestamp: 200,
		Deleted:   false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	entries["entry-1"] = localEntry1
	entries["entry-2"] = localEntry2

	mockStorage := &storage.CRDTStorageMock{
		GetEntriesAfterTimestampFunc: func(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
			result := []*models.CRDTEntry{}
			for _, entry := range entries {
				if entry.Timestamp > timestamp {
					result = append(result, entry)
				}
			}
			return result, nil
		},
		SaveEntryFunc: func(ctx context.Context, entry *models.CRDTEntry) error {
			entries[entry.ID] = entry
			return nil
		},
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			if entry, ok := entries[id]; ok {
				return entry, nil
			}
			return nil, storage.ErrEntryNotFound
		},
	}

	var lastSyncTimestamp int64
	mockMetadata := &MetadataStorageMock{
		GetLastSyncTimestampFunc: func(ctx context.Context) (int64, error) {
			return lastSyncTimestamp, nil
		},
		SaveLastSyncTimestampFunc: func(ctx context.Context, timestamp int64) error {
			lastSyncTimestamp = timestamp
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockAPI, mockStorage, mockMetadata, logger)

	ctx := context.Background()
	accessToken := "token-abc"

	result, err := service.Sync(ctx, userID, accessToken)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 2, result.PushedEntries)
	assert.Equal(t, 0, result.PulledEntries)
	assert.Equal(t, 0, result.MergedEntries)

	// Проверяем что API был вызван с правильными entries
	assert.Len(t, mockAPI.SyncCalls(), 1)
	assert.Len(t, mockAPI.SyncCalls()[0].Req.Entries, 2)
}

func TestSync_PullServerEntries(t *testing.T) {
	entries := make(map[string]*models.CRDTEntry)
	mockStorage := &storage.CRDTStorageMock{
		GetEntriesAfterTimestampFunc: func(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
			result := []*models.CRDTEntry{}
			for _, entry := range entries {
				if entry.Timestamp > timestamp {
					result = append(result, entry)
				}
			}
			return result, nil
		},
		SaveEntryFunc: func(ctx context.Context, entry *models.CRDTEntry) error {
			entries[entry.ID] = entry
			return nil
		},
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			if entry, ok := entries[id]; ok {
				return entry, nil
			}
			return nil, storage.ErrEntryNotFound
		},
	}

	var lastSyncTimestamp int64
	mockMetadata := &MetadataStorageMock{
		GetLastSyncTimestampFunc: func(ctx context.Context) (int64, error) {
			return lastSyncTimestamp, nil
		},
		SaveLastSyncTimestampFunc: func(ctx context.Context, timestamp int64) error {
			lastSyncTimestamp = timestamp
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Мокаем API с серверными entries
	mockAPI := &APIClientMock{
		SyncFunc: func(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error) {
			return &api.SyncResponse{
				Entries: []api.CRDTEntry{
					{
						ID:        "server-entry-1",
						UserID:    "user-123",
						DataType:  models.DataTypeCredential,
						Data:      []byte("server-data-1"),
						Metadata:  "server-metadata-1",
						Timestamp: 300,
						Deleted:   false,
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					},
					{
						ID:        "server-entry-2",
						UserID:    "user-123",
						DataType:  models.DataTypeCredential,
						Data:      []byte("server-data-2"),
						Metadata:  "server-metadata-2",
						Timestamp: 400,
						Deleted:   false,
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					},
				},
				CurrentTimestamp: 400,
				Conflicts:        0,
			}, nil
		},
	}

	service := NewService(mockAPI, mockStorage, mockMetadata, logger)

	ctx := context.Background()
	userID := "user-123"
	accessToken := "token-abc"

	result, err := service.Sync(ctx, userID, accessToken)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.PushedEntries)
	assert.Equal(t, 2, result.PulledEntries)
	assert.Equal(t, 2, result.MergedEntries)
	assert.Equal(t, 0, result.Conflicts)

	// Проверяем что entries сохранились локально
	assert.Len(t, entries, 2)
	assert.NotNil(t, entries["server-entry-1"])
	assert.NotNil(t, entries["server-entry-2"])
}

func TestSync_MergeWithConflict_NewerWins(t *testing.T) {
	userID := "user-123"
	entries := make(map[string]*models.CRDTEntry)

	// Добавляем локальную запись
	localEntry := &models.CRDTEntry{
		ID:        "entry-conflict",
		UserID:    userID,
		Type:      models.DataTypeCredential,
		Data:      []byte("local-data"),
		Metadata:  []byte("local-metadata"),
		Timestamp: 100,
		NodeID:    "node-A",
		Deleted:   false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	entries["entry-conflict"] = localEntry

	mockStorage := &storage.CRDTStorageMock{
		GetEntriesAfterTimestampFunc: func(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
			result := []*models.CRDTEntry{}
			for _, entry := range entries {
				if entry.Timestamp > timestamp {
					result = append(result, entry)
				}
			}
			return result, nil
		},
		SaveEntryFunc: func(ctx context.Context, entry *models.CRDTEntry) error {
			entries[entry.ID] = entry
			return nil
		},
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			if entry, ok := entries[id]; ok {
				return entry, nil
			}
			return nil, storage.ErrEntryNotFound
		},
	}

	var lastSyncTimestamp int64
	mockMetadata := &MetadataStorageMock{
		GetLastSyncTimestampFunc: func(ctx context.Context) (int64, error) {
			return lastSyncTimestamp, nil
		},
		SaveLastSyncTimestampFunc: func(ctx context.Context, timestamp int64) error {
			lastSyncTimestamp = timestamp
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Мокаем API с более новой серверной записью
	mockAPI := &APIClientMock{
		SyncFunc: func(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error) {
			return &api.SyncResponse{
				Entries: []api.CRDTEntry{
					{
						ID:        "entry-conflict",
						UserID:    "user-123",
						DataType:  models.DataTypeCredential,
						Data:      []byte("server-data-newer"),
						Metadata:  "server-metadata-newer",
						Timestamp: 200, // Newer timestamp
						Deleted:   false,
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					},
				},
				CurrentTimestamp: 200,
				Conflicts:        1,
			}, nil
		},
	}

	service := NewService(mockAPI, mockStorage, mockMetadata, logger)

	ctx := context.Background()
	result, err := service.Sync(ctx, "user-123", "token-abc")

	require.NoError(t, err)
	assert.Equal(t, 1, result.PulledEntries)
	assert.Equal(t, 1, result.MergedEntries)
	assert.Equal(t, 1, result.Conflicts)

	// Проверяем что сохранилась более новая версия с сервера
	savedEntry := entries["entry-conflict"]
	assert.NotNil(t, savedEntry)
	assert.Equal(t, int64(200), savedEntry.Timestamp)
	assert.Equal(t, []byte("server-data-newer"), savedEntry.Data)
}

func TestSync_MergeWithConflict_OlderSkipped(t *testing.T) {
	userID := "user-123"
	entries := make(map[string]*models.CRDTEntry)

	// Добавляем локальную запись с более новым timestamp
	localEntry := &models.CRDTEntry{
		ID:        "entry-conflict",
		UserID:    userID,
		Type:      models.DataTypeCredential,
		Data:      []byte("local-data-newer"),
		Metadata:  []byte("local-metadata-newer"),
		Timestamp: 300,
		NodeID:    "node-A",
		Deleted:   false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	entries["entry-conflict"] = localEntry

	mockStorage := &storage.CRDTStorageMock{
		GetEntriesAfterTimestampFunc: func(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
			result := []*models.CRDTEntry{}
			for _, entry := range entries {
				if entry.Timestamp > timestamp {
					result = append(result, entry)
				}
			}
			return result, nil
		},
		SaveEntryFunc: func(ctx context.Context, entry *models.CRDTEntry) error {
			entries[entry.ID] = entry
			return nil
		},
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			if entry, ok := entries[id]; ok {
				return entry, nil
			}
			return nil, storage.ErrEntryNotFound
		},
	}

	var lastSyncTimestamp int64
	mockMetadata := &MetadataStorageMock{
		GetLastSyncTimestampFunc: func(ctx context.Context) (int64, error) {
			return lastSyncTimestamp, nil
		},
		SaveLastSyncTimestampFunc: func(ctx context.Context, timestamp int64) error {
			lastSyncTimestamp = timestamp
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Мокаем API с более старой серверной записью
	mockAPI := &APIClientMock{
		SyncFunc: func(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error) {
			return &api.SyncResponse{
				Entries: []api.CRDTEntry{
					{
						ID:        "entry-conflict",
						UserID:    "user-123",
						DataType:  models.DataTypeCredential,
						Data:      []byte("server-data-older"),
						Metadata:  "server-metadata-older",
						Timestamp: 100, // Older timestamp
						Deleted:   false,
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					},
				},
				CurrentTimestamp: 300,
				Conflicts:        0,
			}, nil
		},
	}

	service := NewService(mockAPI, mockStorage, mockMetadata, logger)

	ctx := context.Background()
	result, err := service.Sync(ctx, "user-123", "token-abc")

	require.NoError(t, err)
	assert.Equal(t, 1, result.PulledEntries)
	assert.Equal(t, 0, result.MergedEntries) // Не слились, так как локальная новее

	// Проверяем что локальная версия осталась
	savedEntry := entries["entry-conflict"]
	assert.NotNil(t, savedEntry)
	assert.Equal(t, int64(300), savedEntry.Timestamp)
	assert.Equal(t, []byte("local-data-newer"), savedEntry.Data)
}

func TestSync_MergeWithSameTimestamp_NodeIDComparison(t *testing.T) {
	userID := "user-123"
	entries := make(map[string]*models.CRDTEntry)

	// Добавляем локальную запись
	localEntry := &models.CRDTEntry{
		ID:        "entry-same-ts",
		UserID:    userID,
		Type:      models.DataTypeCredential,
		Data:      []byte("local-data"),
		Metadata:  []byte("local-metadata"),
		Timestamp: 200,
		NodeID:    "node-A",
		Deleted:   false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	entries["entry-same-ts"] = localEntry

	mockStorage := &storage.CRDTStorageMock{
		GetEntriesAfterTimestampFunc: func(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
			result := []*models.CRDTEntry{}
			for _, entry := range entries {
				if entry.Timestamp > timestamp {
					result = append(result, entry)
				}
			}
			return result, nil
		},
		SaveEntryFunc: func(ctx context.Context, entry *models.CRDTEntry) error {
			entries[entry.ID] = entry
			return nil
		},
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			if entry, ok := entries[id]; ok {
				return entry, nil
			}
			return nil, storage.ErrEntryNotFound
		},
	}

	var lastSyncTimestamp int64
	mockMetadata := &MetadataStorageMock{
		GetLastSyncTimestampFunc: func(ctx context.Context) (int64, error) {
			return lastSyncTimestamp, nil
		},
		SaveLastSyncTimestampFunc: func(ctx context.Context, timestamp int64) error {
			lastSyncTimestamp = timestamp
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Мокаем API с записью с тем же timestamp но большим NodeID
	mockAPI := &APIClientMock{
		SyncFunc: func(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error) {
			return &api.SyncResponse{
				Entries: []api.CRDTEntry{
					{
						ID:        "entry-same-ts",
						UserID:    "user-123",
						DataType:  models.DataTypeCredential,
						Data:      []byte("server-data"),
						Metadata:  "server-metadata",
						Timestamp: 200, // Same timestamp
						Deleted:   false,
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					},
				},
				CurrentTimestamp: 200,
				Conflicts:        0,
			}, nil
		},
	}

	service := NewService(mockAPI, mockStorage, mockMetadata, logger)

	ctx := context.Background()
	result, err := service.Sync(ctx, "user-123", "token-abc")

	require.NoError(t, err)
	assert.Equal(t, 1, result.PulledEntries)
	// NodeID "" (пустой) < "node-A", поэтому локальная останется
	assert.Equal(t, 0, result.MergedEntries)
}

func TestSync_APIError(t *testing.T) {
	entries := make(map[string]*models.CRDTEntry)
	mockStorage := &storage.CRDTStorageMock{
		GetEntriesAfterTimestampFunc: func(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
			result := []*models.CRDTEntry{}
			for _, entry := range entries {
				if entry.Timestamp > timestamp {
					result = append(result, entry)
				}
			}
			return result, nil
		},
		SaveEntryFunc: func(ctx context.Context, entry *models.CRDTEntry) error {
			entries[entry.ID] = entry
			return nil
		},
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			if entry, ok := entries[id]; ok {
				return entry, nil
			}
			return nil, storage.ErrEntryNotFound
		},
	}

	var lastSyncTimestamp int64
	mockMetadata := &MetadataStorageMock{
		GetLastSyncTimestampFunc: func(ctx context.Context) (int64, error) {
			return lastSyncTimestamp, nil
		},
		SaveLastSyncTimestampFunc: func(ctx context.Context, timestamp int64) error {
			lastSyncTimestamp = timestamp
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	mockAPI := &APIClientMock{
		SyncFunc: func(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error) {
			return nil, errors.New("network error")
		},
	}

	service := NewService(mockAPI, mockStorage, mockMetadata, logger)

	ctx := context.Background()
	result, err := service.Sync(ctx, "user-123", "token-abc")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "sync request failed")
}

func TestSync_GetEntriesError(t *testing.T) {
	mockAPI := &APIClientMock{
		SyncFunc: func(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error) {
			return &api.SyncResponse{}, nil
		},
	}

	mockStorage := &storage.CRDTStorageMock{
		GetEntriesAfterTimestampFunc: func(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
			return nil, errors.New("storage error")
		},
	}

	var lastSyncTimestamp int64
	mockMetadata := &MetadataStorageMock{
		GetLastSyncTimestampFunc: func(ctx context.Context) (int64, error) {
			return lastSyncTimestamp, nil
		},
		SaveLastSyncTimestampFunc: func(ctx context.Context, timestamp int64) error {
			lastSyncTimestamp = timestamp
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockAPI, mockStorage, mockMetadata, logger)

	ctx := context.Background()
	result, err := service.Sync(ctx, "user-123", "token-abc")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to get local entries")
}

func TestSync_SaveEntryError(t *testing.T) {
	entries := make(map[string]*models.CRDTEntry)
	mockStorage := &storage.CRDTStorageMock{
		GetEntriesAfterTimestampFunc: func(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
			result := []*models.CRDTEntry{}
			for _, entry := range entries {
				if entry.Timestamp > timestamp {
					result = append(result, entry)
				}
			}
			return result, nil
		},
		SaveEntryFunc: func(ctx context.Context, entry *models.CRDTEntry) error {
			return errors.New("save error")
		},
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			if entry, ok := entries[id]; ok {
				return entry, nil
			}
			return nil, storage.ErrEntryNotFound
		},
	}

	var lastSyncTimestamp int64
	mockMetadata := &MetadataStorageMock{
		GetLastSyncTimestampFunc: func(ctx context.Context) (int64, error) {
			return lastSyncTimestamp, nil
		},
		SaveLastSyncTimestampFunc: func(ctx context.Context, timestamp int64) error {
			lastSyncTimestamp = timestamp
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Мокаем API с серверными entries
	mockAPI := &APIClientMock{
		SyncFunc: func(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error) {
			return &api.SyncResponse{
				Entries: []api.CRDTEntry{
					{
						ID:        "server-entry",
						UserID:    "user-123",
						DataType:  models.DataTypeCredential,
						Data:      []byte("server-data"),
						Metadata:  "server-metadata",
						Timestamp: 100,
						Deleted:   false,
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					},
				},
				CurrentTimestamp: 100,
				Conflicts:        0,
			}, nil
		},
	}

	service := NewService(mockAPI, mockStorage, mockMetadata, logger)

	ctx := context.Background()
	result, err := service.Sync(ctx, "user-123", "token-abc")

	// Sync не должен падать, а должен пропустить проблемные entries
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, result.PulledEntries)
	assert.Equal(t, 0, result.MergedEntries)
	assert.Equal(t, 1, result.SkippedEntries)
}

func TestGetPendingSyncCount_NoEntries(t *testing.T) {
	mockAPI := &APIClientMock{
		SyncFunc: func(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error) {
			return &api.SyncResponse{}, nil
		},
	}

	entries := make(map[string]*models.CRDTEntry)
	mockStorage := &storage.CRDTStorageMock{
		GetEntriesAfterTimestampFunc: func(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
			result := []*models.CRDTEntry{}
			for _, entry := range entries {
				if entry.Timestamp > timestamp {
					result = append(result, entry)
				}
			}
			return result, nil
		},
	}

	var lastSyncTimestamp int64
	mockMetadata := &MetadataStorageMock{
		GetLastSyncTimestampFunc: func(ctx context.Context) (int64, error) {
			return lastSyncTimestamp, nil
		},
		SaveLastSyncTimestampFunc: func(ctx context.Context, timestamp int64) error {
			lastSyncTimestamp = timestamp
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockAPI, mockStorage, mockMetadata, logger)
	ctx := context.Background()

	count, err := service.GetPendingSyncCount(ctx)

	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestGetPendingSyncCount_WithPendingEntries(t *testing.T) {
	mockAPI := &APIClientMock{
		SyncFunc: func(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error) {
			return &api.SyncResponse{}, nil
		},
	}

	entries := make(map[string]*models.CRDTEntry)

	// Добавляем записи с timestamp > 100 (pending)
	entry1 := &models.CRDTEntry{
		ID:        "entry-1",
		UserID:    "user-123",
		Type:      models.DataTypeCredential,
		Data:      []byte("data-1"),
		Timestamp: 150,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	entry2 := &models.CRDTEntry{
		ID:        "entry-2",
		UserID:    "user-123",
		Type:      models.DataTypeCredential,
		Data:      []byte("data-2"),
		Timestamp: 200,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	// Добавляем запись с timestamp <= 100 (уже синхронизирована)
	entry3 := &models.CRDTEntry{
		ID:        "entry-3",
		UserID:    "user-123",
		Type:      models.DataTypeCredential,
		Data:      []byte("data-3"),
		Timestamp: 50,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	entries["entry-1"] = entry1
	entries["entry-2"] = entry2
	entries["entry-3"] = entry3

	mockStorage := &storage.CRDTStorageMock{
		GetEntriesAfterTimestampFunc: func(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
			result := []*models.CRDTEntry{}
			for _, entry := range entries {
				if entry.Timestamp > timestamp {
					result = append(result, entry)
				}
			}
			return result, nil
		},
	}

	var lastSyncTimestamp int64 = 100
	mockMetadata := &MetadataStorageMock{
		GetLastSyncTimestampFunc: func(ctx context.Context) (int64, error) {
			return lastSyncTimestamp, nil
		},
		SaveLastSyncTimestampFunc: func(ctx context.Context, timestamp int64) error {
			lastSyncTimestamp = timestamp
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockAPI, mockStorage, mockMetadata, logger)
	ctx := context.Background()

	count, err := service.GetPendingSyncCount(ctx)

	require.NoError(t, err)
	assert.Equal(t, 2, count) // Только entry-1 и entry-2
}

func TestGetPendingSyncCount_NoLastSyncTimestamp(t *testing.T) {
	mockAPI := &APIClientMock{
		SyncFunc: func(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error) {
			return &api.SyncResponse{}, nil
		},
	}

	entries := make(map[string]*models.CRDTEntry)

	// Добавляем записи
	entry1 := &models.CRDTEntry{
		ID:        "entry-1",
		UserID:    "user-123",
		Type:      models.DataTypeCredential,
		Data:      []byte("data-1"),
		Timestamp: 100,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	entries["entry-1"] = entry1

	mockStorage := &storage.CRDTStorageMock{
		GetEntriesAfterTimestampFunc: func(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
			result := []*models.CRDTEntry{}
			for _, entry := range entries {
				if entry.Timestamp > timestamp {
					result = append(result, entry)
				}
			}
			return result, nil
		},
	}

	mockMetadata := &MetadataStorageMock{
		GetLastSyncTimestampFunc: func(ctx context.Context) (int64, error) {
			return 0, errors.New("timestamp not found")
		},
		SaveLastSyncTimestampFunc: func(ctx context.Context, timestamp int64) error {
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockAPI, mockStorage, mockMetadata, logger)
	ctx := context.Background()

	count, err := service.GetPendingSyncCount(ctx)

	// При отсутствии lastSyncTimestamp используется 0, все записи считаются pending
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestGetPendingSyncCount_StorageError(t *testing.T) {
	mockAPI := &APIClientMock{
		SyncFunc: func(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error) {
			return &api.SyncResponse{}, nil
		},
	}

	mockStorage := &storage.CRDTStorageMock{
		GetEntriesAfterTimestampFunc: func(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
			return nil, errors.New("storage error")
		},
	}

	var lastSyncTimestamp int64
	mockMetadata := &MetadataStorageMock{
		GetLastSyncTimestampFunc: func(ctx context.Context) (int64, error) {
			return lastSyncTimestamp, nil
		},
		SaveLastSyncTimestampFunc: func(ctx context.Context, timestamp int64) error {
			lastSyncTimestamp = timestamp
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockAPI, mockStorage, mockMetadata, logger)
	ctx := context.Background()

	count, err := service.GetPendingSyncCount(ctx)

	require.Error(t, err)
	assert.Equal(t, 0, count)
	assert.Contains(t, err.Error(), "failed to get pending entries")
}
