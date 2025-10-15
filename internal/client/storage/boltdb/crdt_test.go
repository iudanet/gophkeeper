package boltdb

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/models"
)

// createTestStorage создает временное хранилище для тестов
func createTestCRDTStorage(t *testing.T) (*Storage, func()) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	ctx := context.Background()
	store, err := New(ctx, dbPath)
	require.NoError(t, err)
	require.NotNil(t, store)

	cleanup := func() {
		if store.db != nil {
			err := store.Close()
			require.NoError(t, err)
		}
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Errorf("failed to remove tmpDir: %v", err)
		}
	}

	return store, cleanup
}

// createTestEntry создает тестовую CRDT запись
func createTestEntry(id, userID, nodeID string, timestamp int64, deleted bool) *models.CRDTEntry {
	now := time.Now()
	return &models.CRDTEntry{
		ID:        id,
		UserID:    userID,
		Type:      models.DataTypeCredential,
		NodeID:    nodeID,
		Data:      []byte("encrypted-data-" + id),
		Metadata:  []byte("encrypted-metadata-" + id),
		Version:   1,
		Timestamp: timestamp,
		Deleted:   deleted,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func TestStorage_SaveEntry(t *testing.T) {
	tests := []struct {
		entry   *models.CRDTEntry
		name    string
		wantErr bool
	}{
		{
			name: "successful save credential",
			entry: createTestEntry(
				"entry-1",
				"user-123",
				"node-1",
				1000,
				false,
			),
			wantErr: false,
		},
		{
			name: "successful save with different type",
			entry: &models.CRDTEntry{
				ID:        "entry-2",
				UserID:    "user-123",
				Type:      models.DataTypeText,
				NodeID:    "node-1",
				Data:      []byte("text-data"),
				Metadata:  []byte("text-metadata"),
				Version:   1,
				Timestamp: 2000,
				Deleted:   false,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			wantErr: false,
		},
		{
			name: "successful save deleted entry",
			entry: createTestEntry(
				"entry-3",
				"user-123",
				"node-1",
				3000,
				true, // deleted
			),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, cleanup := createTestCRDTStorage(t)
			defer cleanup()

			ctx := context.Background()
			err := store.SaveEntry(ctx, tt.entry)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Проверяем, что запись можно получить обратно
			retrieved, err := store.GetEntry(ctx, tt.entry.ID)
			require.NoError(t, err)
			assert.Equal(t, tt.entry.ID, retrieved.ID)
			assert.Equal(t, tt.entry.UserID, retrieved.UserID)
			assert.Equal(t, tt.entry.Type, retrieved.Type)
			assert.Equal(t, tt.entry.NodeID, retrieved.NodeID)
			assert.Equal(t, tt.entry.Data, retrieved.Data)
			assert.Equal(t, tt.entry.Metadata, retrieved.Metadata)
			assert.Equal(t, tt.entry.Version, retrieved.Version)
			assert.Equal(t, tt.entry.Timestamp, retrieved.Timestamp)
			assert.Equal(t, tt.entry.Deleted, retrieved.Deleted)
		})
	}
}

func TestStorage_SaveEntry_Update(t *testing.T) {
	// Тест проверяет обновление существующей записи
	store, cleanup := createTestCRDTStorage(t)
	defer cleanup()

	ctx := context.Background()
	entryID := "entry-update-test"

	// Сохраняем первую версию
	entry1 := createTestEntry(entryID, "user-123", "node-1", 1000, false)
	err := store.SaveEntry(ctx, entry1)
	require.NoError(t, err)

	// Обновляем запись (новый timestamp)
	entry2 := createTestEntry(entryID, "user-123", "node-2", 2000, false)
	entry2.Data = []byte("updated-data")
	entry2.Version = 2
	err = store.SaveEntry(ctx, entry2)
	require.NoError(t, err)

	// Проверяем, что получаем обновленную версию
	retrieved, err := store.GetEntry(ctx, entryID)
	require.NoError(t, err)
	assert.Equal(t, entry2.Data, retrieved.Data)
	assert.Equal(t, entry2.Version, retrieved.Version)
	assert.Equal(t, entry2.Timestamp, retrieved.Timestamp)
	assert.Equal(t, entry2.NodeID, retrieved.NodeID)
}

func TestStorage_SaveEntry_ClosedDB(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	cleanup() // Закрываем сразу

	ctx := context.Background()
	entry := createTestEntry("entry-1", "user-123", "node-1", 1000, false)

	err := store.SaveEntry(ctx, entry)
	assert.ErrorIs(t, err, storage.ErrStorageClosed)
}

func TestStorage_GetEntry(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Сохраняем несколько записей
	entry1 := createTestEntry("entry-1", "user-123", "node-1", 1000, false)
	entry2 := createTestEntry("entry-2", "user-123", "node-1", 2000, false)

	err := store.SaveEntry(ctx, entry1)
	require.NoError(t, err)
	err = store.SaveEntry(ctx, entry2)
	require.NoError(t, err)

	tests := []struct {
		wantErr   error
		wantEntry *models.CRDTEntry
		name      string
		id        string
	}{
		{
			name:      "get existing entry 1",
			id:        "entry-1",
			wantEntry: entry1,
			wantErr:   nil,
		},
		{
			name:      "get existing entry 2",
			id:        "entry-2",
			wantEntry: entry2,
			wantErr:   nil,
		},
		{
			name:      "get non-existing entry",
			id:        "non-existing",
			wantEntry: nil,
			wantErr:   storage.ErrEntryNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrieved, err := store.GetEntry(ctx, tt.id)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, retrieved)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, retrieved)
			assert.Equal(t, tt.wantEntry.ID, retrieved.ID)
			assert.Equal(t, tt.wantEntry.Timestamp, retrieved.Timestamp)
		})
	}
}

func TestStorage_GetEntry_ClosedDB(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	cleanup() // Закрываем сразу

	ctx := context.Background()
	_, err := store.GetEntry(ctx, "entry-1")
	assert.ErrorIs(t, err, storage.ErrStorageClosed)
}

func TestStorage_GetAllEntries(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Тест на пустом хранилище
	entries, err := store.GetAllEntries(ctx)
	require.NoError(t, err)
	assert.Empty(t, entries)

	// Сохраняем несколько записей, включая удаленные
	entry1 := createTestEntry("entry-1", "user-123", "node-1", 1000, false)
	entry2 := createTestEntry("entry-2", "user-123", "node-1", 2000, true) // deleted
	entry3 := createTestEntry("entry-3", "user-456", "node-2", 3000, false)

	require.NoError(t, store.SaveEntry(ctx, entry1))
	require.NoError(t, store.SaveEntry(ctx, entry2))
	require.NoError(t, store.SaveEntry(ctx, entry3))

	// Получаем все записи
	entries, err = store.GetAllEntries(ctx)
	require.NoError(t, err)
	assert.Len(t, entries, 3)

	// Проверяем, что deleted записи тоже возвращаются
	deletedCount := 0
	for _, e := range entries {
		if e.Deleted {
			deletedCount++
		}
	}
	assert.Equal(t, 1, deletedCount)
}

func TestStorage_GetAllEntries_ClosedDB(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	cleanup() // Закрываем сразу

	ctx := context.Background()
	_, err := store.GetAllEntries(ctx)
	assert.ErrorIs(t, err, storage.ErrStorageClosed)
}

func TestStorage_GetEntriesAfterTimestamp(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Сохраняем записи с разными timestamp
	entry1 := createTestEntry("entry-1", "user-123", "node-1", 1000, false)
	entry2 := createTestEntry("entry-2", "user-123", "node-1", 2000, false)
	entry3 := createTestEntry("entry-3", "user-123", "node-1", 3000, false)
	entry4 := createTestEntry("entry-4", "user-123", "node-1", 4000, true) // deleted

	require.NoError(t, store.SaveEntry(ctx, entry1))
	require.NoError(t, store.SaveEntry(ctx, entry2))
	require.NoError(t, store.SaveEntry(ctx, entry3))
	require.NoError(t, store.SaveEntry(ctx, entry4))

	tests := []struct {
		name           string
		wantIDs        []string
		afterTimestamp int64
		wantCount      int
	}{
		{
			name:           "get all after timestamp 0",
			afterTimestamp: 0,
			wantCount:      4,
			wantIDs:        []string{"entry-1", "entry-2", "entry-3", "entry-4"},
		},
		{
			name:           "get entries after 1500",
			afterTimestamp: 1500,
			wantCount:      3,
			wantIDs:        []string{"entry-2", "entry-3", "entry-4"},
		},
		{
			name:           "get entries after 3000",
			afterTimestamp: 3000,
			wantCount:      1,
			wantIDs:        []string{"entry-4"},
		},
		{
			name:           "get entries after 5000",
			afterTimestamp: 5000,
			wantCount:      0,
			wantIDs:        []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := store.GetEntriesAfterTimestamp(ctx, tt.afterTimestamp)
			require.NoError(t, err)
			assert.Len(t, entries, tt.wantCount)

			// Проверяем ID записей
			gotIDs := make([]string, len(entries))
			for i, e := range entries {
				gotIDs[i] = e.ID
			}
			assert.ElementsMatch(t, tt.wantIDs, gotIDs)
		})
	}
}

func TestStorage_GetEntriesAfterTimestamp_ClosedDB(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	cleanup() // Закрываем сразу

	ctx := context.Background()
	_, err := store.GetEntriesAfterTimestamp(ctx, 1000)
	assert.ErrorIs(t, err, storage.ErrStorageClosed)
}

func TestStorage_GetActiveEntries(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Тест на пустом хранилище
	entries, err := store.GetActiveEntries(ctx)
	require.NoError(t, err)
	assert.Empty(t, entries)

	// Сохраняем записи (активные и удаленные)
	entry1 := createTestEntry("entry-1", "user-123", "node-1", 1000, false) // active
	entry2 := createTestEntry("entry-2", "user-123", "node-1", 2000, true)  // deleted
	entry3 := createTestEntry("entry-3", "user-123", "node-1", 3000, false) // active
	entry4 := createTestEntry("entry-4", "user-123", "node-1", 4000, true)  // deleted

	require.NoError(t, store.SaveEntry(ctx, entry1))
	require.NoError(t, store.SaveEntry(ctx, entry2))
	require.NoError(t, store.SaveEntry(ctx, entry3))
	require.NoError(t, store.SaveEntry(ctx, entry4))

	// Получаем только активные записи
	entries, err = store.GetActiveEntries(ctx)
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	// Проверяем, что все записи активные
	for _, e := range entries {
		assert.False(t, e.Deleted)
	}

	// Проверяем ID активных записей
	gotIDs := make([]string, len(entries))
	for i, e := range entries {
		gotIDs[i] = e.ID
	}
	assert.ElementsMatch(t, []string{"entry-1", "entry-3"}, gotIDs)
}

func TestStorage_GetActiveEntries_ClosedDB(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	cleanup() // Закрываем сразу

	ctx := context.Background()
	_, err := store.GetActiveEntries(ctx)
	assert.ErrorIs(t, err, storage.ErrStorageClosed)
}

func TestStorage_GetEntriesByType(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Сохраняем записи разных типов
	now := time.Now()
	credential1 := &models.CRDTEntry{
		ID:        "cred-1",
		UserID:    "user-123",
		Type:      models.DataTypeCredential,
		NodeID:    "node-1",
		Data:      []byte("cred-data-1"),
		Metadata:  []byte("cred-meta-1"),
		Version:   1,
		Timestamp: 1000,
		Deleted:   false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	credential2 := &models.CRDTEntry{
		ID:        "cred-2",
		UserID:    "user-123",
		Type:      models.DataTypeCredential,
		NodeID:    "node-1",
		Data:      []byte("cred-data-2"),
		Metadata:  []byte("cred-meta-2"),
		Version:   1,
		Timestamp: 2000,
		Deleted:   true, // deleted - не должна попасть в результат
		CreatedAt: now,
		UpdatedAt: now,
	}

	textEntry := &models.CRDTEntry{
		ID:        "text-1",
		UserID:    "user-123",
		Type:      models.DataTypeText,
		NodeID:    "node-1",
		Data:      []byte("text-data"),
		Metadata:  []byte("text-meta"),
		Version:   1,
		Timestamp: 3000,
		Deleted:   false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	binaryEntry := &models.CRDTEntry{
		ID:        "binary-1",
		UserID:    "user-123",
		Type:      models.DataTypeBinary,
		NodeID:    "node-1",
		Data:      []byte("binary-data"),
		Metadata:  []byte("binary-meta"),
		Version:   1,
		Timestamp: 4000,
		Deleted:   false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	require.NoError(t, store.SaveEntry(ctx, credential1))
	require.NoError(t, store.SaveEntry(ctx, credential2))
	require.NoError(t, store.SaveEntry(ctx, textEntry))
	require.NoError(t, store.SaveEntry(ctx, binaryEntry))

	tests := []struct {
		name      string
		dataType  string
		wantIDs   []string
		wantCount int
	}{
		{
			name:      "get credentials (excluding deleted)",
			dataType:  models.DataTypeCredential,
			wantCount: 1,
			wantIDs:   []string{"cred-1"}, // cred-2 deleted
		},
		{
			name:      "get text entries",
			dataType:  models.DataTypeText,
			wantCount: 1,
			wantIDs:   []string{"text-1"},
		},
		{
			name:      "get binary entries",
			dataType:  models.DataTypeBinary,
			wantCount: 1,
			wantIDs:   []string{"binary-1"},
		},
		{
			name:      "get card entries (none)",
			dataType:  models.DataTypeCard,
			wantCount: 0,
			wantIDs:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := store.GetEntriesByType(ctx, tt.dataType)
			require.NoError(t, err)
			assert.Len(t, entries, tt.wantCount)

			// Проверяем ID и типы записей
			gotIDs := make([]string, len(entries))
			for i, e := range entries {
				gotIDs[i] = e.ID
				assert.Equal(t, tt.dataType, e.Type)
				assert.False(t, e.Deleted) // Все должны быть активными
			}
			assert.ElementsMatch(t, tt.wantIDs, gotIDs)
		})
	}
}

func TestStorage_GetEntriesByType_ClosedDB(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	cleanup() // Закрываем сразу

	ctx := context.Background()
	_, err := store.GetEntriesByType(ctx, models.DataTypeCredential)
	assert.ErrorIs(t, err, storage.ErrStorageClosed)
}

func TestStorage_DeleteEntry(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Сохраняем запись
	entry := createTestEntry("entry-1", "user-123", "node-1", 1000, false)
	require.NoError(t, store.SaveEntry(ctx, entry))

	// Проверяем, что запись существует и активна
	retrieved, err := store.GetEntry(ctx, entry.ID)
	require.NoError(t, err)
	assert.False(t, retrieved.Deleted)
	assert.Equal(t, int64(1000), retrieved.Timestamp)
	assert.Equal(t, "node-1", retrieved.NodeID)

	// Удаляем запись (soft delete)
	newTimestamp := int64(2000)
	newNodeID := "node-2"
	err = store.DeleteEntry(ctx, entry.ID, newTimestamp, newNodeID)
	require.NoError(t, err)

	// Проверяем, что запись помечена как deleted
	deleted, err := store.GetEntry(ctx, entry.ID)
	require.NoError(t, err)
	assert.True(t, deleted.Deleted)
	assert.Equal(t, newTimestamp, deleted.Timestamp)
	assert.Equal(t, newNodeID, deleted.NodeID)

	// Проверяем, что запись не возвращается в GetActiveEntries
	active, err := store.GetActiveEntries(ctx)
	require.NoError(t, err)
	assert.Empty(t, active)

	// Но возвращается в GetAllEntries
	all, err := store.GetAllEntries(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 1)
	assert.True(t, all[0].Deleted)
}

func TestStorage_DeleteEntry_NotFound(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Пытаемся удалить несуществующую запись
	err := store.DeleteEntry(ctx, "non-existing", 1000, "node-1")
	assert.ErrorIs(t, err, storage.ErrEntryNotFound)
}

func TestStorage_DeleteEntry_ClosedDB(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	cleanup() // Закрываем сразу

	ctx := context.Background()
	err := store.DeleteEntry(ctx, "entry-1", 1000, "node-1")
	assert.ErrorIs(t, err, storage.ErrStorageClosed)
}

func TestStorage_GetMaxTimestamp(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Тест на пустом хранилище
	maxTS, err := store.GetMaxTimestamp(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), maxTS)

	// Сохраняем записи с разными timestamp
	entry1 := createTestEntry("entry-1", "user-123", "node-1", 1000, false)
	entry2 := createTestEntry("entry-2", "user-123", "node-1", 5000, false)
	entry3 := createTestEntry("entry-3", "user-123", "node-1", 3000, false)

	require.NoError(t, store.SaveEntry(ctx, entry1))
	require.NoError(t, store.SaveEntry(ctx, entry2))
	require.NoError(t, store.SaveEntry(ctx, entry3))

	// Проверяем максимальный timestamp
	maxTS, err = store.GetMaxTimestamp(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(5000), maxTS)

	// Добавляем запись с еще большим timestamp
	entry4 := createTestEntry("entry-4", "user-123", "node-1", 10000, false)
	require.NoError(t, store.SaveEntry(ctx, entry4))

	maxTS, err = store.GetMaxTimestamp(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(10000), maxTS)
}

func TestStorage_GetMaxTimestamp_ClosedDB(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	cleanup() // Закрываем сразу

	ctx := context.Background()
	_, err := store.GetMaxTimestamp(ctx)
	assert.ErrorIs(t, err, storage.ErrStorageClosed)
}

func TestStorage_Clear(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Сохраняем несколько записей
	entry1 := createTestEntry("entry-1", "user-123", "node-1", 1000, false)
	entry2 := createTestEntry("entry-2", "user-123", "node-1", 2000, false)
	entry3 := createTestEntry("entry-3", "user-123", "node-1", 3000, true)

	require.NoError(t, store.SaveEntry(ctx, entry1))
	require.NoError(t, store.SaveEntry(ctx, entry2))
	require.NoError(t, store.SaveEntry(ctx, entry3))

	// Проверяем, что записи существуют
	all, err := store.GetAllEntries(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 3)

	// Очищаем хранилище
	err = store.Clear(ctx)
	require.NoError(t, err)

	// Проверяем, что все записи удалены
	all, err = store.GetAllEntries(ctx)
	require.NoError(t, err)
	assert.Empty(t, all)

	// Проверяем, что можно добавлять новые записи после очистки
	newEntry := createTestEntry("new-entry", "user-123", "node-1", 4000, false)
	err = store.SaveEntry(ctx, newEntry)
	require.NoError(t, err)

	retrieved, err := store.GetEntry(ctx, "new-entry")
	require.NoError(t, err)
	assert.Equal(t, "new-entry", retrieved.ID)
}

func TestStorage_Clear_EmptyDB(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Очистка пустого хранилища не должна вызывать ошибку
	err := store.Clear(ctx)
	require.NoError(t, err)

	// Проверяем, что можно добавить запись после очистки пустого хранилища
	entry := createTestEntry("entry-1", "user-123", "node-1", 1000, false)
	err = store.SaveEntry(ctx, entry)
	require.NoError(t, err)
}

func TestStorage_Clear_ClosedDB(t *testing.T) {
	store, cleanup := createTestCRDTStorage(t)
	cleanup() // Закрываем сразу

	ctx := context.Background()
	err := store.Clear(ctx)
	assert.ErrorIs(t, err, storage.ErrStorageClosed)
}
