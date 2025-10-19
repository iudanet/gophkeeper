package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/gophkeeper/internal/models"
	"github.com/iudanet/gophkeeper/internal/server/storage"
)

func TestDataStorage_SaveEntry_Create(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	// Создаем тестового пользователя
	userID := createTestUser(t, ctx, s)

	tests := []struct {
		entry     *models.CRDTEntry
		name      string
		wantSaved bool
	}{
		{
			name: "save new credential entry",
			entry: &models.CRDTEntry{
				ID:        uuid.New().String(),
				UserID:    userID,
				Type:      models.DataTypeCredential,
				Data:      []byte("encrypted_credential_data"),
				Metadata:  []byte("encrypted_metadata"),
				Version:   1,
				Timestamp: 100,
				NodeID:    "node1",
				Deleted:   false,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			wantSaved: true,
		},
		{
			name: "save new text entry",
			entry: &models.CRDTEntry{
				ID:        uuid.New().String(),
				UserID:    userID,
				Type:      models.DataTypeText,
				Data:      []byte("encrypted_text_data"),
				Metadata:  []byte("encrypted_metadata"),
				Version:   1,
				Timestamp: 101,
				NodeID:    "node1",
				Deleted:   false,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			wantSaved: true,
		},
		{
			name: "save deleted entry",
			entry: &models.CRDTEntry{
				ID:        uuid.New().String(),
				UserID:    userID,
				Type:      models.DataTypeBinary,
				Data:      []byte("encrypted_binary_data"),
				Metadata:  []byte("encrypted_metadata"),
				Version:   1,
				Timestamp: 102,
				NodeID:    "node1",
				Deleted:   true,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			wantSaved: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saved, err := s.SaveEntry(ctx, tt.entry)
			require.NoError(t, err)
			assert.Equal(t, tt.wantSaved, saved)

			// Проверяем что запись сохранилась
			retrieved, err := s.GetEntry(ctx, tt.entry.ID)
			if tt.entry.Deleted {
				// Удаленные записи не должны возвращаться через GetEntry
				assert.ErrorIs(t, err, storage.ErrEntryNotFound)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.entry.ID, retrieved.ID)
				assert.Equal(t, tt.entry.UserID, retrieved.UserID)
				assert.Equal(t, tt.entry.Type, retrieved.Type)
				assert.Equal(t, tt.entry.Data, retrieved.Data)
				assert.Equal(t, tt.entry.Version, retrieved.Version)
				assert.Equal(t, tt.entry.Timestamp, retrieved.Timestamp)
			}
		})
	}
}

func TestDataStorage_SaveEntry_CRDT_Conflict(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	userID := createTestUser(t, ctx, s)
	entryID := uuid.New().String()

	// Создаем первую версию записи
	entry1 := &models.CRDTEntry{
		ID:        entryID,
		UserID:    userID,
		Type:      models.DataTypeCredential,
		Data:      []byte("version1"),
		Metadata:  []byte("metadata1"),
		Version:   1,
		Timestamp: 100,
		NodeID:    "node1",
		Deleted:   false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	saved, err := s.SaveEntry(ctx, entry1)
	require.NoError(t, err)
	assert.True(t, saved)

	tests := []struct {
		entry     *models.CRDTEntry
		name      string
		wantSaved bool
	}{
		{
			name: "newer timestamp - should save",
			entry: &models.CRDTEntry{
				ID:        entryID,
				UserID:    userID,
				Type:      models.DataTypeCredential,
				Data:      []byte("version2_newer"),
				Metadata:  []byte("metadata2"),
				Version:   2,
				Timestamp: 200, // Newer
				NodeID:    "node2",
				Deleted:   false,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			wantSaved: true,
		},
		{
			name: "older timestamp - should not save",
			entry: &models.CRDTEntry{
				ID:        entryID,
				UserID:    userID,
				Type:      models.DataTypeCredential,
				Data:      []byte("version3_older"),
				Metadata:  []byte("metadata3"),
				Version:   3,
				Timestamp: 50, // Older
				NodeID:    "node3",
				Deleted:   false,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			wantSaved: false,
		},
		{
			name: "same timestamp, higher nodeID - should save",
			entry: &models.CRDTEntry{
				ID:        entryID,
				UserID:    userID,
				Type:      models.DataTypeCredential,
				Data:      []byte("version4_same_ts"),
				Metadata:  []byte("metadata4"),
				Version:   4,
				Timestamp: 200,     // Same as current
				NodeID:    "node9", // Higher than "node2"
				Deleted:   false,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			wantSaved: true,
		},
		{
			name: "same timestamp, lower nodeID - should not save",
			entry: &models.CRDTEntry{
				ID:        entryID,
				UserID:    userID,
				Type:      models.DataTypeCredential,
				Data:      []byte("version5_same_ts"),
				Metadata:  []byte("metadata5"),
				Version:   5,
				Timestamp: 200,     // Same
				NodeID:    "node1", // Lower than "node9"
				Deleted:   false,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			wantSaved: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saved, err := s.SaveEntry(ctx, tt.entry)
			require.NoError(t, err)
			assert.Equal(t, tt.wantSaved, saved, "SaveEntry returned unexpected result")

			// Проверяем что сохранилась правильная версия
			retrieved, err := s.GetEntry(ctx, entryID)
			require.NoError(t, err)

			if tt.wantSaved {
				assert.Equal(t, tt.entry.Data, retrieved.Data, "Data should be updated")
				assert.Equal(t, tt.entry.Timestamp, retrieved.Timestamp)
				assert.Equal(t, tt.entry.NodeID, retrieved.NodeID)
			}
		})
	}
}

func TestDataStorage_GetUserEntries(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	userID := createTestUser(t, ctx, s)

	// Создаем несколько записей
	entries := []*models.CRDTEntry{
		{
			ID:        uuid.New().String(),
			UserID:    userID,
			Type:      models.DataTypeCredential,
			Data:      []byte("cred1"),
			Version:   1,
			Timestamp: 100,
			NodeID:    "node1",
			Deleted:   false,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:        uuid.New().String(),
			UserID:    userID,
			Type:      models.DataTypeText,
			Data:      []byte("text1"),
			Version:   1,
			Timestamp: 101,
			NodeID:    "node1",
			Deleted:   false,
			CreatedAt: time.Now().Add(time.Second),
			UpdatedAt: time.Now().Add(time.Second),
		},
		{
			ID:        uuid.New().String(),
			UserID:    userID,
			Type:      models.DataTypeCredential,
			Data:      []byte("cred2_deleted"),
			Version:   1,
			Timestamp: 102,
			NodeID:    "node1",
			Deleted:   true, // Удаленная запись
			CreatedAt: time.Now().Add(2 * time.Second),
			UpdatedAt: time.Now().Add(2 * time.Second),
		},
	}

	for _, entry := range entries {
		_, err := s.SaveEntry(ctx, entry)
		require.NoError(t, err)
	}

	// Получаем все записи пользователя
	retrieved, err := s.GetUserEntries(ctx, userID)
	require.NoError(t, err)

	// Должны получить только неудаленные записи (2 из 3)
	assert.Len(t, retrieved, 2)

	// Проверяем что удаленная запись не вернулась
	for _, e := range retrieved {
		assert.False(t, e.Deleted, "Should not return deleted entries")
	}
}

func TestDataStorage_GetUserEntriesSince(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	userID := createTestUser(t, ctx, s)

	// Создаем записи с разными timestamp
	entries := []*models.CRDTEntry{
		{
			ID:        uuid.New().String(),
			UserID:    userID,
			Type:      models.DataTypeCredential,
			Data:      []byte("old"),
			Version:   1,
			Timestamp: 100,
			NodeID:    "node1",
			Deleted:   false,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:        uuid.New().String(),
			UserID:    userID,
			Type:      models.DataTypeText,
			Data:      []byte("new"),
			Version:   1,
			Timestamp: 200,
			NodeID:    "node1",
			Deleted:   false,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:        uuid.New().String(),
			UserID:    userID,
			Type:      models.DataTypeBinary,
			Data:      []byte("newer_deleted"),
			Version:   1,
			Timestamp: 300,
			NodeID:    "node1",
			Deleted:   true, // Удаленная
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	for _, entry := range entries {
		_, err := s.SaveEntry(ctx, entry)
		require.NoError(t, err)
	}

	tests := []struct {
		name          string
		since         int64
		expectedCount int
	}{
		{
			name:          "get all entries since 0",
			since:         0,
			expectedCount: 3,
		},
		{
			name:          "get entries since 100",
			since:         100,
			expectedCount: 2,
		},
		{
			name:          "get entries since 200",
			since:         200,
			expectedCount: 1,
		},
		{
			name:          "get entries since 300",
			since:         300,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrieved, err := s.GetUserEntriesSince(ctx, userID, tt.since)
			require.NoError(t, err)
			assert.Len(t, retrieved, tt.expectedCount)
		})
	}
}

func TestDataStorage_GetUserEntriesByType(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	userID := createTestUser(t, ctx, s)

	// Создаем записи разных типов
	entries := []*models.CRDTEntry{
		{
			ID:        uuid.New().String(),
			UserID:    userID,
			Type:      models.DataTypeCredential,
			Data:      []byte("cred1"),
			Version:   1,
			Timestamp: 100,
			NodeID:    "node1",
			Deleted:   false,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:        uuid.New().String(),
			UserID:    userID,
			Type:      models.DataTypeCredential,
			Data:      []byte("cred2"),
			Version:   1,
			Timestamp: 101,
			NodeID:    "node1",
			Deleted:   false,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:        uuid.New().String(),
			UserID:    userID,
			Type:      models.DataTypeText,
			Data:      []byte("text1"),
			Version:   1,
			Timestamp: 102,
			NodeID:    "node1",
			Deleted:   false,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	for _, entry := range entries {
		_, err := s.SaveEntry(ctx, entry)
		require.NoError(t, err)
	}

	tests := []struct {
		name          string
		dataType      string
		expectedCount int
	}{
		{
			name:          "get credential entries",
			dataType:      models.DataTypeCredential,
			expectedCount: 2,
		},
		{
			name:          "get text entries",
			dataType:      models.DataTypeText,
			expectedCount: 1,
		},
		{
			name:          "get binary entries",
			dataType:      models.DataTypeBinary,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrieved, err := s.GetUserEntriesByType(ctx, userID, tt.dataType)
			require.NoError(t, err)
			assert.Len(t, retrieved, tt.expectedCount)

			// Проверяем что все записи нужного типа
			for _, e := range retrieved {
				assert.Equal(t, tt.dataType, e.Type)
			}
		})
	}
}

func TestDataStorage_DeleteEntry(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	userID := createTestUser(t, ctx, s)

	// Создаем запись
	entryID := uuid.New().String()
	entry := &models.CRDTEntry{
		ID:        entryID,
		UserID:    userID,
		Type:      models.DataTypeCredential,
		Data:      []byte("data"),
		Version:   1,
		Timestamp: 100,
		NodeID:    "node1",
		Deleted:   false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_, err := s.SaveEntry(ctx, entry)
	require.NoError(t, err)

	// Удаляем запись
	err = s.DeleteEntry(ctx, entryID, 200, "node2")
	require.NoError(t, err)

	// Проверяем что запись помечена как удаленная
	retrieved, err := s.GetEntry(ctx, entryID)
	assert.ErrorIs(t, err, storage.ErrEntryNotFound, "Deleted entry should not be returned by GetEntry")
	assert.Nil(t, retrieved)

	// Но она должна быть видна через GetUserEntriesSince для синхронизации
	entries, err := s.GetUserEntriesSince(ctx, userID, 0)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.True(t, entries[0].Deleted)
	assert.Equal(t, int64(200), entries[0].Timestamp)
	assert.Equal(t, "node2", entries[0].NodeID)
}

func TestDataStorage_GetEntry_NotFound(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	// Пытаемся получить несуществующую запись
	entry, err := s.GetEntry(ctx, "nonexistent-id")
	assert.ErrorIs(t, err, storage.ErrEntryNotFound)
	assert.Nil(t, entry)
}

func TestDataStorage_DeleteEntry_NotFound(t *testing.T) {
	ctx := context.Background()
	s, cleanup := setupTestStorage(t)
	defer cleanup()

	// Пытаемся удалить несуществующую запись
	err := s.DeleteEntry(ctx, "nonexistent-id", 100, "node1")
	assert.ErrorIs(t, err, storage.ErrEntryNotFound)
}

// Helper functions

func setupTestStorage(t *testing.T) (*Storage, func()) {
	ctx := context.Background()

	// Используем in-memory database для тестов
	storage, err := New(ctx, ":memory:")
	require.NoError(t, err)

	cleanup := func() {
		_ = storage.Close()
	}

	return storage, cleanup
}

func createTestUser(t *testing.T, ctx context.Context, s *Storage) string {
	userID := uuid.New().String()
	user := &models.User{
		ID:          userID,
		Username:    "testuser_" + userID[:8],
		AuthKeyHash: "hash",
		PublicSalt:  "salt",
		CreatedAt:   time.Now(),
		LastLogin:   nil,
	}

	err := s.CreateUser(ctx, user)
	require.NoError(t, err)

	return userID
}
