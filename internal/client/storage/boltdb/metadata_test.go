package boltdb

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
)

// createTestMetadataStorage создает временное BoltDB хранилище и инициализирует buckets
func createTestMetadataStorage(t *testing.T) (*Storage, func()) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "metadata_test.db")

	ctx := context.Background()
	store, err := New(ctx, dbPath)
	require.NoError(t, err)
	require.NotNil(t, store)

	cleanup := func() {
		require.NoError(t, store.Close())
		require.NoError(t, os.RemoveAll(tmpDir))
	}

	return store, cleanup
}

func TestSaveAndGetLastSyncTimestamp(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestMetadataStorage(t)
	defer cleanup()

	// Изначально, если timestamp не сохранён — ожидаем 0
	ts, err := store.GetLastSyncTimestamp(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), ts)

	// Сохраняем timestamp
	var expectedTS int64 = 1234567890
	err = store.SaveLastSyncTimestamp(ctx, expectedTS)
	require.NoError(t, err)

	// Получаем и проверяем
	gotTS, err := store.GetLastSyncTimestamp(ctx)
	require.NoError(t, err)
	assert.Equal(t, expectedTS, gotTS)
}

func TestGetLastSyncTimestamp_BucketMissing(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestMetadataStorage(t)
	defer cleanup()

	// Удаляем bucket metadata напрямую
	err := store.db.Update(func(tx *bbolt.Tx) error {
		return tx.DeleteBucket(bucketMetadata)
	})
	require.NoError(t, err)

	// Попытка получить timestamp должна вернуть ошибку
	_, err = store.GetLastSyncTimestamp(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "metadata bucket not found")
}

func TestSaveLastSyncTimestamp_BucketMissing(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestMetadataStorage(t)
	defer cleanup()

	// Удаляем bucket metadata напрямую
	err := store.db.Update(func(tx *bbolt.Tx) error {
		return tx.DeleteBucket(bucketMetadata)
	})
	require.NoError(t, err)

	// Попытка сохранить timestamp должна вернуть ошибку
	err = store.SaveLastSyncTimestamp(ctx, 42)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "metadata bucket not found")
}
