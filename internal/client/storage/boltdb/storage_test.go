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

func TestNew_Success(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "testdb.db")

	ctx := context.Background()
	store, err := New(ctx, dbPath)
	require.NoError(t, err)
	require.NotNil(t, store)
	defer func() {
		require.NoError(t, store.Close())
	}()

	// Проверяем что файл БД действительно создан
	info, err := os.Stat(dbPath)
	require.NoError(t, err)
	assert.False(t, info.IsDir())

	// Проверяем, что бакеты существуют
	err = store.db.View(func(tx *bbolt.Tx) error {
		for _, b := range [][]byte{bucketAuth, bucketSecrets, bucketMetadata} {
			if tx.Bucket(b) == nil {
				return os.ErrNotExist
			}
		}
		return nil
	})
	require.NoError(t, err)
}

func TestNew_InvalidPath(t *testing.T) {
	// Пытаемся открыть базу в недопустимом пути
	ctx := context.Background()
	// На некоторых системах путь с нулевым символом даст ошибку
	invalidPath := string([]byte{0})
	store, err := New(ctx, invalidPath)
	assert.Error(t, err)
	assert.Nil(t, store)
}

func TestClose(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "testdb.db")

	ctx := context.Background()
	store, err := New(ctx, dbPath)
	require.NoError(t, err)
	require.NotNil(t, store)

	// Закрываем БД
	err = store.Close()
	assert.NoError(t, err)

	// После закрытия поле db должно стать nil
	assert.Nil(t, store.db)

	// Второй вызов Close не должен падать и должен просто ничего не делать
	err = store.Close()
	assert.NoError(t, err)
}

func TestInitBuckets_CreatesBuckets(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "testdb.db")

	// Открываем БД вручную без создания бакетов
	db, err := bbolt.Open(dbPath, 0600, nil)
	require.NoError(t, err)
	defer db.Close()

	// Создаем Storage с установленным db но без вызова initBuckets
	store := &Storage{db: db}

	// Пробуем удалить бакеты (если они есть)
	_ = db.Update(func(tx *bbolt.Tx) error {
		_ = tx.DeleteBucket(bucketAuth)
		_ = tx.DeleteBucket(bucketSecrets)
		_ = tx.DeleteBucket(bucketMetadata)
		return nil
	})

	// Теперь инициализируем бакеты
	err = store.initBuckets()
	assert.NoError(t, err)

	// Проверяем, что бакеты теперь существуют
	err = db.View(func(tx *bbolt.Tx) error {
		for _, b := range [][]byte{bucketAuth, bucketSecrets, bucketMetadata} {
			if tx.Bucket(b) == nil {
				return os.ErrNotExist
			}
		}
		return nil
	})
	assert.NoError(t, err)
}
