package boltdb

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"

	"github.com/iudanet/gophkeeper/internal/client/storage"
)

// создаём тестовое BoltDB хранилище с auth bucket
func createTestAuthStorage(t *testing.T) (*Storage, func()) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "auth_test.db")

	ctx := context.Background()
	store, err := New(ctx, dbPath)
	require.NoError(t, err)
	require.NotNil(t, store)

	cleanup := func() {
		// Закрываем БД
		require.NoError(t, store.Close())
		require.NoError(t, os.RemoveAll(tmpDir))
	}

	return store, cleanup
}

func TestStorage_SaveGetDeleteAuth(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestAuthStorage(t)
	defer cleanup()

	auth := &storage.AuthData{
		Username:     "testuser",
		UserID:       "user-id-123",
		NodeID:       "node-1",
		AccessToken:  "encrypted-access-token",
		RefreshToken: "encrypted-refresh-token",
		PublicSalt:   "salt",
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	}

	// Проверяем что GetAuth до сохранения выдаст ErrAuthNotFound
	_, err := store.GetAuth(ctx)
	assert.ErrorIs(t, err, storage.ErrAuthNotFound)

	// Сохраняем auth
	err = store.SaveAuth(ctx, auth)
	require.NoError(t, err)

	// Получаем auth и сравниваем
	got, err := store.GetAuth(ctx)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, auth.Username, got.Username)
	assert.Equal(t, auth.UserID, got.UserID)
	assert.Equal(t, auth.NodeID, got.NodeID)
	assert.Equal(t, auth.AccessToken, got.AccessToken)
	assert.Equal(t, auth.RefreshToken, got.RefreshToken)
	assert.Equal(t, auth.PublicSalt, got.PublicSalt)
	assert.Equal(t, auth.ExpiresAt, got.ExpiresAt)

	// IsAuthenticated должна вернуть true (токен не просрочен)
	authOk, err := store.IsAuthenticated(ctx)
	require.NoError(t, err)
	assert.True(t, authOk)

	// Обновляем auth с истекшим токеном
	auth.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	err = store.SaveAuth(ctx, auth)
	require.NoError(t, err)

	authOk, err = store.IsAuthenticated(ctx)
	require.NoError(t, err)
	assert.False(t, authOk)

	// Удаляем auth
	err = store.DeleteAuth(ctx)
	require.NoError(t, err)

	// После удаления GetAuth должен вернуть ErrAuthNotFound
	_, err = store.GetAuth(ctx)
	assert.ErrorIs(t, err, storage.ErrAuthNotFound)

	// Удаление уже отсутствующего auth — имеет ли ошибку?
	err = store.DeleteAuth(ctx)
	assert.Error(t, err) // ожидаем ошибку, т.к. auth отсутствует
}

func TestStorage_IsAuthenticated_Errors(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestAuthStorage(t)
	defer cleanup()

	// Если auth не существует, IsAuthenticated должна вернуть false, nil (не ошибку)
	authOk, err := store.IsAuthenticated(ctx)
	require.NoError(t, err)
	assert.False(t, authOk)
}

func TestStorage_DeleteAuth_BucketMissing(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestAuthStorage(t)
	defer cleanup()

	// Для теста удалим bucket auth напрямую
	err := store.db.Update(func(tx *bbolt.Tx) error {
		return tx.DeleteBucket([]byte("auth"))
	})
	assert.NoError(t, err)

	// Теперь DeleteAuth должен вернуть ошибку "auth bucket not found"
	err = store.DeleteAuth(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth bucket not found")
}

func TestStorage_GetAuth_BucketMissing(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestAuthStorage(t)
	defer cleanup()

	// Удаляем bucket auth напрямую
	err := store.db.Update(func(tx *bbolt.Tx) error {
		return tx.DeleteBucket([]byte("auth"))
	})
	assert.NoError(t, err)

	_, err = store.GetAuth(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth bucket not found")
}

func TestStorage_SaveAuth_BucketMissing(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestAuthStorage(t)
	defer cleanup()

	// Удаляем bucket auth напрямую
	err := store.db.Update(func(tx *bbolt.Tx) error {
		return tx.DeleteBucket([]byte("auth"))
	})
	assert.NoError(t, err)

	err = store.SaveAuth(ctx, &storage.AuthData{
		Username: "test",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth bucket not found")
}
