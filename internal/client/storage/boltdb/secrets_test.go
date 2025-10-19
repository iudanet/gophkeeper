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

// createTestSecretsStorage создает временное BoltDB хранилище и инициализирует buckets
func createTestSecretsStorage(t *testing.T) (*Storage, func()) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "secrets_test.db")

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

// createTestSecret формирует тестовый секрет
func createTestSecret(id, userID string, secretType storage.SecretType, deleted bool) *storage.Secret {
	now := time.Now()
	var deletedAt *time.Time
	if deleted {
		d := now
		deletedAt = &d
	}

	return &storage.Secret{
		ID:        id,
		UserID:    userID,
		Type:      secretType,
		Name:      "test-secret",
		Data:      []byte("encrypted-data"),
		Version:   1,
		CreatedAt: now,
		UpdatedAt: now,
		DeletedAt: deletedAt,
		Metadata:  map[string]string{"example": "value"},
	}
}

func TestSaveGetDeleteSecret(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestSecretsStorage(t)
	defer cleanup()

	secret := createTestSecret("secret-1", "user-123", storage.SecretTypeCredentials, false)

	// Сохраняем секрет
	err := store.SaveSecret(ctx, secret)
	require.NoError(t, err)

	// Получаем секрет по ID
	got, err := store.GetSecret(ctx, secret.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, secret.ID, got.ID)
	assert.Equal(t, secret.UserID, got.UserID)
	assert.Equal(t, secret.Type, got.Type)
	assert.Equal(t, secret.Data, got.Data)
	assert.Nil(t, got.DeletedAt)

	// Удаляем секрет (soft delete)
	err = store.DeleteSecret(ctx, secret.ID)
	require.NoError(t, err)

	// После удаления секрет должен иметь DeletedAt != nil и увеличенную версию
	gotDeleted, err := store.GetSecret(ctx, secret.ID)
	require.NoError(t, err)
	require.NotNil(t, gotDeleted.DeletedAt)
	assert.Greater(t, gotDeleted.Version, secret.Version)
}

func TestGetSecret_NotFound(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestSecretsStorage(t)
	defer cleanup()

	_, err := store.GetSecret(ctx, "non-existing")
	assert.ErrorIs(t, err, storage.ErrSecretNotFound)
}

func TestListSecretsFilters(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestSecretsStorage(t)
	defer cleanup()

	secretActive := createTestSecret("s1", "user-1", storage.SecretTypeCredentials, false)
	secretDeleted := createTestSecret("s2", "user-1", storage.SecretTypeText, true)
	secretOtherUser := createTestSecret("s3", "user-2", storage.SecretTypeCredentials, false)

	require.NoError(t, store.SaveSecret(ctx, secretActive))
	require.NoError(t, store.SaveSecret(ctx, secretDeleted))
	require.NoError(t, store.SaveSecret(ctx, secretOtherUser))

	// ListSecrets должен вернуть только не удалённые для user-1
	list, err := store.ListSecrets(ctx, "user-1")
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "s1", list[0].ID)

	// ListSecretsByType должен отфильтровать по типу и не удаленным
	listByType, err := store.ListSecretsByType(ctx, "user-1", storage.SecretTypeCredentials)
	require.NoError(t, err)
	assert.Len(t, listByType, 1)
	assert.Equal(t, "s1", listByType[0].ID)

	// ListSecretsByType с типом, которого нет, вернёт пустой список
	listEmpty, err := store.ListSecretsByType(ctx, "user-1", storage.SecretTypeBinary)
	require.NoError(t, err)
	assert.Empty(t, listEmpty)
}

func TestGetSecretsAfterVersion(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestSecretsStorage(t)
	defer cleanup()

	sec1 := createTestSecret("sec1", "user-1", storage.SecretTypeCredentials, false)
	sec1.Version = 1
	sec2 := createTestSecret("sec2", "user-1", storage.SecretTypeCredentials, false)
	sec2.Version = 3
	sec3 := createTestSecret("sec3", "user-2", storage.SecretTypeCredentials, false)
	sec3.Version = 5

	require.NoError(t, store.SaveSecret(ctx, sec1))
	require.NoError(t, store.SaveSecret(ctx, sec2))
	require.NoError(t, store.SaveSecret(ctx, sec3))

	// Запросить версий больше 1 для user-1 должны вернуть sec2
	results, err := store.GetSecretsAfterVersion(ctx, "user-1", 1)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "sec2", results[0].ID)

	// Запросить версии больше 0 для user-2 должны вернуть sec3
	results2, err := store.GetSecretsAfterVersion(ctx, "user-2", 0)
	require.NoError(t, err)
	require.Len(t, results2, 1)
	assert.Equal(t, "sec3", results2[0].ID)
}

func TestDeleteSecret_NotFound(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestSecretsStorage(t)
	defer cleanup()

	err := store.DeleteSecret(ctx, "non-existing")
	assert.ErrorIs(t, err, storage.ErrSecretNotFound)
}

func Test_SaveSecret_BucketMissing(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestSecretsStorage(t)
	defer cleanup()

	// Удаляем bucket secrets напрямую
	err := store.db.Update(func(tx *bbolt.Tx) error {
		return tx.DeleteBucket(bucketSecrets)
	})
	require.NoError(t, err)

	err = store.SaveSecret(ctx, createTestSecret("id", "user", storage.SecretTypeCredentials, false))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secrets bucket not found")
}

func Test_GetSecret_BucketMissing(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestSecretsStorage(t)
	defer cleanup()

	// Удаляем bucket secrets напрямую
	err := store.db.Update(func(tx *bbolt.Tx) error {
		return tx.DeleteBucket(bucketSecrets)
	})
	require.NoError(t, err)

	_, err = store.GetSecret(ctx, "id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secrets bucket not found")
}

func Test_DeleteSecret_BucketMissing(t *testing.T) {
	ctx := context.Background()
	store, cleanup := createTestSecretsStorage(t)
	defer cleanup()

	// Удаляем bucket secrets напрямую
	err := store.db.Update(func(tx *bbolt.Tx) error {
		return tx.DeleteBucket(bucketSecrets)
	})
	require.NoError(t, err)

	err = store.DeleteSecret(ctx, "id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secrets bucket not found")
}
