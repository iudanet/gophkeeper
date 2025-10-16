package boltdb

import (
	"context"
	"encoding/json"
	"fmt"

	"go.etcd.io/bbolt"

	"github.com/iudanet/gophkeeper/internal/client/storage"
)

// SaveSecret stores or updates a secret
func (s *Storage) SaveSecret(ctx context.Context, secret *storage.Secret) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSecrets)
		if bucket == nil {
			return fmt.Errorf("secrets bucket not found")
		}

		// Сериализуем секрет в JSON
		data, err := json.Marshal(secret)
		if err != nil {
			return fmt.Errorf("failed to marshal secret: %w", err)
		}

		// Сохраняем по ID
		key := []byte(secret.ID)
		if err := bucket.Put(key, data); err != nil {
			return fmt.Errorf("failed to save secret: %w", err)
		}

		return nil
	})
}

// GetSecret retrieves a secret by ID
func (s *Storage) GetSecret(ctx context.Context, id string) (*storage.Secret, error) {
	var secret *storage.Secret

	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSecrets)
		if bucket == nil {
			return fmt.Errorf("secrets bucket not found")
		}

		// Получаем данные по ID
		data := bucket.Get([]byte(id))
		if data == nil {
			return storage.ErrSecretNotFound
		}

		// Десериализуем
		secret = &storage.Secret{}
		if err := json.Unmarshal(data, secret); err != nil {
			return fmt.Errorf("failed to unmarshal secret: %w", err)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return secret, nil
}

// ListSecrets returns all non-deleted secrets for the user
func (s *Storage) ListSecrets(ctx context.Context, userID string) ([]*storage.Secret, error) {
	var secrets []*storage.Secret

	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSecrets)
		if bucket == nil {
			return fmt.Errorf("secrets bucket not found")
		}

		// Итерируемся по всем секретам
		return bucket.ForEach(func(k, v []byte) error {
			secret := &storage.Secret{}
			if err := json.Unmarshal(v, secret); err != nil {
				return fmt.Errorf("failed to unmarshal secret: %w", err)
			}

			// Фильтруем по userID и не удаленным
			if secret.UserID == userID && secret.DeletedAt == nil {
				secrets = append(secrets, secret)
			}

			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	return secrets, nil
}

// ListSecretsByType returns all non-deleted secrets of specific type
func (s *Storage) ListSecretsByType(ctx context.Context, userID string, secretType storage.SecretType) ([]*storage.Secret, error) {
	var secrets []*storage.Secret

	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSecrets)
		if bucket == nil {
			return fmt.Errorf("secrets bucket not found")
		}

		// Итерируемся по всем секретам
		return bucket.ForEach(func(k, v []byte) error {
			secret := &storage.Secret{}
			if err := json.Unmarshal(v, secret); err != nil {
				return fmt.Errorf("failed to unmarshal secret: %w", err)
			}

			// Фильтруем по userID, типу и не удаленным
			if secret.UserID == userID && secret.Type == secretType && secret.DeletedAt == nil {
				secrets = append(secrets, secret)
			}

			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	return secrets, nil
}

// DeleteSecret marks secret as deleted (soft delete for CRDT sync)
func (s *Storage) DeleteSecret(ctx context.Context, id string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSecrets)
		if bucket == nil {
			return fmt.Errorf("secrets bucket not found")
		}

		// Получаем существующий секрет
		data := bucket.Get([]byte(id))
		if data == nil {
			return storage.ErrSecretNotFound
		}

		// Десериализуем
		secret := &storage.Secret{}
		if err := json.Unmarshal(data, secret); err != nil {
			return fmt.Errorf("failed to unmarshal secret: %w", err)
		}

		// Помечаем как удаленный (soft delete)
		now := secret.UpdatedAt // используем текущее время обновления
		secret.DeletedAt = &now
		secret.Version++

		// Сохраняем обратно
		updatedData, err := json.Marshal(secret)
		if err != nil {
			return fmt.Errorf("failed to marshal secret: %w", err)
		}

		if err := bucket.Put([]byte(id), updatedData); err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}

		return nil
	})
}

// GetSecretsAfterVersion returns secrets modified after specific version (for sync)
func (s *Storage) GetSecretsAfterVersion(ctx context.Context, userID string, version int64) ([]*storage.Secret, error) {
	var secrets []*storage.Secret

	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSecrets)
		if bucket == nil {
			return fmt.Errorf("secrets bucket not found")
		}

		// Итерируемся по всем секретам
		return bucket.ForEach(func(k, v []byte) error {
			secret := &storage.Secret{}
			if err := json.Unmarshal(v, secret); err != nil {
				return fmt.Errorf("failed to unmarshal secret: %w", err)
			}

			// Фильтруем по userID и версии
			if secret.UserID == userID && secret.Version > version {
				secrets = append(secrets, secret)
			}

			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	return secrets, nil
}
