package boltdb

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"

	"github.com/iudanet/gophkeeper/internal/client/storage"
)

var authKey = []byte("current")

// SaveAuth stores authentication data
func (s *Storage) SaveAuth(ctx context.Context, auth *storage.AuthData) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketAuth)
		if bucket == nil {
			return fmt.Errorf("auth bucket not found")
		}

		// Сериализуем данные в JSON
		data, err := json.Marshal(auth)
		if err != nil {
			return fmt.Errorf("failed to marshal auth data: %w", err)
		}

		// Сохраняем в bucket
		if err := bucket.Put(authKey, data); err != nil {
			return fmt.Errorf("failed to save auth data: %w", err)
		}

		return nil
	})
}

// GetAuth retrieves stored authentication data
func (s *Storage) GetAuth(ctx context.Context) (*storage.AuthData, error) {
	var auth *storage.AuthData

	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketAuth)
		if bucket == nil {
			return fmt.Errorf("auth bucket not found")
		}

		// Получаем данные
		data := bucket.Get(authKey)
		if data == nil {
			return storage.ErrAuthNotFound
		}

		// Десериализуем
		auth = &storage.AuthData{}
		if err := json.Unmarshal(data, auth); err != nil {
			return fmt.Errorf("failed to unmarshal auth data: %w", err)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return auth, nil
}

// DeleteAuth removes stored authentication data (logout)
func (s *Storage) DeleteAuth(ctx context.Context) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketAuth)
		if bucket == nil {
			return fmt.Errorf("auth bucket not found")
		}

		// Проверяем существование данных
		if bucket.Get(authKey) == nil {
			return storage.ErrAuthNotFound
		}

		// Удаляем данные
		if err := bucket.Delete(authKey); err != nil {
			return fmt.Errorf("failed to delete auth data: %w", err)
		}

		return nil
	})
}

// IsAuthenticated checks if valid authentication exists
func (s *Storage) IsAuthenticated(ctx context.Context) (bool, error) {
	auth, err := s.GetAuth(ctx)
	if err != nil {
		if err == storage.ErrAuthNotFound {
			return false, nil
		}
		return false, err
	}

	// Проверяем, не истек ли токен
	if time.Now().After(auth.ExpiresAt) {
		return false, nil
	}

	return true, nil
}
