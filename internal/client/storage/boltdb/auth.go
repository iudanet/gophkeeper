package boltdb

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"

	"github.com/iudanet/gophkeeper/internal/client/storage"
)

var _ storage.AuthStorage = (*Storage)(nil) // если это реализовано (скорее всего да)

var authKey = []byte("current")

// SaveAuth сохраняет AuthData в BoltDB как есть, не шифрует токены
func (s *Storage) SaveAuth(ctx context.Context, auth *storage.AuthData) error {
	data, err := json.Marshal(auth)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketAuth)
		if b == nil {
			return fmt.Errorf("auth bucket not found")
		}
		return b.Put(authKey, data)
	})
}

// GetAuth получает данные аутентификации из BoltDB
func (s *Storage) GetAuth(ctx context.Context) (*storage.AuthData, error) {
	var data []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketAuth)
		if b == nil {
			return fmt.Errorf("auth bucket not found")
		}
		val := b.Get(authKey)
		if val == nil {
			return storage.ErrAuthNotFound
		}
		data = append([]byte(nil), val...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	var auth storage.AuthData
	if err := json.Unmarshal(data, &auth); err != nil {
		return nil, err
	}
	return &auth, nil
}

// DeleteAuth удаляет все данные авторизации
func (s *Storage) DeleteAuth(ctx context.Context) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketAuth)
		if bucket == nil {
			return fmt.Errorf("auth bucket not found")
		}
		if bucket.Get(authKey) == nil {
			return storage.ErrAuthNotFound
		}
		return bucket.Delete(authKey)
	})
}

// IsAuthenticated проверяет, что в локальном хранилище есть валидные auth данные (токен не просрочен)
func (s *Storage) IsAuthenticated(ctx context.Context) (bool, error) {
	auth, err := s.GetAuth(ctx)
	if err != nil {
		if err == storage.ErrAuthNotFound {
			return false, nil
		}
		return false, err
	}

	expiresAt := time.Unix(auth.ExpiresAt, 0)
	if time.Now().After(expiresAt) {
		return false, nil
	}

	return true, nil
}
