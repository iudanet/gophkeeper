package boltdb

import (
	"context"
	"fmt"

	"go.etcd.io/bbolt"
)

var (
	// BoltDB bucket names
	bucketAuth    = []byte("auth")
	bucketSecrets = []byte("secrets")
)

// Storage represents BoltDB storage implementation for client
type Storage struct {
	db *bbolt.DB
}

// New creates a new BoltDB storage instance
// dbPath is the path to the BoltDB database file
func New(ctx context.Context, dbPath string) (*Storage, error) {
	// Открываем BoltDB
	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open boltdb: %w", err)
	}

	storage := &Storage{db: db}

	// Инициализируем buckets
	if err := storage.initBuckets(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize buckets: %w", err)
	}

	return storage, nil
}

// Close closes the database connection
func (s *Storage) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// initBuckets создает необходимые buckets если они не существуют
func (s *Storage) initBuckets() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		// Создаем bucket для аутентификационных данных
		if _, err := tx.CreateBucketIfNotExists(bucketAuth); err != nil {
			return fmt.Errorf("failed to create auth bucket: %w", err)
		}

		// Создаем bucket для секретов
		if _, err := tx.CreateBucketIfNotExists(bucketSecrets); err != nil {
			return fmt.Errorf("failed to create secrets bucket: %w", err)
		}

		return nil
	})
}
