package boltdb

import (
	"context"
	"encoding/binary"
	"fmt"

	"go.etcd.io/bbolt"
)

const (
	keyLastSyncTimestamp = "last_sync_timestamp"
)

// SaveLastSyncTimestamp saves the timestamp of the last successful sync
func (s *Storage) SaveLastSyncTimestamp(ctx context.Context, timestamp int64) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketMetadata)
		if bucket == nil {
			return fmt.Errorf("metadata bucket not found")
		}

		// Конвертируем int64 в bytes
		timestampBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp))

		// Сохраняем timestamp
		if err := bucket.Put([]byte(keyLastSyncTimestamp), timestampBytes); err != nil {
			return fmt.Errorf("failed to save last sync timestamp: %w", err)
		}

		return nil
	})
}

// GetLastSyncTimestamp retrieves the timestamp of the last successful sync
// Returns 0 if no sync has been performed yet
func (s *Storage) GetLastSyncTimestamp(ctx context.Context) (int64, error) {
	var timestamp int64

	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketMetadata)
		if bucket == nil {
			return fmt.Errorf("metadata bucket not found")
		}

		// Получаем timestamp
		timestampBytes := bucket.Get([]byte(keyLastSyncTimestamp))
		if timestampBytes == nil {
			// Если timestamp не найден, возвращаем 0 (первая синхронизация)
			timestamp = 0
			return nil
		}

		// Конвертируем bytes в int64
		timestamp = int64(binary.BigEndian.Uint64(timestampBytes))
		return nil
	})

	if err != nil {
		return 0, fmt.Errorf("failed to get last sync timestamp: %w", err)
	}

	return timestamp, nil
}
