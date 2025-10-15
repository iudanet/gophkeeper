package boltdb

import (
	"context"
	"encoding/json"
	"fmt"

	"go.etcd.io/bbolt"

	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/models"
)

var (
	// crdtBucket stores CRDT entries
	crdtBucket = []byte("crdt")
)

// SaveEntry stores or updates a CRDT entry in BoltDB
func (s *Storage) SaveEntry(ctx context.Context, entry *models.CRDTEntry) error {
	if s.db == nil {
		return storage.ErrStorageClosed
	}

	// Сериализуем entry в JSON
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal CRDT entry: %w", err)
	}

	err = s.db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(crdtBucket)
		if err != nil {
			return fmt.Errorf("failed to create bucket: %w", err)
		}

		// Сохраняем по ключу ID
		if err := bucket.Put([]byte(entry.ID), data); err != nil {
			return fmt.Errorf("failed to save entry: %w", err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("transaction failed: %w", err)
	}

	return nil
}

// GetEntry retrieves a CRDT entry by ID
func (s *Storage) GetEntry(ctx context.Context, id string) (*models.CRDTEntry, error) {
	if s.db == nil {
		return nil, storage.ErrStorageClosed
	}

	var entry *models.CRDTEntry

	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(crdtBucket)
		if bucket == nil {
			return storage.ErrEntryNotFound
		}

		data := bucket.Get([]byte(id))
		if data == nil {
			return storage.ErrEntryNotFound
		}

		// Десериализуем
		entry = &models.CRDTEntry{}
		if err := json.Unmarshal(data, entry); err != nil {
			return fmt.Errorf("failed to unmarshal entry: %w", err)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return entry, nil
}

// GetAllEntries returns all entries (including deleted ones)
func (s *Storage) GetAllEntries(ctx context.Context) ([]*models.CRDTEntry, error) {
	if s.db == nil {
		return nil, storage.ErrStorageClosed
	}

	var entries []*models.CRDTEntry

	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(crdtBucket)
		if bucket == nil {
			// Нет bucket - возвращаем пустой массив
			return nil
		}

		return bucket.ForEach(func(k, v []byte) error {
			var entry models.CRDTEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return fmt.Errorf("failed to unmarshal entry: %w", err)
			}
			entries = append(entries, &entry)
			return nil
		})
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get all entries: %w", err)
	}

	return entries, nil
}

// GetEntriesAfterTimestamp returns entries modified after specific timestamp
func (s *Storage) GetEntriesAfterTimestamp(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
	if s.db == nil {
		return nil, storage.ErrStorageClosed
	}

	var entries []*models.CRDTEntry

	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(crdtBucket)
		if bucket == nil {
			return nil
		}

		return bucket.ForEach(func(k, v []byte) error {
			var entry models.CRDTEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return fmt.Errorf("failed to unmarshal entry: %w", err)
			}

			// Фильтруем по timestamp
			if entry.Timestamp > timestamp {
				entries = append(entries, &entry)
			}

			return nil
		})
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get entries after timestamp: %w", err)
	}

	return entries, nil
}

// GetActiveEntries returns all non-deleted entries
func (s *Storage) GetActiveEntries(ctx context.Context) ([]*models.CRDTEntry, error) {
	if s.db == nil {
		return nil, storage.ErrStorageClosed
	}

	var entries []*models.CRDTEntry

	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(crdtBucket)
		if bucket == nil {
			return nil
		}

		return bucket.ForEach(func(k, v []byte) error {
			var entry models.CRDTEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return fmt.Errorf("failed to unmarshal entry: %w", err)
			}

			// Фильтруем deleted
			if !entry.Deleted {
				entries = append(entries, &entry)
			}

			return nil
		})
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get active entries: %w", err)
	}

	return entries, nil
}

// GetEntriesByType returns all non-deleted entries of specific type
func (s *Storage) GetEntriesByType(ctx context.Context, dataType string) ([]*models.CRDTEntry, error) {
	if s.db == nil {
		return nil, storage.ErrStorageClosed
	}

	var entries []*models.CRDTEntry

	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(crdtBucket)
		if bucket == nil {
			return nil
		}

		return bucket.ForEach(func(k, v []byte) error {
			var entry models.CRDTEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return fmt.Errorf("failed to unmarshal entry: %w", err)
			}

			// Фильтруем по типу и deleted
			if !entry.Deleted && entry.Type == dataType {
				entries = append(entries, &entry)
			}

			return nil
		})
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get entries by type: %w", err)
	}

	return entries, nil
}

// DeleteEntry marks entry as deleted (soft delete)
func (s *Storage) DeleteEntry(ctx context.Context, id string, timestamp int64, nodeID string) error {
	if s.db == nil {
		return storage.ErrStorageClosed
	}

	err := s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(crdtBucket)
		if bucket == nil {
			return storage.ErrEntryNotFound
		}

		// Получаем существующую запись
		data := bucket.Get([]byte(id))
		if data == nil {
			return storage.ErrEntryNotFound
		}

		var entry models.CRDTEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return fmt.Errorf("failed to unmarshal entry: %w", err)
		}

		// Помечаем как удаленную
		entry.Deleted = true
		entry.Timestamp = timestamp
		entry.NodeID = nodeID

		// Сохраняем обратно
		updatedData, err := json.Marshal(&entry)
		if err != nil {
			return fmt.Errorf("failed to marshal updated entry: %w", err)
		}

		if err := bucket.Put([]byte(id), updatedData); err != nil {
			return fmt.Errorf("failed to save deleted entry: %w", err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("delete transaction failed: %w", err)
	}

	return nil
}

// GetMaxTimestamp returns the maximum timestamp in the local store
func (s *Storage) GetMaxTimestamp(ctx context.Context) (int64, error) {
	if s.db == nil {
		return 0, storage.ErrStorageClosed
	}

	var maxTimestamp int64

	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(crdtBucket)
		if bucket == nil {
			// Нет bucket - возвращаем 0
			return nil
		}

		return bucket.ForEach(func(k, v []byte) error {
			var entry models.CRDTEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return fmt.Errorf("failed to unmarshal entry: %w", err)
			}

			if entry.Timestamp > maxTimestamp {
				maxTimestamp = entry.Timestamp
			}

			return nil
		})
	})

	if err != nil {
		return 0, fmt.Errorf("failed to get max timestamp: %w", err)
	}

	return maxTimestamp, nil
}

// Clear removes all entries from storage
func (s *Storage) Clear(ctx context.Context) error {
	if s.db == nil {
		return storage.ErrStorageClosed
	}

	err := s.db.Update(func(tx *bbolt.Tx) error {
		// Удаляем bucket полностью
		if err := tx.DeleteBucket(crdtBucket); err != nil && err != bbolt.ErrBucketNotFound {
			return fmt.Errorf("failed to delete bucket: %w", err)
		}

		// Создаем заново пустой bucket
		if _, err := tx.CreateBucket(crdtBucket); err != nil {
			return fmt.Errorf("failed to create bucket: %w", err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("clear transaction failed: %w", err)
	}

	return nil
}
