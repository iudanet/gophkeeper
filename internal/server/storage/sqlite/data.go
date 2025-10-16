package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/iudanet/gophkeeper/internal/models"
	"github.com/iudanet/gophkeeper/internal/server/storage"
)

// SaveEntry creates or updates a CRDT entry in the storage
// Uses CRDT logic: only saves if entry is newer than existing
// Returns true if entry was saved (newer), false if existing entry is newer
func (s *Storage) SaveEntry(ctx context.Context, entry *models.CRDTEntry) (bool, error) {
	// Проверяем существующую запись
	existing, err := s.GetEntry(ctx, entry.ID)
	if err != nil && !errors.Is(err, storage.ErrEntryNotFound) {
		return false, fmt.Errorf("failed to check existing entry: %w", err)
	}

	// Если запись существует, проверяем по CRDT логике
	if existing != nil {
		// Если существующая запись новее - не сохраняем
		if !entry.IsNewerThan(existing) {
			return false, nil
		}

		// Обновляем существующую запись
		query := `
			UPDATE user_data
			SET user_id = ?, type = ?, data = ?, metadata = ?,
			    version = ?, timestamp = ?, node_id = ?, deleted = ?,
			    updated_at = ?
			WHERE id = ?
		`

		_, err := s.db.ExecContext(ctx, query,
			entry.UserID,
			entry.Type,
			entry.Data,
			entry.Metadata,
			entry.Version,
			entry.Timestamp,
			entry.NodeID,
			boolToInt(entry.Deleted),
			entry.UpdatedAt.Unix(),
			entry.ID,
		)

		if err != nil {
			return false, fmt.Errorf("failed to update entry: %w", err)
		}

		return true, nil
	}

	// Создаем новую запись
	query := `
		INSERT INTO user_data (
			id, user_id, type, data, metadata,
			version, timestamp, node_id, deleted,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = s.db.ExecContext(ctx, query,
		entry.ID,
		entry.UserID,
		entry.Type,
		entry.Data,
		entry.Metadata,
		entry.Version,
		entry.Timestamp,
		entry.NodeID,
		boolToInt(entry.Deleted),
		entry.CreatedAt.Unix(),
		entry.UpdatedAt.Unix(),
	)

	if err != nil {
		return false, fmt.Errorf("failed to insert entry: %w", err)
	}

	return true, nil
}

// GetEntry retrieves a single entry by ID
// Returns ErrEntryNotFound if entry doesn't exist or is deleted
func (s *Storage) GetEntry(ctx context.Context, id string) (*models.CRDTEntry, error) {
	query := `
		SELECT id, user_id, type, data, metadata,
		       version, timestamp, node_id, deleted,
		       created_at, updated_at
		FROM user_data
		WHERE id = ?
	`

	entry := &models.CRDTEntry{}
	var deleted int
	var createdAt, updatedAt int64

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&entry.ID,
		&entry.UserID,
		&entry.Type,
		&entry.Data,
		&entry.Metadata,
		&entry.Version,
		&entry.Timestamp,
		&entry.NodeID,
		&deleted,
		&createdAt,
		&updatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrEntryNotFound
		}
		return nil, fmt.Errorf("failed to get entry: %w", err)
	}

	entry.Deleted = intToBool(deleted)
	entry.CreatedAt = unixToTime(createdAt)
	entry.UpdatedAt = unixToTime(updatedAt)

	// Если запись помечена как удаленная - возвращаем ошибку
	// (для внешних API, внутри синхронизации используем GetUserEntriesSince)
	if entry.Deleted {
		return nil, storage.ErrEntryNotFound
	}

	return entry, nil
}

// GetUserEntries retrieves all non-deleted entries for a user
// Returns empty slice if no entries found
func (s *Storage) GetUserEntries(ctx context.Context, userID string) ([]*models.CRDTEntry, error) {
	query := `
		SELECT id, user_id, type, data, metadata,
		       version, timestamp, node_id, deleted,
		       created_at, updated_at
		FROM user_data
		WHERE user_id = ? AND deleted = 0
		ORDER BY created_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query entries: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			err = cerr
		}
	}()

	return s.scanEntries(rows)
}

// GetUserEntriesSince retrieves all entries (including deleted) for a user
// modified after the given timestamp. Used for synchronization.
// Returns empty slice if no entries found
func (s *Storage) GetUserEntriesSince(ctx context.Context, userID string, since int64) ([]*models.CRDTEntry, error) {
	query := `
		SELECT id, user_id, type, data, metadata,
		       version, timestamp, node_id, deleted,
		       created_at, updated_at
		FROM user_data
		WHERE user_id = ? AND timestamp > ?
		ORDER BY timestamp ASC
	`

	rows, err := s.db.QueryContext(ctx, query, userID, since)
	if err != nil {
		return nil, fmt.Errorf("failed to query entries since timestamp: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			err = cerr
		}
	}()

	return s.scanEntries(rows)
}

// GetUserEntriesByType retrieves all non-deleted entries for a user filtered by type
// Returns empty slice if no entries found
func (s *Storage) GetUserEntriesByType(ctx context.Context, userID string, dataType string) ([]*models.CRDTEntry, error) {
	query := `
		SELECT id, user_id, type, data, metadata,
		       version, timestamp, node_id, deleted,
		       created_at, updated_at
		FROM user_data
		WHERE user_id = ? AND type = ? AND deleted = 0
		ORDER BY created_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query, userID, dataType)
	if err != nil {
		return nil, fmt.Errorf("failed to query entries by type: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			err = cerr
		}
	}()

	return s.scanEntries(rows)
}

// DeleteEntry marks entry as deleted (soft delete) with new timestamp
// Returns ErrEntryNotFound if entry doesn't exist
func (s *Storage) DeleteEntry(ctx context.Context, id string, timestamp int64, nodeID string) error {
	query := `
		UPDATE user_data
		SET deleted = 1, timestamp = ?, node_id = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := s.db.ExecContext(ctx, query, timestamp, nodeID, timestamp, id)
	if err != nil {
		return fmt.Errorf("failed to delete entry: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return storage.ErrEntryNotFound
	}

	return nil
}

// scanEntries is a helper function to scan multiple entries from rows
func (s *Storage) scanEntries(rows *sql.Rows) ([]*models.CRDTEntry, error) {
	var entries []*models.CRDTEntry

	for rows.Next() {
		entry := &models.CRDTEntry{}
		var deleted int
		var createdAt, updatedAt int64

		err := rows.Scan(
			&entry.ID,
			&entry.UserID,
			&entry.Type,
			&entry.Data,
			&entry.Metadata,
			&entry.Version,
			&entry.Timestamp,
			&entry.NodeID,
			&deleted,
			&createdAt,
			&updatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan entry: %w", err)
		}

		entry.Deleted = intToBool(deleted)
		entry.CreatedAt = unixToTime(createdAt)
		entry.UpdatedAt = unixToTime(updatedAt)

		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return entries, nil
}

// Helper functions for bool/int conversion
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func intToBool(i int) bool {
	return i != 0
}

func unixToTime(timestamp int64) time.Time {
	return time.Unix(timestamp, 0)
}
