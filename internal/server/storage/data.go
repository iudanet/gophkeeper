package storage

import (
	"context"

	"github.com/iudanet/gophkeeper/internal/models"
)

// DataStorage defines interface for user data (CRDT entries) persistence
type DataStorage interface {
	// SaveEntry creates or updates a CRDT entry in the storage
	// Uses CRDT logic: only saves if entry is newer than existing
	// Returns true if entry was saved (newer), false if existing entry is newer
	SaveEntry(ctx context.Context, entry *models.CRDTEntry) (bool, error)

	// GetEntry retrieves a single entry by ID
	// Returns ErrEntryNotFound if entry doesn't exist or is deleted
	GetEntry(ctx context.Context, id string) (*models.CRDTEntry, error)

	// GetUserEntries retrieves all non-deleted entries for a user
	// Returns empty slice if no entries found
	GetUserEntries(ctx context.Context, userID string) ([]*models.CRDTEntry, error)

	// GetUserEntriesSince retrieves all entries (including deleted) for a user
	// modified after the given timestamp. Used for synchronization.
	// Returns empty slice if no entries found
	GetUserEntriesSince(ctx context.Context, userID string, since int64) ([]*models.CRDTEntry, error)

	// GetUserEntriesByType retrieves all non-deleted entries for a user filtered by type
	// Returns empty slice if no entries found
	GetUserEntriesByType(ctx context.Context, userID string, dataType string) ([]*models.CRDTEntry, error)

	// DeleteEntry marks entry as deleted (soft delete) with new timestamp
	// Returns ErrEntryNotFound if entry doesn't exist
	DeleteEntry(ctx context.Context, id string, timestamp int64, nodeID string) error
}
