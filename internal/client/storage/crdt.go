package storage

import (
	"context"

	"github.com/iudanet/gophkeeper/internal/models"
)

//go:generate moq -out crdtstorage_mock.go . CRDTStorage

// CRDTStorage defines interface for storing CRDT entries on client
type CRDTStorage interface {
	// SaveEntry stores or updates a CRDT entry
	SaveEntry(ctx context.Context, entry *models.CRDTEntry) error

	// GetEntry retrieves a CRDT entry by ID
	// Returns ErrEntryNotFound if entry doesn't exist
	GetEntry(ctx context.Context, id string) (*models.CRDTEntry, error)

	// GetAllEntries returns all entries (including deleted ones)
	// Used for sync operations
	GetAllEntries(ctx context.Context) ([]*models.CRDTEntry, error)

	// GetEntriesAfterTimestamp returns entries modified after specific timestamp
	// Used for incremental sync
	GetEntriesAfterTimestamp(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error)

	// GetActiveEntries returns all non-deleted entries
	GetActiveEntries(ctx context.Context) ([]*models.CRDTEntry, error)

	// GetEntriesByType returns all non-deleted entries of specific type
	GetEntriesByType(ctx context.Context, dataType string) ([]*models.CRDTEntry, error)

	// DeleteEntry marks entry as deleted (soft delete)
	DeleteEntry(ctx context.Context, id string, timestamp int64, nodeID string) error

	// GetMaxTimestamp returns the maximum timestamp in the local store
	// Used for sync operations
	GetMaxTimestamp(ctx context.Context) (int64, error)

	// Clear removes all entries from storage
	// Used for testing and full re-sync
	Clear(ctx context.Context) error
}
