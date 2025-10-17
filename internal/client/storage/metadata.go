package storage

import "context"

//go:generate moq -out metafata_mock.go . MetadataStorage

// MetadataStorage defines interface for storing client metadata
type MetadataStorage interface {
	// SaveLastSyncTimestamp saves the timestamp of the last successful sync
	SaveLastSyncTimestamp(ctx context.Context, timestamp int64) error

	// GetLastSyncTimestamp retrieves the timestamp of the last successful sync
	// Returns 0 if no sync has been performed yet
	GetLastSyncTimestamp(ctx context.Context) (int64, error)
}
