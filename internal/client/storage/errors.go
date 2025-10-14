package storage

import "errors"

// Common client storage errors
var (
	// ErrAuthNotFound indicates that no authentication data exists
	ErrAuthNotFound = errors.New("authentication data not found")

	// ErrSecretNotFound indicates that secret was not found
	ErrSecretNotFound = errors.New("secret not found")

	// ErrStorageClosed indicates that storage is closed
	ErrStorageClosed = errors.New("storage is closed")
)
