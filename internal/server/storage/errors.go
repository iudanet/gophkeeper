package storage

import "errors"

// Common storage errors
var (
	// ErrUserNotFound indicates that user was not found in storage
	ErrUserNotFound = errors.New("user not found")

	// ErrUserAlreadyExists indicates that user with this username already exists
	ErrUserAlreadyExists = errors.New("user already exists")

	// ErrTokenNotFound indicates that refresh token was not found
	ErrTokenNotFound = errors.New("refresh token not found")

	// ErrInvalidToken indicates that token format is invalid
	ErrInvalidToken = errors.New("invalid token")

	// ErrEntryNotFound indicates that data entry was not found
	ErrEntryNotFound = errors.New("entry not found")
)
