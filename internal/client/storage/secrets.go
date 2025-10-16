package storage

import (
	"context"
	"time"
)

// SecretType represents the type of stored secret
type SecretType string

const (
	SecretTypeCredentials SecretType = "credentials" // Login/password pair
	SecretTypeText        SecretType = "text"        // Arbitrary text
	SecretTypeBinary      SecretType = "binary"      // Binary data/files
	SecretTypeCard        SecretType = "card"        // Bank card information
)

// Secret represents a stored secret item
type Secret struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	Metadata  map[string]string
	DeletedAt *time.Time
	ID        string
	UserID    string
	Type      SecretType
	Name      string
	Data      []byte
	Version   int64
}

// SecretsStorage defines interface for storing encrypted secrets on client
type SecretsStorage interface {
	// SaveSecret stores or updates a secret
	SaveSecret(ctx context.Context, secret *Secret) error

	// GetSecret retrieves a secret by ID
	// Returns ErrSecretNotFound if secret doesn't exist
	GetSecret(ctx context.Context, id string) (*Secret, error)

	// ListSecrets returns all non-deleted secrets for the user
	ListSecrets(ctx context.Context, userID string) ([]*Secret, error)

	// ListSecretsByType returns all non-deleted secrets of specific type
	ListSecretsByType(ctx context.Context, userID string, secretType SecretType) ([]*Secret, error)

	// DeleteSecret marks secret as deleted (soft delete for CRDT sync)
	DeleteSecret(ctx context.Context, id string) error

	// GetSecretsAfterVersion returns secrets modified after specific version (for sync)
	GetSecretsAfterVersion(ctx context.Context, userID string, version int64) ([]*Secret, error)
}
