package keys

import (
	"context"
)

// Repository defines the interface for signing key persistence.
type Repository interface {
	// Create persists a new signing key.
	Create(ctx context.Context, key *SigningKey) error

	// GetByKID retrieves a key by its Key ID.
	GetByKID(ctx context.Context, kid string) (*SigningKey, error)

	// GetActive retrieves the currently active signing key.
	GetActive(ctx context.Context) (*SigningKey, error)

	// GetAll retrieves all valid (non-expired) keys.
	// Used for JWKS endpoint - includes rotated keys for verification.
	GetAll(ctx context.Context) ([]*SigningKey, error)

	// SetActive marks a key as active and deactivates others.
	SetActive(ctx context.Context, kid string) error

	// Delete removes an expired key.
	Delete(ctx context.Context, kid string) error

	// DeleteExpired removes all expired keys (cleanup job).
	DeleteExpired(ctx context.Context) (int64, error)
}

// KeyGenerator defines the interface for generating new signing keys.
type KeyGenerator interface {
	// Generate creates a new RSA key pair.
	Generate() (*SigningKey, error)
}
