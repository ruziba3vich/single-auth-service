package oauth

import (
	"context"

	"github.com/google/uuid"
)

// ClientRepository defines the interface for OAuth client persistence.
type ClientRepository interface {
	// Create persists a new OAuth client.
	Create(ctx context.Context, client *Client) error

	// GetByID retrieves a client by internal ID.
	GetByID(ctx context.Context, id uuid.UUID) (*Client, error)

	// GetByClientID retrieves a client by public client_id.
	GetByClientID(ctx context.Context, clientID string) (*Client, error)

	// Update persists changes to an existing client.
	Update(ctx context.Context, client *Client) error

	// Delete removes a client.
	Delete(ctx context.Context, id uuid.UUID) error

	// List retrieves all clients with pagination.
	List(ctx context.Context, limit, offset int) ([]*Client, error)
}

// AuthorizationCodeRepository defines the interface for authorization code storage.
// Authorization codes are short-lived and stored in Redis.
type AuthorizationCodeRepository interface {
	// Store saves an authorization code with automatic expiration.
	Store(ctx context.Context, code *AuthorizationCode) error

	// Get retrieves an authorization code by its value.
	// Returns nil if not found or expired.
	Get(ctx context.Context, code string) (*AuthorizationCode, error)

	// Delete removes an authorization code (after use or revocation).
	Delete(ctx context.Context, code string) error
}
