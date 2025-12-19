package user

import (
	"context"

	"github.com/google/uuid"
)

// Repository defines the interface for user persistence operations.
// This interface is implemented by the infrastructure layer.
type Repository interface {
	// Create persists a new user to the database.
	Create(ctx context.Context, user *User) error

	// GetByID retrieves a user by their unique identifier.
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)

	// GetByEmail retrieves a user by their email address.
	GetByEmail(ctx context.Context, email string) (*User, error)

	// Update persists changes to an existing user.
	Update(ctx context.Context, user *User) error

	// Delete removes a user from the database.
	Delete(ctx context.Context, id uuid.UUID) error

	// ExistsByEmail checks if a user with the given email exists.
	ExistsByEmail(ctx context.Context, email string) (bool, error)
}

// IdentityRepository defines the interface for user identity persistence.
type IdentityRepository interface {
	// Create persists a new user identity link.
	Create(ctx context.Context, identity *UserIdentity) error

	// GetByUserID retrieves all identities for a user.
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*UserIdentity, error)

	// GetByProvider retrieves an identity by provider and provider user ID.
	GetByProvider(ctx context.Context, provider Provider, providerUserID string) (*UserIdentity, error)

	// Delete removes an identity link.
	Delete(ctx context.Context, id uuid.UUID) error

	// DeleteByUserID removes all identity links for a user.
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
}
