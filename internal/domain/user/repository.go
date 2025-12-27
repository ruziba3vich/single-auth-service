package user

import (
	"context"
)

// Repository defines the interface for user persistence operations.
// This interface is implemented by the infrastructure layer.
type Repository interface {
	// Create persists a new user to the database.
	Create(ctx context.Context, user *User) error

	// GetByID retrieves a user by their unique identifier.
	GetByID(ctx context.Context, id int64) (*User, error)

	// GetByPhone retrieves a user by their phone number.
	GetByPhone(ctx context.Context, phone string) (*User, error)

	// GetByEmail retrieves a user by their email address.
	GetByEmail(ctx context.Context, email string) (*User, error)

	// GetByUsername retrieves a user by their username.
	GetByUsername(ctx context.Context, username string) (*User, error)

	// GetByLogin retrieves a user by login identifier (phone, email, or username).
	GetByLogin(ctx context.Context, login string) (*User, error)

	// Update persists changes to an existing user.
	Update(ctx context.Context, user *User) error

	// Delete removes a user from the database.
	Delete(ctx context.Context, id int64) error

	// ExistsByPhone checks if a user with the given phone exists.
	ExistsByPhone(ctx context.Context, phone string) (bool, error)

	// ExistsByEmail checks if a user with the given email exists.
	ExistsByEmail(ctx context.Context, email string) (bool, error)

	// ExistsByUsername checks if a user with the given username exists.
	ExistsByUsername(ctx context.Context, username string) (bool, error)

	// UpdateLastLogin updates the user's last login timestamp and IP.
	UpdateLastLogin(ctx context.Context, id int64, ip string) error
}
