package user

import (
	"time"

	"github.com/google/uuid"
)

// User represents the core user entity in the identity system.
// This is the aggregate root for user-related operations.
type User struct {
	ID            uuid.UUID
	Email         string
	PasswordHash  string
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// NewUser creates a new user with validated email and hashed password.
// The password must be pre-hashed before calling this constructor.
func NewUser(email, passwordHash string) *User {
	now := time.Now().UTC()
	return &User{
		ID:            uuid.New(),
		Email:         email,
		PasswordHash:  passwordHash,
		EmailVerified: false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

// VerifyEmail marks the user's email as verified.
func (u *User) VerifyEmail() {
	u.EmailVerified = true
	u.UpdatedAt = time.Now().UTC()
}

// UpdatePassword updates the user's password hash.
func (u *User) UpdatePassword(newPasswordHash string) {
	u.PasswordHash = newPasswordHash
	u.UpdatedAt = time.Now().UTC()
}

// Provider represents the authentication provider type.
type Provider string

const (
	ProviderLocal  Provider = "local"
	ProviderGoogle Provider = "google"
	ProviderApple  Provider = "apple"
)

// UserIdentity represents a linked external identity provider account.
// A user can have multiple identities (local password, Google, Apple, etc.)
type UserIdentity struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	Provider       Provider
	ProviderUserID string
	CreatedAt      time.Time
}

// NewUserIdentity creates a new identity link for a user.
func NewUserIdentity(userID uuid.UUID, provider Provider, providerUserID string) *UserIdentity {
	return &UserIdentity{
		ID:             uuid.New(),
		UserID:         userID,
		Provider:       provider,
		ProviderUserID: providerUserID,
		CreatedAt:      time.Now().UTC(),
	}
}
