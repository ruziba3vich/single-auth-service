package services

import (
	"context"
	"errors"

	"github.com/prodonik/express-delivery-service/internal/domain"
)

// Common errors returned by SessionService implementations.
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session has expired")
)

// SessionService defines the contract for session storage and retrieval.
// Implementations could use Redis, PostgreSQL, in-memory storage, etc.
type SessionService interface {
	// Create stores a new session.
	// The session.ID should be set by the caller.
	Create(ctx context.Context, session *domain.Session) error

	// Get retrieves a session by its ID.
	// Returns ErrSessionNotFound if the session doesn't exist.
	Get(ctx context.Context, sessionID string) (*domain.Session, error)

	// Update updates an existing session (e.g., after token refresh).
	// Returns ErrSessionNotFound if the session doesn't exist.
	Update(ctx context.Context, session *domain.Session) error

	// Delete removes a session.
	// This should be called on logout.
	Delete(ctx context.Context, sessionID string) error

	// GetByUserID retrieves a session by user ID.
	// Useful for checking if a user already has an active session.
	// Returns ErrSessionNotFound if no session exists for this user.
	GetByUserID(ctx context.Context, userID string) (*domain.Session, error)

	// DeleteByUserID removes all sessions for a user.
	// Useful for "logout from all devices" functionality.
	DeleteByUserID(ctx context.Context, userID string) error
}

// AuthStateService defines the contract for temporary auth state storage.
// This stores PKCE verifiers and CSRF state during the OAuth flow.
type AuthStateService interface {
	// Store saves the auth state with a short TTL (10 minutes max).
	// The state.State value is used as the key.
	Store(ctx context.Context, state *domain.AuthState) error

	// Get retrieves and deletes the auth state (one-time use).
	// Returns error if state doesn't exist or has expired.
	Get(ctx context.Context, stateKey string) (*domain.AuthState, error)
}
