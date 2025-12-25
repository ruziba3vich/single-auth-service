package domain

import (
	"time"
)

// Session represents an authenticated user session.
// It stores the OAuth tokens obtained from the auth service.
type Session struct {
	// ID is the unique session identifier (stored in cookie)
	ID string

	// UserID is the user's identifier from the auth service (sub claim)
	UserID string

	// Email is the user's email (if email scope was granted)
	Email string

	// AccessToken is the JWT access token for API calls
	AccessToken string

	// RefreshToken is used to obtain new access tokens
	RefreshToken string

	// DeviceID is the device binding ID from the auth service
	// Required for token refresh to prevent token theft
	DeviceID string

	// ExpiresAt is when the access token expires
	ExpiresAt time.Time

	// CreatedAt is when this session was created
	CreatedAt time.Time

	// UpdatedAt is when this session was last updated
	UpdatedAt time.Time
}

// IsExpired returns true if the access token has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// NeedsRefresh returns true if the access token will expire within the given duration.
// This allows proactive token refresh before expiration.
func (s *Session) NeedsRefresh(buffer time.Duration) bool {
	return time.Now().Add(buffer).After(s.ExpiresAt)
}

// AuthState holds temporary OAuth state during the authorization flow.
// This is stored in a cookie during the login redirect.
type AuthState struct {
	// State is the CSRF protection token
	State string

	// CodeVerifier is the PKCE code verifier
	CodeVerifier string

	// ReturnTo is where to redirect after login (optional)
	ReturnTo string

	// CreatedAt is when this state was created
	CreatedAt time.Time
}

// IsExpired returns true if the auth state is too old (10 minute max).
func (a *AuthState) IsExpired() bool {
	return time.Since(a.CreatedAt) > 10*time.Minute
}
