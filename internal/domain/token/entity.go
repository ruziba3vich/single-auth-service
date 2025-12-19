package token

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken represents a refresh token bound to a user, client, and device.
// Refresh tokens are stored in the database and can be revoked.
type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ClientID  string
	DeviceID  uuid.UUID
	TokenHash string    // SHA-256 hash of the actual token
	Scope     string    // Granted scopes
	ExpiresAt time.Time
	Revoked   bool
	CreatedAt time.Time
}

// NewRefreshToken creates a new refresh token entity.
// The tokenHash should be computed from the actual token value.
func NewRefreshToken(
	userID uuid.UUID,
	clientID string,
	deviceID uuid.UUID,
	tokenHash string,
	scope string,
	ttl time.Duration,
) *RefreshToken {
	now := time.Now().UTC()
	return &RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		ClientID:  clientID,
		DeviceID:  deviceID,
		TokenHash: tokenHash,
		Scope:     scope,
		ExpiresAt: now.Add(ttl),
		Revoked:   false,
		CreatedAt: now,
	}
}

// IsValid checks if the refresh token is usable.
func (rt *RefreshToken) IsValid() bool {
	if rt.Revoked {
		return false
	}
	return time.Now().UTC().Before(rt.ExpiresAt)
}

// Revoke marks the refresh token as revoked.
func (rt *RefreshToken) Revoke() {
	rt.Revoked = true
}

// AccessTokenClaims represents the claims embedded in an access token JWT.
type AccessTokenClaims struct {
	// Standard JWT claims
	Issuer    string    `json:"iss"`
	Subject   string    `json:"sub"` // user_id or client_id
	Audience  []string  `json:"aud"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
	NotBefore time.Time `json:"nbf"`
	TokenID   string    `json:"jti"`

	// Custom claims
	DeviceID string `json:"device_id,omitempty"` // Empty for client_credentials
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
	Type     string `json:"typ"` // "access" or "refresh"
}

// IDTokenClaims represents the claims for an OpenID Connect ID token.
type IDTokenClaims struct {
	// Standard OIDC claims
	Issuer    string    `json:"iss"`
	Subject   string    `json:"sub"`
	Audience  string    `json:"aud"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
	AuthTime  time.Time `json:"auth_time"`
	Nonce     string    `json:"nonce,omitempty"`

	// User info claims (if scope includes profile/email)
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}
