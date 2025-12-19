package oauth

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// GrantType represents the OAuth 2.1 grant types supported.
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypeClientCredentials GrantType = "client_credentials"
)

// Client represents an OAuth 2.1 client application.
// Clients can be confidential (with secret) or public (PKCE-only).
type Client struct {
	ID               uuid.UUID
	ClientID         string    // Public client identifier
	ClientSecretHash string    // Hashed secret for confidential clients (empty for public)
	Name             string    // Human-readable name
	RedirectURIs     []string  // Allowed redirect URIs
	GrantTypes       []GrantType
	Scopes           []string  // Allowed scopes for this client
	IsConfidential   bool      // True if client has a secret
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// NewClient creates a new OAuth client.
func NewClient(clientID, name string, redirectURIs []string, grantTypes []GrantType, isConfidential bool) *Client {
	now := time.Now().UTC()
	return &Client{
		ID:             uuid.New(),
		ClientID:       clientID,
		Name:           name,
		RedirectURIs:   redirectURIs,
		GrantTypes:     grantTypes,
		Scopes:         []string{"openid", "profile", "email"},
		IsConfidential: isConfidential,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

// SetSecret sets the hashed client secret.
func (c *Client) SetSecret(hashedSecret string) {
	c.ClientSecretHash = hashedSecret
	c.IsConfidential = true
	c.UpdatedAt = time.Now().UTC()
}

// ValidateRedirectURI checks if the given URI is in the allowed list.
func (c *Client) ValidateRedirectURI(uri string) bool {
	for _, allowed := range c.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

// HasGrantType checks if the client supports the given grant type.
func (c *Client) HasGrantType(gt GrantType) bool {
	for _, allowed := range c.GrantTypes {
		if allowed == gt {
			return true
		}
	}
	return false
}

// HasScope checks if the client is allowed to request the given scope.
func (c *Client) HasScope(scope string) bool {
	for _, allowed := range c.Scopes {
		if allowed == scope {
			return true
		}
	}
	return false
}

// ValidateScopes checks if all requested scopes are allowed.
func (c *Client) ValidateScopes(scopes string) bool {
	if scopes == "" {
		return true
	}
	requested := strings.Split(scopes, " ")
	for _, s := range requested {
		if !c.HasScope(s) {
			return false
		}
	}
	return true
}

// AuthorizationCode represents a temporary authorization code for the OAuth flow.
// Stored in Redis with short TTL (10 minutes max per spec).
type AuthorizationCode struct {
	Code                string
	ClientID            string
	UserID              uuid.UUID
	DeviceID            uuid.UUID
	RedirectURI         string
	Scope               string
	CodeChallenge       string    // PKCE: stored challenge
	CodeChallengeMethod string    // PKCE: S256 or plain
	ExpiresAt           time.Time
	CreatedAt           time.Time
}

// NewAuthorizationCode creates a new authorization code.
func NewAuthorizationCode(
	code, clientID string,
	userID, deviceID uuid.UUID,
	redirectURI, scope, codeChallenge, codeChallengeMethod string,
	ttl time.Duration,
) *AuthorizationCode {
	now := time.Now().UTC()
	return &AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		DeviceID:            deviceID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           now.Add(ttl),
		CreatedAt:           now,
	}
}

// IsExpired checks if the authorization code has expired.
func (ac *AuthorizationCode) IsExpired() bool {
	return time.Now().UTC().After(ac.ExpiresAt)
}
