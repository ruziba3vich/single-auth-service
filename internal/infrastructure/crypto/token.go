package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// TokenGenerator provides cryptographically secure token generation.
type TokenGenerator struct{}

// NewTokenGenerator creates a new token generator.
func NewTokenGenerator() *TokenGenerator {
	return &TokenGenerator{}
}

// GenerateToken generates a cryptographically secure random token.
// Returns the token as a URL-safe base64 string.
func (g *TokenGenerator) GenerateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateRefreshToken generates a refresh token (256 bits / 32 bytes).
func (g *TokenGenerator) GenerateRefreshToken() (string, error) {
	return g.GenerateToken(32)
}

// GenerateAuthorizationCode generates an authorization code (256 bits).
func (g *TokenGenerator) GenerateAuthorizationCode() (string, error) {
	return g.GenerateToken(32)
}

// GenerateCSRFToken generates a CSRF token.
func (g *TokenGenerator) GenerateCSRFToken(length int) (string, error) {
	return g.GenerateToken(length)
}

// HashToken creates a SHA-256 hash of a token for secure storage.
// Refresh tokens are stored as hashes so they cannot be leaked from the DB.
func (g *TokenGenerator) HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// PKCECodeVerifier generates a PKCE code verifier (43-128 characters).
func (g *TokenGenerator) PKCECodeVerifier() (string, error) {
	// Generate 32 random bytes (will become 43 base64 chars)
	return g.GenerateToken(32)
}

// PKCECodeChallenge generates a PKCE code challenge from a verifier.
// Uses S256 method: BASE64URL(SHA256(code_verifier))
func (g *TokenGenerator) PKCECodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// VerifyPKCE verifies a PKCE code verifier against a stored challenge.
// Supports both S256 and plain methods (plain only for testing).
func (g *TokenGenerator) VerifyPKCE(verifier, challenge, method string) bool {
	switch method {
	case "S256":
		computed := g.PKCECodeChallenge(verifier)
		return computed == challenge
	case "plain":
		// Plain method is NOT recommended for production
		// but included for completeness per OAuth 2.1 spec
		return verifier == challenge
	default:
		return false
	}
}

// GenerateKID generates a key ID for JWT signing keys.
func (g *TokenGenerator) GenerateKID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate key ID: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
