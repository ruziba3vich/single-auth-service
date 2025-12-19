package keys

import (
	"crypto/rsa"
	"time"
)

// SigningKey represents an RSA key pair used for signing JWTs.
// Multiple keys can exist for key rotation support.
type SigningKey struct {
	KID           string          // Key ID (appears in JWT header)
	PrivateKey    *rsa.PrivateKey // Used for signing (never exposed)
	PublicKey     *rsa.PublicKey  // Exposed via JWKS endpoint
	PrivateKeyPEM string          // PEM-encoded private key (for storage)
	PublicKeyPEM  string          // PEM-encoded public key (for storage)
	Algorithm     string          // Always RS256 for this service
	Active        bool            // Only one key is active for signing
	CreatedAt     time.Time
	ExpiresAt     time.Time // For automatic rotation scheduling
}

// IsValid checks if the key can be used for verification.
// Keys remain valid for verification even after rotation.
func (sk *SigningKey) IsValid() bool {
	return time.Now().UTC().Before(sk.ExpiresAt)
}

// CanSign checks if the key can be used for signing new tokens.
// Only active keys should be used for signing.
func (sk *SigningKey) CanSign() bool {
	return sk.Active && sk.IsValid()
}

// JWK represents a JSON Web Key for the JWKS endpoint.
type JWK struct {
	KID       string `json:"kid"`
	KeyType   string `json:"kty"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	N         string `json:"n"`   // RSA modulus
	E         string `json:"e"`   // RSA exponent
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}
