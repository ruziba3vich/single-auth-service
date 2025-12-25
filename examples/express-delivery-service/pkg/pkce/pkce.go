package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

const (
	// VerifierLength is the length of the code verifier in bytes.
	// The resulting base64url string will be longer.
	// OAuth 2.1 requires 43-128 characters.
	VerifierLength = 32
)

// GenerateVerifier creates a cryptographically random code verifier.
// The verifier is base64url encoded without padding.
// Returns a string of 43 characters (32 bytes base64url encoded).
func GenerateVerifier() (string, error) {
	bytes := make([]byte, VerifierLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateChallenge creates a code challenge from a verifier.
// Uses the S256 method: base64url(sha256(verifier))
// This is the only method supported by OAuth 2.1.
func GenerateChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// GenerateState creates a random state value for CSRF protection.
// The state is base64url encoded without padding.
func GenerateState() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateNonce creates a random nonce for OpenID Connect.
// The nonce prevents replay attacks.
func GenerateNonce() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// Pair holds a generated verifier and its challenge.
type Pair struct {
	Verifier  string
	Challenge string
}

// GeneratePair generates both a verifier and its corresponding challenge.
// This is a convenience function for the common case.
func GeneratePair() (*Pair, error) {
	verifier, err := GenerateVerifier()
	if err != nil {
		return nil, err
	}
	challenge := GenerateChallenge(verifier)
	return &Pair{
		Verifier:  verifier,
		Challenge: challenge,
	}, nil
}
