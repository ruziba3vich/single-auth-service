package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/ruziba3vich/single-auth-service/internal/domain/keys"
)

// RSAKeyGenerator generates RSA key pairs for JWT signing.
type RSAKeyGenerator struct {
	keySize        int
	validityPeriod time.Duration
	tokenGen       *TokenGenerator
}

// NewRSAKeyGenerator creates a new RSA key generator.
// keySize should be at least 2048 bits (recommended: 2048 or 4096).
func NewRSAKeyGenerator(keySize int, validityPeriod time.Duration) *RSAKeyGenerator {
	return &RSAKeyGenerator{
		keySize:        keySize,
		validityPeriod: validityPeriod,
		tokenGen:       NewTokenGenerator(),
	}
}

// Generate creates a new RSA signing key.
func (g *RSAKeyGenerator) Generate() (*keys.SigningKey, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, g.keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Generate key ID
	kid, err := g.tokenGen.GenerateKID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}

	// Encode keys to PEM
	privateKeyPEM, err := g.encodePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	publicKeyPEM, err := g.encodePublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	return &keys.SigningKey{
		KID:           kid,
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		PrivateKeyPEM: privateKeyPEM,
		PublicKeyPEM:  publicKeyPEM,
		Algorithm:     "RS256",
		Active:        true,
		CreatedAt:     now,
		ExpiresAt:     now.Add(g.validityPeriod),
	}, nil
}

// encodePrivateKey encodes an RSA private key to PEM format.
func (g *RSAKeyGenerator) encodePrivateKey(key *rsa.PrivateKey) (string, error) {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// encodePublicKey encodes an RSA public key to PEM format.
func (g *RSAKeyGenerator) encodePublicKey(key *rsa.PublicKey) (string, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// ParsePrivateKey parses a PEM-encoded RSA private key.
func ParsePrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unknown PEM block type: %s", block.Type)
	}
}

// ParsePublicKey parses a PEM-encoded RSA public key.
func ParsePublicKey(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaKey, nil
}
