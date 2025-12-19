package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/ruziba3vich/single-auth-service/internal/domain/keys"

	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

// Manager handles JWT creation and validation.
type Manager struct {
	issuer string
}

// NewManager creates a new JWT manager.
func NewManager(issuer string) *Manager {
	return &Manager{issuer: issuer}
}

// AccessTokenClaims represents the claims in an access token.
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	DeviceID string `json:"device_id,omitempty"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
	Type     string `json:"typ"`
}

// IDTokenClaims represents the claims in an OIDC ID token.
type IDTokenClaims struct {
	jwt.RegisteredClaims
	AuthTime      int64  `json:"auth_time"`
	Nonce         string `json:"nonce,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}

// CreateAccessToken creates a signed access token JWT.
func (m *Manager) CreateAccessToken(
	key *keys.SigningKey,
	subject string,
	audience []string,
	deviceID string,
	clientID string,
	scope string,
	ttl time.Duration,
) (string, error) {
	now := time.Now().UTC()

	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   subject,
			Audience:  audience,
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		DeviceID: deviceID,
		ClientID: clientID,
		Scope:    scope,
		Type:     "access",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.KID

	signedToken, err := token.SignedString(key.PrivateKey)
	if err != nil {
		return "", apperrors.Wrap(err, "failed to sign access token")
	}

	return signedToken, nil
}

// CreateIDToken creates a signed OIDC ID token.
func (m *Manager) CreateIDToken(
	key *keys.SigningKey,
	subject string,
	audience string,
	email string,
	emailVerified bool,
	nonce string,
	authTime time.Time,
	ttl time.Duration,
) (string, error) {
	now := time.Now().UTC()

	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		AuthTime:      authTime.Unix(),
		Nonce:         nonce,
		Email:         email,
		EmailVerified: emailVerified,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.KID

	signedToken, err := token.SignedString(key.PrivateKey)
	if err != nil {
		return "", apperrors.Wrap(err, "failed to sign ID token")
	}

	return signedToken, nil
}

// ValidateAccessToken validates an access token and returns the claims.
func (m *Manager) ValidateAccessToken(tokenString string, getKey func(kid string) (*rsa.PublicKey, error)) (*AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID from header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		// Get the public key for this kid
		return getKey(kid)
	})

	if err != nil {
		return nil, apperrors.Wrap(err, "token validation failed")
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok || !token.Valid {
		return nil, apperrors.ErrTokenInvalid
	}

	// Verify issuer
	if claims.Issuer != m.issuer {
		return nil, apperrors.ErrTokenInvalid
	}

	// Verify token type
	if claims.Type != "access" {
		return nil, apperrors.ErrTokenInvalid
	}

	return claims, nil
}

// ValidateIDToken validates an ID token and returns the claims.
func (m *Manager) ValidateIDToken(tokenString string, getKey func(kid string) (*rsa.PublicKey, error)) (*IDTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &IDTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		return getKey(kid)
	})

	if err != nil {
		return nil, apperrors.Wrap(err, "ID token validation failed")
	}

	claims, ok := token.Claims.(*IDTokenClaims)
	if !ok || !token.Valid {
		return nil, apperrors.ErrTokenInvalid
	}

	if claims.Issuer != m.issuer {
		return nil, apperrors.ErrTokenInvalid
	}

	return claims, nil
}

// ExtractKID extracts the key ID from a token without full validation.
// Useful for key lookup before validation.
func (m *Manager) ExtractKID(tokenString string) (string, error) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", apperrors.Wrap(err, "failed to parse token")
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return "", fmt.Errorf("missing kid in token header")
	}

	return kid, nil
}

// GenerateJWK creates a JWK representation of an RSA public key.
func GenerateJWK(key *keys.SigningKey) keys.JWK {
	return keys.JWK{
		KID:       key.KID,
		KeyType:   "RSA",
		Algorithm: key.Algorithm,
		Use:       "sig",
		N:         base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}
}

// GenerateJWKS creates a JWKS from multiple signing keys.
func GenerateJWKS(signingKeys []*keys.SigningKey) keys.JWKS {
	jwks := keys.JWKS{Keys: make([]keys.JWK, 0, len(signingKeys))}
	for _, key := range signingKeys {
		jwks.Keys = append(jwks.Keys, GenerateJWK(key))
	}
	return jwks
}
