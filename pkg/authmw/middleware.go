package authmw

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims from the auth service.
type Claims struct {
	jwt.RegisteredClaims
	Email    string `json:"email,omitempty"`
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key.
type JWK struct {
	KID string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// KeyCache caches public keys from JWKS endpoint.
type KeyCache struct {
	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	jwksURL     string
	lastFetch   time.Time
	refreshRate time.Duration
}

// Config holds middleware configuration.
type Config struct {
	// JWKSURL is the URL to fetch public keys (e.g., "http://auth-service:8080/jwks.json")
	JWKSURL string

	// RefreshRate is how often to refresh JWKS (default: 1 hour)
	RefreshRate time.Duration

	// Optional: Required scopes for the endpoint
	RequiredScopes []string

	// Optional: Skip auth for certain paths
	SkipPaths []string
}

// contextKey is the type for context keys.
type contextKey string

const (
	// UserIDKey is the context key for user ID.
	UserIDKey contextKey = "user_id"
	// EmailKey is the context key for email.
	EmailKey contextKey = "email"
	// ClaimsKey is the context key for full claims.
	ClaimsKey contextKey = "claims"
)

// NewKeyCache creates a new key cache.
func NewKeyCache(jwksURL string, refreshRate time.Duration) *KeyCache {
	if refreshRate == 0 {
		refreshRate = time.Hour
	}
	return &KeyCache{
		keys:        make(map[string]*rsa.PublicKey),
		jwksURL:     jwksURL,
		refreshRate: refreshRate,
	}
}

// GetKey returns the public key for the given key ID.
func (kc *KeyCache) GetKey(kid string) (*rsa.PublicKey, error) {
	kc.mu.RLock()
	key, ok := kc.keys[kid]
	needsRefresh := time.Since(kc.lastFetch) > kc.refreshRate
	kc.mu.RUnlock()

	if ok && !needsRefresh {
		return key, nil
	}

	// Refresh keys
	if err := kc.refresh(); err != nil {
		// If refresh fails but we have a cached key, use it
		if ok {
			return key, nil
		}
		return nil, err
	}

	kc.mu.RLock()
	key, ok = kc.keys[kid]
	kc.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("key not found: %s", kid)
	}
	return key, nil
}

func (kc *KeyCache) refresh() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kc.jwksURL, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS fetch failed with status: %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	kc.mu.Lock()
	defer kc.mu.Unlock()

	for _, jwk := range jwks.Keys {
		if jwk.Kty != "RSA" {
			continue
		}
		pubKey, err := jwkToRSAPublicKey(jwk)
		if err != nil {
			continue
		}
		kc.keys[jwk.KID] = pubKey
	}
	kc.lastFetch = time.Now()

	return nil
}

func jwkToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())

	return &rsa.PublicKey{N: n, E: e}, nil
}

// GinMiddleware returns a Gin middleware for JWT validation.
func GinMiddleware(cfg Config) gin.HandlerFunc {
	if cfg.RefreshRate == 0 {
		cfg.RefreshRate = time.Hour
	}
	keyCache := NewKeyCache(cfg.JWKSURL, cfg.RefreshRate)

	return func(c *gin.Context) {
		// Check if path should be skipped
		for _, path := range cfg.SkipPaths {
			if c.Request.URL.Path == path || strings.HasPrefix(c.Request.URL.Path, path) {
				c.Next()
				return
			}
		}

		// Extract token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "missing authorization header",
			})
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "invalid authorization header format",
			})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse and validate token
		claims, err := validateToken(tokenString, keyCache)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": err.Error(),
			})
			return
		}

		// Check required scopes
		if len(cfg.RequiredScopes) > 0 {
			tokenScopes := strings.Split(claims.Scope, " ")
			if !hasRequiredScopes(tokenScopes, cfg.RequiredScopes) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":             "forbidden",
					"error_description": "insufficient scope",
				})
				return
			}
		}

		// Set claims in context
		c.Set(string(UserIDKey), claims.Subject)
		c.Set(string(EmailKey), claims.Email)
		c.Set(string(ClaimsKey), claims)

		c.Next()
	}
}

func validateToken(tokenString string, keyCache *KeyCache) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing key ID in token header")
		}

		// Get public key
		return keyCache.GetKey(kid)
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

func hasRequiredScopes(tokenScopes, requiredScopes []string) bool {
	scopeSet := make(map[string]bool)
	for _, s := range tokenScopes {
		scopeSet[s] = true
	}
	for _, required := range requiredScopes {
		if !scopeSet[required] {
			return false
		}
	}
	return true
}

// GetUserID extracts user ID from Gin context.
func GetUserID(c *gin.Context) (string, bool) {
	id, exists := c.Get(string(UserIDKey))
	if !exists {
		return "", false
	}
	return id.(string), true
}

// GetEmail extracts email from Gin context.
func GetEmail(c *gin.Context) (string, bool) {
	email, exists := c.Get(string(EmailKey))
	if !exists {
		return "", false
	}
	return email.(string), true
}

// GetClaims extracts full claims from Gin context.
func GetClaims(c *gin.Context) (*Claims, bool) {
	claims, exists := c.Get(string(ClaimsKey))
	if !exists {
		return nil, false
	}
	return claims.(*Claims), true
}
