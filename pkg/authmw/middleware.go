// Package authmw provides JWT token validation middleware for services
// that integrate with the single-auth-service.
//
// Usage with Gin:
//
//	router := gin.Default()
//	router.Use(authmw.GinMiddleware(authmw.Config{
//	    JWKSURL: "http://auth-service:8080/.well-known/jwks.json",
//	}))
//
// Usage with standard net/http:
//
//	mux := http.NewServeMux()
//	handler := authmw.HTTPMiddleware(authmw.Config{
//	    JWKSURL: "http://auth-service:8080/.well-known/jwks.json",
//	})(mux)
//	http.ListenAndServe(":8080", handler)
//
// Standalone validation:
//
//	validator := authmw.NewValidator(authmw.Config{
//	    JWKSURL: "http://auth-service:8080/.well-known/jwks.json",
//	})
//	claims, err := validator.ValidateToken(tokenString)
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

// Claims represents the JWT claims issued by the auth service.
type Claims struct {
	jwt.RegisteredClaims
	Email    string `json:"email,omitempty"`
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
	Type     string `json:"typ,omitempty"` // "access" or "id"
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

// --- Standard net/http middleware ---

// HTTPMiddleware returns a standard net/http middleware for JWT validation.
func HTTPMiddleware(cfg Config) func(http.Handler) http.Handler {
	if cfg.RefreshRate == 0 {
		cfg.RefreshRate = time.Hour
	}
	keyCache := NewKeyCache(cfg.JWKSURL, cfg.RefreshRate)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path should be skipped
			for _, path := range cfg.SkipPaths {
				if r.URL.Path == path || strings.HasPrefix(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Extract token
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"unauthorized","error_description":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error":"unauthorized","error_description":"invalid authorization header format"}`, http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			// Parse and validate token
			claims, err := validateToken(tokenString, keyCache)
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"unauthorized","error_description":"%s"}`, err.Error()), http.StatusUnauthorized)
				return
			}

			// Check required scopes
			if len(cfg.RequiredScopes) > 0 {
				tokenScopes := strings.Split(claims.Scope, " ")
				if !hasRequiredScopes(tokenScopes, cfg.RequiredScopes) {
					http.Error(w, `{"error":"forbidden","error_description":"insufficient scope"}`, http.StatusForbidden)
					return
				}
			}

			// Add claims to request context
			ctx := context.WithValue(r.Context(), UserIDKey, claims.Subject)
			ctx = context.WithValue(ctx, EmailKey, claims.Email)
			ctx = context.WithValue(ctx, ClaimsKey, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserIDFromContext extracts user ID from standard context.
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(UserIDKey).(string)
	return id, ok
}

// GetEmailFromContext extracts email from standard context.
func GetEmailFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(EmailKey).(string)
	return email, ok
}

// GetClaimsFromContext extracts full claims from standard context.
func GetClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(ClaimsKey).(*Claims)
	return claims, ok
}

// --- Standalone Validator ---

// Validator provides standalone token validation without middleware.
type Validator struct {
	keyCache *KeyCache
}

// NewValidator creates a token validator that fetches keys from JWKS endpoint.
func NewValidator(cfg Config) *Validator {
	if cfg.RefreshRate == 0 {
		cfg.RefreshRate = time.Hour
	}
	return &Validator{
		keyCache: NewKeyCache(cfg.JWKSURL, cfg.RefreshRate),
	}
}

// ValidateToken validates a JWT token and returns its claims.
func (v *Validator) ValidateToken(tokenString string) (*Claims, error) {
	return validateToken(tokenString, v.keyCache)
}

// ValidateTokenWithScopes validates a token and checks for required scopes.
func (v *Validator) ValidateTokenWithScopes(tokenString string, requiredScopes []string) (*Claims, error) {
	claims, err := validateToken(tokenString, v.keyCache)
	if err != nil {
		return nil, err
	}

	if len(requiredScopes) > 0 {
		tokenScopes := strings.Split(claims.Scope, " ")
		if !hasRequiredScopes(tokenScopes, requiredScopes) {
			return nil, errors.New("insufficient scope")
		}
	}

	return claims, nil
}

// HasScope checks if the claims include a specific scope.
func (c *Claims) HasScope(scope string) bool {
	for _, s := range strings.Split(c.Scope, " ") {
		if s == scope {
			return true
		}
	}
	return false
}

// GetUserID returns the user ID (subject) as string.
func (c *Claims) GetUserID() string {
	return c.Subject
}
