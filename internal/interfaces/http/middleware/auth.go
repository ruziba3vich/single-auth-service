package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/ruziba3vich/single-auth-service/internal/application/services"
	"github.com/ruziba3vich/single-auth-service/pkg/errors"
	"github.com/ruziba3vich/single-auth-service/pkg/jwt"
)

// ContextKey is a type for context keys.
type ContextKey string

const (
	// ContextKeyUserID is the context key for user ID.
	ContextKeyUserID ContextKey = "user_id"
	// ContextKeyDeviceID is the context key for device ID.
	ContextKeyDeviceID ContextKey = "device_id"
	// ContextKeyClientID is the context key for client ID.
	ContextKeyClientID ContextKey = "client_id"
	// ContextKeyScope is the context key for token scope.
	ContextKeyScope ContextKey = "scope"
)

// AuthMiddleware validates JWT access tokens and device binding.
type AuthMiddleware struct {
	jwtManager *jwt.Manager
	keyService *services.KeyService
}

// NewAuthMiddleware creates a new auth middleware.
func NewAuthMiddleware(jwtManager *jwt.Manager, keyService *services.KeyService) *AuthMiddleware {
	return &AuthMiddleware{
		jwtManager: jwtManager,
		keyService: keyService,
	}
}

// RequireAuth returns a middleware that requires a valid access token.
func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract Bearer token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "missing Authorization header",
			})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "invalid Authorization header format",
			})
			return
		}

		tokenString := parts[1]

		// Validate token
		claims, err := m.jwtManager.ValidateAccessToken(
			tokenString,
			m.keyService.GetKeyLookupFunc(c.Request.Context()),
		)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "invalid or expired token",
			})
			return
		}

		// CRITICAL: Verify device binding for user tokens
		if claims.DeviceID != "" {
			deviceIDHeader := c.GetHeader("X-Device-ID")
			if deviceIDHeader == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error":             "unauthorized",
					"error_description": "X-Device-ID header required",
				})
				return
			}

			if claims.DeviceID != deviceIDHeader {
				// SECURITY: Device mismatch indicates potential token theft
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error":             "unauthorized",
					"error_description": "device mismatch",
				})
				return
			}
		}

		// Set context values
		c.Set(string(ContextKeyUserID), claims.Subject)
		c.Set(string(ContextKeyDeviceID), claims.DeviceID)
		c.Set(string(ContextKeyClientID), claims.ClientID)
		c.Set(string(ContextKeyScope), claims.Scope)

		c.Next()
	}
}

// RequireDeviceID returns a middleware that requires X-Device-ID header.
func (m *AuthMiddleware) RequireDeviceID() gin.HandlerFunc {
	return func(c *gin.Context) {
		deviceID := c.GetHeader("X-Device-ID")
		if deviceID == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "X-Device-ID header required",
			})
			return
		}

		// Validate UUID format
		if _, err := uuid.Parse(deviceID); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "invalid X-Device-ID format",
			})
			return
		}

		c.Set(string(ContextKeyDeviceID), deviceID)
		c.Next()
	}
}

// OptionalAuth extracts auth info if present but doesn't require it.
func (m *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.Next()
			return
		}

		claims, err := m.jwtManager.ValidateAccessToken(
			parts[1],
			m.keyService.GetKeyLookupFunc(c.Request.Context()),
		)
		if err != nil {
			c.Next()
			return
		}

		c.Set(string(ContextKeyUserID), claims.Subject)
		c.Set(string(ContextKeyDeviceID), claims.DeviceID)
		c.Set(string(ContextKeyClientID), claims.ClientID)
		c.Set(string(ContextKeyScope), claims.Scope)

		c.Next()
	}
}

// GetUserID extracts user ID from context.
func GetUserID(c *gin.Context) (uuid.UUID, error) {
	userIDStr, exists := c.Get(string(ContextKeyUserID))
	if !exists {
		return uuid.Nil, errors.ErrUnauthorized
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		return uuid.Nil, errors.ErrUnauthorized
	}

	return userID, nil
}

// GetDeviceID extracts device ID from context.
func GetDeviceID(c *gin.Context) (uuid.UUID, error) {
	deviceIDStr, exists := c.Get(string(ContextKeyDeviceID))
	if !exists {
		return uuid.Nil, errors.ErrDeviceIDRequired
	}

	str, ok := deviceIDStr.(string)
	if !ok || str == "" {
		return uuid.Nil, errors.ErrDeviceIDRequired
	}

	deviceID, err := uuid.Parse(str)
	if err != nil {
		return uuid.Nil, errors.ErrDeviceIDRequired
	}

	return deviceID, nil
}

// GetClientIP extracts the client IP address.
func GetClientIP(c *gin.Context) string {
	// Check X-Forwarded-For first (for proxies)
	ip := c.GetHeader("X-Forwarded-For")
	if ip != "" {
		// Take the first IP if multiple
		if idx := strings.Index(ip, ","); idx != -1 {
			ip = strings.TrimSpace(ip[:idx])
		}
		return ip
	}

	// Fall back to RemoteAddr
	return c.ClientIP()
}

// CSRF middleware for protecting against cross-site request forgery.
type CSRFMiddleware struct {
	cookieName string
	headerName string
	secure     bool
	domain     string
	sameSite   http.SameSite
}

// NewCSRFMiddleware creates a new CSRF middleware.
func NewCSRFMiddleware(cookieName, headerName string, secure bool, domain string, sameSite string) *CSRFMiddleware {
	var ss http.SameSite
	switch strings.ToLower(sameSite) {
	case "strict":
		ss = http.SameSiteStrictMode
	case "lax":
		ss = http.SameSiteLaxMode
	case "none":
		ss = http.SameSiteNoneMode
	default:
		ss = http.SameSiteStrictMode
	}

	return &CSRFMiddleware{
		cookieName: cookieName,
		headerName: headerName,
		secure:     secure,
		domain:     domain,
		sameSite:   ss,
	}
}

// Protect returns a middleware that validates CSRF tokens.
func (m *CSRFMiddleware) Protect() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip safe methods
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		// Get token from cookie
		cookieToken, err := c.Cookie(m.cookieName)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "forbidden",
				"error_description": "CSRF token missing from cookie",
			})
			return
		}

		// Get token from header
		headerToken := c.GetHeader(m.headerName)
		if headerToken == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "forbidden",
				"error_description": "CSRF token missing from header",
			})
			return
		}

		// Compare tokens
		if cookieToken != headerToken {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "forbidden",
				"error_description": "CSRF token mismatch",
			})
			return
		}

		c.Next()
	}
}

// SetToken sets the CSRF token cookie.
func (m *CSRFMiddleware) SetToken(c *gin.Context, token string) {
	c.SetSameSite(m.sameSite)
	c.SetCookie(
		m.cookieName,
		token,
		3600, // 1 hour
		"/",
		m.domain,
		m.secure,
		true, // httpOnly
	)
}
