package config

import (
	"os"
	"strings"
)

// Config holds OAuth client configuration for connecting to the auth service.
type Config struct {
	// AuthServiceURL is the base URL of the single-auth-service
	// Example: "http://localhost:8080"
	AuthServiceURL string

	// ClientID is the OAuth client identifier obtained during client registration
	ClientID string

	// ClientSecret is the OAuth client secret (for confidential clients)
	// This should be loaded from environment variables in production
	ClientSecret string

	// RedirectURI is the callback URL registered with the auth service
	// Example: "http://localhost:3000/auth/callback"
	RedirectURI string

	// Scopes are the OAuth scopes to request
	// Example: []string{"openid", "email"}
	Scopes []string

	// PostLoginRedirect is where to redirect after successful login
	// Example: "/dashboard"
	PostLoginRedirect string

	// ServerAddress is the address this service listens on
	// Example: ":3000"
	ServerAddress string

	// CookieSecret is used for encrypting cookies (must be 32 bytes for AES-256)
	CookieSecret []byte

	// SecureCookies enables Secure flag on cookies (set true in production)
	SecureCookies bool
}

// LoadFromEnv loads configuration from environment variables.
func LoadFromEnv() *Config {
	scopes := os.Getenv("OAUTH_SCOPES")
	if scopes == "" {
		scopes = "openid email"
	}

	cookieSecret := os.Getenv("COOKIE_SECRET")
	if cookieSecret == "" {
		// Default for development only - MUST be set in production
		cookieSecret = "this-is-32-bytes-dev-secret-key!"
	}

	return &Config{
		AuthServiceURL:    getEnv("AUTH_SERVICE_URL", "http://localhost:8080"),
		ClientID:          getEnv("OAUTH_CLIENT_ID", ""),
		ClientSecret:      getEnv("OAUTH_CLIENT_SECRET", ""),
		RedirectURI:       getEnv("OAUTH_REDIRECT_URI", "http://localhost:3000/auth/callback"),
		Scopes:            strings.Split(scopes, " "),
		PostLoginRedirect: getEnv("POST_LOGIN_REDIRECT", "/dashboard"),
		ServerAddress:     getEnv("SERVER_ADDRESS", ":3000"),
		CookieSecret:      []byte(cookieSecret),
		SecureCookies:     getEnv("SECURE_COOKIES", "false") == "true",
	}
}

// ScopesString returns scopes as a space-separated string.
func (c *Config) ScopesString() string {
	return strings.Join(c.Scopes, " ")
}

// AuthorizeURL returns the full authorization endpoint URL.
func (c *Config) AuthorizeURL() string {
	return c.AuthServiceURL + "/authorize"
}

// TokenURL returns the full token endpoint URL.
func (c *Config) TokenURL() string {
	return c.AuthServiceURL + "/token"
}

// LogoutURL returns the full logout endpoint URL.
func (c *Config) LogoutURL() string {
	return c.AuthServiceURL + "/auth/logout"
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
