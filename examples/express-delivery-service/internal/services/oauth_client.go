package services

import (
	"context"
	"errors"
)

// Common errors returned by OAuthClient implementations.
var (
	ErrInvalidCode         = errors.New("invalid authorization code")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrTokenExpired        = errors.New("token has expired")
	ErrAuthServiceError    = errors.New("auth service returned an error")
)

// TokenResponse represents the response from a token exchange.
type TokenResponse struct {
	// AccessToken is the JWT access token for authenticating API requests
	AccessToken string

	// RefreshToken is used to obtain new access tokens
	RefreshToken string

	// DeviceID is the device binding identifier
	// Must be stored and sent with refresh requests
	DeviceID string

	// ExpiresIn is the access token lifetime in seconds
	ExpiresIn int

	// IDToken is the OpenID Connect ID token (if openid scope was requested)
	IDToken string

	// Scope contains the granted scopes
	Scope string

	// TokenType is typically "Bearer"
	TokenType string
}

// IDTokenClaims represents the claims in an OpenID Connect ID token.
type IDTokenClaims struct {
	// Subject is the user identifier (sub claim)
	Subject string

	// Email is the user's email (if email scope was granted)
	Email string

	// EmailVerified indicates if the email has been verified
	EmailVerified bool

	// IssuedAt is when the token was issued
	IssuedAt int64

	// ExpiresAt is when the token expires
	ExpiresAt int64

	// Nonce is the nonce value from the authorization request
	Nonce string
}

// OAuthClient defines the contract for communicating with the auth service.
// This interface abstracts the HTTP calls to the auth service's OAuth endpoints.
type OAuthClient interface {
	// ExchangeCode exchanges an authorization code for tokens.
	// This is called after the user is redirected back with an auth code.
	//
	// Parameters:
	//   - code: The authorization code from the callback
	//   - codeVerifier: The PKCE code verifier used during authorization
	//
	// The implementation should call POST /token with:
	//   - grant_type=authorization_code
	//   - code=<code>
	//   - code_verifier=<codeVerifier>
	//   - client_id=<from config>
	//   - client_secret=<from config, if confidential client>
	//   - redirect_uri=<from config>
	ExchangeCode(ctx context.Context, code, codeVerifier string) (*TokenResponse, error)

	// RefreshTokens uses a refresh token to obtain new access and refresh tokens.
	// The auth service implements token rotation, so the old refresh token
	// becomes invalid after this call.
	//
	// Parameters:
	//   - refreshToken: The current refresh token
	//   - deviceID: The device binding ID (required for security)
	//
	// The implementation should call POST /token/refresh or POST /token with:
	//   - grant_type=refresh_token
	//   - refresh_token=<refreshToken>
	//   - device_id=<deviceID>
	//   - client_id=<from config>
	RefreshTokens(ctx context.Context, refreshToken, deviceID string) (*TokenResponse, error)

	// RevokeToken revokes a refresh token.
	// Call this when the user logs out to invalidate their token.
	//
	// The implementation should call POST /token/revoke with:
	//   - token=<refreshToken>
	//   - token_type_hint=refresh_token
	//   - client_id=<from config>
	RevokeToken(ctx context.Context, refreshToken string) error

	// Logout logs out a device on the auth service.
	// This revokes the device and all its tokens.
	//
	// The implementation should call POST /auth/logout with:
	//   - Authorization: Bearer <accessToken>
	//   - X-Device-ID: <deviceID>
	Logout(ctx context.Context, accessToken, deviceID string) error

	// ParseIDToken parses and validates an ID token.
	// This extracts user information from the OpenID Connect ID token.
	//
	// The implementation should:
	//   - Fetch JWKS from /.well-known/jwks.json (with caching)
	//   - Verify the signature using the public key
	//   - Validate claims (iss, aud, exp, etc.)
	//   - Return the parsed claims
	ParseIDToken(ctx context.Context, idToken string) (*IDTokenClaims, error)
}
