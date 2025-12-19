package dto

import (
	"time"

	"github.com/google/uuid"
)

// RegisterRequest represents a user registration request.
type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

// RegisterResponse represents a successful registration.
type RegisterResponse struct {
	UserID        uuid.UUID `json:"user_id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
}

// LoginRequest represents a user login request.
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	ClientID string `json:"client_id" binding:"required"`
}

// LoginResponse represents a successful login with device-bound tokens.
type LoginResponse struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	RefreshToken string    `json:"refresh_token"`
	DeviceID     uuid.UUID `json:"device_id"`
	Scope        string    `json:"scope,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
}

// LogoutRequest represents a logout request.
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token,omitempty"`
}

// AuthorizeRequest represents an OAuth authorization request.
type AuthorizeRequest struct {
	ResponseType        string `form:"response_type" binding:"required"`
	ClientID            string `form:"client_id" binding:"required"`
	RedirectURI         string `form:"redirect_uri" binding:"required"`
	Scope               string `form:"scope"`
	State               string `form:"state"`
	CodeChallenge       string `form:"code_challenge" binding:"required"`
	CodeChallengeMethod string `form:"code_challenge_method" binding:"required"`
	Nonce               string `form:"nonce"`
}

// AuthorizeResponse represents an authorization response (redirect parameters).
type AuthorizeResponse struct {
	Code  string `json:"code"`
	State string `json:"state,omitempty"`
}

// TokenRequest represents an OAuth token request.
type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required"`
	Code         string `form:"code"`
	RedirectURI  string `form:"redirect_uri"`
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
	CodeVerifier string `form:"code_verifier"`
	RefreshToken string `form:"refresh_token"`
	Scope        string `form:"scope"`
	DeviceID     string `form:"device_id"`
}

// TokenResponse represents an OAuth token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
}

// RefreshTokenRequest represents a token refresh request.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
	ClientID     string `json:"client_id" binding:"required"`
	DeviceID     string `json:"device_id" binding:"required"`
}

// RevokeTokenRequest represents a token revocation request.
type RevokeTokenRequest struct {
	Token         string `json:"token" binding:"required"`
	TokenTypeHint string `json:"token_type_hint"`
}

// DeviceInfo represents a user device for API responses.
type DeviceInfo struct {
	DeviceID   uuid.UUID `json:"device_id"`
	DeviceName string    `json:"device_name,omitempty"`
	UserAgent  string    `json:"user_agent"`
	IPAddress  string    `json:"ip_address"`
	LastUsedAt time.Time `json:"last_used_at"`
	CreatedAt  time.Time `json:"created_at"`
	IsCurrent  bool      `json:"is_current"`
}

// ListDevicesResponse represents a list of user devices.
type ListDevicesResponse struct {
	Devices []DeviceInfo `json:"devices"`
}

// RevokeDeviceRequest represents a request to revoke a specific device.
type RevokeDeviceRequest struct {
	DeviceID string `uri:"device_id" binding:"required,uuid"`
}
