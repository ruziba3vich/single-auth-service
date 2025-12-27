package dto

import (
	"time"

	"github.com/google/uuid"
)

// RegisterRequest is the payload for user registration.
type RegisterRequest struct {
	Username string  `json:"username" binding:"required"`
	Phone    string  `json:"phone" binding:"required"`
	Password string  `json:"password" binding:"required,min=8"`
	Email    *string `json:"email,omitempty"`
}

type RegisterResponse struct {
	UserID    int64     `json:"user_id"`
	Username  string    `json:"username"`
	Phone     string    `json:"phone"`
	Email     *string   `json:"email,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// LoginRequest accepts phone, email, or username as the login identifier.
type LoginRequest struct {
	Login    string `json:"login" binding:"required"`
	Password string `json:"password" binding:"required"`
	ClientID string `json:"client_id" binding:"required"`
}

// LoginResponse contains device-bound tokens after successful login.
type LoginResponse struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	RefreshToken string    `json:"refresh_token"`
	DeviceID     uuid.UUID `json:"device_id"`
	Scope        string    `json:"scope,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token,omitempty"`
}

// AuthorizeRequest is the OAuth 2.1 authorization endpoint request.
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

type AuthorizeResponse struct {
	Code  string `json:"code"`
	State string `json:"state,omitempty"`
}

// TokenRequest handles authorization_code and refresh_token grants.
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

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
	ClientID     string `json:"client_id" binding:"required"`
	DeviceID     string `json:"device_id" binding:"required"`
}

type RevokeTokenRequest struct {
	Token         string `json:"token" binding:"required"`
	TokenTypeHint string `json:"token_type_hint"`
}

// SessionInfo is the API representation of a user session.
type SessionInfo struct {
	SessionID  uuid.UUID `json:"session_id"`
	DeviceID   uuid.UUID `json:"device_id"`
	DeviceName string    `json:"device_name,omitempty"`
	UserAgent  string    `json:"user_agent"`
	IPAddress  string    `json:"ip_address"`
	LastUsedAt time.Time `json:"last_used_at"`
	CreatedAt  time.Time `json:"created_at"`
	IsCurrent  bool      `json:"is_current"`
}

// RegisterFCMTokenRequest binds an FCM push token to a session.
type RegisterFCMTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
	FCMToken     string `json:"fcm_token" binding:"required"`
}

type FCMTokensResponse struct {
	FCMTokens []string `json:"fcm_tokens"`
}

// ListDevicesResponse lists all active sessions for a user.
type ListDevicesResponse struct {
	Sessions []SessionInfo `json:"sessions"`
}
