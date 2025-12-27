package errors

import (
	"errors"
	"fmt"
)

// Domain errors that map to HTTP responses.
var (
	// User
	ErrUserNotFound          = errors.New("user not found")
	ErrUserAlreadyExists     = errors.New("user already exists")
	ErrPhoneAlreadyExists    = errors.New("phone already exists")
	ErrUsernameAlreadyExists = errors.New("username already exists")
	ErrEmailAlreadyExists    = errors.New("email already exists")
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrUserBanned            = errors.New("user is banned")

	// Session
	ErrSessionNotFound      = errors.New("session not found")
	ErrSessionAlreadyExists = errors.New("session already exists")
	ErrSessionRevoked       = errors.New("session revoked")

	// OAuth (RFC 6749)
	ErrInvalidRequest          = errors.New("invalid_request")
	ErrUnauthorizedClient      = errors.New("unauthorized_client")
	ErrAccessDenied            = errors.New("access_denied")
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	ErrInvalidScope            = errors.New("invalid_scope")
	ErrServerError             = errors.New("server_error")
	ErrInvalidClient           = errors.New("invalid_client")
	ErrInvalidGrant            = errors.New("invalid_grant")
	ErrUnsupportedGrantType    = errors.New("unsupported_grant_type")

	// Token
	ErrTokenExpired  = errors.New("token expired")
	ErrTokenRevoked  = errors.New("token revoked")
	ErrTokenInvalid  = errors.New("token invalid")
	ErrTokenMismatch = errors.New("token mismatch")

	// Device
	ErrDeviceNotFound   = errors.New("device not found")
	ErrDeviceRevoked    = errors.New("device revoked")
	ErrDeviceMismatch   = errors.New("device mismatch")
	ErrDeviceIDRequired = errors.New("device_id required")

	// Client
	ErrClientNotFound      = errors.New("client not found")
	ErrInvalidRedirectURI  = errors.New("invalid redirect_uri")
	ErrInvalidClientSecret = errors.New("invalid client secret")

	// PKCE
	ErrPKCERequired         = errors.New("PKCE required")
	ErrInvalidCodeChallenge = errors.New("invalid code_challenge")
	ErrInvalidCodeVerifier  = errors.New("invalid code_verifier")

	// Signing keys
	ErrKeyNotFound = errors.New("signing key not found")
	ErrNoActiveKey = errors.New("no active signing key")
	ErrKeyExpired  = errors.New("signing key expired")

	// General
	ErrNotFound     = errors.New("not found")
	ErrInternal     = errors.New("internal error")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrValidation   = errors.New("validation error")
)

// OAuthError is an RFC 6749 compliant error response.
type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
	State       string `json:"state,omitempty"`
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

func NewOAuthError(code, description string) *OAuthError {
	return &OAuthError{Code: code, Description: description}
}

// WithState attaches the OAuth state param for redirect errors.
func (e *OAuthError) WithState(state string) *OAuthError {
	e.State = state
	return e
}

// ValidationError holds a single field validation failure.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors collects multiple field validation failures.
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

func (e *ValidationErrors) Error() string {
	return fmt.Sprintf("validation failed: %d errors", len(e.Errors))
}

func (e *ValidationErrors) Add(field, message string) {
	e.Errors = append(e.Errors, ValidationError{Field: field, Message: message})
}

func (e *ValidationErrors) HasErrors() bool {
	return len(e.Errors) > 0
}

// Is is a convenience wrapper for errors.Is.
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// Wrap adds context to an error while preserving the original.
func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}
