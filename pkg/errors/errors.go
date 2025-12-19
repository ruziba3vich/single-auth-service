package errors

import (
	"errors"
	"fmt"
)

// Domain errors - these map to specific HTTP responses
var (
	// User errors
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrEmailNotVerified   = errors.New("email not verified")

	// OAuth errors (RFC 6749 compliant)
	ErrInvalidRequest          = errors.New("invalid_request")
	ErrUnauthorizedClient      = errors.New("unauthorized_client")
	ErrAccessDenied            = errors.New("access_denied")
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	ErrInvalidScope            = errors.New("invalid_scope")
	ErrServerError             = errors.New("server_error")
	ErrInvalidClient           = errors.New("invalid_client")
	ErrInvalidGrant            = errors.New("invalid_grant")
	ErrUnsupportedGrantType    = errors.New("unsupported_grant_type")

	// Token errors
	ErrTokenExpired      = errors.New("token expired")
	ErrTokenRevoked      = errors.New("token revoked")
	ErrTokenInvalid      = errors.New("token invalid")
	ErrTokenMismatch     = errors.New("token mismatch")
	ErrRefreshTokenUsed  = errors.New("refresh token already used")

	// Device errors
	ErrDeviceNotFound   = errors.New("device not found")
	ErrDeviceRevoked    = errors.New("device revoked")
	ErrDeviceMismatch   = errors.New("device mismatch")
	ErrDeviceIDRequired = errors.New("device_id required")

	// Client errors
	ErrClientNotFound      = errors.New("client not found")
	ErrInvalidRedirectURI  = errors.New("invalid redirect_uri")
	ErrInvalidClientSecret = errors.New("invalid client secret")

	// PKCE errors
	ErrPKCERequired         = errors.New("PKCE required")
	ErrInvalidCodeChallenge = errors.New("invalid code_challenge")
	ErrInvalidCodeVerifier  = errors.New("invalid code_verifier")

	// Key errors
	ErrKeyNotFound     = errors.New("signing key not found")
	ErrNoActiveKey     = errors.New("no active signing key")
	ErrKeyExpired      = errors.New("signing key expired")

	// General errors
	ErrNotFound     = errors.New("not found")
	ErrInternal     = errors.New("internal error")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrValidation   = errors.New("validation error")
)

// OAuthError represents an OAuth 2.0 error response.
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

// NewOAuthError creates a new OAuth error.
func NewOAuthError(code, description string) *OAuthError {
	return &OAuthError{
		Code:        code,
		Description: description,
	}
}

// WithState adds state parameter to the error.
func (e *OAuthError) WithState(state string) *OAuthError {
	e.State = state
	return e
}

// ValidationError represents a field validation error.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors is a collection of validation errors.
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

func (e *ValidationErrors) Error() string {
	return fmt.Sprintf("validation failed: %d errors", len(e.Errors))
}

// Add appends a validation error.
func (e *ValidationErrors) Add(field, message string) {
	e.Errors = append(e.Errors, ValidationError{Field: field, Message: message})
}

// HasErrors returns true if there are validation errors.
func (e *ValidationErrors) HasErrors() bool {
	return len(e.Errors) > 0
}

// Is wraps errors.Is for convenience.
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// Wrap wraps an error with additional context.
func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}
