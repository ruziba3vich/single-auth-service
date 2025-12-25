package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/ruziba3vich/single-auth-service/pkg/errors"
)

// handleAuthError converts domain errors to HTTP responses.
func handleAuthError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errors.ErrUserAlreadyExists):
		c.JSON(http.StatusConflict, gin.H{
			"error":             "user_exists",
			"error_description": "user with this email already exists",
		})
	case errors.Is(err, errors.ErrInvalidCredentials):
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_credentials",
			"error_description": "invalid email or password",
		})
	case errors.Is(err, errors.ErrUserNotFound):
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "user_not_found",
			"error_description": "user not found",
		})
	case errors.Is(err, errors.ErrDeviceNotFound):
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "device_not_found",
			"error_description": "device not found",
		})
	case errors.Is(err, errors.ErrDeviceRevoked):
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "device_revoked",
			"error_description": "device has been revoked",
		})
	case errors.Is(err, errors.ErrDeviceMismatch):
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "device_mismatch",
			"error_description": "token not valid for this device",
		})
	case errors.Is(err, errors.ErrForbidden):
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "forbidden",
			"error_description": "access denied",
		})
	case errors.Is(err, errors.ErrInvalidClient):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "invalid client",
		})
	case errors.Is(err, errors.ErrInvalidGrant):
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_grant",
			"error_description": "invalid or expired token",
		})
	case errors.Is(err, errors.ErrTokenRevoked):
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "token_revoked",
			"error_description": "token has been revoked",
		})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "internal server error",
		})
	}
}

// handleOAuthError converts domain errors to OAuth error responses.
func handleOAuthError(c *gin.Context, err error) {
	// Check for OAuth error type
	if oauthErr, ok := err.(*errors.OAuthError); ok {
		c.JSON(http.StatusBadRequest, oauthErr)
		return
	}

	switch {
	case errors.Is(err, errors.ErrInvalidGrant):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "invalid or expired grant",
		})
	case errors.Is(err, errors.ErrInvalidClient):
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "invalid client credentials",
		})
	case errors.Is(err, errors.ErrDeviceMismatch):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "device binding mismatch",
		})
	case errors.Is(err, errors.ErrDeviceRevoked):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "device has been revoked",
		})
	case errors.Is(err, errors.ErrTokenRevoked):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "token has been revoked",
		})
	case errors.Is(err, errors.ErrTokenExpired):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "token has expired",
		})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "internal server error",
		})
	}
}
