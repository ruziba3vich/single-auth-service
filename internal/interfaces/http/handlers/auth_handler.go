package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/ruziba3vich/single-auth-service/internal/application/dto"
	"github.com/ruziba3vich/single-auth-service/internal/application/services"
	"github.com/ruziba3vich/single-auth-service/internal/interfaces/http/middleware"
	"github.com/ruziba3vich/single-auth-service/pkg/errors"
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	authService *services.AuthService
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// Register handles user registration.
// POST /auth/register
func (h *AuthHandler) Register(c *gin.Context) {
	var req dto.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	resp, err := h.authService.Register(c.Request.Context(), &req)
	if err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusCreated, resp)
}

// Login handles user login and returns device-bound tokens.
// POST /auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req dto.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ipAddress := middleware.GetClientIP(c)

	resp, err := h.authService.Login(c.Request.Context(), &req, userAgent, ipAddress)
	if err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Logout handles logout for the current device.
// POST /auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	deviceID, err := middleware.GetDeviceID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "device_id required",
		})
		return
	}

	if err := h.authService.Logout(c.Request.Context(), deviceID); err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}

// LogoutDevice handles logout for a specific device.
// POST /logout/device/:device_id
func (h *AuthHandler) LogoutDevice(c *gin.Context) {
	userID, err := middleware.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "authentication required",
		})
		return
	}

	deviceIDStr := c.Param("device_id")
	deviceID, err := uuid.Parse(deviceIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "invalid device_id",
		})
		return
	}

	if err := h.authService.LogoutDevice(c.Request.Context(), userID, deviceID); err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "device logged out successfully"})
}

// LogoutAllOthers handles logout for all devices except current.
// POST /logout/others
func (h *AuthHandler) LogoutAllOthers(c *gin.Context) {
	userID, err := middleware.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "authentication required",
		})
		return
	}

	currentDeviceID, err := middleware.GetDeviceID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "device_id required",
		})
		return
	}

	if err := h.authService.LogoutAllExceptCurrent(c.Request.Context(), userID, currentDeviceID); err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "all other devices logged out"})
}

// LogoutAll handles global logout.
// POST /logout/all
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	userID, err := middleware.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "authentication required",
		})
		return
	}

	if err := h.authService.LogoutAll(c.Request.Context(), userID); err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "all devices logged out"})
}

// ListDevices returns the user's active devices.
// GET /devices
func (h *AuthHandler) ListDevices(c *gin.Context) {
	userID, err := middleware.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "authentication required",
		})
		return
	}

	currentDeviceID, _ := middleware.GetDeviceID(c)

	resp, err := h.authService.GetUserDevices(c.Request.Context(), userID, currentDeviceID)
	if err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

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
	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "internal server error",
		})
	}
}
