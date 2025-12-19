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

// OAuthHandler handles OAuth 2.1 endpoints.
type OAuthHandler struct {
	oauthService *services.OAuthService
	authService  *services.AuthService
	keyService   *services.KeyService
	issuer       string
}

// NewOAuthHandler creates a new OAuth handler.
func NewOAuthHandler(
	oauthService *services.OAuthService,
	authService *services.AuthService,
	keyService *services.KeyService,
	issuer string,
) *OAuthHandler {
	return &OAuthHandler{
		oauthService: oauthService,
		authService:  authService,
		keyService:   keyService,
		issuer:       issuer,
	}
}

// OpenIDConfiguration returns the OIDC discovery document.
// GET /.well-known/openid-configuration
func (h *OAuthHandler) OpenIDConfiguration(c *gin.Context) {
	config := dto.NewOpenIDConfiguration(h.issuer)
	c.JSON(http.StatusOK, config)
}

// JWKS returns the JSON Web Key Set.
// GET /jwks.json
func (h *OAuthHandler) JWKS(c *gin.Context) {
	jwks, err := h.keyService.GetJWKS(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to get keys",
		})
		return
	}

	// Cache for 1 hour
	c.Header("Cache-Control", "public, max-age=3600")
	c.JSON(http.StatusOK, jwks)
}

// Authorize handles the authorization endpoint.
// GET /authorize
// In a real implementation, this would render a consent page.
// For this implementation, we assume the user is already authenticated
// and authorized, and we issue the code directly.
func (h *OAuthHandler) Authorize(c *gin.Context) {
	var req dto.AuthorizeRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Validate the authorization request
	result, err := h.oauthService.ValidateAuthorizeRequest(c.Request.Context(), &req)
	if err != nil {
		// Check if it's an OAuth error
		if oauthErr, ok := err.(*errors.OAuthError); ok {
			// If redirect_uri was validated, redirect with error
			if result != nil && result.RedirectURI != "" {
				redirectURL := h.oauthService.BuildErrorRedirect(result.RedirectURI, oauthErr)
				c.Redirect(http.StatusFound, redirectURL)
				return
			}
			// Otherwise return error directly
			c.JSON(http.StatusBadRequest, oauthErr)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "internal error",
		})
		return
	}

	// In a real implementation, you would:
	// 1. Check if user is logged in (session/cookie)
	// 2. Show consent page if not already consented
	// 3. Create auth code after user consents

	// For this implementation, we return a form to demonstrate the flow
	// The frontend should collect user consent and call POST /authorize
	c.JSON(http.StatusOK, gin.H{
		"message":      "Authorization required",
		"client_id":    result.Client.ClientID,
		"client_name":  result.Client.Name,
		"scope":        result.Scope,
		"redirect_uri": result.RedirectURI,
		"state":        result.State,
	})
}

// AuthorizeConsent handles user consent submission.
// POST /authorize
// Called after user consents to the authorization.
func (h *OAuthHandler) AuthorizeConsent(c *gin.Context) {
	var req dto.AuthorizeRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Validate the authorization request
	result, err := h.oauthService.ValidateAuthorizeRequest(c.Request.Context(), &req)
	if err != nil {
		if oauthErr, ok := err.(*errors.OAuthError); ok {
			c.JSON(http.StatusBadRequest, oauthErr)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "internal error",
		})
		return
	}

	// Get user ID from authenticated session
	userID, err := middleware.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "user authentication required",
		})
		return
	}

	// Get or create device for this authorization
	deviceID, _ := middleware.GetDeviceID(c)
	if deviceID == uuid.Nil {
		deviceID = uuid.New()
	}

	// Create authorization code
	code, err := h.oauthService.CreateAuthorizationCode(c.Request.Context(), result, userID, deviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to create authorization code",
		})
		return
	}

	// Build redirect URL with code
	redirectURL := h.oauthService.BuildAuthorizationRedirect(result.RedirectURI, code, result.State)
	c.Redirect(http.StatusFound, redirectURL)
}

// Token handles the token endpoint.
// POST /token
func (h *OAuthHandler) Token(c *gin.Context) {
	var req dto.TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ipAddress := middleware.GetClientIP(c)

	switch req.GrantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(c, &req, userAgent, ipAddress)
	case "refresh_token":
		h.handleRefreshTokenGrant(c, &req, ipAddress)
	case "client_credentials":
		h.handleClientCredentialsGrant(c, &req)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "grant_type must be authorization_code, refresh_token, or client_credentials",
		})
	}
}

// handleAuthorizationCodeGrant handles the authorization code exchange.
func (h *OAuthHandler) handleAuthorizationCodeGrant(c *gin.Context, req *dto.TokenRequest, userAgent, ipAddress string) {
	if req.Code == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "code is required",
		})
		return
	}

	if req.RedirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "redirect_uri is required",
		})
		return
	}

	if req.CodeVerifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "code_verifier is required",
		})
		return
	}

	resp, err := h.oauthService.ExchangeAuthorizationCode(c.Request.Context(), req, userAgent, ipAddress)
	if err != nil {
		handleOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// handleRefreshTokenGrant handles token refresh.
func (h *OAuthHandler) handleRefreshTokenGrant(c *gin.Context, req *dto.TokenRequest, ipAddress string) {
	if req.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "refresh_token is required",
		})
		return
	}

	if req.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	if req.DeviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "device_id is required",
		})
		return
	}

	refreshReq := &dto.RefreshTokenRequest{
		RefreshToken: req.RefreshToken,
		ClientID:     req.ClientID,
		DeviceID:     req.DeviceID,
	}

	resp, err := h.authService.RefreshToken(c.Request.Context(), refreshReq, ipAddress)
	if err != nil {
		handleOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// handleClientCredentialsGrant handles client credentials flow.
func (h *OAuthHandler) handleClientCredentialsGrant(c *gin.Context, req *dto.TokenRequest) {
	ccReq := &dto.ClientCredentialsRequest{
		GrantType:    req.GrantType,
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		Scope:        req.Scope,
	}

	resp, err := h.oauthService.ClientCredentialsGrant(c.Request.Context(), ccReq)
	if err != nil {
		handleOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// RefreshToken handles explicit refresh token requests.
// POST /token/refresh
func (h *OAuthHandler) RefreshToken(c *gin.Context) {
	var req dto.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	ipAddress := middleware.GetClientIP(c)

	resp, err := h.authService.RefreshToken(c.Request.Context(), &req, ipAddress)
	if err != nil {
		handleOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// RevokeToken handles token revocation.
// POST /token/revoke
func (h *OAuthHandler) RevokeToken(c *gin.Context) {
	var req dto.RevokeTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Per RFC 7009, always return 200 even if token doesn't exist
	_ = h.authService.RevokeToken(c.Request.Context(), req.Token)

	c.JSON(http.StatusOK, gin.H{"revoked": true})
}

// CreateClient handles client registration.
// POST /oauth/client
func (h *OAuthHandler) CreateClient(c *gin.Context) {
	var req dto.CreateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	resp, err := h.oauthService.CreateClient(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to create client",
		})
		return
	}

	c.JSON(http.StatusCreated, resp)
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
