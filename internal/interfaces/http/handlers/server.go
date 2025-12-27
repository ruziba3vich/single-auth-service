package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/ruziba3vich/single-auth-service/internal/application/dto"
	"github.com/ruziba3vich/single-auth-service/internal/application/services"
	"github.com/ruziba3vich/single-auth-service/internal/generated"
	"github.com/ruziba3vich/single-auth-service/internal/interfaces/http/middleware"
	"github.com/ruziba3vich/single-auth-service/pkg/errors"

	openapi_types "github.com/oapi-codegen/runtime/types"
)

// Server implements the generated.ServerInterface using the application services.
type Server struct {
	authService  *services.AuthService
	oauthService *services.OAuthService
	keyService   *services.KeyService
	issuer       string
	dbHealth     HealthChecker
	redisHealth  HealthChecker
}

// ServerDeps contains dependencies for the server.
type ServerDeps struct {
	AuthService  *services.AuthService
	OAuthService *services.OAuthService
	KeyService   *services.KeyService
	Issuer       string
	DBHealth     HealthChecker
	RedisHealth  HealthChecker
}

// NewServer creates a new server implementing the OpenAPI interface.
func NewServer(deps *ServerDeps) *Server {
	return &Server{
		authService:  deps.AuthService,
		oauthService: deps.OAuthService,
		keyService:   deps.KeyService,
		issuer:       deps.Issuer,
		dbHealth:     deps.DBHealth,
		redisHealth:  deps.RedisHealth,
	}
}

// Ensure Server implements ServerInterface
var _ generated.ServerInterface = (*Server)(nil)

// ============================================================================
// Health Endpoints
// ============================================================================

func (s *Server) GetHealth(c *gin.Context) {
	h := NewHealthHandler(s.dbHealth, s.redisHealth)
	h.Health(c)
}

func (s *Server) GetReady(c *gin.Context) {
	h := NewHealthHandler(s.dbHealth, s.redisHealth)
	h.Ready(c)
}

func (s *Server) GetLive(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"alive": true})
}

// ============================================================================
// Auth Endpoints
// ============================================================================

func (s *Server) Register(c *gin.Context) {
	var req generated.RegisterJSONRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Convert to service DTO
	var email *string
	if req.Email != nil {
		e := string(*req.Email)
		email = &e
	}
	serviceReq := &dto.RegisterRequest{
		Username: req.Username,
		Phone:    req.Phone,
		Password: req.Password,
		Email:    email,
	}

	ipAddress := middleware.GetClientIP(c)
	resp, err := s.authService.Register(c.Request.Context(), serviceReq, ipAddress)
	if err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusCreated, resp)
}

func (s *Server) Login(c *gin.Context) {
	var req generated.LoginJSONRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Convert to service DTO
	serviceReq := &dto.LoginRequest{
		Login:    req.Login,
		Password: req.Password,
		ClientID: req.ClientId,
	}

	userAgent := c.GetHeader("User-Agent")
	ipAddress := middleware.GetClientIP(c)

	resp, err := s.authService.Login(c.Request.Context(), serviceReq, userAgent, ipAddress)
	if err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (s *Server) Logout(c *gin.Context, params generated.LogoutParams) {
	var deviceID uuid.UUID
	if params.XDeviceID != nil {
		deviceID = uuid.UUID(*params.XDeviceID)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "device_id required",
		})
		return
	}

	if err := s.authService.Logout(c.Request.Context(), deviceID); err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}

func (s *Server) ListDevices(c *gin.Context, params generated.ListDevicesParams) {
	userID, err := middleware.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "authentication required",
		})
		return
	}

	var currentDeviceID uuid.UUID
	if params.XDeviceID != nil {
		currentDeviceID = uuid.UUID(*params.XDeviceID)
	}

	resp, err := s.authService.GetUserDevices(c.Request.Context(), userID, currentDeviceID)
	if err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (s *Server) LogoutDevice(c *gin.Context, deviceId openapi_types.UUID) {
	userID, err := middleware.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "authentication required",
		})
		return
	}

	if err := s.authService.LogoutDevice(c.Request.Context(), userID, uuid.UUID(deviceId)); err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "device logged out successfully"})
}

func (s *Server) LogoutAllOthers(c *gin.Context, params generated.LogoutAllOthersParams) {
	userID, err := middleware.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "authentication required",
		})
		return
	}

	if params.XDeviceID == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "device_id required",
		})
		return
	}

	currentDeviceID := uuid.UUID(*params.XDeviceID)
	if err := s.authService.LogoutAllExceptCurrent(c.Request.Context(), userID, currentDeviceID); err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "all other devices logged out"})
}

func (s *Server) LogoutAll(c *gin.Context) {
	userID, err := middleware.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "authentication required",
		})
		return
	}

	if err := s.authService.LogoutAll(c.Request.Context(), userID); err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "all devices logged out"})
}

// ============================================================================
// OAuth Endpoints
// ============================================================================

func (s *Server) GetOpenIDConfiguration(c *gin.Context) {
	config := dto.NewOpenIDConfiguration(s.issuer)
	c.JSON(http.StatusOK, config)
}

func (s *Server) GetJWKS(c *gin.Context) {
	jwks, err := s.keyService.GetJWKS(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to get keys",
		})
		return
	}

	c.Header("Cache-Control", "public, max-age=3600")
	c.JSON(http.StatusOK, jwks)
}

func (s *Server) Authorize(c *gin.Context, params generated.AuthorizeParams) {
	// Convert generated params to service DTO
	req := &dto.AuthorizeRequest{
		ResponseType:        string(params.ResponseType),
		ClientID:            params.ClientId,
		RedirectURI:         params.RedirectUri,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: string(params.CodeChallengeMethod),
	}
	if params.Scope != nil {
		req.Scope = *params.Scope
	}
	if params.State != nil {
		req.State = *params.State
	}
	if params.Nonce != nil {
		req.Nonce = *params.Nonce
	}

	result, err := s.oauthService.ValidateAuthorizeRequest(c.Request.Context(), req)
	if err != nil {
		if oauthErr, ok := err.(*errors.OAuthError); ok {
			if result != nil && result.RedirectURI != "" {
				redirectURL := s.oauthService.BuildErrorRedirect(result.RedirectURI, oauthErr)
				c.Redirect(http.StatusFound, redirectURL)
				return
			}
			c.JSON(http.StatusBadRequest, oauthErr)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "internal error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "Authorization required",
		"client_id":    result.Client.ClientID,
		"client_name":  result.Client.Name,
		"scope":        result.Scope,
		"redirect_uri": result.RedirectURI,
		"state":        result.State,
	})
}

func (s *Server) AuthorizeConsent(c *gin.Context) {
	var body generated.AuthorizeConsentFormdataRequestBody
	if err := c.ShouldBind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Convert to service DTO
	req := &dto.AuthorizeRequest{
		ResponseType:        string(body.ResponseType),
		ClientID:            body.ClientId,
		RedirectURI:         body.RedirectUri,
		CodeChallenge:       body.CodeChallenge,
		CodeChallengeMethod: string(body.CodeChallengeMethod),
	}
	if body.Scope != nil {
		req.Scope = *body.Scope
	}
	if body.State != nil {
		req.State = *body.State
	}
	if body.Nonce != nil {
		req.Nonce = *body.Nonce
	}

	result, err := s.oauthService.ValidateAuthorizeRequest(c.Request.Context(), req)
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

	userID, err := middleware.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "user authentication required",
		})
		return
	}

	deviceID, _ := middleware.GetDeviceID(c)
	if deviceID == uuid.Nil {
		deviceID = uuid.New()
	}

	code, err := s.oauthService.CreateAuthorizationCode(c.Request.Context(), result, userID, deviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to create authorization code",
		})
		return
	}

	redirectURL := s.oauthService.BuildAuthorizationRedirect(result.RedirectURI, code, result.State)
	c.Redirect(http.StatusFound, redirectURL)
}

func (s *Server) Token(c *gin.Context) {
	var body generated.TokenFormdataRequestBody
	if err := c.ShouldBind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ipAddress := middleware.GetClientIP(c)

	switch body.GrantType {
	case generated.TokenFormdataBodyGrantTypeAuthorizationCode:
		s.handleAuthorizationCodeGrant(c, &body, userAgent, ipAddress)
	case generated.TokenFormdataBodyGrantTypeRefreshToken:
		s.handleRefreshTokenGrant(c, &body, ipAddress)
	case generated.TokenFormdataBodyGrantTypeClientCredentials:
		s.handleClientCredentialsGrant(c, &body)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "grant_type must be authorization_code, refresh_token, or client_credentials",
		})
	}
}

func (s *Server) handleAuthorizationCodeGrant(c *gin.Context, body *generated.TokenFormdataRequestBody, userAgent, ipAddress string) {
	if body.Code == nil || *body.Code == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "code is required",
		})
		return
	}

	if body.RedirectUri == nil || *body.RedirectUri == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "redirect_uri is required",
		})
		return
	}

	if body.CodeVerifier == nil || *body.CodeVerifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "code_verifier is required",
		})
		return
	}

	req := &dto.TokenRequest{
		GrantType:    string(body.GrantType),
		Code:         *body.Code,
		RedirectURI:  *body.RedirectUri,
		CodeVerifier: *body.CodeVerifier,
	}
	if body.ClientId != nil {
		req.ClientID = *body.ClientId
	}
	if body.ClientSecret != nil {
		req.ClientSecret = *body.ClientSecret
	}

	resp, err := s.oauthService.ExchangeAuthorizationCode(c.Request.Context(), req, userAgent, ipAddress)
	if err != nil {
		handleOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (s *Server) handleRefreshTokenGrant(c *gin.Context, body *generated.TokenFormdataRequestBody, ipAddress string) {
	if body.RefreshToken == nil || *body.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "refresh_token is required",
		})
		return
	}

	if body.ClientId == nil || *body.ClientId == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	if body.DeviceId == nil || *body.DeviceId == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "device_id is required",
		})
		return
	}

	req := &dto.RefreshTokenRequest{
		RefreshToken: *body.RefreshToken,
		ClientID:     *body.ClientId,
		DeviceID:     *body.DeviceId,
	}

	resp, err := s.authService.RefreshToken(c.Request.Context(), req, ipAddress)
	if err != nil {
		handleOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (s *Server) handleClientCredentialsGrant(c *gin.Context, body *generated.TokenFormdataRequestBody) {
	if body.ClientId == nil || *body.ClientId == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	if body.ClientSecret == nil || *body.ClientSecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_secret is required",
		})
		return
	}

	var scope string
	if body.Scope != nil {
		scope = *body.Scope
	}

	req := &dto.ClientCredentialsRequest{
		GrantType:    string(body.GrantType),
		ClientID:     *body.ClientId,
		ClientSecret: *body.ClientSecret,
		Scope:        scope,
	}

	resp, err := s.oauthService.ClientCredentialsGrant(c.Request.Context(), req)
	if err != nil {
		handleOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (s *Server) RefreshToken(c *gin.Context) {
	var body generated.RefreshTokenJSONRequestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	req := &dto.RefreshTokenRequest{
		RefreshToken: body.RefreshToken,
		ClientID:     body.ClientId,
		DeviceID:     body.DeviceId,
	}

	ipAddress := middleware.GetClientIP(c)
	resp, err := s.authService.RefreshToken(c.Request.Context(), req, ipAddress)
	if err != nil {
		handleOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (s *Server) RevokeToken(c *gin.Context) {
	var body generated.RevokeTokenJSONRequestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Per RFC 7009, always return 200 even if token doesn't exist
	_ = s.authService.RevokeToken(c.Request.Context(), body.Token)

	c.JSON(http.StatusOK, gin.H{"revoked": true})
}

func (s *Server) CreateClient(c *gin.Context) {
	var body generated.CreateClientJSONRequestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Convert grant types
	grantTypes := make([]string, len(body.GrantTypes))
	for i, gt := range body.GrantTypes {
		grantTypes[i] = string(gt)
	}

	var scopes []string
	if body.Scopes != nil {
		scopes = *body.Scopes
	}

	var isConfidential bool
	if body.IsConfidential != nil {
		isConfidential = *body.IsConfidential
	}

	req := &dto.CreateClientRequest{
		Name:           body.Name,
		RedirectURIs:   body.RedirectUris,
		GrantTypes:     grantTypes,
		Scopes:         scopes,
		IsConfidential: isConfidential,
	}

	resp, err := s.oauthService.CreateClient(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to create client",
		})
		return
	}

	c.JSON(http.StatusCreated, resp)
}

// ============================================================================
// FCM Endpoints
// ============================================================================

func (s *Server) RegisterFCMToken(c *gin.Context) {
	var body generated.RegisterFCMTokenJSONRequestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	err := s.authService.RegisterFCMToken(c.Request.Context(), body.RefreshToken, body.FcmToken)
	if err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "FCM token registered successfully"})
}

func (s *Server) GetUserFCMTokens(c *gin.Context, userId openapi_types.UUID) {
	// Verify the authenticated user matches the requested user ID
	authUserID, err := middleware.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "authentication required",
		})
		return
	}

	// Parse the user ID from the path parameter
	// Note: The OpenAPI spec will need to be updated to use int64 for user_id
	// For now, we extract the user ID from the authenticated user
	resp, err := s.authService.GetUserFCMTokens(c.Request.Context(), authUserID)
	if err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}
