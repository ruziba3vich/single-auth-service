package services

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ruziba3vich/single-auth-service/config"
	"github.com/ruziba3vich/single-auth-service/internal/application/dto"
	"github.com/ruziba3vich/single-auth-service/internal/domain/keys"
	"github.com/ruziba3vich/single-auth-service/internal/domain/oauth"
	"github.com/ruziba3vich/single-auth-service/internal/domain/session"
	"github.com/ruziba3vich/single-auth-service/internal/domain/user"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/crypto"
	"github.com/ruziba3vich/single-auth-service/pkg/errors"
	"github.com/ruziba3vich/single-auth-service/pkg/jwt"
)

// OAuthService handles OAuth 2.1 flows.
type OAuthService struct {
	userRepo     user.Repository
	clientRepo   oauth.ClientRepository
	authCodeRepo oauth.AuthorizationCodeRepository
	sessionRepo  session.Repository
	keyRepo      keys.Repository
	hasher       *crypto.Argon2Hasher
	tokenGen     *crypto.TokenGenerator
	jwtManager   *jwt.Manager
	cfg          *config.Config
}

// NewOAuthService creates a new OAuth service.
func NewOAuthService(
	userRepo user.Repository,
	clientRepo oauth.ClientRepository,
	authCodeRepo oauth.AuthorizationCodeRepository,
	sessionRepo session.Repository,
	keyRepo keys.Repository,
	hasher *crypto.Argon2Hasher,
	tokenGen *crypto.TokenGenerator,
	jwtManager *jwt.Manager,
	cfg *config.Config,
) *OAuthService {
	return &OAuthService{
		userRepo:     userRepo,
		clientRepo:   clientRepo,
		authCodeRepo: authCodeRepo,
		sessionRepo:  sessionRepo,
		keyRepo:      keyRepo,
		hasher:       hasher,
		tokenGen:     tokenGen,
		jwtManager:   jwtManager,
		cfg:          cfg,
	}
}

// AuthorizeRequest represents the result of authorization request validation.
type AuthorizeResult struct {
	Client              *oauth.Client
	RedirectURI         string
	State               string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// ValidateAuthorizeRequest validates an OAuth authorization request.
// Returns validation result or an error that should be displayed to the user (not redirected).
func (s *OAuthService) ValidateAuthorizeRequest(ctx context.Context, req *dto.AuthorizeRequest) (*AuthorizeResult, error) {
	// Validate response_type
	if req.ResponseType != "code" {
		return nil, errors.NewOAuthError("unsupported_response_type", "only 'code' is supported")
	}

	// Get and validate client
	client, err := s.clientRepo.GetByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, errors.NewOAuthError("invalid_client", "client not found")
	}

	// Validate redirect URI
	if !client.ValidateRedirectURI(req.RedirectURI) {
		// SECURITY: Do not redirect if redirect_uri is invalid
		return nil, errors.NewOAuthError("invalid_request", "invalid redirect_uri")
	}

	// Validate grant type
	if !client.HasGrantType(oauth.GrantTypeAuthorizationCode) {
		return nil, errors.NewOAuthError("unauthorized_client", "client not authorized for authorization_code grant").WithState(req.State)
	}

	// PKCE is REQUIRED (OAuth 2.1)
	if req.CodeChallenge == "" {
		return nil, errors.NewOAuthError("invalid_request", "code_challenge required").WithState(req.State)
	}
	if req.CodeChallengeMethod != "S256" {
		return nil, errors.NewOAuthError("invalid_request", "code_challenge_method must be S256").WithState(req.State)
	}

	// Validate scopes
	if !client.ValidateScopes(req.Scope) {
		return nil, errors.NewOAuthError("invalid_scope", "requested scope not allowed").WithState(req.State)
	}

	return &AuthorizeResult{
		Client:              client,
		RedirectURI:         req.RedirectURI,
		State:               req.State,
		Scope:               req.Scope,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}, nil
}

// CreateAuthorizationCode creates and stores an authorization code after user consent.
func (s *OAuthService) CreateAuthorizationCode(
	ctx context.Context,
	result *AuthorizeResult,
	userID int64,
	deviceID uuid.UUID,
) (string, error) {
	// Generate authorization code
	code, err := s.tokenGen.GenerateAuthorizationCode()
	if err != nil {
		return "", errors.Wrap(err, "failed to generate authorization code")
	}

	// Create authorization code entity
	authCode := oauth.NewAuthorizationCode(
		code,
		result.Client.ClientID,
		userID,
		deviceID,
		result.RedirectURI,
		result.Scope,
		result.CodeChallenge,
		result.CodeChallengeMethod,
		s.cfg.JWT.AuthCodeTTL,
	)

	// Store in Redis
	if err := s.authCodeRepo.Store(ctx, authCode); err != nil {
		return "", errors.Wrap(err, "failed to store authorization code")
	}

	return code, nil
}

// BuildAuthorizationRedirect builds the redirect URL with authorization code.
func (s *OAuthService) BuildAuthorizationRedirect(redirectURI, code, state string) string {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// BuildErrorRedirect builds the redirect URL with an OAuth error.
func (s *OAuthService) BuildErrorRedirect(redirectURI string, oauthErr *errors.OAuthError) string {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("error", oauthErr.Code)
	if oauthErr.Description != "" {
		q.Set("error_description", oauthErr.Description)
	}
	if oauthErr.State != "" {
		q.Set("state", oauthErr.State)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// ExchangeAuthorizationCode exchanges an authorization code for tokens.
func (s *OAuthService) ExchangeAuthorizationCode(
	ctx context.Context,
	req *dto.TokenRequest,
	userAgent, ipAddress string,
) (*dto.TokenResponse, error) {
	// Get and validate authorization code
	authCode, err := s.authCodeRepo.Get(ctx, req.Code)
	if err != nil {
		return nil, errors.NewOAuthError("invalid_grant", "invalid or expired authorization code")
	}

	// IMPORTANT: Delete code immediately to prevent replay
	defer s.authCodeRepo.Delete(ctx, req.Code)

	// Validate client
	if authCode.ClientID != req.ClientID {
		return nil, errors.NewOAuthError("invalid_grant", "client_id mismatch")
	}

	// Validate redirect URI
	if authCode.RedirectURI != req.RedirectURI {
		return nil, errors.NewOAuthError("invalid_grant", "redirect_uri mismatch")
	}

	// PKCE verification
	if !s.tokenGen.VerifyPKCE(req.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
		return nil, errors.NewOAuthError("invalid_grant", "invalid code_verifier")
	}

	// Get client
	client, err := s.clientRepo.GetByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, errors.NewOAuthError("invalid_client", "client not found")
	}

	// Authenticate confidential clients
	if client.IsConfidential {
		if req.ClientSecret == "" {
			return nil, errors.NewOAuthError("invalid_client", "client_secret required")
		}
		valid, _ := s.hasher.Verify(req.ClientSecret, client.ClientSecretHash)
		if !valid {
			return nil, errors.NewOAuthError("invalid_client", "invalid client credentials")
		}
	}

	// Get user
	u, err := s.userRepo.GetByID(ctx, authCode.UserID)
	if err != nil {
		return nil, errors.NewOAuthError("invalid_grant", "user not found")
	}

	// Check if user is active
	if !u.IsActive() {
		return nil, errors.NewOAuthError("invalid_grant", "user account is not active")
	}

	// Get signing key
	signingKey, err := s.keyRepo.GetActive(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get signing key")
	}

	// Generate refresh token
	refreshTokenValue, err := s.tokenGen.GenerateRefreshToken()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate refresh token")
	}

	// Create session info
	sessionInfo := &session.SessionInfo{
		UserAgent: userAgent,
	}

	// Create session with refresh token
	refreshTokenHash := s.tokenGen.HashToken(refreshTokenValue)
	sess := session.NewUserSession(
		u.ID,
		refreshTokenHash,
		client.ClientID,
		ipAddress,
		sessionInfo,
		authCode.Scope,
		s.cfg.JWT.RefreshTokenTTL,
	)

	if err := s.sessionRepo.Create(ctx, sess); err != nil {
		return nil, errors.Wrap(err, "failed to create session")
	}

	// Generate access token
	accessToken, err := s.jwtManager.CreateAccessToken(
		signingKey,
		strconv.FormatInt(u.ID, 10),
		[]string{client.ClientID},
		sess.DeviceID.String(),
		client.ClientID,
		authCode.Scope,
		s.cfg.JWT.AccessTokenTTL,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create access token")
	}

	// Generate ID token if openid scope
	var idToken string
	if strings.Contains(authCode.Scope, "openid") {
		email := ""
		if u.Email != nil {
			email = *u.Email
		}
		idToken, err = s.jwtManager.CreateIDToken(
			signingKey,
			strconv.FormatInt(u.ID, 10),
			client.ClientID,
			email,
			false, // email not verified by default
			"",    // nonce would come from original authorize request
			time.Now().UTC(),
			s.cfg.JWT.IDTokenTTL,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create ID token")
		}
	}

	return &dto.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.cfg.JWT.AccessTokenTTL.Seconds()),
		RefreshToken: refreshTokenValue,
		Scope:        authCode.Scope,
		IDToken:      idToken,
		DeviceID:     sess.DeviceID.String(),
	}, nil
}

// ClientCredentialsGrant handles the client credentials flow (service-to-service).
func (s *OAuthService) ClientCredentialsGrant(ctx context.Context, req *dto.ClientCredentialsRequest) (*dto.ClientCredentialsResponse, error) {
	// Validate grant type
	if req.GrantType != "client_credentials" {
		return nil, errors.NewOAuthError("unsupported_grant_type", "grant_type must be client_credentials")
	}

	// Get and authenticate client
	client, err := s.clientRepo.GetByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, errors.NewOAuthError("invalid_client", "client not found")
	}

	// Client credentials requires confidential client
	if !client.IsConfidential {
		return nil, errors.NewOAuthError("invalid_client", "client_credentials requires confidential client")
	}

	// Verify client is authorized for this grant type
	if !client.HasGrantType(oauth.GrantTypeClientCredentials) {
		return nil, errors.NewOAuthError("unauthorized_client", "client not authorized for client_credentials grant")
	}

	// Authenticate client
	valid, err := s.hasher.Verify(req.ClientSecret, client.ClientSecretHash)
	if err != nil || !valid {
		return nil, errors.NewOAuthError("invalid_client", "invalid client credentials")
	}

	// Validate scopes
	scope := req.Scope
	if scope != "" && !client.ValidateScopes(scope) {
		return nil, errors.NewOAuthError("invalid_scope", "requested scope not allowed")
	}

	// Get signing key
	signingKey, err := s.keyRepo.GetActive(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get signing key")
	}

	// Generate access token (no device_id for service tokens)
	accessToken, err := s.jwtManager.CreateAccessToken(
		signingKey,
		client.ClientID, // sub is client_id for client credentials
		[]string{client.ClientID},
		"", // no device_id
		client.ClientID,
		scope,
		s.cfg.JWT.AccessTokenTTL,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create access token")
	}

	return &dto.ClientCredentialsResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.cfg.JWT.AccessTokenTTL.Seconds()),
		Scope:       scope,
	}, nil
}

// CreateClient creates a new OAuth client.
func (s *OAuthService) CreateClient(ctx context.Context, req *dto.CreateClientRequest) (*dto.CreateClientResponse, error) {
	// Generate client ID
	clientID := "client_" + uuid.New().String()[:8]

	// Convert grant types
	grantTypes := make([]oauth.GrantType, len(req.GrantTypes))
	for i, gt := range req.GrantTypes {
		grantTypes[i] = oauth.GrantType(gt)
	}

	// Create client entity
	client := oauth.NewClient(clientID, req.Name, req.RedirectURIs, grantTypes, req.IsConfidential)

	// Set scopes if provided
	if len(req.Scopes) > 0 {
		client.Scopes = req.Scopes
	}

	var clientSecret string
	if req.IsConfidential {
		// Generate and hash client secret
		secret, err := s.tokenGen.GenerateToken(32)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate client secret")
		}
		clientSecret = secret

		hash, err := s.hasher.Hash(secret)
		if err != nil {
			return nil, errors.Wrap(err, "failed to hash client secret")
		}
		client.SetSecret(hash)
	}

	// Store client
	if err := s.clientRepo.Create(ctx, client); err != nil {
		return nil, errors.Wrap(err, "failed to create client")
	}

	return &dto.CreateClientResponse{
		ID:           client.ID,
		ClientID:     client.ClientID,
		ClientSecret: clientSecret, // Only returned once
		Name:         client.Name,
		RedirectURIs: client.RedirectURIs,
		GrantTypes:   req.GrantTypes,
		Scopes:       client.Scopes,
		CreatedAt:    client.CreatedAt,
	}, nil
}
