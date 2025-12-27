package services

import (
	"context"
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

// AuthService handles user authentication and token management.
type AuthService struct {
	userRepo    user.Repository
	clientRepo  oauth.ClientRepository
	sessionRepo session.Repository
	keyRepo     keys.Repository
	hasher      *crypto.Argon2Hasher
	tokenGen    *crypto.TokenGenerator
	jwtManager  *jwt.Manager
	cfg         *config.Config
}

// NewAuthService creates a new authentication service.
func NewAuthService(
	userRepo user.Repository,
	clientRepo oauth.ClientRepository,
	sessionRepo session.Repository,
	keyRepo keys.Repository,
	hasher *crypto.Argon2Hasher,
	tokenGen *crypto.TokenGenerator,
	jwtManager *jwt.Manager,
	cfg *config.Config,
) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		clientRepo:  clientRepo,
		sessionRepo: sessionRepo,
		keyRepo:     keyRepo,
		hasher:      hasher,
		tokenGen:    tokenGen,
		jwtManager:  jwtManager,
		cfg:         cfg,
	}
}

// Register creates a new user account.
func (s *AuthService) Register(ctx context.Context, req *dto.RegisterRequest, registerIP string) (*dto.RegisterResponse, error) {
	// Normalize phone
	phone := strings.TrimSpace(req.Phone)
	username := strings.TrimSpace(req.Username)

	// Check if user already exists by phone
	exists, err := s.userRepo.ExistsByPhone(ctx, phone)
	if err != nil {
		return nil, errors.Wrap(err, "failed to check user existence")
	}
	if exists {
		return nil, errors.ErrPhoneAlreadyExists
	}

	// Check username uniqueness
	exists, err = s.userRepo.ExistsByUsername(ctx, username)
	if err != nil {
		return nil, errors.Wrap(err, "failed to check username existence")
	}
	if exists {
		return nil, errors.ErrUsernameAlreadyExists
	}

	// Check email uniqueness if provided
	if req.Email != nil && *req.Email != "" {
		email := strings.ToLower(strings.TrimSpace(*req.Email))
		exists, err = s.userRepo.ExistsByEmail(ctx, email)
		if err != nil {
			return nil, errors.Wrap(err, "failed to check email existence")
		}
		if exists {
			return nil, errors.ErrEmailAlreadyExists
		}
	}

	// Hash password with Argon2id
	passwordHash, err := s.hasher.HashToBytes(req.Password)
	if err != nil {
		return nil, errors.Wrap(err, "failed to hash password")
	}

	// Create user entity
	u := user.NewUser(username, phone, passwordHash)
	if req.Email != nil && *req.Email != "" {
		email := strings.ToLower(strings.TrimSpace(*req.Email))
		u.SetEmail(email)
	}
	u.RegisterIP = &registerIP

	// Persist user
	if err := s.userRepo.Create(ctx, u); err != nil {
		return nil, errors.Wrap(err, "failed to create user")
	}

	return &dto.RegisterResponse{
		UserID:    u.ID,
		Username:  u.Username,
		Phone:     u.Phone,
		Email:     u.Email,
		CreatedAt: u.CreatedAt,
	}, nil
}

// Login authenticates a user and returns device-bound tokens.
// Login identifier can be phone, email, or username.
func (s *AuthService) Login(ctx context.Context, req *dto.LoginRequest, userAgent, ipAddress string) (*dto.LoginResponse, error) {
	login := strings.TrimSpace(req.Login)

	// Validate client
	client, err := s.clientRepo.GetByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, errors.ErrInvalidClient
	}

	// Get user by login (phone, email, or username)
	u, err := s.userRepo.GetByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, errors.ErrUserNotFound) {
			return nil, errors.ErrInvalidCredentials
		}
		return nil, errors.Wrap(err, "failed to get user")
	}

	// Check if user is active
	if !u.IsActive() {
		return nil, errors.ErrUserBanned
	}

	// Verify password
	valid, err := s.hasher.VerifyBytes(req.Password, u.Password)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify password")
	}
	if !valid {
		return nil, errors.ErrInvalidCredentials
	}

	// Check if password needs rehash (parameters changed)
	needsRehash, _ := s.hasher.NeedsRehashBytes(u.Password)
	if needsRehash {
		// Rehash with new parameters
		if newHash, err := s.hasher.HashToBytes(req.Password); err == nil {
			u.UpdatePassword(newHash)
			_ = s.userRepo.Update(ctx, u)
		}
	}

	// Check session limit
	sessionCount, err := s.sessionRepo.CountActiveByUserID(ctx, u.ID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to count sessions")
	}
	if sessionCount >= s.cfg.Auth.MaxDevicesPerUser {
		// Revoke oldest session
		sessions, err := s.sessionRepo.GetActiveByUserID(ctx, u.ID)
		if err == nil && len(sessions) > 0 {
			oldest := sessions[len(sessions)-1]
			_ = s.sessionRepo.Revoke(ctx, oldest.ID)
		}
	}

	// Update last login
	u.UpdateLastLogin(ipAddress)
	_ = s.userRepo.UpdateLastLogin(ctx, u.ID, ipAddress)

	// Generate tokens
	authTime := time.Now().UTC()
	return s.issueTokens(ctx, u, client, userAgent, ipAddress, "openid email", "", authTime)
}

// issueTokens generates access and refresh tokens for a user session.
func (s *AuthService) issueTokens(
	ctx context.Context,
	u *user.User,
	client *oauth.Client,
	userAgent string,
	ipAddress string,
	scope string,
	nonce string,
	authTime time.Time,
) (*dto.LoginResponse, error) {
	// Get active signing key
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

	// Store session with refresh token (hashed)
	refreshTokenHash := s.tokenGen.HashToken(refreshTokenValue)
	sess := session.NewUserSession(
		u.ID,
		refreshTokenHash,
		client.ClientID,
		ipAddress,
		sessionInfo,
		scope,
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
		scope,
		s.cfg.JWT.AccessTokenTTL,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create access token")
	}

	// Generate ID token if openid scope requested
	var idToken string
	if strings.Contains(scope, "openid") {
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
			nonce,
			authTime,
			s.cfg.JWT.IDTokenTTL,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create ID token")
		}
	}

	return &dto.LoginResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.cfg.JWT.AccessTokenTTL.Seconds()),
		RefreshToken: refreshTokenValue,
		DeviceID:     sess.DeviceID,
		Scope:        scope,
		IDToken:      idToken,
	}, nil
}

// RefreshToken refreshes tokens for a device-bound session.
func (s *AuthService) RefreshToken(ctx context.Context, req *dto.RefreshTokenRequest, ipAddress string) (*dto.TokenResponse, error) {
	// Parse device ID
	deviceID, err := uuid.Parse(req.DeviceID)
	if err != nil {
		return nil, errors.ErrDeviceIDRequired
	}

	// Hash the provided refresh token to look it up
	tokenHash := s.tokenGen.HashToken(req.RefreshToken)

	// Get session from database
	sess, err := s.sessionRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, errors.ErrInvalidGrant
	}

	// Validate session
	if !sess.IsValid() {
		return nil, errors.ErrTokenRevoked
	}

	// CRITICAL: Verify device binding
	if sess.DeviceID != deviceID {
		// Potential token theft - revoke all sessions for this user
		_ = s.sessionRepo.RevokeByUserID(ctx, sess.UserID)
		return nil, errors.ErrDeviceMismatch
	}

	// Verify client
	if sess.ClientID != req.ClientID {
		return nil, errors.ErrInvalidClient
	}

	// Get user
	u, err := s.userRepo.GetByID(ctx, sess.UserID)
	if err != nil {
		return nil, errors.ErrUserNotFound
	}

	// Check if user is still active
	if !u.IsActive() {
		return nil, errors.ErrUserBanned
	}

	// Get client
	client, err := s.clientRepo.GetByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, errors.ErrInvalidClient
	}

	// Get active signing key
	signingKey, err := s.keyRepo.GetActive(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get signing key")
	}

	// Generate new refresh token
	newRefreshTokenValue, err := s.tokenGen.GenerateRefreshToken()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate refresh token")
	}

	// REFRESH TOKEN ROTATION: Update session with new token
	newRefreshTokenHash := s.tokenGen.HashToken(newRefreshTokenValue)
	sess.UpdateRefreshToken(newRefreshTokenHash, s.cfg.JWT.RefreshTokenTTL)
	sess.UpdateLastUsed(ipAddress)

	if err := s.sessionRepo.Update(ctx, sess); err != nil {
		return nil, errors.Wrap(err, "failed to update session")
	}

	// Generate new access token
	accessToken, err := s.jwtManager.CreateAccessToken(
		signingKey,
		strconv.FormatInt(u.ID, 10),
		[]string{client.ClientID},
		sess.DeviceID.String(),
		client.ClientID,
		sess.Scope,
		s.cfg.JWT.AccessTokenTTL,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create access token")
	}

	return &dto.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.cfg.JWT.AccessTokenTTL.Seconds()),
		RefreshToken: newRefreshTokenValue,
		Scope:        sess.Scope,
		DeviceID:     sess.DeviceID.String(),
	}, nil
}

// Logout revokes the session for the current device.
func (s *AuthService) Logout(ctx context.Context, deviceID uuid.UUID) error {
	// Revoke session by device ID
	if err := s.sessionRepo.RevokeByDeviceID(ctx, deviceID); err != nil {
		if !errors.Is(err, errors.ErrSessionNotFound) {
			return errors.Wrap(err, "failed to revoke session")
		}
	}
	return nil
}

// LogoutDevice revokes a specific device session for a user.
func (s *AuthService) LogoutDevice(ctx context.Context, userID int64, deviceID uuid.UUID) error {
	// Verify session belongs to user
	sess, err := s.sessionRepo.GetByDeviceID(ctx, deviceID)
	if err != nil {
		return errors.ErrSessionNotFound
	}
	if sess.UserID != userID {
		return errors.ErrForbidden
	}

	// Revoke session
	if err := s.sessionRepo.Revoke(ctx, sess.ID); err != nil {
		return errors.Wrap(err, "failed to revoke session")
	}

	return nil
}

// LogoutAllExceptCurrent revokes all sessions except the current one.
func (s *AuthService) LogoutAllExceptCurrent(ctx context.Context, userID int64, currentDeviceID uuid.UUID) error {
	if err := s.sessionRepo.RevokeByUserExceptDevice(ctx, userID, currentDeviceID); err != nil {
		return errors.Wrap(err, "failed to revoke sessions")
	}
	return nil
}

// LogoutAll revokes all sessions for a user.
func (s *AuthService) LogoutAll(ctx context.Context, userID int64) error {
	if err := s.sessionRepo.RevokeByUserID(ctx, userID); err != nil {
		return errors.Wrap(err, "failed to revoke sessions")
	}
	return nil
}

// GetUserDevices returns all active sessions for a user.
func (s *AuthService) GetUserDevices(ctx context.Context, userID int64, currentDeviceID uuid.UUID) (*dto.ListDevicesResponse, error) {
	sessions, err := s.sessionRepo.GetActiveByUserID(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get sessions")
	}

	response := &dto.ListDevicesResponse{
		Sessions: make([]dto.SessionInfo, 0, len(sessions)),
	}

	for _, sess := range sessions {
		info := dto.SessionInfo{
			SessionID:  sess.ID,
			DeviceID:   sess.DeviceID,
			IPAddress:  sess.IPAddress,
			LastUsedAt: sess.LastUsedAt,
			CreatedAt:  sess.CreatedAt,
			IsCurrent:  sess.DeviceID == currentDeviceID,
		}
		if sess.SessionInfo != nil {
			info.DeviceName = sess.SessionInfo.DeviceName
			info.UserAgent = sess.SessionInfo.UserAgent
		}
		response.Sessions = append(response.Sessions, info)
	}

	return response, nil
}

// RevokeToken revokes a refresh token.
func (s *AuthService) RevokeToken(ctx context.Context, tokenValue string) error {
	tokenHash := s.tokenGen.HashToken(tokenValue)

	sess, err := s.sessionRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		// Per RFC 7009, always return success even if token doesn't exist
		return nil
	}

	return s.sessionRepo.Revoke(ctx, sess.ID)
}

// RegisterFCMToken registers an FCM token for a refresh token session.
func (s *AuthService) RegisterFCMToken(ctx context.Context, refreshToken, fcmToken string) error {
	// Hash the refresh token to look it up
	tokenHash := s.tokenGen.HashToken(refreshToken)

	// Verify the session exists and is valid
	sess, err := s.sessionRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return errors.ErrInvalidGrant
	}

	if !sess.IsValid() {
		return errors.ErrTokenRevoked
	}

	// Update the FCM token
	return s.sessionRepo.UpdateFCMToken(ctx, tokenHash, fcmToken)
}

// GetUserFCMTokens retrieves all active FCM tokens for a user.
func (s *AuthService) GetUserFCMTokens(ctx context.Context, userID int64) (*dto.FCMTokensResponse, error) {
	tokens, err := s.sessionRepo.GetActiveFCMTokensByUserID(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get FCM tokens")
	}

	return &dto.FCMTokensResponse{
		FCMTokens: tokens,
	}, nil
}
