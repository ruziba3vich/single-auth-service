package services

import (
	"context"
	"github.com/ruziba3vich/single-auth-service/config"
	"github.com/ruziba3vich/single-auth-service/internal/domain/keys"
	"github.com/ruziba3vich/single-auth-service/internal/domain/oauth"
	"github.com/ruziba3vich/single-auth-service/internal/domain/token"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/crypto"
	"github.com/ruziba3vich/single-auth-service/pkg/jwt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ruziba3vich/single-auth-service/internal/application/dto"
	"github.com/ruziba3vich/single-auth-service/internal/domain/device"
	"github.com/ruziba3vich/single-auth-service/internal/domain/user"
	"github.com/ruziba3vich/single-auth-service/pkg/errors"
)

// AuthService handles user authentication and token management.
type AuthService struct {
	userRepo     user.Repository
	identityRepo user.IdentityRepository
	clientRepo   oauth.ClientRepository
	tokenRepo    token.RefreshTokenRepository
	deviceRepo   device.Repository
	keyRepo      keys.Repository
	hasher       *crypto.Argon2Hasher
	tokenGen     *crypto.TokenGenerator
	jwtManager   *jwt.Manager
	cfg          *config.Config
}

// NewAuthService creates a new authentication service.
func NewAuthService(
	userRepo user.Repository,
	identityRepo user.IdentityRepository,
	clientRepo oauth.ClientRepository,
	tokenRepo token.RefreshTokenRepository,
	deviceRepo device.Repository,
	keyRepo keys.Repository,
	hasher *crypto.Argon2Hasher,
	tokenGen *crypto.TokenGenerator,
	jwtManager *jwt.Manager,
	cfg *config.Config,
) *AuthService {
	return &AuthService{
		userRepo:     userRepo,
		identityRepo: identityRepo,
		clientRepo:   clientRepo,
		tokenRepo:    tokenRepo,
		deviceRepo:   deviceRepo,
		keyRepo:      keyRepo,
		hasher:       hasher,
		tokenGen:     tokenGen,
		jwtManager:   jwtManager,
		cfg:          cfg,
	}
}

// Register creates a new user account.
func (s *AuthService) Register(ctx context.Context, req *dto.RegisterRequest) (*dto.RegisterResponse, error) {
	// Normalize email to lowercase
	email := strings.ToLower(strings.TrimSpace(req.Email))

	// Check if user already exists
	exists, err := s.userRepo.ExistsByEmail(ctx, email)
	if err != nil {
		return nil, errors.Wrap(err, "failed to check user existence")
	}
	if exists {
		return nil, errors.ErrUserAlreadyExists
	}

	// Hash password with Argon2id
	passwordHash, err := s.hasher.Hash(req.Password)
	if err != nil {
		return nil, errors.Wrap(err, "failed to hash password")
	}

	// Create user entity
	u := user.NewUser(email, passwordHash)

	// Persist user
	if err := s.userRepo.Create(ctx, u); err != nil {
		return nil, errors.Wrap(err, "failed to create user")
	}

	// Create local identity record
	identity := user.NewUserIdentity(u.ID, user.ProviderLocal, u.ID.String())
	if err := s.identityRepo.Create(ctx, identity); err != nil {
		// Log but don't fail - user is created
		// In production, this should be in a transaction
	}

	return &dto.RegisterResponse{
		UserID:        u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		CreatedAt:     u.CreatedAt,
	}, nil
}

// Login authenticates a user and returns device-bound tokens.
func (s *AuthService) Login(ctx context.Context, req *dto.LoginRequest, userAgent, ipAddress string) (*dto.LoginResponse, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))

	// Validate client
	client, err := s.clientRepo.GetByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, errors.ErrInvalidClient
	}

	// Get user by email
	u, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, errors.ErrUserNotFound) {
			return nil, errors.ErrInvalidCredentials
		}
		return nil, errors.Wrap(err, "failed to get user")
	}

	// Verify password
	valid, err := s.hasher.Verify(req.Password, u.PasswordHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify password")
	}
	if !valid {
		return nil, errors.ErrInvalidCredentials
	}

	// Check if password needs rehash (parameters changed)
	needsRehash, _ := s.hasher.NeedsRehash(u.PasswordHash)
	if needsRehash {
		// Rehash with new parameters
		if newHash, err := s.hasher.Hash(req.Password); err == nil {
			u.UpdatePassword(newHash)
			_ = s.userRepo.Update(ctx, u)
		}
	}

	// Check device limit
	deviceCount, err := s.deviceRepo.CountActiveByUserID(ctx, u.ID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to count devices")
	}
	if deviceCount >= s.cfg.Auth.MaxDevicesPerUser {
		// Revoke oldest device
		devices, err := s.deviceRepo.GetActiveByUserID(ctx, u.ID)
		if err == nil && len(devices) > 0 {
			oldest := devices[len(devices)-1]
			_ = s.deviceRepo.Revoke(ctx, oldest.ID)
			_ = s.tokenRepo.RevokeByDeviceID(ctx, oldest.ID)
		}
	}

	// Create new device
	dev := device.NewDevice(u.ID, client.ClientID, userAgent, ipAddress)
	if err := s.deviceRepo.Create(ctx, dev); err != nil {
		return nil, errors.Wrap(err, "failed to create device")
	}

	// Generate tokens
	authTime := time.Now().UTC()
	return s.issueTokens(ctx, u, client, dev, "openid email", "", authTime)
}

// issueTokens generates access and refresh tokens for a user session.
func (s *AuthService) issueTokens(
	ctx context.Context,
	u *user.User,
	client *oauth.Client,
	dev *device.Device,
	scope string,
	nonce string,
	authTime time.Time,
) (*dto.LoginResponse, error) {
	// Get active signing key
	signingKey, err := s.keyRepo.GetActive(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get signing key")
	}

	// Generate access token
	accessToken, err := s.jwtManager.CreateAccessToken(
		signingKey,
		u.ID.String(),
		[]string{client.ClientID},
		dev.ID.String(),
		client.ClientID,
		scope,
		s.cfg.JWT.AccessTokenTTL,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create access token")
	}

	// Generate refresh token
	refreshTokenValue, err := s.tokenGen.GenerateRefreshToken()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate refresh token")
	}

	// Store refresh token (hashed)
	refreshTokenHash := s.tokenGen.HashToken(refreshTokenValue)
	refreshToken := token.NewRefreshToken(
		u.ID,
		client.ClientID,
		dev.ID,
		refreshTokenHash,
		scope,
		s.cfg.JWT.RefreshTokenTTL,
	)

	if err := s.tokenRepo.Create(ctx, refreshToken); err != nil {
		return nil, errors.Wrap(err, "failed to store refresh token")
	}

	// Generate ID token if openid scope requested
	var idToken string
	if strings.Contains(scope, "openid") {
		idToken, err = s.jwtManager.CreateIDToken(
			signingKey,
			u.ID.String(),
			client.ClientID,
			u.Email,
			u.EmailVerified,
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
		DeviceID:     dev.ID,
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

	// Get refresh token from database
	storedToken, err := s.tokenRepo.GetByHash(ctx, tokenHash)
	if err != nil {
		return nil, errors.ErrInvalidGrant
	}

	// Validate refresh token
	if !storedToken.IsValid() {
		return nil, errors.ErrTokenRevoked
	}

	// CRITICAL: Verify device binding
	if storedToken.DeviceID != deviceID {
		// Potential token theft - revoke all tokens for this user
		_ = s.tokenRepo.RevokeByUserID(ctx, storedToken.UserID)
		return nil, errors.ErrDeviceMismatch
	}

	// Verify client
	if storedToken.ClientID != req.ClientID {
		return nil, errors.ErrInvalidClient
	}

	// Get device and verify it's active
	dev, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		return nil, errors.ErrDeviceNotFound
	}
	if !dev.IsActive() {
		return nil, errors.ErrDeviceRevoked
	}

	// Get user
	u, err := s.userRepo.GetByID(ctx, storedToken.UserID)
	if err != nil {
		return nil, errors.ErrUserNotFound
	}

	// Get client
	client, err := s.clientRepo.GetByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, errors.ErrInvalidClient
	}

	// REFRESH TOKEN ROTATION: Revoke old token
	if err := s.tokenRepo.Revoke(ctx, storedToken.ID); err != nil {
		return nil, errors.Wrap(err, "failed to revoke old token")
	}

	// Update device last used
	dev.UpdateLastUsed(ipAddress)
	_ = s.deviceRepo.Update(ctx, dev)

	// Get active signing key
	signingKey, err := s.keyRepo.GetActive(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get signing key")
	}

	// Generate new access token
	accessToken, err := s.jwtManager.CreateAccessToken(
		signingKey,
		u.ID.String(),
		[]string{client.ClientID},
		dev.ID.String(),
		client.ClientID,
		storedToken.Scope,
		s.cfg.JWT.AccessTokenTTL,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create access token")
	}

	// Generate new refresh token
	newRefreshTokenValue, err := s.tokenGen.GenerateRefreshToken()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate refresh token")
	}

	// Store new refresh token
	newRefreshTokenHash := s.tokenGen.HashToken(newRefreshTokenValue)
	newRefreshToken := token.NewRefreshToken(
		u.ID,
		client.ClientID,
		dev.ID,
		newRefreshTokenHash,
		storedToken.Scope,
		s.cfg.JWT.RefreshTokenTTL,
	)

	if err := s.tokenRepo.Create(ctx, newRefreshToken); err != nil {
		return nil, errors.Wrap(err, "failed to store refresh token")
	}

	return &dto.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.cfg.JWT.AccessTokenTTL.Seconds()),
		RefreshToken: newRefreshTokenValue,
		Scope:        storedToken.Scope,
		DeviceID:     dev.ID.String(),
	}, nil
}

// Logout revokes tokens for the current device.
func (s *AuthService) Logout(ctx context.Context, deviceID uuid.UUID) error {
	// Revoke device
	if err := s.deviceRepo.Revoke(ctx, deviceID); err != nil {
		if !errors.Is(err, errors.ErrDeviceNotFound) {
			return errors.Wrap(err, "failed to revoke device")
		}
	}

	// Revoke all refresh tokens for this device
	if err := s.tokenRepo.RevokeByDeviceID(ctx, deviceID); err != nil {
		return errors.Wrap(err, "failed to revoke tokens")
	}

	return nil
}

// LogoutDevice revokes a specific device for a user.
func (s *AuthService) LogoutDevice(ctx context.Context, userID, deviceID uuid.UUID) error {
	// Verify device belongs to user
	dev, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		return errors.ErrDeviceNotFound
	}
	if dev.UserID != userID {
		return errors.ErrForbidden
	}

	// Revoke device and tokens
	if err := s.deviceRepo.Revoke(ctx, deviceID); err != nil {
		return errors.Wrap(err, "failed to revoke device")
	}
	if err := s.tokenRepo.RevokeByDeviceID(ctx, deviceID); err != nil {
		return errors.Wrap(err, "failed to revoke tokens")
	}

	return nil
}

// LogoutAllExceptCurrent revokes all devices except the current one.
func (s *AuthService) LogoutAllExceptCurrent(ctx context.Context, userID, currentDeviceID uuid.UUID) error {
	// Revoke all devices except current
	if err := s.deviceRepo.RevokeByUserExceptDevice(ctx, userID, currentDeviceID); err != nil {
		return errors.Wrap(err, "failed to revoke devices")
	}

	// Revoke all refresh tokens except current device
	if err := s.tokenRepo.RevokeByUserExceptDevice(ctx, userID, currentDeviceID); err != nil {
		return errors.Wrap(err, "failed to revoke tokens")
	}

	return nil
}

// LogoutAll revokes all devices and tokens for a user.
func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	// Revoke all devices
	if err := s.deviceRepo.RevokeByUserID(ctx, userID); err != nil {
		return errors.Wrap(err, "failed to revoke devices")
	}

	// Revoke all refresh tokens
	if err := s.tokenRepo.RevokeByUserID(ctx, userID); err != nil {
		return errors.Wrap(err, "failed to revoke tokens")
	}

	return nil
}

// GetUserDevices returns all active devices for a user.
func (s *AuthService) GetUserDevices(ctx context.Context, userID, currentDeviceID uuid.UUID) (*dto.ListDevicesResponse, error) {
	devices, err := s.deviceRepo.GetActiveByUserID(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get devices")
	}

	response := &dto.ListDevicesResponse{
		Devices: make([]dto.DeviceInfo, 0, len(devices)),
	}

	for _, d := range devices {
		response.Devices = append(response.Devices, dto.DeviceInfo{
			DeviceID:   d.ID,
			DeviceName: d.DeviceName,
			UserAgent:  d.UserAgent,
			IPAddress:  d.IPAddress,
			LastUsedAt: d.LastUsedAt,
			CreatedAt:  d.CreatedAt,
			IsCurrent:  d.ID == currentDeviceID,
		})
	}

	return response, nil
}

// RevokeToken revokes a refresh token.
func (s *AuthService) RevokeToken(ctx context.Context, tokenValue string) error {
	tokenHash := s.tokenGen.HashToken(tokenValue)

	storedToken, err := s.tokenRepo.GetByHash(ctx, tokenHash)
	if err != nil {
		// Per RFC 7009, always return success even if token doesn't exist
		return nil
	}

	return s.tokenRepo.Revoke(ctx, storedToken.ID)
}

// RegisterFCMToken registers an FCM token for a refresh token session.
func (s *AuthService) RegisterFCMToken(ctx context.Context, refreshToken, fcmToken string) error {
	// Hash the refresh token to look it up
	tokenHash := s.tokenGen.HashToken(refreshToken)

	// Verify the refresh token exists and is valid
	storedToken, err := s.tokenRepo.GetByHash(ctx, tokenHash)
	if err != nil {
		return errors.ErrInvalidGrant
	}

	if !storedToken.IsValid() {
		return errors.ErrTokenRevoked
	}

	// Update the FCM token
	return s.tokenRepo.UpdateFCMToken(ctx, tokenHash, fcmToken)
}

// GetUserFCMTokens retrieves all active FCM tokens for a user.
func (s *AuthService) GetUserFCMTokens(ctx context.Context, userID uuid.UUID) (*dto.FCMTokensResponse, error) {
	tokens, err := s.tokenRepo.GetActiveFCMTokensByUserID(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get FCM tokens")
	}

	return &dto.FCMTokensResponse{
		FCMTokens: tokens,
	}, nil
}
