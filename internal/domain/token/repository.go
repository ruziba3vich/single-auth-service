package token

import (
	"context"

	"github.com/google/uuid"
)

// RefreshTokenRepository defines the interface for refresh token persistence.
type RefreshTokenRepository interface {
	// Create persists a new refresh token.
	Create(ctx context.Context, token *RefreshToken) error

	// GetByHash retrieves a refresh token by its hash.
	GetByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)

	// GetByID retrieves a refresh token by ID.
	GetByID(ctx context.Context, id uuid.UUID) (*RefreshToken, error)

	// GetByUserID retrieves all refresh tokens for a user.
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*RefreshToken, error)

	// GetByDeviceID retrieves all refresh tokens for a specific device.
	GetByDeviceID(ctx context.Context, deviceID uuid.UUID) ([]*RefreshToken, error)

	// GetActiveByUserAndDevice retrieves active (non-revoked, non-expired) refresh tokens
	// for a specific user and device combination.
	GetActiveByUserAndDevice(ctx context.Context, userID, deviceID uuid.UUID) ([]*RefreshToken, error)

	// Revoke marks a refresh token as revoked.
	Revoke(ctx context.Context, id uuid.UUID) error

	// RevokeByDeviceID revokes all refresh tokens for a device.
	RevokeByDeviceID(ctx context.Context, deviceID uuid.UUID) error

	// RevokeByUserID revokes all refresh tokens for a user.
	RevokeByUserID(ctx context.Context, userID uuid.UUID) error

	// RevokeByUserExceptDevice revokes all refresh tokens for a user except those on a specific device.
	RevokeByUserExceptDevice(ctx context.Context, userID, exceptDeviceID uuid.UUID) error

	// DeleteExpired removes expired tokens (cleanup job).
	DeleteExpired(ctx context.Context) (int64, error)

	// UpdateFCMToken updates the FCM token for a refresh token identified by its hash.
	UpdateFCMToken(ctx context.Context, tokenHash, fcmToken string) error

	// GetActiveFCMTokensByUserID retrieves all active FCM tokens for a user.
	GetActiveFCMTokensByUserID(ctx context.Context, userID uuid.UUID) ([]string, error)
}
