package session

import (
	"context"

	"github.com/google/uuid"
)

// Repository handles session storage.
type Repository interface {
	Create(ctx context.Context, session *UserSession) error
	GetByID(ctx context.Context, id uuid.UUID) (*UserSession, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (*UserSession, error)
	GetByDeviceID(ctx context.Context, deviceID uuid.UUID) (*UserSession, error)
	GetByUserID(ctx context.Context, userID int64) ([]*UserSession, error)
	GetActiveByUserID(ctx context.Context, userID int64) ([]*UserSession, error)
	Update(ctx context.Context, session *UserSession) error

	// Revocation
	Revoke(ctx context.Context, id uuid.UUID) error
	RevokeByDeviceID(ctx context.Context, deviceID uuid.UUID) error
	RevokeByUserID(ctx context.Context, userID int64) error
	RevokeByUserExceptDevice(ctx context.Context, userID int64, exceptDeviceID uuid.UUID) error

	Delete(ctx context.Context, id uuid.UUID) error
	DeleteExpired(ctx context.Context) (int64, error)
	CountActiveByUserID(ctx context.Context, userID int64) (int, error)

	// Push notifications
	UpdateFCMToken(ctx context.Context, tokenHash, fcmToken string) error
	GetActiveFCMTokensByUserID(ctx context.Context, userID int64) ([]string, error)
}
