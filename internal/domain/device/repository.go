package device

import (
	"context"

	"github.com/google/uuid"
)

// Repository defines the interface for device persistence.
type Repository interface {
	// Create persists a new device.
	Create(ctx context.Context, device *Device) error

	// GetByID retrieves a device by its ID.
	GetByID(ctx context.Context, id uuid.UUID) (*Device, error)

	// GetByUserID retrieves all devices for a user.
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*Device, error)

	// GetActiveByUserID retrieves all active (non-revoked) devices for a user.
	GetActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*Device, error)

	// GetByUserAndClient retrieves devices for a user and specific client.
	GetByUserAndClient(ctx context.Context, userID uuid.UUID, clientID string) ([]*Device, error)

	// Update persists changes to a device.
	Update(ctx context.Context, device *Device) error

	// Revoke marks a device as revoked.
	Revoke(ctx context.Context, id uuid.UUID) error

	// RevokeByUserID revokes all devices for a user.
	RevokeByUserID(ctx context.Context, userID uuid.UUID) error

	// RevokeByUserExceptDevice revokes all devices for a user except a specific one.
	RevokeByUserExceptDevice(ctx context.Context, userID, exceptDeviceID uuid.UUID) error

	// Delete permanently removes a device.
	Delete(ctx context.Context, id uuid.UUID) error

	// CountActiveByUserID counts active devices for a user.
	CountActiveByUserID(ctx context.Context, userID uuid.UUID) (int, error)
}
