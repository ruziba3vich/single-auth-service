package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ruziba3vich/single-auth-service/internal/domain/device"
	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

// DeviceRepository implements device.Repository using PostgreSQL.
type DeviceRepository struct {
	db *DB
}

// NewDeviceRepository creates a new PostgreSQL device repository.
func NewDeviceRepository(db *DB) *DeviceRepository {
	return &DeviceRepository{db: db}
}

// Create persists a new device.
func (r *DeviceRepository) Create(ctx context.Context, d *device.Device) error {
	query := `
		INSERT INTO user_devices (id, user_id, client_id, device_name, user_agent, ip_address, last_used_at, created_at, revoked)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.db.Pool.Exec(ctx, query,
		d.ID,
		d.UserID,
		d.ClientID,
		d.DeviceName,
		d.UserAgent,
		d.IPAddress,
		d.LastUsedAt,
		d.CreatedAt,
		d.Revoked,
	)

	if err != nil {
		return apperrors.Wrap(err, "failed to create device")
	}

	return nil
}

// GetByID retrieves a device by ID.
func (r *DeviceRepository) GetByID(ctx context.Context, id uuid.UUID) (*device.Device, error) {
	query := `
		SELECT id, user_id, client_id, device_name, user_agent, ip_address, last_used_at, created_at, revoked
		FROM user_devices
		WHERE id = $1
	`

	return r.scanDevice(r.db.Pool.QueryRow(ctx, query, id))
}

// GetByUserID retrieves all devices for a user.
func (r *DeviceRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*device.Device, error) {
	query := `
		SELECT id, user_id, client_id, device_name, user_agent, ip_address, last_used_at, created_at, revoked
		FROM user_devices
		WHERE user_id = $1
		ORDER BY last_used_at DESC
	`

	return r.scanDevices(ctx, query, userID)
}

// GetActiveByUserID retrieves active (non-revoked) devices for a user.
func (r *DeviceRepository) GetActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*device.Device, error) {
	query := `
		SELECT id, user_id, client_id, device_name, user_agent, ip_address, last_used_at, created_at, revoked
		FROM user_devices
		WHERE user_id = $1 AND revoked = false
		ORDER BY last_used_at DESC
	`

	return r.scanDevices(ctx, query, userID)
}

// GetByUserAndClient retrieves devices for a user and client.
func (r *DeviceRepository) GetByUserAndClient(ctx context.Context, userID uuid.UUID, clientID string) ([]*device.Device, error) {
	query := `
		SELECT id, user_id, client_id, device_name, user_agent, ip_address, last_used_at, created_at, revoked
		FROM user_devices
		WHERE user_id = $1 AND client_id = $2 AND revoked = false
		ORDER BY last_used_at DESC
	`

	return r.scanDevices(ctx, query, userID, clientID)
}

// Update persists changes to a device.
func (r *DeviceRepository) Update(ctx context.Context, d *device.Device) error {
	query := `
		UPDATE user_devices
		SET device_name = $2, user_agent = $3, ip_address = $4, last_used_at = $5, revoked = $6
		WHERE id = $1
	`

	result, err := r.db.Pool.Exec(ctx, query,
		d.ID,
		d.DeviceName,
		d.UserAgent,
		d.IPAddress,
		d.LastUsedAt,
		d.Revoked,
	)

	if err != nil {
		return apperrors.Wrap(err, "failed to update device")
	}

	if result.RowsAffected() == 0 {
		return apperrors.ErrDeviceNotFound
	}

	return nil
}

// Revoke marks a device as revoked.
func (r *DeviceRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE user_devices SET revoked = true WHERE id = $1`

	result, err := r.db.Pool.Exec(ctx, query, id)
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke device")
	}

	if result.RowsAffected() == 0 {
		return apperrors.ErrDeviceNotFound
	}

	return nil
}

// RevokeByUserID revokes all devices for a user.
func (r *DeviceRepository) RevokeByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE user_devices SET revoked = true WHERE user_id = $1 AND revoked = false`

	_, err := r.db.Pool.Exec(ctx, query, userID)
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke user devices")
	}

	return nil
}

// RevokeByUserExceptDevice revokes all devices for a user except a specific one.
func (r *DeviceRepository) RevokeByUserExceptDevice(ctx context.Context, userID, exceptDeviceID uuid.UUID) error {
	query := `
		UPDATE user_devices
		SET revoked = true
		WHERE user_id = $1 AND id != $2 AND revoked = false
	`

	_, err := r.db.Pool.Exec(ctx, query, userID, exceptDeviceID)
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke devices except current")
	}

	return nil
}

// Delete permanently removes a device.
func (r *DeviceRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM user_devices WHERE id = $1`

	result, err := r.db.Pool.Exec(ctx, query, id)
	if err != nil {
		return apperrors.Wrap(err, "failed to delete device")
	}

	if result.RowsAffected() == 0 {
		return apperrors.ErrDeviceNotFound
	}

	return nil
}

// CountActiveByUserID counts active devices for a user.
func (r *DeviceRepository) CountActiveByUserID(ctx context.Context, userID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM user_devices WHERE user_id = $1 AND revoked = false`

	var count int
	err := r.db.Pool.QueryRow(ctx, query, userID).Scan(&count)
	if err != nil {
		return 0, apperrors.Wrap(err, "failed to count devices")
	}

	return count, nil
}

// scanDevice scans a single device from a row.
func (r *DeviceRepository) scanDevice(row pgx.Row) (*device.Device, error) {
	d := &device.Device{}

	err := row.Scan(
		&d.ID,
		&d.UserID,
		&d.ClientID,
		&d.DeviceName,
		&d.UserAgent,
		&d.IPAddress,
		&d.LastUsedAt,
		&d.CreatedAt,
		&d.Revoked,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrDeviceNotFound
		}
		return nil, apperrors.Wrap(err, "failed to scan device")
	}

	return d, nil
}

// scanDevices executes a query and scans all devices.
func (r *DeviceRepository) scanDevices(ctx context.Context, query string, args ...any) ([]*device.Device, error) {
	rows, err := r.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to query devices")
	}
	defer rows.Close()

	var devices []*device.Device
	for rows.Next() {
		d := &device.Device{}
		err := rows.Scan(
			&d.ID,
			&d.UserID,
			&d.ClientID,
			&d.DeviceName,
			&d.UserAgent,
			&d.IPAddress,
			&d.LastUsedAt,
			&d.CreatedAt,
			&d.Revoked,
		)
		if err != nil {
			return nil, apperrors.Wrap(err, "failed to scan device")
		}
		devices = append(devices, d)
	}

	if err := rows.Err(); err != nil {
		return nil, apperrors.Wrap(err, "error iterating devices")
	}

	return devices, nil
}
