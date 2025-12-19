package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ruziba3vich/single-auth-service/internal/domain/device"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/persistence/postgres/devices"
	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

type DeviceRepository struct {
	queries *devices.Queries
}

func NewDeviceRepository(db *DB) *DeviceRepository {
	return &DeviceRepository{
		queries: devices.New(db.Pool),
	}
}

func (r *DeviceRepository) Create(ctx context.Context, d *device.Device) error {
	err := r.queries.CreateUserDevice(ctx, devices.CreateUserDeviceParams{
		ID:         toPgUUID(d.ID),
		UserID:     toPgUUID(d.UserID),
		ClientID:   d.ClientID,
		DeviceName: pgtype.Text{String: d.DeviceName, Valid: d.DeviceName != ""},
		UserAgent:  d.UserAgent,
		IpAddress:  d.IPAddress,
		LastUsedAt: pgtype.Timestamptz{Time: d.LastUsedAt, Valid: true},
		CreatedAt:  pgtype.Timestamptz{Time: d.CreatedAt, Valid: true},
		Revoked:    d.Revoked,
	})
	if err != nil {
		return apperrors.Wrap(err, "failed to create device")
	}
	return nil
}

func (r *DeviceRepository) GetByID(ctx context.Context, id uuid.UUID) (*device.Device, error) {
	row, err := r.queries.GetUserDeviceByID(ctx, toPgUUID(id))
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrDeviceNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get device by ID")
	}
	return r.toDomainDevice(row), nil
}

func (r *DeviceRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*device.Device, error) {
	rows, err := r.queries.GetUserDevicesByUserID(ctx, toPgUUID(userID))
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to query devices")
	}
	return r.toDomainDevices(rows), nil
}

func (r *DeviceRepository) GetActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*device.Device, error) {
	rows, err := r.queries.GetActiveUserDevicesByUserID(ctx, toPgUUID(userID))
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to query active devices")
	}
	return r.toDomainDevices(rows), nil
}

func (r *DeviceRepository) GetByUserAndClient(ctx context.Context, userID uuid.UUID, clientID string) ([]*device.Device, error) {
	rows, err := r.queries.GetUserDevicesByUserAndClient(ctx, devices.GetUserDevicesByUserAndClientParams{
		UserID:   toPgUUID(userID),
		ClientID: clientID,
	})
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to query devices by user and client")
	}
	return r.toDomainDevices(rows), nil
}

func (r *DeviceRepository) Update(ctx context.Context, d *device.Device) error {
	err := r.queries.UpdateUserDevice(ctx, devices.UpdateUserDeviceParams{
		ID:         toPgUUID(d.ID),
		DeviceName: pgtype.Text{String: d.DeviceName, Valid: d.DeviceName != ""},
		UserAgent:  d.UserAgent,
		IpAddress:  d.IPAddress,
		LastUsedAt: pgtype.Timestamptz{Time: d.LastUsedAt, Valid: true},
		Revoked:    d.Revoked,
	})
	if err != nil {
		return apperrors.Wrap(err, "failed to update device")
	}
	return nil
}

func (r *DeviceRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	err := r.queries.RevokeUserDevice(ctx, toPgUUID(id))
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke device")
	}
	return nil
}

func (r *DeviceRepository) RevokeByUserID(ctx context.Context, userID uuid.UUID) error {
	err := r.queries.RevokeUserDevicesByUserID(ctx, toPgUUID(userID))
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke user devices")
	}
	return nil
}

func (r *DeviceRepository) RevokeByUserExceptDevice(ctx context.Context, userID, exceptDeviceID uuid.UUID) error {
	err := r.queries.RevokeUserDevicesExceptOne(ctx, devices.RevokeUserDevicesExceptOneParams{
		UserID: toPgUUID(userID),
		ID:     toPgUUID(exceptDeviceID),
	})
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke devices except current")
	}
	return nil
}

func (r *DeviceRepository) Delete(ctx context.Context, id uuid.UUID) error {
	err := r.queries.DeleteUserDevice(ctx, toPgUUID(id))
	if err != nil {
		return apperrors.Wrap(err, "failed to delete device")
	}
	return nil
}

func (r *DeviceRepository) CountActiveByUserID(ctx context.Context, userID uuid.UUID) (int, error) {
	count, err := r.queries.CountActiveUserDevicesByUserID(ctx, toPgUUID(userID))
	if err != nil {
		return 0, apperrors.Wrap(err, "failed to count devices")
	}
	return int(count), nil
}

func (r *DeviceRepository) toDomainDevice(row devices.UserDevice) *device.Device {
	return &device.Device{
		ID:         fromPgUUID(row.ID),
		UserID:     fromPgUUID(row.UserID),
		ClientID:   row.ClientID,
		DeviceName: row.DeviceName.String,
		UserAgent:  row.UserAgent,
		IPAddress:  row.IpAddress,
		LastUsedAt: row.LastUsedAt.Time,
		CreatedAt:  row.CreatedAt.Time,
		Revoked:    row.Revoked,
	}
}

func (r *DeviceRepository) toDomainDevices(rows []devices.UserDevice) []*device.Device {
	result := make([]*device.Device, 0, len(rows))
	for _, row := range rows {
		result = append(result, r.toDomainDevice(row))
	}
	return result
}
