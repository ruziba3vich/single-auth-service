package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ruziba3vich/single-auth-service/internal/domain/token"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/persistence/postgres/tokens"
	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

type RefreshTokenRepository struct {
	queries *tokens.Queries
}

func NewRefreshTokenRepository(db *DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{
		queries: tokens.New(db.Pool),
	}
}

func (r *RefreshTokenRepository) Create(ctx context.Context, rt *token.RefreshToken) error {
	err := r.queries.CreateRefreshToken(ctx, tokens.CreateRefreshTokenParams{
		ID:        toPgUUID(rt.ID),
		UserID:    toPgUUID(rt.UserID),
		ClientID:  rt.ClientID,
		DeviceID:  toPgUUID(rt.DeviceID),
		TokenHash: rt.TokenHash,
		Scope:     rt.Scope,
		ExpiresAt: pgtype.Timestamptz{Time: rt.ExpiresAt, Valid: true},
		Revoked:   rt.Revoked,
		CreatedAt: pgtype.Timestamptz{Time: rt.CreatedAt, Valid: true},
	})
	if err != nil {
		return apperrors.Wrap(err, "failed to create refresh token")
	}
	return nil
}

func (r *RefreshTokenRepository) GetByHash(ctx context.Context, tokenHash string) (*token.RefreshToken, error) {
	row, err := r.queries.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrTokenInvalid
		}
		return nil, apperrors.Wrap(err, "failed to get token by hash")
	}
	return r.toDomainToken(row), nil
}

func (r *RefreshTokenRepository) GetByID(ctx context.Context, id uuid.UUID) (*token.RefreshToken, error) {
	row, err := r.queries.GetRefreshTokenByID(ctx, toPgUUID(id))
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrTokenInvalid
		}
		return nil, apperrors.Wrap(err, "failed to get token by ID")
	}
	return r.toDomainToken(row), nil
}

func (r *RefreshTokenRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*token.RefreshToken, error) {
	rows, err := r.queries.GetRefreshTokensByUserID(ctx, toPgUUID(userID))
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to query tokens")
	}
	return r.toDomainTokens(rows), nil
}

func (r *RefreshTokenRepository) GetByDeviceID(ctx context.Context, deviceID uuid.UUID) ([]*token.RefreshToken, error) {
	rows, err := r.queries.GetRefreshTokensByDeviceID(ctx, toPgUUID(deviceID))
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to query tokens by device")
	}
	return r.toDomainTokens(rows), nil
}

func (r *RefreshTokenRepository) GetActiveByUserAndDevice(ctx context.Context, userID, deviceID uuid.UUID) ([]*token.RefreshToken, error) {
	rows, err := r.queries.GetActiveRefreshTokensByUserAndDevice(ctx, tokens.GetActiveRefreshTokensByUserAndDeviceParams{
		UserID:    toPgUUID(userID),
		DeviceID:  toPgUUID(deviceID),
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
	})
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to query active tokens")
	}
	return r.toDomainTokens(rows), nil
}

func (r *RefreshTokenRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	err := r.queries.RevokeRefreshToken(ctx, toPgUUID(id))
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke token")
	}
	return nil
}

func (r *RefreshTokenRepository) RevokeByDeviceID(ctx context.Context, deviceID uuid.UUID) error {
	err := r.queries.RevokeRefreshTokensByDeviceID(ctx, toPgUUID(deviceID))
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke device tokens")
	}
	return nil
}

func (r *RefreshTokenRepository) RevokeByUserID(ctx context.Context, userID uuid.UUID) error {
	err := r.queries.RevokeRefreshTokensByUserID(ctx, toPgUUID(userID))
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke user tokens")
	}
	return nil
}

func (r *RefreshTokenRepository) RevokeByUserExceptDevice(ctx context.Context, userID, exceptDeviceID uuid.UUID) error {
	err := r.queries.RevokeRefreshTokensExceptDevice(ctx, tokens.RevokeRefreshTokensExceptDeviceParams{
		UserID:   toPgUUID(userID),
		DeviceID: toPgUUID(exceptDeviceID),
	})
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke tokens except device")
	}
	return nil
}

func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	count, err := r.queries.DeleteExpiredRefreshTokens(ctx, pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true})
	if err != nil {
		return 0, apperrors.Wrap(err, "failed to delete expired tokens")
	}
	return count, nil
}

func (r *RefreshTokenRepository) toDomainToken(row tokens.RefreshToken) *token.RefreshToken {
	return &token.RefreshToken{
		ID:        fromPgUUID(row.ID),
		UserID:    fromPgUUID(row.UserID),
		ClientID:  row.ClientID,
		DeviceID:  fromPgUUID(row.DeviceID),
		TokenHash: row.TokenHash,
		Scope:     row.Scope,
		ExpiresAt: row.ExpiresAt.Time,
		Revoked:   row.Revoked,
		CreatedAt: row.CreatedAt.Time,
	}
}

func (r *RefreshTokenRepository) toDomainTokens(rows []tokens.RefreshToken) []*token.RefreshToken {
	result := make([]*token.RefreshToken, 0, len(rows))
	for _, row := range rows {
		result = append(result, r.toDomainToken(row))
	}
	return result
}
