package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ruziba3vich/single-auth-service/internal/domain/token"
	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

// RefreshTokenRepository implements token.RefreshTokenRepository using PostgreSQL.
type RefreshTokenRepository struct {
	db *DB
}

// NewRefreshTokenRepository creates a new PostgreSQL refresh token repository.
func NewRefreshTokenRepository(db *DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

// Create persists a new refresh token.
func (r *RefreshTokenRepository) Create(ctx context.Context, rt *token.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, user_id, client_id, device_id, token_hash, scope, expires_at, revoked, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.db.Pool.Exec(ctx, query,
		rt.ID,
		rt.UserID,
		rt.ClientID,
		rt.DeviceID,
		rt.TokenHash,
		rt.Scope,
		rt.ExpiresAt,
		rt.Revoked,
		rt.CreatedAt,
	)

	if err != nil {
		return apperrors.Wrap(err, "failed to create refresh token")
	}

	return nil
}

// GetByHash retrieves a refresh token by its hash.
func (r *RefreshTokenRepository) GetByHash(ctx context.Context, tokenHash string) (*token.RefreshToken, error) {
	query := `
		SELECT id, user_id, client_id, device_id, token_hash, scope, expires_at, revoked, created_at
		FROM refresh_tokens
		WHERE token_hash = $1
	`

	return r.scanToken(r.db.Pool.QueryRow(ctx, query, tokenHash))
}

// GetByID retrieves a refresh token by ID.
func (r *RefreshTokenRepository) GetByID(ctx context.Context, id uuid.UUID) (*token.RefreshToken, error) {
	query := `
		SELECT id, user_id, client_id, device_id, token_hash, scope, expires_at, revoked, created_at
		FROM refresh_tokens
		WHERE id = $1
	`

	return r.scanToken(r.db.Pool.QueryRow(ctx, query, id))
}

// GetByUserID retrieves all refresh tokens for a user.
func (r *RefreshTokenRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*token.RefreshToken, error) {
	query := `
		SELECT id, user_id, client_id, device_id, token_hash, scope, expires_at, revoked, created_at
		FROM refresh_tokens
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	return r.scanTokens(ctx, query, userID)
}

// GetByDeviceID retrieves all refresh tokens for a device.
func (r *RefreshTokenRepository) GetByDeviceID(ctx context.Context, deviceID uuid.UUID) ([]*token.RefreshToken, error) {
	query := `
		SELECT id, user_id, client_id, device_id, token_hash, scope, expires_at, revoked, created_at
		FROM refresh_tokens
		WHERE device_id = $1
		ORDER BY created_at DESC
	`

	return r.scanTokens(ctx, query, deviceID)
}

// GetActiveByUserAndDevice retrieves active tokens for a user and device.
func (r *RefreshTokenRepository) GetActiveByUserAndDevice(ctx context.Context, userID, deviceID uuid.UUID) ([]*token.RefreshToken, error) {
	query := `
		SELECT id, user_id, client_id, device_id, token_hash, scope, expires_at, revoked, created_at
		FROM refresh_tokens
		WHERE user_id = $1 AND device_id = $2 AND revoked = false AND expires_at > $3
		ORDER BY created_at DESC
	`

	rows, err := r.db.Pool.Query(ctx, query, userID, deviceID, time.Now().UTC())
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to query active tokens")
	}
	defer rows.Close()

	return r.collectTokens(rows)
}

// Revoke marks a refresh token as revoked.
func (r *RefreshTokenRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE refresh_tokens SET revoked = true WHERE id = $1`

	result, err := r.db.Pool.Exec(ctx, query, id)
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke token")
	}

	if result.RowsAffected() == 0 {
		return apperrors.ErrTokenInvalid
	}

	return nil
}

// RevokeByDeviceID revokes all refresh tokens for a device.
func (r *RefreshTokenRepository) RevokeByDeviceID(ctx context.Context, deviceID uuid.UUID) error {
	query := `UPDATE refresh_tokens SET revoked = true WHERE device_id = $1 AND revoked = false`

	_, err := r.db.Pool.Exec(ctx, query, deviceID)
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke device tokens")
	}

	return nil
}

// RevokeByUserID revokes all refresh tokens for a user.
func (r *RefreshTokenRepository) RevokeByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false`

	_, err := r.db.Pool.Exec(ctx, query, userID)
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke user tokens")
	}

	return nil
}

// RevokeByUserExceptDevice revokes all tokens for a user except those on a specific device.
func (r *RefreshTokenRepository) RevokeByUserExceptDevice(ctx context.Context, userID, exceptDeviceID uuid.UUID) error {
	query := `
		UPDATE refresh_tokens
		SET revoked = true
		WHERE user_id = $1 AND device_id != $2 AND revoked = false
	`

	_, err := r.db.Pool.Exec(ctx, query, userID, exceptDeviceID)
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke tokens except device")
	}

	return nil
}

// DeleteExpired removes expired tokens.
func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM refresh_tokens WHERE expires_at < $1`

	result, err := r.db.Pool.Exec(ctx, query, time.Now().UTC())
	if err != nil {
		return 0, apperrors.Wrap(err, "failed to delete expired tokens")
	}

	return result.RowsAffected(), nil
}

// scanToken scans a single token from a row.
func (r *RefreshTokenRepository) scanToken(row pgx.Row) (*token.RefreshToken, error) {
	rt := &token.RefreshToken{}

	err := row.Scan(
		&rt.ID,
		&rt.UserID,
		&rt.ClientID,
		&rt.DeviceID,
		&rt.TokenHash,
		&rt.Scope,
		&rt.ExpiresAt,
		&rt.Revoked,
		&rt.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrTokenInvalid
		}
		return nil, apperrors.Wrap(err, "failed to scan token")
	}

	return rt, nil
}

// scanTokens executes a query and scans all tokens.
func (r *RefreshTokenRepository) scanTokens(ctx context.Context, query string, args ...any) ([]*token.RefreshToken, error) {
	rows, err := r.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to query tokens")
	}
	defer rows.Close()

	return r.collectTokens(rows)
}

// collectTokens collects tokens from rows.
func (r *RefreshTokenRepository) collectTokens(rows pgx.Rows) ([]*token.RefreshToken, error) {
	var tokens []*token.RefreshToken
	for rows.Next() {
		rt := &token.RefreshToken{}
		err := rows.Scan(
			&rt.ID,
			&rt.UserID,
			&rt.ClientID,
			&rt.DeviceID,
			&rt.TokenHash,
			&rt.Scope,
			&rt.ExpiresAt,
			&rt.Revoked,
			&rt.CreatedAt,
		)
		if err != nil {
			return nil, apperrors.Wrap(err, "failed to scan token")
		}
		tokens = append(tokens, rt)
	}

	if err := rows.Err(); err != nil {
		return nil, apperrors.Wrap(err, "error iterating tokens")
	}

	return tokens, nil
}
