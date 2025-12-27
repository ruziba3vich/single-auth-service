package postgres

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ruziba3vich/single-auth-service/internal/domain/session"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/persistence/postgres/sessions"
	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

type SessionRepository struct {
	queries *sessions.Queries
}

func NewSessionRepository(db *DB) *SessionRepository {
	return &SessionRepository{
		queries: sessions.New(db.Pool),
	}
}

func (r *SessionRepository) Create(ctx context.Context, s *session.UserSession) error {
	sessionInfoJSON, err := json.Marshal(s.SessionInfo)
	if err != nil {
		return apperrors.Wrap(err, "failed to marshal session info")
	}

	err = r.queries.CreateSession(ctx, sessions.CreateSessionParams{
		ID:               toPgUUID(s.ID),
		UserID:           s.UserID,
		RefreshTokenHash: s.RefreshTokenHash,
		DeviceID:         toPgUUID(s.DeviceID),
		FcmToken:         toPgTextNullable(s.FCMToken),
		IpAddress:        s.IPAddress,
		SessionInfo:      sessionInfoJSON,
		ClientID:         s.ClientID,
		Scope:            s.Scope,
		ExpiresAt:        pgtype.Timestamptz{Time: s.ExpiresAt, Valid: true},
		Revoked:          s.Revoked,
		CreatedAt:        pgtype.Timestamptz{Time: s.CreatedAt, Valid: true},
		LastUsedAt:       pgtype.Timestamptz{Time: s.LastUsedAt, Valid: true},
	})
	if err != nil {
		if isPgUniqueViolation(err) {
			return apperrors.ErrSessionAlreadyExists
		}
		return apperrors.Wrap(err, "failed to create session")
	}
	return nil
}

func (r *SessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*session.UserSession, error) {
	row, err := r.queries.GetSessionByID(ctx, toPgUUID(id))
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrSessionNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get session by ID")
	}
	return r.toDomainSession(row)
}

func (r *SessionRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*session.UserSession, error) {
	row, err := r.queries.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrSessionNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get session by token hash")
	}
	return r.toDomainSession(row)
}

func (r *SessionRepository) GetByDeviceID(ctx context.Context, deviceID uuid.UUID) (*session.UserSession, error) {
	row, err := r.queries.GetSessionByDeviceID(ctx, toPgUUID(deviceID))
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrSessionNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get session by device ID")
	}
	return r.toDomainSession(row)
}

func (r *SessionRepository) GetByUserID(ctx context.Context, userID int64) ([]*session.UserSession, error) {
	rows, err := r.queries.GetSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to get sessions by user ID")
	}
	return r.toDomainSessions(rows)
}

func (r *SessionRepository) GetActiveByUserID(ctx context.Context, userID int64) ([]*session.UserSession, error) {
	rows, err := r.queries.GetActiveSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to get active sessions by user ID")
	}
	return r.toDomainSessions(rows)
}

func (r *SessionRepository) Update(ctx context.Context, s *session.UserSession) error {
	sessionInfoJSON, err := json.Marshal(s.SessionInfo)
	if err != nil {
		return apperrors.Wrap(err, "failed to marshal session info")
	}

	err = r.queries.UpdateSession(ctx, sessions.UpdateSessionParams{
		ID:               toPgUUID(s.ID),
		RefreshTokenHash: s.RefreshTokenHash,
		FcmToken:         toPgTextNullable(s.FCMToken),
		IpAddress:        s.IPAddress,
		SessionInfo:      sessionInfoJSON,
		Scope:            s.Scope,
		ExpiresAt:        pgtype.Timestamptz{Time: s.ExpiresAt, Valid: true},
		LastUsedAt:       pgtype.Timestamptz{Time: s.LastUsedAt, Valid: true},
	})
	if err != nil {
		return apperrors.Wrap(err, "failed to update session")
	}
	return nil
}

func (r *SessionRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	err := r.queries.RevokeSession(ctx, toPgUUID(id))
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke session")
	}
	return nil
}

func (r *SessionRepository) RevokeByDeviceID(ctx context.Context, deviceID uuid.UUID) error {
	err := r.queries.RevokeSessionByDeviceID(ctx, toPgUUID(deviceID))
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke session by device ID")
	}
	return nil
}

func (r *SessionRepository) RevokeByUserID(ctx context.Context, userID int64) error {
	err := r.queries.RevokeSessionsByUserID(ctx, userID)
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke sessions by user ID")
	}
	return nil
}

func (r *SessionRepository) RevokeByUserExceptDevice(ctx context.Context, userID int64, exceptDeviceID uuid.UUID) error {
	err := r.queries.RevokeSessionsByUserExceptDevice(ctx, sessions.RevokeSessionsByUserExceptDeviceParams{
		UserID:   userID,
		DeviceID: toPgUUID(exceptDeviceID),
	})
	if err != nil {
		return apperrors.Wrap(err, "failed to revoke sessions except device")
	}
	return nil
}

func (r *SessionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	err := r.queries.DeleteSession(ctx, toPgUUID(id))
	if err != nil {
		return apperrors.Wrap(err, "failed to delete session")
	}
	return nil
}

func (r *SessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	count, err := r.queries.DeleteExpiredSessions(ctx)
	if err != nil {
		return 0, apperrors.Wrap(err, "failed to delete expired sessions")
	}
	return count, nil
}

func (r *SessionRepository) CountActiveByUserID(ctx context.Context, userID int64) (int, error) {
	count, err := r.queries.CountActiveSessionsByUserID(ctx, userID)
	if err != nil {
		return 0, apperrors.Wrap(err, "failed to count active sessions")
	}
	return int(count), nil
}

func (r *SessionRepository) UpdateFCMToken(ctx context.Context, tokenHash, fcmToken string) error {
	err := r.queries.UpdateFCMToken(ctx, sessions.UpdateFCMTokenParams{
		RefreshTokenHash: tokenHash,
		FcmToken:         pgtype.Text{String: fcmToken, Valid: true},
	})
	if err != nil {
		return apperrors.Wrap(err, "failed to update FCM token")
	}
	return nil
}

func (r *SessionRepository) GetActiveFCMTokensByUserID(ctx context.Context, userID int64) ([]string, error) {
	rows, err := r.queries.GetActiveFCMTokensByUserID(ctx, userID)
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to get active FCM tokens")
	}

	tokens := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.Valid {
			tokens = append(tokens, row.String)
		}
	}
	return tokens, nil
}

func (r *SessionRepository) toDomainSession(row sessions.UserSession) (*session.UserSession, error) {
	var sessionInfo *session.SessionInfo
	if len(row.SessionInfo) > 0 {
		sessionInfo = &session.SessionInfo{}
		if err := json.Unmarshal(row.SessionInfo, sessionInfo); err != nil {
			return nil, apperrors.Wrap(err, "failed to unmarshal session info")
		}
	}

	s := &session.UserSession{
		ID:               fromPgUUID(row.ID),
		UserID:           row.UserID,
		RefreshTokenHash: row.RefreshTokenHash,
		DeviceID:         fromPgUUID(row.DeviceID),
		IPAddress:        row.IpAddress,
		SessionInfo:      sessionInfo,
		ClientID:         row.ClientID,
		Scope:            row.Scope,
		ExpiresAt:        row.ExpiresAt.Time,
		Revoked:          row.Revoked,
		CreatedAt:        row.CreatedAt.Time,
		LastUsedAt:       row.LastUsedAt.Time,
	}

	if row.FcmToken.Valid {
		s.FCMToken = &row.FcmToken.String
	}

	return s, nil
}

func (r *SessionRepository) toDomainSessions(rows []sessions.UserSession) ([]*session.UserSession, error) {
	result := make([]*session.UserSession, 0, len(rows))
	for _, row := range rows {
		s, err := r.toDomainSession(row)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, nil
}
