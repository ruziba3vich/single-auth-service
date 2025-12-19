package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ruziba3vich/single-auth-service/internal/domain/user"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/persistence/postgres/identities"
	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

type IdentityRepository struct {
	queries *identities.Queries
}

func NewIdentityRepository(db *DB) *IdentityRepository {
	return &IdentityRepository{
		queries: identities.New(db.Pool),
	}
}

func (r *IdentityRepository) Create(ctx context.Context, identity *user.UserIdentity) error {
	err := r.queries.CreateUserIdentity(ctx, identities.CreateUserIdentityParams{
		ID:             toPgUUID(identity.ID),
		UserID:         toPgUUID(identity.UserID),
		Provider:       string(identity.Provider),
		ProviderUserID: identity.ProviderUserID,
		CreatedAt:      pgtype.Timestamptz{Time: identity.CreatedAt, Valid: true},
	})
	if err != nil {
		if isPgUniqueViolation(err) {
			return apperrors.Wrap(err, "identity already exists")
		}
		return apperrors.Wrap(err, "failed to create identity")
	}
	return nil
}

func (r *IdentityRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*user.UserIdentity, error) {
	rows, err := r.queries.GetUserIdentitiesByUserID(ctx, toPgUUID(userID))
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to query identities")
	}

	result := make([]*user.UserIdentity, 0, len(rows))
	for _, row := range rows {
		result = append(result, r.toDomainIdentity(row))
	}
	return result, nil
}

func (r *IdentityRepository) GetByProvider(ctx context.Context, provider user.Provider, providerUserID string) (*user.UserIdentity, error) {
	row, err := r.queries.GetUserIdentityByProvider(ctx, identities.GetUserIdentityByProviderParams{
		Provider:       string(provider),
		ProviderUserID: providerUserID,
	})
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get identity by provider")
	}
	return r.toDomainIdentity(row), nil
}

func (r *IdentityRepository) Delete(ctx context.Context, id uuid.UUID) error {
	err := r.queries.DeleteUserIdentity(ctx, toPgUUID(id))
	if err != nil {
		return apperrors.Wrap(err, "failed to delete identity")
	}
	return nil
}

func (r *IdentityRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	err := r.queries.DeleteUserIdentitiesByUserID(ctx, toPgUUID(userID))
	if err != nil {
		return apperrors.Wrap(err, "failed to delete user identities")
	}
	return nil
}

func (r *IdentityRepository) toDomainIdentity(row identities.UserIdentity) *user.UserIdentity {
	return &user.UserIdentity{
		ID:             fromPgUUID(row.ID),
		UserID:         fromPgUUID(row.UserID),
		Provider:       user.Provider(row.Provider),
		ProviderUserID: row.ProviderUserID,
		CreatedAt:      row.CreatedAt.Time,
	}
}
