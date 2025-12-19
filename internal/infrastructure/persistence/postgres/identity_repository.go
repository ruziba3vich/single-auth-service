package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ruziba3vich/single-auth-service/internal/domain/user"
	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

// IdentityRepository implements user.IdentityRepository using PostgreSQL.
type IdentityRepository struct {
	db *DB
}

// NewIdentityRepository creates a new PostgreSQL identity repository.
func NewIdentityRepository(db *DB) *IdentityRepository {
	return &IdentityRepository{db: db}
}

// Create persists a new user identity.
func (r *IdentityRepository) Create(ctx context.Context, identity *user.UserIdentity) error {
	query := `
		INSERT INTO user_identities (id, user_id, provider, provider_user_id, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.db.Pool.Exec(ctx, query,
		identity.ID,
		identity.UserID,
		identity.Provider,
		identity.ProviderUserID,
		identity.CreatedAt,
	)

	if err != nil {
		if isPgUniqueViolation(err) {
			return apperrors.Wrap(err, "identity already exists")
		}
		return apperrors.Wrap(err, "failed to create identity")
	}

	return nil
}

// GetByUserID retrieves all identities for a user.
func (r *IdentityRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*user.UserIdentity, error) {
	query := `
		SELECT id, user_id, provider, provider_user_id, created_at
		FROM user_identities
		WHERE user_id = $1
		ORDER BY created_at ASC
	`

	rows, err := r.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to query identities")
	}
	defer rows.Close()

	var identities []*user.UserIdentity
	for rows.Next() {
		identity := &user.UserIdentity{}
		err := rows.Scan(
			&identity.ID,
			&identity.UserID,
			&identity.Provider,
			&identity.ProviderUserID,
			&identity.CreatedAt,
		)
		if err != nil {
			return nil, apperrors.Wrap(err, "failed to scan identity")
		}
		identities = append(identities, identity)
	}

	if err := rows.Err(); err != nil {
		return nil, apperrors.Wrap(err, "error iterating identities")
	}

	return identities, nil
}

// GetByProvider retrieves an identity by provider and provider user ID.
func (r *IdentityRepository) GetByProvider(ctx context.Context, provider user.Provider, providerUserID string) (*user.UserIdentity, error) {
	query := `
		SELECT id, user_id, provider, provider_user_id, created_at
		FROM user_identities
		WHERE provider = $1 AND provider_user_id = $2
	`

	identity := &user.UserIdentity{}
	err := r.db.Pool.QueryRow(ctx, query, provider, providerUserID).Scan(
		&identity.ID,
		&identity.UserID,
		&identity.Provider,
		&identity.ProviderUserID,
		&identity.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get identity by provider")
	}

	return identity, nil
}

// Delete removes an identity.
func (r *IdentityRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM user_identities WHERE id = $1`

	result, err := r.db.Pool.Exec(ctx, query, id)
	if err != nil {
		return apperrors.Wrap(err, "failed to delete identity")
	}

	if result.RowsAffected() == 0 {
		return apperrors.ErrNotFound
	}

	return nil
}

// DeleteByUserID removes all identities for a user.
func (r *IdentityRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM user_identities WHERE user_id = $1`

	_, err := r.db.Pool.Exec(ctx, query, userID)
	if err != nil {
		return apperrors.Wrap(err, "failed to delete user identities")
	}

	return nil
}
