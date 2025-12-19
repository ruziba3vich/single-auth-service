package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	domainkeys "github.com/ruziba3vich/single-auth-service/internal/domain/keys"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/crypto"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/persistence/postgres/keys"
	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

type SigningKeyRepository struct {
	db      *DB
	queries *keys.Queries
}

func NewSigningKeyRepository(db *DB) *SigningKeyRepository {
	return &SigningKeyRepository{
		db:      db,
		queries: keys.New(db.Pool),
	}
}

func (r *SigningKeyRepository) Create(ctx context.Context, key *domainkeys.SigningKey) error {
	err := r.queries.CreateSigningKey(ctx, keys.CreateSigningKeyParams{
		Kid:        key.KID,
		PrivateKey: key.PrivateKeyPEM,
		PublicKey:  key.PublicKeyPEM,
		Algorithm:  key.Algorithm,
		Active:     key.Active,
		CreatedAt:  pgtype.Timestamptz{Time: key.CreatedAt, Valid: true},
		ExpiresAt:  pgtype.Timestamptz{Time: key.ExpiresAt, Valid: true},
	})
	if err != nil {
		if isPgUniqueViolation(err) {
			return apperrors.Wrap(err, "key already exists")
		}
		return apperrors.Wrap(err, "failed to create signing key")
	}
	return nil
}

func (r *SigningKeyRepository) GetByKID(ctx context.Context, kid string) (*domainkeys.SigningKey, error) {
	row, err := r.queries.GetSigningKeyByKID(ctx, kid)
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrKeyNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get key by KID")
	}
	return r.toDomainKey(row)
}

func (r *SigningKeyRepository) GetActive(ctx context.Context) (*domainkeys.SigningKey, error) {
	row, err := r.queries.GetActiveSigningKey(ctx, pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true})
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrNoActiveKey
		}
		return nil, apperrors.Wrap(err, "failed to get active key")
	}
	return r.toDomainKey(row)
}

func (r *SigningKeyRepository) GetAll(ctx context.Context) ([]*domainkeys.SigningKey, error) {
	rows, err := r.queries.GetAllValidSigningKeys(ctx, pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true})
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to query signing keys")
	}
	return r.toDomainKeys(rows)
}

func (r *SigningKeyRepository) SetActive(ctx context.Context, kid string) error {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return apperrors.Wrap(err, "failed to begin transaction")
	}
	defer tx.Rollback(ctx)

	qtx := r.queries.WithTx(tx)

	if err := qtx.DeactivateAllSigningKeys(ctx); err != nil {
		return apperrors.Wrap(err, "failed to deactivate keys")
	}

	if err := qtx.ActivateSigningKey(ctx, kid); err != nil {
		return apperrors.Wrap(err, "failed to activate key")
	}

	if err := tx.Commit(ctx); err != nil {
		return apperrors.Wrap(err, "failed to commit transaction")
	}

	return nil
}

func (r *SigningKeyRepository) Delete(ctx context.Context, kid string) error {
	err := r.queries.DeleteSigningKey(ctx, kid)
	if err != nil {
		return apperrors.Wrap(err, "failed to delete key")
	}
	return nil
}

func (r *SigningKeyRepository) DeleteExpired(ctx context.Context) (int64, error) {
	count, err := r.queries.DeleteExpiredSigningKeys(ctx, pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true})
	if err != nil {
		return 0, apperrors.Wrap(err, "failed to delete expired keys")
	}
	return count, nil
}

func (r *SigningKeyRepository) toDomainKey(row keys.SigningKey) (*domainkeys.SigningKey, error) {
	key := &domainkeys.SigningKey{
		KID:           row.Kid,
		PrivateKeyPEM: row.PrivateKey,
		PublicKeyPEM:  row.PublicKey,
		Algorithm:     row.Algorithm,
		Active:        row.Active,
		CreatedAt:     row.CreatedAt.Time,
		ExpiresAt:     row.ExpiresAt.Time,
	}

	if err := r.parseKeys(key); err != nil {
		return nil, err
	}

	return key, nil
}

func (r *SigningKeyRepository) toDomainKeys(rows []keys.SigningKey) ([]*domainkeys.SigningKey, error) {
	result := make([]*domainkeys.SigningKey, 0, len(rows))
	for _, row := range rows {
		key, err := r.toDomainKey(row)
		if err != nil {
			return nil, err
		}
		result = append(result, key)
	}
	return result, nil
}

func (r *SigningKeyRepository) parseKeys(key *domainkeys.SigningKey) error {
	privateKey, err := crypto.ParsePrivateKey(key.PrivateKeyPEM)
	if err != nil {
		return apperrors.Wrap(err, "failed to parse private key")
	}
	key.PrivateKey = privateKey

	publicKey, err := crypto.ParsePublicKey(key.PublicKeyPEM)
	if err != nil {
		return apperrors.Wrap(err, "failed to parse public key")
	}
	key.PublicKey = publicKey

	return nil
}
