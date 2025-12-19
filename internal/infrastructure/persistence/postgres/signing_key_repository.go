package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ruziba3vich/single-auth-service/internal/domain/keys"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/crypto"
	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

// SigningKeyRepository implements keys.Repository using PostgreSQL.
type SigningKeyRepository struct {
	db *DB
}

// NewSigningKeyRepository creates a new PostgreSQL signing key repository.
func NewSigningKeyRepository(db *DB) *SigningKeyRepository {
	return &SigningKeyRepository{db: db}
}

// Create persists a new signing key.
func (r *SigningKeyRepository) Create(ctx context.Context, key *keys.SigningKey) error {
	query := `
		INSERT INTO signing_keys (kid, private_key, public_key, algorithm, active, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.db.Pool.Exec(ctx, query,
		key.KID,
		key.PrivateKeyPEM,
		key.PublicKeyPEM,
		key.Algorithm,
		key.Active,
		key.CreatedAt,
		key.ExpiresAt,
	)

	if err != nil {
		if isPgUniqueViolation(err) {
			return apperrors.Wrap(err, "key already exists")
		}
		return apperrors.Wrap(err, "failed to create signing key")
	}

	return nil
}

// GetByKID retrieves a key by Key ID.
func (r *SigningKeyRepository) GetByKID(ctx context.Context, kid string) (*keys.SigningKey, error) {
	query := `
		SELECT kid, private_key, public_key, algorithm, active, created_at, expires_at
		FROM signing_keys
		WHERE kid = $1
	`

	return r.scanKey(r.db.Pool.QueryRow(ctx, query, kid))
}

// GetActive retrieves the currently active signing key.
func (r *SigningKeyRepository) GetActive(ctx context.Context) (*keys.SigningKey, error) {
	query := `
		SELECT kid, private_key, public_key, algorithm, active, created_at, expires_at
		FROM signing_keys
		WHERE active = true AND expires_at > $1
		LIMIT 1
	`

	key, err := r.scanKey(r.db.Pool.QueryRow(ctx, query, time.Now().UTC()))
	if err != nil {
		if apperrors.Is(err, apperrors.ErrKeyNotFound) {
			return nil, apperrors.ErrNoActiveKey
		}
		return nil, err
	}

	return key, nil
}

// GetAll retrieves all valid (non-expired) keys for JWKS.
func (r *SigningKeyRepository) GetAll(ctx context.Context) ([]*keys.SigningKey, error) {
	query := `
		SELECT kid, private_key, public_key, algorithm, active, created_at, expires_at
		FROM signing_keys
		WHERE expires_at > $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.Pool.Query(ctx, query, time.Now().UTC())
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to query signing keys")
	}
	defer rows.Close()

	var signingKeys []*keys.SigningKey
	for rows.Next() {
		key, err := r.scanKeyFromRows(rows)
		if err != nil {
			return nil, err
		}
		signingKeys = append(signingKeys, key)
	}

	if err := rows.Err(); err != nil {
		return nil, apperrors.Wrap(err, "error iterating keys")
	}

	return signingKeys, nil
}

// SetActive marks a key as active and deactivates others.
// This is done in a transaction to ensure consistency.
func (r *SigningKeyRepository) SetActive(ctx context.Context, kid string) error {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return apperrors.Wrap(err, "failed to begin transaction")
	}
	defer tx.Rollback(ctx)

	// Deactivate all keys
	_, err = tx.Exec(ctx, `UPDATE signing_keys SET active = false WHERE active = true`)
	if err != nil {
		return apperrors.Wrap(err, "failed to deactivate keys")
	}

	// Activate the specified key
	result, err := tx.Exec(ctx, `UPDATE signing_keys SET active = true WHERE kid = $1`, kid)
	if err != nil {
		return apperrors.Wrap(err, "failed to activate key")
	}

	if result.RowsAffected() == 0 {
		return apperrors.ErrKeyNotFound
	}

	if err := tx.Commit(ctx); err != nil {
		return apperrors.Wrap(err, "failed to commit transaction")
	}

	return nil
}

// Delete removes a key.
func (r *SigningKeyRepository) Delete(ctx context.Context, kid string) error {
	query := `DELETE FROM signing_keys WHERE kid = $1`

	result, err := r.db.Pool.Exec(ctx, query, kid)
	if err != nil {
		return apperrors.Wrap(err, "failed to delete key")
	}

	if result.RowsAffected() == 0 {
		return apperrors.ErrKeyNotFound
	}

	return nil
}

// DeleteExpired removes expired keys.
func (r *SigningKeyRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM signing_keys WHERE expires_at < $1`

	result, err := r.db.Pool.Exec(ctx, query, time.Now().UTC())
	if err != nil {
		return 0, apperrors.Wrap(err, "failed to delete expired keys")
	}

	return result.RowsAffected(), nil
}

// scanKey scans a single key from a row.
func (r *SigningKeyRepository) scanKey(row pgx.Row) (*keys.SigningKey, error) {
	key := &keys.SigningKey{}

	err := row.Scan(
		&key.KID,
		&key.PrivateKeyPEM,
		&key.PublicKeyPEM,
		&key.Algorithm,
		&key.Active,
		&key.CreatedAt,
		&key.ExpiresAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrKeyNotFound
		}
		return nil, apperrors.Wrap(err, "failed to scan key")
	}

	// Parse the PEM keys
	if err := r.parseKeys(key); err != nil {
		return nil, err
	}

	return key, nil
}

// scanKeyFromRows scans a key from rows iterator.
func (r *SigningKeyRepository) scanKeyFromRows(rows pgx.Rows) (*keys.SigningKey, error) {
	key := &keys.SigningKey{}

	err := rows.Scan(
		&key.KID,
		&key.PrivateKeyPEM,
		&key.PublicKeyPEM,
		&key.Algorithm,
		&key.Active,
		&key.CreatedAt,
		&key.ExpiresAt,
	)

	if err != nil {
		return nil, apperrors.Wrap(err, "failed to scan key")
	}

	// Parse the PEM keys
	if err := r.parseKeys(key); err != nil {
		return nil, err
	}

	return key, nil
}

// parseKeys parses PEM-encoded keys into RSA key structs.
func (r *SigningKeyRepository) parseKeys(key *keys.SigningKey) error {
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
