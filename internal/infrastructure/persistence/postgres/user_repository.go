package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ruziba3vich/single-auth-service/internal/domain/user"
	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

// UserRepository implements user.Repository using PostgreSQL.
type UserRepository struct {
	db *DB
}

// NewUserRepository creates a new PostgreSQL user repository.
func NewUserRepository(db *DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create persists a new user.
func (r *UserRepository) Create(ctx context.Context, u *user.User) error {
	query := `
		INSERT INTO users (id, email, password_hash, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.db.Pool.Exec(ctx, query,
		u.ID,
		u.Email,
		u.PasswordHash,
		u.EmailVerified,
		u.CreatedAt,
		u.UpdatedAt,
	)

	if err != nil {
		// Check for unique constraint violation
		if isPgUniqueViolation(err) {
			return apperrors.ErrUserAlreadyExists
		}
		return apperrors.Wrap(err, "failed to create user")
	}

	return nil
}

// GetByID retrieves a user by ID.
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	query := `
		SELECT id, email, password_hash, email_verified, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	u := &user.User{}
	err := r.db.Pool.QueryRow(ctx, query, id).Scan(
		&u.ID,
		&u.Email,
		&u.PasswordHash,
		&u.EmailVerified,
		&u.CreatedAt,
		&u.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrUserNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get user by ID")
	}

	return u, nil
}

// GetByEmail retrieves a user by email.
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	query := `
		SELECT id, email, password_hash, email_verified, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	u := &user.User{}
	err := r.db.Pool.QueryRow(ctx, query, email).Scan(
		&u.ID,
		&u.Email,
		&u.PasswordHash,
		&u.EmailVerified,
		&u.CreatedAt,
		&u.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrUserNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get user by email")
	}

	return u, nil
}

// Update persists changes to a user.
func (r *UserRepository) Update(ctx context.Context, u *user.User) error {
	query := `
		UPDATE users
		SET email = $2, password_hash = $3, email_verified = $4, updated_at = $5
		WHERE id = $1
	`

	result, err := r.db.Pool.Exec(ctx, query,
		u.ID,
		u.Email,
		u.PasswordHash,
		u.EmailVerified,
		u.UpdatedAt,
	)

	if err != nil {
		return apperrors.Wrap(err, "failed to update user")
	}

	if result.RowsAffected() == 0 {
		return apperrors.ErrUserNotFound
	}

	return nil
}

// Delete removes a user.
func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.db.Pool.Exec(ctx, query, id)
	if err != nil {
		return apperrors.Wrap(err, "failed to delete user")
	}

	if result.RowsAffected() == 0 {
		return apperrors.ErrUserNotFound
	}

	return nil
}

// ExistsByEmail checks if a user with the given email exists.
func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`

	var exists bool
	err := r.db.Pool.QueryRow(ctx, query, email).Scan(&exists)
	if err != nil {
		return false, apperrors.Wrap(err, "failed to check user existence")
	}

	return exists, nil
}

// isPgUniqueViolation checks if the error is a PostgreSQL unique constraint violation.
func isPgUniqueViolation(err error) bool {
	// pgx v5 uses pgconn.PgError
	var pgErr interface {
		SQLState() string
	}
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505" // unique_violation
	}
	return false
}
