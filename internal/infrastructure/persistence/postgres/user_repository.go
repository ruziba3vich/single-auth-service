package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ruziba3vich/single-auth-service/internal/domain/user"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/persistence/postgres/users"
	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

type UserRepository struct {
	queries *users.Queries
}

func NewUserRepository(db *DB) *UserRepository {
	return &UserRepository{
		queries: users.New(db.Pool),
	}
}

func (r *UserRepository) Create(ctx context.Context, u *user.User) error {
	err := r.queries.CreateUser(ctx, users.CreateUserParams{
		ID:            toPgUUID(u.ID),
		Email:         u.Email,
		PasswordHash:  u.PasswordHash,
		EmailVerified: u.EmailVerified,
		CreatedAt:     pgtype.Timestamptz{Time: u.CreatedAt, Valid: true},
		UpdatedAt:     pgtype.Timestamptz{Time: u.UpdatedAt, Valid: true},
	})
	if err != nil {
		if isPgUniqueViolation(err) {
			return apperrors.ErrUserAlreadyExists
		}
		return apperrors.Wrap(err, "failed to create user")
	}
	return nil
}

func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	row, err := r.queries.GetUserByID(ctx, toPgUUID(id))
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrUserNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get user by ID")
	}
	return r.toDomainUser(row), nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	row, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrUserNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get user by email")
	}
	return r.toDomainUser(row), nil
}

func (r *UserRepository) Update(ctx context.Context, u *user.User) error {
	err := r.queries.UpdateUser(ctx, users.UpdateUserParams{
		ID:            toPgUUID(u.ID),
		Email:         u.Email,
		PasswordHash:  u.PasswordHash,
		EmailVerified: u.EmailVerified,
		UpdatedAt:     pgtype.Timestamptz{Time: u.UpdatedAt, Valid: true},
	})
	if err != nil {
		return apperrors.Wrap(err, "failed to update user")
	}
	return nil
}

func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	err := r.queries.DeleteUser(ctx, toPgUUID(id))
	if err != nil {
		return apperrors.Wrap(err, "failed to delete user")
	}
	return nil
}

func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	exists, err := r.queries.ExistsUserByEmail(ctx, email)
	if err != nil {
		return false, apperrors.Wrap(err, "failed to check user existence")
	}
	return exists, nil
}

func (r *UserRepository) toDomainUser(row users.User) *user.User {
	return &user.User{
		ID:            fromPgUUID(row.ID),
		Email:         row.Email,
		PasswordHash:  row.PasswordHash,
		EmailVerified: row.EmailVerified,
		CreatedAt:     row.CreatedAt.Time,
		UpdatedAt:     row.UpdatedAt.Time,
	}
}
