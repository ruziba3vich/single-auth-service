package postgres

import (
	"context"

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
		Username:    u.Username,
		SahiyUserID: toPgInt8Nullable(u.SahiyUserID),
		Phone:       u.Phone,
		Password:    u.Password,
		Avatar:      toPgTextNullable(u.Avatar),
		BirthDate:   pgtype.Timestamptz{Time: u.BirthDate, Valid: true},
		Gender:      toPgInt2Nullable(u.Gender),
		ForbidLogin: toPgInt2NullableFromPtr(u.ForbidLogin),
		Email:       toPgTextNullable(u.Email),
		ProfileID:   toPgInt8Nullable(u.ProfileID),
		RegisterIp:  toPgTextNullable(u.RegisterIP),
		LastloginIp: toPgTextNullable(u.LastLoginIP),
		Status:      int32(u.Status),
		CreatedAt:   pgtype.Timestamptz{Time: u.CreatedAt, Valid: true},
		LastLoginAt: pgtype.Timestamptz{Time: u.LastLoginAt, Valid: true},
	})
	if err != nil {
		if isPgUniqueViolation(err) {
			return apperrors.ErrUserAlreadyExists
		}
		return apperrors.Wrap(err, "failed to create user")
	}
	return nil
}

func (r *UserRepository) GetByID(ctx context.Context, id int64) (*user.User, error) {
	row, err := r.queries.GetUserByID(ctx, id)
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrUserNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get user by ID")
	}
	return r.toDomainUser(row), nil
}

func (r *UserRepository) GetByPhone(ctx context.Context, phone string) (*user.User, error) {
	row, err := r.queries.GetUserByPhone(ctx, phone)
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrUserNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get user by phone")
	}
	return r.toDomainUser(row), nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	row, err := r.queries.GetUserByEmail(ctx, pgtype.Text{String: email, Valid: true})
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrUserNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get user by email")
	}
	return r.toDomainUser(row), nil
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*user.User, error) {
	row, err := r.queries.GetUserByUsername(ctx, username)
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrUserNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get user by username")
	}
	return r.toDomainUser(row), nil
}

func (r *UserRepository) GetByLogin(ctx context.Context, login string) (*user.User, error) {
	row, err := r.queries.GetUserByLogin(ctx, login)
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrUserNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get user by login")
	}
	return r.toDomainUser(row), nil
}

func (r *UserRepository) Update(ctx context.Context, u *user.User) error {
	err := r.queries.UpdateUser(ctx, users.UpdateUserParams{
		ID:          u.ID,
		Username:    u.Username,
		SahiyUserID: toPgInt8Nullable(u.SahiyUserID),
		Phone:       u.Phone,
		Password:    u.Password,
		Avatar:      toPgTextNullable(u.Avatar),
		BirthDate:   pgtype.Timestamptz{Time: u.BirthDate, Valid: true},
		Gender:      toPgInt2Nullable(u.Gender),
		ForbidLogin: toPgInt2NullableFromPtr(u.ForbidLogin),
		Email:       toPgTextNullable(u.Email),
		ProfileID:   toPgInt8Nullable(u.ProfileID),
		Status:      int32(u.Status),
	})
	if err != nil {
		return apperrors.Wrap(err, "failed to update user")
	}
	return nil
}

func (r *UserRepository) Delete(ctx context.Context, id int64) error {
	err := r.queries.DeleteUser(ctx, id)
	if err != nil {
		return apperrors.Wrap(err, "failed to delete user")
	}
	return nil
}

func (r *UserRepository) ExistsByPhone(ctx context.Context, phone string) (bool, error) {
	exists, err := r.queries.ExistsUserByPhone(ctx, phone)
	if err != nil {
		return false, apperrors.Wrap(err, "failed to check user existence by phone")
	}
	return exists, nil
}

func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	exists, err := r.queries.ExistsUserByEmail(ctx, pgtype.Text{String: email, Valid: true})
	if err != nil {
		return false, apperrors.Wrap(err, "failed to check user existence by email")
	}
	return exists, nil
}

func (r *UserRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	exists, err := r.queries.ExistsUserByUsername(ctx, username)
	if err != nil {
		return false, apperrors.Wrap(err, "failed to check user existence by username")
	}
	return exists, nil
}

func (r *UserRepository) UpdateLastLogin(ctx context.Context, id int64, ip string) error {
	err := r.queries.UpdateLastLogin(ctx, users.UpdateLastLoginParams{
		ID:          id,
		LastloginIp: pgtype.Text{String: ip, Valid: true},
	})
	if err != nil {
		return apperrors.Wrap(err, "failed to update last login")
	}
	return nil
}

func (r *UserRepository) toDomainUser(row users.User) *user.User {
	u := &user.User{
		ID:          row.ID,
		Username:    row.Username,
		Phone:       row.Phone,
		Password:    row.Password,
		BirthDate:   row.BirthDate.Time,
		Status:      user.UserStatus(row.Status),
		CreatedAt:   row.CreatedAt.Time,
		LastLoginAt: row.LastLoginAt.Time,
	}

	if row.SahiyUserID.Valid {
		u.SahiyUserID = &row.SahiyUserID.Int64
	}
	if row.Avatar.Valid {
		u.Avatar = &row.Avatar.String
	}
	if row.Gender.Valid {
		g := user.Gender(row.Gender.Int16)
		u.Gender = &g
	}
	if row.ForbidLogin.Valid {
		u.ForbidLogin = &row.ForbidLogin.Int16
	}
	if row.Email.Valid {
		u.Email = &row.Email.String
	}
	if row.ProfileID.Valid {
		u.ProfileID = &row.ProfileID.Int64
	}
	if row.RegisterIp.Valid {
		u.RegisterIP = &row.RegisterIp.String
	}
	if row.LastloginIp.Valid {
		u.LastLoginIP = &row.LastloginIp.String
	}

	return u
}

// Helper functions for nullable types
func toPgInt8Nullable(v *int64) pgtype.Int8 {
	if v == nil {
		return pgtype.Int8{Valid: false}
	}
	return pgtype.Int8{Int64: *v, Valid: true}
}

func toPgInt2Nullable(v *user.Gender) pgtype.Int2 {
	if v == nil {
		return pgtype.Int2{Valid: false}
	}
	return pgtype.Int2{Int16: int16(*v), Valid: true}
}

func toPgInt2NullableFromPtr(v *int16) pgtype.Int2 {
	if v == nil {
		return pgtype.Int2{Valid: false}
	}
	return pgtype.Int2{Int16: *v, Valid: true}
}

func toPgTextNullable(v *string) pgtype.Text {
	if v == nil {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: *v, Valid: true}
}
