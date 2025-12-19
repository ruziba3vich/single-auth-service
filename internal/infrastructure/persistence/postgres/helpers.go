package postgres

import (
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// isPgUniqueViolation checks if the error is a PostgreSQL unique constraint violation.
func isPgUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505" // unique_violation
	}
	return false
}

// isNoRows checks if the error is a "no rows" error.
func isNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}

// toPgUUID converts a google/uuid.UUID to pgtype.UUID.
func toPgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

// fromPgUUID converts a pgtype.UUID to google/uuid.UUID.
func fromPgUUID(id pgtype.UUID) uuid.UUID {
	return uuid.UUID(id.Bytes)
}
