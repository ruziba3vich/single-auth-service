package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ruziba3vich/single-auth-service/internal/domain/oauth"
	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

// ClientRepository implements oauth.ClientRepository using PostgreSQL.
type ClientRepository struct {
	db *DB
}

// NewClientRepository creates a new PostgreSQL client repository.
func NewClientRepository(db *DB) *ClientRepository {
	return &ClientRepository{db: db}
}

// Create persists a new OAuth client.
func (r *ClientRepository) Create(ctx context.Context, client *oauth.Client) error {
	query := `
		INSERT INTO oauth_clients (id, client_id, client_secret_hash, name, redirect_uris, grant_types, scopes, is_confidential, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err := r.db.Pool.Exec(ctx, query,
		client.ID,
		client.ClientID,
		client.ClientSecretHash,
		client.Name,
		client.RedirectURIs,
		grantTypesToStrings(client.GrantTypes),
		client.Scopes,
		client.IsConfidential,
		client.CreatedAt,
		client.UpdatedAt,
	)

	if err != nil {
		if isPgUniqueViolation(err) {
			return apperrors.Wrap(err, "client already exists")
		}
		return apperrors.Wrap(err, "failed to create client")
	}

	return nil
}

// GetByID retrieves a client by internal ID.
func (r *ClientRepository) GetByID(ctx context.Context, id uuid.UUID) (*oauth.Client, error) {
	query := `
		SELECT id, client_id, client_secret_hash, name, redirect_uris, grant_types, scopes, is_confidential, created_at, updated_at
		FROM oauth_clients
		WHERE id = $1
	`

	return r.scanClient(r.db.Pool.QueryRow(ctx, query, id))
}

// GetByClientID retrieves a client by public client_id.
func (r *ClientRepository) GetByClientID(ctx context.Context, clientID string) (*oauth.Client, error) {
	query := `
		SELECT id, client_id, client_secret_hash, name, redirect_uris, grant_types, scopes, is_confidential, created_at, updated_at
		FROM oauth_clients
		WHERE client_id = $1
	`

	return r.scanClient(r.db.Pool.QueryRow(ctx, query, clientID))
}

// Update persists changes to a client.
func (r *ClientRepository) Update(ctx context.Context, client *oauth.Client) error {
	query := `
		UPDATE oauth_clients
		SET client_secret_hash = $2, name = $3, redirect_uris = $4, grant_types = $5, scopes = $6, is_confidential = $7, updated_at = $8
		WHERE id = $1
	`

	result, err := r.db.Pool.Exec(ctx, query,
		client.ID,
		client.ClientSecretHash,
		client.Name,
		client.RedirectURIs,
		grantTypesToStrings(client.GrantTypes),
		client.Scopes,
		client.IsConfidential,
		client.UpdatedAt,
	)

	if err != nil {
		return apperrors.Wrap(err, "failed to update client")
	}

	if result.RowsAffected() == 0 {
		return apperrors.ErrClientNotFound
	}

	return nil
}

// Delete removes a client.
func (r *ClientRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM oauth_clients WHERE id = $1`

	result, err := r.db.Pool.Exec(ctx, query, id)
	if err != nil {
		return apperrors.Wrap(err, "failed to delete client")
	}

	if result.RowsAffected() == 0 {
		return apperrors.ErrClientNotFound
	}

	return nil
}

// List retrieves all clients with pagination.
func (r *ClientRepository) List(ctx context.Context, limit, offset int) ([]*oauth.Client, error) {
	query := `
		SELECT id, client_id, client_secret_hash, name, redirect_uris, grant_types, scopes, is_confidential, created_at, updated_at
		FROM oauth_clients
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.Pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to list clients")
	}
	defer rows.Close()

	var clients []*oauth.Client
	for rows.Next() {
		client, err := r.scanClientFromRows(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}

	if err := rows.Err(); err != nil {
		return nil, apperrors.Wrap(err, "error iterating clients")
	}

	return clients, nil
}

// scanClient scans a single client from a row.
func (r *ClientRepository) scanClient(row pgx.Row) (*oauth.Client, error) {
	client := &oauth.Client{}
	var grantTypes []string

	err := row.Scan(
		&client.ID,
		&client.ClientID,
		&client.ClientSecretHash,
		&client.Name,
		&client.RedirectURIs,
		&grantTypes,
		&client.Scopes,
		&client.IsConfidential,
		&client.CreatedAt,
		&client.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrClientNotFound
		}
		return nil, apperrors.Wrap(err, "failed to scan client")
	}

	client.GrantTypes = stringsToGrantTypes(grantTypes)
	return client, nil
}

// scanClientFromRows scans a client from rows iterator.
func (r *ClientRepository) scanClientFromRows(rows pgx.Rows) (*oauth.Client, error) {
	client := &oauth.Client{}
	var grantTypes []string

	err := rows.Scan(
		&client.ID,
		&client.ClientID,
		&client.ClientSecretHash,
		&client.Name,
		&client.RedirectURIs,
		&grantTypes,
		&client.Scopes,
		&client.IsConfidential,
		&client.CreatedAt,
		&client.UpdatedAt,
	)

	if err != nil {
		return nil, apperrors.Wrap(err, "failed to scan client")
	}

	client.GrantTypes = stringsToGrantTypes(grantTypes)
	return client, nil
}

// grantTypesToStrings converts grant types to string slice.
func grantTypesToStrings(grantTypes []oauth.GrantType) []string {
	result := make([]string, len(grantTypes))
	for i, gt := range grantTypes {
		result[i] = string(gt)
	}
	return result
}

// stringsToGrantTypes converts string slice to grant types.
func stringsToGrantTypes(strings []string) []oauth.GrantType {
	result := make([]oauth.GrantType, len(strings))
	for i, s := range strings {
		result[i] = oauth.GrantType(s)
	}
	return result
}
