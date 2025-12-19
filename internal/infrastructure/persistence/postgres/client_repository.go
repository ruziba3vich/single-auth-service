package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ruziba3vich/single-auth-service/internal/domain/oauth"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/persistence/postgres/clients"
	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

type ClientRepository struct {
	queries *clients.Queries
}

func NewClientRepository(db *DB) *ClientRepository {
	return &ClientRepository{
		queries: clients.New(db.Pool),
	}
}

func (r *ClientRepository) Create(ctx context.Context, client *oauth.Client) error {
	err := r.queries.CreateOAuthClient(ctx, clients.CreateOAuthClientParams{
		ID:               toPgUUID(client.ID),
		ClientID:         client.ClientID,
		ClientSecretHash: pgtype.Text{String: client.ClientSecretHash, Valid: client.ClientSecretHash != ""},
		Name:             client.Name,
		RedirectUris:     client.RedirectURIs,
		GrantTypes:       grantTypesToStrings(client.GrantTypes),
		Scopes:           client.Scopes,
		IsConfidential:   client.IsConfidential,
		CreatedAt:        pgtype.Timestamptz{Time: client.CreatedAt, Valid: true},
		UpdatedAt:        pgtype.Timestamptz{Time: client.UpdatedAt, Valid: true},
	})
	if err != nil {
		if isPgUniqueViolation(err) {
			return apperrors.Wrap(err, "client already exists")
		}
		return apperrors.Wrap(err, "failed to create client")
	}
	return nil
}

func (r *ClientRepository) GetByID(ctx context.Context, id uuid.UUID) (*oauth.Client, error) {
	row, err := r.queries.GetOAuthClientByID(ctx, toPgUUID(id))
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrClientNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get client by ID")
	}
	return r.toDomainClient(row), nil
}

func (r *ClientRepository) GetByClientID(ctx context.Context, clientID string) (*oauth.Client, error) {
	row, err := r.queries.GetOAuthClientByClientID(ctx, clientID)
	if err != nil {
		if isNoRows(err) {
			return nil, apperrors.ErrClientNotFound
		}
		return nil, apperrors.Wrap(err, "failed to get client by client_id")
	}
	return r.toDomainClient(row), nil
}

func (r *ClientRepository) Update(ctx context.Context, client *oauth.Client) error {
	err := r.queries.UpdateOAuthClient(ctx, clients.UpdateOAuthClientParams{
		ID:               toPgUUID(client.ID),
		ClientSecretHash: pgtype.Text{String: client.ClientSecretHash, Valid: client.ClientSecretHash != ""},
		Name:             client.Name,
		RedirectUris:     client.RedirectURIs,
		GrantTypes:       grantTypesToStrings(client.GrantTypes),
		Scopes:           client.Scopes,
		IsConfidential:   client.IsConfidential,
		UpdatedAt:        pgtype.Timestamptz{Time: client.UpdatedAt, Valid: true},
	})
	if err != nil {
		return apperrors.Wrap(err, "failed to update client")
	}
	return nil
}

func (r *ClientRepository) Delete(ctx context.Context, id uuid.UUID) error {
	err := r.queries.DeleteOAuthClient(ctx, toPgUUID(id))
	if err != nil {
		return apperrors.Wrap(err, "failed to delete client")
	}
	return nil
}

func (r *ClientRepository) List(ctx context.Context, limit, offset int) ([]*oauth.Client, error) {
	rows, err := r.queries.ListOAuthClients(ctx, clients.ListOAuthClientsParams{
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		return nil, apperrors.Wrap(err, "failed to list clients")
	}

	result := make([]*oauth.Client, 0, len(rows))
	for _, row := range rows {
		result = append(result, r.toDomainClient(row))
	}
	return result, nil
}

func (r *ClientRepository) toDomainClient(row clients.OauthClient) *oauth.Client {
	return &oauth.Client{
		ID:               fromPgUUID(row.ID),
		ClientID:         row.ClientID,
		ClientSecretHash: row.ClientSecretHash.String,
		Name:             row.Name,
		RedirectURIs:     row.RedirectUris,
		GrantTypes:       stringsToGrantTypes(row.GrantTypes),
		Scopes:           row.Scopes,
		IsConfidential:   row.IsConfidential,
		CreatedAt:        row.CreatedAt.Time,
		UpdatedAt:        row.UpdatedAt.Time,
	}
}

func grantTypesToStrings(grantTypes []oauth.GrantType) []string {
	result := make([]string, len(grantTypes))
	for i, gt := range grantTypes {
		result[i] = string(gt)
	}
	return result
}

func stringsToGrantTypes(strings []string) []oauth.GrantType {
	result := make([]oauth.GrantType, len(strings))
	for i, s := range strings {
		result[i] = oauth.GrantType(s)
	}
	return result
}
