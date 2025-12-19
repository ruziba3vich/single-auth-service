package dto

import (
	"time"

	"github.com/google/uuid"
)

// CreateClientRequest represents a request to create an OAuth client.
type CreateClientRequest struct {
	Name           string   `json:"name" binding:"required"`
	RedirectURIs   []string `json:"redirect_uris" binding:"required,dive,url"`
	GrantTypes     []string `json:"grant_types" binding:"required"`
	Scopes         []string `json:"scopes"`
	IsConfidential bool     `json:"is_confidential"`
}

// CreateClientResponse represents a newly created OAuth client.
// The client_secret is only returned once at creation time.
type CreateClientResponse struct {
	ID           uuid.UUID `json:"id"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret,omitempty"` // Only returned on creation
	Name         string    `json:"name"`
	RedirectURIs []string  `json:"redirect_uris"`
	GrantTypes   []string  `json:"grant_types"`
	Scopes       []string  `json:"scopes"`
	CreatedAt    time.Time `json:"created_at"`
}

// ClientInfo represents OAuth client information (without secret).
type ClientInfo struct {
	ID           uuid.UUID `json:"id"`
	ClientID     string    `json:"client_id"`
	Name         string    `json:"name"`
	RedirectURIs []string  `json:"redirect_uris"`
	GrantTypes   []string  `json:"grant_types"`
	Scopes       []string  `json:"scopes"`
	CreatedAt    time.Time `json:"created_at"`
}

// ClientCredentialsRequest represents a client credentials grant request.
type ClientCredentialsRequest struct {
	GrantType    string `form:"grant_type" binding:"required"`
	ClientID     string `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret" binding:"required"`
	Scope        string `form:"scope"`
}

// ClientCredentialsResponse represents a client credentials token response.
type ClientCredentialsResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}
