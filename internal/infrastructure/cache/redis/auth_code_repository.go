package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/ruziba3vich/single-auth-service/internal/domain/oauth"
	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

const (
	// authCodePrefix is the Redis key prefix for authorization codes.
	authCodePrefix = "auth_code:"
)

// AuthorizationCodeRepository implements oauth.AuthorizationCodeRepository using Redis.
type AuthorizationCodeRepository struct {
	client *Client
}

// NewAuthorizationCodeRepository creates a new Redis authorization code repository.
func NewAuthorizationCodeRepository(client *Client) *AuthorizationCodeRepository {
	return &AuthorizationCodeRepository{client: client}
}

// authCodeData is the serialization format for authorization codes.
type authCodeData struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	DeviceID            string    `json:"device_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
}

// Store saves an authorization code with automatic expiration.
func (r *AuthorizationCodeRepository) Store(ctx context.Context, code *oauth.AuthorizationCode) error {
	key := authCodePrefix + code.Code

	data := authCodeData{
		Code:                code.Code,
		ClientID:            code.ClientID,
		UserID:              code.UserID.String(),
		DeviceID:            code.DeviceID.String(),
		RedirectURI:         code.RedirectURI,
		Scope:               code.Scope,
		CodeChallenge:       code.CodeChallenge,
		CodeChallengeMethod: code.CodeChallengeMethod,
		ExpiresAt:           code.ExpiresAt,
		CreatedAt:           code.CreatedAt,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return apperrors.Wrap(err, "failed to marshal auth code")
	}

	// Calculate TTL based on expiration time
	ttl := time.Until(code.ExpiresAt)
	if ttl <= 0 {
		return apperrors.ErrTokenExpired
	}

	// Use SetNX to prevent overwriting (codes should be unique)
	success, err := r.client.SetNX(ctx, key, jsonData, ttl)
	if err != nil {
		return apperrors.Wrap(err, "failed to store auth code")
	}

	if !success {
		return apperrors.Wrap(apperrors.ErrInvalidRequest, "authorization code collision")
	}

	return nil
}

// Get retrieves an authorization code by its value.
func (r *AuthorizationCodeRepository) Get(ctx context.Context, code string) (*oauth.AuthorizationCode, error) {
	key := authCodePrefix + code

	jsonData, err := r.client.Get(ctx, key)
	if err != nil {
		if err == goredis.Nil {
			return nil, apperrors.ErrInvalidGrant
		}
		return nil, apperrors.Wrap(err, "failed to get auth code")
	}

	var data authCodeData
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		return nil, apperrors.Wrap(err, "failed to unmarshal auth code")
	}

	// Check expiration (belt and suspenders with Redis TTL)
	if time.Now().UTC().After(data.ExpiresAt) {
		_ = r.Delete(ctx, code)
		return nil, apperrors.ErrInvalidGrant
	}

	authCode, err := r.toAuthorizationCode(&data)
	if err != nil {
		return nil, err
	}

	return authCode, nil
}

// Delete removes an authorization code.
func (r *AuthorizationCodeRepository) Delete(ctx context.Context, code string) error {
	key := authCodePrefix + code

	if err := r.client.Delete(ctx, key); err != nil {
		return apperrors.Wrap(err, "failed to delete auth code")
	}

	return nil
}

// toAuthorizationCode converts the stored data back to domain object.
func (r *AuthorizationCodeRepository) toAuthorizationCode(data *authCodeData) (*oauth.AuthorizationCode, error) {
	userID, err := parseUUID(data.UserID)
	if err != nil {
		return nil, apperrors.Wrap(err, "invalid user_id in auth code")
	}

	deviceID, err := parseUUID(data.DeviceID)
	if err != nil {
		return nil, apperrors.Wrap(err, "invalid device_id in auth code")
	}

	return &oauth.AuthorizationCode{
		Code:                data.Code,
		ClientID:            data.ClientID,
		UserID:              userID,
		DeviceID:            deviceID,
		RedirectURI:         data.RedirectURI,
		Scope:               data.Scope,
		CodeChallenge:       data.CodeChallenge,
		CodeChallengeMethod: data.CodeChallengeMethod,
		ExpiresAt:           data.ExpiresAt,
		CreatedAt:           data.CreatedAt,
	}, nil
}

// parseUUID parses a UUID string.
func parseUUID(s string) (uuid [16]byte, err error) {
	// Simple UUID parser - expects format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	if len(s) != 36 {
		return uuid, fmt.Errorf("invalid UUID length")
	}

	// Parse each section
	hexBytes := make([]byte, 0, 32)
	for _, c := range s {
		if c == '-' {
			continue
		}
		hexBytes = append(hexBytes, byte(c))
	}

	if len(hexBytes) != 32 {
		return uuid, fmt.Errorf("invalid UUID format")
	}

	for i := 0; i < 16; i++ {
		high := hexValue(hexBytes[i*2])
		low := hexValue(hexBytes[i*2+1])
		if high < 0 || low < 0 {
			return uuid, fmt.Errorf("invalid hex character in UUID")
		}
		uuid[i] = byte(high<<4 | low)
	}

	return uuid, nil
}

func hexValue(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c - 'a' + 10)
	case 'A' <= c && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}
