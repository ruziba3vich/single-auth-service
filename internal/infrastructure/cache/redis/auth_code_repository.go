package redis

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"

	"github.com/ruziba3vich/single-auth-service/internal/domain/oauth"
	apperrors "github.com/ruziba3vich/single-auth-service/pkg/errors"
)

const authCodePrefix = "auth_code:"

// AuthorizationCodeRepository stores OAuth authorization codes in Redis with auto-expiry.
type AuthorizationCodeRepository struct {
	client *Client
}

func NewAuthorizationCodeRepository(client *Client) *AuthorizationCodeRepository {
	return &AuthorizationCodeRepository{client: client}
}

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

// Store saves the code with TTL. Uses SetNX to prevent collisions.
func (r *AuthorizationCodeRepository) Store(ctx context.Context, code *oauth.AuthorizationCode) error {
	key := authCodePrefix + code.Code

	data := authCodeData{
		Code:                code.Code,
		ClientID:            code.ClientID,
		UserID:              strconv.FormatInt(code.UserID, 10),
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

	ttl := time.Until(code.ExpiresAt)
	if ttl <= 0 {
		return apperrors.ErrTokenExpired
	}

	success, err := r.client.SetNX(ctx, key, jsonData, ttl)
	if err != nil {
		return apperrors.Wrap(err, "failed to store auth code")
	}

	if !success {
		return apperrors.Wrap(apperrors.ErrInvalidRequest, "authorization code collision")
	}

	return nil
}

// Get retrieves and validates a code. Returns ErrInvalidGrant if not found or expired.
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

	// Double-check expiry in case Redis TTL drifted
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

func (r *AuthorizationCodeRepository) Delete(ctx context.Context, code string) error {
	key := authCodePrefix + code

	if err := r.client.Delete(ctx, key); err != nil {
		return apperrors.Wrap(err, "failed to delete auth code")
	}

	return nil
}

func (r *AuthorizationCodeRepository) toAuthorizationCode(data *authCodeData) (*oauth.AuthorizationCode, error) {
	userID, err := strconv.ParseInt(data.UserID, 10, 64)
	if err != nil {
		return nil, apperrors.Wrap(err, "invalid user_id in auth code")
	}

	deviceID, err := uuid.Parse(data.DeviceID)
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
