package services

import (
	"context"
	"crypto/rsa"
	"sync"
	"time"

	"github.com/ruziba3vich/single-auth-service/config"
	"github.com/ruziba3vich/single-auth-service/internal/domain/keys"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/crypto"
	"github.com/ruziba3vich/single-auth-service/pkg/errors"
	"github.com/ruziba3vich/single-auth-service/pkg/jwt"
)

// KeyService manages signing keys and JWKS.
type KeyService struct {
	keyRepo   keys.Repository
	keyGen    *crypto.RSAKeyGenerator
	cfg       *config.Config

	// Cache for JWKS to avoid repeated DB queries
	jwksCache     *keys.JWKS
	jwksCacheMu   sync.RWMutex
	jwksCacheTime time.Time
	jwksCacheTTL  time.Duration
}

// NewKeyService creates a new key service.
func NewKeyService(
	keyRepo keys.Repository,
	cfg *config.Config,
) *KeyService {
	keyGen := crypto.NewRSAKeyGenerator(2048, cfg.JWT.KeyValidityPeriod)
	return &KeyService{
		keyRepo:      keyRepo,
		keyGen:       keyGen,
		cfg:          cfg,
		jwksCacheTTL: 5 * time.Minute,
	}
}

// Initialize ensures there is an active signing key.
// Should be called on service startup.
func (s *KeyService) Initialize(ctx context.Context) error {
	// Check for active key
	_, err := s.keyRepo.GetActive(ctx)
	if err == nil {
		return nil // Active key exists
	}

	if !errors.Is(err, errors.ErrNoActiveKey) {
		return errors.Wrap(err, "failed to check active key")
	}

	// No active key, generate one
	return s.RotateKey(ctx)
}

// RotateKey generates a new signing key and activates it.
func (s *KeyService) RotateKey(ctx context.Context) error {
	// Generate new key
	newKey, err := s.keyGen.Generate()
	if err != nil {
		return errors.Wrap(err, "failed to generate new key")
	}

	// Store new key
	if err := s.keyRepo.Create(ctx, newKey); err != nil {
		return errors.Wrap(err, "failed to store new key")
	}

	// Activate new key (deactivates others)
	if err := s.keyRepo.SetActive(ctx, newKey.KID); err != nil {
		return errors.Wrap(err, "failed to activate new key")
	}

	// Invalidate JWKS cache
	s.invalidateJWKSCache()

	return nil
}

// GetActiveKey returns the active signing key.
func (s *KeyService) GetActiveKey(ctx context.Context) (*keys.SigningKey, error) {
	return s.keyRepo.GetActive(ctx)
}

// GetPublicKey returns the public key for a given KID.
// Used for JWT validation.
func (s *KeyService) GetPublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	key, err := s.keyRepo.GetByKID(ctx, kid)
	if err != nil {
		return nil, err
	}

	if !key.IsValid() {
		return nil, errors.ErrKeyExpired
	}

	return key.PublicKey, nil
}

// GetJWKS returns the JSON Web Key Set for public key distribution.
func (s *KeyService) GetJWKS(ctx context.Context) (*keys.JWKS, error) {
	// Check cache
	s.jwksCacheMu.RLock()
	if s.jwksCache != nil && time.Since(s.jwksCacheTime) < s.jwksCacheTTL {
		jwks := s.jwksCache
		s.jwksCacheMu.RUnlock()
		return jwks, nil
	}
	s.jwksCacheMu.RUnlock()

	// Cache miss, fetch from DB
	signingKeys, err := s.keyRepo.GetAll(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get signing keys")
	}

	jwks := jwt.GenerateJWKS(signingKeys)

	// Update cache
	s.jwksCacheMu.Lock()
	s.jwksCache = &jwks
	s.jwksCacheTime = time.Now()
	s.jwksCacheMu.Unlock()

	return &jwks, nil
}

// invalidateJWKSCache clears the JWKS cache.
func (s *KeyService) invalidateJWKSCache() {
	s.jwksCacheMu.Lock()
	s.jwksCache = nil
	s.jwksCacheMu.Unlock()
}

// CleanupExpiredKeys removes expired keys from the database.
func (s *KeyService) CleanupExpiredKeys(ctx context.Context) (int64, error) {
	count, err := s.keyRepo.DeleteExpired(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "failed to cleanup expired keys")
	}

	if count > 0 {
		s.invalidateJWKSCache()
	}

	return count, nil
}

// StartRotationScheduler starts a background goroutine that rotates keys periodically.
func (s *KeyService) StartRotationScheduler(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.cfg.JWT.KeyRotationInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.RotateKey(ctx); err != nil {
					// Log error but continue
					// In production, use proper logging
				}

				// Cleanup expired keys
				_, _ = s.CleanupExpiredKeys(ctx)
			}
		}
	}()
}

// GetKeyLookupFunc returns a function that can be used for JWT validation.
func (s *KeyService) GetKeyLookupFunc(ctx context.Context) func(kid string) (*rsa.PublicKey, error) {
	return func(kid string) (*rsa.PublicKey, error) {
		return s.GetPublicKey(ctx, kid)
	}
}
