package application

import (
	"github.com/ruziba3vich/single-auth-service/config"
	"github.com/ruziba3vich/single-auth-service/internal/application/services"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/crypto"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/persistence"
	"github.com/ruziba3vich/single-auth-service/pkg/jwt"
)

// Services holds all application services.
type Services struct {
	Auth  *services.AuthService
	OAuth *services.OAuthService
	Key   *services.KeyService
}

// Dependencies holds shared dependencies for services.
type Dependencies struct {
	Hasher     *crypto.Argon2Hasher
	TokenGen   *crypto.TokenGenerator
	JWTManager *jwt.Manager
}

// NewDependencies creates shared dependencies from config.
func NewDependencies(cfg *config.Config) *Dependencies {
	return &Dependencies{
		Hasher: crypto.NewArgon2Hasher(
			cfg.Auth.Argon2Memory,
			cfg.Auth.Argon2Iterations,
			cfg.Auth.Argon2Parallelism,
			cfg.Auth.Argon2SaltLength,
			cfg.Auth.Argon2KeyLength,
		),
		TokenGen:   crypto.NewTokenGenerator(),
		JWTManager: jwt.NewManager(cfg.JWT.Issuer),
	}
}

// NewServices creates all application services.
func NewServices(repos *persistence.Repositories, deps *Dependencies, cfg *config.Config) *Services {
	keyService := services.NewKeyService(repos.Key, cfg)

	authService := services.NewAuthService(
		repos.User,
		repos.Identity,
		repos.Client,
		repos.Token,
		repos.Device,
		repos.Key,
		deps.Hasher,
		deps.TokenGen,
		deps.JWTManager,
		cfg,
	)

	oauthService := services.NewOAuthService(
		repos.User,
		repos.Client,
		repos.AuthCode,
		repos.Token,
		repos.Device,
		repos.Key,
		deps.Hasher,
		deps.TokenGen,
		deps.JWTManager,
		cfg,
	)

	return &Services{
		Auth:  authService,
		OAuth: oauthService,
		Key:   keyService,
	}
}
