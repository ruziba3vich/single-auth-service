package persistence

import (
	"github.com/ruziba3vich/single-auth-service/internal/domain/device"
	"github.com/ruziba3vich/single-auth-service/internal/domain/keys"
	"github.com/ruziba3vich/single-auth-service/internal/domain/oauth"
	"github.com/ruziba3vich/single-auth-service/internal/domain/token"
	"github.com/ruziba3vich/single-auth-service/internal/domain/user"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/cache/redis"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/persistence/postgres"
)

// Repositories holds all repository implementations.
type Repositories struct {
	User     user.Repository
	Identity user.IdentityRepository
	Client   oauth.ClientRepository
	Token    token.RefreshTokenRepository
	Device   device.Repository
	Key      keys.Repository
	AuthCode oauth.AuthorizationCodeRepository
}

// NewRepositories creates all repository implementations.
func NewRepositories(db *postgres.DB, redisClient *redis.Client) *Repositories {
	return &Repositories{
		User:     postgres.NewUserRepository(db),
		Identity: postgres.NewIdentityRepository(db),
		Client:   postgres.NewClientRepository(db),
		Token:    postgres.NewRefreshTokenRepository(db),
		Device:   postgres.NewDeviceRepository(db),
		Key:      postgres.NewSigningKeyRepository(db),
		AuthCode: redis.NewAuthorizationCodeRepository(redisClient),
	}
}
