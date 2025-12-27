package persistence

import (
	"github.com/ruziba3vich/single-auth-service/internal/domain/keys"
	"github.com/ruziba3vich/single-auth-service/internal/domain/oauth"
	"github.com/ruziba3vich/single-auth-service/internal/domain/session"
	"github.com/ruziba3vich/single-auth-service/internal/domain/user"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/cache/redis"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/persistence/postgres"
)

// Repositories holds all repository implementations.
type Repositories struct {
	User     user.Repository
	Client   oauth.ClientRepository
	Session  session.Repository
	Key      keys.Repository
	AuthCode oauth.AuthorizationCodeRepository
}

// NewRepositories creates all repository implementations.
func NewRepositories(db *postgres.DB, redisClient *redis.Client) *Repositories {
	return &Repositories{
		User:     postgres.NewUserRepository(db),
		Client:   postgres.NewClientRepository(db),
		Session:  postgres.NewSessionRepository(db),
		Key:      postgres.NewSigningKeyRepository(db),
		AuthCode: redis.NewAuthorizationCodeRepository(redisClient),
	}
}
