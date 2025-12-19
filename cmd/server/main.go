package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	apphttp "github.com/ruziba3vich/single-auth-service/internal/interfaces/http"

	"github.com/ruziba3vich/single-auth-service/config"
	"github.com/ruziba3vich/single-auth-service/internal/application/services"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/cache/redis"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/crypto"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/persistence/postgres"
	"github.com/ruziba3vich/single-auth-service/pkg/jwt"
)

func main() {
	// Load configuration
	cfg := config.Load()

	log.Println("Starting authentication service...")

	// Initialize database
	db, err := postgres.NewDB(&cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()
	log.Println("Connected to PostgreSQL")

	// Initialize Redis
	redisClient, err := redis.NewClient(&cfg.Redis)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer redisClient.Close()
	log.Println("Connected to Redis")

	// Initialize repositories
	userRepo := postgres.NewUserRepository(db)
	identityRepo := postgres.NewIdentityRepository(db)
	clientRepo := postgres.NewClientRepository(db)
	tokenRepo := postgres.NewRefreshTokenRepository(db)
	deviceRepo := postgres.NewDeviceRepository(db)
	keyRepo := postgres.NewSigningKeyRepository(db)
	authCodeRepo := redis.NewAuthorizationCodeRepository(redisClient)

	// Initialize crypto
	hasher := crypto.NewArgon2Hasher(
		cfg.Auth.Argon2Memory,
		cfg.Auth.Argon2Iterations,
		cfg.Auth.Argon2Parallelism,
		cfg.Auth.Argon2SaltLength,
		cfg.Auth.Argon2KeyLength,
	)
	tokenGen := crypto.NewTokenGenerator()

	// Initialize JWT manager
	jwtManager := jwt.NewManager(cfg.JWT.Issuer)

	// Initialize services
	keyService := services.NewKeyService(keyRepo, cfg)

	// Initialize signing keys
	ctx := context.Background()
	if err := keyService.Initialize(ctx); err != nil {
		log.Fatalf("Failed to initialize signing keys: %v", err)
	}
	log.Println("Signing keys initialized")

	// Start key rotation scheduler
	keyService.StartRotationScheduler(ctx)
	log.Println("Key rotation scheduler started")

	authService := services.NewAuthService(
		userRepo,
		identityRepo,
		clientRepo,
		tokenRepo,
		deviceRepo,
		keyRepo,
		hasher,
		tokenGen,
		jwtManager,
		cfg,
	)

	oauthService := services.NewOAuthService(
		userRepo,
		clientRepo,
		authCodeRepo,
		tokenRepo,
		deviceRepo,
		keyRepo,
		hasher,
		tokenGen,
		jwtManager,
		cfg,
	)

	// Create router dependencies
	deps := &apphttp.RouterDeps{
		AuthService:   authService,
		OAuthService:  oauthService,
		KeyService:    keyService,
		JWTManager:    jwtManager,
		DBHealther:    db,
		RedisHealther: redisClient,
	}

	// Create router
	router := apphttp.NewRouter(cfg, deps)

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router.Engine(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Server listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}
