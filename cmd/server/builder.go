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

	"github.com/ruziba3vich/single-auth-service/config"
	"github.com/ruziba3vich/single-auth-service/internal/application"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/cache/redis"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/persistence"
	"github.com/ruziba3vich/single-auth-service/internal/infrastructure/persistence/postgres"
	apphttp "github.com/ruziba3vich/single-auth-service/internal/interfaces/http"
)

func run() error {
	ctx := context.Background()

	// Load configuration
	cfg := config.Load()
	log.Println("Starting authentication service...")

	// Initialize infrastructure
	db, redisClient, err := initInfrastructure(cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	defer redisClient.Close()

	// Initialize application
	repos := persistence.NewRepositories(db, redisClient)
	deps := application.NewDependencies(cfg)
	svcs := application.NewServices(repos, deps, cfg)

	// Initialize signing keys
	if err := svcs.Key.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize signing keys: %w", err)
	}
	log.Println("Signing keys initialized")

	// Start key rotation scheduler
	svcs.Key.StartRotationScheduler(ctx)
	log.Println("Key rotation scheduler started")

	// Create and start server
	server := newServer(cfg, svcs, deps, db, redisClient)
	return startServer(server, cfg)
}

func initInfrastructure(cfg *config.Config) (*postgres.DB, *redis.Client, error) {
	db, err := postgres.NewDB(&cfg.Database)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	log.Println("Connected to PostgreSQL")

	redisClient, err := redis.NewClient(&cfg.Redis)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}
	log.Println("Connected to Redis")

	return db, redisClient, nil
}

func newServer(
	cfg *config.Config,
	svcs *application.Services,
	deps *application.Dependencies,
	db *postgres.DB,
	redisClient *redis.Client,
) *http.Server {
	routerDeps := &apphttp.RouterDeps{
		AuthService:   svcs.Auth,
		OAuthService:  svcs.OAuth,
		KeyService:    svcs.Key,
		JWTManager:    deps.JWTManager,
		DBHealther:    db,
		RedisHealther: redisClient,
	}

	router := apphttp.NewRouter(cfg, routerDeps)

	return &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router.Engine(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}
}

func startServer(server *http.Server, cfg *config.Config) error {
	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		log.Printf("Server listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for interrupt signal or error
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		return fmt.Errorf("server error: %w", err)
	case <-quit:
		log.Println("Shutting down server...")
	}

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	log.Println("Server exited")
	return nil
}
