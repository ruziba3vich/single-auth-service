package main

import (
	"context"
	"fmt"
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
	"github.com/ruziba3vich/single-auth-service/pkg/logger"
)

func run() error {
	ctx := context.Background()

	// Load configuration
	cfg := config.Load()

	// Initialize logger
	log, logWriter, err := initLogger(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer log.Sync()
	logger.SetDefault(log)

	log.Info("Starting authentication service...",
		logger.Component("main"),
	)

	// Initialize infrastructure
	db, redisClient, err := initInfrastructure(cfg, log)
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
	log.Info("Signing keys initialized", logger.Component("main"))

	// Start key rotation scheduler
	svcs.Key.StartRotationScheduler(ctx)
	log.Info("Key rotation scheduler started", logger.Component("main"))

	// Start log cleanup job if enabled
	if logWriter != nil {
		logWriter.StartCleanupJob(ctx)
		log.Info("Log cleanup job started",
			logger.Component("main"),
			logger.Int("retention_days", cfg.Logging.RetentionDays),
		)
	}

	// Create and start server
	server := newServer(cfg, svcs, deps, db, redisClient, log, logWriter)
	return startServer(server, cfg, log)
}

func initLogger(cfg *config.Config) (logger.Logger, *logger.SQLiteWriter, error) {
	logCfg := logger.Config{
		Level:           cfg.Logging.Level,
		Environment:     cfg.Logging.Environment,
		EnableConsole:   true,
		EnableSQLite:    cfg.Logging.ViewerEnabled,
		SQLiteDBPath:    cfg.Logging.SQLiteDBPath,
		AsyncBufferSize: cfg.Logging.AsyncBufferSize,
		RetentionDays:   cfg.Logging.RetentionDays,
		FlushInterval:   100 * time.Millisecond,
		BatchSize:       100,
	}

	var writer *logger.SQLiteWriter
	var err error

	if logCfg.EnableSQLite {
		writer, err = logger.NewSQLiteWriter(logCfg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create SQLite log writer: %w", err)
		}
	}

	log, err := logger.New(logCfg, writer)
	if err != nil {
		if writer != nil {
			writer.Close()
		}
		return nil, nil, fmt.Errorf("failed to create logger: %w", err)
	}

	return log, writer, nil
}

func initInfrastructure(cfg *config.Config, log logger.Logger) (*postgres.DB, *redis.Client, error) {
	db, err := postgres.NewDB(&cfg.Database)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	log.Info("Connected to PostgreSQL",
		logger.Component("infrastructure"),
		logger.String("host", cfg.Database.Host),
		logger.Int("port", cfg.Database.Port),
	)

	redisClient, err := redis.NewClient(&cfg.Redis)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}
	log.Info("Connected to Redis",
		logger.Component("infrastructure"),
		logger.String("host", cfg.Redis.Host),
		logger.Int("port", cfg.Redis.Port),
	)

	return db, redisClient, nil
}

func newServer(
	cfg *config.Config,
	svcs *application.Services,
	deps *application.Dependencies,
	db *postgres.DB,
	redisClient *redis.Client,
	log logger.Logger,
	logWriter *logger.SQLiteWriter,
) *http.Server {
	routerDeps := &apphttp.RouterDeps{
		AuthService:   svcs.Auth,
		OAuthService:  svcs.OAuth,
		KeyService:    svcs.Key,
		JWTManager:    deps.JWTManager,
		DBHealther:    db,
		RedisHealther: redisClient,
		Logger:        log,
		LogWriter:     logWriter,
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

func startServer(server *http.Server, cfg *config.Config, log logger.Logger) error {
	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		log.Info("Server listening",
			logger.Component("server"),
			logger.String("addr", server.Addr),
		)
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
	case sig := <-quit:
		log.Info("Shutting down server...",
			logger.Component("server"),
			logger.String("signal", sig.String()),
		)
	}

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	log.Info("Server exited", logger.Component("server"))
	return nil
}
