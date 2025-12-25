package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/prodonik/express-delivery-service/internal/config"
	"github.com/prodonik/express-delivery-service/internal/handlers"
	"github.com/prodonik/express-delivery-service/internal/services"
)

func main() {
	// Load configuration
	cfg := config.LoadFromEnv()

	// Validate required configuration
	if cfg.ClientID == "" {
		log.Fatal("OAUTH_CLIENT_ID environment variable is required")
	}

	// =========================================================================
	// IMPORTANT: Implement these interfaces to make the handlers work
	// =========================================================================
	//
	// The handlers are fully implemented and ready to use. You need to provide
	// implementations of the following interfaces:
	//
	// 1. services.SessionService - Stores sessions with OAuth tokens
	//    Options:
	//    - Redis (recommended for production)
	//    - PostgreSQL
	//    - In-memory (for development only)
	//
	// 2. services.OAuthClient - Communicates with the auth service
	//    This makes HTTP calls to:
	//    - POST /token (exchange code for tokens)
	//    - POST /token/refresh (refresh tokens)
	//    - POST /token/revoke (revoke tokens)
	//    - POST /auth/logout (logout device)
	//    - GET /jwks.json (get public keys for ID token validation)
	//
	// Example implementations would look like:
	//
	//   sessionService := redis.NewSessionService(redisClient)
	//   oauthClient := httpclient.NewOAuthClient(cfg)
	//
	// For now, we use nil which will panic - replace with real implementations!
	// =========================================================================

	var sessionService services.SessionService // TODO: Implement
	var oauthClient services.OAuthClient       // TODO: Implement

	// Create handlers
	authHandler := handlers.NewAuthHandler(cfg, sessionService, oauthClient)
	authMiddleware := handlers.NewAuthMiddleware(cfg, sessionService, oauthClient)
	deliveryHandler := handlers.NewDeliveryHandler()

	// Create router
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	// Public routes (no authentication required)
	r.Get("/health", deliveryHandler.HealthCheck)

	// OAuth routes
	r.Route("/auth", func(r chi.Router) {
		r.Get("/login", authHandler.Login)     // Initiates OAuth flow
		r.Get("/callback", authHandler.Callback) // OAuth callback
		r.Post("/logout", authHandler.Logout)  // Logout
		r.Post("/refresh", authHandler.Refresh) // Refresh tokens
	})

	// Home page (shows different content for authenticated vs anonymous)
	r.With(authMiddleware.OptionalAuth).Get("/", deliveryHandler.Home)

	// Protected routes (require authentication)
	r.Group(func(r chi.Router) {
		r.Use(authMiddleware.RequireAuth)

		r.Get("/dashboard", deliveryHandler.Dashboard)

		// API routes
		r.Route("/api", func(r chi.Router) {
			r.Get("/me", deliveryHandler.GetCurrentUser)
			r.Get("/deliveries", deliveryHandler.ListDeliveries)
			r.Post("/deliveries", deliveryHandler.CreateDelivery)
		})
	})

	// Start server
	log.Printf("Express Delivery Service starting on %s", cfg.ServerAddress)
	log.Printf("Auth Service: %s", cfg.AuthServiceURL)
	log.Printf("Callback URL: %s", cfg.RedirectURI)
	log.Println("")
	log.Println("Routes:")
	log.Println("  GET  /              - Home (optional auth)")
	log.Println("  GET  /health        - Health check")
	log.Println("  GET  /auth/login    - Start OAuth login")
	log.Println("  GET  /auth/callback - OAuth callback")
	log.Println("  POST /auth/logout   - Logout")
	log.Println("  POST /auth/refresh  - Refresh tokens")
	log.Println("  GET  /dashboard     - Dashboard (protected)")
	log.Println("  GET  /api/me        - Current user (protected)")
	log.Println("  GET  /api/deliveries - List deliveries (protected)")
	log.Println("  POST /api/deliveries - Create delivery (protected)")
	log.Println("")
	log.Println("To test:")
	log.Println("  1. Register an OAuth client with single-auth-service")
	log.Println("  2. Set OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET env vars")
	log.Println("  3. Implement SessionService and OAuthClient interfaces")
	log.Println("  4. Visit http://localhost:3000/auth/login")

	if err := http.ListenAndServe(cfg.ServerAddress, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
