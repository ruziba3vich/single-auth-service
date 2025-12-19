package http

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ruziba3vich/single-auth-service/config"
	"github.com/ruziba3vich/single-auth-service/internal/application/services"
	"github.com/ruziba3vich/single-auth-service/internal/interfaces/http/handlers"
	"github.com/ruziba3vich/single-auth-service/internal/interfaces/http/middleware"
	"github.com/ruziba3vich/single-auth-service/pkg/jwt"
)

// Router wraps the Gin engine with application dependencies.
type Router struct {
	engine *gin.Engine
	cfg    *config.Config
}

// RouterDeps contains dependencies needed by the router.
type RouterDeps struct {
	AuthService  *services.AuthService
	OAuthService *services.OAuthService
	KeyService   *services.KeyService
	JWTManager   *jwt.Manager
	DBHealther   handlers.HealthChecker
	RedisHealther handlers.HealthChecker
}

// NewRouter creates and configures the HTTP router.
func NewRouter(cfg *config.Config, deps *RouterDeps) *Router {
	// Set Gin mode based on environment
	gin.SetMode(gin.ReleaseMode)

	engine := gin.New()

	// Add recovery middleware
	engine.Use(gin.Recovery())

	// Add request logging (customize as needed)
	engine.Use(gin.Logger())

	// Create handlers
	authHandler := handlers.NewAuthHandler(deps.AuthService)
	oauthHandler := handlers.NewOAuthHandler(
		deps.OAuthService,
		deps.AuthService,
		deps.KeyService,
		cfg.JWT.Issuer,
	)
	healthHandler := handlers.NewHealthHandler(deps.DBHealther, deps.RedisHealther)

	// Create middleware
	authMiddleware := middleware.NewAuthMiddleware(deps.JWTManager, deps.KeyService)

	// Rate limiters
	var rateLimiter *middleware.RateLimiter
	var authRateLimiter *middleware.AuthRateLimiter
	if cfg.Security.RateLimitEnabled {
		rateLimiter = middleware.NewRateLimiter(cfg.Security.RateLimitRPS, cfg.Security.RateLimitBurst)
		authRateLimiter = middleware.NewAuthRateLimiter()
	}

	// Health endpoints (no rate limiting)
	engine.GET("/health", healthHandler.Health)
	engine.GET("/ready", healthHandler.Ready)
	engine.GET("/live", healthHandler.Live)

	// Apply global rate limiting if enabled
	if rateLimiter != nil {
		engine.Use(rateLimiter.Middleware())
	}

	// CORS middleware
	engine.Use(corsMiddleware(cfg.Security.AllowedOrigins))

	// OIDC Discovery endpoints
	engine.GET("/.well-known/openid-configuration", oauthHandler.OpenIDConfiguration)
	engine.GET("/jwks.json", oauthHandler.JWKS)

	// OAuth endpoints
	oauth := engine.Group("")
	{
		// Authorization endpoint
		oauth.GET("/authorize", oauthHandler.Authorize)

		// Authorization consent (requires authentication)
		authorizeConsent := oauth.Group("")
		authorizeConsent.Use(authMiddleware.RequireAuth())
		{
			authorizeConsent.POST("/authorize", oauthHandler.AuthorizeConsent)
		}

		// Token endpoint
		oauth.POST("/token", oauthHandler.Token)
		oauth.POST("/token/refresh", oauthHandler.RefreshToken)
		oauth.POST("/token/revoke", oauthHandler.RevokeToken)

		// Client management (in production, protect this endpoint)
		oauth.POST("/oauth/client", oauthHandler.CreateClient)
	}

	// Auth endpoints with stricter rate limiting
	auth := engine.Group("/auth")
	if authRateLimiter != nil {
		auth.Use(authRateLimiter.Middleware())
	}
	{
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)

		// Logout requires device ID
		logoutGroup := auth.Group("")
		logoutGroup.Use(authMiddleware.RequireDeviceID())
		{
			logoutGroup.POST("/logout", authHandler.Logout)
		}
	}

	// Protected endpoints (require authentication)
	protected := engine.Group("")
	protected.Use(authMiddleware.RequireAuth())
	{
		// Device management
		protected.GET("/devices", authHandler.ListDevices)
		protected.POST("/logout/device/:device_id", authHandler.LogoutDevice)
		protected.POST("/logout/others", authHandler.LogoutAllOthers)
		protected.POST("/logout/all", authHandler.LogoutAll)
	}

	return &Router{
		engine: engine,
		cfg:    cfg,
	}
}

// Engine returns the underlying Gin engine.
func (r *Router) Engine() *gin.Engine {
	return r.engine
}

// corsMiddleware creates a CORS middleware.
func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Check if origin is allowed
		allowed := false
		for _, o := range allowedOrigins {
			if o == "*" || o == origin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Device-ID, X-CSRF-Token")
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Max-Age", "86400")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// NewServer creates an HTTP server with the router.
func NewServer(cfg *config.Config, router *Router) *Server {
	return &Server{
		router: router,
		cfg:    cfg,
	}
}

// Server wraps the HTTP server.
type Server struct {
	router *Router
	cfg    *config.Config
}

// ListenAddr returns the server listen address.
func (s *Server) ListenAddr() string {
	return s.cfg.Server.Host + ":" + itoa(s.cfg.Server.Port)
}

// ReadTimeout returns the server read timeout.
func (s *Server) ReadTimeout() time.Duration {
	return s.cfg.Server.ReadTimeout
}

// WriteTimeout returns the server write timeout.
func (s *Server) WriteTimeout() time.Duration {
	return s.cfg.Server.WriteTimeout
}

// IdleTimeout returns the server idle timeout.
func (s *Server) IdleTimeout() time.Duration {
	return s.cfg.Server.IdleTimeout
}

// Handler returns the HTTP handler.
func (s *Server) Handler() *gin.Engine {
	return s.router.Engine()
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	result := ""
	for i > 0 {
		result = string(rune(i%10+'0')) + result
		i /= 10
	}
	return result
}
