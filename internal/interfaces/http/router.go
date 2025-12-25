package http

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/ruziba3vich/single-auth-service/config"
	"github.com/ruziba3vich/single-auth-service/internal/application/services"
	"github.com/ruziba3vich/single-auth-service/internal/generated"
	"github.com/ruziba3vich/single-auth-service/internal/interfaces/http/handlers"
	"github.com/ruziba3vich/single-auth-service/internal/interfaces/http/middleware"
	"github.com/ruziba3vich/single-auth-service/pkg/jwt"
	"github.com/ruziba3vich/single-auth-service/pkg/logger"
)

// Router wraps the Gin engine with application dependencies.
type Router struct {
	engine *gin.Engine
	cfg    *config.Config
}

// RouterDeps contains dependencies needed by the router.
type RouterDeps struct {
	AuthService   *services.AuthService
	OAuthService  *services.OAuthService
	KeyService    *services.KeyService
	JWTManager    *jwt.Manager
	DBHealther    handlers.HealthChecker
	RedisHealther handlers.HealthChecker
	Logger        logger.Logger
	LogWriter     *logger.SQLiteWriter
}

// NewRouter creates and configures the HTTP router.
func NewRouter(cfg *config.Config, deps *RouterDeps) *Router {
	// Set Gin mode based on environment
	gin.SetMode(gin.ReleaseMode)

	engine := gin.New()

	// Add recovery middleware
	engine.Use(gin.Recovery())

	// Add structured request logging middleware
	if deps.Logger != nil {
		requestLoggerMiddleware := middleware.NewRequestLoggerMiddleware(deps.Logger)
		engine.Use(requestLoggerMiddleware.Handler())
	} else {
		// Fallback to default Gin logger
		engine.Use(gin.Logger())
	}

	// Create the server that implements generated.ServerInterface
	server := handlers.NewServer(&handlers.ServerDeps{
		AuthService:  deps.AuthService,
		OAuthService: deps.OAuthService,
		KeyService:   deps.KeyService,
		Issuer:       cfg.JWT.Issuer,
		DBHealth:     deps.DBHealther,
		RedisHealth:  deps.RedisHealther,
	})

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
	engine.GET("/health", server.GetHealth)
	engine.GET("/ready", server.GetReady)
	engine.GET("/live", server.GetLive)

	// Apply global rate limiting if enabled
	if rateLimiter != nil {
		engine.Use(rateLimiter.Middleware())
	}

	// CORS middleware
	engine.Use(corsMiddleware(cfg.Security.AllowedOrigins))

	// OIDC Discovery endpoints
	engine.GET("/.well-known/openid-configuration", server.GetOpenIDConfiguration)
	engine.GET("/jwks.json", server.GetJWKS)

	// OAuth endpoints
	oauth := engine.Group("")
	{
		// Authorization endpoint (GET - shows consent info)
		oauth.GET("/authorize", wrapWithParams(server.Authorize))

		// Authorization consent (POST - requires authentication)
		authorizeConsent := oauth.Group("")
		authorizeConsent.Use(authMiddleware.RequireAuth())
		{
			authorizeConsent.POST("/authorize", server.AuthorizeConsent)
		}

		// Token endpoints
		oauth.POST("/token", server.Token)
		oauth.POST("/token/refresh", server.RefreshToken)
		oauth.POST("/token/revoke", server.RevokeToken)

		// Client management (in production, protect this endpoint)
		oauth.POST("/oauth/client", server.CreateClient)
	}

	// Auth endpoints with stricter rate limiting
	auth := engine.Group("/auth")
	if authRateLimiter != nil {
		auth.Use(authRateLimiter.Middleware())
	}
	{
		auth.POST("/register", server.Register)
		auth.POST("/login", server.Login)

		// Logout requires device ID
		logoutGroup := auth.Group("")
		logoutGroup.Use(authMiddleware.RequireDeviceID())
		{
			logoutGroup.POST("/logout", wrapWithLogoutParams(server.Logout))
		}
	}

	// Protected endpoints (require authentication)
	protected := engine.Group("")
	protected.Use(authMiddleware.RequireAuth())
	{
		// Device management
		protected.GET("/devices", wrapWithListDevicesParams(server.ListDevices))
		protected.POST("/logout/device/:device_id", wrapWithDeviceID(server.LogoutDevice))
		protected.POST("/logout/others", wrapWithLogoutAllOthersParams(server.LogoutAllOthers))
		protected.POST("/logout/all", server.LogoutAll)

		// FCM token queries (requires auth)
		protected.GET("/users/:user_id/fcm-tokens", wrapWithUserID(server.GetUserFCMTokens))
	}

	// FCM endpoints (public, validates refresh token)
	fcm := engine.Group("/fcm")
	{
		fcm.POST("/register", server.RegisterFCMToken)
	}

	// Log viewer endpoints (no auth for dev)
	if cfg.Logging.ViewerEnabled && deps.LogWriter != nil {
		logViewerHandler, err := handlers.NewLogViewerHandler(&handlers.LogViewerDeps{
			Writer: deps.LogWriter,
		})
		if err == nil {
			admin := engine.Group("/admin")
			{
				admin.GET("/logs", logViewerHandler.Index)
				admin.GET("/logs/entries", logViewerHandler.GetLogs)
			}
			// Serve static assets
			engine.GET("/admin/static/*filepath", func(c *gin.Context) {
				c.Request.URL.Path = strings.TrimPrefix(c.Request.URL.Path, "/admin/static")
				handlers.StaticHandler().ServeHTTP(c.Writer, c.Request)
			})
		}
	}

	return &Router{
		engine: engine,
		cfg:    cfg,
	}
}

// wrapWithParams wraps handlers that need query params extracted
func wrapWithParams(handler func(*gin.Context, generated.AuthorizeParams)) gin.HandlerFunc {
	return func(c *gin.Context) {
		var params generated.AuthorizeParams
		if err := c.ShouldBindQuery(&params); err != nil {
			c.JSON(400, gin.H{"error": "invalid_request", "error_description": err.Error()})
			return
		}
		handler(c, params)
	}
}

// wrapWithLogoutParams wraps logout handler with params extraction
func wrapWithLogoutParams(handler func(*gin.Context, generated.LogoutParams)) gin.HandlerFunc {
	return func(c *gin.Context) {
		params := generated.LogoutParams{}
		if deviceID := c.GetHeader("X-Device-ID"); deviceID != "" {
			params.XDeviceID = parseUUID(deviceID)
		}
		handler(c, params)
	}
}

// wrapWithListDevicesParams wraps list devices handler with params extraction
func wrapWithListDevicesParams(handler func(*gin.Context, generated.ListDevicesParams)) gin.HandlerFunc {
	return func(c *gin.Context) {
		params := generated.ListDevicesParams{}
		if deviceID := c.GetHeader("X-Device-ID"); deviceID != "" {
			params.XDeviceID = parseUUID(deviceID)
		}
		handler(c, params)
	}
}

// wrapWithLogoutAllOthersParams wraps logout others handler with params extraction
func wrapWithLogoutAllOthersParams(handler func(*gin.Context, generated.LogoutAllOthersParams)) gin.HandlerFunc {
	return func(c *gin.Context) {
		params := generated.LogoutAllOthersParams{}
		if deviceID := c.GetHeader("X-Device-ID"); deviceID != "" {
			params.XDeviceID = parseUUID(deviceID)
		}
		handler(c, params)
	}
}

// wrapWithDeviceID wraps handler that needs device_id path param
func wrapWithDeviceID(handler func(*gin.Context, openapi_types.UUID)) gin.HandlerFunc {
	return func(c *gin.Context) {
		deviceIDStr := c.Param("device_id")
		deviceID := parseUUID(deviceIDStr)
		if deviceID == nil {
			c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid device_id"})
			return
		}
		handler(c, *deviceID)
	}
}

// wrapWithUserID wraps handler that needs user_id path param
func wrapWithUserID(handler func(*gin.Context, openapi_types.UUID)) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr := c.Param("user_id")
		userID := parseUUID(userIDStr)
		if userID == nil {
			c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid user_id"})
			return
		}
		handler(c, *userID)
	}
}

// parseUUID parses a string to UUID pointer
func parseUUID(s string) *openapi_types.UUID {
	if s == "" {
		return nil
	}
	parsed, err := parseUUIDString(s)
	if err != nil {
		return nil
	}
	uuid := openapi_types.UUID(parsed)
	return &uuid
}

// parseUUIDString parses UUID string
func parseUUIDString(s string) ([16]byte, error) {
	var result [16]byte
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return result, fmt.Errorf("invalid UUID length")
	}
	for i := 0; i < 16; i++ {
		b, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return result, err
		}
		result[i] = byte(b)
	}
	return result, nil
}

// Engine returns the underlying Gin engine.
func (r *Router) Engine() *gin.Engine {
	return r.engine
}

// corsMiddleware creates a CORS middleware.
func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

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
