package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/ruziba3vich/single-auth-service/pkg/logger"
)

const (
	// ContextKeyRequestID is the context key for request ID.
	ContextKeyRequestID ContextKey = "request_id"
)

// RequestLoggerMiddleware logs all HTTP requests with structured fields.
type RequestLoggerMiddleware struct {
	logger logger.Logger
}

// NewRequestLoggerMiddleware creates a new request logger middleware.
func NewRequestLoggerMiddleware(l logger.Logger) *RequestLoggerMiddleware {
	return &RequestLoggerMiddleware{
		logger: l,
	}
}

// Handler returns the Gin middleware handler.
func (m *RequestLoggerMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Generate or extract request ID
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Set(string(ContextKeyRequestID), requestID)
		c.Header("X-Request-ID", requestID)

		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		// Create request-scoped logger
		requestLogger := m.logger.With(
			logger.RequestID(requestID),
		)
		ctx := logger.WithContext(c.Request.Context(), requestLogger)
		c.Request = c.Request.WithContext(ctx)

		// Process request
		c.Next()

		// Log after request completes
		latency := time.Since(start)
		status := c.Writer.Status()
		clientIP := GetClientIP(c)
		method := c.Request.Method
		userAgent := c.GetHeader("User-Agent")

		fields := []logger.Field{
			logger.RequestID(requestID),
			logger.Method(method),
			logger.Path(path),
			logger.Status(status),
			logger.Latency(latency),
			logger.ClientIP(clientIP),
			logger.UserAgent(userAgent),
			logger.Int("body_size", c.Writer.Size()),
		}

		// Add query if present
		if query != "" {
			fields = append(fields, logger.String("query", query))
		}

		// Add user_id if available
		if userID, exists := c.Get(string(ContextKeyUserID)); exists {
			if uid, ok := userID.(string); ok && uid != "" {
				fields = append(fields, logger.UserID(uid))
			}
		}

		// Add device_id if available
		if deviceID, exists := c.Get(string(ContextKeyDeviceID)); exists {
			if did, ok := deviceID.(string); ok && did != "" {
				fields = append(fields, logger.String("device_id", did))
			}
		}

		// Add error if present
		if len(c.Errors) > 0 {
			fields = append(fields, logger.String("errors", c.Errors.String()))
		}

		// Choose log level based on status
		msg := "HTTP request"
		switch {
		case status >= 500:
			m.logger.Error(msg, fields...)
		case status >= 400:
			m.logger.Warn(msg, fields...)
		default:
			m.logger.Info(msg, fields...)
		}
	}
}

// GetRequestID extracts request ID from context.
func GetRequestID(c *gin.Context) string {
	if requestID, exists := c.Get(string(ContextKeyRequestID)); exists {
		if rid, ok := requestID.(string); ok {
			return rid
		}
	}
	return ""
}
