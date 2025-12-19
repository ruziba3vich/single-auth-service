package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// HealthChecker interface for checking service health.
type HealthChecker interface {
	Health(ctx context.Context) error
}

// HealthHandler handles health check endpoints.
type HealthHandler struct {
	db    HealthChecker
	redis HealthChecker
}

// NewHealthHandler creates a new health handler.
func NewHealthHandler(db, redis HealthChecker) *HealthHandler {
	return &HealthHandler{
		db:    db,
		redis: redis,
	}
}

// Health returns the service health status.
// GET /health
func (h *HealthHandler) Health(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	status := "healthy"
	httpStatus := http.StatusOK

	checks := make(map[string]string)

	// Check database
	if err := h.db.Health(ctx); err != nil {
		checks["database"] = "unhealthy"
		status = "unhealthy"
		httpStatus = http.StatusServiceUnavailable
	} else {
		checks["database"] = "healthy"
	}

	// Check Redis
	if err := h.redis.Health(ctx); err != nil {
		checks["redis"] = "unhealthy"
		status = "unhealthy"
		httpStatus = http.StatusServiceUnavailable
	} else {
		checks["redis"] = "healthy"
	}

	c.JSON(httpStatus, gin.H{
		"status": status,
		"checks": checks,
	})
}

// Ready returns whether the service is ready to accept requests.
// GET /ready
func (h *HealthHandler) Ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// Check critical dependencies
	if err := h.db.Health(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"ready": false})
		return
	}

	if err := h.redis.Health(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"ready": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ready": true})
}

// Live returns whether the service is alive.
// GET /live
func (h *HealthHandler) Live(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"alive": true})
}
