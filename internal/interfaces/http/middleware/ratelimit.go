package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter implements a token bucket rate limiter.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens per second
	burst    int     // maximum tokens
	cleanupInterval time.Duration
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(rps int, burst int) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*bucket),
		rate:    float64(rps),
		burst:   burst,
		cleanupInterval: 10 * time.Minute,
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if a request should be allowed.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, exists := rl.buckets[key]
	if !exists {
		rl.buckets[key] = &bucket{
			tokens:    float64(rl.burst) - 1,
			lastCheck: now,
		}
		return true
	}

	// Add tokens based on time passed
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastCheck = now

	// Check if we have tokens
	if b.tokens >= 1 {
		b.tokens--
		return true
	}

	return false
}

// cleanup removes old entries periodically.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, b := range rl.buckets {
			if now.Sub(b.lastCheck) > rl.cleanupInterval {
				delete(rl.buckets, key)
			}
		}
		rl.mu.Unlock()
	}
}

// Middleware returns a Gin middleware for rate limiting.
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use IP as the rate limit key
		key := GetClientIP(c)

		if !rl.Allow(key) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":             "too_many_requests",
				"error_description": "rate limit exceeded",
			})
			return
		}

		c.Next()
	}
}

// AuthRateLimiter provides stricter rate limiting for auth endpoints.
type AuthRateLimiter struct {
	*RateLimiter
}

// NewAuthRateLimiter creates a rate limiter for auth endpoints.
func NewAuthRateLimiter() *AuthRateLimiter {
	// Stricter limits for auth: 10 requests per minute
	return &AuthRateLimiter{
		RateLimiter: NewRateLimiter(10, 20),
	}
}

// Middleware returns auth-specific rate limiting.
func (rl *AuthRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use IP + endpoint as the rate limit key
		key := GetClientIP(c) + ":" + c.Request.URL.Path

		if !rl.Allow(key) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":             "too_many_requests",
				"error_description": "too many authentication attempts",
			})
			return
		}

		c.Next()
	}
}
