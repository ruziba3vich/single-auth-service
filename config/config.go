package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the service.
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Redis    RedisConfig
	JWT      JWTConfig
	Auth     AuthConfig
	Security SecurityConfig
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Host         string
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// DatabaseConfig holds PostgreSQL configuration.
type DatabaseConfig struct {
	Host            string
	Port            int
	User            string
	Password        string
	Database        string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// RedisConfig holds Redis configuration.
type RedisConfig struct {
	Host         string
	Port         int
	Password     string
	DB           int
	PoolSize     int
	MinIdleConns int
}

// JWTConfig holds JWT-related configuration.
type JWTConfig struct {
	Issuer              string
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	IDTokenTTL          time.Duration
	AuthCodeTTL         time.Duration
	KeyRotationInterval time.Duration
	KeyValidityPeriod   time.Duration
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	// Argon2 parameters
	Argon2Memory      uint32
	Argon2Iterations  uint32
	Argon2Parallelism uint8
	Argon2SaltLength  uint32
	Argon2KeyLength   uint32

	// Session limits
	MaxDevicesPerUser int
}

// SecurityConfig holds security-related configuration.
type SecurityConfig struct {
	AllowedOrigins   []string
	CSRFTokenLength  int
	SecureCookies    bool
	CookieDomain     string
	CookieSameSite   string
	RateLimitEnabled bool
	RateLimitRPS     int
	RateLimitBurst   int
}

// Load loads configuration from environment variables.
func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         getEnv("SERVER_HOST", "0.0.0.0"),
			Port:         getEnvInt("SERVER_PORT", 8080),
			ReadTimeout:  getEnvDuration("SERVER_READ_TIMEOUT", 30*time.Second),
			WriteTimeout: getEnvDuration("SERVER_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:  getEnvDuration("SERVER_IDLE_TIMEOUT", 120*time.Second),
		},
		Database: DatabaseConfig{
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnvInt("DB_PORT", 5432),
			User:            getEnv("DB_USER", "auth"),
			Password:        getEnv("DB_PASSWORD", ""),
			Database:        getEnv("DB_NAME", "auth_service"),
			SSLMode:         getEnv("DB_SSL_MODE", "disable"),
			MaxOpenConns:    getEnvInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvInt("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getEnvDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		},
		Redis: RedisConfig{
			Host:         getEnv("REDIS_HOST", "localhost"),
			Port:         getEnvInt("REDIS_PORT", 6379),
			Password:     getEnv("REDIS_PASSWORD", ""),
			DB:           getEnvInt("REDIS_DB", 0),
			PoolSize:     getEnvInt("REDIS_POOL_SIZE", 10),
			MinIdleConns: getEnvInt("REDIS_MIN_IDLE_CONNS", 5),
		},
		JWT: JWTConfig{
			Issuer:              getEnv("JWT_ISSUER", "https://auth.example.com"),
			AccessTokenTTL:      getEnvDuration("JWT_ACCESS_TOKEN_TTL", 15*time.Minute),
			RefreshTokenTTL:     getEnvDuration("JWT_REFRESH_TOKEN_TTL", 7*24*time.Hour),
			IDTokenTTL:          getEnvDuration("JWT_ID_TOKEN_TTL", 1*time.Hour),
			AuthCodeTTL:         getEnvDuration("JWT_AUTH_CODE_TTL", 10*time.Minute),
			KeyRotationInterval: getEnvDuration("JWT_KEY_ROTATION_INTERVAL", 24*time.Hour),
			KeyValidityPeriod:   getEnvDuration("JWT_KEY_VALIDITY_PERIOD", 7*24*time.Hour),
		},
		Auth: AuthConfig{
			// Argon2id recommended parameters (OWASP)
			Argon2Memory:      getEnvUint32("ARGON2_MEMORY", 64*1024), // 64 MB
			Argon2Iterations:  getEnvUint32("ARGON2_ITERATIONS", 3),
			Argon2Parallelism: getEnvUint8("ARGON2_PARALLELISM", 4),
			Argon2SaltLength:  getEnvUint32("ARGON2_SALT_LENGTH", 16),
			Argon2KeyLength:   getEnvUint32("ARGON2_KEY_LENGTH", 32),
			MaxDevicesPerUser: getEnvInt("MAX_DEVICES_PER_USER", 10),
		},
		Security: SecurityConfig{
			AllowedOrigins:   getEnvSlice("ALLOWED_ORIGINS", []string{"http://localhost:3000"}),
			CSRFTokenLength:  getEnvInt("CSRF_TOKEN_LENGTH", 32),
			SecureCookies:    getEnvBool("SECURE_COOKIES", true),
			CookieDomain:     getEnv("COOKIE_DOMAIN", ""),
			CookieSameSite:   getEnv("COOKIE_SAME_SITE", "Strict"),
			RateLimitEnabled: getEnvBool("RATE_LIMIT_ENABLED", true),
			RateLimitRPS:     getEnvInt("RATE_LIMIT_RPS", 100),
			RateLimitBurst:   getEnvInt("RATE_LIMIT_BURST", 200),
		},
	}
}

// DSN returns the PostgreSQL connection string.
func (c *DatabaseConfig) DSN() string {
	return "host=" + c.Host +
		" port=" + strconv.Itoa(c.Port) +
		" user=" + c.User +
		" password=" + c.Password +
		" dbname=" + c.Database +
		" sslmode=" + c.SSLMode
}

// Helper functions for environment variable parsing

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvUint32(key string, defaultValue uint32) uint32 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseUint(value, 10, 32); err == nil {
			return uint32(intValue)
		}
	}
	return defaultValue
}

func getEnvUint8(key string, defaultValue uint8) uint8 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseUint(value, 10, 8); err == nil {
			return uint8(intValue)
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getEnvSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}
