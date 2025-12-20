package logger

import (
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Field represents a structured log field.
type Field = zap.Field

// String constructs a field with a string value.
func String(key string, val string) Field {
	return zap.String(key, val)
}

// Int constructs a field with an integer value.
func Int(key string, val int) Field {
	return zap.Int(key, val)
}

// Int64 constructs a field with a 64-bit integer value.
func Int64(key string, val int64) Field {
	return zap.Int64(key, val)
}

// Uint constructs a field with an unsigned integer value.
func Uint(key string, val uint) Field {
	return zap.Uint(key, val)
}

// Float64 constructs a field with a float64 value.
func Float64(key string, val float64) Field {
	return zap.Float64(key, val)
}

// Bool constructs a field with a boolean value.
func Bool(key string, val bool) Field {
	return zap.Bool(key, val)
}

// Duration constructs a field with a time.Duration value.
func Duration(key string, val time.Duration) Field {
	return zap.Duration(key, val)
}

// Time constructs a field with a time.Time value.
func Time(key string, val time.Time) Field {
	return zap.Time(key, val)
}

// Error constructs a field with an error value.
func Error(err error) Field {
	return zap.Error(err)
}

// NamedError constructs a field with an error value and custom key.
func NamedError(key string, err error) Field {
	return zap.NamedError(key, err)
}

// Any constructs a field with any value using reflection.
func Any(key string, val interface{}) Field {
	return zap.Any(key, val)
}

// Common field constructors for request context.

// RequestID constructs a request_id field.
func RequestID(id string) Field {
	return String("request_id", id)
}

// UserID constructs a user_id field.
func UserID(id string) Field {
	return String("user_id", id)
}

// Method constructs an HTTP method field.
func Method(method string) Field {
	return String("method", method)
}

// Path constructs an HTTP path field.
func Path(path string) Field {
	return String("path", path)
}

// Status constructs an HTTP status code field.
func Status(code int) Field {
	return Int("status", code)
}

// Latency constructs a latency field from duration.
func Latency(d time.Duration) Field {
	return Duration("latency", d)
}

// ClientIP constructs a client_ip field.
func ClientIP(ip string) Field {
	return String("client_ip", ip)
}

// UserAgent constructs a user_agent field.
func UserAgent(ua string) Field {
	return String("user_agent", ua)
}

// Component constructs a component field for identifying log source.
func Component(name string) Field {
	return String("component", name)
}

// parseLevel converts a string level to zapcore.Level.
func parseLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}
