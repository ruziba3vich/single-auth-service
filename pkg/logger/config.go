package logger

import "time"

// Config holds the logger configuration.
type Config struct {
	// Level sets the minimum log level (debug, info, warn, error)
	Level string

	// Environment determines output format (development = console, production = JSON)
	Environment string

	// EnableConsole enables console output
	EnableConsole bool

	// EnableSQLite enables SQLite log storage
	EnableSQLite bool

	// SQLiteDBPath is the path to the SQLite database file
	SQLiteDBPath string

	// AsyncBufferSize is the buffer size for async log writing
	AsyncBufferSize int

	// RetentionDays is the number of days to keep logs
	RetentionDays int

	// FlushInterval is how often to flush buffered logs to SQLite
	FlushInterval time.Duration

	// BatchSize is the maximum number of logs to write in a single batch
	BatchSize int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Level:           "info",
		Environment:     "development",
		EnableConsole:   true,
		EnableSQLite:    true,
		SQLiteDBPath:    "./data/logs.db",
		AsyncBufferSize: 1000,
		RetentionDays:   7,
		FlushInterval:   100 * time.Millisecond,
		BatchSize:       100,
	}
}
