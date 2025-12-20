package logger

import (
	"context"
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger defines the logging interface.
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	With(fields ...Field) Logger
	Sync() error
}

// LogEntry represents a log entry for storage.
type LogEntry struct {
	Timestamp int64                  `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Caller    string                 `json:"caller,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
}

// LogWriter is the interface for writing log entries to storage.
type LogWriter interface {
	Write(entry LogEntry) error
	Close() error
}

// zapLogger wraps zap.Logger to implement Logger interface.
type zapLogger struct {
	logger *zap.Logger
	writer LogWriter
}

var (
	defaultLogger Logger
	defaultOnce   sync.Once
)

// New creates a new Logger with the given configuration.
func New(cfg Config, writer LogWriter) (Logger, error) {
	var cores []zapcore.Core

	level := parseLevel(cfg.Level)

	// Console core
	if cfg.EnableConsole {
		var encoder zapcore.Encoder
		if cfg.Environment == "production" {
			encoderConfig := zap.NewProductionEncoderConfig()
			encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
			encoder = zapcore.NewJSONEncoder(encoderConfig)
		} else {
			encoderConfig := zap.NewDevelopmentEncoderConfig()
			encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
			encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05.000")
			encoder = zapcore.NewConsoleEncoder(encoderConfig)
		}
		consoleCore := zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), level)
		cores = append(cores, consoleCore)
	}

	// SQLite writer core
	if cfg.EnableSQLite && writer != nil {
		sqliteCore := newSQLiteCore(writer, level)
		cores = append(cores, sqliteCore)
	}

	core := zapcore.NewTee(cores...)
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	return &zapLogger{
		logger: logger,
		writer: writer,
	}, nil
}

// Default returns the default logger, initializing it if needed.
func Default() Logger {
	defaultOnce.Do(func() {
		cfg := DefaultConfig()
		cfg.EnableSQLite = false // No SQLite for default logger
		logger, _ := New(cfg, nil)
		defaultLogger = logger
	})
	return defaultLogger
}

// SetDefault sets the default logger.
func SetDefault(l Logger) {
	defaultLogger = l
}

func (l *zapLogger) Debug(msg string, fields ...Field) {
	l.logger.Debug(msg, fields...)
}

func (l *zapLogger) Info(msg string, fields ...Field) {
	l.logger.Info(msg, fields...)
}

func (l *zapLogger) Warn(msg string, fields ...Field) {
	l.logger.Warn(msg, fields...)
}

func (l *zapLogger) Error(msg string, fields ...Field) {
	l.logger.Error(msg, fields...)
}

func (l *zapLogger) With(fields ...Field) Logger {
	return &zapLogger{
		logger: l.logger.With(fields...),
		writer: l.writer,
	}
}

func (l *zapLogger) Sync() error {
	if l.writer != nil {
		l.writer.Close()
	}
	return l.logger.Sync()
}

// Context key for logger.
type contextKey struct{}

// WithContext returns a context with the logger attached.
func WithContext(ctx context.Context, l Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, l)
}

// FromContext retrieves the logger from context, or returns the default logger.
func FromContext(ctx context.Context) Logger {
	if l, ok := ctx.Value(contextKey{}).(Logger); ok {
		return l
	}
	return Default()
}

// sqliteCore is a zapcore.Core that writes to SQLite.
type sqliteCore struct {
	zapcore.LevelEnabler
	writer LogWriter
	fields []Field
}

func newSQLiteCore(writer LogWriter, level zapcore.Level) zapcore.Core {
	return &sqliteCore{
		LevelEnabler: level,
		writer:       writer,
	}
}

func (c *sqliteCore) With(fields []zapcore.Field) zapcore.Core {
	clone := &sqliteCore{
		LevelEnabler: c.LevelEnabler,
		writer:       c.writer,
		fields:       append(c.fields, fields...),
	}
	return clone
}

func (c *sqliteCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return ce.AddCore(entry, c)
	}
	return ce
}

func (c *sqliteCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	allFields := append(c.fields, fields...)

	// Convert fields to map
	fieldMap := make(map[string]interface{})
	var requestID, userID string

	enc := zapcore.NewMapObjectEncoder()
	for _, f := range allFields {
		f.AddTo(enc)
		if f.Key == "request_id" {
			requestID = f.String
		} else if f.Key == "user_id" {
			userID = f.String
		}
	}
	for k, v := range enc.Fields {
		fieldMap[k] = v
	}

	logEntry := LogEntry{
		Timestamp: entry.Time.UnixMilli(),
		Level:     entry.Level.String(),
		Message:   entry.Message,
		Caller:    entry.Caller.String(),
		Fields:    fieldMap,
		RequestID: requestID,
		UserID:    userID,
	}

	return c.writer.Write(logEntry)
}

func (c *sqliteCore) Sync() error {
	return nil
}
