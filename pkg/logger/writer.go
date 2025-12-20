package logger

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteWriter writes log entries to SQLite asynchronously.
type SQLiteWriter struct {
	db       *sql.DB
	buffer   chan LogEntry
	done     chan struct{}
	wg       sync.WaitGroup
	config   Config
	stopOnce sync.Once
}

// NewSQLiteWriter creates a new SQLite log writer.
func NewSQLiteWriter(cfg Config) (*SQLiteWriter, error) {
	// Ensure directory exists
	dir := filepath.Dir(cfg.SQLiteDBPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", cfg.SQLiteDBPath)
	if err != nil {
		return nil, err
	}

	// Configure SQLite for concurrent access
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		db.Close()
		return nil, err
	}

	// Run migrations
	if err := runMigrations(db); err != nil {
		db.Close()
		return nil, err
	}

	w := &SQLiteWriter{
		db:     db,
		buffer: make(chan LogEntry, cfg.AsyncBufferSize),
		done:   make(chan struct{}),
		config: cfg,
	}

	// Start worker goroutine
	w.wg.Add(1)
	go w.worker()

	return w, nil
}

func runMigrations(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp INTEGER NOT NULL,
		level TEXT NOT NULL,
		message TEXT NOT NULL,
		caller TEXT,
		fields TEXT,
		request_id TEXT,
		user_id TEXT,
		created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
	);

	CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level);
	CREATE INDEX IF NOT EXISTS idx_logs_request_id ON logs(request_id) WHERE request_id IS NOT NULL AND request_id != '';
	CREATE INDEX IF NOT EXISTS idx_logs_user_id ON logs(user_id) WHERE user_id IS NOT NULL AND user_id != '';
	`
	_, err := db.Exec(schema)
	return err
}

// Write queues a log entry for async writing.
func (w *SQLiteWriter) Write(entry LogEntry) error {
	select {
	case w.buffer <- entry:
		return nil
	default:
		// Buffer full, drop the log entry
		return nil
	}
}

// Close stops the writer and flushes remaining entries.
func (w *SQLiteWriter) Close() error {
	w.stopOnce.Do(func() {
		close(w.done)
		w.wg.Wait()
	})
	return w.db.Close()
}

func (w *SQLiteWriter) worker() {
	defer w.wg.Done()

	batch := make([]LogEntry, 0, w.config.BatchSize)
	ticker := time.NewTicker(w.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case entry := <-w.buffer:
			batch = append(batch, entry)
			if len(batch) >= w.config.BatchSize {
				w.flush(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				w.flush(batch)
				batch = batch[:0]
			}
		case <-w.done:
			// Drain remaining entries
			for {
				select {
				case entry := <-w.buffer:
					batch = append(batch, entry)
				default:
					if len(batch) > 0 {
						w.flush(batch)
					}
					return
				}
			}
		}
	}
}

func (w *SQLiteWriter) flush(entries []LogEntry) {
	if len(entries) == 0 {
		return
	}

	tx, err := w.db.Begin()
	if err != nil {
		return
	}

	stmt, err := tx.Prepare(`
		INSERT INTO logs (timestamp, level, message, caller, fields, request_id, user_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		tx.Rollback()
		return
	}
	defer stmt.Close()

	for _, entry := range entries {
		var fieldsJSON []byte
		if len(entry.Fields) > 0 {
			fieldsJSON, _ = json.Marshal(entry.Fields)
		}

		_, err := stmt.Exec(
			entry.Timestamp,
			entry.Level,
			entry.Message,
			entry.Caller,
			string(fieldsJSON),
			entry.RequestID,
			entry.UserID,
		)
		if err != nil {
			// Continue with other entries on error
			continue
		}
	}

	tx.Commit()
}

// Query retrieves log entries with filters.
func (w *SQLiteWriter) Query(ctx context.Context, filter QueryFilter) ([]LogEntry, int64, error) {
	// Build query
	baseQuery := `FROM logs WHERE 1=1`
	var args []interface{}

	if filter.Level != nil && *filter.Level != "" {
		baseQuery += ` AND level = ?`
		args = append(args, *filter.Level)
	}

	if filter.StartTime != nil {
		baseQuery += ` AND timestamp >= ?`
		args = append(args, filter.StartTime.UnixMilli())
	}

	if filter.EndTime != nil {
		baseQuery += ` AND timestamp <= ?`
		args = append(args, filter.EndTime.UnixMilli())
	}

	if filter.Search != nil && *filter.Search != "" {
		baseQuery += ` AND message LIKE ?`
		args = append(args, "%"+*filter.Search+"%")
	}

	if filter.RequestID != nil && *filter.RequestID != "" {
		baseQuery += ` AND request_id = ?`
		args = append(args, *filter.RequestID)
	}

	if filter.UserID != nil && *filter.UserID != "" {
		baseQuery += ` AND user_id = ?`
		args = append(args, *filter.UserID)
	}

	// Count total
	var total int64
	countQuery := `SELECT COUNT(*) ` + baseQuery
	if err := w.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Get entries
	selectQuery := `SELECT id, timestamp, level, message, caller, fields, request_id, user_id ` +
		baseQuery + ` ORDER BY timestamp DESC LIMIT ? OFFSET ?`
	args = append(args, filter.Limit, filter.Offset)

	rows, err := w.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []LogEntry
	for rows.Next() {
		var entry LogEntry
		var id int64
		var fieldsJSON sql.NullString
		var requestID, userID, caller sql.NullString

		if err := rows.Scan(&id, &entry.Timestamp, &entry.Level, &entry.Message,
			&caller, &fieldsJSON, &requestID, &userID); err != nil {
			return nil, 0, err
		}

		entry.Caller = caller.String
		entry.RequestID = requestID.String
		entry.UserID = userID.String

		if fieldsJSON.Valid && fieldsJSON.String != "" {
			json.Unmarshal([]byte(fieldsJSON.String), &entry.Fields)
		}

		entries = append(entries, entry)
	}

	return entries, total, nil
}

// DeleteOlderThan removes logs older than the given time.
func (w *SQLiteWriter) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	result, err := w.db.ExecContext(ctx, `DELETE FROM logs WHERE timestamp < ?`, before.UnixMilli())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// StartCleanupJob starts a background job to clean old logs.
func (w *SQLiteWriter) StartCleanupJob(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		// Run immediately on start
		w.cleanup()

		for {
			select {
			case <-ticker.C:
				w.cleanup()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (w *SQLiteWriter) cleanup() {
	cutoff := time.Now().AddDate(0, 0, -w.config.RetentionDays)
	w.DeleteOlderThan(context.Background(), cutoff)
}

// QueryFilter defines filters for querying logs.
type QueryFilter struct {
	Level     *string
	StartTime *time.Time
	EndTime   *time.Time
	Search    *string
	RequestID *string
	UserID    *string
	Limit     int
	Offset    int
}
