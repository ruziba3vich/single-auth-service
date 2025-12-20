package handlers

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ruziba3vich/single-auth-service/pkg/logger"
	"github.com/ruziba3vich/single-auth-service/web"
)

// LogViewerHandler handles log viewer web UI.
type LogViewerHandler struct {
	writer    *logger.SQLiteWriter
	templates *template.Template
}

// LogViewerDeps contains dependencies for the log viewer.
type LogViewerDeps struct {
	Writer *logger.SQLiteWriter
}

// NewLogViewerHandler creates a new log viewer handler.
func NewLogViewerHandler(deps *LogViewerDeps) (*LogViewerHandler, error) {
	// Parse templates from embedded filesystem
	tmplFS, err := fs.Sub(web.Assets, "templates/logs")
	if err != nil {
		return nil, err
	}

	tmpl, err := template.New("").Funcs(template.FuncMap{
		"json": func(v interface{}) string {
			b, _ := json.MarshalIndent(v, "", "  ")
			return string(b)
		},
	}).ParseFS(tmplFS, "*.html")
	if err != nil {
		return nil, err
	}

	return &LogViewerHandler{
		writer:    deps.Writer,
		templates: tmpl,
	}, nil
}

// Index serves the main log viewer page.
func (h *LogViewerHandler) Index(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(c.Writer, "index.html", nil); err != nil {
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

// LogEntryView represents a log entry for template rendering.
type LogEntryView struct {
	Timestamp      int64
	Level          string
	Message        string
	Caller         string
	Fields         map[string]interface{}
	RequestID      string
	UserID         string
	FormattedTime  string
	FullTime       string
	ShortCaller    string
	ShortRequestID string
	FieldsJSON     string
}

// LogTableData contains data for the log table template.
type LogTableData struct {
	Entries    []LogEntryView
	Total      int64
	From       int
	To         int
	Page       int
	TotalPages int
	PrevOffset int
	NextOffset int
}

// GetLogs returns log entries as an HTMX partial.
func (h *LogViewerHandler) GetLogs(c *gin.Context) {
	// Parse filter parameters
	filter := logger.QueryFilter{
		Limit:  50,
		Offset: 0,
	}

	if level := c.Query("level"); level != "" {
		filter.Level = &level
	}

	if search := c.Query("search"); search != "" {
		filter.Search = &search
	}

	if requestID := c.Query("request_id"); requestID != "" {
		filter.RequestID = &requestID
	}

	if startTime := c.Query("start_time"); startTime != "" {
		if t, err := time.ParseInLocation("2006-01-02T15:04", startTime, time.Local); err == nil {
			filter.StartTime = &t
		}
	}

	if endTime := c.Query("end_time"); endTime != "" {
		if t, err := time.ParseInLocation("2006-01-02T15:04", endTime, time.Local); err == nil {
			filter.EndTime = &t
		}
	}

	if limit := c.Query("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 && l <= 200 {
			filter.Limit = l
		}
	}

	if offset := c.Query("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil && o >= 0 {
			filter.Offset = o
		}
	}

	// Query logs
	entries, total, err := h.writer.Query(c.Request.Context(), filter)
	if err != nil {
		c.String(http.StatusInternalServerError, "Query error: %v", err)
		return
	}

	// Convert to view models
	viewEntries := make([]LogEntryView, len(entries))
	for i, entry := range entries {
		t := time.UnixMilli(entry.Timestamp)
		fieldsJSON := ""
		if len(entry.Fields) > 0 {
			b, _ := json.MarshalIndent(entry.Fields, "", "  ")
			fieldsJSON = string(b)
		}

		shortCaller := entry.Caller
		if idx := strings.LastIndex(entry.Caller, "/"); idx != -1 {
			shortCaller = entry.Caller[idx+1:]
		}

		shortRequestID := entry.RequestID
		if len(entry.RequestID) > 8 {
			shortRequestID = entry.RequestID[:8]
		}

		viewEntries[i] = LogEntryView{
			Timestamp:      entry.Timestamp,
			Level:          entry.Level,
			Message:        entry.Message,
			Caller:         entry.Caller,
			Fields:         entry.Fields,
			RequestID:      entry.RequestID,
			UserID:         entry.UserID,
			FormattedTime:  t.Format("15:04:05.000"),
			FullTime:       t.Format("2006-01-02 15:04:05.000 MST"),
			ShortCaller:    shortCaller,
			ShortRequestID: shortRequestID,
			FieldsJSON:     fieldsJSON,
		}
	}

	// Calculate pagination
	page := (filter.Offset / filter.Limit) + 1
	totalPages := int(total) / filter.Limit
	if int(total)%filter.Limit != 0 {
		totalPages++
	}
	if totalPages == 0 {
		totalPages = 1
	}

	from := filter.Offset + 1
	to := filter.Offset + len(entries)
	if from > int(total) {
		from = int(total)
	}

	data := LogTableData{
		Entries:    viewEntries,
		Total:      total,
		From:       from,
		To:         to,
		Page:       page,
		TotalPages: totalPages,
		PrevOffset: filter.Offset - filter.Limit,
		NextOffset: filter.Offset + filter.Limit,
	}

	if data.PrevOffset < 0 {
		data.PrevOffset = 0
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(c.Writer, "table", data); err != nil {
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

// StaticHandler returns a handler for serving static files.
func StaticHandler() http.Handler {
	staticFS, _ := fs.Sub(web.Assets, "static")
	return http.FileServer(http.FS(staticFS))
}
