package handlers

import (
	"encoding/json"
	"net/http"
	"time"
)

// DeliveryHandler handles delivery-related endpoints.
// This is an example of protected endpoints that require authentication.
type DeliveryHandler struct{}

// NewDeliveryHandler creates a new DeliveryHandler.
func NewDeliveryHandler() *DeliveryHandler {
	return &DeliveryHandler{}
}

// Delivery represents a delivery order.
type Delivery struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Origin      string    `json:"origin"`
	Destination string    `json:"destination"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

// ListDeliveries returns the user's deliveries.
// GET /api/deliveries
//
// This is an example protected endpoint that:
// 1. Gets the user ID from context (set by AuthMiddleware)
// 2. Returns a list of the user's deliveries
//
// In a real implementation, this would query a database.
func (h *DeliveryHandler) ListDeliveries(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Example response - in reality, you would query your database
	deliveries := []Delivery{
		{
			ID:          "del_001",
			UserID:      userID,
			Origin:      "123 Main St, New York, NY",
			Destination: "456 Oak Ave, Los Angeles, CA",
			Status:      "in_transit",
			CreatedAt:   time.Now().Add(-24 * time.Hour),
		},
		{
			ID:          "del_002",
			UserID:      userID,
			Origin:      "789 Pine Rd, Chicago, IL",
			Destination: "321 Elm St, Miami, FL",
			Status:      "delivered",
			CreatedAt:   time.Now().Add(-72 * time.Hour),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"deliveries": deliveries,
		"total":      len(deliveries),
	})
}

// CreateDeliveryRequest is the request body for creating a delivery.
type CreateDeliveryRequest struct {
	Origin      string `json:"origin"`
	Destination string `json:"destination"`
}

// CreateDelivery creates a new delivery order.
// POST /api/deliveries
//
// This is an example protected endpoint that:
// 1. Gets the user ID from context (set by AuthMiddleware)
// 2. Parses the request body
// 3. Creates a new delivery
//
// In a real implementation, this would insert into a database.
func (h *DeliveryHandler) CreateDelivery(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req CreateDeliveryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Origin == "" || req.Destination == "" {
		http.Error(w, "Origin and destination are required", http.StatusBadRequest)
		return
	}

	// Example response - in reality, you would insert into your database
	delivery := Delivery{
		ID:          "del_new_" + time.Now().Format("20060102150405"),
		UserID:      userID,
		Origin:      req.Origin,
		Destination: req.Destination,
		Status:      "pending",
		CreatedAt:   time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(delivery)
}

// GetCurrentUser returns the current user's information.
// GET /api/me
//
// This demonstrates accessing the full session from context.
func (h *DeliveryHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id":    session.UserID,
		"email":      session.Email,
		"device_id":  session.DeviceID,
		"expires_at": session.ExpiresAt,
	})
}

// HealthCheck returns the service health status.
// GET /health
//
// This is an example of an unprotected endpoint.
func (h *DeliveryHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// Home returns the home page content.
// GET /
//
// This demonstrates OptionalAuth - showing different content for
// authenticated vs anonymous users.
func (h *DeliveryHandler) Home(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r.Context())

	w.Header().Set("Content-Type", "application/json")

	if session != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":        "Welcome back!",
			"authenticated":  true,
			"user_id":        session.UserID,
			"email":          session.Email,
			"dashboard_link": "/dashboard",
			"logout_link":    "/auth/logout",
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":       "Welcome to Express Delivery Service",
			"authenticated": false,
			"login_link":    "/auth/login",
		})
	}
}

// Dashboard returns the user dashboard.
// GET /dashboard
//
// This is a protected page that requires authentication.
func (h *DeliveryHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "This is your dashboard",
		"user_id":  session.UserID,
		"email":    session.Email,
		"actions": map[string]string{
			"list_deliveries":   "GET /api/deliveries",
			"create_delivery":   "POST /api/deliveries",
			"get_current_user":  "GET /api/me",
			"logout":            "POST /auth/logout",
		},
	})
}
