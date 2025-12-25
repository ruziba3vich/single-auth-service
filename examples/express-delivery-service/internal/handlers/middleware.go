package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/prodonik/express-delivery-service/internal/config"
	"github.com/prodonik/express-delivery-service/internal/domain"
	"github.com/prodonik/express-delivery-service/internal/services"
)

// Context keys for user information.
type contextKey string

const (
	sessionContextKey contextKey = "session"
	userIDContextKey  contextKey = "user_id"
)

// AuthMiddleware protects routes that require authentication.
type AuthMiddleware struct {
	config         *config.Config
	sessionService services.SessionService
	oauthClient    services.OAuthClient
}

// NewAuthMiddleware creates a new AuthMiddleware.
func NewAuthMiddleware(
	cfg *config.Config,
	sessionService services.SessionService,
	oauthClient services.OAuthClient,
) *AuthMiddleware {
	return &AuthMiddleware{
		config:         cfg,
		sessionService: sessionService,
		oauthClient:    oauthClient,
	}
}

// RequireAuth is middleware that requires a valid session.
// It:
// 1. Extracts session ID from cookie
// 2. Loads the session from storage
// 3. Checks if the access token is expired
// 4. If expired, attempts to refresh the token
// 5. Adds the session to the request context
// 6. Returns 401 if no valid session exists
func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get session ID from cookie
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			http.Error(w, "Unauthorized: no session", http.StatusUnauthorized)
			return
		}

		// Load session from storage
		session, err := m.sessionService.Get(r.Context(), cookie.Value)
		if err != nil {
			http.Error(w, "Unauthorized: invalid session", http.StatusUnauthorized)
			return
		}

		// Check if token needs refresh (refresh 5 minutes before expiry)
		if session.NeedsRefresh(5 * time.Minute) {
			refreshedSession, err := m.refreshSession(r.Context(), session)
			if err != nil {
				// Refresh failed, clear session
				m.sessionService.Delete(r.Context(), session.ID)
				clearCookie(w, sessionCookieName, m.config.SecureCookies)
				http.Error(w, "Session expired, please login again", http.StatusUnauthorized)
				return
			}
			session = refreshedSession
		}

		// Add session to context
		ctx := context.WithValue(r.Context(), sessionContextKey, session)
		ctx = context.WithValue(ctx, userIDContextKey, session.UserID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OptionalAuth is middleware that loads the session if available but doesn't require it.
// Useful for pages that show different content for authenticated vs anonymous users.
func (m *AuthMiddleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get session ID from cookie
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			// No session, continue without auth
			next.ServeHTTP(w, r)
			return
		}

		// Load session from storage
		session, err := m.sessionService.Get(r.Context(), cookie.Value)
		if err != nil {
			// Invalid session, continue without auth
			next.ServeHTTP(w, r)
			return
		}

		// Check if token needs refresh
		if session.NeedsRefresh(5 * time.Minute) {
			refreshedSession, err := m.refreshSession(r.Context(), session)
			if err != nil {
				// Refresh failed, continue without auth
				m.sessionService.Delete(r.Context(), session.ID)
				clearCookie(w, sessionCookieName, m.config.SecureCookies)
				next.ServeHTTP(w, r)
				return
			}
			session = refreshedSession
		}

		// Add session to context
		ctx := context.WithValue(r.Context(), sessionContextKey, session)
		ctx = context.WithValue(ctx, userIDContextKey, session.UserID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// refreshSession refreshes the tokens and updates the session.
func (m *AuthMiddleware) refreshSession(ctx context.Context, session *domain.Session) (*domain.Session, error) {
	// Refresh tokens
	tokens, err := m.oauthClient.RefreshTokens(ctx, session.RefreshToken, session.DeviceID)
	if err != nil {
		return nil, err
	}

	// Update session with new tokens
	session.AccessToken = tokens.AccessToken
	session.RefreshToken = tokens.RefreshToken
	session.ExpiresAt = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
	session.UpdatedAt = time.Now()

	if err := m.sessionService.Update(ctx, session); err != nil {
		return nil, err
	}

	return session, nil
}

// --- Context helpers ---

// GetSession retrieves the session from the request context.
// Returns nil if no session is present (user not authenticated).
func GetSession(ctx context.Context) *domain.Session {
	session, ok := ctx.Value(sessionContextKey).(*domain.Session)
	if !ok {
		return nil
	}
	return session
}

// GetUserID retrieves the user ID from the request context.
// Returns empty string if no user is authenticated.
func GetUserID(ctx context.Context) string {
	userID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		return ""
	}
	return userID
}

// IsAuthenticated returns true if the request has a valid session.
func IsAuthenticated(ctx context.Context) bool {
	return GetSession(ctx) != nil
}

// GetAccessToken retrieves the access token from the request context.
// Useful for making authenticated API calls to other services.
func GetAccessToken(ctx context.Context) string {
	session := GetSession(ctx)
	if session == nil {
		return ""
	}
	return session.AccessToken
}

// --- Helper functions ---

func clearCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}
