package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/prodonik/express-delivery-service/internal/config"
	"github.com/prodonik/express-delivery-service/internal/domain"
	"github.com/prodonik/express-delivery-service/internal/services"
	"github.com/prodonik/express-delivery-service/pkg/pkce"
)

const (
	// Cookie names
	sessionCookieName   = "session_id"
	authStateCookieName = "oauth_state"

	// Cookie settings
	authStateCookieMaxAge = 600 // 10 minutes
)

// AuthHandler handles OAuth authentication flow.
type AuthHandler struct {
	config         *config.Config
	sessionService services.SessionService
	oauthClient    services.OAuthClient
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(
	cfg *config.Config,
	sessionService services.SessionService,
	oauthClient services.OAuthClient,
) *AuthHandler {
	return &AuthHandler{
		config:         cfg,
		sessionService: sessionService,
		oauthClient:    oauthClient,
	}
}

// Login initiates the OAuth authorization flow.
// GET /auth/login
//
// This handler:
// 1. Generates PKCE code verifier and challenge
// 2. Generates CSRF state token
// 3. Stores both in an encrypted cookie
// 4. Redirects to the auth service's /authorize endpoint
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// Generate PKCE pair
	pkcePair, err := pkce.GeneratePair()
	if err != nil {
		http.Error(w, "Failed to generate PKCE", http.StatusInternalServerError)
		return
	}

	// Generate state for CSRF protection
	state, err := pkce.GenerateState()
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	// Generate nonce for OpenID Connect
	nonce, err := pkce.GenerateNonce()
	if err != nil {
		http.Error(w, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}

	// Create auth state to store in cookie
	authState := &domain.AuthState{
		State:        state,
		CodeVerifier: pkcePair.Verifier,
		ReturnTo:     r.URL.Query().Get("return_to"),
		CreatedAt:    time.Now(),
	}

	// Encrypt and store auth state in cookie
	if err := h.setAuthStateCookie(w, authState); err != nil {
		http.Error(w, "Failed to store auth state", http.StatusInternalServerError)
		return
	}

	// Build authorization URL
	authURL, err := url.Parse(h.config.AuthorizeURL())
	if err != nil {
		http.Error(w, "Invalid auth service URL", http.StatusInternalServerError)
		return
	}

	query := authURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", h.config.ClientID)
	query.Set("redirect_uri", h.config.RedirectURI)
	query.Set("scope", h.config.ScopesString())
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", pkcePair.Challenge)
	query.Set("code_challenge_method", "S256")
	authURL.RawQuery = query.Encode()

	// Redirect to auth service
	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// Callback handles the OAuth callback after user authentication.
// GET /auth/callback
//
// This handler:
// 1. Validates the state parameter (CSRF protection)
// 2. Retrieves the code verifier from the cookie
// 3. Exchanges the authorization code for tokens
// 4. Creates a session with the tokens
// 5. Redirects to the dashboard
func (h *AuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	// Check for OAuth error response
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		errDesc := r.URL.Query().Get("error_description")
		http.Error(w, "OAuth error: "+errCode+": "+errDesc, http.StatusBadRequest)
		return
	}

	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Get state from query
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "Missing state parameter", http.StatusBadRequest)
		return
	}

	// Retrieve and validate auth state from cookie
	authState, err := h.getAuthStateCookie(r)
	if err != nil {
		http.Error(w, "Invalid or expired auth state", http.StatusBadRequest)
		return
	}

	// Validate state (CSRF protection)
	if authState.State != state {
		http.Error(w, "State mismatch - possible CSRF attack", http.StatusBadRequest)
		return
	}

	// Check if auth state has expired
	if authState.IsExpired() {
		http.Error(w, "Authorization request has expired", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	tokens, err := h.oauthClient.ExchangeCode(r.Context(), code, authState.CodeVerifier)
	if err != nil {
		http.Error(w, "Failed to exchange code for tokens: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse ID token to get user info
	claims, err := h.oauthClient.ParseIDToken(r.Context(), tokens.IDToken)
	if err != nil {
		http.Error(w, "Failed to parse ID token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Generate session ID
	sessionID, err := generateSessionID()
	if err != nil {
		http.Error(w, "Failed to generate session ID", http.StatusInternalServerError)
		return
	}

	// Create session
	session := &domain.Session{
		ID:           sessionID,
		UserID:       claims.Subject,
		Email:        claims.Email,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		DeviceID:     tokens.DeviceID,
		ExpiresAt:    time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Store session
	if err := h.sessionService.Create(r.Context(), session); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	h.setSessionCookie(w, sessionID)

	// Clear auth state cookie
	h.clearAuthStateCookie(w)

	// Redirect to post-login destination
	redirectTo := h.config.PostLoginRedirect
	if authState.ReturnTo != "" {
		redirectTo = authState.ReturnTo
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

// Logout logs out the user.
// POST /auth/logout
//
// This handler:
// 1. Gets the current session
// 2. Calls the auth service to revoke the device
// 3. Deletes the local session
// 4. Clears cookies
// 5. Redirects to home
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Get session ID from cookie
	sessionID, err := h.getSessionCookie(r)
	if err != nil {
		// No session, just redirect
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Get session from storage
	session, err := h.sessionService.Get(r.Context(), sessionID)
	if err == nil && session != nil {
		// Logout from auth service (best effort)
		_ = h.oauthClient.Logout(r.Context(), session.AccessToken, session.DeviceID)

		// Delete local session
		_ = h.sessionService.Delete(r.Context(), sessionID)
	}

	// Clear session cookie
	h.clearSessionCookie(w)

	// Redirect to home
	http.Redirect(w, r, "/", http.StatusFound)
}

// Refresh refreshes the access token.
// POST /auth/refresh
//
// This handler:
// 1. Gets the current session
// 2. Calls the auth service to refresh tokens
// 3. Updates the local session with new tokens
// 4. Returns success
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	// Get session ID from cookie
	sessionID, err := h.getSessionCookie(r)
	if err != nil {
		http.Error(w, "No active session", http.StatusUnauthorized)
		return
	}

	// Get session from storage
	session, err := h.sessionService.Get(r.Context(), sessionID)
	if err != nil {
		http.Error(w, "Session not found", http.StatusUnauthorized)
		return
	}

	// Refresh tokens
	tokens, err := h.oauthClient.RefreshTokens(r.Context(), session.RefreshToken, session.DeviceID)
	if err != nil {
		// Refresh failed, session is invalid
		_ = h.sessionService.Delete(r.Context(), sessionID)
		h.clearSessionCookie(w)
		http.Error(w, "Session expired, please login again", http.StatusUnauthorized)
		return
	}

	// Update session with new tokens
	session.AccessToken = tokens.AccessToken
	session.RefreshToken = tokens.RefreshToken
	session.ExpiresAt = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
	session.UpdatedAt = time.Now()

	if err := h.sessionService.Update(r.Context(), session); err != nil {
		http.Error(w, "Failed to update session", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// --- Cookie helpers ---

func (h *AuthHandler) setSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.config.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *AuthHandler) getSessionCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func (h *AuthHandler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.config.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *AuthHandler) setAuthStateCookie(w http.ResponseWriter, state *domain.AuthState) error {
	// Serialize auth state to JSON
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}

	// Encrypt the data
	encrypted, err := encrypt(data, h.config.CookieSecret)
	if err != nil {
		return err
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     authStateCookieName,
		Value:    encrypted,
		Path:     "/",
		MaxAge:   authStateCookieMaxAge,
		HttpOnly: true,
		Secure:   h.config.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

func (h *AuthHandler) getAuthStateCookie(r *http.Request) (*domain.AuthState, error) {
	cookie, err := r.Cookie(authStateCookieName)
	if err != nil {
		return nil, err
	}

	// Decrypt the data
	data, err := decrypt(cookie.Value, h.config.CookieSecret)
	if err != nil {
		return nil, err
	}

	// Deserialize auth state
	var state domain.AuthState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	return &state, nil
}

func (h *AuthHandler) clearAuthStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     authStateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.config.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// --- Crypto helpers ---

func encrypt(plaintext, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func decrypt(ciphertext string, key []byte) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, err
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertextBytes, nil)
}

func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
