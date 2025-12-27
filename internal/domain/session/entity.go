package session

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// SessionInfo holds device/browser metadata, stored as JSONB.
type SessionInfo struct {
	DeviceName string `json:"device_name,omitempty"`
	UserAgent  string `json:"user_agent"`
	Browser    string `json:"browser,omitempty"`
	OS         string `json:"os,omitempty"`
	DeviceType string `json:"device_type,omitempty"` // mobile, desktop, tablet
}

func (s *SessionInfo) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

func ParseSessionInfo(data []byte) (*SessionInfo, error) {
	var info SessionInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// UserSession ties a refresh token to a device. One user can have multiple sessions.
type UserSession struct {
	ID               uuid.UUID
	UserID           int64
	RefreshTokenHash string
	DeviceID         uuid.UUID
	FCMToken         *string
	IPAddress        string
	SessionInfo      *SessionInfo
	ClientID         string
	Scope            string
	ExpiresAt        time.Time
	Revoked          bool
	CreatedAt        time.Time
	LastUsedAt       time.Time
}

// NewUserSession creates a session with a new device ID and expiry based on ttl.
func NewUserSession(
	userID int64,
	refreshTokenHash string,
	clientID string,
	ipAddress string,
	sessionInfo *SessionInfo,
	scope string,
	ttl time.Duration,
) *UserSession {
	now := time.Now().UTC()
	return &UserSession{
		ID:               uuid.New(),
		UserID:           userID,
		RefreshTokenHash: refreshTokenHash,
		DeviceID:         uuid.New(),
		IPAddress:        ipAddress,
		SessionInfo:      sessionInfo,
		ClientID:         clientID,
		Scope:            scope,
		ExpiresAt:        now.Add(ttl),
		Revoked:          false,
		CreatedAt:        now,
		LastUsedAt:       now,
	}
}

// IsValid returns true if the session is not revoked and not expired.
func (s *UserSession) IsValid() bool {
	if s.Revoked {
		return false
	}
	return time.Now().UTC().Before(s.ExpiresAt)
}

func (s *UserSession) IsActive() bool {
	return !s.Revoked
}

func (s *UserSession) Revoke() {
	s.Revoked = true
}

// UpdateLastUsed bumps the activity timestamp and optionally updates the IP.
func (s *UserSession) UpdateLastUsed(ipAddress string) {
	s.LastUsedAt = time.Now().UTC()
	if ipAddress != "" {
		s.IPAddress = ipAddress
	}
}

// UpdateRefreshToken rotates the token hash and extends expiry.
func (s *UserSession) UpdateRefreshToken(newHash string, ttl time.Duration) {
	s.RefreshTokenHash = newHash
	s.ExpiresAt = time.Now().UTC().Add(ttl)
	s.LastUsedAt = time.Now().UTC()
}

func (s *UserSession) SetFCMToken(token string) {
	s.FCMToken = &token
}

// SessionInfoForAPI is the public view of a session (no sensitive data).
type SessionInfoForAPI struct {
	SessionID  uuid.UUID `json:"session_id"`
	DeviceID   uuid.UUID `json:"device_id"`
	DeviceName string    `json:"device_name,omitempty"`
	UserAgent  string    `json:"user_agent"`
	IPAddress  string    `json:"ip_address"`
	LastUsedAt time.Time `json:"last_used_at"`
	CreatedAt  time.Time `json:"created_at"`
	IsCurrent  bool      `json:"is_current"`
}

// ToAPIInfo converts the session to a public-safe struct.
func (s *UserSession) ToAPIInfo(currentDeviceID uuid.UUID) SessionInfoForAPI {
	info := SessionInfoForAPI{
		SessionID:  s.ID,
		DeviceID:   s.DeviceID,
		IPAddress:  s.IPAddress,
		LastUsedAt: s.LastUsedAt,
		CreatedAt:  s.CreatedAt,
		IsCurrent:  s.DeviceID == currentDeviceID,
	}
	if s.SessionInfo != nil {
		info.DeviceName = s.SessionInfo.DeviceName
		info.UserAgent = s.SessionInfo.UserAgent
	}
	return info
}
