package device

import (
	"time"

	"github.com/google/uuid"
)

// Device represents a user's authenticated device/session.
// Each device gets a unique ID that is bound to tokens.
type Device struct {
	ID         uuid.UUID // Server-generated device_id
	UserID     uuid.UUID
	ClientID   string    // OAuth client used for this device
	DeviceName string    // Optional user-provided name
	UserAgent  string    // Browser/app user agent
	IPAddress  string    // Last known IP (informational only)
	LastUsedAt time.Time
	CreatedAt  time.Time
	Revoked    bool
}

// NewDevice creates a new device record with a cryptographically secure ID.
func NewDevice(userID uuid.UUID, clientID, userAgent, ipAddress string) *Device {
	now := time.Now().UTC()
	return &Device{
		ID:         uuid.New(),
		UserID:     userID,
		ClientID:   clientID,
		DeviceName: "",
		UserAgent:  userAgent,
		IPAddress:  ipAddress,
		LastUsedAt: now,
		CreatedAt:  now,
		Revoked:    false,
	}
}

// IsActive checks if the device is still valid for use.
func (d *Device) IsActive() bool {
	return !d.Revoked
}

// Revoke marks the device as revoked.
// All tokens bound to this device become invalid.
func (d *Device) Revoke() {
	d.Revoked = true
}

// UpdateLastUsed updates the last activity timestamp.
func (d *Device) UpdateLastUsed(ipAddress string) {
	d.LastUsedAt = time.Now().UTC()
	if ipAddress != "" {
		d.IPAddress = ipAddress
	}
}

// SetName allows the user to name their device.
func (d *Device) SetName(name string) {
	d.DeviceName = name
}

// DeviceInfo represents a sanitized view of a device for API responses.
type DeviceInfo struct {
	ID         uuid.UUID `json:"device_id"`
	DeviceName string    `json:"device_name,omitempty"`
	UserAgent  string    `json:"user_agent"`
	IPAddress  string    `json:"ip_address"`
	LastUsedAt time.Time `json:"last_used_at"`
	CreatedAt  time.Time `json:"created_at"`
	IsCurrent  bool      `json:"is_current"`
}

// ToInfo converts a Device to a sanitized DeviceInfo.
func (d *Device) ToInfo(currentDeviceID uuid.UUID) DeviceInfo {
	return DeviceInfo{
		ID:         d.ID,
		DeviceName: d.DeviceName,
		UserAgent:  d.UserAgent,
		IPAddress:  d.IPAddress,
		LastUsedAt: d.LastUsedAt,
		CreatedAt:  d.CreatedAt,
		IsCurrent:  d.ID == currentDeviceID,
	}
}
