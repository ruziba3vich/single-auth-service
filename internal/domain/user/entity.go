package user

import (
	"time"
)

type UserStatus int

const (
	StatusInactive UserStatus = 0
	StatusActive   UserStatus = 1
	StatusBanned   UserStatus = 2
)

type Gender int16

const (
	GenderUnspecified Gender = 0
	GenderMale        Gender = 1
	GenderFemale      Gender = 2
)

// User is the core identity entity. Password is stored as Argon2id hash.
type User struct {
	ID          int64
	Username    string
	SahiyUserID *int64
	Phone       string
	Password    []byte
	Avatar      *string
	BirthDate   time.Time
	Gender      *Gender
	ForbidLogin *int16
	Email       *string
	ProfileID   *int64
	RegisterIP  *string
	LastLoginIP *string
	Status      UserStatus
	CreatedAt   time.Time
	LastLoginAt time.Time
}

// NewUser creates a user with required fields. Password must be pre-hashed.
func NewUser(username, phone string, passwordHash []byte) *User {
	now := time.Now().UTC()
	return &User{
		Username:    username,
		Phone:       phone,
		Password:    passwordHash,
		Status:      StatusActive,
		BirthDate:   now,
		CreatedAt:   now,
		LastLoginAt: now,
	}
}

// IsActive returns true if the user can log in (active status and not forbidden).
func (u *User) IsActive() bool {
	if u.Status != StatusActive {
		return false
	}
	if u.ForbidLogin != nil && *u.ForbidLogin == 1 {
		return false
	}
	return true
}

// UpdatePassword replaces the password hash.
func (u *User) UpdatePassword(newPasswordHash []byte) {
	u.Password = newPasswordHash
}

// UpdateLastLogin records login time and IP address.
func (u *User) UpdateLastLogin(ip string) {
	u.LastLoginAt = time.Now().UTC()
	u.LastLoginIP = &ip
}

// SetEmail sets the user's email address.
func (u *User) SetEmail(email string) {
	u.Email = &email
}
