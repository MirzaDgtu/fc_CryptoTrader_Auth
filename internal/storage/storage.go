package storage

import "errors"

var (
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrAppNotFound        = errors.New("app not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidEmailFormat = errors.New("invalid email format")
	ErrInternalServer     = errors.New("internal server error")
)

func IsValidEmail(email string) bool {
	// Simple email validation logic
	if len(email) < 5 || len(email) > 254 {
		return false
	}
	if !containsAtSymbol(email) {
		return false
	}
	return true
}

func containsAtSymbol(email string) bool {
	for _, char := range email {
		if char == '@' {
			return true
		}
	}
	return false
}

func IsValidPassword(password string) bool {
	// Simple password validation logic
	if len(password) < 8 {
		return false
	}
	if len(password) > 64 {
		return false
	}
	return true
}
