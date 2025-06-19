package models

import "time"

type User struct {
	Id           string     `json:"id"`
	Username     string     `json:"Username"`
	Email        string     `json:"email"`
	Phone        string     `json:"phone"`
	FirstName    string     `json:"first_name"`
	LastName     string     `json:"last_name"`
	MiddleName   string     `json:"middle_name"`
	PasswordHash []byte     `json:"password_hash"`
	IsActive     bool       `json:"is_active"`
	Role         string     `json:"role"` // e.g., "admin", "user", etc.
	CreatedAt    *time.Time `json:"created_at"`
	UpdatedAt    *time.Time `json:"updated_at"`
	IsAdmin      bool       `json:"is_admin"` // true if the user is an admin
}
