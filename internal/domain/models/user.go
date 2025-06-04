package models

import "time"

type User struct {
	Id         string     `json:"id"`
	Username   string     `json:"Username"`
	Email      string     `json:"email"`
	Phone      string     `json:"phone"`
	FirstName  string     `json:"first_name"`
	LastName   string     `json:"last_name"`
	MiddleName string     `json:"middle_name"`
	CreatedAt  *time.Time `json:"created_at"`
	UpdatedAt  *time.Time `json:"updated_at"`
}
